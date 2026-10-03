use crate::collection::plan::{self, EpochInput, Inclusion, Planned, Publication, Unsealed};
use crate::collection::{Parameters, State};
use crate::db::{Db, PendingEntryRow};
use crate::error::{Error, Result};
use crate::history::History;
use crate::registry;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use wist_core::aggregator_keys::{self, KeyAction, Outcome, Registry};
use wist_core::crypto::SigningKey;
use wist_core::envelope::sign_envelope;
use wist_core::epoch::ENTRY_TYPES as ENTRY_TYPE_ORDER;
use wist_core::objects::AggregatorKeyEntry;
use wist_core::{jcs, merkle, tiles};

pub(super) struct PreparedEpoch {
    pub(super) log_id: String,
    /// WIST-3 §3.4, §5: every key signs the Checkpoint; the first signs the
    /// Snapshot documents.
    pub(super) signers: Vec<SigningKey>,
    /// WIST-3 §7: removed keys included.
    pub(super) key_entries: Vec<AggregatorKeyEntry>,
    pub(super) entries: Vec<Value>,
    pub(super) octets: u64,
    pub(super) epoch_number: u64,
    pub(super) sealed_at: String,
    pub(super) sealed_rowids: Vec<i64>,
    pub(super) accepted_changes: Vec<AcceptedParamChange>,
    pub(super) withdrawals: Vec<OwnedWithdrawal>,
    pub(super) suffix_lists: Vec<String>,
    pub(super) dropped: Vec<String>,
    pub(super) late: Vec<String>,
    pub(super) before: State,
    pub(super) planned: Planned,
    pub(super) scope: BTreeSet<String>,
    pub(super) payload_window_days: i64,
}

fn sealing_slot(db: &Db, now_unix: i64) -> Result<(u64, i64, String)> {
    let now_at = jiff::Timestamp::from_second(now_unix)
        .map_err(|_| Error::Seal("now out of range".into()))?
        .to_string();
    let prev = db.last_epoch()?;
    let cadence = registry::effective(
        db,
        "epoch_cadence_seconds",
        prev.as_ref()
            .map_or(now_at.as_str(), |p| p.sealed_at.as_str()),
    )?;
    if cadence <= 0 {
        return Err(Error::Seal("epoch_cadence_seconds must be positive".into()));
    }
    let sealed_unix = now_unix.div_euclid(cadence) * cadence;
    let sealed_at = jiff::Timestamp::from_second(sealed_unix)
        .map_err(|_| Error::Seal("sealed_at out of range".into()))?
        .to_string();
    let epoch_number = match &prev {
        Some(p) => {
            if sealed_at.as_str() <= p.sealed_at.as_str() {
                return Err(Error::Seal("cadence slot already sealed".into()));
            }
            p.epoch_number + 1
        }
        None => 0,
    };
    Ok((epoch_number, sealed_unix, sealed_at))
}

/// WIST-4 §5: the Log's map, which a replaying Consumer reads; an operator value of a bound
/// on what one Epoch carries may only tighten it.
fn sealing_parameters(db: &Db, sealed_unix: i64, sealed_at: &str) -> Result<Parameters> {
    let schedule = db.parameter_schedule(sealed_unix)?;
    let mut parameters = Parameters::new(
        registry::PARAMS
            .iter()
            .filter_map(|spec| {
                schedule
                    .value_at(spec.name, sealed_unix)
                    .map(|value| (spec.name.to_owned(), value))
            })
            .collect(),
    );
    for name in [
        "domain_epoch_entries_max",
        "labeler_epoch_entries_max",
        "max_inclusion_epochs",
    ] {
        let local = registry::effective(db, name, sealed_at)?;
        let logged = parameters.value(name)?;
        parameters.set(name, logged.min(local));
    }
    let domain = parameters.value("domain_epoch_entries_max")?;
    let labeler = parameters.value("labeler_epoch_entries_max")?;
    parameters.set("labeler_epoch_entries_max", labeler.min(domain));
    Ok(parameters)
}

fn publication_text(publication: &Publication) -> String {
    match publication {
        Publication::Catalog {
            publisher,
            collection,
            catalog,
        } => format!("Catalog {catalog} of {publisher} {collection}"),
        Publication::Item {
            publisher,
            url,
            item,
            ..
        } => format!("Item {item} of {publisher} {url}"),
        Publication::Label { kind, id, .. } => format!("{} {id}", kind.as_str()),
    }
}

fn label_entry_id(entry: &Value) -> Result<String> {
    let body = &entry["body"];
    match entry["type"].as_str() {
        Some("dispute") => wist_core::label::dispute_id(&body["dispute"]),
        _ => wist_core::label::label_id(&body["label"]),
    }
    .map_err(|error| Error::Seal(format!("a planned Label Entry has no ID: {error:?}")))
}

struct Candidates {
    declarations: Vec<Value>,
    updates: Vec<Value>,
    unsealed: BTreeSet<Unsealed>,
}

impl Candidates {
    /// WIST-3 §3.3, Capacity order.
    fn keep_out(&mut self, planned: &Planned, entry: &Value) -> Result<()> {
        let body = &entry["body"];
        match entry["type"].as_str() {
            Some("publisher_declaration") => self.declarations.retain(|kept| kept != body),
            Some("registry_update") => self.updates.retain(|kept| kept != body),
            Some("publisher_catalog") => {
                self.unsealed.insert(Unsealed::Catalog {
                    publisher: body["catalog"]["publisher"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    collection: body["catalog"]["collection"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                });
            }
            Some("publisher_item") => {
                let item_id = wist_core::item::item_id(&body["item"])?;
                let url = body["item"]["url"].as_str().unwrap_or_default();
                let publisher = planned
                    .sealed
                    .iter()
                    .find_map(|sealed| match &sealed.publication {
                        Publication::Item {
                            publisher,
                            url: sealed_url,
                            item,
                            ..
                        } if *item == item_id && sealed_url == url => Some(publisher.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| Error::Seal(format!("a planned Item of {url} is not sealed")))?;
                self.unsealed.insert(Unsealed::Item {
                    publisher,
                    url: url.to_owned(),
                });
            }
            _ => {
                self.unsealed.insert(Unsealed::Label {
                    id: label_entry_id(entry)?,
                });
            }
        }
        Ok(())
    }
}

fn entry_octets(entry: &Value) -> Result<u64> {
    Ok(jcs::canonicalize(entry)?.len() as u64 + 2)
}

/// WIST-3 §3.3, Waiting.
pub(super) fn epoch(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    now_unix: i64,
) -> Result<PreparedEpoch> {
    let (epoch_number, sealed_unix, sealed_at) = sealing_slot(db, now_unix)?;
    let mut history = History::open(db, data_dir, db.last_epoch()?)?;
    while history.next_epoch()?.is_some() {}
    let sealed = db.sealed_from(&history)?;
    for (domain, state) in sealed.declarations.domains() {
        let Some(window) = state.window() else {
            continue;
        };
        if i128::from(sealed_unix) < window.end_s()
            && !db.recovery_queue_held(domain, window.owner().hash())?
        {
            return Err(Error::Seal(format!(
                "the cadence slot {sealed_at} predates completed recovery settlement of {domain}: a pull settled its window at or after the window's end, so an Epoch inside the window could seal what the settlement superseded; seal at a later grid instant"
            )));
        }
    }
    let mut scope = db.waiting_publishers()?;
    for (domain, state) in sealed.declarations.domains() {
        if state.window().is_some() || state.pending().is_some() {
            scope.insert(domain.clone());
        }
    }
    let state = db.load_state(sealed, &scope)?;
    let parameters = sealing_parameters(db, sealed_unix, &sealed_at)?;
    let payload_window_days = parameters.value("payload_window_days")?;

    let (pending, _) = db.peek_pending_entries()?;
    let (updates, oversize): (Vec<SealEntry>, Vec<SealEntry>) = storage_order(
        pending
            .into_iter()
            .filter(|row| row.entry_type == "registry_update")
            .collect(),
    )?
    .into_iter()
    .partition(|entry| entry.canonical.len() as u64 <= tiles::ENTRY_MAX_BYTES);
    let schedule = db.parameter_schedule(sealed_unix)?;
    let mut cap = registry::epoch_cap(&schedule, sealed_unix).min(registry::effective(
        db,
        "epoch_cap_bytes",
        &sealed_at,
    )?);
    let mut tentative = schedule.clone();
    let largest = db.largest_epoch_bytes()?;
    for (index, entry) in updates.iter().enumerate() {
        let update = &entry.body["update"];
        if update["action"] == "parameter_change"
            && check_param_change(
                &mut tentative,
                update,
                sealed_unix,
                epoch_number,
                index as u64,
                largest,
            )
            .is_ok()
        {
            cap = cap.min(registry::epoch_cap(&tentative, sealed_unix));
        }
    }
    let GovernanceOutcome {
        kept,
        param_changes,
        withdrawals,
        suffix_lists,
        mut dropped,
        dropped_rowids,
        key_registry,
    } = enforce_governance(
        db,
        history.key_registry(),
        updates,
        sealed_unix,
        epoch_number,
        0,
    )?;
    for entry in &oversize {
        dropped.push(format!(
            "WIST3-E03 {} Entry over 65 535 octets is not sealed",
            entry.entry_type
        ));
    }
    let mut dropped_rowids = dropped_rowids;
    dropped_rowids.extend(oversize.iter().map(|entry| entry.rowid));
    let signers = held_signers(data_dir, db, sk, &key_registry, epoch_number)?;
    let keys = key_registry.valid_at(epoch_number);
    let log_key = |key_id: &str| {
        keys.iter()
            .find(|key| key.key_id == key_id)
            .map(|key| key.public_key.clone())
    };
    let installed: HashSet<String> = state
        .declarations
        .domains()
        .values()
        .flat_map(|domain| {
            std::iter::once(domain.current().hash().to_string()).chain(
                domain
                    .window()
                    .map(|window| window.head().hash().to_string()),
            )
        })
        .collect();
    let inclusion = Inclusion::constant(
        u64::try_from(parameters.value("max_inclusion_epochs")?)
            .map_err(|_| Error::Param("max_inclusion_epochs".into()))?,
    );
    let suffix_list = crate::suffix_list::in_force_at_epoch(db, epoch_number)?;
    let deadlines: HashMap<String, u64> = state
        .discovered
        .values()
        .flatten()
        .filter_map(|found| {
            found
                .last_seal_height
                .map(|deadline| (found.hash.clone(), deadline))
        })
        .collect();
    let held = crate::db::StoreHeld::new(db, data_dir, &sealed_at);
    let mut candidates = Candidates {
        declarations: state
            .discovered
            .values()
            .flatten()
            .map(|found| found.envelope.clone())
            .collect(),
        updates: kept.iter().map(|entry| entry.body.clone()).collect(),
        unsealed: BTreeSet::new(),
    };
    for (id, label) in &state.labels {
        let wrapped = serde_json::json!({"type": label.kind.as_str(), "body": label.envelope});
        if jcs::canonicalize(&wrapped)?.len() as u64 > tiles::ENTRY_MAX_BYTES {
            dropped.push(format!(
                "WIST3-E03 {} Entry {id} over 65 535 octets is left unsealed",
                label.kind.as_str()
            ));
            candidates
                .unsealed
                .insert(Unsealed::Label { id: id.clone() });
        }
    }
    let planned = loop {
        let input = EpochInput {
            height: epoch_number,
            sealed_at: &sealed_at,
            parameters: &parameters,
            inclusion: &inclusion,
            suffix_list: suffix_list.as_deref(),
            declarations: &candidates.declarations,
            updates: &candidates.updates,
            unsealed: &candidates.unsealed,
            log_key: &log_key,
        };
        let planned = plan::plan(&state, &held, &input)?;
        let mut octets = 0u64;
        let mut oversize = Vec::new();
        for entry in &planned.entries {
            let size = entry_octets(entry)?;
            if size - 2 > tiles::ENTRY_MAX_BYTES {
                oversize.push(entry.clone());
            }
            octets += size;
        }
        let out: Vec<Value> = if !oversize.is_empty() {
            oversize
        } else if octets > u64::try_from(cap).unwrap_or_default() {
            let indexed = planned
                .entries
                .iter()
                .enumerate()
                .map(|(index, entry)| seal_entry(index as i64, entry.clone()))
                .collect::<Result<Vec<_>>>()?;
            let (fit, _) = fit_to_cap(indexed, cap, &installed, &deadlines)?;
            let fit: HashSet<i64> = fit.iter().map(|entry| entry.rowid).collect();
            planned
                .entries
                .iter()
                .enumerate()
                .filter(|(index, _)| !fit.contains(&(*index as i64)))
                .map(|(_, entry)| entry.clone())
                .collect()
        } else {
            plan::verify(&state, &input, &planned.entries)?;
            break planned;
        };
        if out.is_empty() {
            return Err(Error::Seal(
                "the Epoch exceeds epoch_cap_bytes and no Entry can be kept out".into(),
            ));
        }
        for entry in &out {
            candidates.keep_out(&planned, entry)?;
        }
    };

    let entries = planned.entries.clone();
    let octets = entries.iter().map(entry_octets).sum::<Result<u64>>()?;
    let in_epoch = |body: &Value| {
        entries
            .iter()
            .any(|entry| entry["type"] == "registry_update" && entry["body"] == *body)
    };
    let mut sealed_rowids = dropped_rowids;
    let mut accepted_changes = Vec::new();
    for change in param_changes {
        if in_epoch(&change.body) {
            accepted_changes.push(change);
        }
    }
    let withdrawals: Vec<OwnedWithdrawal> = withdrawals
        .into_iter()
        .filter(|withdrawal| in_epoch(&withdrawal.body))
        .collect();
    for entry in &kept {
        let refused = planned.updates_refused.iter().any(|refused| {
            entry.body["update"]["details"]["delta_id"] == refused.item_id.as_str()
                && entry.body["update"]["subject"] == refused.subject.as_str()
        });
        if refused || in_epoch(&entry.body) {
            sealed_rowids.push(entry.rowid);
        }
    }
    for refused in &planned.updates_refused {
        dropped.push(format!(
            "{} payload_withdrawal {} of {} is not sealed: no Item of the subject is sealed below this Epoch",
            refused.code, refused.item_id, refused.subject
        ));
    }
    for rejection in &planned.rejections {
        dropped.push(format!("{}: {}", rejection.id, rejection.code));
    }
    for left in planned.left.iter().filter(|left| left.reported) {
        dropped.push(format!(
            "{} {} leaves at its turn",
            left.codes.join(", "),
            publication_text(&left.publication)
        ));
    }
    for failed in &planned.declarations_failed {
        dropped.push(format!(
            "{} Declaration {} fails at sealing",
            failed.code, failed.declaration
        ));
    }
    for left in &planned.declarations_left {
        dropped.push(format!(
            "{} Declaration {} leaves with the Declaration it names",
            left.code, left.declaration
        ));
    }
    let mut late: Vec<String> = planned
        .sealed
        .iter()
        .filter(|sealed| epoch_number > sealed.ceiling)
        .map(|sealed| {
            format!(
                "{}: sealed at Epoch {epoch_number}, past its inclusion ceiling {}",
                publication_text(&sealed.publication),
                sealed.ceiling
            )
        })
        .collect();
    late.extend(
        planned
            .unsealed
            .iter()
            .filter(|unsealed| unsealed.ceiling <= epoch_number)
            .map(|unsealed| {
                format!(
                    "{}: left unsealed at Epoch {epoch_number}, past its inclusion ceiling {}",
                    publication_text(&unsealed.publication),
                    unsealed.ceiling
                )
            }),
    );
    for found in state.discovered.values().flatten() {
        let Some(deadline) = found.last_seal_height else {
            continue;
        };
        let sealed = entries.iter().any(|entry| {
            entry["type"] == "publisher_declaration" && entry["body"] == found.envelope
        });
        let eligible = planned
            .state
            .discovered
            .values()
            .flatten()
            .any(|kept| kept.hash == found.hash);
        if sealed && epoch_number > deadline {
            late.push(format!(
                "Declaration {}: sealed at Epoch {epoch_number}, past its sealing deadline {deadline}",
                found.hash
            ));
        } else if !sealed && eligible && deadline <= epoch_number {
            late.push(format!(
                "Declaration {}: left unsealed at Epoch {epoch_number}, past its sealing deadline {deadline}",
                found.hash
            ));
        }
    }
    late.extend(planned.held_late.iter().map(|held| {
        format!(
            "{}: held at Epoch {epoch_number} by a Declaration that reduces authority, past its inclusion ceiling {}",
            publication_text(&held.publication),
            held.ceiling
        )
    }));
    Ok(PreparedEpoch {
        log_id: history.log_id().to_owned(),
        signers,
        key_entries: key_registry.entries(),
        entries,
        octets,
        epoch_number,
        sealed_at,
        sealed_rowids,
        accepted_changes,
        withdrawals,
        suffix_lists,
        dropped,
        late,
        before: state,
        planned,
        scope,
        payload_window_days,
    })
}

pub(super) struct AcceptedParamChange {
    pub(super) rowid: i64,
    pub(super) body: Value,
    pub(super) parameter: String,
    pub(super) value: i64,
    pub(super) effective_at: String,
}

pub(super) struct OwnedWithdrawal {
    pub(super) body: Value,
    pub(super) update_id: String,
    pub(super) item_id: String,
    pub(super) domain: String,
}

pub(super) struct GovernanceOutcome {
    pub(super) kept: Vec<SealEntry>,
    pub(super) param_changes: Vec<AcceptedParamChange>,
    pub(super) withdrawals: Vec<OwnedWithdrawal>,
    pub(super) suffix_lists: Vec<String>,
    pub(super) dropped: Vec<String>,
    pub(super) dropped_rowids: Vec<i64>,
    pub(super) key_registry: Registry,
}

pub(super) fn check_param_change(
    schedule: &mut wist_core::parameters::Schedule,
    update: &Value,
    sealed_unix: i64,
    epoch_number: u64,
    entry_index: u64,
    largest_epoch: u64,
) -> std::result::Result<AcceptedParamChange, String> {
    let parameter = update["details"]["parameter"]
        .as_str()
        .ok_or("missing details.parameter")?;
    let value = update["details"]["value"]
        .as_i64()
        .ok_or("missing details.value")?;
    let effective_at = update["effective_at"]
        .as_str()
        .ok_or("missing effective_at")?;
    let amendment = wist_core::parameters::Amendment {
        parameter: parameter.into(),
        value,
        epoch_number,
        entry_index,
        sealed_at_s: sealed_unix,
        effective_at_s: registry::unix(effective_at).map_err(|e| e.to_string())?,
    };
    registry::accept(schedule, amendment, largest_epoch)
        .map_err(|e| format!("{parameter}: {e}"))?;
    Ok(AcceptedParamChange {
        rowid: 0,
        body: Value::Null,
        parameter: parameter.into(),
        value,
        effective_at: effective_at.into(),
    })
}

pub(crate) fn validate_pending_parameter(
    db: &Db,
    update: &Value,
    sk: &SigningKey,
    at: i64,
) -> Result<()> {
    let mut schedule = db.parameter_schedule(at)?;
    let height = db.last_epoch()?.map_or(0, |b| b.epoch_number + 1);
    let largest = db.largest_epoch_bytes()?;
    let (pending, _) = db.peek_pending_entries()?;
    let rowid = pending.iter().map(|p| p.rowid).max().unwrap_or(0) + 1;
    let mut pending: Vec<PendingEntryRow> = pending
        .into_iter()
        .filter(|row| row.entry_type == "registry_update")
        .collect();
    pending.push(PendingEntryRow {
        rowid,
        entry_type: "registry_update".into(),
        domain: String::new(),
        entry_json: sign_envelope(update, "update", &db.signing_key_id(&sk.public())?, sk)?,
        turn_epoch: None,
    });
    for (index, entry) in storage_order(pending)?.iter().enumerate() {
        if entry.entry_type != "registry_update"
            || entry.body["update"]["action"] != "parameter_change"
        {
            continue;
        }
        let result = check_param_change(
            &mut schedule,
            &entry.body["update"],
            at,
            height,
            index as u64,
            largest,
        );
        if entry.rowid == rowid {
            result.map_err(Error::ParamChange)?;
            return Ok(());
        }
    }
    Err(Error::ParamChange(
        "candidate is missing from pending entries".into(),
    ))
}

/// WIST-4 §5.1: the act must verify under the Log key and name an Item
/// sealed for the subject at or below this Epoch; a repeated withdrawal
/// seals and changes nothing.
fn check_withdrawal(
    replay: &mut wist_core::withdrawal::WithdrawalReplay,
    public_key_of: impl Fn(&str) -> Option<wist_core::crypto::PublicKey>,
    body: &Value,
    epoch_number: u64,
    sealed: &wist_core::withdrawal::SealedItems,
) -> std::result::Result<Option<OwnedWithdrawal>, String> {
    use wist_core::withdrawal::Disposition;
    match replay.apply(epoch_number, body, public_key_of, sealed) {
        Disposition::Accepted {
            item_id, publisher, ..
        } => Ok(Some(OwnedWithdrawal {
            body: body.clone(),
            update_id: crate::governance::update_id(&body["update"]).map_err(|e| e.to_string())?,
            item_id,
            domain: publisher,
        })),
        Disposition::Repeated { .. } => Ok(None),
        Disposition::Rejected(code) => Err(format!(
            "{code} payload_withdrawal {} is not sealed",
            body["update"]["details"]["delta_id"]
                .as_str()
                .unwrap_or("without an Item ID")
        )),
        Disposition::NotWithdrawal => Ok(None),
    }
}

/// WIST-3 §3.4, §5: ordered by admitting height, then `key_id`; every one
/// signs the Checkpoint.
fn held_signers(
    data_dir: &Path,
    db: &Db,
    sk: &SigningKey,
    keys: &Registry,
    epoch_number: u64,
) -> Result<Vec<SigningKey>> {
    let store = crate::keys::Store::open(data_dir, db)?;
    if !store.holds(&sk.public()) {
        return Err(Error::Seal(
            "the signing key given is not one the data directory's key store holds".into(),
        ));
    }
    let mut records: Vec<_> = keys
        .records()
        .filter(|record| record.valid_at(epoch_number))
        .collect();
    records.sort_by(|a, b| {
        a.added_height
            .cmp(&b.added_height)
            .then_with(|| a.key_id.cmp(&b.key_id))
    });
    let signers: Vec<SigningKey> = records
        .iter()
        .filter_map(|record| store.signing_for(&record.key_id, &record.public_key))
        .collect();
    if signers.is_empty() {
        return Err(Error::Seal(format!(
            "no Aggregator key valid at height {epoch_number} is held"
        )));
    }
    Ok(signers)
}

/// WIST-3 §3.4: acts are evaluated in canonical Entry order. When the
/// accepted removals would leave no key valid at this height, the removal
/// at the highest Entry index is held back first.
fn evaluate_key_acts(
    base: &Registry,
    epoch_number: u64,
    acts: &[Value],
) -> Result<(Registry, Vec<Outcome>, Vec<usize>)> {
    let mut refused: Vec<usize> = Vec::new();
    loop {
        let mut registry = base.clone();
        let evaluated: Vec<usize> = (0..acts.len())
            .filter(|position| !refused.contains(position))
            .collect();
        let outcomes = registry.apply_epoch(epoch_number, evaluated.iter().map(|at| &acts[*at]));
        if !registry.valid_at(epoch_number).is_empty() {
            let mut dispositions = vec![Outcome::NotKeyAct; acts.len()];
            for (position, outcome) in evaluated.iter().zip(outcomes) {
                dispositions[*position] = outcome;
            }
            refused.sort_unstable();
            return Ok((registry, dispositions, refused));
        }
        let last_removal = evaluated
            .iter()
            .zip(&outcomes)
            .rev()
            .find(|(_, outcome)| {
                matches!(
                    outcome,
                    Outcome::Accepted {
                        action: KeyAction::Remove,
                        ..
                    }
                )
            })
            .map(|(position, _)| *position);
        match last_removal {
            Some(position) => refused.push(position),
            None => {
                return Err(Error::Seal(
                    "no Aggregator key is valid at this Epoch's height and no removal of it can be held back".into(),
                ))
            }
        }
    }
}

/// The code a Consumer replaying the Log would give (WIST-3 §3.4, WIST-4
/// §5.1).
fn key_act_refusal(update: &Value, outcome: &Outcome) -> String {
    let action = update["action"].as_str().unwrap_or("key act");
    let subject = update["subject"].as_str().unwrap_or("without a subject");
    let (code, reason) = match outcome {
        Outcome::Ignored { code, reason } => (*code, *reason),
        Outcome::Conflict { reason } => (aggregator_keys::KEY_ACT_CONFLICT_CODE, *reason),
        Outcome::Accepted { .. } | Outcome::NotKeyAct => ("", "the act is not a key act"),
    };
    format!("{code} {action} {subject} is not sealed: {reason}")
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enforce_governance(
    db: &Db,
    base_keys: &Registry,
    entries: Vec<SealEntry>,
    sealed_unix: i64,
    epoch_number: u64,
    epoch_bytes: u64,
) -> Result<GovernanceOutcome> {
    let mut schedule = db.parameter_schedule(sealed_unix)?;
    let largest = db.largest_epoch_bytes()?.max(epoch_bytes);
    let acts: Vec<Value> = entries
        .iter()
        .filter(|e| e.entry_type == "registry_update")
        .map(|e| e.body.clone())
        .collect();
    let (key_registry, dispositions, refused_removals) =
        evaluate_key_acts(base_keys, epoch_number, &acts)?;
    let sealing_keys = key_registry.valid_at(epoch_number);
    let public_key_of = |key_id: &str| {
        sealing_keys
            .iter()
            .find(|key| key.key_id == key_id)
            .map(|key| key.public_key.clone())
    };
    let mut out = GovernanceOutcome {
        kept: Vec::with_capacity(entries.len()),
        param_changes: Vec::new(),
        withdrawals: Vec::new(),
        suffix_lists: Vec::new(),
        dropped: Vec::new(),
        dropped_rowids: Vec::new(),
        key_registry,
    };
    let sealed_items = crate::governance::sealed_items(db)?;
    let mut replay = wist_core::withdrawal::WithdrawalReplay::new();
    for (item_id, domain, height) in db.withdrawal_state()? {
        replay.adopt(&item_id, &domain, height);
    }
    let mut suffix_replay = wist_core::suffix_list::SuffixListReplay::new();
    for (height, identifier) in db.suffix_list_acts()? {
        suffix_replay.adopt(&identifier, height);
    }
    let mut act_position = 0usize;
    for (index, e) in entries.into_iter().enumerate() {
        if e.entry_type != "registry_update" {
            out.kept.push(e);
            continue;
        }
        let position = act_position;
        act_position += 1;
        let update = e.body["update"].clone();
        match update["action"].as_str() {
            Some("aggregator_key_add") | Some("aggregator_key_remove") => {
                if refused_removals.contains(&position) {
                    out.dropped.push(format!(
                        "{} {} is not sealed: this Epoch's removals would leave no Aggregator key valid at height {epoch_number}",
                        update["action"].as_str().unwrap_or("key act"),
                        update["subject"].as_str().unwrap_or("without a subject")
                    ));
                    out.dropped_rowids.push(e.rowid);
                } else if dispositions[position].is_accepted() {
                    out.kept.push(e);
                } else {
                    out.dropped
                        .push(key_act_refusal(&update, &dispositions[position]));
                    out.dropped_rowids.push(e.rowid);
                }
            }
            Some("parameter_change") => {
                if aggregator_keys::authenticate(&e.body, &sealing_keys).is_err() {
                    out.dropped.push(format!(
                        "WIST4-E11 parameter_change {} is not sealed: no Aggregator key valid at height {epoch_number} signed it",
                        update["subject"].as_str().unwrap_or("without a subject")
                    ));
                    out.dropped_rowids.push(e.rowid);
                    continue;
                }
                match check_param_change(
                    &mut schedule,
                    &update,
                    sealed_unix,
                    epoch_number,
                    index as u64,
                    largest,
                ) {
                    Ok(mut change) => {
                        change.rowid = e.rowid;
                        change.body = e.body.clone();
                        out.param_changes.push(change);
                        out.kept.push(e);
                    }
                    Err(reason) => {
                        out.dropped.push(reason);
                        out.dropped_rowids.push(e.rowid);
                    }
                }
            }
            Some("payload_withdrawal") => {
                match check_withdrawal(
                    &mut replay,
                    public_key_of,
                    &e.body,
                    epoch_number,
                    &sealed_items,
                ) {
                    Ok(Some(withdrawal)) => {
                        out.withdrawals.push(withdrawal);
                        out.kept.push(e);
                    }
                    Ok(None) => out.kept.push(e),
                    Err(reason) => {
                        out.dropped.push(reason);
                        out.dropped_rowids.push(e.rowid);
                    }
                }
            }
            Some("suffix_list_update") => {
                use wist_core::suffix_list::{Disposition, HeldFile};
                match suffix_replay.apply(epoch_number, &e.body, public_key_of, |identifier| {
                    db.suffix_list_bytes(identifier)
                        .ok()
                        .flatten()
                        .map_or(HeldFile::Absent, HeldFile::Bytes)
                }) {
                    Disposition::Accepted {
                        identifier,
                        changed: true,
                        ..
                    } => {
                        out.suffix_lists.push(identifier);
                        out.kept.push(e);
                    }
                    Disposition::Accepted { .. } | Disposition::NotSuffixList => out.kept.push(e),
                    Disposition::Rejected(code) => {
                        out.dropped.push(format!(
                            "{code} suffix_list_update {} is not accepted",
                            update["subject"].as_str().unwrap_or("without a subject")
                        ));
                        out.dropped_rowids.push(e.rowid);
                    }
                }
            }
            _ => out.kept.push(e),
        }
    }
    Ok(out)
}

/// WIST-3 §6: an Epoch's octets, each Entry's JCS serialization plus two,
/// must not exceed the `epoch_cap_bytes` in force.
/// A Declaration packs by the nearest sealing deadline of itself and of those naming it, which
/// cannot seal before it.
pub(super) fn fit_to_cap(
    entries: Vec<SealEntry>,
    cap: i64,
    installed: &HashSet<String>,
    deadlines: &HashMap<String, u64>,
) -> Result<(Vec<SealEntry>, usize)> {
    let cap = u64::try_from(cap).map_err(|_| Error::Seal("invalid Epoch cap".into()))?;
    let named: HashMap<String, Option<String>> = entries
        .iter()
        .filter(|entry| entry.entry_type == "publisher_declaration")
        .filter_map(|entry| {
            crate::declaration::inner_hash(&entry.body)
                .ok()
                .map(|hash| {
                    let previous = entry.body["publisher"]["prev_declaration"]
                        .as_str()
                        .map(str::to_owned);
                    (hash, previous)
                })
        })
        .collect();
    let pending_declarations: HashSet<&String> = named.keys().collect();
    let mut nearest: HashMap<&String, u64> = HashMap::new();
    for (hash, deadline) in deadlines {
        let mut at = named.get_key_value(hash).map(|(hash, _)| hash);
        while let Some(hash) = at {
            let slot = nearest.entry(hash).or_insert(*deadline);
            *slot = (*slot).min(*deadline);
            at = named[hash]
                .as_ref()
                .and_then(|previous| named.get_key_value(previous))
                .map(|(hash, _)| hash);
        }
    }
    let mut entries = entries
        .into_iter()
        .map(|entry| {
            let declaration = if entry.entry_type == "publisher_declaration" {
                let publisher =
                    crate::declaration::publisher_of(&entry.body).map_err(Error::Seal)?;
                let deadline = crate::declaration::inner_hash(&entry.body)
                    .ok()
                    .and_then(|hash| nearest.get(&hash).copied())
                    .unwrap_or(u64::MAX);
                Some((deadline, publisher.domain, publisher.seq))
            } else {
                None
            };
            Ok((declaration, entry))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|(a_declaration, a), (b_declaration, b)| {
        entry_type_rank(&a.entry_type)
            .cmp(&entry_type_rank(&b.entry_type))
            .then_with(|| a_declaration.cmp(b_declaration))
            .then_with(|| a.leaf.cmp(&b.leaf))
    });
    let mut selected = installed.clone();
    let mut deferred_domains = HashSet::new();
    let mut used = 0u64;
    let mut kept = Vec::with_capacity(entries.len());
    let mut deferred = 0usize;
    for (_, e) in entries {
        let declaration_domain = (e.entry_type == "publisher_declaration")
            .then(|| e.body["publisher"]["domain"].as_str().unwrap_or_default());
        if declaration_domain.is_some_and(|domain| {
            deferred_domains.contains(domain)
                || e.body["publisher"]["prev_declaration"]
                    .as_str()
                    .is_some_and(|previous| {
                        pending_declarations.contains(&previous.to_owned())
                            && !selected.contains(previous)
                    })
        }) {
            deferred_domains.insert(declaration_domain.unwrap().to_string());
            deferred += 1;
            continue;
        }

        let size = e.octets();
        if size > cap - used {
            if let Some(domain) = declaration_domain {
                deferred_domains.insert(domain.to_string());
            }
            deferred += 1;
            continue;
        }
        if e.entry_type == "publisher_declaration" {
            if let Ok(hash) = crate::declaration::inner_hash(&e.body) {
                selected.insert(hash);
            }
        }
        used += size;
        kept.push(e);
    }
    kept.sort_by(|a, b| {
        entry_type_rank(&a.entry_type)
            .cmp(&entry_type_rank(&b.entry_type))
            .then_with(|| a.leaf.cmp(&b.leaf))
    });
    Ok((kept, deferred))
}

pub(super) struct SealEntry {
    pub(super) rowid: i64,
    pub(super) entry_type: String,
    pub(super) body: Value,
    pub(super) canonical: Vec<u8>,
    pub(super) leaf: [u8; 32],
}

impl SealEntry {
    /// The octets this Entry occupies in an entry bundle: its JCS
    /// serialization behind a two-octet length prefix (WIST-3 §6).
    pub(super) fn octets(&self) -> u64 {
        self.canonical.len() as u64 + 2
    }
}

pub(super) fn entry_type_rank(entry_type: &str) -> usize {
    ENTRY_TYPE_ORDER
        .iter()
        .position(|t| *t == entry_type)
        .unwrap_or(ENTRY_TYPE_ORDER.len())
}

fn seal_entry(rowid: i64, wrapped: Value) -> Result<SealEntry> {
    let canonical = jcs::canonicalize(&wrapped)?;
    let leaf = merkle::leaf_hash(&canonical);
    Ok(SealEntry {
        rowid,
        entry_type: wrapped["type"].as_str().unwrap_or_default().to_owned(),
        body: wrapped["body"].clone(),
        canonical,
        leaf,
    })
}

pub(super) fn storage_order(peeked: Vec<PendingEntryRow>) -> Result<Vec<SealEntry>> {
    let mut entries = peeked
        .into_iter()
        .map(|p| {
            seal_entry(
                p.rowid,
                serde_json::json!({"type": p.entry_type, "body": p.entry_json}),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|a, b| {
        entry_type_rank(&a.entry_type)
            .cmp(&entry_type_rank(&b.entry_type))
            .then_with(|| a.leaf.cmp(&b.leaf))
    });
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use crate::WIST_VERSION;

    #[test]
    fn domain_cap_counts_per_registrable_domain() {
        use crate::collection::state::{LabelKind, Place, WaitingLabel};
        let mut state = State::default();
        let signer = SigningKey::from_seed(&[3; 32]);
        for (index, labeler) in ["a.example.com", "b.example.com", "alice.github.io"]
            .into_iter()
            .enumerate()
        {
            let inner = serde_json::json!({"wist_version": WIST_VERSION, "labeler": labeler,
                "subject": "https://subject.example/", "name": "wist:spam",
                "asserted_at": "2026-08-09T00:00:00Z"});
            state.labels.insert(
                wist_core::label::label_id(&inner).unwrap(),
                WaitingLabel {
                    kind: LabelKind::Label,
                    publisher: labeler.into(),
                    envelope: sign_envelope(&inner, "label", "labeler-key", &signer).unwrap(),
                    place: Place::url(0, 0, index as u64),
                    eligibility: 0,
                },
            );
        }
        let mut parameters = Parameters::new(Default::default());
        parameters.set("domain_epoch_entries_max", 1);
        parameters.set("labeler_epoch_entries_max", 1);
        let list = wist_core::suffix_list::SuffixList::parse(b"com\ngithub.io\n").unwrap();
        let sealed = |suffix_list| {
            let planned = plan::plan(
                &state,
                &crate::collection::MemoryHeld::default(),
                &EpochInput {
                    height: 0,
                    sealed_at: "2026-08-09T01:00:00Z",
                    parameters: &parameters,
                    inclusion: &Inclusion::constant(24),
                    suffix_list,
                    declarations: &[],
                    updates: &[],
                    unsealed: &BTreeSet::new(),
                    log_key: &|_| None,
                },
            )
            .unwrap();
            let mut labelers: Vec<String> = planned
                .entries
                .iter()
                .map(|entry| {
                    entry["body"]["label"]["labeler"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect();
            labelers.sort();
            labelers
        };
        assert_eq!(sealed(None).len(), 3);
        assert_eq!(sealed(Some(&list)), ["a.example.com", "alice.github.io"]);
    }

    use super::*;

    #[test]
    fn packing_counts_each_entry_as_its_jcs_octets_plus_a_length_prefix() {
        let sk = SigningKey::from_seed(&[42; 32]);
        let entries = |count| {
            storage_order(
                (0..count)
                    .map(|i| {
                        let update = serde_json::json!({"wist_version":WIST_VERSION,
                    "action":"parameter_change","subject":"clock_skew_seconds",
                    "details":{"parameter":"clock_skew_seconds","value":i},
                    "effective_at":"2026-09-17T00:00:00Z"});
                        PendingEntryRow {
                            rowid: i + 1,
                            entry_type: "registry_update".into(),
                            domain: String::new(),
                            entry_json: sign_envelope(
                                &update,
                                "update",
                                crate::keys::GENESIS_KEY_ID,
                                &sk,
                            )
                            .unwrap(),
                            turn_epoch: None,
                        }
                    })
                    .collect(),
            )
            .unwrap()
        };
        for count in [9, 10, 99, 100] {
            let all = entries(count);
            let size: u64 = all.iter().map(|e| e.canonical.len() as u64 + 2).sum();
            assert_eq!(size, all.iter().map(SealEntry::octets).sum::<u64>());
            let (fit, deferred) =
                fit_to_cap(all, size as i64, &HashSet::new(), &HashMap::new()).unwrap();
            assert_eq!(fit.len(), count as usize);
            assert_eq!(deferred, 0);
            let (fit, deferred) = fit_to_cap(
                entries(count),
                size as i64 - 1,
                &HashSet::new(),
                &HashMap::new(),
            )
            .unwrap();
            assert_eq!(fit.len(), count as usize - 1);
            assert_eq!(deferred, 1);
        }
    }
}
