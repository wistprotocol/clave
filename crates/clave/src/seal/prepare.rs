use super::{ENTRY_TYPE_ORDER, GENESIS_KEY_ID};
use crate::db::{Db, PendingEntryRow};
use crate::error::{Error, Result};
use crate::history::declarations::DeclarationsReplay;
use crate::history::declarations::{Declarations, Projection};
use crate::history::History;
use crate::registry;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::objects::ChangeType;
use wist_core::{jcs, merkle, tiles};

/// One Epoch prepared for publication: its Checkpoint, the leaves it
/// appends to the tree, the rows its commit writes and the effects its
/// publication applies.
pub(super) struct PreparedEpoch {
    pub(super) log_id: String,
    pub(super) entries: Vec<Value>,
    pub(super) octets: u64,
    pub(super) epoch_number: u64,
    pub(super) sealed_at: String,
    pub(super) seal_entries: Vec<SealEntry>,
    pub(super) sealed_rowids: Vec<i64>,
    pub(super) accepted_changes: Vec<AcceptedParamChange>,
    pub(super) withdrawals: Vec<OwnedWithdrawal>,
    pub(super) suffix_lists: Vec<String>,
    pub(super) dropped: Vec<String>,
    pub(super) late: Vec<String>,
    pub(super) entry_count: u64,
    pub(super) projection: Projection,
    pub(super) windows: Vec<SealedWindow>,
    pub(super) record_updates: Vec<OwnedRecordUpsert>,
}

/// A recovery window open after this Epoch, as the sealed-window row
/// records it (WIST-1 §5.2).
pub(super) struct SealedWindow {
    pub(super) domain: String,
    pub(super) head: Vec<u8>,
    pub(super) before: Vec<u8>,
    pub(super) owner: Vec<u8>,
    pub(super) opened_epoch: u64,
    pub(super) window_end: String,
}

/// Prepares the next Epoch at the cadence slot `now_unix` falls in:
/// replays the history, settles and diverts recovery, orders and bounds
/// the pending Entries, revalidates them and applies governance, then
/// signs the Epoch. Writes only the diversions, settlements and
/// retirements the preparation itself decides.
pub(super) fn epoch(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    now_unix: i64,
) -> Result<PreparedEpoch> {
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

    let mut history = History::open(db, data_dir, db.last_epoch()?)?;
    let mut declarations = Declarations::default();
    while let Some(epoch) = history.next_epoch()? {
        declarations.apply(&epoch)?;
    }
    for (domain, state) in declarations.domains() {
        if let Some(window) = state.window() {
            if window.end_s() > i128::from(sealed_unix)
                && db.recovery_settled(domain, window.owner().hash())?
            {
                return Err(Error::Seal(
                    "cadence slot predates completed recovery settlement".into(),
                ));
            }
        }
    }
    let recovery_days = history
        .schedule()
        .and_then(|schedule| schedule.value_at("recovery_window_days", sealed_unix))
        .unwrap_or_else(|| {
            registry::spec("recovery_window_days")
                .unwrap()
                .default
                .unwrap()
        });
    let activation_epochs = history
        .schedule()
        .and_then(|schedule| schedule.value_at("declaration_activation_epochs", sealed_unix))
        .unwrap_or_else(|| {
            registry::spec("declaration_activation_epochs")
                .unwrap()
                .default
                .unwrap()
        });
    crate::recovery::settle_due(db, &declarations, &sealed_at)?;
    divert_recovery_deltas(
        db,
        &declarations
            .domains()
            .iter()
            .filter(|(_, state)| {
                state
                    .window()
                    .is_some_and(|window| window.end_s() > i128::from(sealed_unix))
            })
            .map(|(domain, _)| domain.as_str())
            .collect(),
    )?;
    let settlement = declarations.project(&sealed_at, recovery_days, activation_epochs, &[])?;

    let (peeked, _up_to_rowid) = db.peek_pending_entries()?;
    let domain_cap = registry::effective(db, "domain_epoch_entries_max", &sealed_at)?;
    let labeler_cap = registry::effective(db, "labeler_epoch_entries_max", &sealed_at)?;
    let peeked = fit_to_domain_cap(db, peeked, domain_cap, labeler_cap, epoch_number)?;
    let (seal_entries, oversized) = hold_out_oversize_entries(storage_order(peeked)?);
    let schedule = db.parameter_schedule(sealed_unix)?;
    let mut cap = registry::epoch_cap(&schedule, sealed_unix).min(registry::effective(
        db,
        "epoch_cap_bytes",
        &sealed_at,
    )?);
    let mut tentative = schedule.clone();
    let largest = db.largest_epoch_bytes()?;
    for (index, entry) in seal_entries.iter().enumerate() {
        let update = &entry.body["update"];
        if entry.entry_type == "registry_update"
            && update["action"] == "parameter_change"
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
    let installed = settlement
        .domains()
        .values()
        .flat_map(|state| {
            std::iter::once(state.current().hash().to_string()).chain(
                state
                    .window()
                    .map(|window| window.head().hash().to_string()),
            )
        })
        .collect();
    let (seal_entries, _deferred) = fit_to_cap(seal_entries, cap, &installed)?;
    let projection = declarations.project(
        &sealed_at,
        recovery_days,
        activation_epochs,
        &seal_entries
            .iter()
            .map(|entry| entry.wrapped.clone())
            .collect::<Vec<_>>(),
    )?;
    let recovering: HashSet<_> = projection
        .domains()
        .iter()
        .filter(|(_, state)| state.window().is_some())
        .map(|(domain, _)| domain.as_str())
        .collect();
    divert_recovery_deltas(db, &recovering)?;
    let seal_entries = seal_entries
        .into_iter()
        .filter(|entry| {
            entry.entry_type != "publisher_delta" || !recovering.contains(entry.domain.as_str())
        })
        .collect();
    let default_schedule = wist_core::parameters::Schedule::new(sealed_unix);
    let sealing_schedule = history.schedule().unwrap_or(&default_schedule);
    let size_caps =
        crate::declaration::delta::SizeCaps::from_schedule(sealing_schedule, sealed_unix);
    let clock_skew_seconds = sealing_schedule
        .value_at("clock_skew_seconds", sealed_unix)
        .unwrap();
    let (seal_entries, retired_rowids, retired) = revalidate_queued_deltas(
        db,
        data_dir,
        &size_caps,
        clock_skew_seconds,
        seal_entries,
        &sealed_at,
        &projection,
    )?;
    let ceiling = registry::effective(db, "max_inclusion_epochs", &sealed_at)?;
    let late = late_inclusions(&seal_entries, epoch_number, ceiling);
    let candidate_octets = seal_entries.iter().map(SealEntry::octets).sum();
    let mut outcome = enforce_governance(
        db,
        &sk.public(),
        history.log_id(),
        seal_entries,
        sealed_unix,
        epoch_number,
        candidate_octets,
    )?;
    outcome.dropped.extend(retired);
    outcome.dropped_rowids.extend(retired_rowids);
    outcome.dropped.extend(oversized.iter().map(|e| {
        format!(
            "WIST3-E03 {} Entry of {} over 65 535 octets is not sealed",
            e.entry_type, e.domain
        )
    }));
    outcome
        .dropped_rowids
        .extend(oversized.iter().map(|e| e.rowid));
    let GovernanceOutcome {
        kept: seal_entries,
        param_changes: accepted_changes,
        withdrawals,
        suffix_lists,
        dropped,
        dropped_rowids,
    } = outcome;
    let sealed_rowids: Vec<i64> = seal_entries
        .iter()
        .map(|e| e.rowid)
        .chain(dropped_rowids.iter().copied())
        .collect();
    let entries: Vec<Value> = seal_entries.iter().map(|e| e.wrapped.clone()).collect();
    let octets: u64 = seal_entries.iter().map(SealEntry::octets).sum();
    let entry_count = entries.len() as u64;
    if octets > cap.max(0) as u64 {
        return Err(Error::Seal(
            "the Epoch's entry-bundle octets exceed epoch_cap_bytes".into(),
        ));
    }
    let projection =
        declarations.project(&sealed_at, recovery_days, activation_epochs, &entries)?;
    let windows = projection
        .domains()
        .iter()
        .filter_map(|(domain, state)| {
            state.window().map(|window| {
                let window_end = i64::try_from(window.end_s())
                    .ok()
                    .and_then(|end| crate::registry::instant(end).ok())
                    .ok_or_else(|| {
                        Error::Seal("recovery window end exceeds the Log timestamp range".into())
                    })?;
                Ok(SealedWindow {
                    domain: domain.clone(),
                    head: serde_json::to_vec(window.head().envelope())?,
                    before: serde_json::to_vec(window.before().envelope())?,
                    owner: serde_json::to_vec(window.owner().envelope())?,
                    opened_epoch: window.owner().position().epoch_number,
                    window_end,
                })
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let record_updates = resolve_record_updates(data_dir, &size_caps, &seal_entries)?;

    Ok(PreparedEpoch {
        log_id: history.log_id().to_owned(),
        entries,
        octets,
        epoch_number,
        sealed_at,
        seal_entries,
        sealed_rowids,
        accepted_changes,
        withdrawals,
        suffix_lists,
        dropped,
        late,
        entry_count,
        projection,
        windows,
        record_updates,
    })
}

pub(super) struct AcceptedParamChange {
    pub(super) rowid: i64,
    pub(super) parameter: String,
    pub(super) value: i64,
    pub(super) effective_at: String,
}

pub(super) struct OwnedWithdrawal {
    pub(super) update_id: String,
    pub(super) delta_id: String,
    pub(super) domain: String,
}

pub(super) struct GovernanceOutcome {
    pub(super) kept: Vec<SealEntry>,
    pub(super) param_changes: Vec<AcceptedParamChange>,
    pub(super) withdrawals: Vec<OwnedWithdrawal>,
    pub(super) suffix_lists: Vec<String>,
    pub(super) dropped: Vec<String>,
    pub(super) dropped_rowids: Vec<i64>,
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
    let (mut pending, _) = db.peek_pending_entries()?;
    let rowid = pending.iter().map(|p| p.rowid).max().unwrap_or(0) + 1;
    pending.push(PendingEntryRow {
        rowid,
        entry_type: "registry_update".into(),
        domain: String::new(),
        entry_json: sign_envelope(update, "update", GENESIS_KEY_ID, sk)?,
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

/// WIST-2 §5 step 4: a queued Delta is sealed only where it verifies
/// under the Key Set WIST-1 §5.2 resolves at the sealing Epoch — the
/// highest-`seq` Declaration sealed at a height at or below it, this
/// Epoch's own Declarations included (WIST-3 §3.2 applies them first).
/// One whose signing key a Declaration accepted since the pull has
/// retired is WIST1-E02, reported and not sealed.
/// WIST-3 §3.2: an Epoch MUST NOT carry more than
/// `domain_epoch_entries_max` `publisher_delta`, `label` and `dispute`
/// Entries of one Registrable Domain under the snapshot in force at it
/// (WIST-4 §3.1), nor more than `labeler_epoch_entries_max` `label` and
/// `dispute` Entries of one. The surplus waits its turn in acceptance
/// order, and WIST-4 §6.4's inclusion ceiling runs from the Epoch an
/// Entry's turn arrives in — the first with room for it — which is
/// recorded here.
pub(super) fn fit_to_domain_cap(
    db: &Db,
    peeked: Vec<PendingEntryRow>,
    cap: i64,
    labeler_cap: i64,
    epoch_number: u64,
) -> Result<Vec<PendingEntryRow>> {
    let cap = cap.max(0) as usize;
    let labeler_cap = labeler_cap.max(0) as usize;
    let list = crate::suffix_list::in_force_at_epoch(db, epoch_number)?;
    let mut taken: HashMap<String, usize> = HashMap::new();
    let mut labeled: HashMap<String, usize> = HashMap::new();
    let mut kept = Vec::with_capacity(peeked.len());
    for p in peeked {
        if !matches!(
            p.entry_type.as_str(),
            "publisher_delta" | "label" | "dispute"
        ) {
            kept.push(p);
            continue;
        }
        let unit = wist_core::suffix_list::registrable_domain(&p.domain, list.as_deref()).domain;
        let count = taken.entry(unit.clone()).or_insert(0);
        if *count >= cap {
            continue;
        }
        if p.entry_type != "publisher_delta" {
            let opinions = labeled.entry(unit).or_insert(0);
            if *opinions >= labeler_cap {
                continue;
            }
            *opinions += 1;
        }
        *count += 1;
        db.set_turn_epoch(p.rowid, epoch_number)?;
        kept.push(p);
    }
    Ok(kept)
}

/// WIST-4 §6.4: an accepted Delta MUST be sealed no later than
/// `max_inclusion_epochs` Epochs after the Epoch its turn arrived in.
pub(super) fn late_inclusions(
    entries: &[SealEntry],
    epoch_number: u64,
    ceiling: i64,
) -> Vec<String> {
    let ceiling = ceiling.max(0) as u64;
    entries
        .iter()
        .filter(|e| {
            matches!(
                e.entry_type.as_str(),
                "publisher_delta" | "label" | "dispute"
            )
        })
        .filter_map(|e| {
            let turn = e.turn_epoch?;
            (epoch_number > turn + ceiling).then(|| {
                format!(
                    "{}: sealed at Epoch {epoch_number}, {} Epochs after its turn at {turn}",
                    e.domain,
                    epoch_number - turn
                )
            })
        })
        .collect()
}

pub(super) fn divert_recovery_deltas(db: &Db, domains: &HashSet<&str>) -> Result<()> {
    for entry in db.peek_pending_entries()?.0 {
        if entry.entry_type != "publisher_delta" || !domains.contains(entry.domain.as_str()) {
            continue;
        }
        db.requeue_pending_delta(&entry)?;
    }
    Ok(())
}

pub(super) fn revalidate_queued_deltas(
    db: &Db,
    data_dir: &Path,
    size_caps: &crate::declaration::delta::SizeCaps,
    clock_skew_seconds: i64,
    entries: Vec<SealEntry>,
    sealed_at: &str,
    projection: &Projection,
) -> Result<(Vec<SealEntry>, Vec<i64>, Vec<String>)> {
    let clock = sealed_at
        .parse::<jiff::Timestamp>()
        .map_err(|e| Error::Clock(e.to_string()))?;
    let sources = projection
        .domains()
        .iter()
        .filter_map(|(domain, state)| {
            state.delta_sealing_source().map(|source| {
                crate::declaration::publisher_of(source.envelope())
                    .map(|publisher| (domain.clone(), publisher))
                    .map_err(Error::History)
            })
        })
        .collect::<Result<HashMap<_, _>>>()?;

    let mut kept = Vec::with_capacity(entries.len());
    let mut dropped_rowids = Vec::new();
    let mut dropped = Vec::new();
    let mut rejections = std::collections::BTreeMap::<String, Vec<(Value, &str)>>::new();
    for e in entries {
        if e.entry_type != "publisher_delta" {
            kept.push(e);
            continue;
        }
        let source: Vec<_> = sources.get(&e.domain).into_iter().collect();
        let verified = crate::declaration::delta_publisher(&e.body)
            .and_then(|domain| {
                if domain == e.domain {
                    Ok(())
                } else {
                    Err("WIST1-E02")
                }
            })
            .and_then(|()| crate::declaration::verify_delta_authority(&source, &e.body));
        let code = match verified {
            Ok(()) => {
                let sizes = size_caps.validate_delta(&e.body).and_then(|()| {
                    crate::declaration::verify_delta_clock(&e.body, clock, clock_skew_seconds)
                });
                let sizes = match sizes {
                    Ok(()) if e.body["delta"].get("payload").is_some() => {
                        let id = wist_core::delta::delta_id(&e.body["delta"])?;
                        let bytes =
                            std::fs::read(data_dir.join(format!("payloads/{}.json", &id[7..])))?;
                        let payload: Value = crate::json::parse(&bytes)?;
                        let delta: wist_core::objects::Delta =
                            serde_json::from_slice(&jcs::canonicalize(&e.body["delta"])?)?;
                        match crate::payload::validate(
                            &payload,
                            delta.payload.as_ref().unwrap(),
                            &delta.publisher,
                            size_caps,
                        ) {
                            Ok(_) => Ok(()),
                            Err("WIST1-E04") => Err("WIST1-E04"),
                            Err(code) => {
                                return Err(Error::Seal(format!(
                                    "retained Payload {id} failed validation: {code}"
                                )));
                            }
                        }
                    }
                    result => result,
                };
                match sizes {
                    Ok(()) => {
                        kept.push(e);
                        continue;
                    }
                    Err(code) => code,
                }
            }
            Err(code @ ("WIST1-E14" | "WIST1-E03" | "WIST1-E15")) => code,
            Err(_) => "WIST1-E02",
        };
        rejections
            .entry(e.domain.clone())
            .or_default()
            .push((e.body, code));
        dropped_rowids.push(e.rowid);
    }
    for (domain, rejected) in rejections {
        dropped.extend(db.reject_delta_copies(&domain, &rejected, sealed_at)?);
    }
    let retained: HashSet<_> = db
        .peek_pending_entries()?
        .0
        .into_iter()
        .map(|entry| entry.rowid)
        .collect();
    kept.retain(|entry| retained.contains(&entry.rowid));
    Ok((kept, dropped_rowids, dropped))
}

/// WIST-4 §5.1 through core's withdrawal replay: the act must verify under
/// the Log key and name a Delta sealed at or below this Epoch — one this
/// Epoch seals or one the store already holds — whose signed publisher is
/// the subject; a failing act is dropped with its code, and a repeated
/// withdrawal seals and changes nothing.
fn check_withdrawal(
    db: &Db,
    replay: &mut wist_core::withdrawal::WithdrawalReplay,
    log_key: &wist_core::crypto::PublicKey,
    body: &Value,
    epoch_number: u64,
    epoch_deltas: &HashMap<String, String>,
) -> std::result::Result<Option<OwnedWithdrawal>, String> {
    use wist_core::withdrawal::{Disposition, SealedDelta};
    let subject = body["update"]["subject"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let lookup = |delta_id: &str| match epoch_deltas.get(delta_id) {
        Some(publisher) => SealedDelta::Known {
            publisher: publisher.clone(),
            height: epoch_number,
        },
        None => match db.is_delta_sealed_for(delta_id, &subject) {
            Ok(true) => SealedDelta::Known {
                publisher: subject.clone(),
                height: epoch_number,
            },
            _ => SealedDelta::Absent,
        },
    };
    match replay.apply(
        epoch_number,
        body,
        |key_id| (key_id == GENESIS_KEY_ID).then(|| log_key.clone()),
        lookup,
    ) {
        Disposition::Accepted {
            delta_id,
            publisher,
            ..
        } => Ok(Some(OwnedWithdrawal {
            update_id: crate::governance::update_id(&body["update"]).map_err(|e| e.to_string())?,
            delta_id,
            domain: publisher,
        })),
        Disposition::Rejected(code) => Err(format!(
            "{code} payload_withdrawal {} is not sealed",
            body["update"]["details"]["delta_id"]
                .as_str()
                .unwrap_or("without a Delta ID")
        )),
        Disposition::NotWithdrawal => Ok(None),
    }
}

/// WIST-3 §3.4: an Aggregator key signs a Checkpoint as a signed-note
/// signer whose note key ID a Consumer maps back to a `key_id`, so an
/// `aggregator_key_add` whose note key ID equals that of any key already
/// admitted — the genesis key included — is never sealed. This Log seals
/// no key transition at all, because its replay reads every Checkpoint
/// under the genesis key; the collision is reported separately from that
/// refusal so the reason a Consumer would reject the act is the reason
/// the Aggregator gives.
fn refuse_aggregator_key_add(admitted: &[String], log_id: &str, update: &Value) -> String {
    let details = &update["details"];
    let (Some(key_id), Some(public_key)) =
        (details["key_id"].as_str(), details["public_key"].as_str())
    else {
        return "WIST4-E04 aggregator_key_add without a key_id and public_key".into();
    };
    let collides = details["alg"] == "Ed25519"
        && wist_core::crypto::PublicKey::from_b64u(public_key).is_ok_and(|key| {
            admitted.contains(&hex_encode(&wist_core::checkpoint::aggregator_key_id(
                log_id, &key,
            )))
        });
    if collides {
        return format!(
            "WIST3-E03 aggregator_key_add {key_id} collides with an admitted key's note key ID"
        );
    }
    format!("aggregator_key_add {key_id} is not sealed: this Log signs every Checkpoint under its genesis key")
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enforce_governance(
    db: &Db,
    log_key: &wist_core::crypto::PublicKey,
    log_id: &str,
    entries: Vec<SealEntry>,
    sealed_unix: i64,
    epoch_number: u64,
    epoch_bytes: u64,
) -> Result<GovernanceOutcome> {
    let mut schedule = db.parameter_schedule(sealed_unix)?;
    let largest = db.largest_epoch_bytes()?.max(epoch_bytes);
    let mut admitted = db.admitted_note_key_ids()?;
    if admitted.is_empty() {
        admitted.push(hex_encode(&wist_core::checkpoint::aggregator_key_id(
            log_id, log_key,
        )));
    }
    let mut out = GovernanceOutcome {
        kept: Vec::with_capacity(entries.len()),
        param_changes: Vec::new(),
        withdrawals: Vec::new(),
        suffix_lists: Vec::new(),
        dropped: Vec::new(),
        dropped_rowids: Vec::new(),
    };
    let epoch_deltas: HashMap<String, String> = entries
        .iter()
        .filter(|e| e.entry_type == "publisher_delta")
        .map(|e| {
            Ok((
                wist_core::delta::delta_id(&e.body["delta"])?,
                e.domain.clone(),
            ))
        })
        .collect::<Result<_>>()?;
    let mut replay = wist_core::withdrawal::WithdrawalReplay::new();
    for (delta_id, domain, height) in db.withdrawal_state()? {
        replay.adopt(&delta_id, &domain, height);
    }
    let mut suffix_replay = wist_core::suffix_list::SuffixListReplay::new();
    for (height, identifier) in db.suffix_list_acts()? {
        suffix_replay.adopt(&identifier, height);
    }
    for (index, e) in entries.into_iter().enumerate() {
        if e.entry_type != "registry_update" {
            out.kept.push(e);
            continue;
        }
        let update = e.body["update"].clone();
        match update["action"].as_str() {
            Some("parameter_change") => match check_param_change(
                &mut schedule,
                &update,
                sealed_unix,
                epoch_number,
                index as u64,
                largest,
            ) {
                Ok(mut change) => {
                    change.rowid = e.rowid;
                    out.param_changes.push(change);
                    out.kept.push(e);
                }
                Err(reason) => {
                    out.dropped.push(reason);
                    out.dropped_rowids.push(e.rowid);
                }
            },
            Some("payload_withdrawal") => {
                match check_withdrawal(
                    db,
                    &mut replay,
                    log_key,
                    &e.body,
                    epoch_number,
                    &epoch_deltas,
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
                match suffix_replay.apply(
                    epoch_number,
                    &e.body,
                    |key_id| (key_id == GENESIS_KEY_ID).then(|| log_key.clone()),
                    |identifier| {
                        db.suffix_list_bytes(identifier)
                            .ok()
                            .flatten()
                            .map_or(HeldFile::Absent, HeldFile::Bytes)
                    },
                ) {
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
            Some("aggregator_key_add") => {
                out.dropped
                    .push(refuse_aggregator_key_add(&admitted, log_id, &update));
                out.dropped_rowids.push(e.rowid);
            }
            _ => out.kept.push(e),
        }
    }
    Ok(out)
}

/// WIST-3 §6: an Epoch's size is the octets its Entries occupy in entry
/// bundles — each Entry's JCS serialization plus two — and it must not
/// exceed the `epoch_cap_bytes` in force.
pub(super) fn fit_to_cap(
    entries: Vec<SealEntry>,
    cap: i64,
    installed: &HashSet<String>,
) -> Result<(Vec<SealEntry>, usize)> {
    let cap = u64::try_from(cap).map_err(|_| Error::Seal("invalid Epoch cap".into()))?;
    let pending_declarations: HashSet<_> = entries
        .iter()
        .filter(|entry| entry.entry_type == "publisher_declaration")
        .filter_map(|entry| crate::declaration::inner_hash(&entry.body).ok())
        .collect();
    let mut entries = entries
        .into_iter()
        .map(|entry| {
            let declaration = if entry.entry_type == "publisher_declaration" {
                let publisher =
                    crate::declaration::publisher_of(&entry.body).map_err(Error::Seal)?;
                Some((publisher.domain, publisher.seq))
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
                        pending_declarations.contains(previous) && !selected.contains(previous)
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
    pub(super) domain: String,
    pub(super) body: Value,
    pub(super) wrapped: Value,
    pub(super) canonical: Vec<u8>,
    pub(super) leaf: [u8; 32],
    pub(super) turn_epoch: Option<u64>,
}

impl SealEntry {
    /// The octets this Entry occupies in an entry bundle: its JCS
    /// serialization behind a two-octet length prefix (WIST-3 §6).
    pub(super) fn octets(&self) -> u64 {
        self.canonical.len() as u64 + 2
    }
}

/// WIST-3 §3.3: an Entry whose JCS serialization exceeds 65 535 octets
/// does not fit a leaf of an entry bundle and is never sealed. It is
/// held out of the Epoch here, the last point at which the Aggregator
/// still decides membership, and reported with the Epoch's drops.
pub(super) fn hold_out_oversize_entries(
    entries: Vec<SealEntry>,
) -> (Vec<SealEntry>, Vec<SealEntry>) {
    entries
        .into_iter()
        .partition(|entry| entry.canonical.len() as u64 <= tiles::ENTRY_MAX_BYTES)
}

pub(super) struct DeltaApply {
    body: Value,
    id: String,
    prev: Option<String>,
}

pub(super) struct OwnedRecordUpsert {
    pub(super) url: String,
    pub(super) publisher: String,
    pub(super) delta_id: String,
    pub(super) observed_at: String,
    pub(super) title: String,
    pub(super) abstract_text: Option<String>,
    pub(super) lang: String,
}

pub(super) fn entry_type_rank(entry_type: &str) -> usize {
    ENTRY_TYPE_ORDER
        .iter()
        .position(|t| *t == entry_type)
        .unwrap_or(ENTRY_TYPE_ORDER.len())
}

pub(super) fn storage_order(peeked: Vec<PendingEntryRow>) -> Result<Vec<SealEntry>> {
    let mut entries = peeked
        .into_iter()
        .map(|p| {
            let wrapped = serde_json::json!({"type": p.entry_type, "body": p.entry_json});
            let canonical = jcs::canonicalize(&wrapped)?;
            let leaf = merkle::leaf_hash(&canonical);
            Ok(SealEntry {
                rowid: p.rowid,
                entry_type: p.entry_type,
                domain: p.domain,
                body: p.entry_json,
                wrapped,
                canonical,
                leaf,
                turn_epoch: p.turn_epoch,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|a, b| {
        entry_type_rank(&a.entry_type)
            .cmp(&entry_type_rank(&b.entry_type))
            .then_with(|| a.leaf.cmp(&b.leaf))
    });
    Ok(entries)
}

pub(super) fn chain_order(mut remaining: Vec<DeltaApply>) -> Vec<DeltaApply> {
    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let ids: HashSet<String> = remaining.iter().map(|d| d.id.clone()).collect();
        let mut blocked = Vec::with_capacity(remaining.len());
        let mut progressed = false;
        for d in remaining {
            if d.prev.as_deref().is_some_and(|p| ids.contains(p)) {
                blocked.push(d);
            } else {
                progressed = true;
                ordered.push(d);
            }
        }
        if !progressed {
            ordered.extend(blocked);
            break;
        }
        remaining = blocked;
    }
    ordered
}

pub(super) fn resolve_record_updates(
    data_dir: &Path,
    size_caps: &crate::declaration::delta::SizeCaps,
    seal_entries: &[SealEntry],
) -> Result<Vec<OwnedRecordUpsert>> {
    let mut deltas = Vec::new();
    for e in seal_entries {
        if e.entry_type != "publisher_delta" {
            continue;
        }
        let id = wist_core::delta::delta_id(&e.body["delta"])?;
        let prev = e.body["delta"]["prev"].as_str().map(str::to_string);
        deltas.push(DeltaApply {
            body: e.body.clone(),
            id,
            prev,
        });
    }

    let mut updates = Vec::new();
    for d in chain_order(deltas) {
        let delta: wist_core::objects::Delta =
            serde_json::from_slice(&jcs::canonicalize(&d.body["delta"])?)?;
        if !matches!(delta.change_type, ChangeType::New | ChangeType::Update)
            || delta.payload.is_none()
        {
            continue;
        }
        let hex = d.id.strip_prefix("sha256:").unwrap_or(&d.id);
        let payload_path = data_dir.join("payloads").join(format!("{hex}.json"));
        let payload_bytes = std::fs::read(&payload_path)?;
        let payload_value = crate::json::parse(&payload_bytes)?;
        let payload = crate::payload::validate(
            &payload_value,
            delta.payload.as_ref().unwrap(),
            &delta.publisher,
            size_caps,
        )
        .map_err(|code| {
            Error::Seal(format!(
                "retained Payload {} failed validation: {code}",
                d.id
            ))
        })?;
        updates.push(OwnedRecordUpsert {
            url: delta.url,
            publisher: delta.publisher,
            delta_id: d.id,
            observed_at: delta.observed_at,
            title: payload.content.summary.title,
            abstract_text: payload.content.summary.r#abstract,
            lang: delta.meta.lang,
        });
    }
    Ok(updates)
}

#[cfg(test)]
mod tests {
    use crate::WIST_VERSION;

    #[test]
    fn domain_cap_counts_per_registrable_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        let list = b"com\ngithub.io\n";
        let identifier = wist_core::suffix_list::identifier(list);
        db.store_suffix_list(&identifier, list).unwrap();
        db.commit_seal(
            &crate::db::tests::signing_key(),
            crate::db::tests::LOG_ID,
            &[],
            0,
            "2026-08-09T00:00:00Z",
            &[],
            0,
            &[],
            &[],
            &[],
            std::slice::from_ref(&identifier),
            &[],
            &[],
            &[],
        )
        .unwrap();
        for domain in ["a.example.com", "b.example.com", "alice.github.io"] {
            db.insert_pending_entry("publisher_delta", domain, &serde_json::json!({}), 0)
                .unwrap();
        }
        let peeked = db.peek_pending_entries().unwrap().0;
        let under_none = fit_to_domain_cap(&db, peeked, 1, 1, 0).unwrap();
        assert_eq!(under_none.len(), 3);
        let peeked = db.peek_pending_entries().unwrap().0;
        let under_list = fit_to_domain_cap(&db, peeked, 1, 1, 1).unwrap();
        let kept: Vec<&str> = under_list.iter().map(|p| p.domain.as_str()).collect();
        assert_eq!(kept, ["a.example.com", "alice.github.io"]);
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
                            entry_json: sign_envelope(&update, "update", GENESIS_KEY_ID, &sk)
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
            let size: u64 = all
                .iter()
                .map(|e| jcs::canonicalize(&e.wrapped).unwrap().len() as u64 + 2)
                .sum();
            assert_eq!(size, all.iter().map(SealEntry::octets).sum::<u64>());
            let (fit, deferred) = fit_to_cap(all, size as i64, &HashSet::new()).unwrap();
            assert_eq!(fit.len(), count as usize);
            assert_eq!(deferred, 0);
            let (fit, deferred) =
                fit_to_cap(entries(count), size as i64 - 1, &HashSet::new()).unwrap();
            assert_eq!(fit.len(), count as usize - 1);
            assert_eq!(deferred, 1);
        }
    }
}
