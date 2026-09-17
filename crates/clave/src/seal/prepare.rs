use super::{ENTRY_TYPE_ORDER, GENESIS_KEY_ID};
use crate::db::{Db, PendingEntryRow};
use crate::error::{Error, Result};
use crate::history::declarations::DeclarationsReplay;
use crate::history::declarations::{Declarations, Projection};
use crate::history::History;
use crate::registry;
use crate::WIST_VERSION;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::objects::{Block, BlockHeader, ChangeType, Sig};
use wist_core::{jcs, merkle};

/// One Block prepared for publication: the signed Block, the rows its
/// commit writes and the effects its publication applies.
pub(super) struct PreparedBlock {
    pub(super) block: Block,
    pub(super) block_hash: String,
    pub(super) block_number: u64,
    pub(super) sealed_at: String,
    pub(super) cap: i64,
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

/// A recovery window open after this Block, as the sealed-window row
/// records it (WIST-1 §5.2).
pub(super) struct SealedWindow {
    pub(super) domain: String,
    pub(super) head: Vec<u8>,
    pub(super) before: Vec<u8>,
    pub(super) owner: Vec<u8>,
    pub(super) opened_block: u64,
    pub(super) window_end: String,
}

/// Prepares the next Block at the cadence slot `now_epoch` falls in:
/// replays the history, settles and diverts recovery, orders and bounds
/// the pending Entries, revalidates them and applies governance, then
/// signs the Block. Writes only the diversions, settlements and
/// retirements the preparation itself decides.
pub(super) fn block(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    now_epoch: i64,
) -> Result<PreparedBlock> {
    let now_at = jiff::Timestamp::from_second(now_epoch)
        .map_err(|_| Error::Seal("now out of range".into()))?
        .to_string();
    let prev = db.last_block()?;
    let cadence = registry::effective(
        db,
        "block_cadence_seconds",
        prev.as_ref()
            .map_or(now_at.as_str(), |p| p.sealed_at.as_str()),
    )?;
    if cadence <= 0 {
        return Err(Error::Seal("block_cadence_seconds must be positive".into()));
    }
    let sealed_epoch = now_epoch.div_euclid(cadence) * cadence;
    let sealed_at = jiff::Timestamp::from_second(sealed_epoch)
        .map_err(|_| Error::Seal("sealed_at out of range".into()))?
        .to_string();

    let (block_number, prev_block_hash) = match &prev {
        Some(p) => {
            if sealed_at.as_str() <= p.sealed_at.as_str() {
                return Err(Error::Seal("cadence slot already sealed".into()));
            }
            (p.block_number + 1, p.block_hash.clone())
        }
        None => (0, "sha256:genesis".to_string()),
    };

    let mut history = History::open(data_dir, db.last_block()?)?;
    let mut declarations = Declarations::default();
    while let Some(block) = history.next_block()? {
        declarations.apply(&block)?;
    }
    for (domain, state) in declarations.domains() {
        if let Some(window) = state.window() {
            if window.end_s() > i128::from(sealed_epoch)
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
        .and_then(|schedule| schedule.value_at("recovery_window_days", sealed_epoch))
        .unwrap_or_else(|| {
            registry::spec("recovery_window_days")
                .unwrap()
                .default
                .unwrap()
        });
    let activation_blocks = history
        .schedule()
        .and_then(|schedule| schedule.value_at("declaration_activation_blocks", sealed_epoch))
        .unwrap_or_else(|| {
            registry::spec("declaration_activation_blocks")
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
                    .is_some_and(|window| window.end_s() > i128::from(sealed_epoch))
            })
            .map(|(domain, _)| domain.as_str())
            .collect(),
    )?;
    let settlement = declarations.project(&sealed_at, recovery_days, activation_blocks, &[])?;

    let (peeked, _up_to_rowid) = db.peek_pending_entries()?;
    let domain_cap = registry::effective(db, "domain_block_entries_max", &sealed_at)?;
    let labeler_cap = registry::effective(db, "labeler_block_entries_max", &sealed_at)?;
    let peeked = fit_to_domain_cap(db, peeked, domain_cap, labeler_cap, block_number)?;
    let seal_entries = storage_order(peeked)?;
    let schedule = db.parameter_schedule(sealed_epoch)?;
    let mut cap = registry::block_cap(&schedule, sealed_epoch).min(registry::effective(
        db,
        "block_decompressed_cap_bytes",
        &sealed_at,
    )?);
    let mut tentative = schedule.clone();
    let largest = db.largest_block_bytes()?;
    for (index, entry) in seal_entries.iter().enumerate() {
        let update = &entry.body["update"];
        if entry.entry_type == "registry_update"
            && update["action"] == "parameter_change"
            && check_param_change(
                &mut tentative,
                update,
                sealed_epoch,
                block_number,
                index as u64,
                largest,
            )
            .is_ok()
        {
            cap = cap.min(registry::block_cap(&tentative, sealed_epoch));
        }
    }
    let empty = encoded_block(
        block_number,
        &prev_block_hash,
        &sealed_at,
        Vec::new(),
        merkle::leaf_hash(&[]),
        sk,
    )?;
    let framing = jcs::canonicalize(&serde_json::to_value(&empty)?)?.len();
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
    let (seal_entries, _deferred) = fit_to_cap(seal_entries, cap, framing, &installed)?;
    let projection = declarations.project(
        &sealed_at,
        recovery_days,
        activation_blocks,
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
    let default_schedule = wist_core::parameters::Schedule::new(sealed_epoch);
    let sealing_schedule = history.schedule().unwrap_or(&default_schedule);
    let size_caps =
        crate::declaration::delta::SizeCaps::from_schedule(sealing_schedule, sealed_epoch);
    let clock_skew_seconds = sealing_schedule
        .value_at("clock_skew_seconds", sealed_epoch)
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
    let ceiling = registry::effective(db, "max_inclusion_blocks", &sealed_at)?;
    let late = late_inclusions(&seal_entries, block_number, ceiling);
    let candidate = encoded_block(
        block_number,
        &prev_block_hash,
        &sealed_at,
        seal_entries.iter().map(|e| e.wrapped.clone()).collect(),
        merkle::leaf_hash(&[]),
        sk,
    )?;
    let candidate_bytes = jcs::canonicalize(&serde_json::to_value(&candidate)?)?.len() as u64;
    let mut outcome = enforce_governance(
        db,
        &sk.public(),
        seal_entries,
        sealed_epoch,
        block_number,
        candidate_bytes,
    )?;
    outcome.dropped.extend(retired);
    outcome.dropped_rowids.extend(retired_rowids);
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
    let leaves: Vec<[u8; 32]> = seal_entries.iter().map(|e| e.leaf).collect();
    let entry_count = entries.len() as u64;
    let merkle_root = if leaves.is_empty() {
        merkle::leaf_hash(&[])
    } else {
        merkle::merkle_root(&leaves)?
    };

    let block = encoded_block(
        block_number,
        &prev_block_hash,
        &sealed_at,
        entries,
        merkle_root,
        sk,
    )?;
    let block_hash = wist_core::block::block_hash(&serde_json::to_value(&block.header)?)?;

    let projection =
        declarations.project(&sealed_at, recovery_days, activation_blocks, &block.entries)?;
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
                    opened_block: window.owner().position().block_number,
                    window_end,
                })
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let record_updates = resolve_record_updates(data_dir, &size_caps, &seal_entries)?;

    Ok(PreparedBlock {
        block,
        block_hash,
        block_number,
        sealed_at,
        cap,
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
    sealed_epoch: i64,
    block_number: u64,
    entry_index: u64,
    largest_block: u64,
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
        block_number,
        entry_index,
        sealed_at_s: sealed_epoch,
        effective_at_s: registry::epoch(effective_at).map_err(|e| e.to_string())?,
    };
    registry::accept(schedule, amendment, largest_block)
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
    let height = db.last_block()?.map_or(0, |b| b.block_number + 1);
    let largest = db.largest_block_bytes()?;
    let (mut pending, _) = db.peek_pending_entries()?;
    let rowid = pending.iter().map(|p| p.rowid).max().unwrap_or(0) + 1;
    pending.push(PendingEntryRow {
        rowid,
        entry_type: "registry_update".into(),
        domain: String::new(),
        entry_json: sign_envelope(update, "update", GENESIS_KEY_ID, sk)?,
        turn_block: None,
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
/// under the Key Set WIST-1 §5.2 resolves at the sealing Block — the
/// highest-`seq` Declaration sealed at a height at or below it, this
/// Block's own Declarations included (WIST-3 §3.2 applies them first).
/// One whose signing key a Declaration accepted since the pull has
/// retired is WIST1-E02, reported and not sealed.
/// WIST-3 §3.2: a Block MUST NOT carry more than
/// `domain_block_entries_max` `publisher_delta`, `label` and `dispute`
/// Entries of one Registrable Domain under the snapshot in force at it
/// (WIST-4 §3.1), nor more than `labeler_block_entries_max` `label` and
/// `dispute` Entries of one. The surplus waits its turn in acceptance
/// order, and WIST-4 §6.4's inclusion ceiling runs from the Block an
/// Entry's turn arrives in — the first with room for it — which is
/// recorded here.
pub(super) fn fit_to_domain_cap(
    db: &Db,
    peeked: Vec<PendingEntryRow>,
    cap: i64,
    labeler_cap: i64,
    block_number: u64,
) -> Result<Vec<PendingEntryRow>> {
    let cap = cap.max(0) as usize;
    let labeler_cap = labeler_cap.max(0) as usize;
    let list = crate::suffix_list::in_force_at_block(db, block_number)?;
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
        db.set_turn_block(p.rowid, block_number)?;
        kept.push(p);
    }
    Ok(kept)
}

/// WIST-4 §6.4: an accepted Delta MUST be sealed no later than
/// `max_inclusion_blocks` Blocks after the Block its turn arrived in.
pub(super) fn late_inclusions(
    entries: &[SealEntry],
    block_number: u64,
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
            let turn = e.turn_block?;
            (block_number > turn + ceiling).then(|| {
                format!(
                    "{}: sealed at Block {block_number}, {} Blocks after its turn at {turn}",
                    e.domain,
                    block_number - turn
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
/// the Log key and name a Delta sealed at or below this Block — one this
/// Block seals or one the store already holds — whose signed publisher is
/// the subject; a failing act is dropped with its code, and a repeated
/// withdrawal seals and changes nothing.
fn check_withdrawal(
    db: &Db,
    replay: &mut wist_core::withdrawal::WithdrawalReplay,
    log_key: &wist_core::crypto::PublicKey,
    body: &Value,
    block_number: u64,
    block_deltas: &HashMap<String, String>,
) -> std::result::Result<Option<OwnedWithdrawal>, String> {
    use wist_core::withdrawal::{Disposition, SealedDelta};
    let subject = body["update"]["subject"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let lookup = |delta_id: &str| match block_deltas.get(delta_id) {
        Some(publisher) => SealedDelta::Known {
            publisher: publisher.clone(),
            height: block_number,
        },
        None => match db.is_delta_sealed_for(delta_id, &subject) {
            Ok(true) => SealedDelta::Known {
                publisher: subject.clone(),
                height: block_number,
            },
            _ => SealedDelta::Absent,
        },
    };
    match replay.apply(
        block_number,
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

pub(super) fn enforce_governance(
    db: &Db,
    log_key: &wist_core::crypto::PublicKey,
    entries: Vec<SealEntry>,
    sealed_epoch: i64,
    block_number: u64,
    block_bytes: u64,
) -> Result<GovernanceOutcome> {
    let mut schedule = db.parameter_schedule(sealed_epoch)?;
    let largest = db.largest_block_bytes()?.max(block_bytes);
    let mut out = GovernanceOutcome {
        kept: Vec::with_capacity(entries.len()),
        param_changes: Vec::new(),
        withdrawals: Vec::new(),
        suffix_lists: Vec::new(),
        dropped: Vec::new(),
        dropped_rowids: Vec::new(),
    };
    let block_deltas: HashMap<String, String> = entries
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
                sealed_epoch,
                block_number,
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
                    block_number,
                    &block_deltas,
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
                    block_number,
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
            _ => out.kept.push(e),
        }
    }
    Ok(out)
}

pub(super) fn fit_to_cap(
    entries: Vec<SealEntry>,
    cap: i64,
    empty_block_bytes: usize,
    installed: &HashSet<String>,
) -> Result<(Vec<SealEntry>, usize)> {
    let cap = usize::try_from(cap).map_err(|_| Error::Seal("invalid Block cap".into()))?;
    if empty_block_bytes > cap {
        return Err(Error::Seal(
            "empty Block exceeds the decompressed cap".into(),
        ));
    }
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
    let mut used = empty_block_bytes;
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

        let count_bytes = (kept.len() + 1).to_string().len() - kept.len().to_string().len();
        let size =
            jcs::canonicalize(&e.wrapped)?.len() + usize::from(!kept.is_empty()) + count_bytes;
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

pub(super) fn encoded_block(
    block_number: u64,
    prev_block_hash: &str,
    sealed_at: &str,
    entries: Vec<Value>,
    merkle_root: [u8; 32],
    sk: &SigningKey,
) -> Result<Block> {
    let header = BlockHeader {
        wist_version: WIST_VERSION.into(),
        block_number,
        prev_block_hash: prev_block_hash.into(),
        sealed_at: sealed_at.into(),
        merkle_root: format!("sha256:{}", hex_encode(&merkle_root)),
        entry_count: entries.len() as u64,
    };
    let sig_value = sk.sign(&jcs::canonicalize(&serde_json::to_value(&header)?)?);
    Ok(Block {
        header,
        entries,
        sig: Sig {
            key_id: GENESIS_KEY_ID.into(),
            alg: "Ed25519".into(),
            value: sig_value,
        },
    })
}

pub(super) struct SealEntry {
    pub(super) rowid: i64,
    pub(super) entry_type: String,
    pub(super) domain: String,
    pub(super) body: Value,
    pub(super) wrapped: Value,
    pub(super) leaf: [u8; 32],
    pub(super) turn_block: Option<u64>,
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
            let leaf = merkle::leaf_hash(&jcs::canonicalize(&wrapped)?);
            Ok(SealEntry {
                rowid: p.rowid,
                entry_type: p.entry_type,
                domain: p.domain,
                body: p.entry_json,
                wrapped,
                leaf,
                turn_block: p.turn_block,
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
    #[test]
    fn domain_cap_counts_per_registrable_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        let list = b"com\ngithub.io\n";
        let identifier = wist_core::suffix_list::identifier(list);
        db.store_suffix_list(&identifier, list).unwrap();
        db.commit_seal(
            &[],
            0,
            "sha256:h0",
            "2026-08-09T00:00:00Z",
            &[],
            &[],
            &[],
            std::slice::from_ref(&identifier),
            &[],
            &[],
            &[],
            0,
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
    fn packing_accounts_for_entry_count_digits_at_exact_jcs_size() {
        let sk = SigningKey::from_seed(&[42; 32]);
        let at = "2026-09-07T00:00:00Z";
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
                            turn_block: None,
                        }
                    })
                    .collect(),
            )
            .unwrap()
        };
        for count in [9, 10, 99, 100] {
            let all = entries(count);
            let values = all.iter().map(|e| e.wrapped.clone()).collect();
            let root =
                merkle::merkle_root(&all.iter().map(|e| e.leaf).collect::<Vec<_>>()).unwrap();
            let block = encoded_block(10, "sha256:previous", at, values, root, &sk).unwrap();
            let size = jcs::canonicalize(&serde_json::to_value(block).unwrap())
                .unwrap()
                .len();
            let empty = encoded_block(
                10,
                "sha256:previous",
                at,
                Vec::new(),
                merkle::leaf_hash(&[]),
                &sk,
            )
            .unwrap();
            let framing = jcs::canonicalize(&serde_json::to_value(empty).unwrap())
                .unwrap()
                .len();
            let (fit, deferred) = fit_to_cap(all, size as i64, framing, &HashSet::new()).unwrap();
            assert_eq!(fit.len(), count as usize);
            assert_eq!(deferred, 0);
            let (fit, deferred) =
                fit_to_cap(entries(count), size as i64 - 1, framing, &HashSet::new()).unwrap();
            assert_eq!(fit.len(), count as usize - 1);
            assert_eq!(deferred, 1);
        }
    }
}
