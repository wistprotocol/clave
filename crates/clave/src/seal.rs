use crate::db::{
    Db, GovernanceRow, ParamChangeRow, PendingEntryRow, RecordUpsert, SealedDeclarationRow,
};
use crate::error::{Error, Result};
use crate::history::declarations::{Declarations, Projection};
use crate::history::roster::{Outcome, RosterHistory};
use crate::history::History;
use crate::registry;
use crate::WIST_VERSION;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::objects::{Block, BlockHeader, ChangeType, Checkpoint, Sig};
use wist_core::{jcs, merkle};

const DAY_SECONDS: i64 = 86400;

const GENESIS_KEY_ID: &str = "log1";
const ENTRY_TYPE_ORDER: [&str; 4] = [
    "publisher_declaration",
    "registry_update",
    "publisher_delta",
    "audit_record",
];

pub struct SealReport {
    pub block_number: u64,
    pub entry_count: u64,
    pub dropped: Vec<String>,
    /// Deltas sealed past WIST-4 §6.4's inclusion ceiling, counted from
    /// the Block each one's turn arrived in.
    pub late: Vec<String>,
}

struct AcceptedParamChange {
    rowid: i64,
    parameter: String,
    value: i64,
    effective_at: String,
}

struct OwnedGovernanceRow {
    update_id: String,
    action: String,
    domain: String,
    level: Option<i64>,
    notice_id: Option<String>,
    outcome: Option<String>,
    kind: Option<String>,
}

struct GovernanceOutcome {
    kept: Vec<SealEntry>,
    param_changes: Vec<AcceptedParamChange>,
    governance: Vec<OwnedGovernanceRow>,
    withdrawals: Vec<String>,
    dropped: Vec<String>,
    dropped_rowids: Vec<i64>,
}

const GOVERNANCE_ACTIONS: [&str; 6] = [
    "sanction",
    "notice",
    "appeal",
    "appeal_ruling",
    "sanction_lift",
    "payload_withdrawal",
];

fn check_param_change(
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

/// WIST-4 §7: an "unappealed" ruling discharges T only when its Block's
/// `sealed_at` is at or after the close of the appeal window.
fn check_unappealed_ruling(
    db: &Db,
    update: &Value,
    sealed_epoch: i64,
) -> std::result::Result<(), String> {
    let domain = update["subject"].as_str().ok_or("missing subject")?;
    let notice_id = update["details"]["notice"]
        .as_str()
        .ok_or("missing details.notice")?;
    let entries = db
        .governance_for_domain(domain)
        .map_err(|e| e.to_string())?;
    let notice = entries
        .iter()
        .find(|e| e.update_id == notice_id)
        .ok_or_else(|| format!("unappealed ruling names unsealed notice {notice_id}"))?;
    let notice_epoch = notice
        .sealed_at
        .parse::<jiff::Timestamp>()
        .map_err(|_| "unparseable notice sealed_at".to_string())?
        .as_second();
    let window_days = registry::effective(db, "appeal_window_days", &notice.sealed_at)
        .map_err(|e| e.to_string())?;
    let window_close = notice_epoch + window_days * 86400;
    if sealed_epoch < window_close {
        return Err(format!(
            "unappealed ruling for {notice_id} sealed before the appeal window closes"
        ));
    }
    Ok(())
}

/// WIST-2 §5 step 4: a queued Delta is sealed only where it verifies
/// under the Key Set WIST-1 §5.2 resolves at the sealing Block — the
/// highest-`seq` Declaration sealed at a height at or below it, this
/// Block's own Declarations included (WIST-3 §3.2 applies them first).
/// One whose signing key a Declaration accepted since the pull has
/// retired is WIST1-E02, reported and not sealed.
/// WIST-3 §3.2: a Block MUST NOT carry more than
/// `domain_block_entries_max` `publisher_delta` Entries for one domain.
/// The surplus waits its turn in acceptance order, and WIST-4 §6.4's
/// inclusion ceiling runs from the Block a Delta's turn arrives in — the
/// first with room for it — which is recorded here.
fn fit_to_domain_cap(
    db: &Db,
    peeked: Vec<PendingEntryRow>,
    cap: i64,
    block_number: u64,
) -> Result<Vec<PendingEntryRow>> {
    let cap = cap.max(0) as usize;
    let mut taken: HashMap<String, usize> = HashMap::new();
    let mut kept = Vec::with_capacity(peeked.len());
    for p in peeked {
        if p.entry_type != "publisher_delta" {
            kept.push(p);
            continue;
        }
        let count = taken.entry(p.domain.clone()).or_insert(0);
        if *count >= cap {
            continue;
        }
        *count += 1;
        db.set_turn_block(p.rowid, block_number)?;
        kept.push(p);
    }
    Ok(kept)
}

/// WIST-4 §6.4: an accepted Delta MUST be sealed no later than
/// `max_inclusion_blocks` Blocks after the Block its turn arrived in.
fn late_inclusions(entries: &[SealEntry], block_number: u64, ceiling: i64) -> Vec<String> {
    let ceiling = ceiling.max(0) as u64;
    entries
        .iter()
        .filter(|e| e.entry_type == "publisher_delta")
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

fn divert_recovery_deltas(db: &Db, domains: &HashSet<&str>) -> Result<()> {
    for entry in db.peek_pending_entries()?.0 {
        if entry.entry_type != "publisher_delta" || !domains.contains(entry.domain.as_str()) {
            continue;
        }
        db.requeue_pending_delta(&entry)?;
    }
    Ok(())
}

fn check_roster_acts(
    db: &Db,
    entries: Vec<SealEntry>,
    sealed_at: &str,
    sealed_epoch: i64,
    block_number: u64,
    roster: &RosterHistory,
    log_key: &wist_core::crypto::PublicKey,
) -> Result<(Vec<SealEntry>, Vec<i64>, Vec<String>)> {
    if !entries.iter().any(|e| e.entry_type == "registry_update") {
        return Ok((entries, Vec::new(), Vec::new()));
    }
    let wrapped: Vec<Value> = entries.iter().map(|e| e.wrapped.clone()).collect();
    let outcomes = roster.clone().apply_entries(
        block_number,
        sealed_epoch,
        &wrapped,
        GENESIS_KEY_ID,
        log_key,
    )?;
    let mut dropped = Vec::new();
    let mut dropped_rowids = Vec::new();
    let mut accepted = Vec::new();
    let mut rejected_entries = HashSet::new();
    for (index, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Outcome::NotRoster => {}
            Outcome::Rejected(rejection) => {
                dropped.push(format!("{}: {}", rejection.subject, rejection.reason));
                dropped_rowids.push(entries[index].rowid);
                rejected_entries.insert(index);
            }
            Outcome::Accepted(act) if act.action != "observer_checkpoint" => {
                accepted.push(crate::db::RosterActRow {
                    block_number,
                    sealed_at: sealed_at.to_string(),
                    action: act.action,
                    auditor_id: act.subject,
                    key_id: act.key_id,
                    public_key: act.public_key,
                    for_cause: act.for_cause,
                });
            }
            Outcome::Accepted(_) => {}
        }
    }
    db.record_roster_acts(&accepted)?;
    let kept = entries
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !rejected_entries.contains(i))
        .map(|(_, e)| e)
        .collect();
    Ok((kept, dropped_rowids, dropped))
}

fn revalidate_queued_deltas(
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

fn enforce_governance(
    db: &Db,
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
        governance: Vec::new(),
        withdrawals: Vec::new(),
        dropped: Vec::new(),
        dropped_rowids: Vec::new(),
    };
    for (index, e) in entries.into_iter().enumerate() {
        if e.entry_type != "registry_update" {
            out.kept.push(e);
            continue;
        }
        let update = e.body["update"].clone();
        let action = update["action"].as_str().unwrap_or_default().to_string();
        if action == "parameter_change" {
            match check_param_change(
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
            }
            continue;
        }
        if !GOVERNANCE_ACTIONS.contains(&action.as_str()) {
            out.kept.push(e);
            continue;
        }
        if action == "appeal_ruling" && update["details"]["outcome"] == "unappealed" {
            if let Err(reason) = check_unappealed_ruling(db, &update, sealed_epoch) {
                out.dropped.push(reason);
                out.dropped_rowids.push(e.rowid);
                continue;
            }
        }
        let row = OwnedGovernanceRow {
            update_id: crate::governance::update_id(&update)?,
            action: action.clone(),
            domain: update["subject"].as_str().unwrap_or_default().to_string(),
            level: update["details"]["level"].as_i64(),
            notice_id: update["details"]["notice"].as_str().map(str::to_string),
            outcome: update["details"]["outcome"].as_str().map(str::to_string),
            kind: update["details"]["kind"].as_str().map(str::to_string),
        };
        if action == "payload_withdrawal" {
            if let Some(delta_id) = update["details"]["delta_id"].as_str() {
                out.withdrawals.push(delta_id.to_string());
            }
        }
        out.governance.push(row);
        out.kept.push(e);
    }

    let batch_notices: Vec<(String, String)> = out
        .governance
        .iter()
        .filter(|r| r.action == "notice")
        .map(|r| (r.domain.clone(), r.update_id.clone()))
        .collect();
    for row in &mut out.governance {
        if row.action == "sanction" && row.level.unwrap_or(0) >= 3 && row.notice_id.is_none() {
            row.notice_id = batch_notices
                .iter()
                .rev()
                .find(|(d, _)| *d == row.domain)
                .map(|(_, id)| id.clone())
                .or_else(|| {
                    db.governance_for_domain(&row.domain)
                        .ok()
                        .and_then(|entries| {
                            entries
                                .iter()
                                .rev()
                                .find(|e| e.action == "notice")
                                .map(|e| e.update_id.clone())
                        })
                });
        }
    }
    Ok(out)
}

fn fit_to_cap(
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

fn encoded_block(
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

struct SealEntry {
    rowid: i64,
    entry_type: String,
    domain: String,
    body: Value,
    wrapped: Value,
    leaf: [u8; 32],
    turn_block: Option<u64>,
}

struct DeltaApply {
    body: Value,
    id: String,
    prev: Option<String>,
}

struct OwnedRecordUpsert {
    url: String,
    publisher: String,
    delta_id: String,
    observed_at: String,
    title: String,
    abstract_text: Option<String>,
    lang: String,
}

fn entry_type_rank(entry_type: &str) -> usize {
    ENTRY_TYPE_ORDER
        .iter()
        .position(|t| *t == entry_type)
        .unwrap_or(ENTRY_TYPE_ORDER.len())
}

/// WIST-4 §9.1: a sanction notice's `appeal_deadline` restates the
/// `sealed_at` of the Block sealing it plus `appeal_window_days`, which
/// is not knowable when the notice is enqueued. The value is restated
/// here and the update re-signed, so the notice a Consumer reads and
/// §7's own derivation agree.
fn restate_appeal_deadlines(
    db: &Db,
    sk: &SigningKey,
    peeked: Vec<PendingEntryRow>,
    sealed_at: &str,
    sealed_epoch: i64,
) -> Result<Vec<PendingEntryRow>> {
    let mut window_days = None;
    peeked
        .into_iter()
        .map(|mut p| {
            let update = &p.entry_json["update"];
            if p.entry_type != "registry_update"
                || update["action"] != "notice"
                || update["details"]["kind"] != "sanction"
            {
                return Ok(p);
            }
            let days = match window_days {
                Some(days) => days,
                None => {
                    let days = registry::effective(db, "appeal_window_days", sealed_at)?;
                    window_days = Some(days);
                    days
                }
            };
            let deadline = jiff::Timestamp::from_second(sealed_epoch + days * DAY_SECONDS)
                .map_err(|_| Error::Seal("appeal_deadline out of range".into()))?
                .to_string();
            let mut update = update.clone();
            update["details"]["appeal_deadline"] = deadline.into();
            p.entry_json = sign_envelope(&update, "update", GENESIS_KEY_ID, sk)?;
            Ok(p)
        })
        .collect()
}

fn storage_order(peeked: Vec<PendingEntryRow>) -> Result<Vec<SealEntry>> {
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

fn chain_order(mut remaining: Vec<DeltaApply>) -> Vec<DeltaApply> {
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

fn resolve_record_updates(
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

pub fn run(db: &Db, data_dir: &Path, sk: &SigningKey, now_epoch: i64) -> Result<SealReport> {
    let now_at = jiff::Timestamp::from_second(now_epoch)
        .map_err(|_| Error::Seal("now out of range".into()))?
        .to_string();
    let mutation = db.mutation()?;
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
    let mut roster = RosterHistory::start(&history);
    while let Some(block) = history.next_block()? {
        declarations.apply(&block)?;
        roster.apply(&block, history.log_key_id(), history.log_key())?;
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
    let settlement = declarations.project(&sealed_at, recovery_days, &[])?;

    let (peeked, _up_to_rowid) = db.peek_pending_entries()?;
    let peeked = restate_appeal_deadlines(db, sk, peeked, &sealed_at, sealed_epoch)?;
    let domain_cap = registry::effective(db, "domain_block_entries_max", &sealed_at)?;
    let peeked = fit_to_domain_cap(db, peeked, domain_cap, block_number)?;
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
    let (seal_entries, roster_rowids, roster_dropped) = check_roster_acts(
        db,
        seal_entries,
        &sealed_at,
        sealed_epoch,
        block_number,
        &roster,
        &sk.public(),
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
        seal_entries,
        sealed_epoch,
        block_number,
        candidate_bytes,
    )?;
    outcome.dropped.extend(retired);
    outcome.dropped_rowids.extend(retired_rowids);
    outcome.dropped.extend(roster_dropped);
    outcome.dropped_rowids.extend(roster_rowids);
    let GovernanceOutcome {
        kept: seal_entries,
        param_changes: accepted_changes,
        governance,
        withdrawals,
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

    let projection = declarations.project(&sealed_at, recovery_days, &block.entries)?;
    let windows = projection
        .domains()
        .iter()
        .filter_map(|(domain, state)| {
            state.window().map(|window| {
                let window_end = i64::try_from(window.end_s())
                    .ok()
                    .and_then(|end| jiff::Timestamp::from_second(end).ok())
                    .ok_or_else(|| Error::Seal("recovery window end out of range".into()))?
                    .to_string();
                Ok((domain, window, window_end))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let record_updates = resolve_record_updates(data_dir, &size_caps, &seal_entries)?;

    let blocks_dir = data_dir.join("log/blocks");
    std::fs::create_dir_all(&blocks_dir)?;
    let block_bytes = jcs::canonicalize(&serde_json::to_value(&block)?)?;
    if block_bytes.len() as u64 > cap as u64 {
        return Err(Error::Seal(
            "serialized Block exceeds the decompressed cap".into(),
        ));
    }
    let compressed = zstd::bulk::compress(&block_bytes, zstd::DEFAULT_COMPRESSION_LEVEL)?;
    std::fs::write(
        blocks_dir.join(format!("{block_number:09}.json.zst")),
        &compressed,
    )?;

    let checkpoint = Checkpoint {
        wist_version: WIST_VERSION.into(),
        block_number,
        block_hash: block_hash.clone(),
        sealed_at: sealed_at.clone(),
    };
    let checkpoint_value = serde_json::to_value(&checkpoint)?;
    let checkpoint_envelope = sign_envelope(&checkpoint_value, "checkpoint", GENESIS_KEY_ID, sk)?;
    let checkpoint_bytes = serde_json::to_vec(&checkpoint_envelope)?;
    let checkpoints_dir = data_dir.join("log/checkpoints");
    std::fs::create_dir_all(&checkpoints_dir)?;
    std::fs::write(data_dir.join("log/checkpoint.json"), &checkpoint_bytes)?;
    std::fs::write(
        checkpoints_dir.join(format!("{block_number:09}.json")),
        &checkpoint_bytes,
    )?;

    let records: Vec<RecordUpsert> = record_updates
        .iter()
        .map(|r| RecordUpsert {
            url: &r.url,
            publisher: &r.publisher,
            delta_id: &r.delta_id,
            observed_at: &r.observed_at,
            weight: "full",
            title: &r.title,
            abstract_text: r.abstract_text.as_deref(),
            lang: &r.lang,
        })
        .collect();
    let param_changes: Vec<ParamChangeRow> = accepted_changes
        .iter()
        .map(|c| ParamChangeRow {
            entry_index: seal_entries
                .iter()
                .position(|e| e.rowid == c.rowid)
                .expect("accepted parameter entry is retained") as u64,
            parameter: &c.parameter,
            value: c.value,
            effective_at: &c.effective_at,
        })
        .collect();
    let governance_rows: Vec<GovernanceRow> = governance
        .iter()
        .map(|g| GovernanceRow {
            update_id: &g.update_id,
            action: &g.action,
            domain: &g.domain,
            level: g.level,
            notice_id: g.notice_id.as_deref(),
            outcome: g.outcome.as_deref(),
            kind: g.kind.as_deref(),
        })
        .collect();
    let sealed_declarations: Vec<(String, u64, Vec<u8>)> = seal_entries
        .iter()
        .filter(|e| e.entry_type == "publisher_declaration")
        .map(|e| {
            let publisher = crate::declaration::publisher_of(&e.body).map_err(Error::Seal)?;
            Ok((
                publisher.domain,
                publisher.seq,
                serde_json::to_vec(&e.body)?,
            ))
        })
        .collect::<Result<_>>()?;
    let declaration_rows: Vec<SealedDeclarationRow> = sealed_declarations
        .iter()
        .map(|(domain, seq, json)| SealedDeclarationRow {
            domain,
            seq: *seq,
            declaration_json: json,
        })
        .collect();
    db.commit_seal(
        &sealed_rowids,
        block_number,
        &block_hash,
        &sealed_at,
        &records,
        &param_changes,
        &governance_rows,
        &declaration_rows,
        block_bytes.len() as u64,
    )?;

    for (domain, window, window_end) in windows {
        db.store_sealed_recovery_window(
            domain,
            &serde_json::to_vec(window.head().envelope())?,
            &serde_json::to_vec(window.before().envelope())?,
            &serde_json::to_vec(window.owner().envelope())?,
            window.owner().position().block_number,
            &window_end,
        )?;
    }
    for installation in &projection.effects().installations {
        if !installation.opens_window {
            continue;
        }
        let domain = &installation.declaration.envelope()["publisher"]["domain"];
        let update = serde_json::json!({
            "wist_version": WIST_VERSION,
            "action": "notice",
            "subject": domain,
            "details": {"kind": "recovery"},
            "effective_at": sealed_at,
        });
        let envelope = sign_envelope(&update, "update", GENESIS_KEY_ID, sk)?;
        db.insert_pending_entry("registry_update", "", &envelope, 0)?;
    }

    mutation.commit()?;

    if !withdrawals.is_empty() {
        for delta_id in &withdrawals {
            let hex = delta_id.strip_prefix("sha256:").unwrap_or(delta_id);
            let _ = std::fs::remove_file(data_dir.join("payloads").join(format!("{hex}.json")));
            db.delete_record_by_delta(delta_id)?;
        }
        let snapshots_dir = data_dir.join("snapshots");
        if let Ok(dir) = std::fs::read_dir(&snapshots_dir) {
            for entry in dir.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    std::fs::remove_dir_all(&path)?;
                } else {
                    std::fs::remove_file(&path)?;
                }
            }
        }
    }

    let snapshot_date = sealed_at.get(..10).unwrap_or(&sealed_at).to_string();
    crate::snapshot::build(
        db,
        data_dir,
        sk,
        block_number,
        &block_hash,
        &snapshot_date,
        &sealed_at,
    )?;

    Ok(SealReport {
        block_number,
        entry_count,
        dropped,
        late,
    })
}

#[cfg(test)]
mod tests {
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
