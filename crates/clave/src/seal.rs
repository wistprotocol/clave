use crate::db::{Db, GovernanceRow, ParamChangeRow, PendingEntryRow, RecordUpsert};
use crate::error::{Error, Result};
use crate::registry;
use crate::WIST_VERSION;
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::objects::{Block, BlockHeader, ChangeType, Checkpoint, Payload, Sig};
use wist_core::{jcs, merkle};

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
}

struct AcceptedParamChange {
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
}

struct GovernanceOutcome {
    kept: Vec<SealEntry>,
    param_changes: Vec<AcceptedParamChange>,
    governance: Vec<OwnedGovernanceRow>,
    withdrawals: Vec<String>,
    dropped: Vec<String>,
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
    db: &Db,
    update: &Value,
    sealed_at: &str,
    sealed_epoch: i64,
    grace_days: i64,
) -> std::result::Result<AcceptedParamChange, String> {
    let details = &update["details"];
    let parameter = details["parameter"]
        .as_str()
        .ok_or("missing details.parameter")?;
    let value = details["value"].as_i64().ok_or("missing details.value")?;
    let effective_at = update["effective_at"]
        .as_str()
        .ok_or("missing effective_at")?;
    let effective_epoch = effective_at
        .parse::<jiff::Timestamp>()
        .map_err(|_| format!("unparseable effective_at {effective_at:?}"))?
        .as_second();
    if effective_epoch < sealed_epoch + grace_days * 86400 {
        return Err(format!(
            "{parameter}: effective_at {effective_at} is inside the {grace_days}-day grace period from sealed_at {sealed_at}"
        ));
    }
    let lookup = |n: &str| {
        registry::effective(db, n, effective_at)
            .unwrap_or_else(|_| registry::spec(n).and_then(|s| s.default).unwrap_or(0))
    };
    registry::validate(parameter, value, lookup).map_err(|err| err.to_string())?;
    Ok(AcceptedParamChange {
        parameter: parameter.to_string(),
        value,
        effective_at: effective_at.to_string(),
    })
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

fn enforce_governance(
    db: &Db,
    entries: Vec<SealEntry>,
    sealed_at: &str,
    sealed_epoch: i64,
) -> Result<GovernanceOutcome> {
    let grace_days = registry::effective(db, "param_grace_days", sealed_at)?;
    let mut out = GovernanceOutcome {
        kept: Vec::with_capacity(entries.len()),
        param_changes: Vec::new(),
        governance: Vec::new(),
        withdrawals: Vec::new(),
        dropped: Vec::new(),
    };
    for e in entries {
        if e.entry_type != "registry_update" {
            out.kept.push(e);
            continue;
        }
        let update = e.body["update"].clone();
        let action = update["action"].as_str().unwrap_or_default().to_string();
        if action == "parameter_change" {
            match check_param_change(db, &update, sealed_at, sealed_epoch, grace_days) {
                Ok(change) => {
                    out.param_changes.push(change);
                    out.kept.push(e);
                }
                Err(reason) => out.dropped.push(reason),
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

struct SealEntry {
    entry_type: String,
    domain: String,
    body: Value,
    wrapped: Value,
    leaf: [u8; 32],
}

struct DeltaApply {
    domain: String,
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

fn storage_order(peeked: Vec<PendingEntryRow>) -> Result<Vec<SealEntry>> {
    let mut entries = peeked
        .into_iter()
        .map(|p| {
            let wrapped = serde_json::json!({"type": p.entry_type, "body": p.entry_json});
            let leaf = merkle::leaf_hash(&jcs::canonicalize(&wrapped)?);
            Ok(SealEntry {
                entry_type: p.entry_type,
                domain: p.domain,
                body: p.entry_json,
                wrapped,
                leaf,
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
            domain: e.domain.clone(),
            body: e.body.clone(),
            id,
            prev,
        });
    }

    let mut updates = Vec::new();
    for d in chain_order(deltas) {
        let delta: wist_core::objects::Delta = serde_json::from_value(d.body["delta"].clone())?;
        if !matches!(delta.change_type, ChangeType::New | ChangeType::Update)
            || delta.payload.is_none()
        {
            continue;
        }
        let hex = d.id.strip_prefix("sha256:").unwrap_or(&d.id);
        let payload_path = data_dir.join("payloads").join(format!("{hex}.json"));
        let Ok(payload_bytes) = std::fs::read(&payload_path) else {
            continue;
        };
        let Ok(payload) = serde_json::from_slice::<Payload>(&payload_bytes) else {
            continue;
        };
        updates.push(OwnedRecordUpsert {
            url: delta.url,
            publisher: d.domain,
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

    let (peeked, up_to_rowid) = db.peek_pending_entries()?;
    let seal_entries = storage_order(peeked)?;
    let outcome = enforce_governance(db, seal_entries, &sealed_at, sealed_epoch)?;
    let GovernanceOutcome {
        kept: seal_entries,
        param_changes: accepted_changes,
        governance,
        withdrawals,
        dropped,
    } = outcome;
    let entries: Vec<Value> = seal_entries.iter().map(|e| e.wrapped.clone()).collect();
    let leaves: Vec<[u8; 32]> = seal_entries.iter().map(|e| e.leaf).collect();
    let entry_count = entries.len() as u64;
    let merkle_root = if leaves.is_empty() {
        merkle::leaf_hash(&[])
    } else {
        merkle::merkle_root(&leaves)?
    };

    let header = BlockHeader {
        wist_version: WIST_VERSION.into(),
        block_number,
        prev_block_hash,
        sealed_at: sealed_at.clone(),
        merkle_root: format!("sha256:{}", hex_encode(&merkle_root)),
        entry_count,
    };
    let header_value = serde_json::to_value(&header)?;
    let canonical_header = jcs::canonicalize(&header_value)?;
    let sig_value = sk.sign(&canonical_header);
    let block_hash = wist_core::block::block_hash(&header_value)?;

    let block = Block {
        header,
        entries,
        sig: Sig {
            key_id: GENESIS_KEY_ID.into(),
            alg: "Ed25519".into(),
            value: sig_value,
        },
    };

    let record_updates = resolve_record_updates(data_dir, &seal_entries)?;

    let blocks_dir = data_dir.join("log/blocks");
    std::fs::create_dir_all(&blocks_dir)?;
    let block_bytes = serde_json::to_vec(&block)?;
    let compressed = zstd::encode_all(block_bytes.as_slice(), zstd::DEFAULT_COMPRESSION_LEVEL)?;
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
        })
        .collect();
    db.commit_seal(
        up_to_rowid,
        block_number,
        &block_hash,
        &sealed_at,
        &records,
        &param_changes,
        &governance_rows,
    )?;

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
    })
}
