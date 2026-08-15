use crate::db::{Db, ParamChangeRow, PendingEntryRow, RecordUpsert};
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

fn enforce_param_changes(
    db: &Db,
    entries: Vec<SealEntry>,
    sealed_at: &str,
    sealed_epoch: i64,
) -> Result<(Vec<SealEntry>, Vec<AcceptedParamChange>, Vec<String>)> {
    let grace_days = registry::effective(db, "param_grace_days", sealed_at)?;
    let mut kept = Vec::with_capacity(entries.len());
    let mut accepted = Vec::new();
    let mut dropped = Vec::new();
    for e in entries {
        if e.entry_type != "registry_update" || e.body["update"]["action"] != "parameter_change" {
            kept.push(e);
            continue;
        }
        let details = &e.body["update"]["details"];
        let verdict = (|| -> std::result::Result<AcceptedParamChange, String> {
            let parameter = details["parameter"]
                .as_str()
                .ok_or("missing details.parameter")?;
            let value = details["value"].as_i64().ok_or("missing details.value")?;
            let effective_at = e.body["update"]["effective_at"]
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
        })();
        match verdict {
            Ok(change) => {
                accepted.push(change);
                kept.push(e);
            }
            Err(reason) => dropped.push(reason),
        }
    }
    Ok((kept, accepted, dropped))
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
    let (seal_entries, accepted_changes, dropped) =
        enforce_param_changes(db, seal_entries, &sealed_at, sealed_epoch)?;
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
    db.commit_seal(
        up_to_rowid,
        block_number,
        &block_hash,
        &sealed_at,
        &records,
        &param_changes,
    )?;

    let snapshot_date = sealed_at.get(..10).unwrap_or(&sealed_at).to_string();
    crate::snapshot::build(db, data_dir, sk, block_number, &block_hash, &snapshot_date)?;

    Ok(SealReport {
        block_number,
        entry_count,
        dropped,
    })
}
