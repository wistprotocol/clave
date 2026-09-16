use super::prepare::PreparedBlock;
use super::{SealReport, GENESIS_KEY_ID};
use crate::db::Mutation;
use crate::db::{Db, GovernanceRow, ParamChangeRow, RecordUpsert, SealedDeclarationRow};
use crate::error::{Error, Result};
use crate::WIST_VERSION;
use std::path::Path;
use wist_core::crypto::SigningKey;
use wist_core::envelope::sign_envelope;
use wist_core::jcs;
use wist_core::objects::Checkpoint;

/// Publishes a prepared Block: writes the Block and Checkpoint files,
/// commits the seal with its acceptance, schedule, governance and
/// Declaration rows, records sealed windows and recovery notices,
/// refreshes derived state, applies withdrawals and rebuilds the Snapshot.
pub(super) fn block(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    mutation: Mutation<'_>,
    prepared: PreparedBlock,
) -> Result<SealReport> {
    let PreparedBlock {
        block,
        block_hash,
        block_number,
        sealed_at,
        cap,
        seal_entries,
        sealed_rowids,
        accepted_changes,
        governance,
        withdrawals,
        dropped,
        late,
        entry_count,
        projection,
        windows,
        record_updates,
    } = prepared;
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

    for window in &windows {
        db.store_sealed_recovery_window(
            &window.domain,
            &window.head,
            &window.before,
            &window.owner,
            window.opened_block,
            &window.window_end,
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
    let sealed_update_ids: Vec<String> = seal_entries
        .iter()
        .filter(|e| e.entry_type == "registry_update")
        .filter_map(|e| crate::governance::update_id(&e.body["update"]).ok())
        .collect();
    db.record_sealed_updates(block_number, &sealed_update_ids)?;
    crate::derived::refresh(db, data_dir, sk)?;

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
        projection.domains(),
    )?;

    Ok(SealReport {
        block_number,
        entry_count,
        dropped,
        late,
    })
}
