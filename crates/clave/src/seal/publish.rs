use super::prepare::PreparedBlock;
use super::{SealReport, GENESIS_KEY_ID};
use crate::db::Mutation;
use crate::db::{Db, ParamChangeRow, RecordUpsert, SealedDeclarationRow, WithdrawalRow};
use crate::error::{Error, Result};
use crate::WIST_VERSION;
use std::path::Path;
use wist_core::crypto::SigningKey;
use wist_core::envelope::sign_envelope;
use wist_core::jcs;
use wist_core::objects::Checkpoint;

/// Publishes a prepared Block: writes the Block and Checkpoint files,
/// commits the seal with its acceptance, schedule, withdrawal and
/// Declaration rows, records sealed windows, applies withdrawals and
/// rebuilds the Snapshot.
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
        withdrawals,
        dropped,
        late,
        entry_count,
        projection,
        windows,
        record_updates,
    } = prepared;
    let block_bytes = jcs::canonicalize(&serde_json::to_value(&block)?)?;
    if block_bytes.len() as u64 > cap as u64 {
        return Err(Error::Seal(
            "serialized Block exceeds the decompressed cap".into(),
        ));
    }

    let checkpoint = Checkpoint {
        wist_version: WIST_VERSION.into(),
        block_number,
        block_hash: block_hash.clone(),
        sealed_at: sealed_at.clone(),
    };
    let checkpoint_value = serde_json::to_value(&checkpoint)?;
    let checkpoint_envelope = sign_envelope(&checkpoint_value, "checkpoint", GENESIS_KEY_ID, sk)?;
    let checkpoint_bytes = serde_json::to_vec(&checkpoint_envelope)?;

    let records: Vec<RecordUpsert> = record_updates
        .iter()
        .map(|r| RecordUpsert {
            url: &r.url,
            publisher: &r.publisher,
            delta_id: &r.delta_id,
            observed_at: &r.observed_at,
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
    let withdrawal_rows: Vec<WithdrawalRow> = withdrawals
        .iter()
        .map(|w| WithdrawalRow {
            update_id: &w.update_id,
            delta_id: &w.delta_id,
            domain: &w.domain,
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
        &withdrawal_rows,
        &declaration_rows,
        block_bytes.len() as u64,
    )?;
    db.record_publication(block_number, &block_bytes, &checkpoint_bytes)?;

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
    mutation.commit()?;
    crate::publication::publish(data_dir, block_number, &block_bytes, &checkpoint_bytes)?;
    db.mark_published(block_number)?;

    if !withdrawals.is_empty() {
        for delta_id in withdrawals.iter().map(|w| &w.delta_id) {
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
        projection.domains(),
    )?;

    Ok(SealReport {
        block_number,
        entry_count,
        dropped,
        late,
    })
}
