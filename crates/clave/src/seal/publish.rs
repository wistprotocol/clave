use super::prepare::PreparedEpoch;
use super::SealReport;
use crate::db::Mutation;
use crate::db::{
    Db, ParamChangeRow, RecordUpsert, SealedDeclarationRow, SealedDisputeRow, SealedLabelRow,
    WithdrawalRow,
};
use crate::error::{Error, Result};
use std::path::Path;
use wist_core::crypto::SigningKey;

pub(super) fn epoch(
    db: &Db,
    data_dir: &Path,
    client: &crate::fetch::Client,
    mutation: Mutation<'_>,
    prepared: PreparedEpoch,
) -> Result<SealReport> {
    let PreparedEpoch {
        log_id,
        signers,
        key_entries,
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
    } = prepared;
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
    let sealed_labels: Vec<(String, u64, wist_core::objects::Label)> = seal_entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.entry_type == "label")
        .map(|(index, e)| {
            Ok((
                wist_core::label::label_id(&e.body["label"])
                    .map_err(|r| Error::Seal(format!("sealed label: {r:?}")))?,
                index as u64,
                serde_json::from_value(e.body["label"].clone())?,
            ))
        })
        .collect::<Result<_>>()?;
    let label_rows: Vec<SealedLabelRow> = sealed_labels
        .iter()
        .map(|(id, index, label)| SealedLabelRow {
            label_id: id,
            entry_index: *index,
            label,
        })
        .collect();
    let sealed_disputes: Vec<(String, u64, wist_core::objects::Dispute)> = seal_entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.entry_type == "dispute")
        .map(|(index, e)| {
            Ok((
                wist_core::label::dispute_id(&e.body["dispute"])
                    .map_err(|r| Error::Seal(format!("sealed dispute: {r:?}")))?,
                index as u64,
                serde_json::from_value(e.body["dispute"].clone())?,
            ))
        })
        .collect::<Result<_>>()?;
    let dispute_rows: Vec<SealedDisputeRow> = sealed_disputes
        .iter()
        .map(|(id, index, dispute)| SealedDisputeRow {
            dispute_id: id,
            entry_index: *index,
            dispute,
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
    let signer_refs: Vec<&SigningKey> = signers.iter().collect();
    db.commit_seal_under(
        &signer_refs,
        Some(&key_entries),
        &log_id,
        &sealed_rowids,
        epoch_number,
        &sealed_at,
        &entries,
        octets,
        &records,
        &param_changes,
        &withdrawal_rows,
        &suffix_lists,
        &label_rows,
        &dispute_rows,
        &declaration_rows,
    )?;

    for activation in &projection.effects().activations {
        let publisher = crate::declaration::publisher_of(activation.activated.envelope())
            .map_err(Error::History)?;
        let key = &publisher.keys[0];
        db.restore_publisher_declaration(
            &activation.domain,
            &serde_json::to_vec(activation.activated.envelope())?,
            &key.kid,
            &key.x,
        )?;
        db.clear_pending_identity(&activation.domain)?;
    }
    for installation in &projection.effects().installations {
        if installation.reversed.is_some() {
            if let Some(domain) =
                installation.declaration.envelope()["publisher"]["domain"].as_str()
            {
                db.clear_pending_identity(domain)?;
            }
        }
    }
    for window in &windows {
        db.store_sealed_recovery_window(
            &window.domain,
            &window.head,
            &window.before,
            &window.owner,
            window.opened_epoch,
            &window.window_end,
        )?;
    }
    mutation.commit()?;
    crate::publication::recover(db, data_dir)?;
    db.check_fence()?;
    if let Err(error) = crate::witness::submit_head(db, client, data_dir) {
        tracing::warn!(%error, "witness submission did not complete");
    }
    db.check_fence()?;

    Ok(SealReport {
        epoch_number,
        entry_count,
        dropped,
        late,
    })
}
