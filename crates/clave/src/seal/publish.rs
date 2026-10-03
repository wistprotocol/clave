use super::prepare::PreparedEpoch;
use super::SealReport;
use crate::collection::plan::{Planned, Publication};
use crate::collection::{SettledOutcome, State};
use crate::db::Mutation;
use crate::db::{
    Db, ParamChangeRow, SealedDeclarationRow, SealedDisputeRow, SealedLabelRow, WithdrawalRow,
};
use crate::error::{Error, Result};
use std::collections::BTreeSet;
use std::path::Path;
use wist_core::crypto::SigningKey;
use wist_core::objects::StatusRejection;

const DAY_SECONDS: i64 = 86_400;

fn rejection(code: &str, at: &str) -> StatusRejection {
    StatusRejection {
        code: code.to_owned(),
        at: at.to_owned(),
        id: None,
        collection: None,
        urls: None,
        condition: None,
        change_list: None,
        detail: None,
    }
}

/// WIST-2 §7.1.
fn record_reports(db: &Db, before: &State, planned: &Planned, at: &str) -> Result<()> {
    for settled in &planned.settlement {
        let code = match settled.outcome {
            SettledOutcome::Regressed => crate::collection::queue::REGRESSED,
            SettledOutcome::Rejected(_) => crate::collection::queue::REJECTED,
            _ => continue,
        };
        let mut row = rejection(code, at);
        row.id = Some(settled.catalog.clone());
        row.collection = Some(settled.collection.clone());
        row.detail = settled.outcome.condition_code().map(str::to_owned);
        db.record_rejection(&settled.publisher, &row)?;
    }
    for left in planned.left.iter().filter(|left| left.reported) {
        for code in &left.codes {
            let mut row = rejection(code, at);
            let publisher = match &left.publication {
                Publication::Catalog {
                    publisher,
                    collection,
                    catalog,
                } => {
                    row.id = Some(catalog.clone());
                    row.collection = Some(collection.clone());
                    publisher
                }
                Publication::Item {
                    publisher,
                    collection,
                    url,
                    item,
                } => {
                    row.id = Some(item.clone());
                    row.collection = Some(collection.clone());
                    row.urls = Some(vec![url.clone()]);
                    row.detail = left.payload_code.map(str::to_owned);
                    publisher
                }
                Publication::Label { publisher, id, .. } => {
                    row.id = Some(id.clone());
                    publisher
                }
            };
            db.record_rejection(publisher, &row)?;
        }
    }
    for label in &planned.rejections {
        let publisher = before
            .labels
            .get(&label.id)
            .map(|waiting| waiting.publisher.clone());
        let mut row = rejection(label.code, at);
        row.id = Some(label.id.clone());
        row.detail = Some(
            "the Label or dispute fails at its turn a check of WIST-2 §3.3 repeated under the candidate Epoch"
                .into(),
        );
        if let Some(publisher) = publisher {
            db.record_rejection(&publisher, &row)?;
        }
        db.forget_seen_label(&label.id)?;
    }
    let failed = planned
        .declarations_failed
        .iter()
        .map(|failed| (&failed.declaration, failed.code));
    let left = planned
        .declarations_left
        .iter()
        .map(|left| (&left.declaration, left.code));
    for (declaration, code) in failed.chain(left) {
        if let Some(domain) = declaration_domain(before, declaration) {
            let mut row = rejection(code, at);
            row.id = Some(declaration.clone());
            db.record_rejection(&domain, &row)?;
        }
    }
    Ok(())
}

fn declaration_domain(before: &State, hash: &str) -> Option<String> {
    before
        .discovered
        .iter()
        .find(|(_, found)| found.iter().any(|found| found.hash == hash))
        .map(|(domain, _)| domain.clone())
}

/// WIST-3 §6.1, §6.2.
fn record_sealed_items(db: &Db, prepared: &PreparedEpoch) -> Result<()> {
    let sealed_at_s = wist_core::timestamp::log_seconds(&prepared.sealed_at)?;
    let until = crate::registry::instant(
        sealed_at_s.saturating_add(prepared.payload_window_days.saturating_mul(DAY_SECONDS)),
    )?;
    for entry in prepared
        .entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_item")
    {
        let item = &entry["body"]["item"];
        let item_id = wist_core::item::item_id(item)?;
        let url = item["url"].as_str().unwrap_or_default();
        let publisher = prepared
            .planned
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
            .ok_or_else(|| Error::Seal(format!("a sealed Item of {url} has no publication")))?;
        let kind = wist_core::item::kind(item);
        db.record_sealed_item(
            &item_id,
            &publisher,
            match kind {
                wist_core::item::Kind::Page => crate::collection::state::ItemKind::Page,
                wist_core::item::Kind::Removed => crate::collection::state::ItemKind::Removed,
            },
            prepared.epoch_number,
        )?;
        if kind == wist_core::item::Kind::Page {
            db.add_payload_duty(&item_id, &publisher, url, &until)?;
        }
    }
    for withdrawal in &prepared.withdrawals {
        db.end_payload_duty(&withdrawal.item_id)?;
    }
    Ok(())
}

pub(super) fn epoch(
    db: &Db,
    data_dir: &Path,
    client: &crate::fetch::Client,
    mutation: Mutation<'_>,
    prepared: PreparedEpoch,
) -> Result<SealReport> {
    let param_changes: Vec<ParamChangeRow> = prepared
        .accepted_changes
        .iter()
        .map(|change| {
            Ok(ParamChangeRow {
                entry_index: prepared
                    .entries
                    .iter()
                    .position(|entry| {
                        entry["type"] == "registry_update" && entry["body"] == change.body
                    })
                    .ok_or_else(|| {
                        Error::Seal("an accepted parameter_change is not sealed".into())
                    })? as u64,
                parameter: &change.parameter,
                value: change.value,
                effective_at: &change.effective_at,
            })
        })
        .collect::<Result<_>>()?;
    let withdrawal_rows: Vec<WithdrawalRow> = prepared
        .withdrawals
        .iter()
        .map(|w| WithdrawalRow {
            update_id: &w.update_id,
            item_id: &w.item_id,
            domain: &w.domain,
        })
        .collect();
    let mut sealed_labels = Vec::new();
    let mut sealed_disputes = Vec::new();
    let mut sealed_declarations = Vec::new();
    for (index, entry) in prepared.entries.iter().enumerate() {
        let body = &entry["body"];
        match entry["type"].as_str() {
            Some("label") => sealed_labels.push((
                wist_core::label::label_id(&body["label"])
                    .map_err(|r| Error::Seal(format!("sealed label: {r:?}")))?,
                index as u64,
                serde_json::from_value::<wist_core::objects::Label>(body["label"].clone())?,
            )),
            Some("dispute") => sealed_disputes.push((
                wist_core::label::dispute_id(&body["dispute"])
                    .map_err(|r| Error::Seal(format!("sealed dispute: {r:?}")))?,
                index as u64,
                serde_json::from_value::<wist_core::objects::Dispute>(body["dispute"].clone())?,
            )),
            Some("publisher_declaration") => {
                let publisher = crate::declaration::publisher_of(body).map_err(Error::Seal)?;
                sealed_declarations.push((
                    publisher.domain,
                    publisher.seq,
                    serde_json::to_vec(body)?,
                ));
            }
            _ => {}
        }
    }
    let label_rows: Vec<SealedLabelRow> = sealed_labels
        .iter()
        .map(|(id, index, label)| SealedLabelRow {
            label_id: id,
            entry_index: *index,
            label,
        })
        .collect();
    let dispute_rows: Vec<SealedDisputeRow> = sealed_disputes
        .iter()
        .map(|(id, index, dispute)| SealedDisputeRow {
            dispute_id: id,
            entry_index: *index,
            dispute,
        })
        .collect();
    let declaration_rows: Vec<SealedDeclarationRow> = sealed_declarations
        .iter()
        .map(|(domain, seq, json)| SealedDeclarationRow {
            domain,
            seq: *seq,
            declaration_json: json,
        })
        .collect();
    let signer_refs: Vec<&SigningKey> = prepared.signers.iter().collect();
    let sealed = db.commit_seal_under(
        &signer_refs,
        Some(&prepared.key_entries),
        &prepared.log_id,
        &prepared.sealed_rowids,
        prepared.epoch_number,
        &prepared.sealed_at,
        &prepared.entries,
        prepared.octets,
        &param_changes,
        &withdrawal_rows,
        &prepared.suffix_lists,
        &label_rows,
        &dispute_rows,
        &declaration_rows,
    )?;
    let mut after = prepared.planned.state.clone();
    after.declarations.seed_head(
        prepared.epoch_number,
        &sealed.root,
        Some(wist_core::timestamp::log_seconds(&prepared.sealed_at)?),
    );
    let scope: BTreeSet<String> = prepared
        .scope
        .iter()
        .cloned()
        .chain(
            after
                .collections
                .keys()
                .map(|(publisher, _)| publisher.clone()),
        )
        .chain(after.urls.keys().map(|(publisher, _)| publisher.clone()))
        .chain(after.discovered.keys().cloned())
        .collect();
    crate::db::store_changes(db, &prepared.before, &after, &scope, &prepared.sealed_at)?;
    record_sealed_items(db, &prepared)?;
    db.store_waiting_reports(&scope, &prepared.planned.deferred, &prepared.planned.held)?;
    record_reports(db, &prepared.before, &prepared.planned, &prepared.sealed_at)?;
    crate::ingest::mirror_sealed(db, &after, &scope, &prepared.sealed_at)?;
    mutation.commit()?;
    crate::publication::recover(db, data_dir)?;
    db.check_fence()?;
    super::retain(db, data_dir, &prepared.sealed_at)?;
    if let Err(error) = crate::witness::submit_head(db, client, data_dir) {
        tracing::warn!(%error, "witness submission did not complete");
    }
    db.check_fence()?;

    Ok(SealReport {
        epoch_number: prepared.epoch_number,
        entry_count: prepared.entries.len() as u64,
        dropped: prepared.dropped,
        late: prepared.late,
    })
}
