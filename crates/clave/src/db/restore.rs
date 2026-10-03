use super::{accepted_declaration_seq, exec_retain_declaration_seq, Db};
use crate::error::{Error, Result};
use crate::history::declarations::DeclarationsReplay;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use wist_core::item::Kind;
use wist_core::sealing::Judgment;

/// Runs in dependency order: each restoration may read what an earlier one
/// restored.
pub(super) fn run(db: &Db, path: &Path) -> Result<()> {
    db.parameter_schedule(0)?;
    db.restore_recovery_owners(path)?;
    db.restore_declaration_floors(path)?;
    db.restore_pull_schedule()
}

impl Db {
    pub(super) fn restore_declaration_floors(&self, path: &Path) -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let rows = tx
            .prepare("SELECT domain, declaration_json FROM publishers WHERE domain NOT IN (SELECT domain FROM declaration_floors) ORDER BY domain")?
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.is_empty() {
            tx.commit()?;
            return Ok(());
        }
        let head = self.last_epoch()?;
        let history = if head.is_some() {
            crate::history::declarations::Declarations::reconstruct(
                self,
                path.parent().unwrap_or_else(|| Path::new(".")),
                head,
            )?
        } else {
            crate::history::declarations::Declarations::default()
        };
        for (domain, raw) in rows {
            let current: Value = crate::json::parse(&raw)?;
            let mut seq = accepted_declaration_seq(&domain, &current)?;
            if let Some(state) = history.domains().get(&domain) {
                seq = seq.max(state.highest_accepted_seq());
            }
            for envelope in self.discovered_declarations(&domain)? {
                seq = seq.max(accepted_declaration_seq(&domain, &envelope)?);
            }
            exec_retain_declaration_seq(&tx, &domain, seq)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(super) fn restore_recovery_owners(&self, path: &Path) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT domain, prior_declaration_json, opened_epoch FROM recovery_windows WHERE owner_declaration_json IS NULL ORDER BY domain",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<u64>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if rows.is_empty() {
            return Ok(());
        }
        let history = if rows.iter().any(|(_, _, opened)| opened.is_some()) {
            Some(crate::history::declarations::Declarations::reconstruct(
                self,
                path.parent().unwrap_or_else(|| Path::new(".")),
                self.last_epoch()?,
            )?)
        } else {
            None
        };
        let at = match self.last_epoch()? {
            Some(head) => crate::registry::unix(&head.sealed_at)?,
            None => 0,
        };
        let limits = crate::declaration::limits(&self.parameter_schedule(at)?, at)?;
        let tx = self.mutation()?;
        for (domain, prior, opened) in rows {
            let prior: Value = crate::json::parse(&prior)?;
            let unavailable = || {
                Error::History(format!(
                    "cannot restore the fixed recovery owner for {domain}"
                ))
            };
            let owner = if let Some(opened) = opened {
                let window = history
                    .as_ref()
                    .and_then(|state| state.domains().get(&domain))
                    .and_then(|state| state.window())
                    .ok_or_else(unavailable)?;
                if window.owner().position().epoch_number != opened
                    || *window.before().envelope() != prior
                {
                    return Err(unavailable());
                }
                window.owner().envelope().clone()
            } else {
                let mut candidates = Vec::new();
                for envelope in self.discovered_declarations(&domain)? {
                    if crate::declaration::evaluate(&prior, &envelope, &limits)
                        == Ok(crate::declaration::Decision::Recovery)
                        && !candidates.contains(&envelope)
                    {
                        candidates.push(envelope);
                    }
                }
                if candidates.len() != 1 {
                    return Err(unavailable());
                }
                candidates.pop().unwrap()
            };
            tx.execute(
                "UPDATE recovery_windows SET owner_declaration_json = ?2 WHERE domain = ?1",
                (&domain, serde_json::to_vec(&owner)?),
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Restored {
    pub collections: usize,
    pub records: usize,
    pub removals: usize,
    pub sealed_items: usize,
    pub withdrawals: usize,
    pub payload_duties: usize,
}

struct Withdrawn {
    update_id: String,
    sealed_at: String,
}

impl Db {
    /// WIST-3 §6.1, §6.2, §7.
    pub fn restore_from_log(&self, data_dir: &Path) -> Result<Restored> {
        let mut history = crate::history::History::open(self, data_dir, self.last_epoch()?)?;
        let mut record_heights: BTreeMap<(String, String), u64> = BTreeMap::new();
        let mut sealed_items: BTreeMap<(String, String, &'static str), u64> = BTreeMap::new();
        let mut duty_until: BTreeMap<String, i64> = BTreeMap::new();
        let mut withdrawn: BTreeMap<(String, u64), Withdrawn> = BTreeMap::new();
        let mut head_sealed_at = None;
        while let Some(epoch) = history.next_epoch()? {
            let height = epoch.epoch_number();
            let window_days = history
                .schedule()
                .and_then(|schedule| schedule.value_at("payload_window_days", epoch.sealed_at_s()))
                .ok_or_else(|| Error::History("no payload_window_days in force".into()))?;
            for (entry, judgment) in epoch.entries().iter().zip(epoch.judgments()) {
                if judgment != &Some(Judgment::Valid) {
                    continue;
                }
                let body = &entry["body"];
                match entry["type"].as_str() {
                    Some("publisher_item") => {
                        let item = &body["item"];
                        let item_id = wist_core::item::item_id(item)?;
                        let publisher = text(item, "publisher")?;
                        let url = text(item, "url")?;
                        let kind = match wist_core::item::kind(item) {
                            Kind::Page => {
                                record_heights.insert((publisher.clone(), url), height);
                                let until = epoch
                                    .sealed_at_s()
                                    .saturating_add(window_days.saturating_mul(86_400));
                                let slot = duty_until.entry(item_id.clone()).or_insert(until);
                                *slot = (*slot).max(until);
                                "page"
                            }
                            Kind::Removed => "removed",
                        };
                        sealed_items
                            .entry((item_id, publisher, kind))
                            .or_insert(height);
                    }
                    Some("registry_update") if body["update"]["action"] == "payload_withdrawal" => {
                        let item_id = text(&body["update"]["details"], "delta_id")?;
                        withdrawn.entry((item_id, height)).or_insert(Withdrawn {
                            update_id: crate::governance::update_id(&body["update"])?,
                            sealed_at: epoch.sealed_at().to_owned(),
                        });
                    }
                    _ => {}
                }
            }
            head_sealed_at = Some(epoch.sealed_at().to_owned());
        }
        let replay = history.replay();
        let duties = match &head_sealed_at {
            Some(at) => replay.payload_duties(at)?,
            None => Vec::new(),
        };
        let tx = self.mutation()?;
        tx.execute_batch(
            "DELETE FROM records; DELETE FROM removals; DELETE FROM sealed_items; DELETE FROM withdrawals; DELETE FROM payload_duties;
             UPDATE collections SET latest_envelope = NULL, latest_id = NULL, latest_height = NULL, latest_base = NULL;",
        )?;
        for (domain, state) in replay.declarations().domains() {
            tx.execute(
                "INSERT INTO sealed_in_force(domain, declaration_json) VALUES (?1, ?2) ON CONFLICT(domain) DO UPDATE SET declaration_json = excluded.declaration_json",
                (domain, serde_json::to_vec(state.current().envelope())?),
            )?;
        }
        let mut restored = Restored::default();
        for (publisher, name, latest) in replay.latest_catalogs() {
            tx.execute(
                "INSERT INTO collections(publisher, name, latest_envelope, latest_id, latest_height, latest_base, left_chain) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)
                 ON CONFLICT(publisher, name) DO UPDATE SET latest_envelope = excluded.latest_envelope, latest_id = excluded.latest_id, latest_height = excluded.latest_height, latest_base = excluded.latest_base",
                rusqlite::params![
                    publisher,
                    name,
                    serde_json::to_vec(&latest.envelope)?,
                    latest.catalog_id,
                    latest.sealing_height as i64,
                    latest.base,
                ],
            )?;
            restored.collections += 1;
        }
        for (publisher, url, record) in replay.records().records() {
            let height = record_heights
                .get(&(publisher.to_owned(), url.to_owned()))
                .copied()
                .ok_or_else(|| Error::History(format!("no Entry sealed the record of {url}")))?;
            tx.execute(
                "INSERT INTO records(publisher, url, item, item_id, collection, catalog_id, generated_at, sealing_height) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    publisher,
                    url,
                    serde_json::to_vec(&record.item)?,
                    record.item_id,
                    record.collection,
                    record.catalog,
                    record.generated_at,
                    height as i64,
                ],
            )?;
            restored.records += 1;
        }
        for (publisher, url, removal) in replay.records().removals() {
            tx.execute(
                "INSERT INTO removals(publisher, url, item_id, catalog_id, generated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                (publisher, url, &removal.item_id, &removal.catalog, &removal.generated_at),
            )?;
            restored.removals += 1;
        }
        for ((item_id, publisher, kind), height) in &sealed_items {
            tx.execute(
                "INSERT INTO sealed_items(item_id, publisher, kind, first_height) VALUES (?1, ?2, ?3, ?4)",
                (item_id, publisher, kind, *height as i64),
            )?;
            restored.sealed_items += 1;
        }
        for entry in replay.withdrawals().entries() {
            let act = withdrawn
                .get(&(entry.item_id.clone(), entry.sealing_height))
                .ok_or_else(|| {
                    Error::History(format!("no sealed act withdraws {}", entry.item_id))
                })?;
            tx.execute(
                "INSERT INTO withdrawals(item_id, domain, update_id, epoch_number, sealed_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    &entry.item_id,
                    &entry.publisher,
                    &act.update_id,
                    entry.sealing_height as i64,
                    &act.sealed_at,
                ),
            )?;
            restored.withdrawals += 1;
        }
        for duty in duties {
            let until = duty_until.get(&duty.item_id).copied().ok_or_else(|| {
                Error::History(format!("no Entry sealed the Item of duty {}", duty.item_id))
            })?;
            let served = crate::db::served_payload_path(data_dir, &duty.item_id)?.exists();
            tx.execute(
                "INSERT INTO payload_duties(item_id, publisher, url, until, served) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    duty.item_id,
                    duty.publisher,
                    duty.url,
                    crate::registry::instant(until)?,
                    served,
                ],
            )?;
            restored.payload_duties += 1;
        }
        tx.commit()?;
        for entry in replay.withdrawals().entries() {
            crate::db::remove_file(&crate::db::served_payload_path(data_dir, &entry.item_id)?)?;
            crate::db::remove_file(&crate::db::held_payload_path(data_dir, &entry.item_id)?)?;
        }
        Ok(restored)
    }
}

fn text(value: &Value, member: &str) -> Result<String> {
    value[member]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::History(format!("a sealed Entry has no {member}")))
}
