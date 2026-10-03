use super::Db;
use crate::collection::plan::{Deferred, HeldBack, Publication};
use crate::error::{Error, Result};
use rusqlite::OptionalExtension;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use wist_core::declarations::Domain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadDutyRow {
    pub item_id: String,
    pub publisher: String,
    pub url: String,
    pub until: String,
    pub served: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingReport {
    pub slot: String,
    pub deferrals: Option<Vec<String>>,
    pub held: Option<String>,
}

type ReportKey = (bool, String, String);

type KeptRow = (
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
);

fn envelope_octets(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

impl Db {
    pub(crate) fn store_waiting_reports(
        &self,
        publishers: &BTreeSet<String>,
        deferred: &[Deferred],
        held: &[HeldBack],
    ) -> Result<()> {
        for publisher in publishers {
            self.conn.execute(
                "UPDATE collections SET waiting_deferrals = NULL, waiting_held = NULL WHERE publisher = ?1",
                [publisher],
            )?;
            self.conn.execute(
                "UPDATE waiting_urls SET deferrals = NULL, held = NULL WHERE publisher = ?1",
                [publisher],
            )?;
        }
        let mut rows: BTreeMap<ReportKey, (Vec<&str>, Option<&str>)> = BTreeMap::new();
        let key = |publication: &Publication| match publication {
            Publication::Catalog {
                publisher,
                collection,
                ..
            } => Some((true, publisher.clone(), collection.clone())),
            Publication::Item { publisher, url, .. } => {
                Some((false, publisher.clone(), url.clone()))
            }
            Publication::Label { .. } => None,
        };
        for deferral in deferred {
            if let Some(key) = key(&deferral.publication) {
                rows.entry(key)
                    .or_default()
                    .0
                    .extend(deferral.reasons.iter().map(|reason| reason.as_str()));
            }
        }
        for holding in held {
            if let Some(key) = key(&holding.publication) {
                rows.entry(key).or_default().1 = Some(holding.reason.as_str());
            }
        }
        for ((catalog, publisher, slot), (reasons, hold)) in rows {
            let reasons = (!reasons.is_empty())
                .then(|| serde_json::to_string(&reasons))
                .transpose()?;
            let sql = if catalog {
                "UPDATE collections SET waiting_deferrals = ?3, waiting_held = ?4 WHERE publisher = ?1 AND name = ?2"
            } else {
                "UPDATE waiting_urls SET deferrals = ?3, held = ?4 WHERE publisher = ?1 AND url = ?2"
            };
            self.conn.execute(sql, (publisher, slot, reasons, hold))?;
        }
        Ok(())
    }

    pub fn waiting_reports(&self, publisher: &str) -> Result<Vec<WaitingReport>> {
        let mut statement = self.conn.prepare(
            "SELECT name, waiting_deferrals, waiting_held FROM collections WHERE publisher = ?1 AND (waiting_deferrals IS NOT NULL OR waiting_held IS NOT NULL)
             UNION ALL SELECT url, deferrals, held FROM waiting_urls WHERE publisher = ?1 AND (deferrals IS NOT NULL OR held IS NOT NULL)",
        )?;
        let rows = statement
            .query_map([publisher], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(slot, reasons, held)| {
                Ok(WaitingReport {
                    slot,
                    deferrals: reasons
                        .map(|reasons| serde_json::from_str(&reasons))
                        .transpose()?,
                    held,
                })
            })
            .collect()
    }

    pub(crate) fn add_payload_duty(
        &self,
        item_id: &str,
        publisher: &str,
        url: &str,
        until: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO payload_duties(item_id, publisher, url, until, served) VALUES (?1, ?2, ?3, ?4, 0)
             ON CONFLICT(item_id) DO UPDATE SET until = MAX(until, excluded.until)",
            (item_id, publisher, url, until),
        )?;
        Ok(())
    }

    pub(crate) fn end_payload_duty(&self, item_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM payload_duties WHERE item_id = ?1", [item_id])?;
        Ok(())
    }

    pub fn payload_duties(&self) -> Result<Vec<PayloadDutyRow>> {
        let mut statement = self.conn.prepare(
            "SELECT item_id, publisher, url, until, served FROM payload_duties ORDER BY publisher, url, item_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(PayloadDutyRow {
                    item_id: row.get(0)?,
                    publisher: row.get(1)?,
                    url: row.get(2)?,
                    until: row.get(3)?,
                    served: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub(crate) fn mark_payload_served(&self, item_id: &str) -> Result<()> {
        self.execute(
            "UPDATE payload_duties SET served = 1 WHERE item_id = ?1",
            [item_id],
        )?;
        Ok(())
    }

    /// WIST-3 §6.1: a record's Item keeps its duty whatever the window.
    pub(crate) fn lapsed_payload_duties(&self, now: &str) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT item_id FROM payload_duties WHERE until <= ?1 AND item_id NOT IN (SELECT item_id FROM records) ORDER BY item_id",
        )?;
        let rows = statement
            .query_map([now], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn payload_under_duty(&self, item_id: &str, now: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM payload_duties WHERE item_id = ?1 AND (until > ?2 OR item_id IN (SELECT item_id FROM records)))",
            (item_id, now),
            |row| row.get(0),
        )?)
    }

    fn kept_catalogs(&self) -> Result<BTreeSet<(String, String, String)>> {
        let mut kept = BTreeSet::new();
        let mut statement = self.conn.prepare(
            "SELECT publisher, name, latest_id, accepted_id, catalog_octets FROM collections",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (publisher, name, latest, accepted, fetched) in rows {
            let fetched = fetched
                .and_then(|octets| crate::json::parse(&octets).ok())
                .and_then(|envelope| wist_core::catalog::catalog_id(&envelope["catalog"]).ok());
            for id in [latest, accepted, fetched].into_iter().flatten() {
                kept.insert((publisher.clone(), name.clone(), id));
            }
        }
        let mut statement = self
            .conn
            .prepare("SELECT publisher, name, catalog_id FROM catalog_queue")?;
        kept.extend(
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
        Ok(kept)
    }

    /// WIST-2 §5.3: the lists of the latest, last accepted and queued Catalogs, and of the
    /// Catalog fetched last, which a refusal for a dropped record leaves held.
    pub(crate) fn discard_unkept_lists(&self) -> Result<usize> {
        let kept = self.kept_catalogs()?;
        let held: Vec<(String, String, String)> = self
            .conn
            .prepare("SELECT publisher, name, catalog_id FROM held_lists")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut discarded = 0;
        for key in held.into_iter().filter(|key| !kept.contains(key)) {
            discarded += self.conn.execute(
                "DELETE FROM held_lists WHERE publisher = ?1 AND name = ?2 AND catalog_id = ?3",
                (&key.0, &key.1, &key.2),
            )?;
        }
        Ok(discarded)
    }

    /// WIST-2 §5.3: tree files are held by hash across Collections, so where the files a kept
    /// Catalog names cannot all be read from those held, as after a chain, none is discarded.
    pub(crate) fn discard_unnamed_tree_files(&self) -> Result<usize> {
        let mut named: BTreeSet<String> = BTreeSet::new();
        for (publisher, name, catalog_id) in self.kept_catalogs()? {
            let envelope = self.kept_envelope(&publisher, &name, &catalog_id)?;
            let Some(envelope) = envelope else {
                return Ok(0);
            };
            let Ok(catalog) =
                serde_json::from_value::<wist_core::objects::Catalog>(envelope["catalog"].clone())
            else {
                return Ok(0);
            };
            let mut read = Vec::new();
            let walk =
                wist_core::tree::walk(&catalog, &wist_core::tree::TreeBounds::suite(), |hex| {
                    read.push(hex.to_owned());
                    match self.held_tree_file(hex) {
                        Ok(Some(octets)) => wist_core::tree::TreeFetch::Octets(octets),
                        _ => wist_core::tree::TreeFetch::Failed,
                    }
                });
            if !matches!(walk, wist_core::tree::Walk::Listed(_)) {
                return Ok(0);
            }
            named.extend(read);
        }
        let held: Vec<String> = self
            .conn
            .prepare("SELECT sha256 FROM tree_files")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut discarded = 0;
        for hex in held.into_iter().filter(|hex| !named.contains(hex)) {
            discarded += self
                .conn
                .execute("DELETE FROM tree_files WHERE sha256 = ?1", [&hex])?;
        }
        Ok(discarded)
    }

    fn held_tree_file(&self, hex: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT octets FROM tree_files WHERE sha256 = ?1",
                [hex],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn kept_envelope(
        &self,
        publisher: &str,
        name: &str,
        catalog_id: &str,
    ) -> Result<Option<Value>> {
        let row: Option<KeptRow> = self
            .conn
            .query_row(
                "SELECT latest_envelope, latest_id, accepted_envelope, accepted_id, catalog_octets FROM collections WHERE publisher = ?1 AND name = ?2",
                (publisher, name),
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        if let Some((latest, latest_id, accepted, accepted_id, fetched)) = row {
            for (envelope, id) in [(latest, latest_id), (accepted, accepted_id)] {
                if let (Some(envelope), Some(id)) = (envelope, id) {
                    if id == catalog_id {
                        return Ok(Some(crate::json::parse(&envelope)?));
                    }
                }
            }
            if let Some(envelope) = fetched.and_then(|octets| crate::json::parse(&octets).ok()) {
                if wist_core::catalog::catalog_id(&envelope["catalog"])
                    .ok()
                    .as_deref()
                    == Some(catalog_id)
                {
                    return Ok(Some(envelope));
                }
            }
        }
        let queued: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT envelope FROM catalog_queue WHERE publisher = ?1 AND name = ?2 AND catalog_id = ?3",
                (publisher, name, catalog_id),
                |row| row.get(0),
            )
            .optional()?;
        queued
            .map(|octets| Ok(crate::json::parse(&octets)?))
            .transpose()
    }

    pub(crate) fn payload_items_needed(&self) -> Result<BTreeSet<String>> {
        let mut needed: BTreeSet<String> = BTreeSet::new();
        for (publisher, name, catalog_id) in self.kept_catalogs()? {
            let mut statement = self.conn.prepare_cached(
                "SELECT item_id FROM list_items WHERE publisher = ?1 AND name = ?2 AND catalog_id = ?3",
            )?;
            needed.extend(
                statement
                    .query_map((&publisher, &name, &catalog_id), |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        for sql in [
            "SELECT item_id FROM records",
            "SELECT item_id FROM waiting_urls",
        ] {
            needed.extend(
                self.conn
                    .prepare(sql)?
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        Ok(needed)
    }

    pub fn discovered_declarations(&self, domain: &str) -> Result<Vec<Value>> {
        let rows: Vec<Vec<u8>> = self
            .conn
            .prepare("SELECT envelope FROM discovered_declarations WHERE domain = ?1 ORDER BY ord")?
            .query_map([domain], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.iter()
            .map(|octets| Ok(crate::json::parse(octets)?))
            .collect()
    }

    pub fn count_discovered_declarations(&self, domain: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM discovered_declarations WHERE domain = ?1",
            [domain],
            |row| row.get(0),
        )?)
    }

    /// Nothing reads these rows to judge a Declaration.
    pub(crate) fn mirror_admission(
        &self,
        domain: &str,
        sealed: Option<&Domain>,
        admission: &Domain,
        windows: &Domain,
        floor: u64,
    ) -> Result<()> {
        let current = admission.current().envelope();
        let publisher = crate::declaration::publisher_of(current).map_err(Error::History)?;
        let key = &publisher.keys[0];
        let octets = envelope_octets(current)?;
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT declaration_json FROM publishers WHERE domain = ?1",
                [domain],
                |row| row.get(0),
            )
            .optional()?;
        let unchanged = stored
            .as_deref()
            .and_then(|octets| crate::json::parse(octets).ok())
            .and_then(|stored| crate::declaration::inner_hash(&stored).ok())
            .is_some_and(|hash| hash == admission.current().hash());
        if unchanged {
            return self.mirror_windows(domain, sealed, admission, windows, floor);
        }
        if stored.is_some() {
            self.conn.execute(
                "UPDATE publishers SET declaration_json = ?2, key_id = ?3, public_key = ?4 WHERE domain = ?1",
                (domain, &octets, &key.kid, &key.x),
            )?;
        } else {
            super::exec_insert_publisher(&self.conn, domain, &octets, &key.kid, &key.x)?;
        }
        self.mirror_windows(domain, sealed, admission, windows, floor)
    }

    fn mirror_windows(
        &self,
        domain: &str,
        sealed: Option<&Domain>,
        admission: &Domain,
        windows: &Domain,
        floor: u64,
    ) -> Result<()> {
        match windows.window() {
            Some(window) => {
                let opened = sealed.and_then(Domain::window).map(|sealed| {
                    (
                        sealed.owner().position().epoch_number,
                        i64::try_from(sealed.end_s())
                            .ok()
                            .and_then(|end| crate::registry::instant(end).ok()),
                    )
                });
                self.conn.execute(
                    "INSERT INTO recovery_windows(domain, declaration_json, prior_declaration_json, owner_declaration_json, opened_epoch, window_end) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(domain) DO UPDATE SET declaration_json = excluded.declaration_json, prior_declaration_json = excluded.prior_declaration_json, owner_declaration_json = excluded.owner_declaration_json, opened_epoch = excluded.opened_epoch, window_end = excluded.window_end",
                    rusqlite::params![
                        domain,
                        envelope_octets(window.head().envelope())?,
                        envelope_octets(window.before().envelope())?,
                        envelope_octets(window.owner().envelope())?,
                        opened.as_ref().map(|(epoch, _)| *epoch as i64),
                        opened.and_then(|(_, end)| end),
                    ],
                )?;
            }
            None => {
                self.conn
                    .execute("DELETE FROM recovery_windows WHERE domain = ?1", [domain])?;
            }
        }
        match admission.pending() {
            Some(pending) => {
                self.conn.execute(
                    "INSERT INTO pending_identities(domain, declaration_json) VALUES (?1, ?2) ON CONFLICT(domain) DO UPDATE SET declaration_json = excluded.declaration_json",
                    (domain, envelope_octets(pending.head().envelope())?),
                )?;
            }
            None => {
                self.conn
                    .execute("DELETE FROM pending_identities WHERE domain = ?1", [domain])?;
            }
        }
        super::exec_retain_declaration_seq(
            &self.conn,
            domain,
            admission.highest_accepted_seq().max(floor),
        )
    }
}

pub(crate) fn remove_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
