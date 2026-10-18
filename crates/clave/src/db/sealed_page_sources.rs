use super::Db;
use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use wist_core::declarations::Effects;
use wist_core::objects::PublisherKey;

pub(crate) type SealedPageSource = (i64, u64, Vec<PublisherKey>);

impl Db {
    pub(crate) fn sealed_page_sources_recorded(&self) -> Result<Option<u64>> {
        recorded(&self.conn)
    }

    pub(crate) fn sealed_page_sources_due(&self, height: u64) -> Result<bool> {
        due(&self.conn, height)
    }

    /// WIST-2 §3.2 with WIST-1 §5.2: a pending head is a source from the Epoch
    /// it activates; a Declaration a reversal discarded or a recovery
    /// superseded is excluded from the Epoch that did so.
    pub(crate) fn record_sealed_page_sources(
        &self,
        height: u64,
        sealed_at_s: i64,
        accepted: Option<&Effects>,
        entries: &[Value],
    ) -> Result<()> {
        self.write(|conn| {
            if !due(conn, height)? {
                return Ok(());
            }
            if let Some(effects) = accepted {
                record_accepted(conn, height, sealed_at_s, effects, entries)?;
            }
            conn.execute(
                "INSERT INTO sealed_page_sources_recorded(id, epoch_number) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET epoch_number = excluded.epoch_number",
                [to_sql(height)?],
            )?;
            Ok(())
        })
    }

    pub(crate) fn sealed_page_sources(
        &self,
        domain: &str,
        at: u64,
    ) -> Result<Vec<SealedPageSource>> {
        let rows = self
            .conn
            .prepare(
                "SELECT s.sealed_at_s, s.seq, s.keys_json FROM sealed_page_sources s WHERE s.domain = ?1 AND s.epoch_number <= ?2 AND NOT EXISTS (SELECT 1 FROM sealed_page_exclusions x WHERE x.domain = s.domain AND x.hash = s.hash AND x.epoch_number <= ?2) ORDER BY s.epoch_number, s.ordinal",
            )?
            .query_map((domain, to_sql(at)?), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(sealed_at_s, seq, keys)| {
                let seq = u64::try_from(seq).map_err(|_| {
                    Error::History("a sealed Page source has a negative seq".into())
                })?;
                Ok((sealed_at_s, seq, serde_json::from_slice(&keys)?))
            })
            .collect()
    }
}

fn to_sql(height: u64) -> Result<i64> {
    i64::try_from(height)
        .map_err(|_| Error::History("Epoch height out of the store's range".into()))
}

fn recorded(conn: &Connection) -> Result<Option<u64>> {
    let height: Option<i64> = conn
        .query_row(
            "SELECT epoch_number FROM sealed_page_sources_recorded WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    height
        .map(|height| {
            u64::try_from(height)
                .map_err(|_| Error::History("a negative recorded sealed Page height".into()))
        })
        .transpose()
}

fn due(conn: &Connection, height: u64) -> Result<bool> {
    Ok(match recorded(conn)? {
        None => height == 0,
        Some(recorded) => recorded.checked_add(1) == Some(height),
    })
}

fn exclude(conn: &Connection, domain: &str, hash: &str, height: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO sealed_page_exclusions(domain, hash, epoch_number) VALUES (?1, ?2, ?3) ON CONFLICT(domain, hash) DO UPDATE SET epoch_number = MIN(epoch_number, excluded.epoch_number)",
        (domain, hash, height),
    )?;
    Ok(())
}

fn record_accepted(
    conn: &Connection,
    height: u64,
    sealed_at_s: i64,
    effects: &Effects,
    entries: &[Value],
) -> Result<()> {
    let height = to_sql(height)?;
    for settlement in &effects.settlements {
        for superseded in &settlement.superseded {
            exclude(conn, &settlement.domain, superseded.hash(), height)?;
        }
    }
    for installation in &effects.installations {
        let Some(domain) = installation.declaration.envelope()["publisher"]["domain"].as_str()
        else {
            continue;
        };
        if installation.pending {
            conn.execute(
                "INSERT OR IGNORE INTO sealed_page_pending_heads(domain, hash) VALUES (?1, ?2)",
                (domain, installation.declaration.hash()),
            )?;
        }
        if installation.reversed.is_some() {
            conn.execute(
                "INSERT INTO sealed_page_exclusions(domain, hash, epoch_number) SELECT domain, hash, ?2 FROM sealed_page_pending_heads WHERE domain = ?1 ON CONFLICT(domain, hash) DO UPDATE SET epoch_number = MIN(epoch_number, excluded.epoch_number)",
                (domain, height),
            )?;
            conn.execute(
                "DELETE FROM sealed_page_pending_heads WHERE domain = ?1",
                [domain],
            )?;
        }
    }
    let mut ordinal = 0_i64;
    let mut source = |domain: &str, hash: &str, envelope: &Value| -> Result<()> {
        let publisher = crate::declaration::publisher_of(envelope).map_err(Error::History)?;
        conn.execute(
            "INSERT INTO sealed_page_sources(domain, hash, epoch_number, ordinal, sealed_at_s, seq, keys_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(domain, hash, epoch_number) DO NOTHING",
            (
                domain,
                hash,
                height,
                ordinal,
                sealed_at_s,
                i64::try_from(publisher.seq)
                    .map_err(|_| Error::History("a Declaration seq out of range".into()))?,
                serde_json::to_vec(&publisher.keys)?,
            ),
        )?;
        ordinal += 1;
        Ok(())
    };
    for activation in &effects.activations {
        conn.execute(
            "DELETE FROM sealed_page_pending_heads WHERE domain = ?1 AND hash = ?2",
            (&activation.domain, activation.activated.hash()),
        )?;
        source(
            &activation.domain,
            activation.activated.hash(),
            activation.activated.envelope(),
        )?;
    }
    for entry in entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_declaration")
    {
        let body = &entry["body"];
        let Some(domain) = body["publisher"]["domain"].as_str() else {
            continue;
        };
        let hash = crate::declaration::inner_hash(body).map_err(Error::History)?;
        let held: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sealed_page_pending_heads WHERE domain = ?1 AND hash = ?2) OR EXISTS(SELECT 1 FROM sealed_page_exclusions WHERE domain = ?1 AND hash = ?2)",
            (domain, &hash),
            |row| row.get(0),
        )?;
        if !held {
            source(domain, &hash, body)?;
        }
    }
    Ok(())
}
