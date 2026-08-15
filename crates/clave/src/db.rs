use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;
use wist_core::objects::{PublisherState, StatusRejection};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS publishers(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new', last_pull_at TEXT);
CREATE TABLE IF NOT EXISTS seen_deltas(delta_id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_entries(rowid INTEGER PRIMARY KEY AUTOINCREMENT, entry_type TEXT NOT NULL, domain TEXT NOT NULL, entry_json BLOB NOT NULL, chain_pos INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(url TEXT NOT NULL, publisher TEXT NOT NULL, delta_id TEXT NOT NULL, observed_at TEXT NOT NULL, weight TEXT NOT NULL, title TEXT NOT NULL, abstract TEXT, lang TEXT NOT NULL, PRIMARY KEY(url, publisher));
CREATE TABLE IF NOT EXISTS blocks(block_number INTEGER PRIMARY KEY, block_hash TEXT NOT NULL, sealed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rejections(domain TEXT NOT NULL, code TEXT NOT NULL, at TEXT NOT NULL, delta_id TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS params(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS url_tips(url TEXT PRIMARY KEY, domain TEXT NOT NULL, tip TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS param_changes(parameter TEXT NOT NULL, value INTEGER NOT NULL, effective_at TEXT NOT NULL, block_number INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS noise_pings(domain TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS ingest_meter(domain TEXT NOT NULL, day TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS walk_state(domain TEXT PRIMARY KEY, suspended INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS governance(update_id TEXT PRIMARY KEY, action TEXT NOT NULL, domain TEXT NOT NULL, level INTEGER, notice_id TEXT, outcome TEXT, sealed_at TEXT NOT NULL, block_number INTEGER NOT NULL);
";

pub struct PublisherRow {
    pub key_id: String,
    pub public_key: String,
}

pub struct PendingEntry {
    pub entry_type: String,
    pub domain: String,
    pub entry_json: Value,
}

pub struct PublisherStatusRow {
    pub last_pull_at: Option<String>,
    pub state: PublisherState,
}

pub struct BlockRow {
    pub block_number: u64,
    pub block_hash: String,
    pub sealed_at: String,
}

pub struct RecordRow {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub observed_at: String,
    pub weight: String,
    pub title: String,
    pub abstract_text: Option<String>,
    pub lang: String,
}

pub struct PublisherListRow {
    pub domain: String,
    pub declaration_json: Vec<u8>,
}

pub struct PendingEntryRow {
    pub rowid: i64,
    pub entry_type: String,
    pub domain: String,
    pub entry_json: Value,
}

pub struct ParamChangeRow<'a> {
    pub parameter: &'a str,
    pub value: i64,
    pub effective_at: &'a str,
}

pub struct GovernanceRow<'a> {
    pub update_id: &'a str,
    pub action: &'a str,
    pub domain: &'a str,
    pub level: Option<i64>,
    pub notice_id: Option<&'a str>,
    pub outcome: Option<&'a str>,
}

pub struct GovernanceEntry {
    pub update_id: String,
    pub action: String,
    pub domain: String,
    pub level: Option<i64>,
    pub notice_id: Option<String>,
    pub outcome: Option<String>,
    pub sealed_at: String,
    pub block_number: u64,
}

pub struct RecordUpsert<'a> {
    pub url: &'a str,
    pub publisher: &'a str,
    pub delta_id: &'a str,
    pub observed_at: &'a str,
    pub weight: &'a str,
    pub title: &'a str,
    pub abstract_text: Option<&'a str>,
    pub lang: &'a str,
}

fn exec_insert_publisher(
    conn: &Connection,
    domain: &str,
    declaration_json: &[u8],
    key_id: &str,
    public_key: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO publishers(domain, declaration_json, key_id, public_key) VALUES (?1, ?2, ?3, ?4)",
        (domain, declaration_json, key_id, public_key),
    )?;
    Ok(())
}

fn exec_insert_pending_entry(
    conn: &Connection,
    entry_type: &str,
    domain: &str,
    entry_json: &Value,
    chain_pos: i64,
) -> Result<()> {
    let bytes = serde_json::to_vec(entry_json)?;
    conn.execute(
        "INSERT INTO pending_entries(entry_type, domain, entry_json, chain_pos) VALUES (?1, ?2, ?3, ?4)",
        (entry_type, domain, bytes, chain_pos),
    )?;
    Ok(())
}

fn exec_insert_seen_delta(conn: &Connection, delta_id: &str, domain: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO seen_deltas(delta_id, domain) VALUES (?1, ?2)",
        (delta_id, domain),
    )?;
    Ok(())
}

fn exec_set_url_tip(conn: &Connection, url: &str, domain: &str, tip: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO url_tips(url, domain, tip) VALUES (?1, ?2, ?3) ON CONFLICT(url) DO UPDATE SET tip = excluded.tip, domain = excluded.domain",
        (url, domain, tip),
    )?;
    Ok(())
}

fn exec_upsert_record(conn: &Connection, r: &RecordUpsert) -> Result<()> {
    conn.execute(
        "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(url, publisher) DO UPDATE SET delta_id = excluded.delta_id, observed_at = excluded.observed_at, weight = excluded.weight, title = excluded.title, abstract = excluded.abstract, lang = excluded.lang",
        (
            r.url,
            r.publisher,
            r.delta_id,
            r.observed_at,
            r.weight,
            r.title,
            r.abstract_text,
            r.lang,
        ),
    )?;
    Ok(())
}

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn })
    }

    pub fn param(&self, name: &str) -> Result<i64> {
        self.conn
            .query_row("SELECT value FROM params WHERE name = ?1", [name], |row| {
                row.get(0)
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::Param(name.to_string()),
                other => Error::Db(other),
            })
    }

    pub fn set_param(&self, name: &str, value: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO params(name, value) VALUES (?1, ?2) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            (name, value),
        )?;
        Ok(())
    }

    pub fn get_publisher(&self, domain: &str) -> Result<Option<PublisherRow>> {
        self.conn
            .query_row(
                "SELECT key_id, public_key FROM publishers WHERE domain = ?1",
                [domain],
                |row| {
                    Ok(PublisherRow {
                        key_id: row.get(0)?,
                        public_key: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Error::Db)
    }

    pub fn get_publisher_scope(&self, domain: &str) -> Result<Option<Vec<String>>> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT declaration_json FROM publishers WHERE domain = ?1",
                [domain],
                |row| row.get(0),
            )
            .optional()
            .map_err(Error::Db)?;
        let Some(blob) = blob else {
            return Ok(None);
        };
        let doc: Value = serde_json::from_slice(&blob)?;
        Ok(doc
            .pointer("/publisher/subdomain_scope")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok()))
    }

    pub fn insert_publisher(
        &self,
        domain: &str,
        declaration_json: &[u8],
        key_id: &str,
        public_key: &str,
    ) -> Result<()> {
        exec_insert_publisher(&self.conn, domain, declaration_json, key_id, public_key)
    }

    pub fn record_publisher_declaration(
        &self,
        domain: &str,
        declaration_json: &[u8],
        key_id: &str,
        public_key: &str,
        entry_json: &Value,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        exec_insert_publisher(&tx, domain, declaration_json, key_id, public_key)?;
        exec_insert_pending_entry(&tx, "publisher_declaration", domain, entry_json, 0)?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_publisher_pulled(&self, domain: &str, now: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE publishers SET last_pull_at = ?2, state = 'active' WHERE domain = ?1",
            (domain, now),
        )?;
        Ok(())
    }

    pub fn is_delta_seen(&self, delta_id: &str) -> Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM seen_deltas WHERE delta_id = ?1",
                [delta_id],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(Error::Db)
    }

    pub fn insert_seen_delta(&self, delta_id: &str, domain: &str) -> Result<()> {
        exec_insert_seen_delta(&self.conn, delta_id, domain)
    }

    pub fn insert_pending_entry(
        &self,
        entry_type: &str,
        domain: &str,
        entry_json: &Value,
        chain_pos: i64,
    ) -> Result<()> {
        exec_insert_pending_entry(&self.conn, entry_type, domain, entry_json, chain_pos)
    }

    pub fn count_pending_entries(&self, entry_type: &str) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM pending_entries WHERE entry_type = ?1",
                [entry_type],
                |row| row.get(0),
            )
            .map_err(Error::Db)
    }

    pub fn drain_pending_entries(&self) -> Result<Vec<PendingEntry>> {
        let tx = self.conn.unchecked_transaction()?;
        let mut stmt = tx
            .prepare("SELECT entry_type, domain, entry_json FROM pending_entries ORDER BY rowid")?;
        let rows: Vec<(String, String, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        tx.execute("DELETE FROM pending_entries", [])?;
        tx.commit()?;
        rows.into_iter()
            .map(|(entry_type, domain, blob)| {
                Ok(PendingEntry {
                    entry_type,
                    domain,
                    entry_json: serde_json::from_slice(&blob)?,
                })
            })
            .collect()
    }

    pub fn last_block(&self) -> Result<Option<BlockRow>> {
        self.conn
            .query_row(
                "SELECT block_number, block_hash, sealed_at FROM blocks ORDER BY block_number DESC LIMIT 1",
                [],
                |row| {
                    Ok(BlockRow {
                        block_number: row.get::<_, i64>(0)? as u64,
                        block_hash: row.get(1)?,
                        sealed_at: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Error::Db)
    }

    pub fn peek_pending_entries(&self) -> Result<(Vec<PendingEntryRow>, i64)> {
        let mut stmt = self.conn.prepare(
            "SELECT rowid, entry_type, domain, entry_json FROM pending_entries ORDER BY rowid ASC",
        )?;
        let rows: Vec<(i64, String, String, Vec<u8>)> = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let max_rowid = rows.iter().map(|(rowid, ..)| *rowid).max().unwrap_or(0);
        let entries = rows
            .into_iter()
            .map(|(rowid, entry_type, domain, blob)| {
                Ok(PendingEntryRow {
                    rowid,
                    entry_type,
                    domain,
                    entry_json: serde_json::from_slice(&blob)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok((entries, max_rowid))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_seal(
        &self,
        up_to_rowid: i64,
        block_number: u64,
        block_hash: &str,
        sealed_at: &str,
        records: &[RecordUpsert],
        param_changes: &[ParamChangeRow],
        governance: &[GovernanceRow],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM pending_entries WHERE rowid <= ?1",
            [up_to_rowid],
        )?;
        tx.execute(
            "INSERT INTO blocks(block_number, block_hash, sealed_at) VALUES (?1, ?2, ?3)",
            (block_number as i64, block_hash, sealed_at),
        )?;
        for r in records {
            exec_upsert_record(&tx, r)?;
        }
        for c in param_changes {
            tx.execute(
                "INSERT INTO param_changes(parameter, value, effective_at, block_number) VALUES (?1, ?2, ?3, ?4)",
                (c.parameter, c.value, c.effective_at, block_number as i64),
            )?;
        }
        for g in governance {
            tx.execute(
                "INSERT INTO governance(update_id, action, domain, level, notice_id, outcome, sealed_at, block_number) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    g.update_id,
                    g.action,
                    g.domain,
                    g.level,
                    g.notice_id,
                    g.outcome,
                    sealed_at,
                    block_number as i64,
                ),
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn bump_noise_ping(&self, domain: &str, day: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO noise_pings(domain, day, count) VALUES (?1, ?2, 1) ON CONFLICT(domain, day) DO UPDATE SET count = count + 1",
            (domain, day),
        )?;
        Ok(())
    }

    pub fn noise_ping_count(&self, domain: &str, day: &str) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT count FROM noise_pings WHERE domain = ?1 AND day = ?2",
                (domain, day),
                |row| row.get(0),
            )
            .optional()
            .map(|v| v.unwrap_or(0))
            .map_err(Error::Db)
    }

    pub fn add_ingest_bytes(&self, domain: &str, day: &str, bytes: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO ingest_meter(domain, day, bytes) VALUES (?1, ?2, ?3) ON CONFLICT(domain, day) DO UPDATE SET bytes = bytes + excluded.bytes",
            (domain, day, bytes),
        )?;
        Ok(())
    }

    pub fn ingest_bytes(&self, domain: &str, day: &str) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT bytes FROM ingest_meter WHERE domain = ?1 AND day = ?2",
                (domain, day),
                |row| row.get(0),
            )
            .optional()
            .map(|v| v.unwrap_or(0))
            .map_err(Error::Db)
    }

    pub fn set_walk_suspended(&self, domain: &str, suspended: bool) -> Result<()> {
        self.conn.execute(
            "INSERT INTO walk_state(domain, suspended) VALUES (?1, ?2) ON CONFLICT(domain) DO UPDATE SET suspended = excluded.suspended",
            (domain, suspended as i64),
        )?;
        Ok(())
    }

    pub fn walk_suspended(&self, domain: &str) -> Result<bool> {
        self.conn
            .query_row(
                "SELECT suspended FROM walk_state WHERE domain = ?1",
                [domain],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map(|v| v.unwrap_or(0) != 0)
            .map_err(Error::Db)
    }

    pub fn delete_record_by_delta(&self, delta_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM records WHERE delta_id = ?1", [delta_id])?;
        Ok(())
    }

    pub fn governance_by_action(&self, action: &str) -> Result<Vec<GovernanceEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT update_id, action, domain, level, notice_id, outcome, sealed_at, block_number FROM governance WHERE action = ?1 ORDER BY sealed_at ASC, block_number ASC",
        )?;
        let rows = stmt
            .query_map([action], |row| {
                Ok(GovernanceEntry {
                    update_id: row.get(0)?,
                    action: row.get(1)?,
                    domain: row.get(2)?,
                    level: row.get(3)?,
                    notice_id: row.get(4)?,
                    outcome: row.get(5)?,
                    sealed_at: row.get(6)?,
                    block_number: row.get::<_, i64>(7)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn governance_for_domain(&self, domain: &str) -> Result<Vec<GovernanceEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT update_id, action, domain, level, notice_id, outcome, sealed_at, block_number FROM governance WHERE domain = ?1 ORDER BY sealed_at ASC, block_number ASC",
        )?;
        let rows = stmt
            .query_map([domain], |row| {
                Ok(GovernanceEntry {
                    update_id: row.get(0)?,
                    action: row.get(1)?,
                    domain: row.get(2)?,
                    level: row.get(3)?,
                    notice_id: row.get(4)?,
                    outcome: row.get(5)?,
                    sealed_at: row.get(6)?,
                    block_number: row.get::<_, i64>(7)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn latest_param_change(&self, name: &str, at: &str) -> Result<Option<i64>> {
        self.conn
            .query_row(
                "SELECT value FROM param_changes WHERE parameter = ?1 AND effective_at <= ?2 ORDER BY effective_at DESC, block_number DESC LIMIT 1",
                (name, at),
                |row| row.get(0),
            )
            .optional()
            .map_err(Error::Db)
    }

    pub fn get_record(&self, url: &str, publisher: &str) -> Result<Option<RecordRow>> {
        self.conn
            .query_row(
                "SELECT url, publisher, delta_id, observed_at, weight, title, abstract, lang FROM records WHERE url = ?1 AND publisher = ?2",
                (url, publisher),
                |row| {
                    Ok(RecordRow {
                        url: row.get(0)?,
                        publisher: row.get(1)?,
                        delta_id: row.get(2)?,
                        observed_at: row.get(3)?,
                        weight: row.get(4)?,
                        title: row.get(5)?,
                        abstract_text: row.get(6)?,
                        lang: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Error::Db)
    }

    pub fn list_records(&self) -> Result<Vec<RecordRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT url, publisher, delta_id, observed_at, weight, title, abstract, lang FROM records ORDER BY publisher, url",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(RecordRow {
                    url: row.get(0)?,
                    publisher: row.get(1)?,
                    delta_id: row.get(2)?,
                    observed_at: row.get(3)?,
                    weight: row.get(4)?,
                    title: row.get(5)?,
                    abstract_text: row.get(6)?,
                    lang: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_publishers(&self) -> Result<Vec<PublisherListRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT domain, declaration_json FROM publishers ORDER BY domain")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(PublisherListRow {
                    domain: row.get(0)?,
                    declaration_json: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn url_tip(&self, url: &str) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT tip FROM url_tips WHERE url = ?1", [url], |row| {
                row.get(0)
            })
            .optional()
            .map_err(Error::Db)
    }

    pub fn set_url_tip(&self, url: &str, domain: &str, tip: &str) -> Result<()> {
        exec_set_url_tip(&self.conn, url, domain, tip)
    }

    pub fn record_accepted_delta(
        &self,
        domain: &str,
        delta_id: &str,
        entry_json: &Value,
        chain_pos: i64,
        url: &str,
        tip: &str,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        exec_insert_seen_delta(&tx, delta_id, domain)?;
        exec_insert_pending_entry(&tx, "publisher_delta", domain, entry_json, chain_pos)?;
        exec_set_url_tip(&tx, url, domain, tip)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_publisher_status(&self, domain: &str) -> Result<Option<PublisherStatusRow>> {
        let row: Option<(Option<String>, String)> = self
            .conn
            .query_row(
                "SELECT last_pull_at, state FROM publishers WHERE domain = ?1",
                [domain],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(Error::Db)?;
        row.map(|(last_pull_at, state)| {
            Ok(PublisherStatusRow {
                last_pull_at,
                state: serde_json::from_value(Value::String(state))?,
            })
        })
        .transpose()
    }

    pub fn list_rejections(&self, domain: &str) -> Result<Vec<StatusRejection>> {
        let mut stmt = self.conn.prepare(
            "SELECT code, at, delta_id, detail FROM rejections WHERE domain = ?1 ORDER BY rowid DESC",
        )?;
        let rows = stmt
            .query_map([domain], |row| {
                Ok(StatusRejection {
                    code: row.get(0)?,
                    at: row.get(1)?,
                    delta_id: row.get(2)?,
                    detail: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn insert_rejection(
        &self,
        domain: &str,
        code: &str,
        at: &str,
        delta_id: Option<&str>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO rejections(domain, code, at, delta_id, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            (domain, code, at, delta_id, detail),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_applies_schema_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clave.sqlite");
        Db::open(&path).unwrap();
        Db::open(&path).unwrap();
    }

    #[test]
    fn open_sets_wal_journal_and_busy_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        let mode: String = db
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let timeout: i64 = db
            .conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000);
    }

    #[test]
    fn concurrent_writer_waits_out_a_held_write_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clave.sqlite");
        let db1 = Db::open(&path).unwrap();
        db1.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        db1.conn
            .execute("INSERT INTO params(name, value) VALUES ('a', 1)", [])
            .unwrap();
        let handle = std::thread::spawn(move || {
            let db2 = Db::open(&path).unwrap();
            db2.set_param("b", 2)
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        db1.conn.execute_batch("COMMIT").unwrap();
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn set_param_then_param_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.set_param("block_cadence_seconds", 3600).unwrap();
        assert_eq!(db.param("block_cadence_seconds").unwrap(), 3600);
        db.set_param("block_cadence_seconds", 60).unwrap();
        assert_eq!(db.param("block_cadence_seconds").unwrap(), 60);
    }

    #[test]
    fn param_missing_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(db.param("nope").is_err());
    }

    #[test]
    fn commit_seal_records_param_changes_for_latest_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.commit_seal(
            0,
            0,
            "sha256:h0",
            "2026-01-01T00:00:00Z",
            &[],
            &[ParamChangeRow {
                parameter: "feed_window",
                value: 500,
                effective_at: "2026-01-10T00:00:00Z",
            }],
            &[],
        )
        .unwrap();
        assert_eq!(
            db.latest_param_change("feed_window", "2026-01-09T23:59:59Z")
                .unwrap(),
            None
        );
        assert_eq!(
            db.latest_param_change("feed_window", "2026-01-10T00:00:00Z")
                .unwrap(),
            Some(500)
        );
        db.commit_seal(
            0,
            1,
            "sha256:h1",
            "2026-01-02T00:00:00Z",
            &[],
            &[ParamChangeRow {
                parameter: "feed_window",
                value: 800,
                effective_at: "2026-01-20T00:00:00Z",
            }],
            &[],
        )
        .unwrap();
        assert_eq!(
            db.latest_param_change("feed_window", "2026-01-15T00:00:00Z")
                .unwrap(),
            Some(500)
        );
        assert_eq!(
            db.latest_param_change("feed_window", "2026-01-25T00:00:00Z")
                .unwrap(),
            Some(800)
        );
    }

    #[test]
    fn publisher_roundtrips_and_pulled_state() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(db.get_publisher("example.com").unwrap().is_none());
        db.insert_publisher("example.com", b"{}", "k1", "pk")
            .unwrap();
        let row = db.get_publisher("example.com").unwrap().unwrap();
        assert_eq!(row.key_id, "k1");
        assert_eq!(row.public_key, "pk");
        db.set_publisher_pulled("example.com", "2026-08-09T00:00:00Z")
            .unwrap();
    }

    #[test]
    fn seen_delta_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(!db.is_delta_seen("sha256:abc").unwrap());
        db.insert_seen_delta("sha256:abc", "example.com").unwrap();
        assert!(db.is_delta_seen("sha256:abc").unwrap());
    }

    #[test]
    fn pending_entries_count_by_type() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 0);
        db.insert_pending_entry("publisher_delta", "example.com", &Value::Null, 0)
            .unwrap();
        assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
        assert_eq!(
            db.count_pending_entries("publisher_declaration").unwrap(),
            0
        );
    }

    #[test]
    fn url_tip_roundtrips_and_updates() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(db.url_tip("https://example.com/a").unwrap().is_none());
        db.set_url_tip("https://example.com/a", "example.com", "sha256:1")
            .unwrap();
        assert_eq!(
            db.url_tip("https://example.com/a").unwrap().unwrap(),
            "sha256:1"
        );
        db.set_url_tip("https://example.com/a", "example.com", "sha256:2")
            .unwrap();
        assert_eq!(
            db.url_tip("https://example.com/a").unwrap().unwrap(),
            "sha256:2"
        );
    }

    #[test]
    fn record_publisher_declaration_is_atomic_on_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.record_publisher_declaration("example.com", b"{}", "k1", "pk", &Value::Null)
            .unwrap();
        assert_eq!(
            db.count_pending_entries("publisher_declaration").unwrap(),
            1
        );
        assert!(db
            .record_publisher_declaration("example.com", b"{}", "k1", "pk", &Value::Null)
            .is_err());
        assert_eq!(
            db.count_pending_entries("publisher_declaration").unwrap(),
            1
        );
    }

    #[test]
    fn record_accepted_delta_is_atomic_on_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.record_accepted_delta(
            "example.com",
            "sha256:a",
            &Value::Null,
            0,
            "https://example.com/x",
            "sha256:a",
        )
        .unwrap();
        assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
        assert!(db
            .record_accepted_delta(
                "example.com",
                "sha256:a",
                &Value::Null,
                1,
                "https://example.com/y",
                "sha256:a",
            )
            .is_err());
        assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
        assert!(db.url_tip("https://example.com/y").unwrap().is_none());
    }

    #[test]
    fn drain_pending_entries_orders_by_rowid_and_empties_table() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.record_publisher_declaration("example.com", b"{}", "k1", "pk", &Value::Null)
            .unwrap();
        db.record_accepted_delta(
            "example.com",
            "sha256:a",
            &serde_json::json!({"n": 1}),
            0,
            "https://example.com/x",
            "sha256:a",
        )
        .unwrap();
        db.record_accepted_delta(
            "example.com",
            "sha256:b",
            &serde_json::json!({"n": 2}),
            0,
            "https://example.com/y",
            "sha256:b",
        )
        .unwrap();

        let entries = db.drain_pending_entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].entry_type, "publisher_declaration");
        assert_eq!(entries[1].entry_type, "publisher_delta");
        assert_eq!(entries[1].entry_json, serde_json::json!({"n": 1}));
        assert_eq!(entries[2].entry_type, "publisher_delta");
        assert_eq!(entries[2].entry_json, serde_json::json!({"n": 2}));

        assert!(db.drain_pending_entries().unwrap().is_empty());
    }

    #[test]
    fn peek_pending_entries_orders_without_deleting_then_commit_seal_drains_up_to_rowid() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.record_publisher_declaration("example.com", b"{}", "k1", "pk", &Value::Null)
            .unwrap();
        db.record_accepted_delta(
            "example.com",
            "sha256:a",
            &serde_json::json!({"n": 1}),
            0,
            "https://example.com/x",
            "sha256:a",
        )
        .unwrap();

        let (peeked, up_to) = db.peek_pending_entries().unwrap();
        assert_eq!(peeked.len(), 2);
        assert_eq!(peeked[0].entry_type, "publisher_declaration");
        assert_eq!(peeked[1].entry_type, "publisher_delta");
        assert_eq!(up_to, peeked[1].rowid);
        let (peeked_again, _) = db.peek_pending_entries().unwrap();
        assert_eq!(peeked_again.len(), 2);

        db.commit_seal(
            up_to,
            0,
            "sha256:blockhash0",
            "2026-08-09T00:00:00Z",
            &[RecordUpsert {
                url: "https://example.com/x",
                publisher: "example.com",
                delta_id: "sha256:a",
                observed_at: "2026-08-09T00:00:00Z",
                weight: "full",
                title: "t",
                abstract_text: None,
                lang: "en",
            }],
            &[],
            &[],
        )
        .unwrap();

        let (drained, _) = db.peek_pending_entries().unwrap();
        assert!(drained.is_empty());
        assert_eq!(
            db.last_block().unwrap().unwrap().block_hash,
            "sha256:blockhash0"
        );
        assert_eq!(
            db.get_record("https://example.com/x", "example.com")
                .unwrap()
                .unwrap()
                .delta_id,
            "sha256:a"
        );
    }

    #[test]
    fn commit_seal_rolls_back_pending_delete_on_conflicting_block_number() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.record_accepted_delta(
            "example.com",
            "sha256:a",
            &serde_json::json!({"n": 1}),
            0,
            "https://example.com/x",
            "sha256:a",
        )
        .unwrap();
        let (peeked, up_to) = db.peek_pending_entries().unwrap();
        db.commit_seal(
            up_to,
            0,
            "sha256:blockhash0",
            "2026-08-09T00:00:00Z",
            &[],
            &[],
            &[],
        )
        .unwrap();
        let _ = peeked;

        db.record_accepted_delta(
            "example.com",
            "sha256:b",
            &serde_json::json!({"n": 2}),
            0,
            "https://example.com/y",
            "sha256:b",
        )
        .unwrap();
        let (peeked2, up_to2) = db.peek_pending_entries().unwrap();
        assert_eq!(peeked2.len(), 1);

        let result = db.commit_seal(
            up_to2,
            0,
            "sha256:blockhash0-conflict",
            "2026-08-09T00:01:00Z",
            &[],
            &[],
            &[],
        );
        assert!(result.is_err());

        let (still_pending, _) = db.peek_pending_entries().unwrap();
        assert_eq!(still_pending.len(), 1);
        assert_eq!(still_pending[0].rowid, peeked2[0].rowid);
        assert_eq!(
            db.last_block().unwrap().unwrap().block_hash,
            "sha256:blockhash0"
        );
    }

    #[test]
    fn get_publisher_status_none_for_unknown_row_for_known() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(db.get_publisher_status("example.com").unwrap().is_none());
        db.insert_publisher("example.com", b"{}", "k1", "pk")
            .unwrap();
        let row = db.get_publisher_status("example.com").unwrap().unwrap();
        assert!(row.last_pull_at.is_none());
        assert!(matches!(row.state, PublisherState::New));
        db.set_publisher_pulled("example.com", "2026-08-09T00:00:00Z")
            .unwrap();
        let row = db.get_publisher_status("example.com").unwrap().unwrap();
        assert_eq!(row.last_pull_at.as_deref(), Some("2026-08-09T00:00:00Z"));
        assert!(matches!(row.state, PublisherState::Active));
    }

    #[test]
    fn list_rejections_orders_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(db.list_rejections("example.com").unwrap().is_empty());
        db.insert_rejection(
            "example.com",
            "WIST2-E01",
            "2026-08-09T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        db.insert_rejection(
            "example.com",
            "WIST2-E03",
            "2026-08-09T00:01:00Z",
            Some("sha256:abc"),
            Some("bad commitment"),
        )
        .unwrap();
        let rejections = db.list_rejections("example.com").unwrap();
        assert_eq!(rejections.len(), 2);
        assert_eq!(rejections[0].code, "WIST2-E03");
        assert_eq!(rejections[0].delta_id.as_deref(), Some("sha256:abc"));
        assert_eq!(rejections[1].code, "WIST2-E01");
    }

    #[test]
    fn insert_rejection_accepts_optional_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.insert_rejection(
            "example.com",
            "WIST2-E01",
            "2026-08-09T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        db.insert_rejection(
            "example.com",
            "WIST2-E03",
            "2026-08-09T00:00:00Z",
            Some("sha256:abc"),
            Some("bad commitment"),
        )
        .unwrap();
    }
}
