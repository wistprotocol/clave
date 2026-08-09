use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS publishers(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new', last_pull_at TEXT);
CREATE TABLE IF NOT EXISTS seen_deltas(delta_id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_entries(rowid INTEGER PRIMARY KEY AUTOINCREMENT, entry_type TEXT NOT NULL, domain TEXT NOT NULL, entry_json BLOB NOT NULL, chain_pos INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(url TEXT NOT NULL, publisher TEXT NOT NULL, delta_id TEXT NOT NULL, observed_at TEXT NOT NULL, weight TEXT NOT NULL, title TEXT NOT NULL, abstract TEXT, lang TEXT NOT NULL, PRIMARY KEY(url, publisher));
CREATE TABLE IF NOT EXISTS blocks(block_number INTEGER PRIMARY KEY, block_hash TEXT NOT NULL, sealed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rejections(domain TEXT NOT NULL, code TEXT NOT NULL, at TEXT NOT NULL, delta_id TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS params(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS url_tips(url TEXT PRIMARY KEY, domain TEXT NOT NULL, tip TEXT NOT NULL);
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

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path)?;
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
