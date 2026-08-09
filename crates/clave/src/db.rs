use crate::error::{Error, Result};
use rusqlite::Connection;
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS publishers(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new', last_pull_at TEXT);
CREATE TABLE IF NOT EXISTS seen_deltas(delta_id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_entries(rowid INTEGER PRIMARY KEY AUTOINCREMENT, entry_type TEXT NOT NULL, domain TEXT NOT NULL, entry_json BLOB NOT NULL, chain_pos INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(url TEXT NOT NULL, publisher TEXT NOT NULL, delta_id TEXT NOT NULL, observed_at TEXT NOT NULL, weight TEXT NOT NULL, title TEXT NOT NULL, abstract TEXT, lang TEXT NOT NULL, PRIMARY KEY(url, publisher));
CREATE TABLE IF NOT EXISTS blocks(block_number INTEGER PRIMARY KEY, block_hash TEXT NOT NULL, sealed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rejections(domain TEXT NOT NULL, code TEXT NOT NULL, at TEXT NOT NULL, delta_id TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS params(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
";

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
}
