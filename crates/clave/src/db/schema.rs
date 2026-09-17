//! The store's schema and the migrations a reopened store applies before
//! any routine operation reads it.
use super::Mutation;
use crate::error::{Error, Result};
use rusqlite::Connection;

/// Applies the schema, the added columns, the acceptance-order clock and
/// the url_tips key migration, each idempotent on a current store.
pub(super) fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    add_missing_columns(conn)?;
    restore_acceptance_order(conn)?;
    let old_tips: bool = conn.query_row(
        "SELECT pk = 0 FROM pragma_table_info('url_tips') WHERE name = 'domain'",
        [],
        |row| row.get(0),
    )?;
    if old_tips {
        let tx = Mutation::new(conn)?;
        tx.execute_batch("ALTER TABLE url_tips RENAME TO old_url_tips;
            CREATE TABLE url_tips(url TEXT NOT NULL, domain TEXT NOT NULL, tip TEXT NOT NULL, PRIMARY KEY(domain, url));
            INSERT INTO url_tips SELECT url, domain, tip FROM old_url_tips;
            DROP TABLE old_url_tips;")?;
        tx.commit()?;
    }
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS publishers(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new', last_pull_at TEXT, declaration_fetched_at TEXT);
CREATE TABLE IF NOT EXISTS declaration_floors(domain TEXT PRIMARY KEY, seq INTEGER NOT NULL CHECK(typeof(seq) = 'integer' AND seq BETWEEN 0 AND 9007199254740991));
CREATE TABLE IF NOT EXISTS seen_deltas(delta_id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_entries(rowid INTEGER PRIMARY KEY AUTOINCREMENT, entry_type TEXT NOT NULL, domain TEXT NOT NULL, entry_json BLOB NOT NULL, chain_pos INTEGER NOT NULL, turn_block INTEGER, acceptance_order INTEGER);
CREATE TABLE IF NOT EXISTS records(url TEXT NOT NULL, publisher TEXT NOT NULL, delta_id TEXT NOT NULL, observed_at TEXT NOT NULL, title TEXT NOT NULL, abstract TEXT, lang TEXT NOT NULL, sealed_at TEXT NOT NULL DEFAULT '', PRIMARY KEY(url, publisher));
CREATE TABLE IF NOT EXISTS blocks(block_number INTEGER PRIMARY KEY, block_hash TEXT NOT NULL, sealed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rejections(domain TEXT NOT NULL, code TEXT NOT NULL, at TEXT NOT NULL, delta_id TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS params(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS url_tips(url TEXT NOT NULL, domain TEXT NOT NULL, tip TEXT NOT NULL, PRIMARY KEY(domain, url));
CREATE TABLE IF NOT EXISTS param_changes(parameter TEXT NOT NULL, value INTEGER NOT NULL, effective_at TEXT NOT NULL, block_number INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS noise_pings(domain TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS ingest_meter(domain TEXT NOT NULL, day TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS walk_state(domain TEXT PRIMARY KEY, suspended INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS feed_observations(domain TEXT PRIMARY KEY, generated_at_s INTEGER NOT NULL CHECK(typeof(generated_at_s) = 'integer' AND generated_at_s BETWEEN -62167219200 AND 253402300799));
CREATE TABLE IF NOT EXISTS withdrawals(delta_id TEXT PRIMARY KEY, domain TEXT NOT NULL, update_id TEXT NOT NULL, block_number INTEGER NOT NULL, sealed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_windows(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, prior_declaration_json BLOB NOT NULL, owner_declaration_json BLOB NOT NULL, opened_block INTEGER, window_end TEXT);
CREATE TABLE IF NOT EXISTS recovery_settlements(domain TEXT NOT NULL, owner_hash TEXT NOT NULL, PRIMARY KEY(domain, owner_hash));
CREATE TABLE IF NOT EXISTS sealed_declarations(domain TEXT NOT NULL, seq INTEGER NOT NULL, block_number INTEGER NOT NULL, sealed_at TEXT NOT NULL, declaration_json BLOB NOT NULL, PRIMARY KEY(domain, seq));
CREATE TABLE IF NOT EXISTS queued_deltas(rowid INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, delta_id TEXT NOT NULL, entry_json BLOB NOT NULL, url TEXT NOT NULL, chain_pos INTEGER NOT NULL, acceptance_order INTEGER);
CREATE TABLE IF NOT EXISTS publications(block_number INTEGER PRIMARY KEY, block_json BLOB NOT NULL, checkpoint_json BLOB NOT NULL, published INTEGER NOT NULL DEFAULT 0);
";

pub(super) fn add_missing_columns(conn: &Connection) -> Result<()> {
    for statement in [
        "ALTER TABLE records ADD COLUMN sealed_at TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE publishers ADD COLUMN declaration_fetched_at TEXT",
        "ALTER TABLE pending_entries ADD COLUMN turn_block INTEGER",
        "ALTER TABLE pending_entries ADD COLUMN acceptance_order INTEGER",
        "ALTER TABLE queued_deltas ADD COLUMN acceptance_order INTEGER",
        "ALTER TABLE param_changes ADD COLUMN entry_index INTEGER",
        "ALTER TABLE blocks ADD COLUMN decompressed_bytes INTEGER",
        "ALTER TABLE recovery_windows ADD COLUMN owner_declaration_json BLOB",
    ] {
        match conn.execute(statement, []) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(ref m)))
                if m.contains("duplicate column") => {}
            Err(e) => return Err(Error::Db(e)),
        }
    }
    Ok(())
}

pub(super) fn restore_acceptance_order(conn: &Connection) -> Result<()> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let ambiguous: bool = tx.query_row(
        "SELECT EXISTS(SELECT domain FROM (SELECT domain, acceptance_order FROM pending_entries WHERE entry_type = 'publisher_delta' UNION ALL SELECT domain, acceptance_order FROM queued_deltas) GROUP BY domain HAVING COUNT(*) > 1 AND COUNT(acceptance_order) < COUNT(*))",
        [],
        |row| row.get(0),
    )?;
    if ambiguous {
        return Err(Error::History(
            "legacy Delta copies lack a provable acceptance order; restore an independently retained admission order before reopening".into(),
        ));
    }
    tx.execute_batch("CREATE TABLE IF NOT EXISTS acceptance_clock(id INTEGER PRIMARY KEY CHECK(id = 1), position INTEGER NOT NULL CHECK(typeof(position) = 'integer' AND position >= 0));
        INSERT OR IGNORE INTO acceptance_clock VALUES (1, 0);
        UPDATE acceptance_clock SET position = MAX(position, COALESCE((SELECT MAX(acceptance_order) FROM pending_entries), 0), COALESCE((SELECT MAX(acceptance_order) FROM queued_deltas), 0));")?;
    for table in ["pending_entries", "queued_deltas"] {
        let rows = tx
            .prepare(&format!(
                "SELECT rowid FROM {table} WHERE acceptance_order IS NULL ORDER BY rowid"
            ))?
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for rowid in rows {
            tx.execute("UPDATE acceptance_clock SET position = position + 1", [])?;
            tx.execute(&format!(
                "UPDATE {table} SET acceptance_order = (SELECT position FROM acceptance_clock) WHERE rowid = ?1"
            ), [rowid])?;
        }
        tx.execute_batch(&format!(
            "CREATE UNIQUE INDEX IF NOT EXISTS {table}_acceptance_order ON {table}(acceptance_order);
            CREATE TRIGGER IF NOT EXISTS {table}_assign_order AFTER INSERT ON {table} WHEN NEW.acceptance_order IS NULL BEGIN
                UPDATE acceptance_clock SET position = position + 1;
                UPDATE {table} SET acceptance_order = (SELECT position FROM acceptance_clock) WHERE rowid = NEW.rowid;
            END;"
        ))?;
    }
    tx.commit()?;
    Ok(())
}
