//! The store's schema and the migrations a reopened store applies before
//! any routine operation reads it.
use super::Mutation;
use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};

/// Applies the schema, the lease tables, the added columns, the acceptance-order clock, the
/// key-act backfill and the url_tips key migration, each idempotent on a
/// current store.
pub(super) fn migrate(conn: &Connection) -> Result<()> {
    refuse_superseded_layout(conn)?;
    conn.execute_batch(SCHEMA)?;
    super::leases::create(conn)?;
    super::pull_runs::create(conn)?;
    add_missing_columns(conn)?;
    restore_acceptance_order(conn)?;
    backfill_key_acts(conn)?;
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

/// A store written before the Log became one growing tree keys its
/// Blocks by a per-Block hash and holds no leaf data; its Blocks cannot
/// be replayed into a tree, so it is refused rather than half-migrated.
/// A later store that still names that table `blocks` and its columns
/// after `block` is refused the same way.
fn refuse_superseded_layout(conn: &Connection) -> Result<()> {
    let hash_chain: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('blocks') WHERE name = 'block_hash')",
        [],
        |row| row.get(0),
    )?;
    if hash_chain {
        return Err(Error::History(
            "this store holds a Log in the superseded per-Block hash-chain format; start a new data directory".into(),
        ));
    }
    let pre_epoch: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'blocks')",
        [],
        |row| row.get(0),
    )?;
    if pre_epoch {
        return Err(Error::History(
            "this store holds a Log in the superseded Block-named schema; start a new data directory".into(),
        ));
    }
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS publishers(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new', last_pull_at TEXT, declaration_fetched_at TEXT);
CREATE TABLE IF NOT EXISTS declaration_floors(domain TEXT PRIMARY KEY, seq INTEGER NOT NULL CHECK(typeof(seq) = 'integer' AND seq BETWEEN 0 AND 9007199254740991));
CREATE TABLE IF NOT EXISTS seen_deltas(delta_id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_entries(rowid INTEGER PRIMARY KEY AUTOINCREMENT, entry_type TEXT NOT NULL, domain TEXT NOT NULL, entry_json BLOB NOT NULL, chain_pos INTEGER NOT NULL, turn_epoch INTEGER, acceptance_order INTEGER);
CREATE TABLE IF NOT EXISTS records(url TEXT NOT NULL, publisher TEXT NOT NULL, delta_id TEXT NOT NULL, observed_at TEXT NOT NULL, title TEXT NOT NULL, abstract TEXT, lang TEXT NOT NULL, sealed_at TEXT NOT NULL DEFAULT '', PRIMARY KEY(url, publisher));
CREATE TABLE IF NOT EXISTS epochs(epoch_number INTEGER PRIMARY KEY, tree_size INTEGER NOT NULL, root TEXT NOT NULL, sealed_at TEXT NOT NULL, note TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 0, epoch_bytes INTEGER);
CREATE TABLE IF NOT EXISTS log_entries(leaf_index INTEGER PRIMARY KEY, epoch_number INTEGER NOT NULL, entry_json BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS log_entries_epoch ON log_entries(epoch_number);
CREATE TABLE IF NOT EXISTS log_tiles(level INTEGER NOT NULL, tile_index INTEGER NOT NULL, hashes BLOB NOT NULL, PRIMARY KEY(level, tile_index));
CREATE TABLE IF NOT EXISTS witnesses(name TEXT PRIMARY KEY, public_key TEXT NOT NULL, base_url TEXT NOT NULL, last_size INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS aggregator_keys(note_key_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, public_key TEXT NOT NULL, added_epoch INTEGER NOT NULL, removed_epoch INTEGER, adding_act BLOB, removing_act BLOB);
CREATE TABLE IF NOT EXISTS rejections(domain TEXT NOT NULL, code TEXT NOT NULL, at TEXT NOT NULL, delta_id TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS params(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS url_tips(url TEXT NOT NULL, domain TEXT NOT NULL, tip TEXT NOT NULL, PRIMARY KEY(domain, url));
CREATE TABLE IF NOT EXISTS param_changes(parameter TEXT NOT NULL, value INTEGER NOT NULL, effective_at TEXT NOT NULL, epoch_number INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS noise_pings(domain TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS ingest_meter(domain TEXT NOT NULL, day TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS walk_state(domain TEXT PRIMARY KEY, suspended INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS feed_observations(domain TEXT PRIMARY KEY, generated_at_s INTEGER NOT NULL CHECK(typeof(generated_at_s) = 'integer' AND generated_at_s BETWEEN -62167219200 AND 253402300799));
CREATE TABLE IF NOT EXISTS seen_labels(id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS labels(label_id TEXT PRIMARY KEY, labeler TEXT NOT NULL, subject TEXT NOT NULL, name TEXT NOT NULL, value INTEGER, asserted_at TEXT NOT NULL, retracted INTEGER NOT NULL, expires_at TEXT, delta TEXT, epoch_number INTEGER NOT NULL, entry_index INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS disputes(dispute_id TEXT PRIMARY KEY, label_id TEXT NOT NULL, disputant TEXT NOT NULL, reason TEXT, asserted_at TEXT NOT NULL, epoch_number INTEGER NOT NULL, entry_index INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS label_feed_observations(domain TEXT PRIMARY KEY, generated_at_s INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS suffix_lists(sha256 TEXT PRIMARY KEY, octets BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS suffix_list_acts(rowid INTEGER PRIMARY KEY AUTOINCREMENT, epoch_number INTEGER NOT NULL, sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS withdrawals(delta_id TEXT PRIMARY KEY, domain TEXT NOT NULL, update_id TEXT NOT NULL, epoch_number INTEGER NOT NULL, sealed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_windows(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, prior_declaration_json BLOB NOT NULL, owner_declaration_json BLOB NOT NULL, opened_epoch INTEGER, window_end TEXT);
CREATE TABLE IF NOT EXISTS recovery_settlements(domain TEXT NOT NULL, owner_hash TEXT NOT NULL, PRIMARY KEY(domain, owner_hash));
CREATE TABLE IF NOT EXISTS sealed_declarations(domain TEXT NOT NULL, seq INTEGER NOT NULL, epoch_number INTEGER NOT NULL, sealed_at TEXT NOT NULL, declaration_json BLOB NOT NULL, PRIMARY KEY(domain, seq));
CREATE TABLE IF NOT EXISTS queued_deltas(rowid INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, delta_id TEXT NOT NULL, entry_json BLOB NOT NULL, url TEXT NOT NULL, chain_pos INTEGER NOT NULL, acceptance_order INTEGER);
CREATE TABLE IF NOT EXISTS pending_identities(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL);
";

pub(super) fn add_missing_columns(conn: &Connection) -> Result<()> {
    for statement in [
        "ALTER TABLE records ADD COLUMN sealed_at TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE publishers ADD COLUMN declaration_fetched_at TEXT",
        "ALTER TABLE pending_entries ADD COLUMN turn_epoch INTEGER",
        "ALTER TABLE pending_entries ADD COLUMN acceptance_order INTEGER",
        "ALTER TABLE queued_deltas ADD COLUMN acceptance_order INTEGER",
        "ALTER TABLE param_changes ADD COLUMN entry_index INTEGER",
        "ALTER TABLE recovery_windows ADD COLUMN owner_declaration_json BLOB",
        "ALTER TABLE aggregator_keys ADD COLUMN removed_epoch INTEGER",
        "ALTER TABLE aggregator_keys ADD COLUMN adding_act BLOB",
        "ALTER TABLE aggregator_keys ADD COLUMN removing_act BLOB",
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

struct KeyRow {
    key_id: String,
    public_key: String,
    added_epoch: u64,
    removed_epoch: Option<u64>,
    holds_adding_act: bool,
    holds_removing_act: bool,
}

/// WIST-3 §7: every `aggregator_key` tuple but the genesis key's carries
/// the accepted `aggregator_key_add` that admitted it, and every removed
/// key's carries the accepted `aggregator_key_remove` that retired it. A
/// store written before the key table held the acts recovers both by
/// replaying the Entries it has sealed from the one key of its table that
/// no sealed act admits; a table that replay does not reproduce is refused
/// rather than served as tuples without acts.
fn backfill_key_acts(conn: &Connection) -> Result<()> {
    let mut statement = conn.prepare(
        "SELECT key_id, public_key, added_epoch, removed_epoch, adding_act IS NOT NULL, removing_act IS NOT NULL FROM aggregator_keys ORDER BY key_id",
    )?;
    let rows: Vec<KeyRow> = statement
        .query_map([], |row| {
            Ok(KeyRow {
                key_id: row.get(0)?,
                public_key: row.get(1)?,
                added_epoch: row.get::<_, i64>(2)?.max(0) as u64,
                removed_epoch: row.get::<_, Option<i64>>(3)?.map(|h| h.max(0) as u64),
                holds_adding_act: row.get(4)?,
                holds_removing_act: row.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let rootless = rows.iter().filter(|row| !row.holds_adding_act).count();
    let unrecorded_removal = rows
        .iter()
        .any(|row| row.removed_epoch.is_some() && !row.holds_removing_act);
    if rootless <= 1 && !unrecorded_removal {
        return Ok(());
    }

    let recovered = replay_key_acts(conn, &rows)?;
    let tx = Mutation::new(conn)?;
    for entry in &recovered {
        tx.execute(
            "UPDATE aggregator_keys SET adding_act = ?2, removing_act = ?3 WHERE key_id = ?1",
            (
                &entry.key_id,
                entry
                    .adding_act
                    .as_ref()
                    .map(serde_json::to_vec)
                    .transpose()?,
                entry
                    .removing_act
                    .as_ref()
                    .map(serde_json::to_vec)
                    .transpose()?,
            ),
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn replay_key_acts(
    conn: &Connection,
    rows: &[KeyRow],
) -> Result<Vec<wist_core::objects::AggregatorKeyEntry>> {
    let note: Option<String> = conn
        .query_row(
            "SELECT note FROM epochs ORDER BY epoch_number LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let log_id = match note {
        Some(note) => wist_core::checkpoint::Checkpoint::parse(&note)
            .map_err(|e| Error::History(e.to_string()))?
            .origin()
            .to_owned(),
        None => return Err(unrecoverable_key_acts()),
    };

    let mut statement =
        conn.prepare("SELECT epoch_number, entry_json FROM log_entries ORDER BY leaf_index")?;
    let sealed = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?.max(0) as u64,
                row.get::<_, Vec<u8>>(1)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let mut acts: std::collections::BTreeMap<u64, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();
    for (height, entry_json) in sealed {
        let entry: serde_json::Value = serde_json::from_slice(&entry_json)?;
        if entry["type"] == "registry_update" {
            acts.entry(height).or_default().push(entry["body"].clone());
        }
    }

    for candidate in rows.iter().filter(|row| row.added_epoch == 0) {
        let genesis = wist_core::objects::GenesisKey {
            key_id: candidate.key_id.clone(),
            alg: "Ed25519".into(),
            public_key: candidate.public_key.clone(),
        };
        let Ok(mut registry) =
            wist_core::aggregator_keys::Registry::from_genesis(&log_id, &genesis)
        else {
            continue;
        };
        for (height, epoch_acts) in &acts {
            registry.apply_epoch(*height, epoch_acts.iter());
        }
        let replayed = registry.entries();
        let reproduces = replayed.len() == rows.len()
            && replayed.iter().zip(rows).all(|(entry, row)| {
                entry.key_id == row.key_id
                    && entry.public_key == row.public_key
                    && entry.added_height == row.added_epoch
                    && entry.removed_height == row.removed_epoch
            });
        if reproduces {
            return Ok(replayed);
        }
    }
    Err(unrecoverable_key_acts())
}

fn unrecoverable_key_acts() -> Error {
    Error::History(
        "the Entries this store retains do not reproduce the Aggregator key registry it records, so the key acts each aggregator_key tuple carries cannot be recovered; start from a data directory whose Log replays".into(),
    )
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
