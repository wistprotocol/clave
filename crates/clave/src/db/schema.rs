use super::Mutation;
use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};

/// Each migration is idempotent on a current store.
pub(super) fn migrate(conn: &Connection) -> Result<()> {
    refuse_superseded_layout(conn)?;
    refuse_unstamped_layout(conn)?;
    conn.execute_batch(SCHEMA)?;
    super::leases::create(conn)?;
    super::pull_runs::create(conn)?;
    super::collections::create(conn)?;
    add_missing_columns(conn)?;
    conn.execute_batch(INDEXES)?;
    relax_publisher_columns(conn)?;
    restore_acceptance_order(conn)?;
    backfill_key_acts(conn)?;
    conn.pragma_update(None, "user_version", LAYOUT_VERSION)?;
    Ok(())
}

const LAYOUT_VERSION: i64 = 3;

fn refuse_unstamped_layout(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let empty: bool = conn.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table')",
        [],
        |row| row.get(0),
    )?;
    if version == LAYOUT_VERSION || (version == 0 && empty) {
        return Ok(());
    }
    Err(Error::History(format!(
        "this store holds the superseded layout {version} rather than layout {LAYOUT_VERSION}; start a new data directory"
    )))
}

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
CREATE TABLE IF NOT EXISTS publishers(domain TEXT PRIMARY KEY, declaration_json BLOB, key_id TEXT, public_key TEXT, state TEXT NOT NULL DEFAULT 'new', last_pull_at TEXT);
CREATE TABLE IF NOT EXISTS declaration_floors(domain TEXT PRIMARY KEY, seq INTEGER NOT NULL CHECK(typeof(seq) = 'integer' AND seq BETWEEN 0 AND 9007199254740991));
CREATE TABLE IF NOT EXISTS pending_entries(rowid INTEGER PRIMARY KEY AUTOINCREMENT, entry_type TEXT NOT NULL, domain TEXT NOT NULL, entry_json BLOB NOT NULL, chain_pos INTEGER NOT NULL, turn_epoch INTEGER, acceptance_order INTEGER, label_id TEXT UNIQUE, place_event INTEGER, place_position INTEGER, place_index INTEGER, eligibility INTEGER);
CREATE TABLE IF NOT EXISTS epochs(epoch_number INTEGER PRIMARY KEY, tree_size INTEGER NOT NULL, root TEXT NOT NULL, sealed_at TEXT NOT NULL, note TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 0, epoch_bytes INTEGER, rejected INTEGER NOT NULL DEFAULT 0, judged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS log_entries(leaf_index INTEGER PRIMARY KEY, epoch_number INTEGER NOT NULL, entry_json BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS log_entries_epoch ON log_entries(epoch_number);
CREATE TABLE IF NOT EXISTS log_tiles(level INTEGER NOT NULL, tile_index INTEGER NOT NULL, hashes BLOB NOT NULL, PRIMARY KEY(level, tile_index));
CREATE TABLE IF NOT EXISTS witnesses(name TEXT PRIMARY KEY, public_key TEXT NOT NULL, base_url TEXT NOT NULL, last_size INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS aggregator_keys(note_key_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, public_key TEXT NOT NULL, added_epoch INTEGER NOT NULL, removed_epoch INTEGER, adding_act BLOB, removing_act BLOB);
CREATE TABLE IF NOT EXISTS rejections(domain TEXT NOT NULL, code TEXT NOT NULL, at TEXT NOT NULL, id TEXT, detail TEXT, collection TEXT, urls_json TEXT, condition TEXT, change_list TEXT, left_epoch INTEGER);
CREATE TABLE IF NOT EXISTS params(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS genesis_params(parameter TEXT NOT NULL, value INTEGER NOT NULL, effective_at TEXT);
CREATE TABLE IF NOT EXISTS param_changes(parameter TEXT NOT NULL, value INTEGER NOT NULL, effective_at TEXT NOT NULL, epoch_number INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS noise_pings(domain TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS ingest_meter(domain TEXT NOT NULL, day TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS walk_state(domain TEXT PRIMARY KEY, suspended INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS seen_labels(id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS labels(label_id TEXT PRIMARY KEY, labeler TEXT NOT NULL, subject TEXT NOT NULL, name TEXT NOT NULL, value INTEGER, asserted_at TEXT NOT NULL, retracted INTEGER NOT NULL, expires_at TEXT, delta TEXT, epoch_number INTEGER NOT NULL, entry_index INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS disputes(dispute_id TEXT PRIMARY KEY, label_id TEXT NOT NULL, disputant TEXT NOT NULL, reason TEXT, asserted_at TEXT NOT NULL, epoch_number INTEGER NOT NULL, entry_index INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS labels_labeler ON labels(labeler);
CREATE INDEX IF NOT EXISTS disputes_disputant ON disputes(disputant);
CREATE TABLE IF NOT EXISTS label_feed_observations(domain TEXT PRIMARY KEY, generated_at_s INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS suffix_lists(sha256 TEXT PRIMARY KEY, octets BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS suffix_list_acts(rowid INTEGER PRIMARY KEY AUTOINCREMENT, epoch_number INTEGER NOT NULL, sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS withdrawals(item_id TEXT PRIMARY KEY, domain TEXT NOT NULL, update_id TEXT NOT NULL, epoch_number INTEGER NOT NULL, sealed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_removals(item_id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_windows(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, prior_declaration_json BLOB NOT NULL, owner_declaration_json BLOB NOT NULL, opened_epoch INTEGER, window_end TEXT);
CREATE TABLE IF NOT EXISTS recovery_settlements(domain TEXT NOT NULL, owner_hash TEXT NOT NULL, PRIMARY KEY(domain, owner_hash));
CREATE TABLE IF NOT EXISTS sealed_declarations(domain TEXT NOT NULL, seq INTEGER NOT NULL, epoch_number INTEGER NOT NULL, sealed_at TEXT NOT NULL, declaration_json BLOB NOT NULL, PRIMARY KEY(domain, seq));
CREATE TABLE IF NOT EXISTS pending_identities(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sealing_reservation(id INTEGER PRIMARY KEY CHECK(id = 1), epoch_number INTEGER NOT NULL, event INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sealed_in_force(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS derived_state(epoch_number INTEGER PRIMARY KEY, root TEXT NOT NULL, declarations_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS accepted_updates(update_id TEXT PRIMARY KEY, epoch_number INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sealed_page_sources(domain TEXT NOT NULL, hash TEXT NOT NULL, epoch_number INTEGER NOT NULL, ordinal INTEGER NOT NULL, sealed_at_s INTEGER NOT NULL, seq INTEGER NOT NULL, keys_json BLOB NOT NULL, PRIMARY KEY(domain, hash, epoch_number));
CREATE TABLE IF NOT EXISTS sealed_page_pending_heads(domain TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(domain, hash));
CREATE TABLE IF NOT EXISTS sealed_page_exclusions(domain TEXT NOT NULL, hash TEXT NOT NULL, epoch_number INTEGER NOT NULL, PRIMARY KEY(domain, hash));
CREATE TABLE IF NOT EXISTS sealed_page_sources_recorded(id INTEGER PRIMARY KEY CHECK(id = 1), epoch_number INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS parameter_schedule_cache(id INTEGER PRIMARY KEY CHECK(id = 1), epoch_number INTEGER NOT NULL, root TEXT NOT NULL, largest INTEGER NOT NULL, schedule_json BLOB NOT NULL);
";

const INDEXES: &str = "
CREATE INDEX IF NOT EXISTS payload_duties_unserved ON payload_duties(publisher, url, item_id) WHERE served = 0;
CREATE INDEX IF NOT EXISTS rejections_left_epoch ON rejections(domain, left_epoch);
CREATE INDEX IF NOT EXISTS rejections_collection_code ON rejections(domain, collection, code);
CREATE INDEX IF NOT EXISTS pending_entries_domain ON pending_entries(domain);
CREATE INDEX IF NOT EXISTS records_item ON records(item_id);
CREATE INDEX IF NOT EXISTS param_changes_epoch ON param_changes(epoch_number, entry_index);
";

fn relax_publisher_columns(conn: &Connection) -> Result<()> {
    let required: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('publishers') WHERE name = 'declaration_json' AND \"notnull\" = 1)",
        [],
        |row| row.get(0),
    )?;
    if !required {
        return Ok(());
    }
    conn.execute_batch(
        "CREATE TABLE publishers_relaxed(domain TEXT PRIMARY KEY, declaration_json BLOB, key_id TEXT, public_key TEXT, state TEXT NOT NULL DEFAULT 'new', last_pull_at TEXT);
         INSERT INTO publishers_relaxed(domain, declaration_json, key_id, public_key, state, last_pull_at) SELECT domain, declaration_json, key_id, public_key, state, last_pull_at FROM publishers;
         DROP TABLE publishers;
         ALTER TABLE publishers_relaxed RENAME TO publishers;",
    )?;
    Ok(())
}

pub(super) fn add_missing_columns(conn: &Connection) -> Result<()> {
    for statement in [
        "ALTER TABLE pending_entries ADD COLUMN turn_epoch INTEGER",
        "ALTER TABLE pending_entries ADD COLUMN acceptance_order INTEGER",
        "ALTER TABLE param_changes ADD COLUMN entry_index INTEGER",
        "ALTER TABLE recovery_windows ADD COLUMN owner_declaration_json BLOB",
        "ALTER TABLE aggregator_keys ADD COLUMN removed_epoch INTEGER",
        "ALTER TABLE aggregator_keys ADD COLUMN adding_act BLOB",
        "ALTER TABLE aggregator_keys ADD COLUMN removing_act BLOB",
        "ALTER TABLE pull_walk ADD COLUMN raw BLOB",
        "ALTER TABLE pull_objects ADD COLUMN unit TEXT",
        "ALTER TABLE pull_objects ADD COLUMN day TEXT",
        "ALTER TABLE discovered_declarations ADD COLUMN competes_with TEXT",
        "ALTER TABLE collections ADD COLUMN waiting_deferrals TEXT",
        "ALTER TABLE collections ADD COLUMN waiting_held TEXT",
        "ALTER TABLE waiting_urls ADD COLUMN deferrals TEXT",
        "ALTER TABLE waiting_urls ADD COLUMN held TEXT",
        "ALTER TABLE payload_duties ADD COLUMN served INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE collections ADD COLUMN accepted_read TEXT",
        "ALTER TABLE list_items ADD COLUMN read TEXT",
        "ALTER TABLE rejections ADD COLUMN left_epoch INTEGER",
        "ALTER TABLE epochs ADD COLUMN rejected INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE epochs ADD COLUMN judged INTEGER NOT NULL DEFAULT 0",
    ] {
        match conn.execute(statement, []) {
            Ok(_) if statement.contains("ADD COLUMN judged") => {
                conn.execute("UPDATE epochs SET judged = 1", [])?;
            }
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

/// WIST-3 §7: every `aggregator_key` tuple but the genesis key's carries the
/// accepted `aggregator_key_add` that admitted it, and every removed key's
/// the `aggregator_key_remove` that retired it.
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
    tx.execute_batch("CREATE TABLE IF NOT EXISTS acceptance_clock(id INTEGER PRIMARY KEY CHECK(id = 1), position INTEGER NOT NULL CHECK(typeof(position) = 'integer' AND position >= 0));
        INSERT OR IGNORE INTO acceptance_clock VALUES (1, 0);
        UPDATE acceptance_clock SET position = MAX(position, COALESCE((SELECT MAX(acceptance_order) FROM pending_entries), 0));")?;
    let rows = tx
        .prepare("SELECT rowid FROM pending_entries WHERE acceptance_order IS NULL ORDER BY rowid")?
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for rowid in rows {
        tx.execute("UPDATE acceptance_clock SET position = position + 1", [])?;
        tx.execute(
            "UPDATE pending_entries SET acceptance_order = (SELECT position FROM acceptance_clock) WHERE rowid = ?1",
            [rowid],
        )?;
    }
    tx.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS pending_entries_acceptance_order ON pending_entries(acceptance_order);
        CREATE TRIGGER IF NOT EXISTS pending_entries_assign_order AFTER INSERT ON pending_entries WHEN NEW.acceptance_order IS NULL BEGIN
            UPDATE acceptance_clock SET position = position + 1;
            UPDATE pending_entries SET acceptance_order = (SELECT position FROM acceptance_clock) WHERE rowid = NEW.rowid;
        END;",
    )?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::db::Db;

    fn plan(db: &Db, sql: &str) -> Vec<String> {
        let mut statement = db
            .conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        let count = statement.parameter_count();
        let parameters: Vec<String> = (0..count).map(|_| String::new()).collect();
        statement
            .query_map(rusqlite::params_from_iter(parameters), |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn the_queries_that_grow_with_the_log_search_their_indexes() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        for (sql, expected) in [
            (
                "SELECT item_id, publisher, url, until, served FROM payload_duties WHERE served = 0 ORDER BY publisher, url, item_id",
                "SCAN payload_duties USING INDEX payload_duties_unserved",
            ),
            (
                "SELECT r.code, r.at, r.id, r.detail, r.collection, r.urls_json, r.condition, r.change_list FROM rejections r WHERE r.domain = ?1 ORDER BY COALESCE((SELECT MAX(g.rowid) FROM rejections g WHERE g.domain = r.domain AND g.left_epoch = r.left_epoch), r.rowid) DESC, r.rowid ASC",
                "SEARCH g USING COVERING INDEX rejections_left_epoch (domain=? AND left_epoch=?)",
            ),
            (
                "SELECT at, id, condition, change_list FROM rejections WHERE domain = ?1 AND collection = ?2 AND code = ?3 ORDER BY rowid DESC LIMIT 1",
                "SEARCH rejections USING INDEX rejections_collection_code (domain=? AND collection=? AND code=?)",
            ),
            (
                "DELETE FROM rejections WHERE domain = ?1 AND collection = ?2 AND code = ?3",
                "SEARCH rejections USING INDEX rejections_collection_code (domain=? AND collection=? AND code=?)",
            ),
            (
                "SELECT entry_type, label_id, entry_json, place_event, place_position, place_index, eligibility FROM pending_entries WHERE domain = ?1 AND label_id IS NOT NULL AND place_event IS NOT NULL",
                "SEARCH pending_entries USING INDEX pending_entries_domain (domain=?)",
            ),
            (
                "SELECT item_id FROM payload_duties WHERE until <= ?1 AND item_id NOT IN (SELECT item_id FROM records) ORDER BY item_id",
                "USING INDEX records_item FOR IN-OPERATOR",
            ),
            (
                "SELECT EXISTS(SELECT 1 FROM payload_duties WHERE item_id = ?1 AND (until > ?2 OR item_id IN (SELECT item_id FROM records)))",
                "USING INDEX records_item FOR IN-OPERATOR",
            ),
            (
                "SELECT item_id FROM records",
                "SCAN records USING COVERING INDEX records_item",
            ),
            (
                "SELECT parameter, value, epoch_number, entry_index, effective_at FROM param_changes WHERE epoch_number > ?1 ORDER BY epoch_number, entry_index",
                "SEARCH param_changes USING INDEX param_changes_epoch (epoch_number>?)",
            ),
        ] {
            let plan = plan(&db, sql);
            assert!(plan.iter().any(|line| line == expected), "{sql}: {plan:?}");
        }
    }

    #[test]
    fn a_store_without_the_indexes_gains_them_at_open_and_keeps_its_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clave.sqlite");
        let indexes = [
            "payload_duties_unserved",
            "rejections_left_epoch",
            "rejections_collection_code",
            "pending_entries_domain",
            "records_item",
            "param_changes_epoch",
        ];
        drop(Db::open(&path).unwrap());
        let conn = rusqlite::Connection::open(&path).unwrap();
        for index in indexes {
            conn.execute_batch(&format!("DROP INDEX {index}")).unwrap();
        }
        drop(conn);

        let db = Db::open(&path).unwrap();

        for index in indexes {
            let held: bool = db
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1)",
                    [index],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(held, "{index}");
        }
        let version: i64 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, super::LAYOUT_VERSION);
    }
}
