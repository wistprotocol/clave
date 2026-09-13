use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;
use wist_core::objects::{PublisherState, StatusRejection};

mod delta_history;
mod delta_indexes;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS publishers(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new', last_pull_at TEXT, declaration_fetched_at TEXT);
CREATE TABLE IF NOT EXISTS declaration_floors(domain TEXT PRIMARY KEY, seq INTEGER NOT NULL CHECK(typeof(seq) = 'integer' AND seq BETWEEN 0 AND 9007199254740991));
CREATE TABLE IF NOT EXISTS seen_deltas(delta_id TEXT PRIMARY KEY, domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_entries(rowid INTEGER PRIMARY KEY AUTOINCREMENT, entry_type TEXT NOT NULL, domain TEXT NOT NULL, entry_json BLOB NOT NULL, chain_pos INTEGER NOT NULL, turn_block INTEGER, acceptance_order INTEGER);
CREATE TABLE IF NOT EXISTS records(url TEXT NOT NULL, publisher TEXT NOT NULL, delta_id TEXT NOT NULL, observed_at TEXT NOT NULL, weight TEXT NOT NULL, title TEXT NOT NULL, abstract TEXT, lang TEXT NOT NULL, sealed_at TEXT NOT NULL DEFAULT '', PRIMARY KEY(url, publisher));
CREATE TABLE IF NOT EXISTS blocks(block_number INTEGER PRIMARY KEY, block_hash TEXT NOT NULL, sealed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rejections(domain TEXT NOT NULL, code TEXT NOT NULL, at TEXT NOT NULL, delta_id TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS params(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS url_tips(url TEXT NOT NULL, domain TEXT NOT NULL, tip TEXT NOT NULL, PRIMARY KEY(domain, url));
CREATE TABLE IF NOT EXISTS param_changes(parameter TEXT NOT NULL, value INTEGER NOT NULL, effective_at TEXT NOT NULL, block_number INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS noise_pings(domain TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS ingest_meter(domain TEXT NOT NULL, day TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(domain, day));
CREATE TABLE IF NOT EXISTS walk_state(domain TEXT PRIMARY KEY, suspended INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS feed_observations(domain TEXT PRIMARY KEY, generated_at_s INTEGER NOT NULL CHECK(typeof(generated_at_s) = 'integer' AND generated_at_s BETWEEN -62167219200 AND 253402300799));
CREATE TABLE IF NOT EXISTS governance(update_id TEXT PRIMARY KEY, action TEXT NOT NULL, domain TEXT NOT NULL, level INTEGER, notice_id TEXT, outcome TEXT, sealed_at TEXT NOT NULL, block_number INTEGER NOT NULL, kind TEXT);
CREATE TABLE IF NOT EXISTS recovery_windows(domain TEXT PRIMARY KEY, declaration_json BLOB NOT NULL, prior_declaration_json BLOB NOT NULL, owner_declaration_json BLOB NOT NULL, opened_block INTEGER, window_end TEXT);
CREATE TABLE IF NOT EXISTS recovery_settlements(domain TEXT NOT NULL, owner_hash TEXT NOT NULL, PRIMARY KEY(domain, owner_hash));
CREATE TABLE IF NOT EXISTS sealed_declarations(domain TEXT NOT NULL, seq INTEGER NOT NULL, block_number INTEGER NOT NULL, sealed_at TEXT NOT NULL, declaration_json BLOB NOT NULL, PRIMARY KEY(domain, seq));
CREATE TABLE IF NOT EXISTS roster_acts(block_number INTEGER NOT NULL, act_index INTEGER NOT NULL, sealed_at TEXT NOT NULL, action TEXT NOT NULL, auditor_id TEXT NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, for_cause INTEGER NOT NULL, PRIMARY KEY(block_number, act_index));
CREATE TABLE IF NOT EXISTS queued_deltas(rowid INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, delta_id TEXT NOT NULL, entry_json BLOB NOT NULL, url TEXT NOT NULL, chain_pos INTEGER NOT NULL, acceptance_order INTEGER);
";

fn add_missing_columns(conn: &Connection) -> Result<()> {
    for statement in [
        "ALTER TABLE governance ADD COLUMN kind TEXT",
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

fn restore_acceptance_order(conn: &Connection) -> Result<()> {
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

pub(crate) struct Mutation<'a> {
    conn: &'a Connection,
    committed: bool,
}

impl<'a> Mutation<'a> {
    fn new(conn: &'a Connection) -> Result<Self> {
        conn.execute_batch("SAVEPOINT clave_mutation")?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    pub(crate) fn commit(mut self) -> Result<()> {
        self.conn
            .execute_batch("RELEASE SAVEPOINT clave_mutation")?;
        self.committed = true;
        Ok(())
    }
}

impl std::ops::Deref for Mutation<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn
    }
}

impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch(
                "ROLLBACK TO SAVEPOINT clave_mutation; RELEASE SAVEPOINT clave_mutation",
            );
        }
    }
}

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
    /// `sealed_at` of the Block that sealed the Delta this record holds.
    pub sealed_at: String,
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
    /// WIST-4 §6.4: the Block at which this Delta's turn arrived — the
    /// first with room for it under WIST-3 §3.2's per-domain capacity.
    /// The inclusion ceiling runs from here.
    pub turn_block: Option<u64>,
}

pub struct ParamChangeRow<'a> {
    pub entry_index: u64,
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
    pub kind: Option<&'a str>,
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
    pub kind: Option<String>,
}

/// `(auditor_id, key_id, public_key, admitted height, removed height)`
pub type RosterTenure = (String, String, String, u64, Option<u64>);

pub struct RosterActRow {
    pub block_number: u64,
    pub sealed_at: String,
    pub action: String,
    pub auditor_id: String,
    pub key_id: String,
    pub public_key: String,
    pub for_cause: bool,
}

pub struct SealedDeclarationRow<'a> {
    pub domain: &'a str,
    pub seq: u64,
    pub declaration_json: &'a [u8],
}

pub struct SealedDeclarationEntry {
    pub seq: u64,
    pub block_number: u64,
    pub sealed_at: String,
    pub declaration_json: Vec<u8>,
}

pub struct RecoveryWindowRow {
    pub declaration_json: Vec<u8>,
    pub owner_declaration_json: Vec<u8>,
    pub prior_declaration_json: Vec<u8>,
    pub opened_block: Option<i64>,
    pub window_end: Option<String>,
}

pub struct QueuedDeltaRow {
    pub delta_id: String,
    pub entry_json: Value,
    pub url: String,
    pub chain_pos: i64,
    pub(crate) acceptance_order: i64,
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

fn exec_retain_declaration_seq(conn: &Connection, domain: &str, seq: u64) -> Result<()> {
    conn.execute(
        "INSERT INTO declaration_floors(domain, seq) VALUES (?1, ?2) ON CONFLICT(domain) DO UPDATE SET seq = MAX(seq, excluded.seq)",
        (domain, seq),
    )?;
    Ok(())
}

fn accepted_declaration_seq(domain: &str, doc: &Value) -> Result<u64> {
    let publisher = crate::declaration::validate_fields(doc)
        .map_err(|(code, detail)| Error::History(format!("{code} {detail}")))?
        .publisher;
    if publisher.domain != domain {
        return Err(Error::History("stored Declaration domain mismatch".into()));
    }
    Ok(publisher.seq)
}

fn exec_set_url_tip(conn: &Connection, url: &str, domain: &str, tip: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO url_tips(url, domain, tip) VALUES (?1, ?2, ?3) ON CONFLICT(domain, url) DO UPDATE SET tip = excluded.tip",
        (url, domain, tip),
    )?;
    Ok(())
}

fn exec_upsert_record(conn: &Connection, r: &RecordUpsert, sealed_at: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang, sealed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(url, publisher) DO UPDATE SET delta_id = excluded.delta_id, observed_at = excluded.observed_at, weight = excluded.weight, title = excluded.title, abstract = excluded.abstract, lang = excluded.lang, sealed_at = excluded.sealed_at",
        (
            r.url,
            r.publisher,
            r.delta_id,
            r.observed_at,
            r.weight,
            r.title,
            r.abstract_text,
            r.lang,
            sealed_at,
        ),
    )?;
    Ok(())
}

pub struct Db {
    conn: Connection,
}

impl Db {
    pub(crate) fn observe_feed_generated_at(&self, domain: &str, at: &str) -> Result<bool> {
        let at = crate::registry::epoch(at)?;
        Ok(self
            .conn
            .query_row(
                "INSERT INTO feed_observations(domain, generated_at_s) VALUES (?1, ?2)
                 ON CONFLICT(domain) DO UPDATE SET generated_at_s = excluded.generated_at_s
                 WHERE excluded.generated_at_s >= feed_observations.generated_at_s
                 RETURNING generated_at_s",
                rusqlite::params![domain, at],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    pub(crate) fn mutation(&self) -> Result<Mutation<'_>> {
        Mutation::new(&self.conn)
    }

    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute_batch(SCHEMA)?;
        add_missing_columns(&conn)?;
        restore_acceptance_order(&conn)?;
        let old_tips: bool = conn.query_row(
            "SELECT pk = 0 FROM pragma_table_info('url_tips') WHERE name = 'domain'",
            [],
            |row| row.get(0),
        )?;
        if old_tips {
            let tx = Mutation::new(&conn)?;
            tx.execute_batch("ALTER TABLE url_tips RENAME TO old_url_tips;
                CREATE TABLE url_tips(url TEXT NOT NULL, domain TEXT NOT NULL, tip TEXT NOT NULL, PRIMARY KEY(domain, url));
                INSERT INTO url_tips SELECT url, domain, tip FROM old_url_tips;
                DROP TABLE old_url_tips;")?;
            tx.commit()?;
        }
        let db = Db { conn };
        db.restore_block_sizes(path)?;
        db.parameter_schedule(0)?;
        db.restore_recovery_owners(path)?;
        db.restore_declaration_floors(path)?;
        db.restore_delta_indexes(path)?;
        Ok(db)
    }

    fn restore_declaration_floors(&self, path: &Path) -> Result<()> {
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
        let head = self.last_block()?;
        let history = if head.is_some() {
            crate::history::declarations::Declarations::reconstruct(
                path.parent().unwrap_or_else(|| Path::new(".")),
                head,
            )?
        } else {
            crate::history::declarations::Declarations::default()
        };
        let pending = self.peek_pending_entries()?.0;
        for (domain, raw) in rows {
            let current: Value = crate::json::parse(&raw)?;
            let mut seq = accepted_declaration_seq(&domain, &current)?;
            if let Some(state) = history.domains().get(&domain) {
                seq = seq.max(state.highest_accepted_seq());
            }
            for entry in pending.iter().filter(|entry| {
                entry.domain == domain && entry.entry_type == "publisher_declaration"
            }) {
                seq = seq.max(accepted_declaration_seq(&domain, &entry.entry_json)?);
            }
            exec_retain_declaration_seq(&tx, &domain, seq)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn highest_accepted_declaration_seq(&self, domain: &str) -> Result<Option<u64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT seq FROM declaration_floors WHERE domain = ?1",
                [domain],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn restore_recovery_owners(&self, path: &Path) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT domain, prior_declaration_json, opened_block FROM recovery_windows WHERE owner_declaration_json IS NULL ORDER BY domain",
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
                path.parent().unwrap_or_else(|| Path::new(".")),
                self.last_block()?,
            )?)
        } else {
            None
        };
        let pending = self.peek_pending_entries()?.0;
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
                if window.owner().position().block_number != opened
                    || *window.before().envelope() != prior
                {
                    return Err(unavailable());
                }
                window.owner().envelope().clone()
            } else {
                let mut candidates = Vec::new();
                for entry in &pending {
                    if entry.entry_type == "publisher_declaration"
                        && entry.domain == domain
                        && crate::declaration::evaluate(&prior, &entry.entry_json)
                            == Ok(crate::declaration::Decision::Recovery)
                        && !candidates.contains(&entry.entry_json)
                    {
                        candidates.push(entry.entry_json.clone());
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
        let doc: Value = crate::json::parse(&blob)?;
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
        let tx = self.mutation()?;
        exec_insert_publisher(&tx, domain, declaration_json, key_id, public_key)?;
        exec_insert_pending_entry(&tx, "publisher_declaration", domain, entry_json, 0)?;
        exec_retain_declaration_seq(&tx, domain, accepted_declaration_seq(domain, entry_json)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn update_publisher_declaration(
        &self,
        domain: &str,
        declaration_json: &[u8],
        key_id: &str,
        public_key: &str,
        entry_json: &Value,
    ) -> Result<()> {
        let tx = self.mutation()?;
        tx.execute(
            "UPDATE publishers SET declaration_json = ?2, key_id = ?3, public_key = ?4 WHERE domain = ?1",
            (domain, declaration_json, key_id, public_key),
        )?;
        exec_insert_pending_entry(&tx, "publisher_declaration", domain, entry_json, 0)?;
        exec_retain_declaration_seq(&tx, domain, accepted_declaration_seq(domain, entry_json)?)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn restore_publisher_declaration(
        &self,
        domain: &str,
        declaration_json: &[u8],
        key_id: &str,
        public_key: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE publishers SET declaration_json = ?2, key_id = ?3, public_key = ?4 WHERE domain = ?1",
            (domain, declaration_json, key_id, public_key),
        )?;
        Ok(())
    }

    pub(crate) fn store_sealed_recovery_window(
        &self,
        domain: &str,
        head: &[u8],
        before: &[u8],
        owner: &[u8],
        opened_block: u64,
        window_end: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO recovery_windows(domain, declaration_json, prior_declaration_json, owner_declaration_json, opened_block, window_end) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(domain) DO UPDATE SET declaration_json = excluded.declaration_json, prior_declaration_json = excluded.prior_declaration_json, owner_declaration_json = excluded.owner_declaration_json, opened_block = excluded.opened_block, window_end = excluded.window_end",
            (domain, head, before, owner, opened_block, window_end),
        )?;
        Ok(())
    }

    /// WIST-1 §5.1: the instant the stored Key Set was last discovered,
    /// against which `keyset_cache_ttl_seconds` is measured.
    pub fn declaration_fetched_at(&self, domain: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT declaration_fetched_at FROM publishers WHERE domain = ?1",
                [domain],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn mark_declaration_fetched(&self, domain: &str, at: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE publishers SET declaration_fetched_at = ?2 WHERE domain = ?1",
            (domain, at),
        )?;
        Ok(())
    }

    /// Every Declaration of a domain the Log has sealed, oldest first,
    /// so a Key Set can be resolved at the height a rule names rather
    /// than only at the present.
    pub fn sealed_declarations(&self, domain: &str) -> Result<Vec<SealedDeclarationEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, block_number, sealed_at, declaration_json FROM sealed_declarations WHERE domain = ?1 ORDER BY seq ASC",
        )?;
        let rows = stmt
            .query_map([domain], |row| {
                Ok(SealedDeclarationEntry {
                    seq: row.get::<_, i64>(0)? as u64,
                    block_number: row.get::<_, i64>(1)? as u64,
                    sealed_at: row.get(2)?,
                    declaration_json: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every roster act the Log has accepted, in Log order, so the
    /// WIST-4 §4 roster can be replayed before the next Block's acts are
    /// checked against it.
    pub fn accepted_roster_acts(&self) -> Result<Vec<RosterActRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT block_number, sealed_at, action, auditor_id, key_id, public_key, for_cause FROM roster_acts ORDER BY block_number ASC, act_index ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(RosterActRow {
                    block_number: row.get::<_, i64>(0)? as u64,
                    sealed_at: row.get(1)?,
                    action: row.get(2)?,
                    auditor_id: row.get(3)?,
                    key_id: row.get(4)?,
                    public_key: row.get(5)?,
                    for_cause: row.get::<_, i64>(6)? != 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn record_roster_acts(&self, acts: &[RosterActRow]) -> Result<()> {
        let tx = self.mutation()?;
        for (i, a) in acts.iter().enumerate() {
            tx.execute(
                "INSERT INTO roster_acts(block_number, act_index, sealed_at, action, auditor_id, key_id, public_key, for_cause) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(block_number, act_index) DO NOTHING",
                (
                    a.block_number as i64,
                    i as i64,
                    &a.sealed_at,
                    &a.action,
                    &a.auditor_id,
                    &a.key_id,
                    &a.public_key,
                    i64::from(a.for_cause),
                ),
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_turn_block(&self, rowid: i64, block_number: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE pending_entries SET turn_block = ?2 WHERE rowid = ?1 AND turn_block IS NULL",
            (rowid, block_number as i64),
        )?;
        Ok(())
    }

    pub fn get_publisher_declaration(&self, domain: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT declaration_json FROM publishers WHERE domain = ?1",
                [domain],
                |row| row.get(0),
            )
            .optional()
            .map_err(Error::Db)
    }

    pub fn open_recovery_window(
        &self,
        domain: &str,
        declaration_json: &[u8],
        prior_declaration_json: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO recovery_windows(domain, declaration_json, prior_declaration_json, owner_declaration_json) VALUES (?1, ?2, ?3, ?2)",
            (domain, declaration_json, prior_declaration_json),
        )?;
        Ok(())
    }

    pub fn get_recovery_window(&self, domain: &str) -> Result<Option<RecoveryWindowRow>> {
        self.conn
            .query_row(
                "SELECT declaration_json, prior_declaration_json, opened_block, window_end, owner_declaration_json FROM recovery_windows WHERE domain = ?1",
                [domain],
                |row| {
                    Ok(RecoveryWindowRow {
                        declaration_json: row.get(0)?,
                        prior_declaration_json: row.get(1)?,
                        opened_block: row.get(2)?,
                        window_end: row.get(3)?,
                        owner_declaration_json: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Error::Db)
    }

    /// WIST-1 §5.2: the window's chain head — the recovery Declaration, or
    /// the newest Declaration that legitimately follows it. Settlement
    /// revalidates against this and the domain resumes under it.
    pub fn update_recovery_chain_head(&self, domain: &str, declaration_json: &[u8]) -> Result<()> {
        self.conn.execute(
            "UPDATE recovery_windows SET declaration_json = ?2 WHERE domain = ?1",
            (domain, declaration_json),
        )?;
        Ok(())
    }

    pub fn list_pending_recovery_windows(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT domain FROM recovery_windows WHERE opened_block IS NULL ORDER BY domain",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()
            .map_err(Error::Db)
    }

    pub fn activate_recovery_window(
        &self,
        domain: &str,
        opened_block: i64,
        window_end: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE recovery_windows SET opened_block = ?2, window_end = ?3 WHERE domain = ?1 AND opened_block IS NULL",
            (domain, opened_block, window_end),
        )?;
        Ok(())
    }

    pub fn list_due_recovery_windows(&self, now: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT domain, declaration_json FROM recovery_windows WHERE window_end IS NOT NULL AND window_end <= ?1 ORDER BY domain",
        )?;
        let rows = stmt.query_map([now], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Error::Db)
    }

    pub fn list_open_recovery_windows(&self) -> Result<Vec<(String, i64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT domain, opened_block, window_end FROM recovery_windows WHERE opened_block IS NOT NULL ORDER BY domain",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Error::Db)
    }

    pub(crate) fn recovery_settled(&self, domain: &str, owner_hash: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_settlements WHERE domain = ?1 AND owner_hash = ?2)",
            (domain, owner_hash),
            |row| row.get(0),
        )?)
    }

    pub(crate) fn mark_recovery_settled(&self, domain: &str, owner_hash: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO recovery_settlements(domain, owner_hash) VALUES (?1, ?2)",
            (domain, owner_hash),
        )?;
        Ok(())
    }

    pub(crate) fn remove_pending_declaration(&self, rowid: i64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM pending_entries WHERE rowid = ?1 AND entry_type = 'publisher_declaration'",
            [rowid],
        )?;
        Ok(())
    }

    pub fn close_recovery_window(&self, domain: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM recovery_windows WHERE domain = ?1", [domain])?;
        Ok(())
    }

    pub fn queue_delta(
        &self,
        domain: &str,
        delta_id: &str,
        entry_json: &Value,
        url: &str,
        tip: &str,
        chain_pos: i64,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(entry_json)?;
        let tx = self.mutation()?;
        exec_insert_seen_delta(&tx, delta_id, domain)?;
        tx.execute(
            "INSERT INTO queued_deltas(domain, delta_id, entry_json, url, chain_pos) VALUES (?1, ?2, ?3, ?4, ?5)",
            (domain, delta_id, bytes, url, chain_pos),
        )?;
        exec_set_url_tip(&tx, url, domain, tip)?;
        tx.commit()?;
        Ok(())
    }

    /// A Delta already accepted and pending when its domain's recovery
    /// window opens: it is moved into the queue rather than sealed, and
    /// its `seen` and chain-tip state is already recorded.
    pub(crate) fn requeue_pending_delta(&self, entry: &PendingEntryRow) -> Result<()> {
        let delta = &entry.entry_json["delta"];
        let delta_id = wist_core::delta::delta_id(delta)?;
        let url = delta["url"].as_str().unwrap_or_default();
        let tx = self.mutation()?;
        let moved = tx.execute(
            "INSERT INTO queued_deltas(domain, delta_id, entry_json, url, chain_pos, acceptance_order) SELECT domain, ?2, entry_json, ?3, chain_pos, acceptance_order FROM pending_entries WHERE rowid = ?1 AND entry_type = 'publisher_delta' AND domain = ?4",
            (entry.rowid, delta_id, url, &entry.domain),
        )?;
        if moved != 1 {
            return Err(Error::History(
                "pending Delta copy unavailable for recovery diversion".into(),
            ));
        }
        tx.execute(
            "DELETE FROM pending_entries WHERE rowid = ?1",
            [entry.rowid],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn drain_queued_deltas(&self, domain: &str) -> Result<Vec<QueuedDeltaRow>> {
        let tx = self.mutation()?;
        let rows = {
            let mut stmt = tx.prepare(
                "SELECT delta_id, entry_json, url, chain_pos, acceptance_order FROM queued_deltas WHERE domain = ?1 ORDER BY acceptance_order",
            )?;
            let mapped = stmt.query_map([domain], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let entries = rows
            .into_iter()
            .map(|(delta_id, blob, url, chain_pos, acceptance_order)| {
                Ok(QueuedDeltaRow {
                    delta_id,
                    entry_json: crate::json::parse(&blob)?,
                    url,
                    chain_pos,
                    acceptance_order,
                })
            })
            .collect::<Result<_>>()?;
        tx.execute("DELETE FROM queued_deltas WHERE domain = ?1", [domain])?;
        tx.commit()?;
        Ok(entries)
    }

    pub(crate) fn reject_delta_copies(
        &self,
        domain: &str,
        rejected: &[(Value, &str)],
        at: &str,
    ) -> Result<Vec<String>> {
        if rejected.is_empty() {
            return Ok(Vec::new());
        }
        let tx = self.mutation()?;
        let mut dropped = std::collections::BTreeMap::new();
        for (envelope, code) in rejected {
            let delta = &envelope["delta"];
            dropped.insert(
                wist_core::delta::delta_id(delta)?,
                (delta["prev"].as_str().map(str::to_owned), *code),
            );
        }
        let mut statement = tx.prepare(
            "SELECT entry_json FROM pending_entries WHERE entry_type = 'publisher_delta' AND domain = ?1 UNION ALL SELECT entry_json FROM queued_deltas WHERE domain = ?1",
        )?;
        let copies = statement
            .query_map([domain], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|raw| crate::json::parse(&raw))
            .collect::<serde_json::Result<Vec<_>>>()?;
        drop(statement);
        loop {
            let count = dropped.len();
            for envelope in &copies {
                let delta = &envelope["delta"];
                let id = wist_core::delta::delta_id(delta)?;
                if !dropped.contains_key(&id)
                    && delta["prev"]
                        .as_str()
                        .is_some_and(|prev| dropped.contains_key(prev))
                {
                    dropped.insert(id, (delta["prev"].as_str().map(str::to_owned), "WIST1-E07"));
                }
            }
            if dropped.len() == count {
                break;
            }
        }
        let mut tip_statement = tx.prepare("SELECT url, tip FROM url_tips WHERE domain = ?1")?;
        let tips = tip_statement
            .query_map([domain], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(tip_statement);
        for (url, tip) in tips {
            if !dropped.contains_key(&tip) {
                continue;
            }
            let mut restored = Some(tip);
            let mut visited = std::collections::HashSet::new();
            while let Some(id) = &restored {
                if !visited.insert(id.clone()) {
                    return Err(Error::History("accepted Delta predecessor cycle".into()));
                }
                let Some((prev, _)) = dropped.get(id) else {
                    break;
                };
                restored = prev.clone();
            }
            match restored {
                Some(id) if self.is_delta_seen_for(&id, domain)? => {
                    exec_set_url_tip(&tx, &url, domain, &id)?
                }
                _ => {
                    tx.execute(
                        "DELETE FROM url_tips WHERE domain = ?1 AND url = ?2",
                        (domain, &url),
                    )?;
                }
            }
        }
        let mut report = Vec::new();
        for (id, (_, code)) in &dropped {
            self.insert_rejection(domain, code, at, Some(id), Some("accepted Delta copy rejected; dependent copies cannot resolve their predecessor"))?;
            tx.execute(
                "DELETE FROM seen_deltas WHERE domain = ?1 AND delta_id = ?2",
                (domain, &id),
            )?;
            tx.execute(
                "DELETE FROM queued_deltas WHERE domain = ?1 AND delta_id = ?2",
                (domain, &id),
            )?;
            report.push(format!("{id}: {code}"));
        }
        for entry in self.peek_pending_entries()?.0 {
            if entry.entry_type == "publisher_delta"
                && entry.domain == domain
                && dropped.contains_key(&wist_core::delta::delta_id(&entry.entry_json["delta"])?)
            {
                tx.execute(
                    "DELETE FROM pending_entries WHERE rowid = ?1",
                    [entry.rowid],
                )?;
            }
        }
        tx.commit()?;
        Ok(report)
    }

    pub(crate) fn release_queued_delta(&self, domain: &str, delta: &QueuedDeltaRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO pending_entries(entry_type, domain, entry_json, chain_pos, acceptance_order) VALUES ('publisher_delta', ?1, ?2, ?3, ?4)",
            (domain, serde_json::to_vec(&delta.entry_json)?, delta.chain_pos, delta.acceptance_order),
        )?;
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

    pub fn is_delta_seen_for(&self, delta_id: &str, domain: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM seen_deltas WHERE delta_id = ?1 AND domain = ?2",
                (delta_id, domain),
                |_| Ok(()),
            )
            .optional()?
            .is_some())
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
        let tx = self.mutation()?;
        let mut stmt = tx
            .prepare("SELECT entry_type, domain, entry_json FROM pending_entries ORDER BY rowid")?;
        let rows: Vec<(String, String, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        let entries = rows
            .into_iter()
            .map(|(entry_type, domain, blob)| {
                Ok(PendingEntry {
                    entry_type,
                    domain,
                    entry_json: crate::json::parse(&blob)?,
                })
            })
            .collect::<Result<_>>()?;
        tx.execute("DELETE FROM pending_entries", [])?;
        tx.commit()?;
        Ok(entries)
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
            "SELECT rowid, entry_type, domain, entry_json, turn_block FROM pending_entries ORDER BY acceptance_order ASC",
        )?;
        type PendingRow = (i64, String, String, Vec<u8>, Option<i64>);
        let rows: Vec<PendingRow> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let max_rowid = rows.iter().map(|(rowid, ..)| *rowid).max().unwrap_or(0);
        let entries = rows
            .into_iter()
            .map(|(rowid, entry_type, domain, blob, turn_block)| {
                Ok(PendingEntryRow {
                    rowid,
                    entry_type,
                    domain,
                    entry_json: crate::json::parse(&blob)?,
                    turn_block: turn_block.map(|b| b as u64),
                })
            })
            .collect::<Result<_>>()?;
        Ok((entries, max_rowid))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_seal(
        &self,
        sealed_rowids: &[i64],
        block_number: u64,
        block_hash: &str,
        sealed_at: &str,
        records: &[RecordUpsert],
        param_changes: &[ParamChangeRow],
        governance: &[GovernanceRow],
        declarations: &[SealedDeclarationRow],
        decompressed_bytes: u64,
    ) -> Result<()> {
        let tx = self.mutation()?;
        for rowid in sealed_rowids {
            tx.execute("DELETE FROM pending_entries WHERE rowid = ?1", [rowid])?;
        }
        tx.execute(
            "INSERT INTO blocks(block_number, block_hash, sealed_at, decompressed_bytes) VALUES (?1, ?2, ?3, ?4)",
            (block_number as i64, block_hash, sealed_at, decompressed_bytes),
        )?;
        for r in records {
            exec_upsert_record(&tx, r, sealed_at)?;
        }
        for d in declarations {
            exec_retain_declaration_seq(&tx, d.domain, d.seq)?;
            tx.execute(
                "INSERT INTO sealed_declarations(domain, seq, block_number, sealed_at, declaration_json) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(domain, seq) DO NOTHING",
                (
                    d.domain,
                    d.seq as i64,
                    block_number as i64,
                    sealed_at,
                    d.declaration_json,
                ),
            )?;
        }
        for c in param_changes {
            tx.execute(
                "INSERT INTO param_changes(parameter, value, effective_at, block_number, entry_index) VALUES (?1, ?2, ?3, ?4, ?5)",
                (c.parameter, c.value, c.effective_at, block_number as i64, c.entry_index),
            )?;
        }
        for g in governance {
            tx.execute(
                "INSERT INTO governance(update_id, action, domain, level, notice_id, outcome, sealed_at, block_number, kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                (
                    g.update_id,
                    g.action,
                    g.domain,
                    g.level,
                    g.notice_id,
                    g.outcome,
                    sealed_at,
                    block_number as i64,
                    g.kind,
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

    pub fn list_publisher_pull_times(&self) -> Result<Vec<(String, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT domain, last_pull_at FROM publishers ORDER BY domain")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn delete_record_by_delta(&self, delta_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM records WHERE delta_id = ?1", [delta_id])?;
        Ok(())
    }

    pub fn governance_by_action(&self, action: &str) -> Result<Vec<GovernanceEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT update_id, action, domain, level, notice_id, outcome, sealed_at, block_number, kind FROM governance WHERE action = ?1 ORDER BY sealed_at ASC, block_number ASC",
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
                    kind: row.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn governance_for_domain(&self, domain: &str) -> Result<Vec<GovernanceEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT update_id, action, domain, level, notice_id, outcome, sealed_at, block_number, kind FROM governance WHERE domain = ?1 ORDER BY sealed_at ASC, block_number ASC",
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
                    kind: row.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn restore_block_sizes(&self, path: &Path) -> Result<()> {
        let missing: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE decompressed_bytes IS NULL) OR EXISTS(SELECT 1 FROM param_changes WHERE entry_index IS NULL)",
            [], |row| row.get(0),
        )?;
        if !missing {
            return Ok(());
        }
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let anchor: Value = crate::json::parse(&std::fs::read(directory.join("anchor.json"))?)?;
        let public_key = anchor["anchor"]["genesis_key"]["public_key"]
            .as_str()
            .ok_or_else(|| Error::Key("stored Log Anchor has no genesis public key".into()))?;
        let key = wist_core::crypto::PublicKey::from_b64u(public_key)?;
        wist_core::envelope::verify_envelope(&anchor, "anchor", &key)?;
        let mut stmt = self.conn.prepare(
            "SELECT block_number, block_hash, sealed_at FROM blocks ORDER BY block_number",
        )?;
        let blocks = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let first = blocks
            .first()
            .map(|b| crate::registry::epoch(&b.2))
            .transpose()?
            .unwrap_or(0);
        let mut schedule = wist_core::parameters::Schedule::new(first);
        let mut largest = 0;
        let mut prior_at = None;
        let mut prior_hash = "sha256:genesis".to_string();
        let tx = self.mutation()?;
        for (index, (height, hash, sealed_at)) in blocks.into_iter().enumerate() {
            let bound = prior_at.map_or(
                crate::registry::spec("block_decompressed_cap_bytes")
                    .unwrap()
                    .default
                    .unwrap() as u64,
                |at| schedule.block_size_bounds(at).1,
            );
            let file = directory.join(format!("log/blocks/{height:09}.json.zst"));
            let bytes = crate::block_file::read(&file, bound).map_err(|error| match error {
                Error::History(message) => Error::Seal(message),
                error => error,
            })?;
            let block: Value = crate::json::parse(&bytes)?;
            wist_core::block::verify_block(&block, &key)?;
            wist_core::block::verify_chain_link(&block["header"], &prior_hash)?;
            if height != index as u64
                || block["header"]["block_number"] != height
                || block["header"]["sealed_at"] != sealed_at
                || wist_core::block::block_hash(&block["header"])? != hash
            {
                return Err(Error::Seal(
                    "stored Block does not match its history row".into(),
                ));
            }
            let at = crate::registry::epoch(&sealed_at)?;
            if prior_at.is_some_and(|prior| at <= prior) {
                return Err(Error::Seal(
                    "stored Block timestamps are not increasing".into(),
                ));
            }
            let canonical = wist_core::jcs::canonicalize(&block)?;
            let size = canonical.len() as u64;
            largest = largest.max(size);
            tx.execute(
                "DELETE FROM param_changes WHERE block_number = ?1",
                [height],
            )?;
            for (entry_index, entry) in block["entries"].as_array().unwrap().iter().enumerate() {
                let update = &entry["body"]["update"];
                if entry["type"] != "registry_update" || update["action"] != "parameter_change" {
                    continue;
                }
                wist_core::envelope::verify_envelope(&entry["body"], "update", &key)?;
                let Some(parameter) = update["details"]["parameter"].as_str() else {
                    continue;
                };
                let Some(value) = update["details"]["value"].as_i64() else {
                    continue;
                };
                let Some(effective_at) = update["effective_at"].as_str() else {
                    continue;
                };
                let Ok(effective_at_s) = crate::registry::epoch(effective_at) else {
                    continue;
                };
                let amendment = wist_core::parameters::Amendment {
                    parameter: parameter.into(),
                    value,
                    block_number: height,
                    entry_index: entry_index as u64,
                    sealed_at_s: at,
                    effective_at_s,
                };
                let _ = crate::registry::accept(&mut schedule, amendment, largest);
                tx.execute(
                    "INSERT INTO param_changes(parameter, value, effective_at, block_number, entry_index) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (parameter, value, effective_at, height, entry_index as u64),
                )?;
            }
            if largest > schedule.block_size_bounds(at).0 {
                return Err(Error::Seal(format!(
                    "WIST3-E03 Block {height} exceeds the accepted size schedule"
                )));
            }
            if bytes != canonical {
                use std::io::Write;
                let temporary = file.with_extension("zst.tmp");
                let compressed = zstd::bulk::compress(&canonical, zstd::DEFAULT_COMPRESSION_LEVEL)?;
                let mut output = std::fs::File::create(&temporary)?;
                output.write_all(&compressed)?;
                output.sync_all()?;
                std::fs::rename(&temporary, &file)?;
                std::fs::File::open(file.parent().unwrap())?.sync_all()?;
            }
            tx.execute(
                "UPDATE blocks SET decompressed_bytes = ?1 WHERE block_number = ?2",
                (size, height),
            )?;
            prior_at = Some(at);
            prior_hash = hash;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn largest_block_bytes(&self) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(decompressed_bytes), 0) FROM blocks",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn parameter_schedule(
        &self,
        first_block_s: i64,
    ) -> Result<wist_core::parameters::Schedule> {
        let mut stmt = self.conn.prepare(
            "SELECT block_number, sealed_at, decompressed_bytes FROM blocks ORDER BY block_number",
        )?;
        let blocks = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let first = blocks
            .first()
            .map(|b| crate::registry::epoch(&b.1))
            .transpose()?
            .unwrap_or(first_block_s);
        let mut schedule = wist_core::parameters::Schedule::new(first);
        let mut stmt = self.conn.prepare(
            "SELECT parameter, value, block_number, entry_index, effective_at FROM param_changes ORDER BY block_number, entry_index",
        )?;
        let changes = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut changes = changes.into_iter().peekable();
        let mut largest = 0;
        for (height, sealed_at, bytes) in blocks {
            largest = largest.max(bytes);
            let at = crate::registry::epoch(&sealed_at)?;
            while changes.peek().is_some_and(|c| c.2 == height) {
                let (parameter, value, block_number, entry_index, effective_at) =
                    changes.next().unwrap();
                let amendment = wist_core::parameters::Amendment {
                    parameter,
                    value,
                    block_number,
                    entry_index,
                    sealed_at_s: at,
                    effective_at_s: crate::registry::epoch(&effective_at)?,
                };
                let _ = crate::registry::accept(&mut schedule, amendment, largest);
            }
            if largest > schedule.block_size_bounds(at).0 {
                return Err(Error::Seal(format!(
                    "WIST3-E03 Block {height} exceeds the accepted size schedule"
                )));
            }
        }
        if changes.next().is_some() {
            return Err(Error::Seal(
                "parameter history names a missing Block".into(),
            ));
        }
        Ok(schedule)
    }

    pub fn latest_param_change(&self, name: &str, at: &str) -> Result<Option<i64>> {
        let at = crate::registry::epoch(at)?;
        let schedule = self.parameter_schedule(at)?;
        Ok(schedule
            .accepted()
            .iter()
            .filter(|a| a.parameter == name && a.effective_at_s <= at)
            .max_by_key(|a| (a.effective_at_s, a.block_number, a.entry_index))
            .map(|a| a.value))
    }

    pub fn parameter_state(&self, at: &str) -> Result<Vec<(String, i64, String)>> {
        let at = crate::registry::epoch(at)?;
        let schedule = self.parameter_schedule(at)?;
        let mut latest = std::collections::BTreeMap::new();
        for amendment in schedule.accepted().iter().filter(|a| a.sealed_at_s <= at) {
            latest.insert(
                (amendment.parameter.clone(), amendment.effective_at_s),
                amendment.value,
            );
        }
        latest
            .into_iter()
            .map(|((name, effective_at), value)| {
                Ok((
                    name,
                    value,
                    jiff::Timestamp::from_second(effective_at)
                        .map_err(|e| Error::ParamChange(e.to_string()))?
                        .to_string(),
                ))
            })
            .collect()
    }

    pub fn get_record(&self, url: &str, publisher: &str) -> Result<Option<RecordRow>> {
        self.conn
            .query_row(
                "SELECT url, publisher, delta_id, observed_at, weight, title, abstract, lang, sealed_at FROM records WHERE url = ?1 AND publisher = ?2",
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
                        sealed_at: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(Error::Db)
    }

    pub fn list_records(&self) -> Result<Vec<RecordRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT url, publisher, delta_id, observed_at, weight, title, abstract, lang, sealed_at FROM records ORDER BY publisher, url",
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
                    sealed_at: row.get(8)?,
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

    /// Every domain the Log carries a `sanction` for, so §7's derived
    /// state can be read for each.
    pub fn sanctioned_domains(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT domain FROM governance WHERE action = 'sanction' ORDER BY domain",
        )?;
        let rows = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(rows)
    }

    pub fn list_url_tips(&self) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT domain, url, tip FROM url_tips ORDER BY domain, url")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// WIST-3 §7 `auditor` tuples: each admitted key with the height that
    /// admitted it and the height that removed it, if any.
    pub fn roster_state(&self) -> Result<Vec<RosterTenure>> {
        let mut admitted: Vec<RosterTenure> = Vec::new();
        for act in self.accepted_roster_acts()? {
            match act.action.as_str() {
                "auditor_admit" => admitted.push((
                    act.auditor_id,
                    act.key_id,
                    act.public_key,
                    act.block_number,
                    None,
                )),
                _ => {
                    if let Some(row) = admitted
                        .iter_mut()
                        .find(|(a, k, ..)| *a == act.auditor_id && *k == act.key_id)
                    {
                        row.4 = Some(act.block_number);
                    }
                }
            }
        }
        Ok(admitted)
    }

    pub fn url_tip(&self, domain: &str, url: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT tip FROM url_tips WHERE domain = ?1 AND url = ?2",
                (domain, url),
                |row| row.get(0),
            )
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
        let tx = self.mutation()?;
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

    fn test_declaration(seq: u64) -> Value {
        let key = wist_core::crypto::SigningKey::from_seed(&[1; 32]);
        let mut publisher = serde_json::json!({
            "wist_version": "1.0.0", "domain": "example.com", "seq": seq,
            "keys": [{"key_id": "k1", "alg": "Ed25519",
                "public_key": key.public().to_b64u(), "valid_from": "2026-01-01T00:00:00Z"}]
        });
        if seq > 0 {
            publisher["prev_declaration"] = crate::declaration::inner_hash(&test_declaration(0))
                .unwrap()
                .into();
        }
        wist_core::envelope::sign_envelope(&publisher, "publisher", "k1", &key).unwrap()
    }

    fn record_test_declaration(db: &Db) -> Result<()> {
        let doc = test_declaration(0);
        db.record_publisher_declaration("example.com", &serde_json::to_vec(&doc)?, "k1", "pk", &doc)
    }

    #[test]
    fn recovery_window_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(db.get_recovery_window("example.com").unwrap().is_none());

        db.open_recovery_window("example.com", b"{\"new\":1}", b"{\"old\":1}")
            .unwrap();
        let w = db.get_recovery_window("example.com").unwrap().unwrap();
        assert_eq!(w.declaration_json, b"{\"new\":1}");
        assert_eq!(w.prior_declaration_json, b"{\"old\":1}");
        assert!(w.opened_block.is_none());
        assert!(w.window_end.is_none());
        assert_eq!(db.list_pending_recovery_windows().unwrap(), ["example.com"]);

        db.activate_recovery_window("example.com", 4, "2026-08-23T12:00:00Z")
            .unwrap();
        let w = db.get_recovery_window("example.com").unwrap().unwrap();
        assert_eq!(w.opened_block, Some(4));
        assert_eq!(w.window_end.as_deref(), Some("2026-08-23T12:00:00Z"));
        assert!(db.list_pending_recovery_windows().unwrap().is_empty());

        assert!(db
            .list_due_recovery_windows("2026-08-23T11:59:59Z")
            .unwrap()
            .is_empty());
        let due = db
            .list_due_recovery_windows("2026-08-23T12:00:00Z")
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0, "example.com");

        db.close_recovery_window("example.com").unwrap();
        assert!(db.get_recovery_window("example.com").unwrap().is_none());
    }

    #[test]
    fn open_recovery_window_refuses_second_window() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.open_recovery_window("example.com", b"a", b"b").unwrap();
        assert!(db.open_recovery_window("example.com", b"c", b"d").is_err());
    }

    #[test]
    fn queue_delta_marks_seen_sets_tip_and_drains_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.queue_delta(
            "example.com",
            "sha256:d1",
            &serde_json::json!({"n": 1}),
            "https://example.com/a",
            "sha256:d1",
            0,
        )
        .unwrap();
        db.queue_delta(
            "example.com",
            "sha256:d2",
            &serde_json::json!({"n": 2}),
            "https://example.com/a",
            "sha256:d2",
            1,
        )
        .unwrap();
        assert!(db.is_delta_seen("sha256:d1").unwrap());
        assert_eq!(
            db.url_tip("example.com", "https://example.com/a")
                .unwrap()
                .as_deref(),
            Some("sha256:d2")
        );
        assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 0);

        let drained = db.drain_queued_deltas("example.com").unwrap();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].delta_id, "sha256:d1");
        assert_eq!(drained[0].entry_json, serde_json::json!({"n": 1}));
        assert_eq!(drained[0].chain_pos, 0);
        assert_eq!(drained[1].delta_id, "sha256:d2");
        assert!(db.drain_queued_deltas("example.com").unwrap().is_empty());
    }

    #[test]
    fn update_publisher_declaration_updates_row_and_enqueues_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        record_test_declaration(&db).unwrap();
        db.update_publisher_declaration(
            "example.com",
            &serde_json::to_vec(&test_declaration(1)).unwrap(),
            "k2",
            "pk2",
            &test_declaration(1),
        )
        .unwrap();
        let row = db.get_publisher("example.com").unwrap().unwrap();
        assert_eq!(row.key_id, "k2");
        assert_eq!(row.public_key, "pk2");
        assert_eq!(
            db.get_publisher_declaration("example.com")
                .unwrap()
                .unwrap(),
            serde_json::to_vec(&test_declaration(1)).unwrap()
        );
        assert_eq!(
            db.count_pending_entries("publisher_declaration").unwrap(),
            2
        );
    }

    #[test]
    fn open_applies_schema_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clave.sqlite");
        Db::open(&path).unwrap();
        Db::open(&path).unwrap();
    }

    #[test]
    fn feed_observations_are_atomic_and_host_scoped_across_connections() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        assert!(db
            .observe_feed_generated_at("example.com", "0000-01-01T00:00:00Z")
            .unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = ["2026-08-09T14:00:00Z", "2026-08-09T14:00:01Z"].map(|at| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let db = Db::open(&path).unwrap();
                barrier.wait();
                db.observe_feed_generated_at("example.com", at).unwrap()
            })
        });
        let [earlier, later] = handles;
        earlier.join().unwrap();
        assert!(later.join().unwrap());
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(!db
            .observe_feed_generated_at("example.com", "2026-08-09T14:00:00Z")
            .unwrap());
        assert!(db
            .observe_feed_generated_at("other.example", "0000-01-01T00:00:00Z")
            .unwrap());
        assert!(db
            .observe_feed_generated_at("example.com", "2026-08-09T14:00:01Z")
            .unwrap());
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
            &[],
            0,
            "sha256:h0",
            "2026-01-01T00:00:00Z",
            &[],
            &[ParamChangeRow {
                entry_index: 0,
                parameter: "feed_window",
                value: 500,
                effective_at: "2026-01-10T00:00:00Z",
            }],
            &[],
            &[],
            0,
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
            &[],
            1,
            "sha256:h1",
            "2026-01-02T00:00:00Z",
            &[],
            &[ParamChangeRow {
                entry_index: 0,
                parameter: "feed_window",
                value: 800,
                effective_at: "2026-01-20T00:00:00Z",
            }],
            &[],
            &[],
            0,
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
        assert!(db
            .url_tip("example.com", "https://example.com/a")
            .unwrap()
            .is_none());
        db.set_url_tip("https://example.com/a", "example.com", "sha256:1")
            .unwrap();
        assert_eq!(
            db.url_tip("example.com", "https://example.com/a")
                .unwrap()
                .unwrap(),
            "sha256:1"
        );
        db.set_url_tip("https://example.com/a", "example.com", "sha256:2")
            .unwrap();
        assert_eq!(
            db.url_tip("example.com", "https://example.com/a")
                .unwrap()
                .unwrap(),
            "sha256:2"
        );
    }

    #[test]
    fn record_publisher_declaration_is_atomic_on_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        record_test_declaration(&db).unwrap();
        assert_eq!(
            db.count_pending_entries("publisher_declaration").unwrap(),
            1
        );
        assert!(record_test_declaration(&db).is_err());
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
        assert!(db
            .url_tip("example.com", "https://example.com/y")
            .unwrap()
            .is_none());
    }

    #[test]
    fn drain_pending_entries_orders_by_rowid_and_empties_table() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        record_test_declaration(&db).unwrap();
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
        record_test_declaration(&db).unwrap();
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

        let sealed: Vec<i64> = peeked.iter().map(|e| e.rowid).collect();
        db.commit_seal(
            &sealed,
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
            &[],
            0,
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
        let (peeked, _up_to) = db.peek_pending_entries().unwrap();
        let sealed: Vec<i64> = peeked.iter().map(|e| e.rowid).collect();
        db.commit_seal(
            &sealed,
            0,
            "sha256:blockhash0",
            "2026-08-09T00:00:00Z",
            &[],
            &[],
            &[],
            &[],
            0,
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
        let (peeked2, _up_to2) = db.peek_pending_entries().unwrap();
        assert_eq!(peeked2.len(), 1);

        let sealed2: Vec<i64> = peeked2.iter().map(|e| e.rowid).collect();
        let result = db.commit_seal(
            &sealed2,
            0,
            "sha256:blockhash0-conflict",
            "2026-08-09T00:01:00Z",
            &[],
            &[],
            &[],
            &[],
            0,
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
