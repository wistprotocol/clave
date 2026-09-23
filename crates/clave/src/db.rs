use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use wist_core::objects::{AggregatorKeyEntry, PublisherState, StatusRejection};

mod delta_history;
mod delta_indexes;
mod leases;
mod pull_runs;
mod pull_schedule;
mod restore;
mod schema;
mod tree;

pub use leases::{
    process_owner, Fence, Lease, PARTITIONS, PARTITION_LEASE_SECONDS, SEALER_LEASE_SECONDS,
};
pub(crate) use pull_runs::{Credit, NewRun, Phase, PullObject, PullRun, Settled, Status, WalkPage};
pub use pull_schedule::{
    DuePull, PingAdmission, PullLease, PullOutcome, PullTask, Reason, LEASE_SECONDS,
    RETRY_BASE_SECONDS,
};
pub use pull_schedule::{AGE_PRIORITY_SECONDS, BYTES_PER_SLOT_SECOND};
pub use tree::StoredTree;

/// A top-level transaction takes the write lock before any read, so a
/// concurrent connection can neither invalidate what it read nor make its
/// commit fail.
pub(crate) struct Mutation<'a> {
    conn: &'a Connection,
    committed: bool,
    top_level: bool,
}

impl<'a> Mutation<'a> {
    pub(super) fn new(conn: &'a Connection) -> Result<Self> {
        Self::fenced(conn, None)
    }

    /// The fence token is compared under the write lock, which no takeover can
    /// change before the transaction ends; a nested transaction inherits the
    /// enclosing one's check.
    fn fenced(conn: &'a Connection, fence: Option<Fence>) -> Result<Self> {
        let top_level = conn.is_autocommit();
        if top_level {
            conn.execute_batch("BEGIN IMMEDIATE")?;
        } else {
            conn.execute_batch("SAVEPOINT clave_mutation")?;
        }
        let mutation = Self {
            conn,
            committed: false,
            top_level,
        };
        if let (true, Some(fence)) = (top_level, fence) {
            if !leases::fence_holds(conn, fence)? {
                return Err(Error::Fenced);
            }
        }
        Ok(mutation)
    }

    pub(crate) fn commit(mut self) -> Result<()> {
        if self.top_level {
            self.conn.execute_batch("COMMIT")?;
        } else {
            self.conn
                .execute_batch("RELEASE SAVEPOINT clave_mutation")?;
        }
        self.committed = true;
        #[cfg(test)]
        if self.top_level {
            interrupt::committed();
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod interrupt {
    use std::cell::Cell;

    thread_local! {
        static REMAINING: Cell<Option<usize>> = const { Cell::new(None) };
    }

    pub(crate) fn after(commits: usize) {
        REMAINING.with(|remaining| remaining.set(Some(commits)));
    }

    pub(crate) fn disarm() -> bool {
        REMAINING.with(|remaining| remaining.take().is_some())
    }

    pub(crate) struct Interrupted;

    pub(super) fn committed() {
        REMAINING.with(|remaining| match remaining.get() {
            Some(0) => {
                remaining.set(None);
                std::panic::resume_unwind(Box::new(Interrupted));
            }
            Some(n) => remaining.set(Some(n - 1)),
            None => {}
        });
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
        if self.committed {
            return;
        }
        let _ = if self.top_level {
            self.conn.execute_batch("ROLLBACK")
        } else {
            self.conn.execute_batch(
                "ROLLBACK TO SAVEPOINT clave_mutation; RELEASE SAVEPOINT clave_mutation",
            )
        };
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

#[derive(Debug, Clone)]
pub struct EpochRow {
    pub epoch_number: u64,
    pub tree_size: u64,
    pub root: String,
    pub sealed_at: String,
}

pub struct RecordRow {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub observed_at: String,
    pub title: String,
    pub abstract_text: Option<String>,
    pub lang: String,
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
    /// WIST-4 §5: the first Epoch with room for this Delta under WIST-3 §3.2's
    /// per-domain capacity; the inclusion ceiling runs from it.
    pub turn_epoch: Option<u64>,
}

pub struct ParamChangeRow<'a> {
    pub entry_index: u64,
    pub parameter: &'a str,
    pub value: i64,
    pub effective_at: &'a str,
}

pub struct WithdrawalRow<'a> {
    pub update_id: &'a str,
    pub delta_id: &'a str,
    pub domain: &'a str,
}

/// WIST-3 §7 `withdrawal` tuple: `(delta_id, publisher domain, sealing
/// height)`.
pub type WithdrawalState = (String, String, u64);

pub struct SealedLabelRow<'a> {
    pub label_id: &'a str,
    pub entry_index: u64,
    pub label: &'a wist_core::objects::Label,
}

pub struct SealedDisputeRow<'a> {
    pub dispute_id: &'a str,
    pub entry_index: u64,
    pub dispute: &'a wist_core::objects::Dispute,
}

pub struct SealedDeclarationRow<'a> {
    pub domain: &'a str,
    pub seq: u64,
    pub declaration_json: &'a [u8],
}

pub struct SealedDeclarationEntry {
    pub seq: u64,
    pub epoch_number: u64,
    pub sealed_at: String,
    pub declaration_json: Vec<u8>,
}

pub struct RecoveryWindowRow {
    pub declaration_json: Vec<u8>,
    pub owner_declaration_json: Vec<u8>,
    pub prior_declaration_json: Vec<u8>,
    pub opened_epoch: Option<i64>,
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
    pull_schedule::exec_schedule_new_publisher(conn, domain)
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

pub(super) fn exec_retain_declaration_seq(conn: &Connection, domain: &str, seq: u64) -> Result<()> {
    conn.execute(
        "INSERT INTO declaration_floors(domain, seq) VALUES (?1, ?2) ON CONFLICT(domain) DO UPDATE SET seq = MAX(seq, excluded.seq)",
        (domain, seq),
    )?;
    Ok(())
}

pub(super) fn accepted_declaration_seq(domain: &str, doc: &Value) -> Result<u64> {
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

fn exec_set_sealed_url_tip(conn: &Connection, url: &str, domain: &str, tip: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO sealed_url_tips(url, domain, tip) VALUES (?1, ?2, ?3) ON CONFLICT(domain, url) DO UPDATE SET tip = excluded.tip",
        (url, domain, tip),
    )?;
    Ok(())
}

fn epoch_chain_tips(entries: &[Value]) -> Result<Vec<(String, String, String)>> {
    let mut chains: BTreeMap<(String, String), BTreeMap<String, Option<String>>> = BTreeMap::new();
    for entry in entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_delta")
    {
        let body = &entry["body"]["delta"];
        let unreadable = || Error::Seal("a sealed Delta lacks its publisher or URL".into());
        let domain = wist_core::delta::publisher(body).map_err(|_| unreadable())?;
        let url = body["url"]
            .as_str()
            .filter(|url| !url.is_empty())
            .ok_or_else(unreadable)?;
        let id = wist_core::delta::delta_id(body)?;
        let prev = body["prev"].as_str().map(str::to_string);
        let chain = chains.entry((domain.into(), url.into())).or_default();
        if chain.insert(id, prev).is_some() {
            return Err(Error::Seal(format!(
                "the Epoch repeats a Delta of {domain} {url}"
            )));
        }
    }
    let mut tips = Vec::with_capacity(chains.len());
    for ((domain, url), chain) in chains {
        let prevs: BTreeSet<&String> = chain.values().flatten().collect();
        let mut candidates = chain.keys().filter(|id| !prevs.contains(id));
        let (Some(tip), None) = (candidates.next(), candidates.next()) else {
            return Err(Error::Seal(format!(
                "the Epoch's Deltas for {domain} {url} do not form a single chain"
            )));
        };
        tips.push((domain, url, tip.clone()));
    }
    Ok(tips)
}

fn exec_upsert_record(conn: &Connection, r: &RecordUpsert, sealed_at: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO records(url, publisher, delta_id, observed_at, title, abstract, lang, sealed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(url, publisher) DO UPDATE SET delta_id = excluded.delta_id, observed_at = excluded.observed_at, title = excluded.title, abstract = excluded.abstract, lang = excluded.lang, sealed_at = excluded.sealed_at",
        (
            r.url,
            r.publisher,
            r.delta_id,
            r.observed_at,
            r.title,
            r.abstract_text,
            r.lang,
            sealed_at,
        ),
    )?;
    Ok(())
}

pub type Publication = (u64, String);

#[derive(Debug, Clone)]
pub struct WitnessRow {
    pub name: String,
    pub public_key: String,
    pub base_url: String,
    pub last_size: u64,
}

pub struct Db {
    conn: Connection,
    fence: Option<Fence>,
}

impl Db {
    pub(crate) fn observe_feed_generated_at(&self, domain: &str, at: &str) -> Result<bool> {
        let at = crate::registry::unix(at)?;
        self.write(|conn| {
            Ok(conn
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
        })
    }

    pub(crate) fn mutation(&self) -> Result<Mutation<'_>> {
        Mutation::fenced(&self.conn, self.fence)
    }

    fn write<T>(&self, change: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let tx = self.mutation()?;
        let changed = change(&tx)?;
        tx.commit()?;
        Ok(changed)
    }

    pub fn consistent_read<T>(&self, read: impl FnOnce(&Db) -> Result<T>) -> Result<T> {
        self.conn.execute_batch("BEGIN")?;
        match read(self) {
            Ok(value) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn execute(&self, sql: &str, params: impl rusqlite::Params) -> Result<usize> {
        self.write(|conn| Ok(conn.execute(sql, params)?))
    }

    pub fn fenced(self, fence: Fence) -> Db {
        Db {
            fence: Some(fence),
            ..self
        }
    }

    pub fn open(path: &Path) -> Result<Db> {
        let db = Db::connect(path)?;
        schema::migrate(&db.conn)?;
        restore::run(&db, path)?;
        Ok(db)
    }

    /// Work that must not share a connection (each pull, status request and
    /// background pass) takes its own.
    pub fn connect(path: &Path) -> Result<Db> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(Db { conn, fence: None })
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
        self.execute(
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
        let tx = self.mutation()?;
        exec_insert_publisher(&tx, domain, declaration_json, key_id, public_key)?;
        tx.commit()
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

    /// WIST-1 §5.2: a fresh identity's pending head is held beside the current
    /// Declaration until the Log activates or reverses it.
    pub fn get_pending_identity(&self, domain: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT declaration_json FROM pending_identities WHERE domain = ?1",
                [domain],
                |row| row.get(0),
            )
            .optional()
            .map_err(Error::Db)
    }

    pub fn record_pending_identity(
        &self,
        domain: &str,
        declaration_json: &[u8],
        entry_json: &Value,
    ) -> Result<()> {
        let tx = self.mutation()?;
        tx.execute(
            "INSERT INTO pending_identities(domain, declaration_json) VALUES (?1, ?2) ON CONFLICT(domain) DO UPDATE SET declaration_json = excluded.declaration_json",
            (domain, declaration_json),
        )?;
        exec_insert_pending_entry(&tx, "publisher_declaration", domain, entry_json, 0)?;
        exec_retain_declaration_seq(&tx, domain, accepted_declaration_seq(domain, entry_json)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn clear_pending_identity(&self, domain: &str) -> Result<()> {
        self.execute("DELETE FROM pending_identities WHERE domain = ?1", [domain])?;
        Ok(())
    }

    pub(crate) fn restore_publisher_declaration(
        &self,
        domain: &str,
        declaration_json: &[u8],
        key_id: &str,
        public_key: &str,
    ) -> Result<()> {
        self.execute(
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
        opened_epoch: u64,
        window_end: &str,
    ) -> Result<()> {
        self.execute(
            "INSERT INTO recovery_windows(domain, declaration_json, prior_declaration_json, owner_declaration_json, opened_epoch, window_end) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(domain) DO UPDATE SET declaration_json = excluded.declaration_json, prior_declaration_json = excluded.prior_declaration_json, owner_declaration_json = excluded.owner_declaration_json, opened_epoch = excluded.opened_epoch, window_end = excluded.window_end",
            (domain, head, before, owner, opened_epoch, window_end),
        )?;
        Ok(())
    }

    /// WIST-1 §5.1: `keyset_cache_ttl_seconds` is measured from this instant.
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
        self.execute(
            "UPDATE publishers SET declaration_fetched_at = ?2 WHERE domain = ?1",
            (domain, at),
        )?;
        Ok(())
    }

    pub fn sealed_declarations(&self, domain: &str) -> Result<Vec<SealedDeclarationEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, epoch_number, sealed_at, declaration_json FROM sealed_declarations WHERE domain = ?1 ORDER BY seq ASC",
        )?;
        let rows = stmt
            .query_map([domain], |row| {
                Ok(SealedDeclarationEntry {
                    seq: row.get::<_, i64>(0)? as u64,
                    epoch_number: row.get::<_, i64>(1)? as u64,
                    sealed_at: row.get(2)?,
                    declaration_json: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn set_turn_epoch(&self, rowid: i64, epoch_number: u64) -> Result<()> {
        self.execute(
            "UPDATE pending_entries SET turn_epoch = ?2 WHERE rowid = ?1 AND turn_epoch IS NULL",
            (rowid, epoch_number as i64),
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
        self.execute(
            "INSERT INTO recovery_windows(domain, declaration_json, prior_declaration_json, owner_declaration_json) VALUES (?1, ?2, ?3, ?2)",
            (domain, declaration_json, prior_declaration_json),
        )?;
        Ok(())
    }

    pub fn get_recovery_window(&self, domain: &str) -> Result<Option<RecoveryWindowRow>> {
        self.conn
            .query_row(
                "SELECT declaration_json, prior_declaration_json, opened_epoch, window_end, owner_declaration_json FROM recovery_windows WHERE domain = ?1",
                [domain],
                |row| {
                    Ok(RecoveryWindowRow {
                        declaration_json: row.get(0)?,
                        prior_declaration_json: row.get(1)?,
                        opened_epoch: row.get(2)?,
                        window_end: row.get(3)?,
                        owner_declaration_json: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Error::Db)
    }

    /// WIST-1 §5.2: the recovery Declaration or the newest Declaration that
    /// legitimately follows it; settlement revalidates against it.
    pub fn update_recovery_chain_head(&self, domain: &str, declaration_json: &[u8]) -> Result<()> {
        self.execute(
            "UPDATE recovery_windows SET declaration_json = ?2 WHERE domain = ?1",
            (domain, declaration_json),
        )?;
        Ok(())
    }

    pub fn list_pending_recovery_windows(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT domain FROM recovery_windows WHERE opened_epoch IS NULL ORDER BY domain",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()
            .map_err(Error::Db)
    }

    pub fn activate_recovery_window(
        &self,
        domain: &str,
        opened_epoch: i64,
        window_end: &str,
    ) -> Result<()> {
        self.execute(
            "UPDATE recovery_windows SET opened_epoch = ?2, window_end = ?3 WHERE domain = ?1 AND opened_epoch IS NULL",
            (domain, opened_epoch, window_end),
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
            "SELECT domain, opened_epoch, window_end FROM recovery_windows WHERE opened_epoch IS NOT NULL ORDER BY domain",
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
        self.execute(
            "INSERT INTO recovery_settlements(domain, owner_hash) VALUES (?1, ?2)",
            (domain, owner_hash),
        )?;
        Ok(())
    }

    pub(crate) fn remove_pending_declaration(&self, rowid: i64) -> Result<()> {
        self.execute(
            "DELETE FROM pending_entries WHERE rowid = ?1 AND entry_type = 'publisher_declaration'",
            [rowid],
        )?;
        Ok(())
    }

    pub fn close_recovery_window(&self, domain: &str) -> Result<()> {
        self.execute("DELETE FROM recovery_windows WHERE domain = ?1", [domain])?;
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

    pub(crate) fn reject_label_entries(
        &self,
        rejected: &[(i64, String, String, String)],
        at: &str,
    ) -> Result<Vec<String>> {
        if rejected.is_empty() {
            return Ok(Vec::new());
        }
        let tx = self.mutation()?;
        let mut report = Vec::with_capacity(rejected.len());
        for (rowid, domain, entry_type, id) in rejected {
            tx.execute(
                "INSERT INTO rejections(domain, code, at, delta_id, detail) VALUES (?1, 'WIST2-E06', ?2, ?3, ?4)",
                (
                    domain,
                    at,
                    id,
                    format!("queued {entry_type} asserted_at exceeds the clock_skew_seconds allowance at sealing"),
                ),
            )?;
            tx.execute(
                "DELETE FROM seen_labels WHERE domain = ?1 AND id = ?2",
                (domain, id),
            )?;
            tx.execute("DELETE FROM pending_entries WHERE rowid = ?1", [rowid])?;
            report.push(format!("{id}: WIST2-E06"));
        }
        tx.commit()?;
        Ok(report)
    }

    pub(crate) fn release_queued_delta(&self, domain: &str, delta: &QueuedDeltaRow) -> Result<()> {
        self.execute(
            "INSERT INTO pending_entries(entry_type, domain, entry_json, chain_pos, acceptance_order) VALUES ('publisher_delta', ?1, ?2, ?3, ?4)",
            (domain, serde_json::to_vec(&delta.entry_json)?, delta.chain_pos, delta.acceptance_order),
        )?;
        Ok(())
    }

    pub fn set_publisher_pulled(&self, domain: &str, now: &str) -> Result<()> {
        self.execute(
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
        self.write(|conn| exec_insert_seen_delta(conn, delta_id, domain))
    }

    pub fn insert_pending_entry(
        &self,
        entry_type: &str,
        domain: &str,
        entry_json: &Value,
        chain_pos: i64,
    ) -> Result<()> {
        self.write(|conn| {
            exec_insert_pending_entry(conn, entry_type, domain, entry_json, chain_pos)
        })
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

    pub fn last_epoch(&self) -> Result<Option<EpochRow>> {
        self.epoch(
            "SELECT epoch_number, tree_size, root, sealed_at FROM epochs ORDER BY epoch_number DESC LIMIT 1",
            [],
        )
    }

    pub fn epoch_at(&self, epoch_number: u64) -> Result<Option<EpochRow>> {
        self.epoch(
            "SELECT epoch_number, tree_size, root, sealed_at FROM epochs WHERE epoch_number = ?1",
            [epoch_number as i64],
        )
    }

    fn epoch<P: rusqlite::Params>(&self, sql: &str, params: P) -> Result<Option<EpochRow>> {
        self.conn
            .query_row(sql, params, |row| {
                Ok(EpochRow {
                    epoch_number: row.get::<_, i64>(0)? as u64,
                    tree_size: row.get::<_, i64>(1)? as u64,
                    root: row.get(2)?,
                    sealed_at: row.get(3)?,
                })
            })
            .optional()
            .map_err(Error::Db)
    }

    /// WIST-3 §3: `size(-1)` is 0.
    pub fn size_before(&self, epoch_number: u64) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(tree_size), 0) FROM epochs WHERE epoch_number < ?1",
            [epoch_number as i64],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    pub fn tree_size(&self) -> Result<u64> {
        self.size_before(u64::MAX)
    }

    pub fn log_tree(&self) -> StoredTree<'_> {
        StoredTree::new(&self.conn)
    }

    pub fn entry_range(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>> {
        tree::entry_range(&self.conn, from, to)
    }

    pub fn tile_hashes(&self, level: u8, index: u64) -> Result<Option<Vec<[u8; 32]>>> {
        tree::read_tile(&self.conn, level, index)
    }

    pub fn root_after_appending(
        &self,
        previous_size: u64,
        leaves: &[[u8; 32]],
    ) -> Result<[u8; 32]> {
        tree::root_after_appending(&self.conn, previous_size, leaves)
    }

    pub fn consistency_proof(&self, from: u64, to: u64) -> Result<Vec<[u8; 32]>> {
        wist_core::merkle::consistency_proof_from(&self.log_tree(), from, to)
            .map_err(|e| Error::History(e.to_string()))
    }

    pub fn epoch_entries(&self, epoch_number: u64) -> Result<Vec<Value>> {
        let Some(epoch) = self.epoch_at(epoch_number)? else {
            return Ok(Vec::new());
        };
        self.entry_range(self.size_before(epoch_number)?, epoch.tree_size)?
            .iter()
            .map(|bytes| crate::json::parse(bytes).map_err(Error::from))
            .collect()
    }

    pub fn peek_pending_entries(&self) -> Result<(Vec<PendingEntryRow>, i64)> {
        let mut stmt = self.conn.prepare(
            "SELECT rowid, entry_type, domain, entry_json, turn_epoch FROM pending_entries ORDER BY acceptance_order ASC",
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
            .map(|(rowid, entry_type, domain, blob, turn_epoch)| {
                Ok(PendingEntryRow {
                    rowid,
                    entry_type,
                    domain,
                    entry_json: crate::json::parse(&blob)?,
                    turn_epoch: turn_epoch.map(|b| b as u64),
                })
            })
            .collect::<Result<_>>()?;
        Ok((entries, max_rowid))
    }

    pub fn mark_published(&self, epoch_number: u64) -> Result<()> {
        self.execute(
            "UPDATE epochs SET published = 1 WHERE epoch_number = ?1",
            [epoch_number as i64],
        )?;
        Ok(())
    }

    pub fn unpublished_publications(&self) -> Result<Vec<Publication>> {
        let mut statement = self.conn.prepare(
            "SELECT epoch_number, note FROM epochs WHERE published = 0 ORDER BY epoch_number",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn head_publication(&self) -> Result<Option<Publication>> {
        Ok(self
            .conn
            .query_row(
                "SELECT epoch_number, note FROM epochs ORDER BY epoch_number DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn checkpoint_note(&self, epoch_number: u64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT note FROM epochs WHERE epoch_number = ?1",
                [epoch_number as i64],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// WIST-3 §6: the note text never changes; only signature lines are added.
    pub fn replace_checkpoint_note(&self, epoch_number: u64, note: &str) -> Result<()> {
        self.execute(
            "UPDATE epochs SET note = ?2 WHERE epoch_number = ?1",
            (epoch_number as i64, note),
        )?;
        Ok(())
    }

    pub fn witnesses(&self) -> Result<Vec<WitnessRow>> {
        let mut statement = self
            .conn
            .prepare("SELECT name, public_key, base_url, last_size FROM witnesses ORDER BY name")?;
        let rows = statement
            .query_map([], |row| {
                Ok(WitnessRow {
                    name: row.get(0)?,
                    public_key: row.get(1)?,
                    base_url: row.get(2)?,
                    last_size: row.get::<_, i64>(3)?.max(0) as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn add_witness(&self, name: &str, public_key: &str, base_url: &str) -> Result<()> {
        self.execute(
            "INSERT INTO witnesses(name, public_key, base_url, last_size) VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(name) DO UPDATE SET public_key = excluded.public_key, base_url = excluded.base_url",
            (name, public_key, base_url),
        )?;
        Ok(())
    }

    pub fn remove_witness(&self, name: &str) -> Result<()> {
        self.execute("DELETE FROM witnesses WHERE name = ?1", [name])?;
        Ok(())
    }

    pub fn set_witness_size(&self, name: &str, size: u64) -> Result<()> {
        self.execute(
            "UPDATE witnesses SET last_size = ?2 WHERE name = ?1",
            (name, size as i64),
        )?;
        Ok(())
    }

    /// WIST-3 §3.4: the genesis key included.
    pub fn admitted_note_key_ids(&self) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare("SELECT note_key_id FROM aggregator_keys ORDER BY note_key_id")?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn admit_aggregator_key(
        &self,
        note_key_id: &str,
        key_id: &str,
        public_key: &str,
        added_epoch: u64,
    ) -> Result<()> {
        self.execute(
            "INSERT OR IGNORE INTO aggregator_keys(note_key_id, key_id, public_key, added_epoch) VALUES (?1, ?2, ?3, ?4)",
            (note_key_id, key_id, public_key, added_epoch as i64),
        )?;
        Ok(())
    }

    /// WIST-3 §3.4, §7: removed keys included, ordered by `key_id`.
    pub fn aggregator_key_entries(&self) -> Result<Vec<AggregatorKeyEntry>> {
        let mut statement = self.conn.prepare(
            "SELECT key_id, public_key, added_epoch, removed_epoch, adding_act, removing_act FROM aggregator_keys ORDER BY key_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    AggregatorKeyEntry {
                        key_id: row.get(0)?,
                        public_key: row.get(1)?,
                        added_height: row.get::<_, i64>(2)? as u64,
                        removed_height: row.get::<_, Option<i64>>(3)?.map(|h| h as u64),
                        adding_act: None,
                        removing_act: None,
                    },
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(entry, adding, removing)| {
                Ok(AggregatorKeyEntry {
                    adding_act: adding.map(|act| crate::json::parse(&act)).transpose()?,
                    removing_act: removing.map(|act| crate::json::parse(&act)).transpose()?,
                    ..entry
                })
            })
            .collect()
    }

    pub fn signing_key_id(&self, public_key: &wist_core::crypto::PublicKey) -> Result<String> {
        let encoded = public_key.to_b64u();
        Ok(self
            .conn
            .query_row(
                "SELECT key_id FROM aggregator_keys WHERE public_key = ?1 ORDER BY added_epoch, key_id LIMIT 1",
                [&encoded],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| crate::keys::GENESIS_KEY_ID.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_seal(
        &self,
        sk: &wist_core::crypto::SigningKey,
        log_id: &str,
        sealed_rowids: &[i64],
        epoch_number: u64,
        sealed_at: &str,
        entries: &[Value],
        epoch_bytes: u64,
        records: &[RecordUpsert],
        param_changes: &[ParamChangeRow],
        withdrawals: &[WithdrawalRow],
        suffix_lists: &[String],
        labels: &[SealedLabelRow],
        disputes: &[SealedDisputeRow],
        declarations: &[SealedDeclarationRow],
    ) -> Result<EpochRow> {
        self.commit_seal_under(
            &[sk],
            None,
            log_id,
            sealed_rowids,
            epoch_number,
            sealed_at,
            entries,
            epoch_bytes,
            records,
            param_changes,
            withdrawals,
            suffix_lists,
            labels,
            disputes,
            declarations,
        )
    }

    /// WIST-3 §3.2, §5: the leaves, the Checkpoint signed under every `signers`
    /// key (the held keys valid at this height, §3.4) and the rows the Epoch
    /// carries are written in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_seal_under(
        &self,
        signers: &[&wist_core::crypto::SigningKey],
        key_entries: Option<&[AggregatorKeyEntry]>,
        log_id: &str,
        sealed_rowids: &[i64],
        epoch_number: u64,
        sealed_at: &str,
        entries: &[Value],
        epoch_bytes: u64,
        records: &[RecordUpsert],
        param_changes: &[ParamChangeRow],
        withdrawals: &[WithdrawalRow],
        suffix_lists: &[String],
        labels: &[SealedLabelRow],
        disputes: &[SealedDisputeRow],
        declarations: &[SealedDeclarationRow],
    ) -> Result<EpochRow> {
        if signers.is_empty() {
            return Err(Error::Seal(
                "WIST3-E03 no held Aggregator key is valid at this Epoch's height".into(),
            ));
        }
        if signers.len() > wist_core::checkpoint::MAX_SIGNATURE_LINES {
            return Err(Error::Seal(format!(
                "a Checkpoint carries at most {} signature lines, and {} held keys are valid at this height",
                wist_core::checkpoint::MAX_SIGNATURE_LINES,
                signers.len()
            )));
        }
        let chain_tips = epoch_chain_tips(entries)?;
        let tx = self.mutation()?;
        for rowid in sealed_rowids {
            tx.execute("DELETE FROM pending_entries WHERE rowid = ?1", [rowid])?;
        }
        let previous_size = self.size_before(epoch_number)?;
        let mut leaf_data = Vec::with_capacity(entries.len());
        let mut leaves = Vec::with_capacity(entries.len());
        for entry in entries {
            let canonical = wist_core::jcs::canonicalize(entry)?;
            wist_core::tiles::check_entry_bytes(canonical.len() as u64)
                .map_err(|e| Error::Seal(e.to_string()))?;
            leaves.push(wist_core::merkle::leaf_hash(&canonical));
            leaf_data.push(canonical);
        }
        let root = tree::append(&tx, previous_size, &leaves)?;
        let tree_size = previous_size + leaves.len() as u64;
        let mut checkpoint = wist_core::checkpoint::Checkpoint::new(
            log_id,
            tree_size,
            root,
            epoch_number,
            sealed_at,
        )
        .map_err(|e| Error::Seal(e.to_string()))?;
        for signer in signers {
            checkpoint.sign(signer);
        }
        if let Some(entries) = key_entries {
            tx.execute("DELETE FROM aggregator_keys", [])?;
            for entry in entries {
                let public_key = wist_core::crypto::PublicKey::from_b64u(&entry.public_key)?;
                tx.execute(
                    "INSERT INTO aggregator_keys(note_key_id, key_id, public_key, added_epoch, removed_epoch, adding_act, removing_act) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    (
                        wist_core::crypto::hex_encode(&wist_core::checkpoint::aggregator_key_id(
                            log_id,
                            &public_key,
                        )),
                        &entry.key_id,
                        &entry.public_key,
                        entry.added_height as i64,
                        entry.removed_height.map(|h| h as i64),
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
        }
        let epoch = EpochRow {
            epoch_number,
            tree_size,
            root: checkpoint.root_token(),
            sealed_at: sealed_at.to_owned(),
        };
        tree::put_entries(&tx, epoch_number, previous_size, &leaf_data)?;
        tx.execute(
            "INSERT INTO epochs(epoch_number, tree_size, root, sealed_at, note, published, epoch_bytes) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            (
                epoch_number as i64,
                tree_size as i64,
                &epoch.root,
                sealed_at,
                checkpoint.encode(),
                epoch_bytes as i64,
            ),
        )?;
        for r in records {
            exec_upsert_record(&tx, r, sealed_at)?;
        }
        for (domain, url, tip) in &chain_tips {
            exec_set_sealed_url_tip(&tx, url, domain, tip)?;
        }
        for d in declarations {
            exec_retain_declaration_seq(&tx, d.domain, d.seq)?;
            tx.execute(
                "INSERT INTO sealed_declarations(domain, seq, epoch_number, sealed_at, declaration_json) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(domain, seq) DO NOTHING",
                (
                    d.domain,
                    d.seq as i64,
                    epoch_number as i64,
                    sealed_at,
                    d.declaration_json,
                ),
            )?;
        }
        for c in param_changes {
            tx.execute(
                "INSERT INTO param_changes(parameter, value, effective_at, epoch_number, entry_index) VALUES (?1, ?2, ?3, ?4, ?5)",
                (c.parameter, c.value, c.effective_at, epoch_number as i64, c.entry_index),
            )?;
        }
        for w in withdrawals {
            tx.execute(
                "INSERT OR IGNORE INTO withdrawals(delta_id, domain, update_id, epoch_number, sealed_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                (w.delta_id, w.domain, w.update_id, epoch_number as i64, sealed_at),
            )?;
        }
        for identifier in suffix_lists {
            tx.execute(
                "INSERT INTO suffix_list_acts(epoch_number, sha256) VALUES (?1, ?2)",
                (epoch_number as i64, identifier),
            )?;
        }
        for row in labels {
            let label = row.label;
            tx.execute(
                "INSERT OR IGNORE INTO labels(label_id, labeler, subject, name, value, asserted_at, retracted, expires_at, delta, epoch_number, entry_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    row.label_id,
                    label.labeler,
                    label.subject,
                    label.name,
                    label.value,
                    label.asserted_at,
                    label.retracted == Some(true),
                    label.expires_at,
                    label.delta,
                    epoch_number as i64,
                    row.entry_index as i64,
                ],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO seen_labels(id, domain) VALUES (?1, ?2)",
                (row.label_id, &label.labeler),
            )?;
        }
        for row in disputes {
            let dispute = row.dispute;
            tx.execute(
                "INSERT OR IGNORE INTO disputes(dispute_id, label_id, disputant, reason, asserted_at, epoch_number, entry_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    row.dispute_id,
                    dispute.label,
                    dispute.disputant,
                    dispute.reason,
                    dispute.asserted_at,
                    epoch_number as i64,
                    row.entry_index as i64,
                ],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO seen_labels(id, domain) VALUES (?1, ?2)",
                (row.dispute_id, &dispute.disputant),
            )?;
        }
        tx.commit()?;
        Ok(epoch)
    }

    /// WIST-2 §3.3: a Label ID or Dispute ID the Log sealed or holds
    /// accepted for sealing is seen, exactly as a Delta ID is.
    pub fn is_label_seen_for(&self, id: &str, domain: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM seen_labels WHERE id = ?1 AND domain = ?2",
                (id, domain),
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn insert_seen_label(&self, id: &str, domain: &str) -> Result<()> {
        self.execute(
            "INSERT OR IGNORE INTO seen_labels(id, domain) VALUES (?1, ?2)",
            (id, domain),
        )?;
        Ok(())
    }

    pub fn sealed_label_subject(&self, label_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT subject FROM labels WHERE label_id = ?1",
                [label_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// WIST-2 §3.3, under §3.2's rules: accepted when `at` does not regress the
    /// retained observation.
    pub(crate) fn observe_label_feed_generated_at(&self, domain: &str, at: &str) -> Result<bool> {
        let at = crate::registry::unix(at)?;
        self.write(|conn| {
            Ok(conn
                .query_row(
                    "INSERT INTO label_feed_observations(domain, generated_at_s) VALUES (?1, ?2)
                     ON CONFLICT(domain) DO UPDATE SET generated_at_s = excluded.generated_at_s
                     WHERE excluded.generated_at_s >= label_feed_observations.generated_at_s
                     RETURNING generated_at_s",
                    rusqlite::params![domain, at],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .is_some())
        })
    }

    pub fn sealed_labels(&self) -> Result<Vec<wist_core::label::SealedLabel>> {
        let mut stmt = self.conn.prepare(
            "SELECT label_id, labeler, subject, name, value, asserted_at, retracted, expires_at, delta, epoch_number, entry_index FROM labels ORDER BY epoch_number, entry_index",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(wist_core::label::SealedLabel {
                    label: wist_core::objects::Label {
                        wist_version: crate::WIST_VERSION.to_string(),
                        labeler: row.get(1)?,
                        subject: row.get(2)?,
                        name: row.get(3)?,
                        value: row.get(4)?,
                        asserted_at: row.get(5)?,
                        retracted: row.get::<_, bool>(6)?.then_some(true),
                        expires_at: row.get(7)?,
                        delta: row.get(8)?,
                    },
                    label_id: row.get(0)?,
                    height: row.get::<_, i64>(9)?.max(0) as u64,
                    entry_index: row.get::<_, i64>(10)?.max(0) as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn sealed_disputes(&self) -> Result<Vec<wist_core::label::SealedDispute>> {
        let mut stmt = self.conn.prepare(
            "SELECT dispute_id, label_id, disputant, reason, asserted_at, epoch_number, entry_index FROM disputes ORDER BY epoch_number, entry_index",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(wist_core::label::SealedDispute {
                    dispute: wist_core::objects::Dispute {
                        wist_version: crate::WIST_VERSION.to_string(),
                        disputant: row.get(2)?,
                        label: row.get(1)?,
                        log: String::new(),
                        height: 0,
                        reason: row.get(3)?,
                        asserted_at: row.get(4)?,
                    },
                    dispute_id: row.get(0)?,
                    height: row.get::<_, i64>(5)?.max(0) as u64,
                    entry_index: row.get::<_, i64>(6)?.max(0) as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn store_suffix_list(&self, identifier: &str, octets: &[u8]) -> Result<()> {
        self.execute(
            "INSERT OR IGNORE INTO suffix_lists(sha256, octets) VALUES (?1, ?2)",
            (identifier, octets),
        )?;
        Ok(())
    }

    pub fn suffix_list_octets(&self, identifier: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT octets FROM suffix_lists WHERE sha256 = ?1",
                [identifier],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn suffix_list_bytes(&self, identifier: &str) -> Result<Option<u64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT length(octets) FROM suffix_lists WHERE sha256 = ?1",
                [identifier],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|n| n.max(0) as u64))
    }

    /// WIST-4 §3.1: only acts that changed the snapshot in force, in Log order.
    pub fn suffix_list_acts(&self) -> Result<Vec<(u64, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT epoch_number, sha256 FROM suffix_list_acts ORDER BY rowid")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?.max(0) as u64, row.get(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn suffix_list_row(
        &self,
        sql: &str,
        param: impl rusqlite::ToSql,
    ) -> Result<Option<(String, u64)>> {
        Ok(self
            .conn
            .query_row(sql, [param], |row| {
                Ok((row.get(0)?, row.get::<_, i64>(1)?.max(0) as u64))
            })
            .optional()?)
    }

    pub fn suffix_list_in_force_at(&self, at: &str) -> Result<Option<(String, u64)>> {
        self.suffix_list_row(
            "SELECT a.sha256, a.epoch_number FROM suffix_list_acts a JOIN epochs b ON b.epoch_number = a.epoch_number WHERE b.sealed_at <= ?1 ORDER BY a.rowid DESC LIMIT 1",
            at,
        )
    }

    pub fn suffix_list_in_force_at_epoch(
        &self,
        epoch_number: u64,
    ) -> Result<Option<(String, u64)>> {
        self.suffix_list_row(
            "SELECT sha256, epoch_number FROM suffix_list_acts WHERE epoch_number < ?1 ORDER BY rowid DESC LIMIT 1",
            epoch_number as i64,
        )
    }

    /// WIST-3 §7: the most recent act sealed at or below the Snapshot's Epoch.
    pub fn suffix_list_at_epoch(&self, epoch_number: u64) -> Result<Option<(String, u64)>> {
        self.suffix_list_row(
            "SELECT sha256, epoch_number FROM suffix_list_acts WHERE epoch_number <= ?1 ORDER BY rowid DESC LIMIT 1",
            epoch_number as i64,
        )
    }

    /// WIST-3 §7: each withdrawn Delta at the earliest Epoch that sealed a
    /// withdrawal of it.
    pub fn withdrawal_state(&self) -> Result<Vec<WithdrawalState>> {
        let mut stmt = self
            .conn
            .prepare("SELECT delta_id, domain, epoch_number FROM withdrawals ORDER BY delta_id")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn is_withdrawn(&self, delta_id: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM withdrawals WHERE delta_id = ?1)",
            [delta_id],
            |row| row.get(0),
        )?)
    }

    pub fn is_delta_sealed_for(&self, delta_id: &str, domain: &str) -> Result<bool> {
        if !self.is_delta_seen_for(delta_id, domain)? {
            return Ok(false);
        }
        let queued: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM queued_deltas WHERE delta_id = ?1 AND domain = ?2)",
            (delta_id, domain),
            |row| row.get(0),
        )?;
        if queued {
            return Ok(false);
        }
        let mut statement = self.conn.prepare(
            "SELECT entry_json FROM pending_entries WHERE entry_type = 'publisher_delta' AND domain = ?1",
        )?;
        let mut rows = statement.query([domain])?;
        while let Some(row) = rows.next()? {
            let doc: Value = crate::json::parse(&row.get::<_, Vec<u8>>(0)?)?;
            if wist_core::delta::delta_id(&doc["delta"])? == delta_id {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn bump_noise_ping(&self, domain: &str, day: &str) -> Result<()> {
        self.execute(
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
        self.execute(
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
        self.execute(
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
        self.execute("DELETE FROM records WHERE delta_id = ?1", [delta_id])?;
        Ok(())
    }

    pub fn largest_epoch_bytes(&self) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(epoch_bytes), 0) FROM epochs",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn parameter_schedule(
        &self,
        first_epoch_s: i64,
    ) -> Result<wist_core::parameters::Schedule> {
        let mut stmt = self.conn.prepare(
            "SELECT epoch_number, sealed_at, epoch_bytes FROM epochs ORDER BY epoch_number",
        )?;
        let epochs = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let first = epochs
            .first()
            .map(|b| crate::registry::unix(&b.1))
            .transpose()?
            .unwrap_or(first_epoch_s);
        let mut schedule = wist_core::parameters::Schedule::new(first);
        let mut stmt = self.conn.prepare(
            "SELECT parameter, value, epoch_number, entry_index, effective_at FROM param_changes ORDER BY epoch_number, entry_index",
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
        for (height, sealed_at, bytes) in epochs {
            largest = largest.max(bytes);
            let at = crate::registry::unix(&sealed_at)?;
            while changes.peek().is_some_and(|c| c.2 == height) {
                let (parameter, value, epoch_number, entry_index, effective_at) =
                    changes.next().unwrap();
                let amendment = wist_core::parameters::Amendment {
                    parameter,
                    value,
                    epoch_number,
                    entry_index,
                    sealed_at_s: at,
                    effective_at_s: crate::registry::unix(&effective_at)?,
                };
                let _ = crate::registry::accept(&mut schedule, amendment, largest);
            }
            if largest > schedule.epoch_size_bounds(at).0 {
                return Err(Error::Seal(format!(
                    "WIST3-E03 Epoch {height} exceeds the accepted size schedule"
                )));
            }
        }
        if changes.next().is_some() {
            return Err(Error::Seal(
                "parameter history names a missing Epoch".into(),
            ));
        }
        Ok(schedule)
    }

    pub fn latest_param_change(&self, name: &str, at: &str) -> Result<Option<i64>> {
        let at = crate::registry::unix(at)?;
        let schedule = self.parameter_schedule(at)?;
        Ok(schedule
            .accepted()
            .iter()
            .filter(|a| a.parameter == name && a.effective_at_s <= at)
            .max_by_key(|a| (a.effective_at_s, a.epoch_number, a.entry_index))
            .map(|a| a.value))
    }

    pub fn parameter_state(&self, at: &str) -> Result<Vec<(String, i64, String)>> {
        let at = crate::registry::unix(at)?;
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
                "SELECT url, publisher, delta_id, observed_at, title, abstract, lang, sealed_at FROM records WHERE url = ?1 AND publisher = ?2",
                (url, publisher),
                |row| {
                    Ok(RecordRow {
                        url: row.get(0)?,
                        publisher: row.get(1)?,
                        delta_id: row.get(2)?,
                        observed_at: row.get(3)?,
                        title: row.get(4)?,
                        abstract_text: row.get(5)?,
                        lang: row.get(6)?,
                        sealed_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Error::Db)
    }

    pub fn list_records(&self) -> Result<Vec<RecordRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT url, publisher, delta_id, observed_at, title, abstract, lang, sealed_at FROM records ORDER BY publisher, url",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(RecordRow {
                    url: row.get(0)?,
                    publisher: row.get(1)?,
                    delta_id: row.get(2)?,
                    observed_at: row.get(3)?,
                    title: row.get(4)?,
                    abstract_text: row.get(5)?,
                    lang: row.get(6)?,
                    sealed_at: row.get(7)?,
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

    pub fn list_url_tips(&self) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT domain, url, tip FROM url_tips ORDER BY domain, url")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_sealed_url_tips(&self) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT domain, url, tip FROM sealed_url_tips ORDER BY domain, url")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
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
        self.write(|conn| exec_set_url_tip(conn, url, domain, tip))
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
        self.execute(
            "INSERT INTO rejections(domain, code, at, delta_id, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            (domain, code, at, delta_id, detail),
        )?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const LOG_ID: &str = "log.example.org";

    pub(crate) fn signing_key() -> wist_core::crypto::SigningKey {
        wist_core::crypto::SigningKey::from_seed(&[7u8; 32])
    }

    pub(crate) fn seal_epoch(
        db: &Db,
        epoch_number: u64,
        sealed_at: &str,
        param_changes: &[ParamChangeRow],
    ) -> EpochRow {
        db.commit_seal(
            &signing_key(),
            LOG_ID,
            &[],
            epoch_number,
            sealed_at,
            &[],
            0,
            &[],
            param_changes,
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap()
    }

    fn test_declaration(seq: u64) -> Value {
        let key = wist_core::crypto::SigningKey::from_seed(&[1; 32]);
        let entry =
            wist_core::objects::PublisherKey::new(&key.public().to_b64u(), 1_767_225_600, None);
        let mut publisher = serde_json::json!({
            "wist_version": "1.0.0", "domain": "example.com", "seq": seq,
            "keys": [entry]
        });
        if seq > 0 {
            publisher["prev_declaration"] = crate::declaration::inner_hash(&test_declaration(0))
                .unwrap()
                .into();
        }
        wist_core::envelope::sign_envelope(&publisher, "publisher", &entry.kid, &key).unwrap()
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
        assert!(w.opened_epoch.is_none());
        assert!(w.window_end.is_none());
        assert_eq!(db.list_pending_recovery_windows().unwrap(), ["example.com"]);

        db.activate_recovery_window("example.com", 4, "2026-08-23T12:00:00Z")
            .unwrap();
        let w = db.get_recovery_window("example.com").unwrap().unwrap();
        assert_eq!(w.opened_epoch, Some(4));
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
    fn a_run_table_naming_its_disposition_noise_is_reopened_with_the_column_renamed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let mut run = db
            .start_pull_run(&NewRun {
                domain: "a.example",
                now: "2026-08-09T12:00:00Z",
                day: "2026-08-09",
                unit: "a.example",
                work_bytes: 1,
                work_objects: 1,
                pages_epoch: None,
            })
            .unwrap();
        run.ended = Some("WIST2-E01".to_string());
        db.update_pull_run(&run).unwrap();
        db.conn
            .execute_batch("ALTER TABLE pull_runs RENAME COLUMN ended TO noise")
            .unwrap();
        drop(db);

        let db = Db::open(&path).unwrap();
        assert_eq!(db.pull_run(run.run_id).unwrap(), Some(run));
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
    fn open_sets_wal_journal_full_synchronous_and_busy_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        let mode: String = db
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let synchronous: i64 = db
            .conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 2);
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
        db.set_param("epoch_cadence_seconds", 3600).unwrap();
        assert_eq!(db.param("epoch_cadence_seconds").unwrap(), 3600);
        db.set_param("epoch_cadence_seconds", 60).unwrap();
        assert_eq!(db.param("epoch_cadence_seconds").unwrap(), 60);
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
        seal_epoch(
            &db,
            0,
            "2026-01-01T00:00:00Z",
            &[ParamChangeRow {
                entry_index: 0,
                parameter: "feed_window",
                value: 500,
                effective_at: "2026-01-10T00:00:00Z",
            }],
        );
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
        seal_epoch(
            &db,
            1,
            "2026-01-02T00:00:00Z",
            &[ParamChangeRow {
                entry_index: 0,
                parameter: "feed_window",
                value: 800,
                effective_at: "2026-01-20T00:00:00Z",
            }],
        );
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
            &signing_key(),
            LOG_ID,
            &sealed,
            0,
            "2026-08-09T00:00:00Z",
            &[],
            0,
            &[RecordUpsert {
                url: "https://example.com/x",
                publisher: "example.com",
                delta_id: "sha256:a",
                observed_at: "2026-08-09T00:00:00Z",
                title: "t",
                abstract_text: None,
                lang: "en",
            }],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();

        let (drained, _) = db.peek_pending_entries().unwrap();
        assert!(drained.is_empty());
        assert_eq!(
            db.last_epoch().unwrap().unwrap().sealed_at,
            "2026-08-09T00:00:00Z"
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
    fn commit_seal_rolls_back_pending_delete_on_conflicting_epoch_number() {
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
            &signing_key(),
            LOG_ID,
            &sealed,
            0,
            "2026-08-09T00:00:00Z",
            &[],
            0,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
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
            &signing_key(),
            LOG_ID,
            &sealed2,
            0,
            "2026-08-09T00:01:00Z",
            &[],
            0,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
        );
        assert!(result.is_err());

        let (still_pending, _) = db.peek_pending_entries().unwrap();
        assert_eq!(still_pending.len(), 1);
        assert_eq!(still_pending[0].rowid, peeked2[0].rowid);
        assert_eq!(
            db.last_epoch().unwrap().unwrap().sealed_at,
            "2026-08-09T00:00:00Z"
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
