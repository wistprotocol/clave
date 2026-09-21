//! The persisted state of each pull in progress: one run per domain with
//! its phase, remaining work and item queue; every object the run fetched
//! with its status, its bytes and the references it was verified under;
//! the Declaration retries and predecessor retrievals it used; and, per
//! domain and walk, the pages walked so far. WIST-2 §5's resumption is a
//! later pull, so a run an interrupted pull left open is dropped, while
//! the walk cursor outlives it.
use super::Db;
use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pull_runs(run_id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, token INTEGER, now TEXT NOT NULL, day TEXT NOT NULL, unit TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('walk','deltas','labels','label_items','closing','aborted')), work_bytes INTEGER NOT NULL, work_objects INTEGER NOT NULL, feed_retry_used INTEGER NOT NULL DEFAULT 0, unseen_any INTEGER NOT NULL DEFAULT 0, suspended INTEGER NOT NULL DEFAULT 0, chain_pos INTEGER NOT NULL DEFAULT 0, pages_epoch INTEGER, queue_json BLOB NOT NULL DEFAULT '[]', position INTEGER NOT NULL DEFAULT 0, ended TEXT);
CREATE TABLE IF NOT EXISTS pull_objects(run_id INTEGER NOT NULL, kind TEXT NOT NULL, object_id TEXT NOT NULL, url TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('issued','fetched','verified','admitted','rejected','failed')), raw BLOB, byte_len INTEGER, debited INTEGER NOT NULL DEFAULT 0, checks_json TEXT, refs_json TEXT, report TEXT, report_seq INTEGER, PRIMARY KEY(run_id, kind, object_id));
CREATE TABLE IF NOT EXISTS pull_walk(domain TEXT NOT NULL, feed TEXT NOT NULL CHECK(feed IN ('feed','label')), idx INTEGER NOT NULL, url TEXT NOT NULL, generated_at TEXT NOT NULL, ids_json BLOB NOT NULL, next_url TEXT, raw BLOB, PRIMARY KEY(domain, feed, idx));
CREATE TABLE IF NOT EXISTS pull_attempts(run_id INTEGER NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('delta_refresh','resolved_prev')), id TEXT NOT NULL, PRIMARY KEY(run_id, kind, id));
";

pub(super) fn create(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

/// How far a run has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Declaration discovery and the Feed walk.
    Walk,
    /// The walked Delta IDs, in the run's queue.
    Deltas,
    /// The Label Feed walk.
    Labels,
    /// The walked Label and dispute IDs, in the run's queue.
    LabelItems,
    /// Every step ran; the run waits to be closed.
    Closing,
    /// The pull ended early at a recorded rejection.
    Aborted,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Walk => "walk",
            Phase::Deltas => "deltas",
            Phase::Labels => "labels",
            Phase::LabelItems => "label_items",
            Phase::Closing => "closing",
            Phase::Aborted => "aborted",
        }
    }

    fn parse(value: &str) -> Result<Phase> {
        Ok(match value {
            "walk" => Phase::Walk,
            "deltas" => Phase::Deltas,
            "labels" => Phase::Labels,
            "label_items" => Phase::LabelItems,
            "closing" => Phase::Closing,
            "aborted" => Phase::Aborted,
            other => return Err(Error::History(format!("unknown pull phase {other}"))),
        })
    }
}

/// Where a fetched object stands: its request issued with the budget
/// reserved, its response persisted, verified, admitted or rejected by
/// admission, or its request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Issued,
    Fetched,
    Verified,
    Admitted,
    Rejected,
    Failed,
}

impl Status {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Status::Issued => "issued",
            Status::Fetched => "fetched",
            Status::Verified => "verified",
            Status::Admitted => "admitted",
            Status::Rejected => "rejected",
            Status::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Status> {
        Ok(match value {
            "issued" => Status::Issued,
            "fetched" => Status::Fetched,
            "verified" => Status::Verified,
            "admitted" => Status::Admitted,
            "rejected" => Status::Rejected,
            "failed" => Status::Failed,
            other => {
                return Err(Error::History(format!(
                    "unknown pull object status {other}"
                )))
            }
        })
    }

    /// Whether admission is done with the object, so the next occurrence
    /// of its ID is a new attempt.
    pub(crate) fn is_final(self) -> bool {
        matches!(self, Status::Admitted | Status::Rejected)
    }
}

/// A run as its row records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullRun {
    pub run_id: i64,
    pub domain: String,
    pub now: String,
    pub day: String,
    pub unit: String,
    pub phase: Phase,
    pub work_bytes: u64,
    pub work_objects: u32,
    pub feed_retry_used: bool,
    pub unseen_any: bool,
    pub suspended: bool,
    pub chain_pos: i64,
    /// The height sealed Pages resolve their Key Sets at.
    pub pages_epoch: Option<u64>,
    pub queue: Vec<String>,
    pub position: usize,
    pub ended: Option<String>,
}

/// One object of a run as its row records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullObject {
    pub url: String,
    pub status: Status,
    pub raw: Option<Vec<u8>>,
    /// The bytes reserved while issued, and debited once fetched.
    pub debited: u64,
    pub checks_json: Option<String>,
    pub refs_json: Option<String>,
}

/// A page walked into a domain's cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WalkPage {
    pub url: String,
    pub generated_at: String,
    pub ids: Vec<String>,
    /// The target the page's `next` names under the target rule, if any.
    pub next_url: Option<String>,
    /// The Envelope octets the page was authenticated as; `None` in a store
    /// written before the cursor retained them.
    pub raw: Option<Vec<u8>>,
}

type WalkRow = (String, String, Vec<u8>, Option<String>, Option<Vec<u8>>);

fn walk_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WalkRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn page_of((url, generated_at, ids, next_url, raw): WalkRow) -> Result<WalkPage> {
    Ok(WalkPage {
        url,
        generated_at,
        ids: serde_json::from_slice(&ids)?,
        next_url,
        raw,
    })
}

/// How a fetch that was issued ended, as persisted.
pub(crate) enum Settled<'a> {
    Body(&'a [u8]),
    Bounded(u64),
    Failed(&'a str),
}

const RUN_COLUMNS: &str = "run_id, domain, now, day, unit, phase, work_bytes, work_objects, feed_retry_used, unseen_any, suspended, chain_pos, pages_epoch, queue_json, position, ended";

fn run_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(PullRun, String, String)> {
    Ok((
        PullRun {
            run_id: row.get(0)?,
            domain: row.get(1)?,
            now: row.get(2)?,
            day: row.get(3)?,
            unit: row.get(4)?,
            phase: Phase::Walk,
            work_bytes: row.get::<_, i64>(6)?.max(0) as u64,
            work_objects: row.get::<_, i64>(7)?.clamp(0, u32::MAX as i64) as u32,
            feed_retry_used: row.get(8)?,
            unseen_any: row.get(9)?,
            suspended: row.get(10)?,
            chain_pos: row.get(11)?,
            pages_epoch: row.get::<_, Option<i64>>(12)?.map(|h| h.max(0) as u64),
            queue: Vec::new(),
            position: row.get::<_, i64>(14)?.max(0) as usize,
            ended: row.get(15)?,
        },
        row.get(5)?,
        row.get(13)?,
    ))
}

fn run_by(conn: &Connection, filter: &str, key: impl rusqlite::Params) -> Result<Option<PullRun>> {
    let found = conn
        .query_row(
            &format!("SELECT {RUN_COLUMNS} FROM pull_runs WHERE {filter}"),
            key,
            run_row,
        )
        .optional()?;
    found
        .map(|(mut run, phase, queue)| {
            run.phase = Phase::parse(&phase)?;
            run.queue = serde_json::from_str(&queue)?;
            Ok(run)
        })
        .transpose()
}

fn release_reservations(conn: &Connection, run_id: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO ingest_meter(domain, day, bytes) SELECT run.unit, run.day, -SUM(object.debited) FROM pull_runs run JOIN pull_objects object ON object.run_id = run.run_id WHERE run.run_id = ?1 AND object.status = 'issued' GROUP BY run.unit, run.day ON CONFLICT(domain, day) DO UPDATE SET bytes = bytes + excluded.bytes",
        [run_id],
    )?;
    Ok(())
}

fn delete_run(conn: &Connection, run_id: i64) -> Result<()> {
    release_reservations(conn, run_id)?;
    conn.execute("DELETE FROM pull_objects WHERE run_id = ?1", [run_id])?;
    conn.execute("DELETE FROM pull_attempts WHERE run_id = ?1", [run_id])?;
    conn.execute("DELETE FROM pull_runs WHERE run_id = ?1", [run_id])?;
    Ok(())
}

/// The fresh run of a pull of `domain` at `now`.
pub(crate) struct NewRun<'a> {
    pub domain: &'a str,
    pub now: &'a str,
    pub day: &'a str,
    pub unit: &'a str,
    pub work_bytes: u64,
    pub work_objects: u32,
    pub pages_epoch: Option<u64>,
}

impl Db {
    /// Opens a fresh run of a pull of `run.domain`, dropping one an earlier
    /// pull left open and returning its unsettled reservations to the
    /// budget: WIST-2 §5's resumption is a later pull, and WIST-1 §3.4
    /// gives a new attempt a new clock and schedule. The walk cursor
    /// outlives the run.
    pub(crate) fn start_pull_run(&self, run: &NewRun<'_>) -> Result<PullRun> {
        let tx = self.mutation()?;
        let token = self.fence.map(|fence| match fence {
            super::Fence::Partition { token, .. } | super::Fence::Sealer { token } => token,
        });
        if let Some(open) = run_by(&tx, "domain = ?1", [run.domain])? {
            delete_run(&tx, open.run_id)?;
        }
        tx.execute(
            "INSERT INTO pull_runs(domain, token, now, day, unit, phase, work_bytes, work_objects, pages_epoch) VALUES (?1, ?2, ?3, ?4, ?5, 'walk', ?6, ?7, ?8)",
            (
                run.domain,
                token,
                run.now,
                run.day,
                run.unit,
                run.work_bytes.min(i64::MAX as u64) as i64,
                run.work_objects,
                run.pages_epoch.map(|h| h as i64),
            ),
        )?;
        let started = run_by(&tx, "domain = ?1", [run.domain])?
            .ok_or_else(|| Error::History("pull run lost after insertion".into()))?;
        tx.commit()?;
        Ok(started)
    }

    /// The run `run_id`, if it is still open.
    pub(crate) fn pull_run(&self, run_id: i64) -> Result<Option<PullRun>> {
        run_by(&self.conn, "run_id = ?1", [run_id])
    }

    /// Records `run`'s phase, remaining work, flags, position and `ended`,
    /// not its queue: rewriting that per item costs its length squared.
    pub(crate) fn update_pull_run(&self, run: &PullRun) -> Result<()> {
        self.execute(
            "UPDATE pull_runs SET phase = ?2, work_bytes = ?3, work_objects = ?4, feed_retry_used = ?5, unseen_any = ?6, suspended = ?7, chain_pos = ?8, position = ?9, ended = ?10 WHERE run_id = ?1",
            rusqlite::params![
                run.run_id,
                run.phase.as_str(),
                run.work_bytes.min(i64::MAX as u64) as i64,
                run.work_objects,
                run.feed_retry_used,
                run.unseen_any,
                run.suspended,
                run.chain_pos,
                run.position as i64,
                run.ended,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn set_pull_queue(&self, run: &PullRun) -> Result<()> {
        self.execute(
            "UPDATE pull_runs SET queue_json = ?2 WHERE run_id = ?1",
            rusqlite::params![run.run_id, serde_json::to_string(&run.queue)?],
        )?;
        Ok(())
    }

    /// Drops run `run_id` with its objects and attempts.
    pub(crate) fn delete_pull_run(&self, run_id: i64) -> Result<()> {
        self.write(|conn| delete_run(conn, run_id))
    }

    pub(crate) fn pull_object(
        &self,
        run_id: i64,
        kind: &str,
        object_id: &str,
    ) -> Result<Option<PullObject>> {
        self.conn
            .query_row(
                "SELECT url, status, raw, debited, checks_json, refs_json FROM pull_objects WHERE run_id = ?1 AND kind = ?2 AND object_id = ?3",
                (run_id, kind, object_id),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?
            .map(|(url, status, raw, debited, checks_json, refs_json)| {
                Ok(PullObject {
                    url,
                    status: Status::parse(&status)?,
                    raw,
                    debited: debited.max(0) as u64,
                    checks_json,
                    refs_json,
                })
            })
            .transpose()
    }

    /// The highest attempt number run `run_id` holds for the item `id` of
    /// `kind`, whose object IDs are `<id>#<attempt>`, with that attempt's
    /// status.
    pub(crate) fn latest_pull_attempt(
        &self,
        run_id: i64,
        kind: &str,
        id: &str,
    ) -> Result<Option<(u32, Status)>> {
        let rows = self
            .conn
            .prepare("SELECT object_id, status FROM pull_objects WHERE run_id = ?1 AND kind = ?2 AND object_id > ?3 AND object_id < ?4")?
            .query_map((run_id, kind, format!("{id}#"), format!("{id}$")), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut latest = None;
        for (object_id, status) in rows {
            let Some(attempt) = object_id
                .strip_prefix(id)
                .and_then(|rest| rest.strip_prefix('#'))
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if latest.is_none_or(|(n, _)| attempt > n) {
                latest = Some((attempt, Status::parse(&status)?));
            }
        }
        Ok(latest)
    }

    /// Records an object fetched outside the budget unless the run already
    /// holds it; returns whether it was recorded.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_pull_object(
        &self,
        run_id: i64,
        kind: &str,
        object_id: &str,
        url: &str,
        status: Status,
        raw: Option<&[u8]>,
        checks_json: Option<&str>,
    ) -> Result<bool> {
        Ok(self.execute(
            "INSERT OR IGNORE INTO pull_objects(run_id, kind, object_id, url, status, raw, byte_len, checks_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                run_id,
                kind,
                object_id,
                url,
                status.as_str(),
                raw,
                raw.map(|raw| raw.len() as i64),
                checks_json,
            ],
        )? == 1)
    }

    /// Issues a metered request: records the object as issued with `limit`
    /// bytes reserved in the budget of `unit` for `day`, or moves an
    /// issued object's reservation to `limit`, in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reserve_pull_object(
        &self,
        run_id: i64,
        kind: &str,
        object_id: &str,
        url: &str,
        unit: &str,
        day: &str,
        limit: u64,
    ) -> Result<()> {
        let tx = self.mutation()?;
        let reserved = match self.pull_object(run_id, kind, object_id)? {
            Some(object) if object.status == Status::Issued => object.debited,
            Some(_) => {
                return Err(Error::History(format!(
                    "{kind} {object_id} was fetched before it was issued"
                )))
            }
            None => 0,
        };
        tx.execute(
            "INSERT INTO pull_objects(run_id, kind, object_id, url, status, debited) VALUES (?1, ?2, ?3, ?4, 'issued', ?5) ON CONFLICT(run_id, kind, object_id) DO UPDATE SET debited = excluded.debited",
            (run_id, kind, object_id, url, limit as i64),
        )?;
        self.add_ingest_bytes(unit, day, limit as i64 - reserved as i64)?;
        tx.commit()
    }

    /// Persists how an issued metered request ended and settles its
    /// reservation to the bytes actually debited, with `run`'s remaining
    /// work, in one transaction. Returns `false`, writing nothing, when
    /// the object is no longer issued, as when the same result is
    /// delivered twice.
    pub(crate) fn settle_pull_object(
        &self,
        run: &PullRun,
        kind: &str,
        object_id: &str,
        settled: Settled<'_>,
    ) -> Result<bool> {
        let tx = self.mutation()?;
        let Some(issued) = self
            .pull_object(run.run_id, kind, object_id)?
            .filter(|object| object.status == Status::Issued)
        else {
            return Ok(false);
        };
        let (status, raw, debited, checks) = match settled {
            Settled::Body(raw) => (Status::Fetched, Some(raw), raw.len() as u64, None),
            Settled::Bounded(debited) => (Status::Failed, None, debited, None),
            Settled::Failed(detail) => (
                Status::Failed,
                None,
                0,
                Some(serde_json::json!({ "detail": detail }).to_string()),
            ),
        };
        tx.execute(
            "UPDATE pull_objects SET status = ?4, raw = ?5, byte_len = ?6, debited = ?7, checks_json = ?8 WHERE run_id = ?1 AND kind = ?2 AND object_id = ?3",
            rusqlite::params![
                run.run_id,
                kind,
                object_id,
                status.as_str(),
                raw,
                raw.map(|raw| raw.len() as i64),
                debited as i64,
                checks,
            ],
        )?;
        self.add_ingest_bytes(&run.unit, &run.day, debited as i64 - issued.debited as i64)?;
        self.update_pull_run(run)?;
        tx.commit()?;
        Ok(true)
    }

    /// Moves an object from one of `from` to `to`, recording `checks`
    /// when given; returns whether it moved.
    pub(crate) fn advance_pull_object(
        &self,
        run_id: i64,
        kind: &str,
        object_id: &str,
        from: &[Status],
        to: Status,
        checks: Option<&str>,
    ) -> Result<bool> {
        let tx = self.mutation()?;
        let moved = match self.pull_object(run_id, kind, object_id)? {
            Some(object) if from.contains(&object.status) => {
                tx.execute(
                    "UPDATE pull_objects SET status = ?4, checks_json = COALESCE(?5, checks_json) WHERE run_id = ?1 AND kind = ?2 AND object_id = ?3",
                    (run_id, kind, object_id, to.as_str(), checks),
                )?;
                true
            }
            _ => false,
        };
        tx.commit()?;
        Ok(moved)
    }

    /// Records the references an object's attempt was issued with.
    pub(crate) fn set_pull_object_refs(
        &self,
        run_id: i64,
        kind: &str,
        object_id: &str,
        refs_json: &str,
    ) -> Result<()> {
        self.execute(
            "UPDATE pull_objects SET refs_json = ?4 WHERE run_id = ?1 AND kind = ?2 AND object_id = ?3",
            (run_id, kind, object_id, refs_json),
        )?;
        Ok(())
    }

    /// Enters an object into the run's report as `report` — `accepted`,
    /// `queued`, `label` or a rejection code — after every entry before
    /// it, recording the row when the run holds none.
    pub(crate) fn report_pull_object(
        &self,
        run_id: i64,
        kind: &str,
        object_id: &str,
        status: Status,
        report: &str,
    ) -> Result<()> {
        let tx = self.mutation()?;
        tx.execute(
            "INSERT OR IGNORE INTO pull_objects(run_id, kind, object_id, url, status) VALUES (?1, ?2, ?3, '', ?4)",
            (run_id, kind, object_id, status.as_str()),
        )?;
        tx.execute(
            "UPDATE pull_objects SET status = ?4, report = ?5, report_seq = (SELECT COALESCE(MAX(report_seq), 0) + 1 FROM pull_objects WHERE run_id = ?1) WHERE run_id = ?1 AND kind = ?2 AND object_id = ?3",
            (run_id, kind, object_id, status.as_str(), report),
        )?;
        tx.commit()
    }

    /// The run's report entries in the order they were entered, each as
    /// the object ID and what it reports.
    pub(crate) fn pull_report(&self, run_id: i64) -> Result<Vec<(String, String)>> {
        Ok(self
            .conn
            .prepare("SELECT object_id, report FROM pull_objects WHERE run_id = ?1 AND report_seq IS NOT NULL ORDER BY report_seq")?
            .query_map([run_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Whether run `run_id` used the attempt `kind` for `id`.
    pub(crate) fn pull_attempted(&self, run_id: i64, kind: &str, id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM pull_attempts WHERE run_id = ?1 AND kind = ?2 AND id = ?3",
                (run_id, kind, id),
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub(crate) fn record_pull_attempt(&self, run_id: i64, kind: &str, id: &str) -> Result<()> {
        self.execute(
            "INSERT OR IGNORE INTO pull_attempts(run_id, kind, id) VALUES (?1, ?2, ?3)",
            (run_id, kind, id),
        )?;
        Ok(())
    }

    pub(crate) fn forget_pull_attempt(&self, run_id: i64, kind: &str, id: &str) -> Result<()> {
        self.execute(
            "DELETE FROM pull_attempts WHERE run_id = ?1 AND kind = ?2 AND id = ?3",
            (run_id, kind, id),
        )?;
        Ok(())
    }

    /// Page `idx` of `domain`'s `feed` walk, if walked.
    pub(crate) fn walk_page(&self, domain: &str, feed: &str, idx: u32) -> Result<Option<WalkPage>> {
        self.conn
            .query_row(
                "SELECT url, generated_at, ids_json, next_url, raw FROM pull_walk WHERE domain = ?1 AND feed = ?2 AND idx = ?3",
                (domain, feed, idx),
                walk_row,
            )
            .optional()?
            .map(page_of)
            .transpose()
    }

    pub(crate) fn record_walk_page(
        &self,
        domain: &str,
        feed: &str,
        idx: u32,
        page: &WalkPage,
    ) -> Result<()> {
        self.execute(
            "INSERT OR REPLACE INTO pull_walk(domain, feed, idx, url, generated_at, ids_json, next_url, raw) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                domain,
                feed,
                idx,
                page.url,
                page.generated_at,
                serde_json::to_vec(&page.ids)?,
                page.next_url,
                page.raw,
            ],
        )?;
        Ok(())
    }

    /// The pages `domain`'s `feed` walk holds, in walk order.
    pub(crate) fn walk_pages(&self, domain: &str, feed: &str) -> Result<Vec<WalkPage>> {
        let rows = self
            .conn
            .prepare("SELECT url, generated_at, ids_json, next_url, raw FROM pull_walk WHERE domain = ?1 AND feed = ?2 ORDER BY idx")?
            .query_map((domain, feed), walk_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(page_of).collect()
    }

    /// Drops the pages a walk that ended before `pages` left behind.
    pub(crate) fn trim_walk(&self, domain: &str, feed: &str, pages: u32) -> Result<()> {
        self.execute(
            "DELETE FROM pull_walk WHERE domain = ?1 AND feed = ?2 AND idx >= ?3",
            (domain, feed, pages),
        )?;
        Ok(())
    }

    /// Drops `domain`'s cursor for one walk, once the items it fed have
    /// been processed.
    pub(crate) fn clear_walk(&self, domain: &str, feed: &str) -> Result<()> {
        self.execute(
            "DELETE FROM pull_walk WHERE domain = ?1 AND feed = ?2",
            (domain, feed),
        )?;
        Ok(())
    }
}
