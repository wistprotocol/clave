use super::Db;
use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pull_runs(run_id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, token INTEGER, now TEXT NOT NULL, day TEXT NOT NULL, unit TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('walk','labels','label_items','closing','aborted')), work_bytes INTEGER NOT NULL, work_objects INTEGER NOT NULL, discovered INTEGER NOT NULL DEFAULT 0, suspended INTEGER NOT NULL DEFAULT 0, pages_epoch INTEGER, queue_json BLOB NOT NULL DEFAULT '[]', position INTEGER NOT NULL DEFAULT 0, ended TEXT);
CREATE TABLE IF NOT EXISTS pull_objects(run_id INTEGER NOT NULL, kind TEXT NOT NULL, object_id TEXT NOT NULL, url TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('issued','fetched','verified','admitted','rejected','failed')), raw BLOB, byte_len INTEGER, debited INTEGER NOT NULL DEFAULT 0, unit TEXT, day TEXT, checks_json TEXT, refs_json TEXT, report TEXT, report_seq INTEGER, PRIMARY KEY(run_id, kind, object_id));
CREATE TABLE IF NOT EXISTS pull_walk(domain TEXT NOT NULL, feed TEXT NOT NULL CHECK(feed IN ('label')), idx INTEGER NOT NULL, url TEXT NOT NULL, generated_at TEXT NOT NULL, ids_json BLOB NOT NULL, next_url TEXT, raw BLOB, PRIMARY KEY(domain, feed, idx));
";

pub(super) fn create(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Walk,
    Labels,
    LabelItems,
    Closing,
    Aborted,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Walk => "walk",
            Phase::Labels => "labels",
            Phase::LabelItems => "label_items",
            Phase::Closing => "closing",
            Phase::Aborted => "aborted",
        }
    }

    fn parse(value: &str) -> Result<Phase> {
        Ok(match value {
            "walk" => Phase::Walk,
            "labels" => Phase::Labels,
            "label_items" => Phase::LabelItems,
            "closing" => Phase::Closing,
            "aborted" => Phase::Aborted,
            other => return Err(Error::History(format!("unknown pull phase {other}"))),
        })
    }
}

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

    pub(crate) fn is_final(self) -> bool {
        matches!(self, Status::Admitted | Status::Rejected)
    }
}

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
    pub discovered: bool,
    pub suspended: bool,
    pub pages_epoch: Option<u64>,
    pub queue: Vec<String>,
    pub position: usize,
    pub ended: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullObject {
    pub url: String,
    pub status: Status,
    pub raw: Option<Vec<u8>>,
    /// Octets: reserved while issued, debited once fetched.
    pub debited: u64,
    pub checks_json: Option<String>,
    pub refs_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WalkPage {
    pub url: String,
    pub generated_at: String,
    pub ids: Vec<String>,
    pub next_url: Option<String>,
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

pub(crate) enum Settled<'a> {
    Body(&'a [u8]),
    Bounded(u64),
    Failed(&'a str),
}

const RUN_COLUMNS: &str = "run_id, domain, now, day, unit, phase, work_bytes, work_objects, discovered, suspended, pages_epoch, queue_json, position, ended";

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
            discovered: row.get(8)?,
            suspended: row.get(9)?,
            pages_epoch: row.get::<_, Option<i64>>(10)?.map(|h| h.max(0) as u64),
            queue: Vec::new(),
            position: row.get::<_, i64>(12)?.max(0) as usize,
            ended: row.get(13)?,
        },
        row.get(5)?,
        row.get(11)?,
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

fn release_reservations(conn: &Connection, run_id: i64) -> Result<Vec<Credit>> {
    let credited = conn
        .prepare("SELECT COALESCE(object.unit, run.unit), COALESCE(object.day, run.day), SUM(object.debited) FROM pull_runs run JOIN pull_objects object ON object.run_id = run.run_id WHERE run.run_id = ?1 AND object.status = 'issued' GROUP BY COALESCE(object.unit, run.unit), COALESCE(object.day, run.day) HAVING SUM(object.debited) > 0")?
        .query_map([run_id], |row| {
            Ok(Credit {
                unit: row.get(0)?,
                day: row.get(1)?,
                bytes: row.get::<_, i64>(2)?.max(0) as u64,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    conn.execute(
        "INSERT INTO ingest_meter(domain, day, bytes) SELECT COALESCE(object.unit, run.unit), COALESCE(object.day, run.day), -SUM(object.debited) FROM pull_runs run JOIN pull_objects object ON object.run_id = run.run_id WHERE run.run_id = ?1 AND object.status = 'issued' GROUP BY COALESCE(object.unit, run.unit), COALESCE(object.day, run.day) ON CONFLICT(domain, day) DO UPDATE SET bytes = bytes + excluded.bytes",
        [run_id],
    )?;
    Ok(credited)
}

fn reservation_meter(
    conn: &Connection,
    run_id: i64,
    kind: &str,
    object_id: &str,
) -> Result<Option<(String, String)>> {
    Ok(conn
        .query_row(
            "SELECT COALESCE(object.unit, run.unit), COALESCE(object.day, run.day) FROM pull_objects object JOIN pull_runs run ON run.run_id = object.run_id WHERE object.run_id = ?1 AND object.kind = ?2 AND object.object_id = ?3",
            (run_id, kind, object_id),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

fn delete_run(conn: &Connection, run_id: i64) -> Result<Vec<Credit>> {
    let credited = release_reservations(conn, run_id)?;
    conn.execute("DELETE FROM pull_objects WHERE run_id = ?1", [run_id])?;
    conn.execute("DELETE FROM pull_runs WHERE run_id = ?1", [run_id])?;
    Ok(credited)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Credit {
    pub unit: String,
    pub day: String,
    pub bytes: u64,
}

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
    #[cfg(test)]
    pub(crate) fn start_pull_run(&self, run: &NewRun<'_>) -> Result<PullRun> {
        Ok(self.replace_pull_run(run)?.0)
    }

    /// WIST-2 §5: resumption is a later pull, and WIST-1 §3.4 gives a new
    /// attempt a new clock and schedule. The walk cursor outlives the run.
    pub(crate) fn replace_pull_run(&self, run: &NewRun<'_>) -> Result<(PullRun, Vec<Credit>)> {
        let tx = self.mutation()?;
        let token = self.fence.map(|fence| match fence {
            super::Fence::Partition { token, .. } | super::Fence::Sealer { token } => token,
        });
        let credited = match run_by(&tx, "domain = ?1", [run.domain])? {
            Some(open) => delete_run(&tx, open.run_id)?,
            None => Vec::new(),
        };
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
        Ok((started, credited))
    }

    pub(crate) fn pull_run(&self, run_id: i64) -> Result<Option<PullRun>> {
        run_by(&self.conn, "run_id = ?1", [run_id])
    }

    pub(crate) fn update_pull_run(&self, run: &PullRun) -> Result<()> {
        self.execute(
            "UPDATE pull_runs SET phase = ?2, work_bytes = ?3, work_objects = ?4, discovered = ?5, suspended = ?6, position = ?7, ended = ?8 WHERE run_id = ?1",
            rusqlite::params![
                run.run_id,
                run.phase.as_str(),
                run.work_bytes.min(i64::MAX as u64) as i64,
                run.work_objects,
                run.discovered,
                run.suspended,
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

    pub(crate) fn delete_pull_run(&self, run_id: i64) -> Result<Vec<Credit>> {
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
        let held = reservation_meter(&tx, run_id, kind, object_id)?
            .filter(|_| reserved > 0)
            .filter(|(held_unit, held_day)| held_unit != unit || held_day != day);
        tx.execute(
            "INSERT INTO pull_objects(run_id, kind, object_id, url, status, debited, unit, day) VALUES (?1, ?2, ?3, ?4, 'issued', ?5, ?6, ?7) ON CONFLICT(run_id, kind, object_id) DO UPDATE SET debited = excluded.debited, unit = excluded.unit, day = excluded.day",
            (run_id, kind, object_id, url, limit as i64, unit, day),
        )?;
        match held {
            Some((held_unit, held_day)) => {
                self.add_ingest_bytes(&held_unit, &held_day, -(reserved as i64))?;
                self.add_ingest_bytes(unit, day, limit as i64)?;
            }
            None => self.add_ingest_bytes(unit, day, limit as i64 - reserved as i64)?,
        }
        tx.commit()
    }

    #[cfg(test)]
    pub(crate) fn settle_pull_object(
        &self,
        run: &PullRun,
        kind: &str,
        object_id: &str,
        settled: Settled<'_>,
    ) -> Result<bool> {
        Ok(self
            .settle_pull_object_crediting(run, kind, object_id, settled)?
            .is_some())
    }

    pub(crate) fn settle_pull_object_crediting(
        &self,
        run: &PullRun,
        kind: &str,
        object_id: &str,
        settled: Settled<'_>,
    ) -> Result<Option<Credit>> {
        let tx = self.mutation()?;
        let Some(issued) = self
            .pull_object(run.run_id, kind, object_id)?
            .filter(|object| object.status == Status::Issued)
        else {
            return Ok(None);
        };
        let (unit, day) = reservation_meter(&tx, run.run_id, kind, object_id)?
            .ok_or_else(|| Error::History(format!("{kind} {object_id} lost its reservation")))?;
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
        self.add_ingest_bytes(&unit, &day, debited as i64 - issued.debited as i64)?;
        self.update_pull_run(run)?;
        tx.commit()?;
        Ok(Some(Credit {
            unit,
            day,
            bytes: issued.debited.saturating_sub(debited),
        }))
    }

    pub(crate) fn wake_deferred_resumes(&self, unit: &str, day: &str, now: i64) -> Result<usize> {
        let at = crate::registry::instant(now)?;
        if at.get(..10) != Some(day) {
            return Ok(0);
        }
        let budget = crate::registry::effective(self, "ingest_budget_bytes_day", &at)?;
        if budget - self.ingest_bytes(unit, day)? < crate::fetch::OBJECT_CAP_BYTES as i64 {
            return Ok(0);
        }
        let mut deferred = Vec::new();
        for partition in 0..super::PARTITIONS {
            deferred.extend(
                self.conn
                    .prepare_cached("SELECT domain FROM pull_schedule WHERE partition = ?1 AND reason = 'resume' AND due_at > ?2")?
                    .query_map((partition, now), |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        let mut woken = 0;
        for domain in deferred {
            if crate::suffix_list::unit_at(self, &domain, &at)? == unit {
                woken += self.execute(
                    "UPDATE pull_schedule SET due_at = ?2 WHERE domain = ?1 AND reason = 'resume' AND due_at > ?2",
                    (&domain, now),
                )?;
            }
        }
        Ok(woken)
    }

    pub(crate) fn walk_extent(&self, domain: &str, feed: &str, except: u32) -> Result<(u64, u64)> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(raw)), 0) FROM pull_walk WHERE domain = ?1 AND feed = ?2 AND idx != ?3",
            (domain, feed, except),
            |row| Ok((row.get::<_, i64>(0)?.max(0) as u64, row.get::<_, i64>(1)?.max(0) as u64)),
        )?)
    }

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
                    "UPDATE pull_objects SET status = ?4, checks_json = COALESCE(?5, checks_json), raw = CASE WHEN ?4 IN ('admitted', 'rejected') AND kind = 'label' THEN NULL ELSE raw END WHERE run_id = ?1 AND kind = ?2 AND object_id = ?3",
                    (run_id, kind, object_id, to.as_str(), checks),
                )?;
                true
            }
            _ => false,
        };
        tx.commit()?;
        Ok(moved)
    }

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
            "UPDATE pull_objects SET status = ?4, report = ?5, report_seq = (SELECT COALESCE(MAX(report_seq), 0) + 1 FROM pull_objects WHERE run_id = ?1), raw = CASE WHEN ?4 IN ('admitted', 'rejected') AND kind = 'label' THEN NULL ELSE raw END WHERE run_id = ?1 AND kind = ?2 AND object_id = ?3",
            (run_id, kind, object_id, status.as_str(), report),
        )?;
        tx.commit()
    }

    pub(crate) fn pull_report(&self, run_id: i64) -> Result<Vec<(String, String)>> {
        Ok(self
            .conn
            .prepare("SELECT object_id, report FROM pull_objects WHERE run_id = ?1 AND report_seq IS NOT NULL ORDER BY report_seq")?
            .query_map([run_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

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

    pub(crate) fn walk_pages(&self, domain: &str, feed: &str) -> Result<Vec<WalkPage>> {
        let rows = self
            .conn
            .prepare("SELECT url, generated_at, ids_json, next_url, raw FROM pull_walk WHERE domain = ?1 AND feed = ?2 ORDER BY idx")?
            .query_map((domain, feed), walk_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(page_of).collect()
    }

    pub(crate) fn trim_walk(&self, domain: &str, feed: &str, pages: u32) -> Result<()> {
        self.execute(
            "DELETE FROM pull_walk WHERE domain = ?1 AND feed = ?2 AND idx >= ?3",
            (domain, feed, pages),
        )?;
        Ok(())
    }

    pub(crate) fn clear_walk(&self, domain: &str, feed: &str) -> Result<()> {
        self.execute(
            "DELETE FROM pull_walk WHERE domain = ?1 AND feed = ?2",
            (domain, feed),
        )?;
        Ok(())
    }
}
