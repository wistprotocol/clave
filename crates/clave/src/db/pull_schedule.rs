//! The durable pull schedule: one due-time row per domain waiting for a
//! pull and one leased task per pull in flight, both in Unix seconds.
use super::Db;
use crate::error::Result;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use rusqlite::{Connection, OptionalExtension};

/// How long a claimed pull stays owned before another dispatcher pass may
/// return it to the schedule; a running pull's lease is renewed while it
/// runs.
pub const LEASE_SECONDS: i64 = 600;
/// The delay after a pull's first consecutive failure; each further
/// failure doubles it, up to `baseline_poll_seconds`.
pub const RETRY_BASE_SECONDS: i64 = 60;

const SCHEMA: &str = "
CREATE TABLE pull_schedule(domain TEXT PRIMARY KEY, due_at INTEGER NOT NULL, reason TEXT NOT NULL CHECK(reason IN ('ping','baseline','resume','retry')), attempts INTEGER NOT NULL DEFAULT 0);
CREATE INDEX pull_schedule_due ON pull_schedule(due_at, domain);
CREATE INDEX pull_schedule_reason ON pull_schedule(reason, due_at, domain);
CREATE TABLE pull_tasks(domain TEXT PRIMARY KEY, reason TEXT NOT NULL CHECK(reason IN ('ping','baseline','resume','retry')), owner TEXT NOT NULL, lease_until INTEGER NOT NULL, issued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
CREATE INDEX pull_tasks_lease ON pull_tasks(lease_until);
";

const OLDEST_DUE_PING: &str = "SELECT domain, due_at, reason, attempts FROM pull_schedule WHERE reason = 'ping' AND due_at <= ?1 AND NOT EXISTS (SELECT 1 FROM pull_tasks WHERE pull_tasks.domain = pull_schedule.domain) ORDER BY due_at, domain LIMIT 1";
const OLDEST_DUE_DUTY: &str = "SELECT domain, due_at, reason, attempts FROM pull_schedule WHERE reason != 'ping' AND due_at <= ?1 AND NOT EXISTS (SELECT 1 FROM pull_tasks WHERE pull_tasks.domain = pull_schedule.domain) ORDER BY due_at, domain LIMIT 1";

/// Why a domain is due for a pull.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Ping,
    Baseline,
    Resume,
    Retry,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Ping => "ping",
            Reason::Baseline => "baseline",
            Reason::Resume => "resume",
            Reason::Retry => "retry",
        }
    }
}

impl FromSql for Reason {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value.as_str()? {
            "ping" => Ok(Reason::Ping),
            "baseline" => Ok(Reason::Baseline),
            "resume" => Ok(Reason::Resume),
            "retry" => Ok(Reason::Retry),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

/// A domain's pending pull: due at `due_at` for `reason`, after
/// `attempts` consecutive failed pulls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuePull {
    pub domain: String,
    pub due_at: i64,
    pub reason: Reason,
    pub attempts: i64,
}

/// A pull claimed for one dispatcher to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullTask {
    pub domain: String,
    pub reason: Reason,
    pub attempts: i64,
}

/// A pull in flight: its owner and the instant its lease lapses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullLease {
    pub owner: String,
    pub lease_until: i64,
    pub attempts: i64,
}

/// What a Ping's domain was admitted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingAdmission {
    /// A new Ping row now waits for a worker.
    Scheduled,
    /// The domain already waits or is being pulled; no new row was taken.
    Duplicate,
    /// Every Ping row the backlog allows is taken.
    Overloaded,
}

/// How a claimed pull ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullOutcome {
    /// The pull ran; `suspended` when the walk stopped at the budget or
    /// the pull's work limits.
    Pulled {
        suspended: bool,
    },
    Failed,
}

/// The row that results from scheduling `incoming` for a domain that
/// already has `existing`: the earlier due time, the `retry` reason over
/// every other and `resume` over `ping` and `baseline`, and between
/// `ping` and `baseline` the reason of the strictly earlier row, the
/// existing one on a tie. The failure count is the larger of the two.
pub fn merge(existing: &DuePull, incoming: &DuePull) -> DuePull {
    use Reason::*;
    let reason = match (existing.reason, incoming.reason) {
        (a, b) if a == b => a,
        (Retry, _) | (_, Retry) => Retry,
        (Resume, _) | (_, Resume) => Resume,
        _ if incoming.due_at < existing.due_at => incoming.reason,
        _ => existing.reason,
    };
    DuePull {
        domain: existing.domain.clone(),
        due_at: existing.due_at.min(incoming.due_at),
        reason,
        attempts: existing.attempts.max(incoming.attempts),
    }
}

fn due_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DuePull> {
    Ok(DuePull {
        domain: row.get(0)?,
        due_at: row.get(1)?,
        reason: row.get(2)?,
        attempts: row.get(3)?,
    })
}

fn scheduled(conn: &Connection, domain: &str) -> Result<Option<DuePull>> {
    Ok(conn
        .query_row(
            "SELECT domain, due_at, reason, attempts FROM pull_schedule WHERE domain = ?1",
            [domain],
            due_row,
        )
        .optional()?)
}

fn in_flight(conn: &Connection, domain: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM pull_tasks WHERE domain = ?1",
            [domain],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn schedule(conn: &Connection, incoming: &DuePull) -> Result<()> {
    let row = match scheduled(conn, &incoming.domain)? {
        Some(existing) => merge(&existing, incoming),
        None => incoming.clone(),
    };
    conn.execute(
        "INSERT INTO pull_schedule(domain, due_at, reason, attempts) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(domain) DO UPDATE SET due_at = excluded.due_at, reason = excluded.reason, attempts = excluded.attempts",
        (&row.domain, row.due_at, row.reason.as_str(), row.attempts),
    )?;
    Ok(())
}

/// Inserts a never-pulled publisher's baseline row, due at once, unless
/// the domain already waits or is being pulled.
pub(super) fn exec_schedule_new_publisher(conn: &Connection, domain: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO pull_schedule(domain, due_at, reason, attempts) SELECT ?1, 0, 'baseline', 0 WHERE NOT EXISTS (SELECT 1 FROM pull_tasks WHERE domain = ?1)",
        [domain],
    )?;
    Ok(())
}

fn return_tasks(
    conn: &Connection,
    filter: &str,
    params: impl rusqlite::Params,
    now: i64,
) -> Result<usize> {
    let tasks = conn
        .prepare(&format!(
            "SELECT domain, attempts FROM pull_tasks WHERE {filter}"
        ))?
        .query_map(params, |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (domain, attempts) in &tasks {
        conn.execute("DELETE FROM pull_tasks WHERE domain = ?1", [domain])?;
        schedule(
            conn,
            &DuePull {
                domain: domain.clone(),
                due_at: now,
                reason: Reason::Retry,
                attempts: *attempts,
            },
        )?;
    }
    Ok(tasks.len())
}

fn baseline_interval(db: &Db, now: i64) -> Result<i64> {
    crate::registry::effective(db, "baseline_poll_seconds", &crate::registry::instant(now)?)
}

impl Db {
    /// Creates the schedule on a store that lacks it and gives every
    /// known publisher its row: `resume` due at once for a suspended
    /// walk, otherwise `baseline` due `baseline_poll_seconds` after its
    /// last pull, or at once if it was never pulled.
    pub(super) fn restore_pull_schedule(&self) -> Result<()> {
        let tx = self.mutation()?;
        let present: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pull_schedule')",
            [],
            |row| row.get(0),
        )?;
        if present {
            return tx.commit();
        }
        tx.execute_batch(SCHEMA)?;
        let now = jiff::Timestamp::now().as_second();
        let interval = baseline_interval(self, now)?;
        let publishers = tx
            .prepare("SELECT p.domain, p.last_pull_at, COALESCE(w.suspended, 0) FROM publishers p LEFT JOIN walk_state w ON w.domain = p.domain")?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)? != 0,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (domain, last_pull_at, suspended) in publishers {
            let (due_at, reason) = if suspended {
                (0, Reason::Resume)
            } else {
                let pulled = last_pull_at.and_then(|at| crate::registry::unix(&at).ok());
                (pulled.map_or(0, |at| at + interval), Reason::Baseline)
            };
            schedule(
                &tx,
                &DuePull {
                    domain,
                    due_at,
                    reason,
                    attempts: 0,
                },
            )?;
        }
        tx.commit()
    }

    /// Admits a Ping for `domain` received at `now`. A domain that already
    /// waits has its row moved to `now` when that is earlier; a domain
    /// being pulled gets a Ping row the next pull starts from; neither
    /// takes a new backlog slot. Any other domain gets a `ping` row due
    /// at `now` unless `max_pending` Ping rows already wait.
    pub fn schedule_ping(
        &self,
        domain: &str,
        now: i64,
        max_pending: usize,
    ) -> Result<PingAdmission> {
        let tx = self.mutation()?;
        let ping = DuePull {
            domain: domain.to_string(),
            due_at: now,
            reason: Reason::Ping,
            attempts: 0,
        };
        let admission = if scheduled(&tx, domain)?.is_some() || in_flight(&tx, domain)? {
            PingAdmission::Duplicate
        } else {
            let waiting: i64 = tx.query_row(
                "SELECT COUNT(*) FROM pull_schedule WHERE reason = 'ping'",
                [],
                |row| row.get(0),
            )?;
            if waiting >= max_pending as i64 {
                return Ok(PingAdmission::Overloaded);
            }
            PingAdmission::Scheduled
        };
        schedule(&tx, &ping)?;
        tx.commit()?;
        Ok(admission)
    }

    /// Claims up to `slots` due pulls for `owner` at `now`, leasing each
    /// for `LEASE_SECONDS`, after returning every lapsed lease to the
    /// schedule. Claims alternate between the oldest due Ping row and the
    /// oldest due row of any other reason, starting with Pings when
    /// `ping_next` is set; a class with nothing due yields its turn. On
    /// return `ping_next` names the class the next claim starts with, so
    /// neither Pings nor scheduled duties wait behind the other.
    pub fn claim_pulls(
        &self,
        now: i64,
        slots: usize,
        owner: &str,
        ping_next: &mut bool,
    ) -> Result<Vec<PullTask>> {
        let tx = self.mutation()?;
        return_tasks(&tx, "lease_until <= ?1", [now], now)?;
        let mut claimed = Vec::new();
        while claimed.len() < slots {
            let order = if *ping_next {
                [OLDEST_DUE_PING, OLDEST_DUE_DUTY]
            } else {
                [OLDEST_DUE_DUTY, OLDEST_DUE_PING]
            };
            let mut next = None;
            for query in order {
                next = tx.query_row(query, [now], due_row).optional()?;
                if next.is_some() {
                    break;
                }
            }
            let Some(due) = next else {
                break;
            };
            *ping_next = due.reason != Reason::Ping;
            tx.execute("DELETE FROM pull_schedule WHERE domain = ?1", [&due.domain])?;
            tx.execute(
                "INSERT INTO pull_tasks(domain, reason, owner, lease_until, issued_at, attempts) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (&due.domain, due.reason.as_str(), owner, now + LEASE_SECONDS, now, due.attempts),
            )?;
            claimed.push(PullTask {
                domain: due.domain,
                reason: due.reason,
                attempts: due.attempts,
            });
        }
        tx.commit()?;
        Ok(claimed)
    }

    /// Extends the leases `owner` holds on `domains` to `LEASE_SECONDS`
    /// past `now` once less than half of a lease remains.
    pub fn renew_pull_leases(&self, domains: &[String], owner: &str, now: i64) -> Result<()> {
        let tx = self.mutation()?;
        for domain in domains {
            tx.execute(
                "UPDATE pull_tasks SET lease_until = ?3 WHERE domain = ?1 AND owner = ?2 AND lease_until < ?4",
                (domain, owner, now + LEASE_SECONDS, now + LEASE_SECONDS / 2),
            )?;
        }
        tx.commit()
    }

    /// Returns to the schedule, as `retry` due at `now`, every pull in
    /// flight that another owner holds or whose lease has lapsed; the
    /// pull is safe to run again because admission is transactional and
    /// deduplicates by Delta ID. Returns how many were returned.
    pub fn reclaim_pulls(&self, owner: &str, now: i64) -> Result<usize> {
        let tx = self.mutation()?;
        let returned = return_tasks(&tx, "owner != ?1 OR lease_until <= ?2", (owner, now), now)?;
        tx.commit()?;
        Ok(returned)
    }

    /// Ends `owner`'s pull of `task`, which started at `started_at`, and
    /// schedules the domain's next pull at `now`: after a failure `retry`
    /// with one more attempt, due after `RETRY_BASE_SECONDS` doubled per
    /// earlier consecutive failure and at most `baseline_poll_seconds`;
    /// after a suspended walk `resume`, due at once while the domain's
    /// daily ingest budget has room and at the next UTC day otherwise;
    /// after a completed walk `baseline`, due `baseline_poll_seconds`
    /// after `started_at`. A Ping row that arrived meanwhile is merged
    /// in. A domain that is no known publisher gets no next pull.
    pub fn complete_pull(
        &self,
        task: &PullTask,
        owner: &str,
        started_at: i64,
        outcome: PullOutcome,
        now: i64,
    ) -> Result<()> {
        let tx = self.mutation()?;
        tx.execute(
            "DELETE FROM pull_tasks WHERE domain = ?1 AND owner = ?2",
            (&task.domain, owner),
        )?;
        if self.get_publisher(&task.domain)?.is_none() {
            return tx.commit();
        }
        let interval = baseline_interval(self, now)?;
        let (due_at, reason, attempts) = match outcome {
            PullOutcome::Failed => {
                let attempts = task.attempts + 1;
                let backoff = RETRY_BASE_SECONDS
                    .checked_shl((attempts - 1).clamp(0, 32) as u32)
                    .unwrap_or(i64::MAX)
                    .min(interval);
                (now.saturating_add(backoff), Reason::Retry, attempts)
            }
            PullOutcome::Pulled { suspended: true } => {
                (self.resume_at(&task.domain, now)?, Reason::Resume, 0)
            }
            PullOutcome::Pulled { suspended: false } => {
                (started_at.saturating_add(interval), Reason::Baseline, 0)
            }
        };
        schedule(
            &tx,
            &DuePull {
                domain: task.domain.clone(),
                due_at,
                reason,
                attempts,
            },
        )?;
        tx.commit()
    }

    fn resume_at(&self, domain: &str, now: i64) -> Result<i64> {
        let at = crate::registry::instant(now)?;
        let day = at.get(..10).unwrap_or(&at);
        let unit = crate::suffix_list::unit_at(self, domain, &at)?;
        let budget = crate::registry::effective(self, "ingest_budget_bytes_day", &at)?;
        if self.ingest_bytes(&unit, day)? < budget {
            return Ok(now);
        }
        Ok(now - now.rem_euclid(86_400) + 86_400)
    }

    /// The pull `domain` waits for, if any.
    pub fn scheduled_pull(&self, domain: &str) -> Result<Option<DuePull>> {
        scheduled(&self.conn, domain)
    }

    /// The lease on `domain`'s pull in flight, if any.
    pub fn pull_lease(&self, domain: &str) -> Result<Option<PullLease>> {
        Ok(self
            .conn
            .query_row(
                "SELECT owner, lease_until, attempts FROM pull_tasks WHERE domain = ?1",
                [domain],
                |row| {
                    Ok(PullLease {
                        owner: row.get(0)?,
                        lease_until: row.get(1)?,
                        attempts: row.get(2)?,
                    })
                },
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn ts(unix: i64) -> String {
        jiff::Timestamp::from_second(unix).unwrap().to_string()
    }

    fn open_db() -> (tempfile::TempDir, Db) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        (tmp, db)
    }

    fn due(domain: &str, due_at: i64, reason: Reason, attempts: i64) -> DuePull {
        DuePull {
            domain: domain.into(),
            due_at,
            reason,
            attempts,
        }
    }

    fn plan(db: &Db, query: &str) -> String {
        let mut statement = db
            .conn
            .prepare(&format!("EXPLAIN QUERY PLAN {query}"))
            .unwrap();
        statement
            .query_map([NOW], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join("\n")
    }

    fn claim(db: &Db, slots: usize, ping_next: &mut bool) -> Vec<String> {
        db.claim_pulls(NOW, slots, "me", ping_next)
            .unwrap()
            .into_iter()
            .map(|task| task.domain)
            .collect()
    }

    #[test]
    fn claim_queries_search_the_due_indexes_instead_of_scanning() {
        let (_tmp, db) = open_db();
        let duty = plan(&db, OLDEST_DUE_DUTY);
        assert!(
            duty.contains("SEARCH pull_schedule USING INDEX pull_schedule_due (due_at<?)"),
            "{duty}"
        );
        let ping = plan(&db, OLDEST_DUE_PING);
        assert!(
            ping.contains(
                "SEARCH pull_schedule USING INDEX pull_schedule_reason (reason=? AND due_at<?)"
            ),
            "{ping}"
        );
        for plan in [duty, ping] {
            assert!(!plan.contains("SCAN"), "{plan}");
            assert!(!plan.contains("TEMP B-TREE"), "{plan}");
        }
    }

    #[test]
    fn a_ping_moves_a_baseline_earlier_but_never_later() {
        let later = due("a.example", NOW + 100, Reason::Baseline, 0);
        let ping = due("a.example", NOW, Reason::Ping, 0);
        assert_eq!(merge(&later, &ping), ping);
        let overdue = due("a.example", NOW - 100, Reason::Baseline, 0);
        assert_eq!(merge(&overdue, &ping), overdue);
    }

    #[test]
    fn retry_and_resume_are_never_downgraded_and_keep_their_attempts() {
        let retry = due("a.example", NOW + 100, Reason::Retry, 3);
        let ping = due("a.example", NOW, Reason::Ping, 0);
        assert_eq!(
            merge(&retry, &ping),
            due("a.example", NOW, Reason::Retry, 3)
        );
        let resume = due("a.example", NOW + 100, Reason::Resume, 0);
        assert_eq!(
            merge(&resume, &ping),
            due("a.example", NOW, Reason::Resume, 0)
        );
        let pinged = due("a.example", NOW - 5, Reason::Ping, 0);
        assert_eq!(
            merge(&pinged, &due("a.example", NOW, Reason::Resume, 0)),
            due("a.example", NOW - 5, Reason::Resume, 0)
        );
        assert_eq!(
            merge(&pinged, &due("a.example", NOW + 3600, Reason::Baseline, 0)),
            pinged
        );
    }

    #[test]
    fn restoring_seeds_never_pulled_stale_fresh_and_suspended_publishers() {
        let (_tmp, db) = open_db();
        for domain in ["never", "stale", "fresh", "suspended"] {
            db.insert_publisher(&format!("{domain}.example"), b"{}", "k", "p")
                .unwrap();
        }
        let now = jiff::Timestamp::now().as_second();
        db.set_publisher_pulled("stale.example", &ts(now - 90_000))
            .unwrap();
        db.set_publisher_pulled("fresh.example", &ts(now - 60))
            .unwrap();
        db.set_publisher_pulled("suspended.example", &ts(now - 60))
            .unwrap();
        db.set_walk_suspended("suspended.example", true).unwrap();
        db.set_param("baseline_poll_seconds", 3600).unwrap();
        db.conn
            .execute_batch("DROP TABLE pull_schedule; DROP TABLE pull_tasks;")
            .unwrap();
        db.restore_pull_schedule().unwrap();
        let row = |domain: &str| db.scheduled_pull(domain).unwrap().unwrap();
        assert_eq!(
            row("never.example"),
            due("never.example", 0, Reason::Baseline, 0)
        );
        assert_eq!(
            row("stale.example"),
            due("stale.example", now - 90_000 + 3600, Reason::Baseline, 0)
        );
        assert_eq!(
            row("fresh.example"),
            due("fresh.example", now - 60 + 3600, Reason::Baseline, 0)
        );
        assert_eq!(
            row("suspended.example"),
            due("suspended.example", 0, Reason::Resume, 0)
        );
        let mut ping_next = false;
        let mut claimed = db
            .claim_pulls(now, 10, "me", &mut ping_next)
            .unwrap()
            .into_iter()
            .map(|task| task.domain)
            .collect::<Vec<_>>();
        claimed.sort();
        assert_eq!(
            claimed,
            vec!["never.example", "stale.example", "suspended.example"]
        );

        db.conn.execute("DELETE FROM pull_tasks", []).unwrap();
        db.restore_pull_schedule().unwrap();
        assert_eq!(db.scheduled_pull("never.example").unwrap(), None);
    }

    #[test]
    fn a_new_publisher_is_due_at_once_unless_its_pull_is_in_flight() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due("a.example", 0, Reason::Baseline, 0))
        );
        assert_eq!(
            db.schedule_ping("b.example", NOW, 4).unwrap(),
            PingAdmission::Scheduled
        );
        assert_eq!(claim(&db, 2, &mut false), vec!["a.example", "b.example"]);
        db.insert_publisher("b.example", b"{}", "k", "p").unwrap();
        assert_eq!(db.scheduled_pull("b.example").unwrap(), None);
    }

    #[test]
    fn pings_dedup_against_waiting_and_in_flight_domains_and_respect_the_bound() {
        let (_tmp, db) = open_db();
        assert_eq!(
            db.schedule_ping("a.example", NOW, 2).unwrap(),
            PingAdmission::Scheduled
        );
        assert_eq!(
            db.schedule_ping("b.example", NOW, 2).unwrap(),
            PingAdmission::Scheduled
        );
        assert_eq!(
            db.schedule_ping("c.example", NOW, 2).unwrap(),
            PingAdmission::Overloaded
        );
        assert_eq!(db.scheduled_pull("c.example").unwrap(), None);
        assert_eq!(
            db.schedule_ping("a.example", NOW + 1, 2).unwrap(),
            PingAdmission::Duplicate
        );
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due("a.example", NOW, Reason::Ping, 0))
        );
        assert_eq!(claim(&db, 1, &mut true), vec!["a.example"]);
        assert_eq!(
            db.schedule_ping("c.example", NOW, 2).unwrap(),
            PingAdmission::Scheduled
        );
        assert_eq!(
            db.schedule_ping("a.example", NOW, 2).unwrap(),
            PingAdmission::Duplicate
        );
        assert!(db.pull_lease("a.example").unwrap().is_some());
        assert_eq!(
            claim(&db, 4, &mut true),
            vec!["b.example", "c.example"],
            "a domain in flight is not claimed twice"
        );
    }

    #[test]
    fn claims_never_exceed_the_free_slots() {
        let (_tmp, db) = open_db();
        for n in 0..5 {
            db.schedule_ping(&format!("{n}.example"), NOW, 10).unwrap();
        }
        assert!(claim(&db, 0, &mut true).is_empty());
        assert_eq!(claim(&db, 2, &mut true).len(), 2);
        assert_eq!(claim(&db, 2, &mut true).len(), 2);
        assert_eq!(claim(&db, 2, &mut true).len(), 1);
    }

    #[test]
    fn a_due_baseline_is_claimed_within_two_claims_under_saturated_pings() {
        let (_tmp, db) = open_db();
        db.insert_publisher("duty.example", b"{}", "k", "p")
            .unwrap();
        db.conn
            .execute(
                "UPDATE pull_schedule SET due_at = ?1 WHERE domain = 'duty.example'",
                [NOW - 10],
            )
            .unwrap();
        for n in 0..8 {
            db.schedule_ping(&format!("{n}.example"), NOW - 20 + n, 64)
                .unwrap();
        }
        let mut ping_next = true;
        assert_eq!(claim(&db, 1, &mut ping_next), vec!["0.example"]);
        assert_eq!(claim(&db, 1, &mut ping_next), vec!["duty.example"]);
        assert_eq!(claim(&db, 1, &mut ping_next), vec!["1.example"]);
    }

    #[test]
    fn scheduled_duties_do_not_starve_pings() {
        let (_tmp, db) = open_db();
        for n in 0..4 {
            db.insert_publisher(&format!("{n}.duty.example"), b"{}", "k", "p")
                .unwrap();
        }
        db.schedule_ping("pinged.example", NOW, 4).unwrap();
        assert_eq!(
            claim(&db, 2, &mut false),
            vec!["0.duty.example", "pinged.example"]
        );
    }

    #[test]
    fn a_successful_pull_is_next_due_one_baseline_interval_after_it_started() {
        let (_tmp, db) = open_db();
        db.set_param("baseline_poll_seconds", 3600).unwrap();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let task = db.claim_pulls(NOW, 1, "me", &mut false).unwrap().remove(0);
        db.complete_pull(
            &task,
            "me",
            NOW,
            PullOutcome::Pulled { suspended: false },
            NOW + 30,
        )
        .unwrap();
        assert_eq!(db.pull_lease("a.example").unwrap(), None);
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due("a.example", NOW + 3600, Reason::Baseline, 0))
        );
    }

    #[test]
    fn a_ping_during_a_pull_wins_when_earlier_than_the_next_baseline() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let task = db.claim_pulls(NOW, 1, "me", &mut false).unwrap().remove(0);
        assert_eq!(
            db.schedule_ping("a.example", NOW + 5, 0).unwrap(),
            PingAdmission::Duplicate
        );
        db.complete_pull(
            &task,
            "me",
            NOW,
            PullOutcome::Pulled { suspended: false },
            NOW + 30,
        )
        .unwrap();
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due("a.example", NOW + 5, Reason::Ping, 0))
        );
    }

    #[test]
    fn a_suspended_walk_is_due_at_once_as_resume_while_budget_remains() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let task = db.claim_pulls(NOW, 1, "me", &mut false).unwrap().remove(0);
        db.complete_pull(
            &task,
            "me",
            NOW,
            PullOutcome::Pulled { suspended: true },
            NOW + 30,
        )
        .unwrap();
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due("a.example", NOW + 30, Reason::Resume, 0))
        );
    }

    #[test]
    fn a_walk_suspended_on_a_spent_budget_resumes_at_the_next_utc_day() {
        let (_tmp, db) = open_db();
        db.set_param("ingest_budget_bytes_day", 10).unwrap();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        db.add_ingest_bytes("a.example", &ts(NOW)[..10], 10)
            .unwrap();
        let task = db.claim_pulls(NOW, 1, "me", &mut false).unwrap().remove(0);
        db.complete_pull(
            &task,
            "me",
            NOW,
            PullOutcome::Pulled { suspended: true },
            NOW,
        )
        .unwrap();
        let next_day = (NOW / 86_400 + 1) * 86_400;
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due("a.example", next_day, Reason::Resume, 0))
        );
    }

    #[test]
    fn failing_pulls_back_off_exponentially_up_to_the_baseline_interval_and_reset_on_success() {
        let (_tmp, db) = open_db();
        db.set_param("baseline_poll_seconds", 600).unwrap();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let mut now = NOW;
        for (attempts, backoff) in [(1, 60), (2, 120), (3, 240), (4, 480), (5, 600)] {
            let task = db.claim_pulls(now, 1, "me", &mut false).unwrap().remove(0);
            db.complete_pull(&task, "me", now, PullOutcome::Failed, now)
                .unwrap();
            assert_eq!(
                db.scheduled_pull("a.example").unwrap(),
                Some(due("a.example", now + backoff, Reason::Retry, attempts))
            );
            assert!(db
                .claim_pulls(now + backoff - 1, 1, "me", &mut false)
                .unwrap()
                .is_empty());
            now += backoff;
        }
        let task = db.claim_pulls(now, 1, "me", &mut false).unwrap().remove(0);
        db.complete_pull(
            &task,
            "me",
            now,
            PullOutcome::Pulled { suspended: false },
            now,
        )
        .unwrap();
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due("a.example", now + 600, Reason::Baseline, 0))
        );
    }

    #[test]
    fn a_pull_of_an_unknown_domain_schedules_nothing_after_it() {
        let (_tmp, db) = open_db();
        db.schedule_ping("unknown.example", NOW, 4).unwrap();
        let task = db.claim_pulls(NOW, 1, "me", &mut true).unwrap().remove(0);
        db.complete_pull(
            &task,
            "me",
            NOW,
            PullOutcome::Pulled { suspended: false },
            NOW,
        )
        .unwrap();
        assert_eq!(db.scheduled_pull("unknown.example").unwrap(), None);
        assert_eq!(db.pull_lease("unknown.example").unwrap(), None);
    }

    #[test]
    fn foreign_and_lapsed_leases_return_as_retry_due_at_once() {
        let (_tmp, db) = open_db();
        db.insert_publisher("mine.example", b"{}", "k", "p")
            .unwrap();
        db.insert_publisher("theirs.example", b"{}", "k", "p")
            .unwrap();
        claim(&db, 1, &mut false);
        db.claim_pulls(NOW, 1, "gone", &mut false).unwrap();
        assert_eq!(db.reclaim_pulls("me", NOW + 1).unwrap(), 1);
        assert_eq!(
            db.scheduled_pull("theirs.example").unwrap(),
            Some(due("theirs.example", NOW + 1, Reason::Retry, 0))
        );
        assert!(db.pull_lease("mine.example").unwrap().is_some());

        db.renew_pull_leases(&["mine.example".into()], "me", NOW + LEASE_SECONDS / 2 + 1)
            .unwrap();
        assert_eq!(
            db.pull_lease("mine.example").unwrap().unwrap().lease_until,
            NOW + LEASE_SECONDS + LEASE_SECONDS / 2 + 1
        );
        let lapsed = NOW + LEASE_SECONDS * 2;
        let claimed = db.claim_pulls(lapsed, 0, "me", &mut false).unwrap();
        assert!(claimed.is_empty());
        assert_eq!(db.pull_lease("mine.example").unwrap(), None);
        assert_eq!(
            db.scheduled_pull("mine.example").unwrap(),
            Some(due("mine.example", lapsed, Reason::Retry, 0))
        );
    }
}
