//! The durable pull schedule: one due-time row per domain waiting for a
//! pull and one leased task per pull in flight, both in Unix seconds.
//! Each domain belongs to one partition; a dispatcher claims due rows only
//! from partitions it holds, and each task records the partition token it
//! was claimed under.
use super::leases::{
    fence_holds, partition_of, Fence, PARTITION_LEASE_SECONDS, SEALER_LEASE_SECONDS,
};
use super::Db;
use crate::error::{Error, Result};
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use rusqlite::{Connection, OptionalExtension};

/// How long a claimed pull stays owned before a pass of the dispatcher
/// holding its partition may return it to the schedule; a running pull's
/// lease is renewed while it runs.
pub const LEASE_SECONDS: i64 = 600;
/// The delay after a pull's first consecutive failure; each further
/// failure doubles it, up to `baseline_poll_seconds`.
pub const RETRY_BASE_SECONDS: i64 = 60;

const SCHEMA: &str = "
CREATE TABLE pull_schedule(domain TEXT PRIMARY KEY, partition INTEGER NOT NULL, due_at INTEGER NOT NULL, reason TEXT NOT NULL CHECK(reason IN ('ping','baseline','resume','retry')), attempts INTEGER NOT NULL DEFAULT 0, pinged_at INTEGER);
CREATE TABLE pull_tasks(domain TEXT PRIMARY KEY, partition INTEGER NOT NULL, token INTEGER NOT NULL, reason TEXT NOT NULL CHECK(reason IN ('ping','baseline','resume','retry')), owner TEXT NOT NULL, lease_until INTEGER NOT NULL, issued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, pinged_at INTEGER);
";

const PARTITION_COLUMNS: &str = "
ALTER TABLE pull_schedule ADD COLUMN partition INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pull_tasks ADD COLUMN partition INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pull_tasks ADD COLUMN token INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pull_schedule ADD COLUMN pinged_at INTEGER;
ALTER TABLE pull_tasks ADD COLUMN pinged_at INTEGER;
DROP INDEX IF EXISTS pull_schedule_due;
DROP INDEX IF EXISTS pull_tasks_lease;
";

const INDEXES: &str = "
CREATE INDEX IF NOT EXISTS pull_schedule_reason ON pull_schedule(reason, due_at, domain);
CREATE INDEX IF NOT EXISTS pull_schedule_partition_due ON pull_schedule(partition, due_at, domain);
CREATE INDEX IF NOT EXISTS pull_schedule_partition_reason ON pull_schedule(partition, reason, due_at, domain);
CREATE INDEX IF NOT EXISTS pull_tasks_partition ON pull_tasks(partition, lease_until);
";

const OLDEST_DUE_PING: &str = "SELECT domain, due_at, reason, attempts, pinged_at FROM pull_schedule WHERE partition = ?2 AND reason = 'ping' AND due_at <= ?1 AND NOT EXISTS (SELECT 1 FROM pull_tasks WHERE pull_tasks.domain = pull_schedule.domain) ORDER BY due_at, domain";
const OLDEST_DUE_DUTY: &str = "SELECT domain, due_at, reason, attempts, pinged_at FROM pull_schedule WHERE partition = ?2 AND reason != 'ping' AND due_at <= ?1 AND NOT EXISTS (SELECT 1 FROM pull_tasks WHERE pull_tasks.domain = pull_schedule.domain) ORDER BY due_at, domain";

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
/// `attempts` consecutive failed pulls. `pinged_at` is the receipt
/// instant of the earliest Ping this pull serves, which WIST-2 §4 keys
/// the noise it may cost at; a pull no Ping asked for carries none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuePull {
    pub domain: String,
    pub due_at: i64,
    pub reason: Reason,
    pub attempts: i64,
    pub pinged_at: Option<i64>,
}

/// A pull claimed for one dispatcher to run under its hold on
/// `partition` at `token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullTask {
    pub domain: String,
    pub reason: Reason,
    pub attempts: i64,
    pub partition: i64,
    pub token: i64,
    /// The receipt instant of the earliest Ping this pull serves, if any.
    pub pinged_at: Option<i64>,
}

impl PullTask {
    /// The fence every write of this pull must pass.
    pub fn fence(&self) -> Fence {
        Fence::Partition {
            partition: self.partition,
            token: self.token,
        }
    }
}

/// A pull in flight: its owner, the instant its lease lapses and the
/// partition token it was claimed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullLease {
    pub owner: String,
    pub lease_until: i64,
    pub attempts: i64,
    pub token: i64,
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
/// existing one on a tie. The pull serves the earlier of the two Pings.
/// The failure count is the larger of the two, except that a Ping
/// arriving against a waiting `retry` row clears it: WIST-2 §7's
/// `WIST2-E01` row makes a fresh Ping cancel a pending backoff and start
/// a new attempt.
pub fn merge(existing: &DuePull, incoming: &DuePull) -> DuePull {
    use Reason::*;
    let reason = match (existing.reason, incoming.reason) {
        (a, b) if a == b => a,
        (Retry, _) | (_, Retry) => Retry,
        (Resume, _) | (_, Resume) => Resume,
        _ if incoming.due_at < existing.due_at => incoming.reason,
        _ => existing.reason,
    };
    let attempts = match (existing.reason, incoming.reason) {
        (Retry, Ping) => 0,
        _ => existing.attempts.max(incoming.attempts),
    };
    DuePull {
        domain: existing.domain.clone(),
        due_at: existing.due_at.min(incoming.due_at),
        reason,
        attempts,
        pinged_at: match (existing.pinged_at, incoming.pinged_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (at, None) | (None, at) => at,
        },
    }
}

fn due_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DuePull> {
    Ok(DuePull {
        domain: row.get(0)?,
        due_at: row.get(1)?,
        reason: row.get(2)?,
        attempts: row.get(3)?,
        pinged_at: row.get(4)?,
    })
}

fn scheduled(conn: &Connection, domain: &str) -> Result<Option<DuePull>> {
    Ok(conn
        .query_row(
            "SELECT domain, due_at, reason, attempts, pinged_at FROM pull_schedule WHERE domain = ?1",
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
        "INSERT INTO pull_schedule(domain, partition, due_at, reason, attempts, pinged_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(domain) DO UPDATE SET due_at = excluded.due_at, reason = excluded.reason, attempts = excluded.attempts, pinged_at = excluded.pinged_at",
        (
            &row.domain,
            partition_of(conn, &row.domain)?,
            row.due_at,
            row.reason.as_str(),
            row.attempts,
            row.pinged_at,
        ),
    )?;
    Ok(())
}

/// Inserts a never-pulled publisher's baseline row, due at once, unless
/// the domain already waits or is being pulled.
pub(super) fn exec_schedule_new_publisher(conn: &Connection, domain: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO pull_schedule(domain, partition, due_at, reason, attempts, pinged_at) SELECT ?1, ?2, 0, 'baseline', 0, NULL WHERE NOT EXISTS (SELECT 1 FROM pull_tasks WHERE domain = ?1)",
        (domain, partition_of(conn, domain)?),
    )?;
    Ok(())
}

/// Returns the tasks `filter` selects to the schedule as `retry` due at
/// `now`, leaving out every domain of `except`, whose pull is still
/// running under the caller and would otherwise be dispatched a second
/// time beside itself.
fn return_tasks(
    conn: &Connection,
    filter: &str,
    params: impl rusqlite::Params,
    except: &[String],
    now: i64,
) -> Result<usize> {
    let tasks = conn
        .prepare(&format!(
            "SELECT domain, attempts, pinged_at FROM pull_tasks WHERE {filter}"
        ))?
        .query_map(params, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|(domain, _, _)| !except.contains(domain))
        .collect::<Vec<_>>();
    for (domain, attempts, pinged_at) in &tasks {
        conn.execute("DELETE FROM pull_tasks WHERE domain = ?1", [domain])?;
        schedule(
            conn,
            &DuePull {
                domain: domain.clone(),
                due_at: now,
                reason: Reason::Retry,
                attempts: *attempts,
                pinged_at: *pinged_at,
            },
        )?;
    }
    Ok(tasks.len())
}

/// Renews every partition lease `owner` holds to `PARTITION_LEASE_SECONDS`
/// past `now`, then takes over unheld or lapsed partitions, lowest first,
/// until `owner` holds `max_partitions`. A takeover increments the
/// partition's token and returns every task claimed under an older one to
/// the schedule as `retry` due at `now`. Returns the partitions `owner`
/// holds with their tokens.
fn hold_partitions(
    conn: &Connection,
    owner: &str,
    max_partitions: usize,
    now: i64,
) -> Result<Vec<(i64, i64)>> {
    let until = now.saturating_add(PARTITION_LEASE_SECONDS);
    let renewed = conn.execute(
        "UPDATE pull_partitions SET lease_until = ?2 WHERE owner = ?1",
        (owner, until),
    )?;
    let room = max_partitions.saturating_sub(renewed);
    let free = conn
        .prepare("SELECT partition FROM pull_partitions WHERE owner IS NULL OR lease_until <= ?1 ORDER BY partition LIMIT ?2")?
        .query_map((now, room as i64), |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for partition in free {
        let token: i64 = conn.query_row(
            "UPDATE pull_partitions SET owner = ?2, lease_until = ?3, token = token + 1 WHERE partition = ?1 RETURNING token",
            (partition, owner, until),
            |row| row.get(0),
        )?;
        return_tasks(
            conn,
            "partition = ?1 AND token < ?2",
            (partition, token),
            &[],
            now,
        )?;
    }
    Ok(conn
        .prepare("SELECT partition, token FROM pull_partitions WHERE owner = ?1 AND lease_until > ?2 ORDER BY partition")?
        .query_map((owner, now), |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The oldest row `query` finds due at `now` in any of `partitions`,
/// ordered by due time and then domain, skipping every domain of
/// `running`, whose pull the caller has in flight.
fn oldest_due(
    conn: &Connection,
    query: &str,
    partitions: &[(i64, i64)],
    now: i64,
    running: &[String],
) -> Result<Option<(DuePull, i64, i64)>> {
    let mut statement = conn.prepare_cached(query)?;
    let mut oldest: Option<(DuePull, i64, i64)> = None;
    for &(partition, token) in partitions {
        let mut rows = statement.query((now, partition))?;
        while let Some(row) = rows.next()? {
            let due = due_row(row)?;
            if running.contains(&due.domain) {
                continue;
            }
            if oldest
                .as_ref()
                .is_none_or(|(o, _, _)| (due.due_at, &due.domain) < (o.due_at, &o.domain))
            {
                oldest = Some((due, partition, token));
            }
            break;
        }
    }
    Ok(oldest)
}

fn baseline_interval(db: &Db, now: i64) -> Result<i64> {
    crate::registry::effective(db, "baseline_poll_seconds", &crate::registry::instant(now)?)
}

impl Db {
    /// Creates the schedule on a store that lacks it and gives every
    /// known publisher its row: `resume` due at once for a suspended
    /// walk, otherwise `baseline` due `baseline_poll_seconds` after its
    /// last pull, or at once if it was never pulled. A schedule without
    /// partitions has each row assigned its domain's partition; its tasks
    /// carry token 0 and return to the schedule when their partition is
    /// first taken.
    pub(super) fn restore_pull_schedule(&self) -> Result<()> {
        let tx = self.mutation()?;
        let present: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pull_schedule')",
            [],
            |row| row.get(0),
        )?;
        if present {
            let partitioned: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('pull_schedule') WHERE name = 'partition')",
                [],
                |row| row.get(0),
            )?;
            if !partitioned {
                tx.execute_batch(PARTITION_COLUMNS)?;
                for table in ["pull_schedule", "pull_tasks"] {
                    let domains = tx
                        .prepare(&format!("SELECT domain FROM {table}"))?
                        .query_map([], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    for domain in domains {
                        tx.execute(
                            &format!("UPDATE {table} SET partition = ?2 WHERE domain = ?1"),
                            (&domain, partition_of(&tx, &domain)?),
                        )?;
                    }
                }
            }
            tx.execute_batch(INDEXES)?;
            return tx.commit();
        }
        tx.execute_batch(SCHEMA)?;
        tx.execute_batch(INDEXES)?;
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
                    pinged_at: None,
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
            pinged_at: Some(now),
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

    /// Re-takes, in one transaction, every partition lease and the sealer
    /// lease the store records under `owner`, incrementing each token so
    /// that any work an earlier incarnation of this instance left running
    /// is fenced out, and returning those partitions' tasks to the
    /// schedule as `retry` due at `now`. A process that starts under the
    /// name it ran under before therefore resumes its place at once
    /// instead of waiting for its own leases to lapse.
    pub fn reclaim_instance_leases(&self, owner: &str, now: i64) -> Result<()> {
        let tx = self.mutation()?;
        let partitions = tx
            .prepare("SELECT partition FROM pull_partitions WHERE owner = ?1 ORDER BY partition")?
            .query_map([owner], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for partition in partitions {
            tx.execute(
                "UPDATE pull_partitions SET lease_until = ?2, token = token + 1 WHERE partition = ?1",
                (partition, now.saturating_add(PARTITION_LEASE_SECONDS)),
            )?;
            return_tasks(&tx, "partition = ?1", [partition], &[], now)?;
        }
        tx.execute(
            "UPDATE sealer_lease SET lease_until = ?2, token = token + 1 WHERE id = 0 AND owner = ?1",
            (owner, now.saturating_add(SEALER_LEASE_SECONDS)),
        )?;
        tx.commit()
    }

    /// Claims up to `slots` due pulls for `owner` at `now`. First renews
    /// the partition leases `owner` holds and takes over unheld or lapsed
    /// ones up to `max_partitions`, returning the tasks a takeover fences
    /// out and every lapsed task of a held partition to the schedule.
    /// `running` names the domains `owner` has a pull in flight for: their
    /// tasks are neither returned nor claimed, since a lease that lapsed
    /// under a slow renewal names a pull that is still running here, and
    /// dispatching it again would run two pulls of one domain that both
    /// pass the partition's fence. Claims come only from partitions
    /// `owner` holds and alternate between the oldest due Ping row and the
    /// oldest due row of any other reason, starting with Pings when
    /// `ping_next` is set; a class with nothing due yields its turn. On
    /// return `ping_next` names the class the next claim starts with, so
    /// neither Pings nor scheduled duties wait behind the other.
    pub fn claim_pulls(
        &self,
        now: i64,
        slots: usize,
        owner: &str,
        max_partitions: usize,
        running: &[String],
        ping_next: &mut bool,
    ) -> Result<Vec<PullTask>> {
        let tx = self.mutation()?;
        let held = hold_partitions(&tx, owner, max_partitions, now)?;
        for &(partition, _) in &held {
            return_tasks(
                &tx,
                "partition = ?1 AND lease_until <= ?2",
                (partition, now),
                running,
                now,
            )?;
        }
        let mut claimed = Vec::new();
        while claimed.len() < slots {
            let order = if *ping_next {
                [OLDEST_DUE_PING, OLDEST_DUE_DUTY]
            } else {
                [OLDEST_DUE_DUTY, OLDEST_DUE_PING]
            };
            let mut next = None;
            for query in order {
                next = oldest_due(&tx, query, &held, now, running)?;
                if next.is_some() {
                    break;
                }
            }
            let Some((due, partition, token)) = next else {
                break;
            };
            *ping_next = due.reason != Reason::Ping;
            tx.execute("DELETE FROM pull_schedule WHERE domain = ?1", [&due.domain])?;
            tx.execute(
                "INSERT INTO pull_tasks(domain, partition, token, reason, owner, lease_until, issued_at, attempts, pinged_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                (&due.domain, partition, token, due.reason.as_str(), owner, now + LEASE_SECONDS, now, due.attempts, due.pinged_at),
            )?;
            claimed.push(PullTask {
                domain: due.domain,
                reason: due.reason,
                attempts: due.attempts,
                partition,
                token,
                pinged_at: due.pinged_at,
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

    /// Ends `owner`'s pull of `task`, which started at `started_at`, and
    /// schedules the domain's next pull at `now`: after a failure `retry`
    /// with one more attempt, due after `RETRY_BASE_SECONDS` doubled per
    /// earlier consecutive failure and at most `baseline_poll_seconds`;
    /// after a suspended walk `resume`, due at once while the domain's
    /// daily ingest budget has room and at the next UTC day otherwise;
    /// after a completed walk `baseline`, due `baseline_poll_seconds`
    /// after `started_at`. A Ping row that arrived meanwhile is merged
    /// in. A domain that is no known publisher gets no next pull. Once the
    /// task's partition has been taken over the pull is fenced out:
    /// nothing is written and `Error::Fenced` is returned, since the new
    /// holder has already scheduled the domain again.
    pub fn complete_pull(
        &self,
        task: &PullTask,
        owner: &str,
        started_at: i64,
        outcome: PullOutcome,
        now: i64,
    ) -> Result<()> {
        let tx = self.mutation()?;
        if !fence_holds(&tx, task.fence())? {
            return Err(Error::Fenced);
        }
        tx.execute(
            "DELETE FROM pull_tasks WHERE domain = ?1 AND owner = ?2 AND token = ?3",
            (&task.domain, owner, task.token),
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
                pinged_at: None,
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
                "SELECT owner, lease_until, attempts, token FROM pull_tasks WHERE domain = ?1",
                [domain],
                |row| {
                    Ok(PullLease {
                        owner: row.get(0)?,
                        lease_until: row.get(1)?,
                        attempts: row.get(2)?,
                        token: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::leases::PARTITIONS;

    const NOW: i64 = 1_800_000_000;
    const ALL: usize = PARTITIONS as usize;

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
            pinged_at: None,
        }
    }

    /// `due` for a row a Ping received at `pinged_at` asked for.
    fn pinged(domain: &str, due_at: i64, reason: Reason, attempts: i64, pinged_at: i64) -> DuePull {
        DuePull {
            pinged_at: Some(pinged_at),
            ..due(domain, due_at, reason, attempts)
        }
    }

    fn plan(db: &Db, query: &str) -> String {
        let mut statement = db
            .conn
            .prepare(&format!("EXPLAIN QUERY PLAN {query}"))
            .unwrap();
        statement
            .query_map((NOW, 0), |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join("\n")
    }

    fn claim(db: &Db, slots: usize, ping_next: &mut bool) -> Vec<String> {
        db.claim_pulls(NOW, slots, "me", ALL, &[], ping_next)
            .unwrap()
            .into_iter()
            .map(|task| task.domain)
            .collect()
    }

    #[test]
    fn claim_queries_search_a_partitions_due_indexes_instead_of_scanning() {
        let (_tmp, db) = open_db();
        let duty = plan(&db, OLDEST_DUE_DUTY);
        assert!(
            duty.contains(
                "SEARCH pull_schedule USING INDEX pull_schedule_partition_due (partition=? AND due_at<?)"
            ),
            "{duty}"
        );
        let ping = plan(&db, OLDEST_DUE_PING);
        assert!(
            ping.contains(
                "SEARCH pull_schedule USING INDEX pull_schedule_partition_reason (partition=? AND reason=? AND due_at<?)"
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
        let ping = pinged("a.example", NOW, Reason::Ping, 0, NOW);
        assert_eq!(merge(&later, &ping), ping);
        let overdue = due("a.example", NOW - 100, Reason::Baseline, 0);
        assert_eq!(
            merge(&overdue, &ping),
            pinged("a.example", NOW - 100, Reason::Baseline, 0, NOW)
        );
    }

    #[test]
    fn retry_and_resume_are_never_downgraded_and_a_ping_clears_a_pending_backoff() {
        let retry = due("a.example", NOW + 100, Reason::Retry, 3);
        let ping = pinged("a.example", NOW, Reason::Ping, 0, NOW);
        assert_eq!(
            merge(&retry, &ping),
            pinged("a.example", NOW, Reason::Retry, 0, NOW),
            "WIST-2 §7: a fresh Ping cancels a pending backoff and starts a new attempt"
        );
        let resume = due("a.example", NOW + 100, Reason::Resume, 0);
        assert_eq!(
            merge(&resume, &ping),
            pinged("a.example", NOW, Reason::Resume, 0, NOW)
        );
        let earlier = pinged("a.example", NOW - 5, Reason::Ping, 0, NOW - 5);
        assert_eq!(
            merge(&earlier, &due("a.example", NOW, Reason::Resume, 0)),
            pinged("a.example", NOW - 5, Reason::Resume, 0, NOW - 5)
        );
        assert_eq!(
            merge(&earlier, &due("a.example", NOW + 3600, Reason::Baseline, 0)),
            earlier
        );
    }

    #[test]
    fn a_pull_serves_the_earliest_ping_merged_into_its_row_and_no_other() {
        let first = pinged("a.example", NOW, Reason::Ping, 0, NOW);
        let later = pinged("a.example", NOW + 30, Reason::Ping, 0, NOW + 30);
        assert_eq!(merge(&first, &later).pinged_at, Some(NOW));
        assert_eq!(merge(&later, &first).pinged_at, Some(NOW));
        let baseline = due("a.example", NOW + 3600, Reason::Baseline, 0);
        assert_eq!(merge(&baseline, &later).pinged_at, Some(NOW + 30));
        assert_eq!(
            merge(&baseline, &due("a.example", NOW, Reason::Retry, 1)).pinged_at,
            None,
            "a pull no Ping asked for serves none"
        );
    }

    #[test]
    fn a_failed_pulls_retry_serves_no_ping_and_a_ping_meanwhile_is_the_one_it_serves() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        db.schedule_ping("a.example", NOW, 4).unwrap();
        let task = db
            .claim_pulls(NOW, 1, "me", ALL, &[], &mut true)
            .unwrap()
            .remove(0);
        assert_eq!(task.pinged_at, Some(NOW));
        db.complete_pull(&task, "me", NOW, PullOutcome::Failed, NOW + 1)
            .unwrap();
        assert_eq!(
            db.scheduled_pull("a.example").unwrap().unwrap().pinged_at,
            None
        );

        db.schedule_ping("a.example", NOW + 2, 4).unwrap();
        let retry = db
            .claim_pulls(NOW + 300, 1, "me", ALL, &[], &mut true)
            .unwrap()
            .remove(0);
        assert_eq!(retry.pinged_at, Some(NOW + 2));
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
            .claim_pulls(now, 10, "me", ALL, &[], &mut ping_next)
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
            Some(pinged("a.example", NOW, Reason::Ping, 0, NOW))
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
        let task = db
            .claim_pulls(NOW, 1, "me", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
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
        let task = db
            .claim_pulls(NOW, 1, "me", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
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
            Some(pinged("a.example", NOW + 5, Reason::Ping, 0, NOW + 5))
        );
    }

    #[test]
    fn a_suspended_walk_is_due_at_once_as_resume_while_budget_remains() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let task = db
            .claim_pulls(NOW, 1, "me", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
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
        let task = db
            .claim_pulls(NOW, 1, "me", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
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
            let task = db
                .claim_pulls(now, 1, "me", ALL, &[], &mut false)
                .unwrap()
                .remove(0);
            db.complete_pull(&task, "me", now, PullOutcome::Failed, now)
                .unwrap();
            assert_eq!(
                db.scheduled_pull("a.example").unwrap(),
                Some(due("a.example", now + backoff, Reason::Retry, attempts))
            );
            assert!(db
                .claim_pulls(now + backoff - 1, 1, "me", ALL, &[], &mut false)
                .unwrap()
                .is_empty());
            now += backoff;
        }
        let task = db
            .claim_pulls(now, 1, "me", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
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
        let task = db
            .claim_pulls(NOW, 1, "me", ALL, &[], &mut true)
            .unwrap()
            .remove(0);
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

    fn owners(db: &Db) -> Vec<Option<String>> {
        db.partition_leases()
            .unwrap()
            .into_iter()
            .map(|(_, lease)| lease.owner)
            .collect()
    }

    #[test]
    fn a_domains_partition_is_the_sha256_prefix_of_its_host_modulo_the_stores_count() {
        use sha2::{Digest, Sha256};
        let (_tmp, db) = open_db();
        assert_eq!(db.partition_leases().unwrap().len(), PARTITIONS as usize);
        for n in 0..64 {
            let domain = format!("{n}.example");
            let digest = Sha256::digest(domain.as_bytes());
            let prefix = u64::from_be_bytes(digest[..8].try_into().unwrap());
            assert_eq!(
                db.partition_of(&domain).unwrap(),
                (prefix % PARTITIONS as u64) as i64
            );
        }
    }

    #[test]
    fn two_dispatchers_split_the_partitions_and_never_claim_the_same_domain() {
        let (_tmp, db) = open_db();
        for n in 0..64 {
            db.schedule_ping(&format!("{n}.example"), NOW, 64).unwrap();
        }
        let half = ALL / 2;
        let mut claimed: std::collections::BTreeMap<String, &str> = Default::default();
        let (mut a_next, mut b_next) = (true, true);
        loop {
            let a = db.claim_pulls(NOW, 3, "a", half, &[], &mut a_next).unwrap();
            let b = db.claim_pulls(NOW, 3, "b", half, &[], &mut b_next).unwrap();
            if a.is_empty() && b.is_empty() {
                break;
            }
            for (owner, tasks) in [("a", a), ("b", b)] {
                for task in tasks {
                    let (partition, lease) = db
                        .partition_leases()
                        .unwrap()
                        .remove(task.partition as usize);
                    assert_eq!(partition, db.partition_of(&task.domain).unwrap());
                    assert_eq!(lease.owner.as_deref(), Some(owner));
                    assert_eq!(lease.token, task.token);
                    assert!(
                        claimed.insert(task.domain.clone(), owner).is_none(),
                        "{} was claimed twice",
                        task.domain
                    );
                }
            }
        }
        assert_eq!(claimed.len(), 64);
        let held = owners(&db);
        assert_eq!(
            held.iter().filter(|o| o.as_deref() == Some("a")).count(),
            half
        );
        assert_eq!(
            held.iter().filter(|o| o.as_deref() == Some("b")).count(),
            half
        );
        assert!(db
            .claim_pulls(NOW + 1, 1, "c", ALL, &[], &mut true)
            .unwrap()
            .is_empty());
        assert!(owners(&db).iter().all(|o| o.as_deref() != Some("c")));
    }

    #[test]
    fn a_dispatcher_takes_over_only_lapsed_partitions_and_returns_their_tasks_as_retry() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let old = db
            .claim_pulls(NOW, 1, "old", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
        let live = NOW + PARTITION_LEASE_SECONDS - 1;
        assert!(db
            .claim_pulls(live, 0, "new", ALL, &[], &mut false)
            .unwrap()
            .is_empty());
        assert!(owners(&db).iter().all(|o| o.as_deref() == Some("old")));
        assert_eq!(db.pull_lease("a.example").unwrap().unwrap().owner, "old");

        let lapsed = NOW + PARTITION_LEASE_SECONDS;
        db.claim_pulls(lapsed, 0, "new", ALL, &[], &mut false)
            .unwrap();
        assert!(owners(&db).iter().all(|o| o.as_deref() == Some("new")));
        assert_eq!(db.pull_lease("a.example").unwrap(), None);
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due("a.example", lapsed, Reason::Retry, 0))
        );
        let new = db
            .claim_pulls(lapsed, 1, "new", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
        assert_eq!(new.domain, "a.example");
        assert_eq!(new.token, old.token + 1);
    }

    #[test]
    fn a_stale_owners_completion_is_fenced_and_schedules_nothing() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let old = db
            .claim_pulls(NOW, 1, "old", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
        let lapsed = NOW + PARTITION_LEASE_SECONDS;
        db.claim_pulls(lapsed, 0, "new", ALL, &[], &mut false)
            .unwrap();
        let retry = db.scheduled_pull("a.example").unwrap();
        assert!(matches!(
            db.complete_pull(
                &old,
                "old",
                NOW,
                PullOutcome::Pulled { suspended: false },
                lapsed
            ),
            Err(Error::Fenced)
        ));
        assert_eq!(db.scheduled_pull("a.example").unwrap(), retry);

        let new = db
            .claim_pulls(lapsed, 1, "new", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
        assert!(matches!(
            db.complete_pull(&old, "old", NOW, PullOutcome::Failed, lapsed),
            Err(Error::Fenced)
        ));
        assert_eq!(db.scheduled_pull("a.example").unwrap(), None);
        assert_eq!(db.pull_lease("a.example").unwrap().unwrap().owner, "new");
        db.complete_pull(&new, "new", lapsed, PullOutcome::Failed, lapsed)
            .unwrap();
        assert_eq!(
            db.scheduled_pull("a.example").unwrap(),
            Some(due(
                "a.example",
                lapsed + RETRY_BASE_SECONDS,
                Reason::Retry,
                1
            ))
        );
    }

    #[test]
    fn a_fenced_connection_writes_only_while_its_partition_token_holds() {
        let (tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let task = db
            .claim_pulls(NOW, 1, "old", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
        let pull = Db::connect(&tmp.path().join("clave.sqlite"))
            .unwrap()
            .fenced(task.fence());
        pull.set_walk_suspended("a.example", true).unwrap();
        db.claim_pulls(
            NOW + PARTITION_LEASE_SECONDS,
            0,
            "new",
            ALL,
            &[],
            &mut false,
        )
        .unwrap();
        assert!(matches!(
            pull.set_walk_suspended("a.example", false),
            Err(Error::Fenced)
        ));
        assert!(matches!(
            pull.set_publisher_pulled("a.example", &ts(NOW)),
            Err(Error::Fenced)
        ));
        assert!(db.walk_suspended("a.example").unwrap());
        assert!(db
            .get_publisher_status("a.example")
            .unwrap()
            .unwrap()
            .last_pull_at
            .is_none());
    }

    #[test]
    fn a_lapsed_task_of_a_held_partition_returns_as_retry_and_a_renewed_one_stays() {
        let (_tmp, db) = open_db();
        db.insert_publisher("mine.example", b"{}", "k", "p")
            .unwrap();
        claim(&db, 1, &mut false);
        db.renew_pull_leases(&["mine.example".into()], "me", NOW + LEASE_SECONDS / 2 + 1)
            .unwrap();
        assert_eq!(
            db.pull_lease("mine.example").unwrap().unwrap().lease_until,
            NOW + LEASE_SECONDS + LEASE_SECONDS / 2 + 1
        );
        let renewed = NOW + LEASE_SECONDS + 1;
        db.claim_pulls(renewed, 0, "me", ALL, &[], &mut false)
            .unwrap();
        assert!(db.pull_lease("mine.example").unwrap().is_some());
        let lapsed = NOW + LEASE_SECONDS * 2;
        let claimed = db
            .claim_pulls(lapsed, 0, "me", ALL, &[], &mut false)
            .unwrap();
        assert!(claimed.is_empty());
        assert_eq!(db.pull_lease("mine.example").unwrap(), None);
        assert_eq!(
            db.scheduled_pull("mine.example").unwrap(),
            Some(due("mine.example", lapsed, Reason::Retry, 0))
        );
    }

    /// Two domains the store maps to one partition, so that a claim must
    /// look past the first of them rather than give the partition up.
    fn colliding_domains(db: &Db) -> (String, String) {
        let mut seen: std::collections::BTreeMap<i64, String> = Default::default();
        for n in 0.. {
            let domain = format!("{n}.example");
            let partition = db.partition_of(&domain).unwrap();
            if let Some(first) = seen.insert(partition, domain.clone()) {
                return (first, domain);
            }
        }
        unreachable!("the partition count is finite")
    }

    #[test]
    fn a_running_pulls_lapsed_task_is_neither_returned_nor_claimed_beside_itself() {
        let (_tmp, db) = open_db();
        let (mine, other) = colliding_domains(&db);
        for domain in [&mine, &other] {
            db.insert_publisher(domain, b"{}", "k", "p").unwrap();
        }
        let move_due = |domain: &str, due_at: i64| {
            db.conn
                .execute(
                    "UPDATE pull_schedule SET due_at = ?2 WHERE domain = ?1",
                    (domain, due_at),
                )
                .unwrap();
        };
        move_due(&mine, NOW);
        move_due(&other, NOW + 5);
        let task = db
            .claim_pulls(NOW, 1, "me", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
        assert_eq!(task.domain, mine);

        let lapsed = NOW + LEASE_SECONDS + 1;
        let running = [mine.clone()];
        let claimed = db
            .claim_pulls(lapsed, 4, "me", ALL, &running, &mut false)
            .unwrap();
        assert_eq!(
            claimed.iter().map(|task| &task.domain).collect::<Vec<_>>(),
            vec![&other],
            "the partition's other due domain is still claimed"
        );
        assert_eq!(db.scheduled_pull(&mine).unwrap(), None);
        let lease = db.pull_lease(&mine).unwrap().unwrap();
        assert_eq!(
            (lease.owner.as_str(), lease.token),
            ("me", task.token),
            "a pull still running here keeps its task at its token"
        );

        let ended = lapsed + 1;
        assert!(db
            .claim_pulls(ended, 0, "me", ALL, &[], &mut false)
            .unwrap()
            .is_empty());
        assert_eq!(db.pull_lease(&mine).unwrap(), None);
        assert_eq!(
            db.scheduled_pull(&mine).unwrap(),
            Some(due(&mine, ended, Reason::Retry, 0)),
            "a lapsed task no pull holds returns to the schedule"
        );
    }

    #[test]
    fn a_schedule_without_partitions_is_migrated_and_its_tasks_return_on_first_takeover() {
        let (tmp, db) = open_db();
        db.conn
            .execute_batch(
                "DROP TABLE pull_schedule; DROP TABLE pull_tasks;
                CREATE TABLE pull_schedule(domain TEXT PRIMARY KEY, due_at INTEGER NOT NULL, reason TEXT NOT NULL CHECK(reason IN ('ping','baseline','resume','retry')), attempts INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX pull_schedule_due ON pull_schedule(due_at, domain);
                CREATE INDEX pull_schedule_reason ON pull_schedule(reason, due_at, domain);
                CREATE TABLE pull_tasks(domain TEXT PRIMARY KEY, reason TEXT NOT NULL CHECK(reason IN ('ping','baseline','resume','retry')), owner TEXT NOT NULL, lease_until INTEGER NOT NULL, issued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX pull_tasks_lease ON pull_tasks(lease_until);
                INSERT INTO pull_schedule VALUES ('waiting.example', 5, 'baseline', 0);
                INSERT INTO pull_tasks VALUES ('running.example', 'ping', 'earlier', 9999999999, 1, 2);",
            )
            .unwrap();
        drop(db);
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        for (table, domain) in [
            ("pull_schedule", "waiting.example"),
            ("pull_tasks", "running.example"),
        ] {
            let partition: i64 = db
                .conn
                .query_row(
                    &format!("SELECT partition FROM {table} WHERE domain = ?1"),
                    [domain],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(partition, db.partition_of(domain).unwrap());
        }
        assert_eq!(db.pull_lease("running.example").unwrap().unwrap().token, 0);
        let plan = plan(&db, OLDEST_DUE_DUTY);
        assert!(plan.contains("pull_schedule_partition_due"), "{plan}");

        let mut claimed = claim(&db, 2, &mut false);
        claimed.sort();
        assert_eq!(claimed, vec!["running.example", "waiting.example"]);
        let lease = db.pull_lease("running.example").unwrap().unwrap();
        assert_eq!((lease.owner.as_str(), lease.attempts), ("me", 2));
    }

    #[test]
    fn released_partitions_are_taken_at_once_and_fence_the_releasers_pulls() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        let old = db
            .claim_pulls(NOW, 1, "old", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
        db.release_partitions("old").unwrap();
        assert!(owners(&db).iter().all(Option::is_none));
        let new = db
            .claim_pulls(NOW + 1, 1, "new", ALL, &[], &mut false)
            .unwrap()
            .remove(0);
        assert_eq!(new.domain, "a.example");
        assert_eq!(new.token, old.token + 1);
        assert!(matches!(
            db.complete_pull(&old, "old", NOW, PullOutcome::Failed, NOW + 1),
            Err(Error::Fenced)
        ));
    }
}
