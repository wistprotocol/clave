use crate::db::{Db, Fence, SEALER_LEASE_SECONDS};
use crate::error::{Error, Result};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};
use wist_core::crypto::SigningKey;

mod merge;
mod prepare;
mod publish;
#[cfg(test)]
mod rejected_epoch_tests;
#[cfg(test)]
mod replan_tests;
#[cfg(test)]
mod retention_tests;
#[cfg(test)]
mod withdrawal_tests;

pub(crate) use prepare::validate_pending_parameter;

pub struct SealReport {
    pub epoch_number: u64,
    pub entry_count: u64,
    pub dropped: Vec<String>,
    /// Entries sealed past WIST-4 §5's inclusion ceiling, counted from
    /// the Epoch each one's turn arrived in.
    pub late: Vec<String>,
    pub replanned: usize,
    /// Per discarded plan, the publishers whose waiting state changed under it.
    pub conflicts: Vec<Vec<String>>,
    pub merged: Vec<String>,
    pub phases: Vec<(&'static str, Phase)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Phase {
    pub ms: u64,
    pub sqlite_ms: u64,
    pub rss_kb: u64,
    pub hwm_kb: u64,
}

pub const PHASES: [&str; 11] = [
    "catch_up",
    "planning",
    "lock_wait",
    "merge",
    "entries",
    "replay",
    "state",
    "commit",
    "publication",
    "retention",
    "witness",
];

impl SealReport {
    pub fn phases_json(&self) -> String {
        let fields: Vec<String> = self
            .phases
            .iter()
            .map(|(name, phase)| {
                format!(
                    "\"{name}\":{{\"ms\":{},\"sqlite_ms\":{},\"rss_kb\":{},\"hwm_kb\":{}}}",
                    phase.ms, phase.sqlite_ms, phase.rss_kb, phase.hwm_kb
                )
            })
            .collect();
        format!("{{{}}}", fields.join(","))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Step {
    CatchUp,
    Planning,
    LockWait,
    Merge,
    Entries,
    Replay,
    State,
    Commit,
    Publication,
    Retention,
    Witness,
}

#[derive(Debug, Default)]
pub(crate) struct Timings {
    spent: [(Duration, u64); PHASES.len()],
    memory: [(u64, u64); PHASES.len()],
}

impl Timings {
    pub(crate) fn time<T>(&mut self, step: Step, work: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let sqlite = crate::db::sqlite_nanos();
        let done = work();
        let (spent, sqlite_nanos) = &mut self.spent[step as usize];
        *spent += started.elapsed();
        *sqlite_nanos += crate::db::sqlite_nanos().saturating_sub(sqlite);
        self.memory[step as usize] = memory_kb();
        done
    }

    pub(crate) fn phases(&self) -> Vec<(&'static str, Phase)> {
        PHASES
            .iter()
            .zip(self.spent.iter().zip(&self.memory))
            .map(|(name, ((spent, sqlite_nanos), (rss_kb, hwm_kb)))| {
                (
                    *name,
                    Phase {
                        ms: u64::try_from(spent.as_millis()).unwrap_or(u64::MAX),
                        sqlite_ms: sqlite_nanos / 1_000_000,
                        rss_kb: *rss_kb,
                        hwm_kb: *hwm_kb,
                    },
                )
            })
            .collect()
    }
}

fn memory_kb() -> (u64, u64) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return (0, 0);
    };
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().strip_suffix("kB"))
            .and_then(|kb| kb.trim().parse().ok())
            .unwrap_or(0)
    };
    (field("VmRSS:"), field("VmHWM:"))
}

const PLAN_ATTEMPTS: usize = 3;
const EPOCH_CHANGED: &str = "<epoch>";
const LOCAL_BOUNDS_CHANGED: &str = "<local bounds>";

pub fn run(db: &Db, data_dir: &Path, sk: &SigningKey, now_unix: i64) -> Result<SealReport> {
    run_with_client(
        db,
        data_dir,
        sk,
        &crate::fetch::Client::new(false),
        now_unix,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseTerms {
    pub lease_seconds: i64,
    pub renewal: Duration,
}

impl Default for LeaseTerms {
    fn default() -> Self {
        LeaseTerms {
            lease_seconds: SEALER_LEASE_SECONDS,
            renewal: Duration::from_secs((SEALER_LEASE_SECONDS / 3) as u64),
        }
    }
}

/// Renewal runs on its own connection in a separate thread so a seal
/// longer than the lease keeps it.
pub(crate) fn under_renewed_lease<T>(
    db_path: &Path,
    owner: &str,
    token: i64,
    terms: LeaseTerms,
    work: impl FnOnce() -> T,
) -> T {
    let (stop, stopped) = mpsc::channel::<()>();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            crate::db::exclude_thread_from_counters();
            let Ok(db) = Db::connect(db_path) else {
                return;
            };
            while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(terms.renewal) {
                let now = jiff::Timestamp::now().as_second();
                if let Ok(false) = db.renew_sealer_lease(owner, token, now, terms.lease_seconds) {
                    return;
                }
            }
        });
        let done = work();
        drop(stop);
        done
    })
}

pub fn run_leased(
    db_path: &Path,
    data_dir: &Path,
    sk: &SigningKey,
    client: &crate::fetch::Client,
    now_unix: i64,
    owner: &str,
) -> Result<SealReport> {
    run_leased_with(
        db_path,
        data_dir,
        sk,
        client,
        now_unix,
        owner,
        LeaseTerms::default(),
    )
}

pub fn run_leased_with(
    db_path: &Path,
    data_dir: &Path,
    sk: &SigningKey,
    client: &crate::fetch::Client,
    now_unix: i64,
    owner: &str,
    terms: LeaseTerms,
) -> Result<SealReport> {
    let db = Db::connect(db_path)?;
    let now = jiff::Timestamp::now().as_second();
    let Some(token) = db.hold_sealer_lease_for(owner, now, terms.lease_seconds)? else {
        let lease = db.sealer_lease()?;
        return Err(Error::Seal(format!(
            "the sealer lease is held by {} until {}; stop that process or wait for its lease to lapse",
            lease.owner.as_deref().unwrap_or("another process"),
            crate::registry::instant(lease.lease_until)?
        )));
    };
    let db = db.fenced(Fence::Sealer { token });
    let sealed = under_renewed_lease(db_path, owner, token, terms, || {
        run_with_client(&db, data_dir, sk, client, now_unix)
    });
    let _ = db.release_sealer_lease(owner);
    sealed
}

pub fn run_with_client(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    client: &crate::fetch::Client,
    now_unix: i64,
) -> Result<SealReport> {
    run_confirming(db, data_dir, sk, client, now_unix, &mut HashSet::new())
}

/// WIST-3 §6.1: a Payload whose duty ended is no longer served; WIST-2 §5.3: a held Payload,
/// list or tree file nothing kept names is discarded. Files go after the rows that named them.
pub(crate) fn retain(db: &Db, data_dir: &Path, now: &str) -> Result<()> {
    db.end_lost_pull_runs()?;
    let held = held_payloads(data_dir)?;
    let scan = db.read_only(|| db.scan_retention(now, held))?;
    #[cfg(test)]
    hook::run(&hook::BETWEEN_RETENTION_SCAN_AND_WRITE);
    let mutation = db.mutation()?;
    let retained = db.apply_retention(now, scan)?;
    // An orphan is unlinked before the commit so that a pull reading the directory after it
    // finds no file to reuse and fetches the Payload again.
    for path in &retained.orphans {
        crate::db::remove_file(path)?;
    }
    mutation.commit()?;
    for item_id in &retained.ended {
        crate::db::remove_file(&crate::db::served_payload_path(data_dir, item_id)?)?;
    }
    Ok(())
}

fn held_payloads(data_dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    let entries = match std::fs::read_dir(data_dir.join("held/payloads")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut held = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let Some(hex) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        held.push((format!("sha256:{hex}"), path));
    }
    Ok(held)
}

pub(crate) fn run_confirming(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    client: &crate::fetch::Client,
    now_unix: i64,
    confirmed: &mut HashSet<String>,
) -> Result<SealReport> {
    let unconfirmed: Vec<String> = crate::mirrors::list(data_dir)?
        .into_iter()
        .filter(|url| !confirmed.contains(url))
        .collect();
    crate::publication::confirm_mirrors(db, data_dir, client, &unconfirmed)?;
    crate::publication::recover(db, data_dir)?;
    let report = seal_epoch(db, data_dir, sk, client, now_unix)?;
    confirmed.extend(unconfirmed);
    Ok(report)
}

struct PlanInputs {
    epoch: Option<u64>,
    versions: BTreeMap<String, i64>,
    local_bounds: Vec<Option<i64>>,
}

impl PlanInputs {
    fn read(db: &Db, scope: &BTreeSet<String>) -> Result<PlanInputs> {
        Ok(PlanInputs {
            epoch: db.last_epoch()?.map(|epoch| epoch.epoch_number),
            versions: db.waiting_versions(scope)?,
            local_bounds: crate::registry::LOCAL_BOUNDS
                .iter()
                .map(|name| crate::registry::local_bound(db, name))
                .collect::<Result<_>>()?,
        })
    }

    fn changed(&self, now: &PlanInputs) -> Vec<String> {
        let mut changed: Vec<String> = self
            .versions
            .iter()
            .filter(|(publisher, version)| now.versions.get(*publisher) != Some(version))
            .map(|(publisher, _)| publisher.clone())
            .collect();
        if self.epoch != now.epoch {
            changed.push(EPOCH_CHANGED.into());
        }
        if self.local_bounds != now.local_bounds {
            changed.push(LOCAL_BOUNDS_CHANGED.into());
        }
        changed
    }
}

// The genesis Epoch's preparation queues its amendments, a write, so it plans under the write lock.
fn seal_epoch(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    client: &crate::fetch::Client,
    now_unix: i64,
) -> Result<SealReport> {
    let mut timings = Timings::default();
    if db.last_epoch()?.is_none() {
        return seal_under_lock(db, data_dir, sk, client, now_unix, 0, timings);
    }
    timings.time(Step::CatchUp, || catch_up_history(db, data_dir))?;
    let mut conflicts = Vec::new();
    let event = timings.time(Step::Planning, || reserve(db))?;
    for replanned in 0..PLAN_ATTEMPTS {
        let (mut prepared, scope, planned) = timings.time(Step::Planning, || {
            db.read_only(|| {
                let prepared = prepare::epoch(db, data_dir, sk, now_unix, event)?;
                let scope = prepared.checked_scope();
                let planned = PlanInputs::read(db, &scope)?;
                Ok((prepared, scope, planned))
            })
        })?;
        #[cfg(test)]
        hook::run(&hook::BETWEEN_PLAN_AND_WRITE);
        let mutation = timings.time(Step::LockWait, || db.mutation())?;
        let merged = timings.time(Step::Merge, || -> Result<Option<Vec<String>>> {
            let changed = planned.changed(&PlanInputs::read(db, &scope)?);
            if changed.is_empty() {
                return Ok(Some(Vec::new()));
            }
            if changed
                .iter()
                .any(|name| name == EPOCH_CHANGED || name == LOCAL_BOUNDS_CHANGED)
            {
                conflicts.push(changed);
                return Ok(None);
            }
            match merge::into_current(db, data_dir, &mut prepared, &changed)? {
                merge::Merge::Done(publishers) => Ok(Some(publishers)),
                merge::Merge::Replan(reasons) => {
                    tracing::info!(?reasons, "the seal re-plans: its plan does not merge");
                    conflicts.push(changed);
                    Ok(None)
                }
            }
        })?;
        let Some(merged) = merged else {
            continue;
        };
        let mut report = publish::timed_epoch(db, data_dir, client, mutation, prepared, timings)?;
        report.replanned = replanned;
        report.conflicts = conflicts;
        report.merged = merged;
        return Ok(report);
    }
    let mut report = seal_under_lock(db, data_dir, sk, client, now_unix, PLAN_ATTEMPTS, timings)?;
    report.conflicts = conflicts;
    Ok(report)
}

fn reserve(db: &Db) -> Result<u64> {
    let mutation = db.mutation()?;
    let event = db.reserve_epoch_event(prepare::next_epoch_number(db)?)?;
    mutation.commit()?;
    Ok(event)
}

fn seal_under_lock(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    client: &crate::fetch::Client,
    now_unix: i64,
    replanned: usize,
    mut timings: Timings,
) -> Result<SealReport> {
    let mutation = timings.time(Step::LockWait, || db.mutation())?;
    let prepared = timings.time(Step::Planning, || {
        let event = db.reserve_epoch_event(prepare::next_epoch_number(db)?)?;
        prepare::epoch(db, data_dir, sk, now_unix, event)
    })?;
    let mut report = publish::timed_epoch(db, data_dir, client, mutation, prepared, timings)?;
    report.replanned = replanned;
    Ok(report)
}

fn catch_up_history(db: &Db, data_dir: &Path) -> Result<()> {
    let Some(head) = db.last_epoch()? else {
        return Ok(());
    };
    let derived = db.derived_declarations(&head)?.is_some();
    let recorded = db
        .sealed_page_sources_recorded()?
        .is_some_and(|recorded| recorded >= head.epoch_number);
    if derived && recorded {
        return Ok(());
    }
    let mutation = db.mutation()?;
    if !derived {
        crate::history::History::resume(db, data_dir)?;
    }
    crate::history::record_sealed_page_sources(db, data_dir)?;
    mutation.commit()
}

#[cfg(test)]
pub(crate) mod hook {
    use std::cell::RefCell;
    use std::thread::LocalKey;

    pub(crate) type Slot = RefCell<Option<Box<dyn FnMut()>>>;
    pub(crate) type Point = &'static LocalKey<Slot>;

    thread_local! {
        pub(crate) static BETWEEN_PLAN_AND_WRITE: Slot = const { RefCell::new(None) };
        pub(crate) static BETWEEN_RETENTION_SCAN_AND_WRITE: Slot = const { RefCell::new(None) };
    }

    pub(crate) fn set(point: Point, hook: impl FnMut() + 'static) {
        point.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn clear(point: Point) {
        point.with(|slot| slot.borrow_mut().take());
    }

    pub(super) fn run(point: Point) {
        let hook = point.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook();
            point.with(|slot| {
                slot.borrow_mut().get_or_insert(hook);
            });
        }
    }
}
