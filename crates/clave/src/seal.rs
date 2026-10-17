use crate::db::{Db, Fence, SEALER_LEASE_SECONDS};
use crate::error::{Error, Result};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;
use wist_core::crypto::SigningKey;

mod prepare;
mod publish;
#[cfg(test)]
mod rejected_epoch_tests;
#[cfg(test)]
mod replan_tests;
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
}

const PLAN_ATTEMPTS: usize = 3;

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
    let mutation = db.mutation()?;
    let lapsed = db.lapsed_payload_duties(now)?;
    for item_id in &lapsed {
        db.end_payload_duty(item_id)?;
    }
    let needed = db.payload_items_needed()?;
    let mut unneeded = Vec::new();
    match std::fs::read_dir(data_dir.join("held/payloads")) {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                let Some(hex) = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_suffix(".json"))
                else {
                    continue;
                };
                if !needed.contains(&format!("sha256:{hex}")) {
                    unneeded.push(path);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    db.discard_unkept_lists()?;
    db.discard_unnamed_tree_files()?;
    db.discard_unmarked_list_rows()?;
    for path in &unneeded {
        crate::db::remove_file(path)?;
    }
    mutation.commit()?;
    for item_id in &lapsed {
        crate::db::remove_file(&crate::db::served_payload_path(data_dir, item_id)?)?;
    }
    Ok(())
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
    clock: i64,
    versions: BTreeMap<String, i64>,
    local_bounds: Vec<Option<i64>>,
}

impl PlanInputs {
    fn read(db: &Db, scope: &BTreeSet<String>) -> Result<PlanInputs> {
        Ok(PlanInputs {
            epoch: db.last_epoch()?.map(|epoch| epoch.epoch_number),
            clock: db.acceptance_clock()?,
            versions: db.waiting_versions(scope)?,
            local_bounds: crate::registry::LOCAL_BOUNDS
                .iter()
                .map(|name| crate::registry::local_bound(db, name))
                .collect::<Result<_>>()?,
        })
    }

    fn changed(&self, now: &PlanInputs, advances_clock: bool) -> Vec<String> {
        let mut changed: Vec<String> = self
            .versions
            .iter()
            .filter(|(publisher, version)| now.versions.get(*publisher) != Some(version))
            .map(|(publisher, _)| publisher.clone())
            .collect();
        if self.epoch != now.epoch {
            changed.push("<epoch>".into());
        }
        if self.local_bounds != now.local_bounds {
            changed.push("<local bounds>".into());
        }
        if advances_clock && self.clock != now.clock {
            changed.push("<acceptance clock>".into());
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
    if db.last_epoch()?.is_none() {
        return seal_under_lock(db, data_dir, sk, client, now_unix, 0);
    }
    catch_up_history(db, data_dir)?;
    let mut conflicts = Vec::new();
    for replanned in 0..PLAN_ATTEMPTS {
        let (prepared, scope, planned) = db.read_only(|| {
            let prepared = prepare::epoch(db, data_dir, sk, now_unix)?;
            let scope = prepared.checked_scope();
            let planned = PlanInputs::read(db, &scope)?;
            Ok((prepared, scope, planned))
        })?;
        #[cfg(test)]
        between_plan_and_write::run();
        let mutation = db.mutation()?;
        let changed = planned.changed(&PlanInputs::read(db, &scope)?, prepared.advances_clock());
        if changed.is_empty() {
            let mut report = publish::epoch(db, data_dir, client, mutation, prepared)?;
            report.replanned = replanned;
            report.conflicts = conflicts;
            return Ok(report);
        }
        conflicts.push(changed);
    }
    let mut report = seal_under_lock(db, data_dir, sk, client, now_unix, PLAN_ATTEMPTS)?;
    report.conflicts = conflicts;
    Ok(report)
}

fn seal_under_lock(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    client: &crate::fetch::Client,
    now_unix: i64,
    replanned: usize,
) -> Result<SealReport> {
    let mutation = db.mutation()?;
    let prepared = prepare::epoch(db, data_dir, sk, now_unix)?;
    let mut report = publish::epoch(db, data_dir, client, mutation, prepared)?;
    report.replanned = replanned;
    Ok(report)
}

fn catch_up_history(db: &Db, data_dir: &Path) -> Result<()> {
    let Some(head) = db.last_epoch()? else {
        return Ok(());
    };
    if db.derived_declarations(&head)?.is_some() {
        return Ok(());
    }
    let mutation = db.mutation()?;
    crate::history::History::resume(db, data_dir)?;
    mutation.commit()
}

#[cfg(test)]
pub(crate) mod between_plan_and_write {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut()>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(crate) fn set(hook: impl FnMut() + 'static) {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn clear() {
        HOOK.with(|slot| slot.borrow_mut().take());
    }

    pub(super) fn run() {
        let hook = HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook();
            HOOK.with(|slot| {
                slot.borrow_mut().get_or_insert(hook);
            });
        }
    }
}
