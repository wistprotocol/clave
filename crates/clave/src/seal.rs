use crate::db::{Db, Fence, SEALER_LEASE_SECONDS};
use crate::error::{Error, Result};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;
use wist_core::crypto::SigningKey;

mod prepare;
mod publish;
#[cfg(test)]
mod withdrawal_tests;

pub(crate) use prepare::validate_pending_parameter;

pub(super) const ENTRY_TYPE_ORDER: [&str; 5] = [
    "publisher_declaration",
    "registry_update",
    "publisher_delta",
    "label",
    "dispute",
];

pub struct SealReport {
    pub epoch_number: u64,
    pub entry_count: u64,
    pub dropped: Vec<String>,
    /// Deltas sealed past WIST-4 §5's inclusion ceiling, counted from
    /// the Epoch each one's turn arrived in.
    pub late: Vec<String>,
}

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
    crate::publication::recover(db, data_dir)?;
    let mutation = db.mutation()?;
    let prepared = prepare::epoch(db, data_dir, sk, now_unix)?;
    publish::epoch(db, data_dir, client, mutation, prepared)
}
