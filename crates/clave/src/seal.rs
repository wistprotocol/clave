use crate::db::{Db, Fence, SEALER_LEASE_SECONDS};
use crate::error::{Error, Result};
use std::collections::HashSet;
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;
use wist_core::crypto::SigningKey;

mod prepare;
mod publish;
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
    let mutation = db.mutation()?;
    let prepared = prepare::epoch(db, data_dir, sk, now_unix)?;
    let report = publish::epoch(db, data_dir, client, mutation, prepared)?;
    confirmed.extend(unconfirmed);
    Ok(report)
}
