use crate::db::Db;
use crate::error::Result;
use std::path::Path;
use wist_core::crypto::SigningKey;

mod prepare;
mod publish;

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

/// Seals the next Epoch and distributes it, submitting its Checkpoint to
/// the configured Witnesses through `client`.
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
