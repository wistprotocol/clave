use crate::db::Db;
use crate::error::Result;
use std::path::Path;
use wist_core::crypto::SigningKey;

pub fn build(
    _db: &Db,
    _data_dir: &Path,
    _sk: &SigningKey,
    _log_position: u64,
    _anchor_block_hash: &str,
    _snapshot_date: &str,
) -> Result<()> {
    Ok(())
}
