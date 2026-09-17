//! WIST-4 §3.1: the Public Suffix List snapshot pinned in the Log by a
//! `suffix_list_update`, served at `/log/suffix-lists/<hex>.dat`, and the
//! Registrable Domain every quota, ingest budget and Block capacity is
//! keyed on under the snapshot in force.
use crate::db::Db;
use crate::error::{Error, Result};
use crate::WIST_VERSION;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use wist_core::crypto::SigningKey;
use wist_core::suffix_list::{self, SuffixList};

pub struct PinReport {
    pub identifier: String,
    pub bytes: u64,
    pub update_id: String,
}

pub fn file_path(data_dir: &Path, identifier: &str) -> PathBuf {
    let hex = identifier.strip_prefix("sha256:").unwrap_or(identifier);
    data_dir.join("log/suffix-lists").join(format!("{hex}.dat"))
}

/// Holds a snapshot's octets in the store and beside the Log, and queues
/// the `suffix_list_update` naming them for the next Block.
pub fn pin(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    file: &Path,
    now_epoch: i64,
) -> Result<PinReport> {
    let octets = std::fs::read(file)?;
    SuffixList::parse(&octets)
        .map_err(|e| Error::Governance(format!("{}: {e}", file.display())))?;
    let identifier = suffix_list::identifier(&octets);
    let path = file_path(data_dir, &identifier);
    std::fs::create_dir_all(path.parent().expect("suffix-list path has a parent"))?;
    let staged = path.with_extension("dat.tmp");
    std::fs::write(&staged, &octets)?;
    std::fs::rename(&staged, &path)?;
    db.store_suffix_list(&identifier, &octets)?;
    let effective_at = jiff::Timestamp::from_second(now_epoch)
        .map_err(|_| Error::Governance("timestamp out of range".into()))?
        .to_string();
    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "suffix_list_update",
        "subject": identifier,
        "details": {"sha256": identifier, "bytes": octets.len()},
        "effective_at": effective_at,
    });
    let update_id = crate::governance::enqueue(db, sk, update)?;
    Ok(PinReport {
        identifier,
        bytes: octets.len() as u64,
        update_id,
    })
}

static PARSED: Mutex<Vec<(String, Arc<SuffixList>)>> = Mutex::new(Vec::new());

fn load(db: &Db, identifier: &str) -> Result<Arc<SuffixList>> {
    let mut parsed = PARSED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, list)) = parsed.iter().find(|(id, _)| id == identifier) {
        return Ok(list.clone());
    }
    let octets = db.suffix_list_octets(identifier)?.ok_or_else(|| {
        Error::Governance(format!("suffix-list snapshot {identifier} is not held"))
    })?;
    let list = Arc::new(SuffixList::parse(&octets).map_err(|e| Error::Governance(e.to_string()))?);
    if parsed.len() >= 4 {
        parsed.remove(0);
    }
    parsed.push((identifier.to_string(), list.clone()));
    Ok(list)
}

/// The snapshot in force at the instant `at`: the one named by the most
/// recent accepted act sealed at or before it.
pub fn in_force_at(db: &Db, at: &str) -> Result<Option<Arc<SuffixList>>> {
    db.suffix_list_in_force_at(at)?
        .map(|(identifier, _)| load(db, &identifier))
        .transpose()
}

/// The snapshot in force at Block `block_number`: the one named by the
/// most recent accepted act sealed below it.
pub fn in_force_at_block(db: &Db, block_number: u64) -> Result<Option<Arc<SuffixList>>> {
    db.suffix_list_in_force_at_block(block_number)?
        .map(|(identifier, _)| load(db, &identifier))
        .transpose()
}

/// The accounting unit of a Canonical Host at the instant `at`.
pub fn unit_at(db: &Db, host: &str, at: &str) -> Result<String> {
    Ok(suffix_list::registrable_domain(host, in_force_at(db, at)?.as_deref()).domain)
}
