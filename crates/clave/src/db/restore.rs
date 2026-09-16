//! Restoration of derived columns and tables a reopened store may lack,
//! recomputed from the retained Log files and the store's own rows before
//! routine operations read them.
use super::{accepted_declaration_seq, exec_retain_declaration_seq, Db};
use crate::error::{Error, Result};
use crate::history::declarations::DeclarationsReplay;
use serde_json::Value;
use std::path::Path;

/// Runs every restoration in dependency order: Block sizes and parameter
/// amendments first, then the schedule, recovery owners, Declaration
/// floors and Delta indexes.
pub(super) fn run(db: &Db, path: &Path) -> Result<()> {
    db.restore_block_sizes(path)?;
    db.parameter_schedule(0)?;
    db.restore_recovery_owners(path)?;
    db.restore_declaration_floors(path)?;
    db.restore_delta_indexes(path)?;
    Ok(())
}

impl Db {
    pub(super) fn restore_declaration_floors(&self, path: &Path) -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let rows = tx
            .prepare("SELECT domain, declaration_json FROM publishers WHERE domain NOT IN (SELECT domain FROM declaration_floors) ORDER BY domain")?
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.is_empty() {
            tx.commit()?;
            return Ok(());
        }
        let head = self.last_block()?;
        let history = if head.is_some() {
            crate::history::declarations::Declarations::reconstruct(
                path.parent().unwrap_or_else(|| Path::new(".")),
                head,
            )?
        } else {
            crate::history::declarations::Declarations::default()
        };
        let pending = self.peek_pending_entries()?.0;
        for (domain, raw) in rows {
            let current: Value = crate::json::parse(&raw)?;
            let mut seq = accepted_declaration_seq(&domain, &current)?;
            if let Some(state) = history.domains().get(&domain) {
                seq = seq.max(state.highest_accepted_seq());
            }
            for entry in pending.iter().filter(|entry| {
                entry.domain == domain && entry.entry_type == "publisher_declaration"
            }) {
                seq = seq.max(accepted_declaration_seq(&domain, &entry.entry_json)?);
            }
            exec_retain_declaration_seq(&tx, &domain, seq)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(super) fn restore_recovery_owners(&self, path: &Path) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT domain, prior_declaration_json, opened_block FROM recovery_windows WHERE owner_declaration_json IS NULL ORDER BY domain",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<u64>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if rows.is_empty() {
            return Ok(());
        }
        let history = if rows.iter().any(|(_, _, opened)| opened.is_some()) {
            Some(crate::history::declarations::Declarations::reconstruct(
                path.parent().unwrap_or_else(|| Path::new(".")),
                self.last_block()?,
            )?)
        } else {
            None
        };
        let pending = self.peek_pending_entries()?.0;
        let tx = self.mutation()?;
        for (domain, prior, opened) in rows {
            let prior: Value = crate::json::parse(&prior)?;
            let unavailable = || {
                Error::History(format!(
                    "cannot restore the fixed recovery owner for {domain}"
                ))
            };
            let owner = if let Some(opened) = opened {
                let window = history
                    .as_ref()
                    .and_then(|state| state.domains().get(&domain))
                    .and_then(|state| state.window())
                    .ok_or_else(unavailable)?;
                if window.owner().position().block_number != opened
                    || *window.before().envelope() != prior
                {
                    return Err(unavailable());
                }
                window.owner().envelope().clone()
            } else {
                let mut candidates = Vec::new();
                for entry in &pending {
                    if entry.entry_type == "publisher_declaration"
                        && entry.domain == domain
                        && crate::declaration::evaluate(&prior, &entry.entry_json)
                            == Ok(crate::declaration::Decision::Recovery)
                        && !candidates.contains(&entry.entry_json)
                    {
                        candidates.push(entry.entry_json.clone());
                    }
                }
                if candidates.len() != 1 {
                    return Err(unavailable());
                }
                candidates.pop().unwrap()
            };
            tx.execute(
                "UPDATE recovery_windows SET owner_declaration_json = ?2 WHERE domain = ?1",
                (&domain, serde_json::to_vec(&owner)?),
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(super) fn restore_block_sizes(&self, path: &Path) -> Result<()> {
        let missing: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE decompressed_bytes IS NULL) OR EXISTS(SELECT 1 FROM param_changes WHERE entry_index IS NULL)",
            [], |row| row.get(0),
        )?;
        if !missing {
            return Ok(());
        }
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let anchor: Value = crate::json::parse(&std::fs::read(directory.join("anchor.json"))?)?;
        let public_key = anchor["anchor"]["genesis_key"]["public_key"]
            .as_str()
            .ok_or_else(|| Error::Key("stored Log Anchor has no genesis public key".into()))?;
        let key = wist_core::crypto::PublicKey::from_b64u(public_key)?;
        wist_core::envelope::verify_envelope(&anchor, "anchor", &key)?;
        let mut stmt = self.conn.prepare(
            "SELECT block_number, block_hash, sealed_at FROM blocks ORDER BY block_number",
        )?;
        let blocks = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let first = blocks
            .first()
            .map(|b| crate::registry::epoch(&b.2))
            .transpose()?
            .unwrap_or(0);
        let mut schedule = wist_core::parameters::Schedule::new(first);
        let mut largest = 0;
        let mut prior_at = None;
        let mut prior_hash = "sha256:genesis".to_string();
        let tx = self.mutation()?;
        for (index, (height, hash, sealed_at)) in blocks.into_iter().enumerate() {
            let bound = prior_at.map_or(
                crate::registry::spec("block_decompressed_cap_bytes")
                    .unwrap()
                    .default
                    .unwrap() as u64,
                |at| schedule.block_size_bounds(at).1,
            );
            let file = directory.join(format!("log/blocks/{height:09}.json.zst"));
            let bytes = crate::block_file::read(&file, bound).map_err(|error| match error {
                Error::History(message) => Error::Seal(message),
                error => error,
            })?;
            let block: Value = crate::json::parse(&bytes)?;
            wist_core::block::verify_block(&block, &key)?;
            wist_core::block::verify_chain_link(&block["header"], &prior_hash)?;
            if height != index as u64
                || block["header"]["block_number"] != height
                || block["header"]["sealed_at"] != sealed_at
                || wist_core::block::block_hash(&block["header"])? != hash
            {
                return Err(Error::Seal(
                    "stored Block does not match its history row".into(),
                ));
            }
            let at = crate::registry::epoch(&sealed_at)?;
            if prior_at.is_some_and(|prior| at <= prior) {
                return Err(Error::Seal(
                    "stored Block timestamps are not increasing".into(),
                ));
            }
            let canonical = wist_core::jcs::canonicalize(&block)?;
            let size = canonical.len() as u64;
            largest = largest.max(size);
            tx.execute(
                "DELETE FROM param_changes WHERE block_number = ?1",
                [height],
            )?;
            for (entry_index, entry) in block["entries"].as_array().unwrap().iter().enumerate() {
                let update = &entry["body"]["update"];
                if entry["type"] != "registry_update" || update["action"] != "parameter_change" {
                    continue;
                }
                wist_core::envelope::verify_envelope(&entry["body"], "update", &key)?;
                let Some(parameter) = update["details"]["parameter"].as_str() else {
                    continue;
                };
                let Some(value) = update["details"]["value"].as_i64() else {
                    continue;
                };
                let Some(effective_at) = update["effective_at"].as_str() else {
                    continue;
                };
                let Ok(effective_at_s) = crate::registry::epoch(effective_at) else {
                    continue;
                };
                let amendment = wist_core::parameters::Amendment {
                    parameter: parameter.into(),
                    value,
                    block_number: height,
                    entry_index: entry_index as u64,
                    sealed_at_s: at,
                    effective_at_s,
                };
                let _ = crate::registry::accept(&mut schedule, amendment, largest);
                tx.execute(
                    "INSERT INTO param_changes(parameter, value, effective_at, block_number, entry_index) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (parameter, value, effective_at, height, entry_index as u64),
                )?;
            }
            if largest > schedule.block_size_bounds(at).0 {
                return Err(Error::Seal(format!(
                    "WIST3-E03 Block {height} exceeds the accepted size schedule"
                )));
            }
            if bytes != canonical {
                use std::io::Write;
                let temporary = file.with_extension("zst.tmp");
                let compressed = zstd::bulk::compress(&canonical, zstd::DEFAULT_COMPRESSION_LEVEL)?;
                let mut output = std::fs::File::create(&temporary)?;
                output.write_all(&compressed)?;
                output.sync_all()?;
                std::fs::rename(&temporary, &file)?;
                std::fs::File::open(file.parent().unwrap())?.sync_all()?;
            }
            tx.execute(
                "UPDATE blocks SET decompressed_bytes = ?1 WHERE block_number = ?2",
                (size, height),
            )?;
            prior_at = Some(at);
            prior_hash = hash;
        }
        tx.commit()?;
        Ok(())
    }
}
