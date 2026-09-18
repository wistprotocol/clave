//! Restoration of derived columns and tables a reopened store may lack,
//! recomputed from the retained Log and the store's own rows before
//! routine operations read them.
use super::{accepted_declaration_seq, exec_retain_declaration_seq, Db};
use crate::error::{Error, Result};
use crate::history::declarations::DeclarationsReplay;
use serde_json::Value;
use std::path::Path;

/// Runs every restoration in dependency order: the parameter schedule
/// first, then recovery owners, Declaration floors and Delta indexes.
pub(super) fn run(db: &Db, path: &Path) -> Result<()> {
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
                self,
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
                self,
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
}
