use super::{accepted_declaration_seq, exec_retain_declaration_seq, Db};
use crate::error::{Error, Result};
use crate::history::declarations::DeclarationsReplay;
use serde_json::Value;
use std::path::Path;

/// Runs in dependency order: each restoration may read what an earlier one
/// restored.
pub(super) fn run(db: &Db, path: &Path) -> Result<()> {
    db.parameter_schedule(0)?;
    db.restore_recovery_owners(path)?;
    db.restore_declaration_floors(path)?;
    db.restore_pull_schedule()
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
        let head = self.last_epoch()?;
        let history = if head.is_some() {
            crate::history::declarations::Declarations::reconstruct(
                self,
                path.parent().unwrap_or_else(|| Path::new(".")),
                head,
            )?
        } else {
            crate::history::declarations::Declarations::default()
        };
        for (domain, raw) in rows {
            let current: Value = crate::json::parse(&raw)?;
            let mut seq = accepted_declaration_seq(&domain, &current)?;
            if let Some(state) = history.domains().get(&domain) {
                seq = seq.max(state.highest_accepted_seq());
            }
            for envelope in self.discovered_declarations(&domain)? {
                seq = seq.max(accepted_declaration_seq(&domain, &envelope)?);
            }
            exec_retain_declaration_seq(&tx, &domain, seq)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(super) fn restore_recovery_owners(&self, path: &Path) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT domain, prior_declaration_json, opened_epoch FROM recovery_windows WHERE owner_declaration_json IS NULL ORDER BY domain",
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
                self.last_epoch()?,
            )?)
        } else {
            None
        };
        let at = match self.last_epoch()? {
            Some(head) => crate::registry::unix(&head.sealed_at)?,
            None => 0,
        };
        let limits = crate::declaration::limits(&self.parameter_schedule(at)?, at)?;
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
                if window.owner().position().epoch_number != opened
                    || *window.before().envelope() != prior
                {
                    return Err(unavailable());
                }
                window.owner().envelope().clone()
            } else {
                let mut candidates = Vec::new();
                for envelope in self.discovered_declarations(&domain)? {
                    if crate::declaration::evaluate(&prior, &envelope, &limits)
                        == Ok(crate::declaration::Decision::Recovery)
                        && !candidates.contains(&envelope)
                    {
                        candidates.push(envelope);
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
