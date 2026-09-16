use crate::db::Db;
use crate::declaration;
use crate::error::{Error, Result};
use crate::history::declarations::Declarations;
use crate::history::declarations::DeclarationsReplay;
use std::path::Path;

pub fn settle(db: &Db, data_dir: &Path, now: &str) -> Result<()> {
    let mutation = db.mutation()?;
    let history = Declarations::reconstruct(data_dir, db.last_block()?)?;
    settle_due(db, &history, now)?;
    mutation.commit()
}

pub(crate) fn settle_due(db: &Db, history: &Declarations, now: &str) -> Result<()> {
    let at = now
        .parse::<jiff::Timestamp>()
        .map_err(|e| Error::Clock(e.to_string()))?;
    for (domain, state) in history.domains() {
        let Some(window) = state.window() else {
            continue;
        };
        if i128::from(at.as_second()) < window.end_s()
            || db.recovery_settled(domain, window.owner().hash())?
        {
            continue;
        }
        let mut head = window.head().envelope().clone();
        let mut current = state.current().envelope().clone();
        let mut floor = state.highest_accepted_seq();
        let mut pending = db
            .peek_pending_entries()?
            .0
            .into_iter()
            .filter(|entry| entry.domain == *domain)
            .map(|entry| {
                let seq = if entry.entry_type == "publisher_declaration" {
                    Some(
                        declaration::publisher_of(&entry.entry_json)
                            .map_err(Error::History)?
                            .seq,
                    )
                } else {
                    None
                };
                Ok((seq, entry))
            })
            .collect::<Result<Vec<_>>>()?;
        pending.sort_by_key(|(seq, _)| *seq);
        for (seq, entry) in pending {
            if let Some(seq) = seq {
                declaration::evaluate_with_heads(&current, Some(&head), floor, &entry.entry_json)
                    .map_err(|(code, detail)| Error::History(format!("{code}: {detail}")))?;
                floor = floor.max(seq);
                current = entry.entry_json.clone();
                if declaration::follows_chain_head(&head, &entry.entry_json) {
                    head = entry.entry_json;
                } else {
                    db.remove_pending_declaration(entry.rowid)?;
                }
            } else if entry.entry_type == "publisher_delta" {
                db.requeue_pending_delta(&entry)?;
            }
        }
        let sealed = declaration::publisher_of(window.head().envelope()).map_err(Error::History)?;
        let mut rejected = Vec::new();
        for queued in db.drain_queued_deltas(domain)? {
            let result = declaration::delta_publisher(&queued.entry_json)
                .and_then(|author| {
                    if author == domain {
                        Ok(())
                    } else {
                        Err("WIST1-E02")
                    }
                })
                .and_then(|()| declaration::verify_delta_authority(&[&sealed], &queued.entry_json));
            match result {
                Ok(()) => db.release_queued_delta(domain, &queued)?,
                Err(code) => rejected.push((
                    queued.entry_json,
                    if code == "WIST1-E14" {
                        code
                    } else {
                        "WIST1-E13"
                    },
                )),
            }
        }
        db.reject_delta_copies(domain, &rejected, now)?;
        let publisher = declaration::publisher_of(&head).map_err(Error::History)?;
        let key = &publisher.keys[0];
        db.restore_publisher_declaration(
            domain,
            &serde_json::to_vec(&head)?,
            &key.key_id,
            &key.public_key,
        )?;
        db.close_recovery_window(domain)?;
        db.mark_recovery_settled(domain, window.owner().hash())?;
    }
    Ok(())
}
