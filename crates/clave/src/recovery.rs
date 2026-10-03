use crate::db::Db;
use crate::declaration;
use crate::error::{Error, Result};
use crate::history::declarations::Declarations;
use crate::history::declarations::DeclarationsReplay;
use std::path::Path;

pub fn settle(db: &Db, data_dir: &Path, now: &str) -> Result<()> {
    let mutation = db.mutation()?;
    let history = Declarations::reconstruct(db, data_dir, db.last_epoch()?)?;
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
        let limits = declaration::limits(&db.parameter_schedule(at.as_second())?, at.as_second())?;
        let mut pending = db
            .peek_pending_entries()?
            .0
            .into_iter()
            .filter(|entry| entry.domain == *domain && entry.entry_type == "publisher_declaration")
            .map(|entry| {
                let seq = declaration::publisher_of(&entry.entry_json)
                    .map_err(Error::History)?
                    .seq;
                Ok((seq, entry))
            })
            .collect::<Result<Vec<_>>>()?;
        pending.sort_by_key(|(seq, _)| *seq);
        for (seq, entry) in pending {
            declaration::evaluate_with_heads(
                &current,
                Some(&head),
                None,
                floor,
                &entry.entry_json,
                &limits,
            )
            .map_err(|(code, detail)| Error::History(format!("{code}: {detail}")))?;
            floor = floor.max(seq);
            current = entry.entry_json.clone();
            if declaration::follows_chain_head(&head, &entry.entry_json) {
                head = entry.entry_json;
            } else {
                db.remove_pending_declaration(entry.rowid)?;
            }
        }
        let publisher = declaration::publisher_of(&head).map_err(Error::History)?;
        let key = &publisher.keys[0];
        db.restore_publisher_declaration(domain, &serde_json::to_vec(&head)?, &key.kid, &key.x)?;
        db.close_recovery_window(domain)?;
        db.mark_recovery_settled(domain, window.owner().hash())?;
    }
    Ok(())
}
