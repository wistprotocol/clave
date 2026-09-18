use super::{Db, Result};
use crate::error::Error;
use crate::history::declarations::DeclarationsReplay;
use crate::history::{
    declarations::Declarations,
    deltas::{Chains, Delta},
    History,
};
use rusqlite::TransactionBehavior;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

impl Db {
    pub(super) fn restore_delta_indexes(&self, path: &Path) -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS delta_index_reconciliation(id INTEGER PRIMARY KEY CHECK(id = 1));")?;
        let complete: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM delta_index_reconciliation WHERE id = 1)",
            [],
            |row| row.get(0),
        )?;
        if complete {
            tx.commit()?;
            return Ok(());
        }
        let mut indexes = Chains::default();
        let head = self.last_block()?;
        if head.is_some() {
            let mut history =
                History::open(self, path.parent().unwrap_or_else(|| Path::new(".")), head)?;
            let mut declarations = Declarations::default();
            while let Some(block) = history.next_block()? {
                declarations.apply(&block)?;
                indexes.apply(&block, &declarations)?;
            }
        }
        let mut statement = tx.prepare(
            "SELECT domain, entry_json, acceptance_order, NULL, NULL FROM pending_entries WHERE entry_type = 'publisher_delta' UNION ALL SELECT domain, entry_json, acceptance_order, delta_id, url FROM queued_deltas ORDER BY acceptance_order",
        )?;
        let mut rows = statement.query([])?;
        let mut positions = BTreeSet::new();
        while let Some(row) = rows.next()? {
            let domain: String = row.get(0)?;
            let envelope: Value = crate::json::parse(&row.get::<_, Vec<u8>>(1)?)?;
            let position: i64 = row.get(2)?;
            let stored_id: Option<String> = row.get(3)?;
            let stored_url: Option<String> = row.get(4)?;
            let delta = Delta::read(&envelope)?;
            if position <= 0 || !positions.insert(position) {
                return Err(failure(
                    "retained Delta acceptance positions are invalid or duplicated",
                ));
            }
            if domain != delta.domain
                || stored_id.as_ref().is_some_and(|id| id != &delta.id)
                || stored_url.as_ref().is_some_and(|url| url != &delta.url)
            {
                return Err(failure("retained Delta disagrees with its admission row"));
            }
            indexes.append(delta)?;
        }
        drop(rows);
        drop(statement);
        tx.execute_batch("DELETE FROM seen_deltas; DELETE FROM url_tips;")?;
        for (id, domain) in indexes.seen {
            super::exec_insert_seen_delta(&tx, &id, &domain)?;
        }
        for ((domain, url), tip) in indexes.tips {
            super::exec_set_url_tip(&tx, &url, &domain, &tip.id)?;
        }
        tx.execute("INSERT INTO delta_index_reconciliation VALUES (1)", [])?;
        tx.commit()?;
        Ok(())
    }
}

fn failure(detail: &str) -> Error {
    Error::History(format!("Delta index reconciliation: {detail}"))
}
