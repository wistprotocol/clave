use super::Db;
use crate::error::{Error, Result};
use crate::history::deltas::DeltaSource;
use serde_json::Value;
use std::path::Path;

impl Db {
    pub(crate) fn accepted_delta(&self, directory: &Path, domain: &str, id: &str) -> Result<Value> {
        if !self.is_delta_seen_for(id, domain)? {
            return Err(Error::History("predecessor is no longer accepted".into()));
        }
        let mut statement = self.conn.prepare(
            "SELECT entry_json FROM pending_entries WHERE entry_type = 'publisher_delta' AND domain = ?1 UNION ALL SELECT entry_json FROM queued_deltas WHERE domain = ?1",
        )?;
        let mut rows = statement.query([domain])?;
        while let Some(row) = rows.next()? {
            let doc: Value = crate::json::parse(&row.get::<_, Vec<u8>>(0)?)?;
            if wist_core::delta::delta_id(&doc["delta"])? == id {
                return Ok(doc);
            }
        }
        let source = DeltaSource::reconstruct(directory, self.last_block()?, id)?;
        Ok(source.envelope().clone())
    }
}
