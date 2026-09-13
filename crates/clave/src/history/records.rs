use super::{declarations::Position, History};
use crate::db::BlockRow;
use crate::error::Result;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationProfile {
    pub auditors: u64,
    pub window_hours: u64,
}

#[derive(Debug, Clone)]
pub struct IncludedRecord {
    envelope: Value,
    position: Position,
    sealed_at_s: i64,
    block_hash: String,
    confirmation_profile: ConfirmationProfile,
}

impl IncludedRecord {
    pub fn reconstruct_all(directory: &Path, head: Option<BlockRow>) -> Result<Vec<Self>> {
        let mut history = History::open(directory, head)?;
        let mut records = Vec::new();
        while let Some(block) = history.next_block()? {
            for (entry_index, entry) in block.block().entries.iter().enumerate() {
                if entry["type"] == "audit_record" {
                    records.push(Self {
                        envelope: entry["body"].clone(),
                        position: Position {
                            block_number: block.block().header.block_number,
                            entry_index,
                        },
                        sealed_at_s: block.sealed_at_s(),
                        block_hash: block.hash().into(),
                        confirmation_profile: *block.confirmation_profile(),
                    });
                }
            }
        }
        Ok(records)
    }

    pub fn envelope(&self) -> &Value {
        &self.envelope
    }

    pub fn position(&self) -> Position {
        self.position
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }

    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    pub fn confirmation_profile(&self) -> &ConfirmationProfile {
        &self.confirmation_profile
    }
}
