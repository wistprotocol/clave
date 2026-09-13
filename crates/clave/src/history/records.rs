use super::{
    declarations::Position, deltas::DeltaSource, payloads::PayloadSource, references::AuditChain,
    History,
};
use crate::db::BlockRow;
use crate::error::{Error, Result};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationProfile {
    pub auditors: u64,
    pub window_hours: u64,
}

#[derive(Debug, Clone)]
pub struct IncludedRecord {
    anchor_hash: [u8; 32],
    envelope: Value,
    position: Position,
    sealed_at_s: i64,
    block_hash: String,
    confirmation_profile: ConfirmationProfile,
}

pub struct RecordReference {
    record: IncludedRecord,
    audited: DeltaSource,
    reference: DeltaSource,
    payload: Option<PayloadSource>,
}

impl IncludedRecord {
    pub fn reconstruct_all(directory: &Path, head: Option<BlockRow>) -> Result<Vec<Self>> {
        let mut history = History::open(directory, head)?;
        let mut records = Vec::new();
        while let Some(block) = history.next_block()? {
            for (entry_index, entry) in block.block().entries.iter().enumerate() {
                if entry["type"] == "audit_record" {
                    records.push(Self {
                        anchor_hash: history.anchor_hash,
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

    pub fn resolve_reference(&self, directory: &Path) -> Result<RecordReference> {
        let body = &self.envelope["record"];
        let field = |name: &str| {
            body[name].as_str().ok_or_else(|| {
                Error::History(format!("Record reference: missing or non-string {name}"))
            })
        };
        let audited_id = field("audited_delta")?;
        let reference_id = field("reference_delta")?;
        let fetched_at = field("fetched_at")?;
        let fetched_at_s = crate::registry::epoch(fetched_at)
            .map_err(|e| Error::History(format!("Record reference: {e}")))?;
        if fetched_at_s > self.sealed_at_s {
            return Err(Error::History(
                "WIST4-E02: Record fetch is after its sealing Block".into(),
            ));
        }
        let head = BlockRow {
            block_number: self.position.block_number,
            block_hash: self.block_hash.clone(),
            sealed_at: jiff::Timestamp::from_second(self.sealed_at_s)
                .map_err(|e| Error::History(e.to_string()))?
                .to_string(),
        };
        let chain = AuditChain::reconstruct(directory, Some(head), audited_id)?;
        if chain.audited().anchor_hash() != self.anchor_hash {
            return Err(Error::History(
                "Record reference: Log Anchor differs from the inclusion source".into(),
            ));
        }
        let reference = chain.resolve(reference_id, fetched_at)?;
        Ok(RecordReference {
            record: self.clone(),
            audited: chain.audited().clone(),
            reference: reference.delta().clone(),
            payload: reference.payload_source().cloned(),
        })
    }
}

impl RecordReference {
    pub fn record(&self) -> &IncludedRecord {
        &self.record
    }

    pub fn audited(&self) -> &DeltaSource {
        &self.audited
    }

    pub fn reference(&self) -> &DeltaSource {
        &self.reference
    }

    pub fn payload_source(&self) -> Option<&PayloadSource> {
        self.payload.as_ref()
    }
}
