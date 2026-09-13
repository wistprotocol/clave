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

    pub fn evidence_fields_valid(&self) -> bool {
        let body = &self.envelope["record"];
        let Some(verdict) = body["verdict"].as_str() else {
            return false;
        };
        let measured = match verdict {
            "consistent" | "dynamic_variance" | "inconsistent" | "link_variance"
            | "link_inconsistent" => true,
            "unreachable" | "not_auditable" => false,
            _ => return false,
        };
        for field in [
            "response_commitment",
            "credit_commitment",
            "ref_extract_commitment",
            "evidence_commitment",
        ] {
            match body.get(field) {
                Some(value) if measured => {
                    if !value
                        .as_str()
                        .and_then(|value| value.strip_prefix("hmac-sha256:"))
                        .is_some_and(|hex| {
                            hex.len() == 64
                                && hex
                                    .bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        })
                    {
                        return false;
                    }
                }
                None if !measured => {}
                _ => return false,
            }
        }
        let micro = |value: &Value| value.as_u64().is_some_and(|n| n <= 1_000_000);
        if body.get("similarity").is_some_and(micro) != measured
            || (!measured && body.get("similarity").is_some())
            || body
                .get("link_agreement")
                .is_some_and(|value| !measured || !micro(value))
            || (matches!(verdict, "link_variance" | "link_inconsistent")
                && body.get("link_agreement").is_none())
            || body
                .get("robots_excluded")
                .is_some_and(|value| verdict != "unreachable" || value != true)
        {
            return false;
        }
        match body.get("unmeasured") {
            Some(value) => {
                verdict == "not_auditable"
                    && matches!(value.as_str(), Some("observed" | "reference"))
            }
            None => verdict != "not_auditable",
        }
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

    pub fn validate_verdict_scores(&self) -> Result<()> {
        use wist_core::verdict::{self, ChangeType, Verdict};

        let failure = || Error::History("WIST4-E02: invalid Record verdict scores".into());
        let body = &self.record.envelope["record"];
        let score = |name: &str| {
            body.get(name)
                .map(|value| value.as_u64().ok_or_else(failure))
                .transpose()
        };
        let verdict = match body["verdict"].as_str() {
            Some("consistent") => Verdict::Consistent,
            Some("dynamic_variance") => Verdict::DynamicVariance,
            Some("inconsistent") => Verdict::Inconsistent,
            Some("unreachable") => Verdict::Unreachable,
            Some("not_auditable") => Verdict::NotAuditable,
            Some("link_variance") => Verdict::LinkVariance,
            Some("link_inconsistent") => Verdict::LinkInconsistent,
            _ => return Err(failure()),
        };
        let change = match self.reference.envelope()["delta"]["change_type"]
            .as_str()
            .unwrap()
        {
            "new" => ChangeType::New,
            "update" => ChangeType::Update,
            "attest" => ChangeType::Attest,
            "delete" => ChangeType::Delete,
            _ => unreachable!(),
        };
        if verdict::record_scores_valid(
            change,
            verdict,
            score("similarity")?,
            score("link_agreement")?,
            self.audited.verdict_thresholds(),
        ) {
            Ok(())
        } else {
            Err(failure())
        }
    }
}
