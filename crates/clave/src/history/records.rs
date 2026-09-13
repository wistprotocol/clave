use super::{
    declarations::Position,
    deltas::DeltaSource,
    payloads::{PayloadLocations, PayloadRetrievalError, PayloadSource, RetrievedPayload},
    references::AuditChain,
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

pub struct RecordPayloadRetrieval<'a> {
    reference: &'a RecordReference,
    locations: PayloadLocations,
    result: std::result::Result<RetrievedPayload<'a>, PayloadRetrievalError>,
}

impl RecordPayloadRetrieval<'_> {
    pub fn reference(&self) -> &RecordReference {
        self.reference
    }

    pub fn locations(&self) -> &PayloadLocations {
        &self.locations
    }

    pub fn result(&self) -> std::result::Result<&RetrievedPayload<'_>, &PayloadRetrievalError> {
        self.result.as_ref()
    }
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
        crate::record::evidence_fields_valid(&self.envelope)
    }

    pub fn field_validation(&self) -> crate::record::FieldValidation {
        crate::record::RecordEnvelope::from_included(&self.envelope).fields()
    }

    pub fn disposition(
        &self,
        context: &crate::record::ReplayContext<'_>,
    ) -> crate::record::Disposition {
        crate::record::RecordEnvelope::from_included(&self.envelope).disposition(context)
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

    pub fn retrieve_payload(
        &self,
        client: &crate::fetch::Client,
        directory: &Path,
        independent_origins: &[String],
        mirror_list_origins: &[String],
    ) -> Option<RecordPayloadRetrieval<'_>> {
        let source = self.payload_source()?;
        let locations = source.discover_with_remote_mirrors(
            client,
            directory,
            independent_origins,
            mirror_list_origins,
        );
        let result = source.retrieve(client, locations.locations().iter().cloned());
        Some(RecordPayloadRetrieval {
            reference: self,
            locations,
            result,
        })
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
