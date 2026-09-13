use super::{declarations::Declarations, History};
use crate::db::BlockRow;
use crate::declaration::{self, delta::SizeCaps};
use crate::error::{Error, Result};
use serde_json::Value;
use std::path::Path;
use wist_core::objects::{DeltaPayloadCommitment, Payload};

pub struct PayloadSource {
    envelope: Value,
    block_number: u64,
    caps: SizeCaps,
    commitment: DeltaPayloadCommitment,
}

impl PayloadSource {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>, delta_id: &str) -> Result<Self> {
        let mut history = History::open(directory, head)?;
        let mut declarations = Declarations::default();
        let mut found = None;
        while let Some(block) = history.next_block()? {
            declarations.apply(&block)?;
            for entry in &block.block().entries {
                if entry["type"] != "publisher_delta"
                    || wist_core::delta::delta_id(&entry["body"]["delta"])? != delta_id
                {
                    continue;
                }
                if found.is_some() {
                    return Err(failure("requested Delta occurs more than once"));
                }
                let envelope = &entry["body"];
                block
                    .delta_size_caps()
                    .validate_delta(envelope)
                    .map_err(failure)?;
                let publisher = envelope["delta"]["publisher"].as_str().unwrap();
                let source = declarations
                    .domains()
                    .get(publisher)
                    .and_then(|domain| domain.delta_sealing_source())
                    .ok_or_else(|| {
                        failure("requested Delta lacks an eligible Declaration source")
                    })?;
                let publisher = declaration::publisher_of(source.envelope())
                    .map_err(|detail| failure(&detail))?;
                declaration::verify_delta_authority(&[&publisher], envelope).map_err(failure)?;
                let commitment = envelope["delta"]
                    .get("payload")
                    .ok_or_else(|| failure("requested Delta has no Payload commitment"))?;
                let commitment =
                    serde_json::from_slice(&wist_core::jcs::canonicalize(commitment)?)?;
                found = Some(Self {
                    envelope: envelope.clone(),
                    block_number: block.block().header.block_number,
                    caps: block.delta_size_caps().clone(),
                    commitment,
                });
            }
        }
        found.ok_or_else(|| failure("requested Delta is absent from the pinned history"))
    }

    pub fn envelope(&self) -> &Value {
        &self.envelope
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn size_caps(&self) -> &SizeCaps {
        &self.caps
    }

    pub fn validate(&self, raw: &[u8]) -> std::result::Result<Payload, &'static str> {
        let payload = crate::json::parse(raw).map_err(|_| "WIST1-E05")?;
        crate::payload::validate(
            &payload,
            &self.commitment,
            self.envelope["delta"]["publisher"].as_str().unwrap(),
            &self.caps,
        )
    }
}

fn failure(detail: &str) -> Error {
    Error::History(format!("historical Payload source: {detail}"))
}
