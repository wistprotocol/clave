use super::deltas::DeltaSource;
use crate::db::BlockRow;
use crate::declaration::delta::SizeCaps;
use crate::error::{Error, Result};
use serde_json::Value;
use std::path::Path;
use wist_core::objects::{DeltaPayloadCommitment, Payload};

pub struct PayloadSource {
    delta: DeltaSource,
    commitment: DeltaPayloadCommitment,
}

pub struct RetrievedPayload<'a> {
    source: &'a PayloadSource,
    raw: Vec<u8>,
    payload: Payload,
}

impl PayloadSource {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>, delta_id: &str) -> Result<Self> {
        let delta = DeltaSource::reconstruct(directory, head, delta_id)?;
        Self::from_delta(delta)
    }

    pub(crate) fn from_delta(delta: DeltaSource) -> Result<Self> {
        let commitment = delta.envelope()["delta"]
            .get("payload")
            .ok_or_else(|| failure("requested Delta has no Payload commitment"))?;
        let commitment = serde_json::from_slice(&wist_core::jcs::canonicalize(commitment)?)?;
        Ok(Self { delta, commitment })
    }

    pub fn delta_source(&self) -> &DeltaSource {
        &self.delta
    }

    pub fn envelope(&self) -> &Value {
        self.delta.envelope()
    }

    pub fn block_number(&self) -> u64 {
        self.delta.position().block_number
    }

    pub fn size_caps(&self) -> &SizeCaps {
        self.delta.size_caps()
    }

    pub fn validate(&self, raw: &[u8]) -> std::result::Result<Payload, &'static str> {
        let payload = crate::json::parse(raw).map_err(|_| "WIST1-E05")?;
        crate::payload::validate(
            &payload,
            &self.commitment,
            self.envelope()["delta"]["publisher"].as_str().unwrap(),
            self.size_caps(),
        )
    }

    pub fn read(&self, directory: &Path) -> Result<RetrievedPayload<'_>> {
        let path = directory
            .join("payloads")
            .join(format!("{}.json", &self.delta.id()[7..]));
        self.checked(std::fs::read(path)?)
    }

    pub fn fetch(&self, client: &crate::fetch::Client, url: &str) -> Result<RetrievedPayload<'_>> {
        self.checked(client.get_bytes(url)?)
    }

    fn checked(&self, raw: Vec<u8>) -> Result<RetrievedPayload<'_>> {
        let payload = self.validate(&raw).map_err(Error::Payload)?;
        Ok(RetrievedPayload {
            source: self,
            raw,
            payload,
        })
    }
}

impl RetrievedPayload<'_> {
    pub fn source(&self) -> &PayloadSource {
        self.source
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }
}

fn failure(detail: &str) -> Error {
    Error::History(format!("historical Payload source: {detail}"))
}
