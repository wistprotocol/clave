use super::deltas::DeltaSource;
use crate::db::BlockRow;
use crate::declaration::delta::SizeCaps;
use crate::error::{Error, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use wist_core::objects::{DeltaPayloadCommitment, Payload};

pub struct PayloadSource {
    delta: DeltaSource,
    commitment: DeltaPayloadCommitment,
}

pub struct RetrievedPayload<'a> {
    source: &'a PayloadSource,
    location: PayloadLocation,
    failed_attempts: Vec<PayloadAttemptFailure>,
    raw: Vec<u8>,
    payload: Payload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadLocation {
    File(PathBuf),
    Url(String),
}

#[derive(Debug)]
pub struct PayloadAttemptFailure {
    pub location: PayloadLocation,
    pub error: Error,
}

#[derive(Debug, thiserror::Error)]
#[error("no candidate supplied a valid historical Payload")]
pub struct PayloadRetrievalError {
    pub attempts: Vec<PayloadAttemptFailure>,
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
        let path = directory.join(self.relative_path());
        self.checked(std::fs::read(&path)?, PayloadLocation::File(path))
    }

    pub fn fetch(&self, client: &crate::fetch::Client, url: &str) -> Result<RetrievedPayload<'_>> {
        self.checked(client.get_bytes(url)?, PayloadLocation::Url(url.into()))
    }

    pub fn retained_location(&self, directory: &Path) -> PayloadLocation {
        PayloadLocation::File(directory.join(self.relative_path()))
    }

    pub fn distribution_location(&self, origin: &str) -> Result<PayloadLocation> {
        let parsed = url::Url::parse(origin)
            .map_err(|error| Error::Fetch(format!("invalid Payload origin: {error}")))?;
        if !matches!(parsed.scheme(), "https" | "http")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::Fetch(
                "Payload distribution requires a bare HTTP(S) origin".into(),
            ));
        }
        Ok(PayloadLocation::Url(format!(
            "{parsed}{}",
            self.relative_path()
        )))
    }

    pub fn publisher_location(&self, client: &crate::fetch::Client) -> PayloadLocation {
        let publisher = self.envelope()["delta"]["publisher"].as_str().unwrap();
        let scheme = crate::fetch::scheme_for_host(publisher, client.allow_http());
        PayloadLocation::Url(format!(
            "{scheme}://{publisher}/.well-known/wist/{}",
            self.relative_path(),
        ))
    }

    pub fn retrieve(
        &self,
        client: &crate::fetch::Client,
        candidates: impl IntoIterator<Item = PayloadLocation>,
    ) -> std::result::Result<RetrievedPayload<'_>, PayloadRetrievalError> {
        let mut attempts = Vec::new();
        for location in candidates {
            let raw = match &location {
                PayloadLocation::File(path) => std::fs::read(path).map_err(Error::from),
                PayloadLocation::Url(url) => client.get_bytes(url),
            };
            match raw.and_then(|raw| self.checked(raw, location.clone())) {
                Ok(mut retrieved) => {
                    retrieved.failed_attempts = attempts;
                    return Ok(retrieved);
                }
                Err(error) => attempts.push(PayloadAttemptFailure { location, error }),
            }
        }
        Err(PayloadRetrievalError { attempts })
    }

    fn relative_path(&self) -> String {
        format!("payloads/{}.json", &self.delta.id()[7..])
    }

    fn checked(&self, raw: Vec<u8>, location: PayloadLocation) -> Result<RetrievedPayload<'_>> {
        let payload = self.validate(&raw).map_err(Error::Payload)?;
        Ok(RetrievedPayload {
            source: self,
            location,
            failed_attempts: Vec::new(),
            raw,
            payload,
        })
    }
}

impl RetrievedPayload<'_> {
    pub fn source(&self) -> &PayloadSource {
        self.source
    }

    pub fn location(&self) -> &PayloadLocation {
        &self.location
    }

    pub fn failed_attempts(&self) -> &[PayloadAttemptFailure] {
        &self.failed_attempts
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
