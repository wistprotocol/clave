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

#[derive(Debug)]
pub struct PayloadLocations {
    locations: Vec<PayloadLocation>,
    discovery_failures: Vec<PayloadAttemptFailure>,
}

impl PayloadLocations {
    pub fn locations(&self) -> &[PayloadLocation] {
        &self.locations
    }

    pub fn discovery_failures(&self) -> &[PayloadAttemptFailure] {
        &self.discovery_failures
    }

    fn add_origin(&mut self, source: &PayloadSource, origin: &str) {
        match source.distribution_location(origin) {
            Ok(location) => {
                if !self.locations.contains(&location) {
                    self.locations.push(location);
                }
            }
            Err(error) => self.discovery_failures.push(PayloadAttemptFailure {
                location: PayloadLocation::Url(origin.into()),
                error,
            }),
        }
    }
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
        Self::origin_url(origin, &self.relative_path()).map(PayloadLocation::Url)
    }

    fn origin_url(origin: &str, path: &str) -> Result<String> {
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
        Ok(format!("{parsed}{path}"))
    }

    pub fn publisher_location(&self, client: &crate::fetch::Client) -> PayloadLocation {
        let publisher = self.envelope()["delta"]["publisher"].as_str().unwrap();
        let scheme = crate::fetch::scheme_for_host(publisher, client.allow_http());
        PayloadLocation::Url(format!(
            "{scheme}://{publisher}/.well-known/wist/{}",
            self.relative_path(),
        ))
    }

    pub fn discover(
        &self,
        client: &crate::fetch::Client,
        directory: &Path,
        independent_origins: &[String],
    ) -> PayloadLocations {
        self.discover_with_remote_mirrors(client, directory, independent_origins, &[])
    }

    pub fn discover_with_remote_mirrors(
        &self,
        client: &crate::fetch::Client,
        directory: &Path,
        independent_origins: &[String],
        mirror_list_origins: &[String],
    ) -> PayloadLocations {
        let mut discovered = PayloadLocations {
            locations: vec![self.retained_location(directory)],
            discovery_failures: Vec::new(),
        };
        for origin in independent_origins {
            discovered.add_origin(self, origin);
        }
        let path = directory.join("log/mirrors.json");
        let mirrors = std::fs::read(&path)
            .map_err(Error::from)
            .and_then(|raw| mirror_hints(&raw));
        match mirrors {
            Ok(origins) => {
                for origin in origins {
                    discovered.add_origin(self, &origin);
                }
            }
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => discovered.discovery_failures.push(PayloadAttemptFailure {
                location: PayloadLocation::File(path),
                error,
            }),
        }
        let mut fetched = std::collections::HashSet::new();
        for origin in mirror_list_origins {
            let url = match Self::origin_url(origin, "log/mirrors.json") {
                Ok(url) => url,
                Err(error) => {
                    discovered.discovery_failures.push(PayloadAttemptFailure {
                        location: PayloadLocation::Url(origin.clone()),
                        error,
                    });
                    continue;
                }
            };
            if !fetched.insert(url.clone()) {
                continue;
            }
            match client.get_bytes(&url).and_then(|raw| mirror_hints(&raw)) {
                Ok(origins) => {
                    for origin in origins {
                        discovered.add_origin(self, &origin);
                    }
                }
                Err(error) => discovered.discovery_failures.push(PayloadAttemptFailure {
                    location: PayloadLocation::Url(url),
                    error,
                }),
            }
        }
        discovered.locations.push(self.publisher_location(client));
        discovered
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

fn mirror_hints(raw: &[u8]) -> Result<Vec<String>> {
    let doc = crate::json::parse(raw)?;
    serde_json::from_value(doc["mirrors"]["mirror_urls"].clone()).map_err(Error::from)
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
