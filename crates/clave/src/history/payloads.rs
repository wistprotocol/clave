use crate::error::{Error, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use wist_core::item::SizeCaps;
use wist_core::objects::{PageItem, Payload};

#[derive(Clone)]
pub struct PayloadSource {
    item: Value,
    page: PageItem,
    collection: String,
    name: String,
    epoch_number: u64,
    size_caps: SizeCaps,
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
    pub fn from_item(
        item: Value,
        collection: &str,
        epoch_number: u64,
        size_caps: SizeCaps,
    ) -> Result<Self> {
        let page: PageItem = serde_json::from_slice(&wist_core::jcs::canonicalize(&item)?)
            .map_err(|_| failure("the sealed Item is not of kind page"))?;
        let name = wist_core::item::payload_name(&item)?;
        Ok(Self {
            item,
            page,
            collection: collection.to_owned(),
            name,
            epoch_number,
            size_caps,
        })
    }

    /// WIST-3 §6.1, §6.2.
    pub fn reconstruct(
        db: &crate::db::Db,
        directory: &Path,
        head: Option<crate::db::EpochRow>,
        item_id: &str,
    ) -> Result<Self> {
        let mut history = super::History::open(db, directory, head)?;
        let mut found = None;
        while let Some(epoch) = history.next_epoch()? {
            if found.is_some() {
                continue;
            }
            for (index, entry) in epoch.entries().iter().enumerate() {
                let valid = matches!(
                    epoch.judgments().get(index),
                    Some(Some(wist_core::sealing::Judgment::Valid))
                );
                let item = &entry["body"]["item"];
                if entry["type"] == "publisher_item"
                    && valid
                    && wist_core::item::item_id(item).ok().as_deref() == Some(item_id)
                {
                    found = Some((
                        item.clone(),
                        entry["body"]["collection"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                        epoch.epoch_number(),
                        *epoch.size_caps(),
                    ));
                    break;
                }
            }
        }
        if history.replay().withdrawals().is_withdrawn(item_id) {
            return Err(failure(
                "a withdrawal sealed for the Item removed its Payload",
            ));
        }
        let (item, collection, epoch_number, size_caps) =
            found.ok_or_else(|| failure("no Epoch seals a valid Item of that ID"))?;
        Self::from_item(item, &collection, epoch_number, size_caps)
    }

    pub fn item(&self) -> &Value {
        &self.item
    }

    pub fn epoch_number(&self) -> u64 {
        self.epoch_number
    }

    pub fn size_caps(&self) -> &SizeCaps {
        &self.size_caps
    }

    pub fn validate(&self, raw: &[u8]) -> std::result::Result<Payload, &'static str> {
        crate::payload::judge(&self.page, raw, &self.size_caps)
    }

    pub fn read(&self, directory: &Path) -> Result<RetrievedPayload<'_>> {
        let path = directory.join(self.relative_path());
        self.checked(std::fs::read(&path)?, PayloadLocation::File(path))
    }

    pub fn fetch(&self, client: &crate::fetch::Client, url: &str) -> Result<RetrievedPayload<'_>> {
        let raw =
            client.get_bytes_bounded(url, &[], crate::payload::cap_bytes(self.size_caps()))?;
        self.checked(raw, PayloadLocation::Url(url.into()))
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

    /// WIST-2 §3, §3.1.
    pub fn publisher_location(&self, client: &crate::fetch::Client) -> PayloadLocation {
        let publisher = self.page.publisher.as_str();
        let scheme = crate::fetch::scheme_for_host(publisher, client.allow_http());
        PayloadLocation::Url(format!(
            "{scheme}://{publisher}/.well-known/wist/collections/{}/{}",
            self.collection,
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
                PayloadLocation::Url(url) => {
                    client.get_bytes_bounded(url, &[], crate::payload::cap_bytes(self.size_caps()))
                }
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
        format!("payloads/{}.json", self.name)
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
