use super::{deltas::DeltaSource, payloads::PayloadSource};
use crate::db::BlockRow;
use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;
use wist_core::reference::{self, ChainDelta};
use wist_core::verdict::ChangeType;

pub struct AuditChain {
    sources: Vec<DeltaSource>,
    audited: usize,
}

pub struct Reference<'a> {
    delta: &'a DeltaSource,
    payload: Option<PayloadSource>,
}

impl AuditChain {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>, audited: &str) -> Result<Self> {
        let source = DeltaSource::reconstruct(directory, head.clone(), audited)?;
        let body = &source.envelope()["delta"];
        let selected = DeltaSource::reconstruct_matching(directory, head, |_, envelope| {
            envelope["delta"]["publisher"] == body["publisher"]
                && envelope["delta"]["url"] == body["url"]
        })?;
        let mut successors: BTreeMap<_, _> = selected
            .into_iter()
            .map(|source| {
                (
                    source.envelope()["delta"]["prev"]
                        .as_str()
                        .map(str::to_owned),
                    source,
                )
            })
            .collect();
        let mut sources = Vec::<DeltaSource>::new();
        while let Some(source) =
            successors.remove(&sources.last().map(|source| source.id().to_owned()))
        {
            sources.push(source);
        }
        if !successors.is_empty() {
            return Err(failure("authenticated chain is disconnected"));
        }
        let audited = sources
            .iter()
            .position(|source| source.id() == audited)
            .ok_or_else(|| failure("audited Delta is absent from its authenticated chain"))?;
        Ok(Self { sources, audited })
    }

    pub fn audited(&self) -> &DeltaSource {
        &self.sources[self.audited]
    }

    pub fn newest_at(&self, fetched_at: &str) -> Result<Option<&DeltaSource>> {
        let at = crate::registry::epoch(fetched_at).map_err(|e| failure(&e.to_string()))?;
        Ok(reference::newest_at_or_before(&self.chain(), at)
            .and_then(|id| self.sources.iter().find(|source| source.id() == id)))
    }

    pub fn resolve(&self, reference_id: &str, fetched_at: &str) -> Result<Reference<'_>> {
        let at = crate::registry::epoch(fetched_at).map_err(|e| failure(&e.to_string()))?;
        let chain = self.chain();
        reference::reference_valid(&chain, self.audited().id(), reference_id, at)?;
        let delta = self
            .sources
            .iter()
            .find(|source| source.id() == reference_id)
            .unwrap();
        let payload = reference::resolve_anchor(&chain, reference_id)?
            .map(|id| {
                PayloadSource::from_delta(
                    self.sources
                        .iter()
                        .find(|source| source.id() == id)
                        .unwrap()
                        .clone(),
                )
            })
            .transpose()?;
        Ok(Reference { delta, payload })
    }

    fn chain(&self) -> Vec<ChainDelta<'_>> {
        self.sources
            .iter()
            .map(|source| {
                let change = match source.envelope()["delta"]["change_type"].as_str().unwrap() {
                    "new" => ChangeType::New,
                    "update" => ChangeType::Update,
                    "attest" => ChangeType::Attest,
                    "delete" => ChangeType::Delete,
                    _ => unreachable!(),
                };
                ChainDelta {
                    id: source.id(),
                    height: source.position().block_number,
                    sealed_at_s: source.sealed_at_s(),
                    change,
                    payload: matches!(change, ChangeType::New | ChangeType::Update)
                        .then_some(source.id()),
                }
            })
            .collect()
    }
}

impl Reference<'_> {
    pub fn delta(&self) -> &DeltaSource {
        self.delta
    }

    pub fn payload_source(&self) -> Option<&PayloadSource> {
        self.payload.as_ref()
    }
}

fn failure(detail: &str) -> Error {
    Error::History(format!("audit reference: {detail}"))
}
