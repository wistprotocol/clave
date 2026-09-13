use super::{
    declarations::{Declaration, Declarations, Position},
    History, VerifiedBlock,
};
use crate::db::BlockRow;
use crate::declaration::{self, delta::SizeCaps};
use crate::error::{Error, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone)]
pub struct DeltaSource {
    id: String,
    envelope: Value,
    position: Position,
    sealed_at_s: i64,
    declaration: Declaration,
    identity_start: Position,
    caps: SizeCaps,
    audit_profile: wist_core::canary::ScoringProfile,
}

impl DeltaSource {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>, delta_id: &str) -> Result<Self> {
        Self::reconstruct_matching(directory, head, |id, _| id == delta_id)?
            .pop()
            .ok_or_else(|| failure("requested Delta is absent from the pinned history"))
    }

    pub(crate) fn reconstruct_matching(
        directory: &Path,
        head: Option<BlockRow>,
        select: impl Fn(&str, &Value) -> bool,
    ) -> Result<Vec<Self>> {
        let mut history = History::open(directory, head)?;
        let mut declarations = Declarations::default();
        let mut chains = Chains::default();
        let mut found = Vec::new();
        while let Some(block) = history.next_block()? {
            declarations.apply(&block)?;
            chains.apply(&block, &declarations)?;
            for (entry_index, entry) in block.block().entries.iter().enumerate() {
                if entry["type"] != "publisher_delta" {
                    continue;
                }
                let envelope = &entry["body"];
                let id = wist_core::delta::delta_id(&envelope["delta"])?;
                if !select(&id, envelope) {
                    continue;
                }
                let domain =
                    &declarations.domains()[envelope["delta"]["publisher"].as_str().unwrap()];
                found.push(Self {
                    id,
                    envelope: envelope.clone(),
                    position: Position {
                        block_number: block.block().header.block_number,
                        entry_index,
                    },
                    sealed_at_s: block.sealed_at_s(),
                    declaration: domain.delta_sealing_source().unwrap().clone(),
                    identity_start: domain.reset().unwrap_or(domain.first()),
                    caps: block.delta_size_caps().clone(),
                    audit_profile: *block.audit_profile(),
                });
            }
        }
        Ok(found)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }

    pub fn envelope(&self) -> &Value {
        &self.envelope
    }

    pub fn position(&self) -> Position {
        self.position
    }

    pub fn declaration(&self) -> &Declaration {
        &self.declaration
    }

    pub fn identity_start(&self) -> Position {
        self.identity_start
    }

    pub fn size_caps(&self) -> &SizeCaps {
        &self.caps
    }

    pub fn audit_profile(&self) -> &wist_core::canary::ScoringProfile {
        &self.audit_profile
    }
}

pub(crate) struct Delta {
    pub(crate) id: String,
    pub(crate) domain: String,
    pub(crate) url: String,
    prev: Option<String>,
    observed_at: String,
}

impl Delta {
    pub(crate) fn read(envelope: &Value) -> Result<Self> {
        declaration::delta::validate_content_and_prev(envelope).map_err(failure)?;
        let body = &envelope["delta"];
        let domain = wist_core::delta::publisher(body).map_err(|e| failure(&e.to_string()))?;
        let url = body["url"]
            .as_str()
            .filter(|url| !url.is_empty())
            .ok_or_else(|| failure("retained Delta has no URL"))?;
        let prev = body["prev"].as_str().map(str::to_string);
        Ok(Self {
            id: wist_core::delta::delta_id(body)?,
            domain: domain.into(),
            url: url.into(),
            prev,
            observed_at: body["observed_at"].as_str().unwrap().into(),
        })
    }
}

#[derive(Default)]
pub(crate) struct Chains {
    pub(crate) seen: BTreeMap<String, String>,
    pub(crate) tips: BTreeMap<(String, String), Tip>,
}

pub(crate) struct Tip {
    pub(crate) id: String,
    observed_at: String,
}

impl Chains {
    pub(crate) fn append(&mut self, delta: Delta) -> Result<()> {
        let pair = (delta.domain.clone(), delta.url);
        if self.seen.contains_key(&delta.id) {
            return Err(failure("duplicate retained Delta ID"));
        }
        let tip = self.tips.get(&pair);
        if tip.map(|tip| &tip.id) != delta.prev.as_ref() {
            return Err(failure("retained Delta does not extend its Publisher/URL tip; restore missing accepted Envelopes or reconcile invalid retained copies"));
        }
        if let Some(tip) = tip {
            declaration::verify_observation_order(&delta.observed_at, &tip.observed_at)
                .map_err(failure)?;
        }
        self.tips.insert(
            pair,
            Tip {
                id: delta.id.clone(),
                observed_at: delta.observed_at,
            },
        );
        self.seen.insert(delta.id, delta.domain);
        Ok(())
    }

    fn block(&mut self, deltas: Vec<Delta>) -> Result<()> {
        let mut chains = BTreeMap::<_, BTreeMap<_, _>>::new();
        for delta in deltas {
            let chain = chains
                .entry((delta.domain.clone(), delta.url.clone()))
                .or_default();
            if chain.insert(delta.prev.clone(), delta).is_some() {
                return Err(failure("sealed Delta chain forks or repeats an ID"));
            }
        }
        for (pair, mut chain) in chains {
            while let Some(delta) = chain.remove(&self.tips.get(&pair).map(|tip| tip.id.clone())) {
                self.append(delta)?;
            }
            if !chain.is_empty() {
                return Err(failure(
                    "sealed Delta chain is disconnected from its Publisher/URL tip",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn apply(
        &mut self,
        block: &VerifiedBlock,
        declarations: &Declarations,
    ) -> Result<()> {
        let mut deltas = Vec::new();
        for entry in block
            .block()
            .entries
            .iter()
            .filter(|entry| entry["type"] == "publisher_delta")
        {
            let envelope = &entry["body"];
            block
                .delta_size_caps()
                .validate_delta(envelope)
                .map_err(failure)?;
            let delta = Delta::read(envelope)?;
            let source = declarations
                .domains()
                .get(&delta.domain)
                .and_then(|domain| domain.delta_sealing_source())
                .ok_or_else(|| failure("sealed Delta lacks an eligible Declaration source"))?;
            let publisher =
                declaration::publisher_of(source.envelope()).map_err(|e| failure(&e))?;
            declaration::verify_delta_authority(&[&publisher], envelope).map_err(failure)?;
            deltas.push(delta);
        }
        self.block(deltas)
    }
}

fn failure(detail: &str) -> Error {
    Error::History(format!("Delta history: {detail}"))
}
