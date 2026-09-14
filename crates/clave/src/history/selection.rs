use super::{
    declarations::Declarations,
    deltas::{Chains, Delta},
    roster::RosterHistory,
    History, VerifiedBlock,
};
use crate::db::BlockRow;
use crate::error::{Error, Result};
use std::path::Path;
use wist_core::sampling::{self, SamplingConstants};
use wist_core::vrf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionDelta {
    pub entry_index: usize,
    pub id: String,
    pub publisher: String,
    pub url_host: String,
    pub host_seq0_height: Option<u64>,
    pub excluded: bool,
}

#[derive(Debug, Clone)]
pub struct SelectionDomain {
    anchor_hash: [u8; 32],
    block: BlockRow,
    sealed_at_s: i64,
    sampling: SamplingConstants,
    deltas: Vec<SelectionDelta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingState {
    pub reputation_u: u64,
    pub level1_sanction: bool,
    pub escalated_sampling: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    OutsideDomain,
    SelfAudit,
    NotDrawn,
    Selected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionFailure {
    NoKeyAtBlock,
    ProofDoesNotVerify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Draw<'a> {
    pub delta: &'a SelectionDelta,
    pub d: Option<u64>,
    pub p_1e7: Option<u64>,
    pub disposition: Disposition,
}

#[derive(Debug)]
pub struct SelectionSet<'a> {
    domain: &'a SelectionDomain,
    auditor_id: String,
    key_id: String,
    public_key: String,
    beta: [u8; 64],
    draws: Vec<Draw<'a>>,
}

impl SelectionDomain {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>, block_hash: &str) -> Result<Self> {
        let mut history = History::open(directory, head)?;
        let mut declarations = Declarations::default();
        let mut chains = Chains::default();
        let mut found = None;
        while let Some(block) = history.next_block()? {
            declarations.apply(&block)?;
            chains.apply(&block, &declarations)?;
            if block.hash() == block_hash {
                found = Some(Self::from_block(
                    history.anchor_hash,
                    &block,
                    &declarations,
                )?);
            }
        }
        found.ok_or_else(|| Error::History("selection Block is absent from pinned history".into()))
    }

    pub(crate) fn from_block(
        anchor_hash: [u8; 32],
        block: &VerifiedBlock,
        declarations: &Declarations,
    ) -> Result<Self> {
        let height = block.block().header.block_number;
        let mut deltas = Vec::new();
        for (entry_index, entry) in block.block().entries.iter().enumerate() {
            if entry["type"] != "publisher_delta" {
                continue;
            }
            let delta = Delta::read(&entry["body"])?;
            let url_host = crate::declaration::url_host(&delta.url).to_owned();
            let host_seq0_height = declarations
                .domains()
                .get(&url_host)
                .map(|domain| domain.first().block_number);
            let excluded = !sampling::in_selection_domain(
                height,
                sampling::DomainDelta {
                    publisher: &delta.domain,
                    url_host: &url_host,
                },
                host_seq0_height,
            );
            deltas.push(SelectionDelta {
                entry_index,
                id: delta.id,
                publisher: delta.domain,
                url_host,
                host_seq0_height,
                excluded,
            });
        }
        Ok(Self {
            anchor_hash,
            block: BlockRow {
                block_number: height,
                block_hash: block.hash().into(),
                sealed_at: block.block().header.sealed_at.clone(),
            },
            sealed_at_s: block.sealed_at_s(),
            sampling: *block.sampling_constants(),
            deltas,
        })
    }

    pub fn anchor_hash(&self) -> &[u8; 32] {
        &self.anchor_hash
    }

    pub fn block(&self) -> &BlockRow {
        &self.block
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }

    pub fn sampling_constants(&self) -> &SamplingConstants {
        &self.sampling
    }

    pub fn deltas(&self) -> &[SelectionDelta] {
        &self.deltas
    }

    pub fn in_domain(&self) -> impl Iterator<Item = &SelectionDelta> {
        self.deltas.iter().filter(|delta| !delta.excluded)
    }

    pub fn selection_set(
        &self,
        roster: &RosterHistory,
        auditor_id: &str,
        vrf_proof: &[u8; vrf::PROOF_LEN],
        state: &dyn Fn(&str) -> SamplingState,
    ) -> Result<std::result::Result<SelectionSet<'_>, SelectionFailure>> {
        if roster.anchor_hash() != &self.anchor_hash {
            return Err(Error::History(
                "selection set: Log Anchor differs from the selection domain's source".into(),
            ));
        }
        let alpha = sampling::alpha_from_block_hash(&self.block.block_hash)?;
        if roster.block_hash_at(self.block.block_number) != Some(&alpha) {
            return Err(Error::History(
                "selection set: roster history does not carry the selection Block".into(),
            ));
        }
        let Some(key) = roster.admitted_key_at(auditor_id, self.sealed_at_s) else {
            return Ok(Err(SelectionFailure::NoKeyAtBlock));
        };
        let public_key: Option<[u8; 32]> = wist_core::crypto::b64u_decode(key.public_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok());
        let Some(beta) =
            public_key.and_then(|public_key| vrf::verify(&public_key, &alpha, vrf_proof).ok())
        else {
            return Ok(Err(SelectionFailure::ProofDoesNotVerify));
        };
        let draws = self
            .deltas
            .iter()
            .map(|delta| {
                let (d, p_1e7, disposition) = if delta.excluded {
                    (None, None, Disposition::OutsideDomain)
                } else if sampling::self_audit_barred(auditor_id, &delta.publisher) {
                    (None, None, Disposition::SelfAudit)
                } else {
                    let d = sampling::draw(&beta, &delta.id);
                    let state = state(&delta.publisher);
                    let p_1e7 = sampling::p_1e7(
                        state.reputation_u,
                        state.level1_sanction,
                        state.escalated_sampling,
                        &self.sampling,
                    );
                    let disposition = if sampling::selected(d, p_1e7) {
                        Disposition::Selected
                    } else {
                        Disposition::NotDrawn
                    };
                    (Some(d), Some(p_1e7), disposition)
                };
                Draw {
                    delta,
                    d,
                    p_1e7,
                    disposition,
                }
            })
            .collect();
        Ok(Ok(SelectionSet {
            domain: self,
            auditor_id: auditor_id.to_owned(),
            key_id: key.key_id.to_owned(),
            public_key: key.public_key.to_owned(),
            beta,
            draws,
        }))
    }
}

impl<'a> SelectionSet<'a> {
    pub fn domain(&self) -> &'a SelectionDomain {
        self.domain
    }

    pub fn auditor_id(&self) -> &str {
        &self.auditor_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn beta(&self) -> &[u8; 64] {
        &self.beta
    }

    pub fn draws(&self) -> &[Draw<'a>] {
        &self.draws
    }

    pub fn disposition(&self, delta_id: &str) -> Option<Disposition> {
        self.draws
            .iter()
            .find(|draw| draw.delta.id == delta_id)
            .map(|draw| draw.disposition)
    }

    pub fn selected(&self) -> impl Iterator<Item = &'a SelectionDelta> + '_ {
        self.draws
            .iter()
            .filter(|draw| draw.disposition == Disposition::Selected)
            .map(|draw| draw.delta)
    }

    pub fn is_empty(&self) -> bool {
        self.selected().next().is_none()
    }
}
