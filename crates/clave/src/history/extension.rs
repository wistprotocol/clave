use super::{
    declarations::{Declarations, Position},
    deltas::{Chains, Delta},
    roster::RosterHistory,
    History, VerifiedBlock,
};
use crate::db::BlockRow;
use crate::error::{Error, Result};
use crate::record::{Duty, RecordEnvelope, ReplayContext};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use wist_core::confirmation::{independent, CandidateRecord};
use wist_core::coverage::{within_days_ending_at, Block};
pub use wist_core::extension::ExtensionOutcome;
use wist_core::extension::{self, Escalation, ExtensionClaim, ExtensionRecord, RATION_WINDOW_DAYS};
use wist_core::objects::audit::Verdict as SealedVerdict;
use wist_core::sampling::{self, SamplingConstants};
use wist_core::verdict::{self, ChangeType, Thresholds, Verdict};
use wist_core::vrf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorState {
    pub reputation_u: u64,
    pub level1_sanction: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoidReason {
    Malformed,
    UnknownDelta,
    OutsideDomain,
    SelfAudit,
    NoKeyAtBlock,
    ProofWithoutStanding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    Selected,
    Extension { trigger_height: u64 },
    Void(VoidReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStanding {
    pub position: Position,
    pub sealed_at_s: i64,
    pub auditor_id: String,
    pub audited_delta: String,
    pub publisher: Option<String>,
    pub audited_height: Option<u64>,
    pub verdict: Option<Verdict>,
    pub standing: Standing,
    pub duty: Duty,
    pub authentic: bool,
    pub diagnostic: Option<&'static str>,
    pub discharges_coverage: bool,
}

impl RecordStanding {
    pub fn evidence(&self) -> bool {
        self.diagnostic.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trigger {
    pub position: Position,
    pub sealed_at_s: i64,
    pub auditor_id: String,
    pub delta_id: String,
    pub publisher: String,
    pub verdict: Verdict,
    pub summons: bool,
    pub summoned: Vec<String>,
    pub deadline_s: i128,
    pub confirm_window_hours: u64,
    pub confirm_auditors: u64,
    pub outcome: Option<ExtensionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionDuty {
    pub auditor_id: String,
    pub trigger: Position,
    pub trigger_height: u64,
    pub delta_id: String,
    pub publisher: String,
    pub deadline_s: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationRecord {
    pub publisher: String,
    pub trigger: Position,
    pub establishing_height: u64,
    pub establishing_sealed_at_s: i64,
}

struct BlockFact {
    block: Block,
    alpha: [u8; 32],
    sampling: SamplingConstants,
    thresholds: Thresholds,
    confirm_window_hours: u64,
    confirm_auditors: u64,
    extension_triggers_max: u64,
}

struct DeltaFact {
    height: u64,
    publisher: String,
    excluded: bool,
    chain: (String, String),
    index: u64,
    change: ChangeType,
}

#[derive(Clone)]
struct Evidence {
    position: Position,
    sealed_at_s: i64,
    auditor_id: String,
    verdict: Verdict,
}

pub struct ExtensionHistory {
    anchor_hash: [u8; 32],
    through: Option<BlockRow>,
    blocks: Vec<BlockFact>,
    deltas: BTreeMap<String, DeltaFact>,
    roster: RosterHistory,
    records: Vec<RecordStanding>,
    evidence: BTreeMap<String, Vec<Evidence>>,
    summoning: Vec<(String, i64)>,
    named: BTreeMap<(String, String), Vec<u64>>,
    triggers: Vec<Trigger>,
    duties: Vec<ExtensionDuty>,
    escalations: Vec<EscalationRecord>,
}

impl ExtensionHistory {
    pub fn reconstruct(
        directory: &Path,
        head: Option<BlockRow>,
        prior: &dyn Fn(&str, u64) -> PriorState,
    ) -> Result<Self> {
        let mut history = History::open(directory, head.clone())?;
        let mut declarations = Declarations::default();
        let mut chains = Chains::default();
        let mut replay = Self {
            anchor_hash: history.anchor_hash,
            through: head,
            blocks: Vec::new(),
            deltas: BTreeMap::new(),
            roster: RosterHistory::start(&history),
            records: Vec::new(),
            evidence: BTreeMap::new(),
            summoning: Vec::new(),
            named: BTreeMap::new(),
            triggers: Vec::new(),
            duties: Vec::new(),
            escalations: Vec::new(),
        };
        while let Some(block) = history.next_block()? {
            declarations.apply(&block)?;
            chains.apply(&block, &declarations)?;
            replay
                .roster
                .apply(&block, history.log_key_id(), history.log_key())?;
            replay.register_block(&block)?;
            replay.register_deltas(&block, &declarations)?;
            for (entry_index, entry) in block.block().entries.iter().enumerate() {
                if entry["type"] == "audit_record" {
                    replay.classify(&block, entry_index, &entry["body"], prior)?;
                }
            }
            replay.close_extensions()?;
        }
        Ok(replay)
    }

    fn register_block(&mut self, block: &VerifiedBlock) -> Result<()> {
        let height = block.block().header.block_number;
        if self.blocks.len() as u64 != height {
            return Err(Error::History(
                "extension replay requires contiguous Blocks from genesis".into(),
            ));
        }
        let confirmation = block.confirmation_profile();
        self.blocks.push(BlockFact {
            block: Block {
                height,
                sealed_at_s: block.sealed_at_s(),
            },
            alpha: sampling::alpha_from_block_hash(block.hash())?,
            sampling: *block.sampling_constants(),
            thresholds: *block.verdict_thresholds(),
            confirm_window_hours: confirmation.window_hours,
            confirm_auditors: confirmation.auditors,
            extension_triggers_max: block.extension_triggers_max(),
        });
        Ok(())
    }

    fn register_deltas(
        &mut self,
        block: &VerifiedBlock,
        declarations: &Declarations,
    ) -> Result<()> {
        let height = block.block().header.block_number;
        let mut pending = Vec::new();
        for entry in block.block().entries.iter() {
            if entry["type"] != "publisher_delta" {
                continue;
            }
            let envelope = &entry["body"];
            let delta = Delta::read(envelope)?;
            let change = match envelope["delta"]["change_type"].as_str() {
                Some("new") => ChangeType::New,
                Some("update") => ChangeType::Update,
                Some("attest") => ChangeType::Attest,
                Some("delete") => ChangeType::Delete,
                _ => return Err(Error::History("sealed Delta has no change type".into())),
            };
            let prev = envelope["delta"]["prev"].as_str().map(str::to_owned);
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
            pending.push((delta, prev, change, excluded));
        }
        while !pending.is_empty() {
            let before = pending.len();
            pending.retain(|(delta, prev, change, excluded)| {
                let index = match prev {
                    None => Some(0),
                    Some(prev) => self.deltas.get(prev).map(|fact| fact.index + 1),
                };
                let Some(index) = index else {
                    return true;
                };
                self.deltas.insert(
                    delta.id.clone(),
                    DeltaFact {
                        height,
                        publisher: delta.domain.clone(),
                        excluded: *excluded,
                        chain: (delta.domain.clone(), delta.url.clone()),
                        index,
                        change: *change,
                    },
                );
                false
            });
            if pending.len() == before {
                return Err(Error::History(
                    "sealed Delta chain is disconnected from its predecessor".into(),
                ));
            }
        }
        Ok(())
    }

    fn escalated_before(&self, publisher: &str, audited_height: u64) -> bool {
        audited_height
            .checked_sub(1)
            .is_some_and(|height| self.escalated_sampling(publisher, height))
    }

    fn classify(
        &mut self,
        block: &VerifiedBlock,
        entry_index: usize,
        body: &Value,
        prior: &dyn Fn(&str, u64) -> PriorState,
    ) -> Result<()> {
        let height = block.block().header.block_number;
        let sealed_at_s = block.sealed_at_s();
        let position = Position {
            block_number: height,
            entry_index,
        };
        let envelope = RecordEnvelope::from_included(body);
        let fields = envelope.fields();
        let record = &body["record"];
        let auditor_id = record["auditor_id"].as_str().unwrap_or("").to_owned();
        let audited_delta = record["audited_delta"].as_str().unwrap_or("").to_owned();
        let verdict = record["verdict"].as_str().and_then(parse_verdict);
        let signed_under = body["sig"]["key_id"].as_str().unwrap_or("");
        let fact = self.deltas.get(&audited_delta);
        let publisher = fact.map(|fact| fact.publisher.clone());
        let audited_height = fact.map(|fact| fact.height);
        let proof = record["vrf_proof"]
            .as_str()
            .and_then(|hex| wist_core::crypto::hex_decode(hex).ok())
            .and_then(|bytes| <[u8; vrf::PROOF_LEN]>::try_from(bytes).ok());

        let (standing, anchor_s) = match (fact, proof) {
            _ if !fields.non_evidence_valid() => (Standing::Void(VoidReason::Malformed), None),
            (_, None) => (Standing::Void(VoidReason::Malformed), None),
            (None, _) => (Standing::Void(VoidReason::UnknownDelta), None),
            (Some(fact), _) if fact.excluded => (Standing::Void(VoidReason::OutsideDomain), None),
            (Some(fact), _) if sampling::self_audit_barred(&auditor_id, &fact.publisher) => {
                (Standing::Void(VoidReason::SelfAudit), None)
            }
            (Some(fact), Some(proof)) => {
                let audited = &self.blocks[fact.height as usize];
                let mut key_seen = false;
                let mut result = None;
                if let Some(beta) = self.beta_at(&auditor_id, audited, &proof, &mut key_seen) {
                    let state = prior(&fact.publisher, fact.height);
                    let p_1e7 = sampling::p_1e7(
                        state.reputation_u,
                        state.level1_sanction,
                        self.escalated_before(&fact.publisher, fact.height),
                        &audited.sampling,
                    );
                    if sampling::selected(sampling::draw(&beta, &audited_delta), p_1e7) {
                        result = Some((Standing::Selected, audited.block.sealed_at_s));
                    }
                }
                if result.is_none() {
                    let named = self
                        .named
                        .get(&(audited_delta.clone(), auditor_id.clone()))
                        .cloned()
                        .unwrap_or_default();
                    for trigger_height in named {
                        let trigger = &self.blocks[trigger_height as usize];
                        if self
                            .beta_at(&auditor_id, trigger, &proof, &mut key_seen)
                            .is_some()
                        {
                            result = Some((
                                Standing::Extension { trigger_height },
                                trigger.block.sealed_at_s,
                            ));
                            break;
                        }
                    }
                }
                match result {
                    Some((standing, anchor)) => (standing, Some(anchor)),
                    None if key_seen => (Standing::Void(VoidReason::ProofWithoutStanding), None),
                    None => (Standing::Void(VoidReason::NoKeyAtBlock), None),
                }
            }
        };

        let own_key = self
            .roster
            .admitted_key_at(&auditor_id, sealed_at_s)
            .map(|key| key.key_id.to_owned());
        let anchor_key = anchor_s
            .and_then(|at| self.roster.admitted_key_at(&auditor_id, at))
            .map(|key| key.key_id.to_owned());
        let (binding_at, duty) = match anchor_s {
            None => (sealed_at_s, Duty::Absent),
            Some(_) if own_key.as_deref() == Some(signed_under) => (sealed_at_s, Duty::Active),
            Some(anchor) if anchor_key.as_deref() == Some(signed_under) => {
                (anchor, Duty::RemovedAfterAnchor)
            }
            Some(_) => (sealed_at_s, Duty::Active),
        };
        let signing = self.roster.signing_binding(&auditor_id, binding_at);
        let authentic = signing.as_ref().is_some_and(|binding| {
            record["auditor_id"] == binding.auditor_id
                && signed_under == binding.key_id
                && wist_core::envelope::verify_envelope(body, "record", binding.public_key).is_ok()
        });
        let semantic_evidence_error = fields.evidence_valid()
            && !self.evidence_semantics_valid(record, fact, anchor_s, sealed_at_s, verdict);
        let disposition = envelope.disposition(&ReplayContext {
            signing,
            duty,
            coverage_failure: false,
            semantic_evidence_error,
        });
        let standing_record = RecordStanding {
            position,
            sealed_at_s,
            auditor_id: auditor_id.clone(),
            audited_delta: audited_delta.clone(),
            publisher: publisher.clone(),
            audited_height,
            verdict,
            standing,
            duty,
            authentic,
            diagnostic: disposition.diagnostic,
            discharges_coverage: disposition.discharges_coverage,
        };
        let evidence = standing_record.evidence();
        self.records.push(standing_record);
        if !evidence {
            return Ok(());
        }
        let (Some(verdict), Some(publisher)) = (verdict, publisher) else {
            return Ok(());
        };
        if matches!(verdict, Verdict::Inconsistent | Verdict::LinkInconsistent) {
            self.trigger(
                position,
                sealed_at_s,
                &auditor_id,
                &audited_delta,
                &publisher,
                verdict,
            );
        }
        self.evidence
            .entry(audited_delta)
            .or_default()
            .push(Evidence {
                position,
                sealed_at_s,
                auditor_id,
                verdict,
            });
        Ok(())
    }

    fn beta_at(
        &self,
        auditor_id: &str,
        block: &BlockFact,
        proof: &[u8; vrf::PROOF_LEN],
        key_seen: &mut bool,
    ) -> Option<[u8; vrf::OUTPUT_LEN]> {
        let key = self
            .roster
            .admitted_key_at(auditor_id, block.block.sealed_at_s)?;
        *key_seen = true;
        let public_key: [u8; 32] = wist_core::crypto::b64u_decode(key.public_key)
            .ok()?
            .try_into()
            .ok()?;
        vrf::verify(&public_key, &block.alpha, proof).ok()
    }

    fn evidence_semantics_valid(
        &self,
        record: &Value,
        audited: Option<&DeltaFact>,
        anchor_s: Option<i64>,
        sealed_at_s: i64,
        verdict: Option<Verdict>,
    ) -> bool {
        let (Some(audited), Some(verdict)) = (audited, verdict) else {
            return false;
        };
        let Ok(fetched_at_s) = record["fetched_at"]
            .as_str()
            .ok_or(())
            .and_then(|at| crate::registry::epoch(at).map_err(|_| ()))
        else {
            return false;
        };
        if fetched_at_s > sealed_at_s || anchor_s.is_some_and(|anchor| fetched_at_s < anchor) {
            return false;
        }
        let Some(reference) = record["reference_delta"]
            .as_str()
            .and_then(|id| self.deltas.get(id))
        else {
            return false;
        };
        if reference.chain != audited.chain
            || reference.index < audited.index
            || self.blocks[reference.height as usize].block.sealed_at_s > fetched_at_s
        {
            return false;
        }
        let score = |name: &str| record.get(name).map(Value::as_u64);
        let (Some(similarity), Some(link_agreement)) = (
            score("similarity").map_or(Some(None), |value| value.map(Some)),
            score("link_agreement").map_or(Some(None), |value| value.map(Some)),
        ) else {
            return false;
        };
        verdict::record_scores_valid(
            reference.change,
            verdict,
            similarity,
            link_agreement,
            &self.blocks[audited.height as usize].thresholds,
        )
    }

    fn trigger(
        &mut self,
        position: Position,
        sealed_at_s: i64,
        auditor_id: &str,
        delta_id: &str,
        publisher: &str,
        verdict: Verdict,
    ) {
        let block = &self.blocks[position.block_number as usize];
        let confirm_window_hours = block.confirm_window_hours;
        let confirm_auditors = block.confirm_auditors;
        let extension_triggers_max = block.extension_triggers_max;
        let window_s = i128::from(confirm_window_hours) * 3_600;
        let mut filers: Vec<String> = Vec::new();
        let mut suppressed = false;
        for earlier in self
            .evidence
            .get(delta_id)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|record| {
                matches!(
                    record.verdict,
                    Verdict::Inconsistent | Verdict::LinkInconsistent
                )
            })
        {
            if i128::from(sealed_at_s) - i128::from(earlier.sealed_at_s) <= window_s {
                suppressed = true;
            }
            filers.push(earlier.auditor_id.clone());
        }
        if suppressed {
            return;
        }
        filers.push(auditor_id.to_owned());
        let prior = self
            .summoning
            .iter()
            .filter(|(auditor, at)| {
                auditor == auditor_id && within_days_ending_at(*at, sealed_at_s, RATION_WINDOW_DAYS)
            })
            .count() as u64;
        let summons = prior < extension_triggers_max;
        let deadline_s = extension::extension_deadline_s(sealed_at_s, confirm_window_hours);
        let summoned: Vec<String> = if summons {
            self.roster
                .admitted_at(sealed_at_s)
                .into_iter()
                .map(|(candidate, _)| candidate.to_owned())
                .filter(|candidate| {
                    independent(candidate, publisher)
                        && filers.iter().all(|filer| independent(candidate, filer))
                })
                .collect()
        } else {
            Vec::new()
        };
        if summons {
            self.summoning.push((auditor_id.to_owned(), sealed_at_s));
        }
        for candidate in &summoned {
            self.named
                .entry((delta_id.to_owned(), candidate.clone()))
                .or_default()
                .push(position.block_number);
            self.duties.push(ExtensionDuty {
                auditor_id: candidate.clone(),
                trigger: position,
                trigger_height: position.block_number,
                delta_id: delta_id.to_owned(),
                publisher: publisher.to_owned(),
                deadline_s,
            });
        }
        self.triggers.push(Trigger {
            position,
            sealed_at_s,
            auditor_id: auditor_id.to_owned(),
            delta_id: delta_id.to_owned(),
            publisher: publisher.to_owned(),
            verdict,
            summons,
            summoned,
            deadline_s,
            confirm_window_hours,
            confirm_auditors,
            outcome: None,
        });
    }

    fn close_extensions(&mut self) -> Result<()> {
        let blocks: Vec<Block> = self.blocks.iter().map(|fact| fact.block).collect();
        let head = *blocks.last().unwrap();
        for index in 0..self.triggers.len() {
            let trigger = &self.triggers[index];
            if trigger.outcome.is_some() {
                continue;
            }
            let end =
                i128::from(trigger.sealed_at_s) + i128::from(trigger.confirm_window_hours) * 3_600;
            if i128::from(head.sealed_at_s) <= end {
                continue;
            }
            let (position, delta_id, publisher, claim) = (
                trigger.position,
                trigger.delta_id.clone(),
                trigger.publisher.clone(),
                ExtensionClaim {
                    trigger_index: 0,
                    summoned: trigger.summons,
                    confirm_window_hours: trigger.confirm_window_hours,
                    confirm_auditors: trigger.confirm_auditors,
                },
            );
            let evidence = self.evidence.get(&delta_id).cloned().unwrap_or_default();
            let records: Vec<ExtensionRecord<'_>> = evidence
                .iter()
                .map(|record| ExtensionRecord {
                    position: CandidateRecord {
                        block_height: record.position.block_number,
                        entry_index: record.position.entry_index as u64,
                        block_sealed_at_s: record.sealed_at_s,
                        auditor_id: &record.auditor_id,
                        effective_similarity: 0,
                    },
                    verdict: sealed_verdict(record.verdict),
                })
                .collect();
            let trigger_index = evidence
                .iter()
                .position(|record| record.position == position)
                .ok_or_else(|| Error::History("triggering Record left its evidence set".into()))?;
            let outcome = extension::evaluate(
                &ExtensionClaim {
                    trigger_index,
                    ..claim
                },
                &records,
                &blocks,
            )?;
            if let Some(established) = outcome.establishing_block {
                self.escalations.push(EscalationRecord {
                    publisher,
                    trigger: position,
                    establishing_height: established.height,
                    establishing_sealed_at_s: established.sealed_at_s,
                });
            }
            self.triggers[index].outcome = Some(outcome);
        }
        Ok(())
    }

    pub fn anchor_hash(&self) -> &[u8; 32] {
        &self.anchor_hash
    }

    pub fn through(&self) -> Option<&BlockRow> {
        self.through.as_ref()
    }

    pub fn roster(&self) -> &RosterHistory {
        &self.roster
    }

    pub fn records(&self) -> &[RecordStanding] {
        &self.records
    }

    pub fn record_at(&self, position: Position) -> Option<&RecordStanding> {
        self.records
            .iter()
            .find(|record| record.position == position)
    }

    pub fn triggers(&self) -> &[Trigger] {
        &self.triggers
    }

    pub fn duties(&self) -> &[ExtensionDuty] {
        &self.duties
    }

    pub fn named(&self, auditor_id: &str, trigger_height: u64) -> Vec<&ExtensionDuty> {
        self.duties
            .iter()
            .filter(|duty| duty.auditor_id == auditor_id && duty.trigger_height == trigger_height)
            .collect()
    }

    pub fn escalations(&self) -> &[EscalationRecord] {
        &self.escalations
    }

    pub fn escalated_sampling(&self, publisher: &str, height: u64) -> bool {
        let Some(at) = self.blocks.get(height as usize) else {
            return false;
        };
        let escalations: Vec<Escalation<'_>> = self
            .escalations
            .iter()
            .map(|record| Escalation {
                publisher_domain: &record.publisher,
                establishing_block: Block {
                    height: record.establishing_height,
                    sealed_at_s: record.establishing_sealed_at_s,
                },
            })
            .collect();
        extension::escalated_sampling(&escalations, publisher, at.block)
    }
}

fn parse_verdict(name: &str) -> Option<Verdict> {
    Some(match name {
        "consistent" => Verdict::Consistent,
        "dynamic_variance" => Verdict::DynamicVariance,
        "inconsistent" => Verdict::Inconsistent,
        "unreachable" => Verdict::Unreachable,
        "not_auditable" => Verdict::NotAuditable,
        "link_variance" => Verdict::LinkVariance,
        "link_inconsistent" => Verdict::LinkInconsistent,
        _ => return None,
    })
}

fn sealed_verdict(verdict: Verdict) -> SealedVerdict {
    match verdict {
        Verdict::Consistent => SealedVerdict::Consistent,
        Verdict::DynamicVariance => SealedVerdict::DynamicVariance,
        Verdict::Inconsistent => SealedVerdict::Inconsistent,
        Verdict::Unreachable => SealedVerdict::Unreachable,
        Verdict::NotAuditable => SealedVerdict::NotAuditable,
        Verdict::LinkVariance => SealedVerdict::LinkVariance,
        Verdict::LinkInconsistent => SealedVerdict::LinkInconsistent,
    }
}
