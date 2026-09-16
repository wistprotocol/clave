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
use wist_core::confirmation::{
    ci_severity, confirming_index_including, independent, CandidateRecord,
};
use wist_core::coverage::{self, within_days_ending_at, Block, COVERAGE_FAILURES_MAX};
use wist_core::crypto::PublicKey;
use wist_core::derivation::{
    age_days, c_count, most_recent_reset, penalty_inputs, ConsistentAudit, DeltaEvent,
};
use wist_core::envelope::verify_envelope;
pub use wist_core::extension::ExtensionOutcome;
use wist_core::extension::{self, Escalation, ExtensionClaim, ExtensionRecord, RATION_WINDOW_DAYS};
use wist_core::objects::audit::Verdict as SealedVerdict;
use wist_core::objects::audit::{RegistryAction, RegistryUpdateEnvelope};
use wist_core::reputation::{
    apply_provisional_cap, base_u, is_provisional, penalty_n_within, reputation_formula_u,
    DecayTable, PROVISIONAL_CAP_U,
};
use wist_core::sampling::{self, SamplingConstants};
use wist_core::sanctions::{Ladder, OrderedFinding, SanctionBlock};
use wist_core::verdict::{self, ChangeType, Thresholds, Verdict};
use wist_core::vrf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorState {
    pub reputation_u: u64,
    pub level1_sanction: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationState {
    pub age_days: u64,
    pub c: u64,
    pub penalty_n: u128,
    pub provisional: bool,
    pub reputation_u: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub publisher: String,
    pub delta_id: String,
    pub link: bool,
    pub audited_height: u64,
    pub confirming: Position,
    pub confirming_sealed_at_s: i64,
    pub confirming_record_id: String,
    pub severity: u8,
}

struct FindingRecord {
    position: Position,
    sealed_at_s: i64,
    auditor_id: String,
    effective_similarity: u64,
    confirm_window_hours: u64,
    confirm_auditors: u64,
}

struct AcceptedAudit {
    height: u64,
    audited_height: u64,
    url: String,
    change: ChangeType,
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
    pub reference_delta: Option<String>,
    pub similarity: Option<u64>,
    pub record_id: Option<String>,
    pub standing: Standing,
    pub duty: Duty,
    pub authentic: bool,
    pub coverage_failure: bool,
    pub diagnostic: Option<&'static str>,
    pub discharges_coverage: bool,
}

impl RecordStanding {
    pub fn evidence(&self) -> bool {
        self.diagnostic.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullAttestation {
    pub position: Position,
    pub found: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageDuty {
    pub auditor_id: String,
    pub height: u64,
    pub sealed_at_s: i64,
    pub deadline_s: i128,
    pub seal_blocks: u64,
    pub beta: Option<[u8; vrf::OUTPUT_LEN]>,
    pub selection: Option<Vec<String>>,
    pub named: Vec<String>,
    pub discharged: BTreeMap<String, u64>,
    pub attested_empty_at: Option<u64>,
    pub pull: Option<PullAttestation>,
    pub successors_after_deadline: u64,
    pub unattested_height: Option<u64>,
    pub complete_at: Option<u64>,
}

impl CoverageDuty {
    pub fn establishing_height(&self) -> Option<u64> {
        let attested = self.pull.as_ref().map(|pull| pull.position.block_number);
        match (attested, self.unattested_height) {
            (Some(a), Some(u)) => Some(a.min(u)),
            (a, u) => a.or(u),
        }
    }

    pub fn duty_set(&self) -> Option<Vec<String>> {
        let mut set = self.selection.clone()?;
        for delta in &self.named {
            if !set.contains(delta) {
                set.push(delta.clone());
            }
        }
        Some(set)
    }

    pub fn published(&self) -> bool {
        self.beta.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedAct {
    pub position: Position,
    pub action: String,
    pub subject: String,
    pub code: &'static str,
    pub reason: String,
}

#[derive(Clone)]
struct Publication {
    auditor_id: String,
    height: u64,
    prev_record: Option<String>,
    authentic: bool,
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
    coverage: super::coverage::CoverageProfile,
    decay_horizon_days: u64,
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
    heights: BTreeMap<String, u64>,
    deltas: BTreeMap<String, DeltaFact>,
    deltas_by_height: BTreeMap<u64, Vec<String>>,
    roster: RosterHistory,
    records: Vec<RecordStanding>,
    pending: Vec<(usize, Option<&'static str>, bool)>,
    evidence: BTreeMap<String, Vec<Evidence>>,
    summoning: Vec<(String, i64)>,
    named: BTreeMap<(String, String), Vec<u64>>,
    triggers: Vec<Trigger>,
    duties: Vec<ExtensionDuty>,
    escalations: Vec<EscalationRecord>,
    coverage: BTreeMap<(String, u64), CoverageDuty>,
    publications: Vec<Publication>,
    sealed_ids: BTreeMap<String, u64>,
    rejected_acts: Vec<RejectedAct>,
    resets: BTreeMap<String, Vec<u64>>,
    accepted: BTreeMap<String, Vec<DeltaEvent>>,
    audits: BTreeMap<String, Vec<AcceptedAudit>>,
    finding_records: BTreeMap<(String, bool), Vec<FindingRecord>>,
    findings: Vec<Finding>,
    ladders: BTreeMap<String, Ladder>,
    rungs: BTreeMap<String, Vec<(u64, u8)>>,
    block_resets: Vec<String>,
    block_lifts: Vec<String>,
}

impl ExtensionHistory {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>) -> Result<Self> {
        let mut history = History::open(directory, head.clone())?;
        let mut declarations = Declarations::default();
        let mut chains = Chains::default();
        let mut replay = Self {
            anchor_hash: history.anchor_hash,
            through: head,
            blocks: Vec::new(),
            heights: BTreeMap::new(),
            deltas: BTreeMap::new(),
            deltas_by_height: BTreeMap::new(),
            roster: RosterHistory::start(&history),
            records: Vec::new(),
            pending: Vec::new(),
            evidence: BTreeMap::new(),
            summoning: Vec::new(),
            named: BTreeMap::new(),
            triggers: Vec::new(),
            duties: Vec::new(),
            escalations: Vec::new(),
            coverage: BTreeMap::new(),
            publications: Vec::new(),
            sealed_ids: BTreeMap::new(),
            rejected_acts: Vec::new(),
            resets: BTreeMap::new(),
            accepted: BTreeMap::new(),
            audits: BTreeMap::new(),
            finding_records: BTreeMap::new(),
            findings: Vec::new(),
            ladders: BTreeMap::new(),
            rungs: BTreeMap::new(),
            block_resets: Vec::new(),
            block_lifts: Vec::new(),
        };
        while let Some(block) = history.next_block()? {
            let effects = declarations.apply(&block)?;
            for installation in &effects.installations {
                if installation.resets_identity {
                    let domain = installation.declaration.envelope()["publisher"]["domain"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned();
                    replay
                        .resets
                        .entry(domain.clone())
                        .or_default()
                        .push(block.block().header.block_number);
                    replay.block_resets.push(domain);
                }
            }
            chains.apply(&block, &declarations)?;
            replay
                .roster
                .apply(&block, history.log_key_id(), history.log_key())?;
            replay.register_block(&block)?;
            replay.register_deltas(&block, &declarations)?;
            replay.open_duties(&block);
            for (entry_index, entry) in block.block().entries.iter().enumerate() {
                match entry["type"].as_str() {
                    Some("registry_update") => replay.registry_update(
                        &block,
                        entry_index,
                        &entry["body"],
                        history.log_key_id(),
                        history.log_key(),
                    )?,
                    Some("audit_record") => replay.classify(&block, entry_index, &entry["body"])?,
                    _ => {}
                }
            }
            replay.settle(&block)?;
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
        self.heights.insert(block.hash().to_owned(), height);
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
            coverage: *block.coverage_profile(),
            decay_horizon_days: block.decay_horizon_days(),
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
                self.deltas_by_height
                    .entry(height)
                    .or_default()
                    .push(delta.id.clone());
                self.accepted
                    .entry(delta.domain.clone())
                    .or_default()
                    .push(DeltaEvent {
                        height,
                        sealed_at_s: self.blocks[height as usize].block.sealed_at_s,
                    });
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

    fn classify(&mut self, block: &VerifiedBlock, entry_index: usize, body: &Value) -> Result<()> {
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
        let mut betas: Vec<(u64, [u8; vrf::OUTPUT_LEN])> = Vec::new();

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
                    betas.push((fact.height, beta));
                    let state = self.prior_state(&fact.publisher, fact.height.checked_sub(1));
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
                        if let Some(beta) =
                            self.beta_at(&auditor_id, trigger, &proof, &mut key_seen)
                        {
                            betas.push((trigger_height, beta));
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
        for (duty_height, beta) in betas {
            if let Some(pair) = self.coverage.get_mut(&(auditor_id.clone(), duty_height)) {
                pair.beta.get_or_insert(beta);
            }
        }
        let anchor_height = match standing {
            Standing::Selected => audited_height,
            Standing::Extension { trigger_height } => Some(trigger_height),
            Standing::Void(_) => None,
        };
        if disposition.discharges_coverage {
            if let Some(pair) = anchor_height
                .and_then(|anchor| self.coverage.get_mut(&(auditor_id.clone(), anchor)))
            {
                pair.discharged
                    .entry(audited_delta.clone())
                    .or_insert(height);
            }
        }
        let record_id = wist_core::delta::delta_id(record).ok();
        if let Some(id) = &record_id {
            self.sealed_ids.entry(id.clone()).or_insert(height);
        }
        self.publications.push(Publication {
            auditor_id: auditor_id.clone(),
            height,
            prev_record: record["prev_record"].as_str().map(str::to_owned),
            authentic: authentic && fields.non_evidence_valid(),
        });
        self.pending.push((
            self.records.len(),
            fields.diagnostic(),
            fields.supported_major(),
        ));
        self.records.push(RecordStanding {
            position,
            sealed_at_s,
            auditor_id,
            audited_delta,
            publisher,
            audited_height,
            verdict,
            reference_delta: record["reference_delta"].as_str().map(str::to_owned),
            similarity: record["similarity"].as_u64(),
            record_id,
            standing,
            duty,
            authentic,
            coverage_failure: false,
            diagnostic: disposition.diagnostic,
            discharges_coverage: disposition.discharges_coverage,
        });
        Ok(())
    }

    fn open_duties(&mut self, block: &VerifiedBlock) {
        let height = block.block().header.block_number;
        let sealed_at_s = block.sealed_at_s();
        let profile = self.blocks[height as usize].coverage;
        for (auditor_id, _) in self.roster.admitted_at(sealed_at_s) {
            self.coverage.insert(
                (auditor_id.to_owned(), height),
                CoverageDuty {
                    auditor_id: auditor_id.to_owned(),
                    height,
                    sealed_at_s,
                    deadline_s: i128::from(sealed_at_s)
                        + i128::from(profile.deadline_hours) * 3_600,
                    seal_blocks: profile.seal_blocks,
                    beta: None,
                    selection: None,
                    named: Vec::new(),
                    discharged: BTreeMap::new(),
                    attested_empty_at: None,
                    pull: None,
                    successors_after_deadline: 0,
                    unattested_height: None,
                    complete_at: None,
                },
            );
        }
    }

    fn registry_update(
        &mut self,
        block: &VerifiedBlock,
        entry_index: usize,
        body: &Value,
        log_key_id: &str,
        log_key: &PublicKey,
    ) -> Result<()> {
        let action = body["update"]["action"].as_str().unwrap_or("");
        if !matches!(
            action,
            "pull_attestation" | "coverage_attestation" | "sanction_lift"
        ) {
            return Ok(());
        }
        let position = Position {
            block_number: block.block().header.block_number,
            entry_index,
        };
        if let Err((code, reason)) = self.attest_inner(block, position, body, log_key_id, log_key) {
            self.rejected_acts.push(RejectedAct {
                position,
                action: action.to_owned(),
                subject: body["update"]["subject"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                code,
                reason: format!("{code}: {reason}"),
            });
        }
        Ok(())
    }

    fn attest_inner(
        &mut self,
        block: &VerifiedBlock,
        position: Position,
        body: &Value,
        log_key_id: &str,
        log_key: &PublicKey,
    ) -> std::result::Result<(), (&'static str, String)> {
        let height = position.block_number;
        let sealed_at_s = block.sealed_at_s();
        if let Ok(id) = crate::governance::update_id(&body["update"]) {
            self.sealed_ids.entry(id).or_insert(height);
        }
        let envelope: RegistryUpdateEnvelope =
            serde_json::from_value(body.clone()).map_err(|e| {
                (
                    "WIST4-E11",
                    format!("malformed Registry Update envelope: {e}"),
                )
            })?;
        let update = &envelope.update;
        if !crate::record::release(&update.wist_version)
            || update.wist_version.split('.').next() != Some("1")
        {
            return Err(("WIST4-E11", "unsupported Registry Update version".into()));
        }
        if crate::registry::epoch(&update.effective_at).is_err() {
            return Err((
                "WIST4-E11",
                "effective_at is not a whole-second UTC instant".into(),
            ));
        }
        if envelope.sig.alg != "Ed25519"
            || envelope.sig.key_id.chars().count() > 64
            || !canonical_b64u(&envelope.sig.value, 64)
        {
            return Err(("WIST4-E11", "malformed signature fields".into()));
        }
        if !crate::record::hostname_subject(&update.subject) {
            return Err((
                "WIST4-E04",
                "subject is not a hostname of at least two labels".into(),
            ));
        }
        if matches!(update.action, RegistryAction::SanctionLift) {
            if envelope.sig.key_id != log_key_id
                || verify_envelope(body, "update", log_key).is_err()
            {
                return Err((
                    "WIST4-E11",
                    "signature does not verify under the Log key".into(),
                ));
            }
            self.block_lifts.push(update.subject.clone());
            return Ok(());
        }
        let details = update
            .details
            .as_ref()
            .filter(|details| details.is_object())
            .ok_or(("WIST4-E04", "details are missing".to_owned()))?;
        let block_hash = details["block"]
            .as_str()
            .filter(|hash| digest(hash))
            .ok_or(("WIST4-E04", "details.block is not a Block Hash".to_owned()))?;
        let subject = update.subject.clone();
        let duty_height = self
            .heights
            .get(block_hash)
            .copied()
            .filter(|duty| *duty < height);
        let duty_sealed_at_s = duty_height.map(|duty| self.blocks[duty as usize].block.sealed_at_s);
        enum Parsed {
            Pull(Vec<String>),
            Coverage([u8; vrf::PROOF_LEN], Option<String>),
        }
        let parsed = match update.action {
            RegistryAction::PullAttestation => Parsed::Pull(
                details["found"]
                    .as_array()
                    .ok_or(("WIST4-E04", "details.found is not an array".to_owned()))?
                    .iter()
                    .map(|id| {
                        id.as_str()
                            .filter(|id| digest(id))
                            .map(str::to_owned)
                            .ok_or((
                                "WIST4-E04",
                                "details.found carries a malformed ID".to_owned(),
                            ))
                    })
                    .collect::<std::result::Result<_, _>>()?,
            ),
            RegistryAction::CoverageAttestation => {
                let proof = details["vrf_proof"]
                    .as_str()
                    .filter(|hex| {
                        hex.len() == 2 * vrf::PROOF_LEN
                            && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                    })
                    .and_then(|hex| wist_core::crypto::hex_decode(hex).ok())
                    .and_then(|bytes| <[u8; vrf::PROOF_LEN]>::try_from(bytes).ok())
                    .ok_or(("WIST4-E04", "details.vrf_proof is malformed".to_owned()))?;
                let prev_record = match details.get("prev_record") {
                    Some(Value::Null) => None,
                    Some(Value::String(id)) if digest(id) => Some(id.clone()),
                    _ => {
                        return Err((
                            "WIST4-E04",
                            "details.prev_record is neither null nor an ID".into(),
                        ))
                    }
                };
                Parsed::Coverage(proof, prev_record)
            }
            _ => unreachable!("only attestation actions reach attest_inner"),
        };
        let authentic = match &parsed {
            Parsed::Pull(_) => {
                envelope.sig.key_id == log_key_id
                    && verify_envelope(body, "update", log_key).is_ok()
            }
            Parsed::Coverage(..) => [
                self.roster.admitted_key_at(&subject, sealed_at_s),
                duty_sealed_at_s.and_then(|at| self.roster.admitted_key_at(&subject, at)),
            ]
            .into_iter()
            .flatten()
            .find(|key| key.key_id == envelope.sig.key_id)
            .is_some_and(|key| {
                PublicKey::from_b64u(key.public_key)
                    .is_ok_and(|key| verify_envelope(body, "update", &key).is_ok())
            }),
        };
        if !authentic {
            return Err((
                "WIST4-E11",
                "signature does not verify under the key the action's signing rule names".into(),
            ));
        }
        let duty_height = duty_height.ok_or((
            "WIST4-E04",
            "details.block names no earlier sealed Block".to_owned(),
        ))?;
        if !self.coverage.contains_key(&(subject.clone(), duty_height)) {
            return Err((
                "WIST4-E04",
                "the subject held no coverage duty for the named Block".into(),
            ));
        }
        match parsed {
            Parsed::Pull(found) => {
                let pair = self.coverage.get_mut(&(subject, duty_height)).unwrap();
                if pair.pull.is_none() {
                    pair.pull = Some(PullAttestation { position, found });
                }
            }
            Parsed::Coverage(proof, prev_record) => {
                let mut key_seen = false;
                let beta = self
                    .beta_at(
                        &subject,
                        &self.blocks[duty_height as usize],
                        &proof,
                        &mut key_seen,
                    )
                    .ok_or((
                        "WIST4-E01",
                        "vrf_proof does not verify over the named Block".to_owned(),
                    ))?;
                self.publications.push(Publication {
                    auditor_id: subject.clone(),
                    height,
                    prev_record,
                    authentic: true,
                });
                let pair = self.coverage.get_mut(&(subject, duty_height)).unwrap();
                pair.beta.get_or_insert(beta);
                pair.attested_empty_at.get_or_insert(height);
            }
        }
        Ok(())
    }

    fn settle(&mut self, block: &VerifiedBlock) -> Result<()> {
        let height = block.block().header.block_number;
        let sealed_at_s = block.sealed_at_s();
        for pair in self.coverage.values_mut() {
            if pair.height < height
                && pair.unattested_height.is_none()
                && i128::from(sealed_at_s) > pair.deadline_s
            {
                pair.successors_after_deadline += 1;
                if pair.successors_after_deadline == pair.seal_blocks {
                    pair.unattested_height = Some(height);
                }
            }
        }
        let underived: Vec<(String, u64)> = self
            .coverage
            .iter()
            .filter(|(_, pair)| pair.beta.is_some() && pair.selection.is_none())
            .map(|(key, _)| key.clone())
            .collect();
        for key in underived {
            let selection = self.derive_selection(&key.0, key.1);
            self.coverage.get_mut(&key).unwrap().selection = Some(selection);
        }
        for pair in self.coverage.values_mut() {
            if pair.complete_at.is_some() {
                continue;
            }
            let Some(set) = pair.duty_set() else {
                continue;
            };
            pair.complete_at = if set.is_empty() {
                pair.attested_empty_at
            } else {
                set.iter()
                    .map(|delta| pair.discharged.get(delta).copied())
                    .collect::<Option<Vec<u64>>>()
                    .and_then(|heights| heights.into_iter().max())
            };
        }
        let pending = std::mem::take(&mut self.pending);
        let mut failing: BTreeMap<String, bool> = BTreeMap::new();
        let mut new_findings: BTreeMap<String, Vec<OrderedFinding>> = BTreeMap::new();
        for (index, field_diagnostic, supported_major) in pending {
            let auditor_id = self.records[index].auditor_id.clone();
            let in_failure = match failing.get(&auditor_id) {
                Some(state) => *state,
                None => {
                    let state = self.in_coverage_failure(&auditor_id, height);
                    failing.insert(auditor_id.clone(), state);
                    state
                }
            };
            if in_failure {
                let record = &mut self.records[index];
                record.coverage_failure = true;
                if field_diagnostic.is_none() && supported_major {
                    record.diagnostic = Some("WIST4-E01");
                }
            }
            let record = &self.records[index];
            if !record.evidence() {
                continue;
            }
            let (Some(verdict), Some(publisher)) = (record.verdict, record.publisher.clone())
            else {
                continue;
            };
            let (position, sealed_at_s, audited_delta) = (
                record.position,
                record.sealed_at_s,
                record.audited_delta.clone(),
            );
            let bindings = record
                .reference_delta
                .as_deref()
                .and_then(|id| self.deltas.get(id))
                .zip(self.deltas.get(&audited_delta))
                .map(|(reference, audited)| {
                    (audited.height, audited.chain.1.clone(), reference.change)
                });
            let Some((audited_height, url, change)) = bindings else {
                return Err(Error::History(
                    "evidence Record lost its authenticated Delta bindings".into(),
                ));
            };
            match verdict {
                Verdict::Consistent => {
                    self.audits
                        .entry(publisher.clone())
                        .or_default()
                        .push(AcceptedAudit {
                            height,
                            audited_height,
                            url,
                            change,
                        });
                }
                Verdict::Inconsistent | Verdict::LinkInconsistent => {
                    if let Some(finding) = self.confirm(
                        index,
                        &publisher,
                        &audited_delta,
                        audited_height,
                        change,
                        verdict == Verdict::LinkInconsistent,
                    ) {
                        new_findings
                            .entry(publisher.clone())
                            .or_default()
                            .push(finding);
                    }
                }
                _ => {}
            }
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
        }
        let resets = std::mem::take(&mut self.block_resets);
        let lifts = std::mem::take(&mut self.block_lifts);
        let mut publishers: Vec<String> = resets.iter().chain(&lifts).cloned().collect();
        publishers.extend(new_findings.keys().cloned());
        publishers.sort();
        publishers.dedup();
        for publisher in publishers {
            let ladder = self.ladders.entry(publisher.clone()).or_default();
            ladder.apply_block(SanctionBlock {
                height,
                sealed_at_s,
                reset: resets.contains(&publisher),
                lift: lifts.contains(&publisher),
                voids: &[],
                findings: new_findings
                    .get(&publisher)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            });
            let level = ladder.level();
            let rungs = self.rungs.entry(publisher).or_default();
            if rungs.last().is_none_or(|(_, recorded)| *recorded != level) {
                rungs.push((height, level));
            }
        }
        Ok(())
    }

    fn confirm(
        &mut self,
        index: usize,
        publisher: &str,
        delta_id: &str,
        audited_height: u64,
        change: ChangeType,
        link: bool,
    ) -> Option<OrderedFinding> {
        if self
            .findings
            .iter()
            .any(|finding| finding.delta_id == delta_id && finding.link == link)
        {
            return None;
        }
        let record = &self.records[index];
        let id: [u8; 32] = record
            .record_id
            .as_deref()
            .and_then(|id| id.strip_prefix("sha256:"))
            .and_then(|hex| wist_core::crypto::hex_decode(hex).ok())
            .and_then(|bytes| bytes.try_into().ok())?;
        let block = &self.blocks[record.position.block_number as usize];
        let entry = FindingRecord {
            position: record.position,
            sealed_at_s: record.sealed_at_s,
            auditor_id: record.auditor_id.clone(),
            effective_similarity: verdict::effective_similarity(
                record.similarity.unwrap_or(0),
                change,
            ),
            confirm_window_hours: block.confirm_window_hours,
            confirm_auditors: block.confirm_auditors,
        };
        let (position, sealed_at_s) = (record.position, record.sealed_at_s);
        let records = self
            .finding_records
            .entry((delta_id.to_owned(), link))
            .or_default();
        records.push(entry);
        let candidates: Vec<CandidateRecord<'_>> = records
            .iter()
            .map(|r| CandidateRecord {
                block_height: r.position.block_number,
                entry_index: r.position.entry_index as u64,
                block_sealed_at_s: r.sealed_at_s,
                auditor_id: &r.auditor_id,
                effective_similarity: r.effective_similarity,
            })
            .collect();
        let last = candidates.len() - 1;
        let confirmed = confirming_index_including(
            &candidates,
            records[last].confirm_window_hours,
            records[last].confirm_auditors,
            last,
        )
        .ok()
        .flatten()
        .is_some_and(|i| i == last);
        if !confirmed {
            return None;
        }
        let severity = if link {
            1
        } else {
            ci_severity(&candidates, last).ok()?
        };
        let confirming_record_id = format!("sha256:{}", wist_core::crypto::hex_encode(&id));
        self.findings.push(Finding {
            publisher: publisher.to_owned(),
            delta_id: delta_id.to_owned(),
            link,
            audited_height,
            confirming: position,
            confirming_sealed_at_s: sealed_at_s,
            confirming_record_id,
            severity,
        });
        let reset = most_recent_reset(
            self.resets
                .get(publisher)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            position.block_number,
        );
        if reset.is_some_and(|r| audited_height < r) {
            return None;
        }
        Some(OrderedFinding {
            record_id: id,
            entry_index: position.entry_index as u64,
            severity,
        })
    }

    pub fn reputation(&self, publisher: &str, height: u64) -> Option<ReputationState> {
        let at = self.blocks.get(height as usize)?;
        let reset = most_recent_reset(
            self.resets
                .get(publisher)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            height,
        );
        let accepted = self
            .accepted
            .get(publisher)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let age_days = age_days(accepted, reset, height, at.block.sealed_at_s).ok()?;
        let audits: Vec<ConsistentAudit<'_>> = self
            .audits
            .get(publisher)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|audit| ConsistentAudit {
                height: audit.height,
                audited_height: audit.audited_height,
                url: &audit.url,
                change: audit.change,
            })
            .collect();
        let c = c_count(&audits, reset, height);
        let findings: Vec<wist_core::derivation::ConfirmedFinding<'_>> = self
            .findings
            .iter()
            .filter(|finding| {
                finding.publisher == publisher && finding.confirming.block_number <= height
            })
            .map(|finding| wist_core::derivation::ConfirmedFinding {
                confirming_height: finding.confirming.block_number,
                audited_height: finding.audited_height,
                confirming_sealed_at_s: finding.confirming_sealed_at_s,
                delta_id: &finding.delta_id,
                severity: finding.severity,
            })
            .collect();
        let inputs = penalty_inputs(&findings, reset, height, at.block.sealed_at_s).ok()?;
        let penalty_n = penalty_n_within(&inputs, DecayTable::builtin(), at.decay_horizon_days);
        let formula = reputation_formula_u(base_u(age_days), c, penalty_n);
        Some(ReputationState {
            age_days,
            c,
            penalty_n,
            provisional: is_provisional(age_days, c),
            reputation_u: apply_provisional_cap(formula, age_days, c),
        })
    }

    pub fn sanction_level(&self, publisher: &str, height: u64) -> u8 {
        self.rungs
            .get(publisher)
            .and_then(|rungs| rungs.iter().rev().find(|(at, _)| *at <= height))
            .map_or(0, |(_, level)| *level)
    }

    pub fn level1_sanction(&self, publisher: &str, height: u64) -> bool {
        self.sanction_level(publisher, height) >= 1
    }

    pub fn prior_state(&self, publisher: &str, height: Option<u64>) -> PriorState {
        let Some(height) = height else {
            return PriorState {
                reputation_u: PROVISIONAL_CAP_U,
                level1_sanction: false,
            };
        };
        PriorState {
            reputation_u: self
                .reputation(publisher, height)
                .map_or(PROVISIONAL_CAP_U, |state| state.reputation_u),
            level1_sanction: self.level1_sanction(publisher, height),
        }
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    fn derive_selection(&self, auditor_id: &str, height: u64) -> Vec<String> {
        let block = &self.blocks[height as usize];
        let beta = self.coverage[&(auditor_id.to_owned(), height)]
            .beta
            .expect("selection is derived from a sealed proof");
        let mut selection: Vec<String> = self
            .deltas_by_height
            .get(&height)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|id| {
                let fact = &self.deltas[*id];
                if fact.excluded || sampling::self_audit_barred(auditor_id, &fact.publisher) {
                    return false;
                }
                let state = self.prior_state(&fact.publisher, height.checked_sub(1));
                let p_1e7 = sampling::p_1e7(
                    state.reputation_u,
                    state.level1_sanction,
                    self.escalated_before(&fact.publisher, height),
                    &block.sampling,
                );
                sampling::selected(sampling::draw(&beta, id), p_1e7)
            })
            .cloned()
            .collect();
        selection.sort();
        selection
    }

    fn exempt(&self, pair: &CoverageDuty, height: u64) -> bool {
        let Some(pull) = &pair.pull else {
            return false;
        };
        let from = pull.position.block_number;
        from <= height
            && self.publications.iter().any(|publication| {
                publication.auditor_id == pair.auditor_id
                    && publication.authentic
                    && (from..=height).contains(&publication.height)
                    && publication.prev_record.as_deref().is_some_and(|prev| {
                        pull.found.iter().any(|found| found == prev)
                            && !self
                                .sealed_ids
                                .get(prev)
                                .is_some_and(|sealed| *sealed <= height)
                    })
            })
    }

    fn counts_at(&self, pair: &CoverageDuty, height: u64, sealed_at_s: i64) -> bool {
        coverage::failure_counts_at(
            pair.establishing_height(),
            pair.sealed_at_s,
            height,
            sealed_at_s,
        ) && !pair.complete_at.is_some_and(|complete| complete <= height)
            && !self.exempt(pair, height)
    }

    pub fn counting_failures(&self, auditor_id: &str, height: u64) -> Vec<u64> {
        let Some(at) = self.blocks.get(height as usize) else {
            return Vec::new();
        };
        self.coverage
            .range((auditor_id.to_owned(), 0)..=(auditor_id.to_owned(), height))
            .filter(|(_, pair)| self.counts_at(pair, height, at.block.sealed_at_s))
            .map(|(key, _)| key.1)
            .collect()
    }

    pub fn in_coverage_failure(&self, auditor_id: &str, height: u64) -> bool {
        let Some(at) = self.blocks.get(height as usize) else {
            return false;
        };
        let times: Vec<i64> = self
            .counting_failures(auditor_id, height)
            .into_iter()
            .map(|duty| self.blocks[duty as usize].block.sealed_at_s)
            .collect();
        coverage::in_coverage_failure(&times, at.block.sealed_at_s, COVERAGE_FAILURES_MAX)
    }

    pub fn coverage_duties(&self) -> impl Iterator<Item = &CoverageDuty> {
        self.coverage.values()
    }

    pub fn coverage_duty(&self, auditor_id: &str, height: u64) -> Option<&CoverageDuty> {
        self.coverage.get(&(auditor_id.to_owned(), height))
    }

    pub fn rejected_acts(&self) -> &[RejectedAct] {
        &self.rejected_acts
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
            if let Some(pair) = self
                .coverage
                .get_mut(&(candidate.clone(), position.block_number))
            {
                pair.named.push(delta_id.to_owned());
            }
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

fn canonical_b64u(value: &str, octets: usize) -> bool {
    wist_core::crypto::b64u_decode(value)
        .is_ok_and(|bytes| bytes.len() == octets && wist_core::crypto::b64u_encode(&bytes) == value)
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
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
