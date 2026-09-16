use super::declarations::Position;
use super::{History, VerifiedBlock};
use crate::db::BlockRow;
use crate::error::{Error, Result};
use crate::record::SigningBinding;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use wist_core::crypto::PublicKey;
use wist_core::envelope::verify_envelope;
use wist_core::objects::audit::{RegistryDetails, RegistryUpdateEnvelope, TrackRecord};
use wist_core::roster::{
    validate_admission_evidence, ObserverCheckpoint, ObserverRegistration, Roster, RosterAct,
    RosterAction,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedAct {
    pub position: Position,
    pub action: String,
    pub subject: String,
    pub code: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBinding<'a> {
    pub key_id: &'a str,
    pub public_key: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tenure {
    pub from_s: i64,
    pub until_s: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCheckpoint {
    pub observer_id: String,
    pub height: u64,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rejection {
    pub action: String,
    pub subject: String,
    pub code: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RosterCandidate {
    pub action: RosterAction,
    pub subject: String,
    pub key_id: String,
    pub public_key: String,
    pub track_record: Option<TrackRecord>,
}

#[derive(Debug, Clone)]
pub(crate) struct CheckpointCandidate {
    pub subject: String,
    pub key_id: String,
    pub id: String,
}

#[derive(Debug, Clone)]
pub(crate) enum RosterEntry {
    Act(RosterCandidate),
    Checkpoint(CheckpointCandidate),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcceptedAct {
    pub action: String,
    pub subject: String,
    pub key_id: String,
    pub public_key: String,
    pub for_cause: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    NotRoster,
    Accepted(AcceptedAct),
    Rejected(Rejection),
    Idempotent,
}

#[derive(Clone)]
pub struct RosterHistory {
    anchor_hash: [u8; 32],
    through: Option<BlockRow>,
    log_id: String,
    hashes: Vec<[u8; 32]>,
    roster: Roster,
    verifiers: BTreeMap<String, Option<PublicKey>>,
    registrations: Vec<(String, u64)>,
    checkpoints: Vec<SealedCheckpoint>,
    rejected: Vec<RejectedAct>,
    accepted_ids: BTreeSet<String>,
    idempotent: Vec<Position>,
}

const ROSTER_ACTIONS: [&str; 4] = [
    "auditor_admit",
    "auditor_remove",
    "observer_register",
    "observer_checkpoint",
];

impl RosterHistory {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>) -> Result<Self> {
        let mut history = History::open(directory, head)?;
        let mut roster = Self::start(&history);
        while let Some(block) = history.next_block()? {
            roster.apply(&block, history.log_key_id(), history.log_key())?;
        }
        Ok(roster)
    }

    pub(crate) fn start(history: &History) -> Self {
        Self {
            anchor_hash: history.anchor_hash,
            through: history.head.clone(),
            log_id: history.log_id().to_owned(),
            hashes: Vec::new(),
            roster: Roster::new(history.log_id()),
            verifiers: BTreeMap::new(),
            registrations: Vec::new(),
            checkpoints: Vec::new(),
            rejected: Vec::new(),
            accepted_ids: BTreeSet::new(),
            idempotent: Vec::new(),
        }
    }

    pub(crate) fn apply(
        &mut self,
        block: &VerifiedBlock,
        log_key_id: &str,
        log_key: &PublicKey,
    ) -> Result<()> {
        let height = block.block().header.block_number;
        if self.hashes.len() as u64 != height {
            return Err(Error::History(
                "roster replay requires contiguous Blocks from genesis".into(),
            ));
        }
        let hash = block
            .hash()
            .strip_prefix("sha256:")
            .and_then(|hex| wist_core::crypto::hex_decode(hex).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| Error::History("Block hash is not a sha256 digest".into()))?;
        self.hashes.push(hash);
        let outcomes = self.apply_entries(
            height,
            block.sealed_at_s(),
            &block.block().entries,
            log_key_id,
            log_key,
        )?;
        for (entry_index, outcome) in outcomes.into_iter().enumerate() {
            let position = Position {
                block_number: height,
                entry_index,
            };
            match outcome {
                Outcome::Rejected(rejection) => self.rejected.push(RejectedAct {
                    position,
                    action: rejection.action,
                    subject: rejection.subject,
                    code: rejection.code,
                    reason: rejection.reason,
                }),
                Outcome::Idempotent => self.idempotent.push(position),
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) fn apply_entries(
        &mut self,
        height: u64,
        sealed_at_s: i64,
        entries: &[Value],
        log_key_id: &str,
        log_key: &PublicKey,
    ) -> Result<Vec<Outcome>> {
        let mut outcomes = vec![Outcome::NotRoster; entries.len()];
        let mut acts: Vec<(usize, RosterCandidate)> = Vec::new();
        let mut checkpoints: Vec<(usize, CheckpointCandidate)> = Vec::new();
        let mut ids: BTreeMap<usize, String> = BTreeMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if entry["type"] != "registry_update" {
                continue;
            }
            let classified = match classify(&entry["body"], log_key_id, log_key) {
                None => continue,
                Some(Err(rejection)) => {
                    outcomes[index] = Outcome::Rejected(rejection);
                    continue;
                }
                Some(Ok(classified)) => classified,
            };
            if let Ok(id) = crate::governance::update_id(&entry["body"]["update"]) {
                if self.accepted_ids.contains(&id) || ids.values().any(|seen| *seen == id) {
                    outcomes[index] = Outcome::Idempotent;
                    continue;
                }
                ids.insert(index, id);
            }
            match classified {
                RosterEntry::Act(candidate) => acts.push((index, candidate)),
                RosterEntry::Checkpoint(candidate) => checkpoints.push((index, candidate)),
            }
        }
        let roster_acts: Vec<RosterAct<'_>> = acts
            .iter()
            .map(|(_, c)| RosterAct {
                action: c.action,
                auditor_id: &c.subject,
                key_id: &c.key_id,
                public_key: &c.public_key,
            })
            .collect();
        let registrations: Vec<ObserverRegistration<'_>> = self
            .registrations
            .iter()
            .map(|(observer_id, height)| ObserverRegistration {
                observer_id,
                height: *height,
            })
            .collect();
        let sealed_checkpoints: Vec<ObserverCheckpoint<'_>> = self
            .checkpoints
            .iter()
            .map(|c| ObserverCheckpoint {
                observer_id: &c.observer_id,
                height: c.height,
                update_id: &c.id,
            })
            .collect();
        let rejected: BTreeMap<usize, wist_core::Error> = self
            .roster
            .apply_block_checked(sealed_at_s, &roster_acts, |i| {
                let candidate = &acts[i].1;
                if candidate.action == RosterAction::Admit {
                    validate_admission_evidence(
                        &candidate.subject,
                        height,
                        &registrations,
                        &sealed_checkpoints,
                        candidate.track_record.as_ref(),
                    )
                } else {
                    Ok(())
                }
            })
            .map_err(|e| Error::History(format!("roster replay failed: {e}")))?
            .into_iter()
            .collect();
        for (i, (index, candidate)) in acts.iter().enumerate() {
            let action = action_name(candidate.action).to_owned();
            outcomes[*index] = match rejected.get(&i) {
                Some(error) => {
                    let reason = error.to_string();
                    let code = if reason.contains("WIST4-E04") {
                        "WIST4-E04"
                    } else {
                        "WIST4-E07"
                    };
                    Outcome::Rejected(Rejection {
                        action,
                        subject: candidate.subject.clone(),
                        code,
                        reason,
                    })
                }
                None => {
                    if candidate.action == RosterAction::Register {
                        self.registrations.push((candidate.subject.clone(), height));
                    }
                    if !matches!(candidate.action, RosterAction::Remove { .. }) {
                        self.verifiers
                            .entry(candidate.public_key.clone())
                            .or_insert_with(|| PublicKey::from_b64u(&candidate.public_key).ok());
                    }
                    Outcome::Accepted(AcceptedAct {
                        action,
                        subject: candidate.subject.clone(),
                        key_id: candidate.key_id.clone(),
                        public_key: candidate.public_key.clone(),
                        for_cause: candidate.action == RosterAction::Remove { for_cause: true },
                    })
                }
            };
        }
        for (index, candidate) in checkpoints {
            let registered = self.roster.observer_key_at(&candidate.subject, sealed_at_s)
                == Some(candidate.key_id.as_str());
            let verifier = self
                .roster
                .observer_public_key_at(&candidate.subject, sealed_at_s)
                .and_then(|public_key| self.verifiers.get(public_key))
                .and_then(Option::as_ref);
            let authentic = registered
                && verifier.is_some_and(|key| {
                    verify_envelope(&entries[index]["body"], "update", key).is_ok()
                });
            outcomes[index] = if authentic {
                self.checkpoints.push(SealedCheckpoint {
                    observer_id: candidate.subject.clone(),
                    height,
                    id: candidate.id,
                });
                Outcome::Accepted(AcceptedAct {
                    action: "observer_checkpoint".into(),
                    subject: candidate.subject,
                    key_id: candidate.key_id,
                    public_key: String::new(),
                    for_cause: false,
                })
            } else {
                Outcome::Rejected(Rejection {
                    action: "observer_checkpoint".into(),
                    subject: candidate.subject,
                    code: "WIST4-E07",
                    reason: "WIST4-E07: checkpoint is not signed by the key registered for its subject at its Block".into(),
                })
            };
        }
        for (index, outcome) in outcomes.iter().enumerate() {
            if matches!(outcome, Outcome::Accepted(_)) {
                if let Some(id) = ids.get(&index) {
                    self.accepted_ids.insert(id.clone());
                }
            }
        }
        Ok(outcomes)
    }

    pub fn anchor_hash(&self) -> &[u8; 32] {
        &self.anchor_hash
    }

    pub fn through(&self) -> Option<&BlockRow> {
        self.through.as_ref()
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    pub fn block_hash_at(&self, height: u64) -> Option<&[u8; 32]> {
        usize::try_from(height)
            .ok()
            .and_then(|h| self.hashes.get(h))
    }

    pub fn admitted_key_at(&self, auditor_id: &str, sealed_at_s: i64) -> Option<KeyBinding<'_>> {
        Some(KeyBinding {
            key_id: self.roster.key_at(auditor_id, sealed_at_s)?,
            public_key: self.roster.public_key_at(auditor_id, sealed_at_s)?,
        })
    }

    pub fn registered_key_at(&self, observer_id: &str, sealed_at_s: i64) -> Option<KeyBinding<'_>> {
        Some(KeyBinding {
            key_id: self.roster.observer_key_at(observer_id, sealed_at_s)?,
            public_key: self
                .roster
                .observer_public_key_at(observer_id, sealed_at_s)?,
        })
    }

    pub fn admitted_at(&self, sealed_at_s: i64) -> Vec<(&str, &str)> {
        self.roster.admitted_at(sealed_at_s)
    }

    pub fn registered_at(&self, sealed_at_s: i64) -> Vec<(&str, &str)> {
        self.roster.registered_at(sealed_at_s)
    }

    pub fn tenure(&self, auditor_id: &str, key_id: &str) -> Option<Tenure> {
        self.roster
            .tenure(auditor_id, key_id)
            .map(|(from_s, until_s)| Tenure { from_s, until_s })
    }

    pub fn signing_binding<'a>(
        &'a self,
        auditor_id: &'a str,
        sealed_at_s: i64,
    ) -> Option<SigningBinding<'a>> {
        let binding = self.admitted_key_at(auditor_id, sealed_at_s)?;
        let public_key = self.verifiers.get(binding.public_key)?.as_ref()?;
        Some(SigningBinding {
            auditor_id,
            key_id: binding.key_id,
            public_key,
        })
    }

    pub fn checkpoints(&self) -> &[SealedCheckpoint] {
        &self.checkpoints
    }

    pub fn idempotent(&self) -> &[Position] {
        &self.idempotent
    }

    pub fn rejected(&self) -> &[RejectedAct] {
        &self.rejected
    }
}

fn action_name(action: RosterAction) -> &'static str {
    match action {
        RosterAction::Admit => "auditor_admit",
        RosterAction::Register => "observer_register",
        RosterAction::Remove { .. } => "auditor_remove",
    }
}

fn canonical_b64u(value: &str, octets: usize) -> bool {
    wist_core::crypto::b64u_decode(value)
        .is_ok_and(|bytes| bytes.len() == octets && wist_core::crypto::b64u_encode(&bytes) == value)
}

pub(crate) fn classify(
    body: &Value,
    log_key_id: &str,
    log_key: &PublicKey,
) -> Option<std::result::Result<RosterEntry, Rejection>> {
    let action = body["update"]["action"].as_str()?;
    if !ROSTER_ACTIONS.contains(&action) {
        return None;
    }
    let subject = body["update"]["subject"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let reject = |code: &'static str, reason: &str| Rejection {
        action: action.to_owned(),
        subject: subject.clone(),
        code,
        reason: format!("{code}: {reason}"),
    };
    let envelope: RegistryUpdateEnvelope = match serde_json::from_value(body.clone()) {
        Ok(envelope) => envelope,
        Err(e) => {
            return Some(Err(reject(
                "WIST4-E11",
                &format!("malformed Registry Update envelope: {e}"),
            )))
        }
    };
    let update = &envelope.update;
    if !crate::record::release(&update.wist_version)
        || update.wist_version.split('.').next() != Some("1")
    {
        return Some(Err(reject(
            "WIST4-E11",
            "unsupported Registry Update version",
        )));
    }
    if crate::registry::epoch(&update.effective_at).is_err() {
        return Some(Err(reject(
            "WIST4-E11",
            "effective_at is not a whole-second UTC instant",
        )));
    }
    if envelope.sig.alg != "Ed25519"
        || envelope.sig.key_id.chars().count() > 64
        || !canonical_b64u(&envelope.sig.value, 64)
    {
        return Some(Err(reject("WIST4-E11", "malformed signature fields")));
    }
    if !crate::record::hostname_subject(&update.subject) {
        return Some(Err(reject(
            "WIST4-E04",
            "subject is not a hostname of at least two labels",
        )));
    }
    let log_signed = |body: &Value| {
        envelope.sig.key_id == log_key_id && verify_envelope(body, "update", log_key).is_ok()
    };
    let entry = match action {
        "auditor_admit" => {
            let Ok(RegistryDetails::Admission(details)) = update.typed_details() else {
                return Some(Err(reject(
                    "WIST4-E04",
                    "auditor_admit details are malformed",
                )));
            };
            if details.key_id.chars().count() > 64 || !canonical_b64u(&details.public_key, 32) {
                return Some(Err(reject(
                    "WIST4-E04",
                    "auditor_admit key fields are malformed",
                )));
            }
            if !log_signed(body) {
                return Some(Err(reject(
                    "WIST4-E11",
                    "signature does not verify under the Log key",
                )));
            }
            RosterEntry::Act(RosterCandidate {
                action: RosterAction::Admit,
                subject: update.subject.clone(),
                key_id: details.key_id,
                public_key: details.public_key,
                track_record: details.track_record,
            })
        }
        "auditor_remove" => {
            let Ok(RegistryDetails::Removal(details)) = update.typed_details() else {
                return Some(Err(reject(
                    "WIST4-E04",
                    "auditor_remove details are malformed",
                )));
            };
            if details.key_id.chars().count() > 64 {
                return Some(Err(reject(
                    "WIST4-E04",
                    "auditor_remove key_id is malformed",
                )));
            }
            let evidence = update.evidence.as_deref();
            if evidence.is_some_and(|ids| ids.iter().any(|id| id.chars().count() > 256)) {
                return Some(Err(reject(
                    "WIST4-E04",
                    "removal evidence IDs are malformed",
                )));
            }
            let action = match RosterAction::try_remove_with(evidence) {
                Ok(action) => action,
                Err(_) => {
                    return Some(Err(reject(
                        "WIST4-E04",
                        "removal evidence must be absent or nonempty",
                    )))
                }
            };
            if !log_signed(body) {
                return Some(Err(reject(
                    "WIST4-E11",
                    "signature does not verify under the Log key",
                )));
            }
            RosterEntry::Act(RosterCandidate {
                action,
                subject: update.subject.clone(),
                key_id: details.key_id,
                public_key: String::new(),
                track_record: None,
            })
        }
        "observer_register" => {
            let Ok(RegistryDetails::Registration(details)) = update.typed_details() else {
                return Some(Err(reject(
                    "WIST4-E04",
                    "observer_register details are malformed",
                )));
            };
            if details.key_id.chars().count() > 64 || !canonical_b64u(&details.public_key, 32) {
                return Some(Err(reject(
                    "WIST4-E04",
                    "observer_register key fields are malformed",
                )));
            }
            if envelope.sig.key_id != details.key_id {
                return Some(Err(reject(
                    "WIST4-E11",
                    "observer_register is not signed by the key it registers",
                )));
            }
            let verifies = PublicKey::from_b64u(&details.public_key)
                .is_ok_and(|key| verify_envelope(body, "update", &key).is_ok());
            if !verifies {
                return Some(Err(reject(
                    "WIST4-E11",
                    "signature does not verify under the registered key",
                )));
            }
            RosterEntry::Act(RosterCandidate {
                action: RosterAction::Register,
                subject: update.subject.clone(),
                key_id: details.key_id,
                public_key: details.public_key,
                track_record: None,
            })
        }
        _ => {
            let Ok(RegistryDetails::ObserverCheckpoint(_)) = update.typed_details() else {
                return Some(Err(reject(
                    "WIST4-E04",
                    "observer_checkpoint details are malformed",
                )));
            };
            let id = match wist_core::delta::delta_id(&body["update"]) {
                Ok(id) => id,
                Err(e) => {
                    return Some(Err(reject(
                        "WIST4-E11",
                        &format!("checkpoint cannot be identified: {e}"),
                    )))
                }
            };
            RosterEntry::Checkpoint(CheckpointCandidate {
                subject: update.subject.clone(),
                key_id: envelope.sig.key_id.clone(),
                id,
            })
        }
    };
    Some(Ok(entry))
}
