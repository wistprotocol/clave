pub mod declarations;
pub mod deltas;
pub mod payloads;
pub mod records;
pub mod references;

use crate::db::BlockRow;
use crate::error::{Error, Result};
use crate::registry;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use wist_core::crypto::PublicKey;
use wist_core::objects::{Block, LogAnchorEnvelope, RegistryUpdateEnvelope};
use wist_core::parameters::{Amendment, Schedule};

#[derive(Debug)]
pub struct VerifiedBlock {
    block: Block,
    hash: String,
    sealed_at_s: i64,
    decompressed_bytes: u64,
    rejected_parameters: Vec<usize>,
    recovery_window_days: i64,
    delta_size_caps: crate::declaration::delta::SizeCaps,
    audit_profile: wist_core::canary::ScoringProfile,
    verdict_thresholds: wist_core::verdict::Thresholds,
    sampling_constants: wist_core::sampling::SamplingConstants,
    confirmation_profile: records::ConfirmationProfile,
}

impl VerifiedBlock {
    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }

    pub fn decompressed_bytes(&self) -> u64 {
        self.decompressed_bytes
    }

    pub fn delta_size_caps(&self) -> &crate::declaration::delta::SizeCaps {
        &self.delta_size_caps
    }

    pub fn audit_profile(&self) -> &wist_core::canary::ScoringProfile {
        &self.audit_profile
    }

    pub fn verdict_thresholds(&self) -> &wist_core::verdict::Thresholds {
        &self.verdict_thresholds
    }

    pub fn sampling_constants(&self) -> &wist_core::sampling::SamplingConstants {
        &self.sampling_constants
    }

    pub fn confirmation_profile(&self) -> &records::ConfirmationProfile {
        &self.confirmation_profile
    }

    pub fn rejected_parameters(&self) -> &[usize] {
        &self.rejected_parameters
    }
}

pub struct History {
    anchor_hash: [u8; 32],
    directory: PathBuf,
    head: Option<BlockRow>,
    key: PublicKey,
    key_id: String,
    next_height: u64,
    prior_hash: String,
    prior_at: Option<i64>,
    largest: u64,
    schedule: Option<Schedule>,
    failed: bool,
}

impl History {
    pub fn open(directory: &Path, head: Option<BlockRow>) -> Result<Self> {
        let doc: Value = crate::json::parse(&std::fs::read(directory.join("anchor.json"))?)?;
        let anchor: LogAnchorEnvelope = serde_json::from_value(doc.clone())?;
        let genesis = &anchor.anchor.genesis_key;
        if anchor.anchor.wist_version != crate::WIST_VERSION || anchor.anchor.predecessor.is_some()
        {
            return Err(Error::History(
                "unsupported Log Anchor version or predecessor".into(),
            ));
        }
        if genesis.alg != "Ed25519"
            || anchor.sig.alg != "Ed25519"
            || anchor.sig.key_id != genesis.key_id
        {
            return Err(failure(
                "Log Anchor signature does not name its genesis key",
            ));
        }
        let key = PublicKey::from_b64u(&genesis.public_key)?;
        wist_core::envelope::verify_envelope(&doc, "anchor", &key)?;
        Ok(Self {
            anchor_hash: Sha256::digest(wist_core::jcs::canonicalize(&doc["anchor"])?).into(),
            directory: directory.into(),
            head,
            key,
            key_id: genesis.key_id.clone(),
            next_height: 0,
            prior_hash: "sha256:genesis".into(),
            prior_at: None,
            largest: 0,
            schedule: None,
            failed: false,
        })
    }

    pub fn schedule(&self) -> Option<&Schedule> {
        self.schedule.as_ref()
    }

    pub fn next_block(&mut self) -> Result<Option<VerifiedBlock>> {
        if self.failed {
            return Err(failure("history reader cannot continue after a failure"));
        }
        let result = self.read_next();
        self.failed = result.is_err();
        result
    }

    fn read_next(&mut self) -> Result<Option<VerifiedBlock>> {
        let Some(head) = &self.head else {
            return Ok(None);
        };
        let height = self.next_height;
        if height > head.block_number {
            return Ok(None);
        }
        let bound = match (&self.schedule, self.prior_at) {
            (Some(schedule), Some(at)) => schedule.block_size_bounds(at).1,
            _ => registry::spec("block_decompressed_cap_bytes")
                .unwrap()
                .default
                .unwrap() as u64,
        };
        let bytes = crate::block_file::read(
            &self
                .directory
                .join(format!("log/blocks/{height:09}.json.zst")),
            bound,
        )?;
        let doc: Value = crate::json::parse(&bytes).map_err(|e| failure(&e.to_string()))?;
        let block: Block =
            serde_json::from_value(doc.clone()).map_err(|e| failure(&e.to_string()))?;
        if block.header.wist_version != crate::WIST_VERSION {
            return Err(Error::History("unsupported Block version".into()));
        }
        if block.sig.alg != "Ed25519" || block.sig.key_id != self.key_id {
            return Err(Error::History(
                "unsupported Block signing key or algorithm".into(),
            ));
        }
        wist_core::block::verify_block(&doc, &self.key).map_err(|e| failure(&e.to_string()))?;
        wist_core::block::verify_chain_link(&doc["header"], &self.prior_hash)
            .map_err(|e| Error::History(format!("WIST3-E02 {e}")))?;
        let hash = wist_core::block::block_hash(&doc["header"])?;
        if block.header.block_number != height {
            return Err(failure("Block height does not match its path"));
        }
        if height == head.block_number
            && (hash != head.block_hash || block.header.sealed_at != head.sealed_at)
        {
            return Err(Error::History(
                "WIST3-E02 Block does not match the pinned history head".into(),
            ));
        }
        let at = registry::epoch(&block.header.sealed_at).map_err(|e| failure(&e.to_string()))?;
        if self.prior_at.is_some_and(|prior| at <= prior) {
            return Err(failure("Block timestamps are not strictly increasing"));
        }
        if wist_core::jcs::canonicalize(&doc)? != bytes {
            return Err(failure("Block file does not contain canonical JCS bytes"));
        }
        let mut schedule = self.schedule.clone().unwrap_or_else(|| Schedule::new(at));
        let cadence = schedule
            .value_at("block_cadence_seconds", self.prior_at.unwrap_or(at))
            .unwrap();
        if at.rem_euclid(cadence) != 0 {
            return Err(failure("Block timestamp is off the accepted cadence grid"));
        }
        validate_entry_order(&block.entries)?;
        let size = bytes.len() as u64;
        let largest = self.largest.max(size);
        let mut rejected_parameters = Vec::new();
        for (index, entry) in block.entries.iter().enumerate() {
            if entry["type"] != "registry_update" {
                continue;
            }
            let update = &entry["body"]["update"];
            if matches!(
                update["action"].as_str(),
                Some("aggregator_key_add" | "aggregator_key_remove")
            ) {
                return Err(Error::History(
                    "Log key transitions are not supported by this reader".into(),
                ));
            }
            if update["action"] != "parameter_change" {
                continue;
            }
            if !self.accept_parameter(&mut schedule, entry, height, index, at, largest) {
                rejected_parameters.push(index);
            }
        }
        if largest > schedule.block_size_bounds(at).0 {
            return Err(failure("Block exceeds the accepted size schedule"));
        }
        self.next_height = height
            .checked_add(1)
            .ok_or_else(|| failure("Block height overflow"))?;
        self.prior_hash = hash.clone();
        self.prior_at = Some(at);
        self.largest = largest;
        let recovery_window_days = schedule.value_at("recovery_window_days", at).unwrap();
        let delta_size_caps = crate::declaration::delta::SizeCaps::from_schedule(&schedule, at);
        let audit_profile = wist_core::canary::ScoringProfile::at_audited_delta(at, |name, at| {
            schedule.value_at(name, at).unwrap() as u64
        });
        let verdict_thresholds = wist_core::verdict::Thresholds {
            similarity_consistent: audit_profile.similarity_consistent,
            similarity_variance_floor: audit_profile.similarity_variance_floor,
            min_observed_words: audit_profile.min_observed_words,
            link_agreement_consistent: schedule.value_at("link_agreement_consistent", at).unwrap()
                as u64,
            link_variance_floor: schedule.value_at("link_variance_floor", at).unwrap() as u64,
        };
        let sampling_constants = wist_core::sampling::SamplingConstants {
            floor_1e7: schedule.value_at("sampling_floor", at).unwrap() as u64,
            ceiling_1e7: schedule.value_at("sampling_ceiling", at).unwrap() as u64,
            slope_per_micro: schedule.value_at("sampling_slope", at).unwrap(),
        };
        let confirmation_profile = records::ConfirmationProfile {
            auditors: schedule.value_at("confirm_auditors", at).unwrap() as u64,
            window_hours: schedule.value_at("confirm_window_hours", at).unwrap() as u64,
        };
        self.schedule = Some(schedule);
        Ok(Some(VerifiedBlock {
            block,
            hash,
            sealed_at_s: at,
            decompressed_bytes: size,
            rejected_parameters,
            recovery_window_days,
            delta_size_caps,
            audit_profile,
            verdict_thresholds,
            sampling_constants,
            confirmation_profile,
        }))
    }

    fn accept_parameter(
        &self,
        schedule: &mut Schedule,
        entry: &Value,
        height: u64,
        index: usize,
        at: i64,
        largest: u64,
    ) -> bool {
        let body = &entry["body"];
        let Ok(parsed) = serde_json::from_value::<RegistryUpdateEnvelope>(body.clone()) else {
            return false;
        };
        if parsed.update.wist_version != crate::WIST_VERSION
            || parsed.update.subject.chars().count() > 256
            || parsed
                .update
                .evidence
                .as_ref()
                .is_some_and(|ids| ids.iter().any(|id| id.chars().count() > 256))
            || body["sig"]["alg"] != "Ed25519"
            || body["sig"]["key_id"] != self.key_id
            || wist_core::envelope::verify_envelope(body, "update", &self.key).is_err()
        {
            return false;
        }
        let update = &body["update"];
        let (Some(parameter), Some(value), Some(effective_at)) = (
            update["details"]["parameter"].as_str(),
            update["details"]["value"].as_i64(),
            update["effective_at"].as_str(),
        ) else {
            return false;
        };
        let Ok(effective_at_s) = registry::epoch(effective_at) else {
            return false;
        };
        registry::accept(
            schedule,
            Amendment {
                parameter: parameter.into(),
                value,
                block_number: height,
                entry_index: index as u64,
                sealed_at_s: at,
                effective_at_s,
            },
            largest,
        )
        .is_ok()
    }
}

fn validate_entry_order(entries: &[Value]) -> Result<()> {
    let mut previous = None;
    for entry in entries {
        let kind = match entry["type"].as_str() {
            Some("publisher_declaration") => 0,
            Some("registry_update") => 1,
            Some("publisher_delta") => 2,
            Some("audit_record") => 3,
            _ => return Err(failure("unknown Block Entry type")),
        };
        if entry.as_object().is_none_or(|object| object.len() != 2) || !entry["body"].is_object() {
            return Err(failure("malformed Block Entry envelope"));
        }
        let order = (
            kind,
            wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(entry)?),
        );
        if previous.is_some_and(|previous| previous > order) {
            return Err(failure("Block Entries are not in canonical order"));
        }
        previous = Some(order);
    }
    Ok(())
}

fn failure(message: &str) -> Error {
    Error::History(format!("WIST3-E03 {message}"))
}
