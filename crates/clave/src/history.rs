pub mod declarations;
pub mod deltas;
pub mod payloads;

use crate::db::{BlockRow, Db};
use crate::error::{Error, Result};
use crate::registry;
use serde_json::Value;
use std::path::Path;
use wist_core::checkpoint::{self, AggregatorKey, Checkpoint};
use wist_core::crypto::PublicKey;
use wist_core::objects::{LogAnchorEnvelope, RegistryUpdateEnvelope};
use wist_core::parameters::{Amendment, Schedule};

/// The Log's out-of-band trust root as the data directory holds it.
pub struct LogAnchor {
    pub log_id: String,
    pub key: PublicKey,
    pub key_id: String,
}

/// Reads and verifies `anchor.json`: it is self-signed under the very
/// genesis key it declares (WIST-3 §3.4).
pub fn anchor(directory: &Path) -> Result<LogAnchor> {
    let doc: Value = crate::json::parse(&std::fs::read(directory.join("anchor.json"))?)?;
    let parsed: LogAnchorEnvelope = serde_json::from_value(doc.clone())?;
    let genesis = &parsed.anchor.genesis_key;
    if parsed.anchor.wist_version != crate::WIST_VERSION || parsed.anchor.predecessor.is_some() {
        return Err(Error::History(
            "unsupported Log Anchor version or predecessor".into(),
        ));
    }
    if genesis.alg != "Ed25519"
        || parsed.sig.alg != "Ed25519"
        || parsed.sig.key_id != genesis.key_id
    {
        return Err(failure(
            "Log Anchor signature does not name its genesis key",
        ));
    }
    let key = PublicKey::from_b64u(&genesis.public_key)?;
    wist_core::envelope::verify_envelope(&doc, "anchor", &key)?;
    Ok(LogAnchor {
        log_id: parsed.anchor.log_id.clone(),
        key,
        key_id: genesis.key_id.clone(),
    })
}

/// One Block of the Log with its Checkpoint verified and its Entries
/// checked against the tree that Checkpoint states.
#[derive(Debug)]
pub struct VerifiedBlock {
    block_number: u64,
    tree_size: u64,
    root: String,
    sealed_at: String,
    entries: Vec<Value>,
    sealed_at_s: i64,
    octets: u64,
    rejected_parameters: Vec<usize>,
    recovery_window_days: i64,
    declaration_activation_blocks: i64,
    delta_size_caps: crate::declaration::delta::SizeCaps,
    clock_skew_seconds: i64,
}

impl VerifiedBlock {
    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// The root of the tree at this Block in the `"sha256:" + hex` form
    /// WIST-3 §3.1 gives it.
    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn sealed_at(&self) -> &str {
        &self.sealed_at
    }

    pub fn entries(&self) -> &[Value] {
        &self.entries
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }

    /// The octets this Block's Entries occupy in entry bundles
    /// (WIST-3 §6).
    pub fn octets(&self) -> u64 {
        self.octets
    }

    pub fn delta_size_caps(&self) -> &crate::declaration::delta::SizeCaps {
        &self.delta_size_caps
    }

    pub fn clock_skew_seconds(&self) -> i64 {
        self.clock_skew_seconds
    }

    pub fn rejected_parameters(&self) -> &[usize] {
        &self.rejected_parameters
    }
}

pub struct History<'a> {
    db: &'a Db,
    head: Option<BlockRow>,
    log_id: String,
    key: PublicKey,
    key_id: String,
    next_height: u64,
    previous: Option<Checkpoint>,
    prior_at: Option<i64>,
    largest: u64,
    schedule: Option<Schedule>,
    failed: bool,
}

impl<'a> History<'a> {
    pub fn open(db: &'a Db, directory: &Path, head: Option<BlockRow>) -> Result<Self> {
        let anchor = anchor(directory)?;
        Ok(Self {
            db,
            head,
            log_id: anchor.log_id,
            key: anchor.key,
            key_id: anchor.key_id,
            next_height: 0,
            previous: None,
            prior_at: None,
            largest: 0,
            schedule: None,
            failed: false,
        })
    }

    pub fn schedule(&self) -> Option<&Schedule> {
        self.schedule.as_ref()
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    pub fn log_key(&self) -> &PublicKey {
        &self.key
    }

    pub fn log_key_id(&self) -> &str {
        &self.key_id
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
        let row = self
            .db
            .block_at(height)?
            .ok_or_else(|| failure("the store is missing a Block below its head"))?;
        let note = self
            .db
            .checkpoint_note(height)?
            .ok_or_else(|| failure("the store is missing a Block's Checkpoint"))?;
        let checkpoint = Checkpoint::parse(&note).map_err(|e| failure(&e.to_string()))?;
        checkpoint::verify(
            &checkpoint,
            &self.log_id,
            &[AggregatorKey {
                key_id: self.key_id.clone(),
                public_key: self.key.clone(),
            }],
            &[],
        )
        .map_err(|e| failure(&e.to_string()))?;
        if checkpoint.block_number() != height
            || checkpoint.tree_size() != row.tree_size
            || checkpoint.root_token() != row.root
            || checkpoint.sealed_at() != row.sealed_at
        {
            return Err(Error::History(
                "WIST3-E02 the stored Checkpoint is not the Block the store records".into(),
            ));
        }
        if height == head.block_number && (row.root != head.root || row.sealed_at != head.sealed_at)
        {
            return Err(Error::History(
                "WIST3-E02 Block does not match the pinned history head".into(),
            ));
        }
        let at = checkpoint
            .sealed_at_s()
            .map_err(|e| failure(&e.to_string()))?;
        let mut schedule = self.schedule.clone().unwrap_or_else(|| Schedule::new(at));
        let cadence = schedule
            .value_at("block_cadence_seconds", self.prior_at.unwrap_or(at))
            .unwrap();
        checkpoint::check_sequence(self.previous.as_ref(), &checkpoint, cadence)
            .map_err(|e| failure(&e.to_string()))?;

        let previous_size = self.db.size_before(height)?;
        let entries = self.db.block_entries(height)?;
        let cap = schedule.block_size_bounds(at).1;
        let summary = wist_core::block::verify_block(
            previous_size,
            &checkpoint,
            &entries,
            &self.db.log_tree(),
            cap,
        )
        .map_err(|e| failure(&e.to_string()))?;

        let largest = self.largest.max(summary.octets);
        let mut rejected_parameters = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
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
        self.prior_at = Some(at);
        self.largest = largest;
        let recovery_window_days = schedule.value_at("recovery_window_days", at).unwrap();
        let declaration_activation_blocks = schedule
            .value_at("declaration_activation_blocks", at)
            .unwrap();
        let delta_size_caps = crate::declaration::delta::SizeCaps::from_schedule(&schedule, at);
        let clock_skew_seconds = schedule.value_at("clock_skew_seconds", at).unwrap();
        self.schedule = Some(schedule);
        self.previous = Some(checkpoint);
        Ok(Some(VerifiedBlock {
            block_number: height,
            tree_size: row.tree_size,
            root: row.root,
            sealed_at: row.sealed_at,
            entries,
            sealed_at_s: at,
            octets: summary.octets,
            rejected_parameters,
            recovery_window_days,
            declaration_activation_blocks,
            delta_size_caps,
            clock_skew_seconds,
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

fn failure(message: &str) -> Error {
    Error::History(format!("WIST3-E03 {message}"))
}
