pub mod declarations;
pub mod payloads;

use crate::db::{Db, EpochRow};
use crate::error::{Error, Result};
use crate::registry;
use serde_json::Value;
use std::path::Path;
use wist_core::aggregator_keys::Registry;
use wist_core::checkpoint::{self, AggregatorKey, Checkpoint};
use wist_core::crypto::PublicKey;
use wist_core::objects::{
    AggregatorKeyEntry, GenesisKey, LogAnchorEnvelope, RegistryUpdateEnvelope,
};
use wist_core::parameters::{Amendment, Schedule};
use wist_core::sealing::{Epoch, Judgment, Outcome, Removed, Replay};
use wist_core::suffix_list::{Disposition, HeldFile, SuffixListReplay};

pub struct LogAnchor {
    pub log_id: String,
    pub key: PublicKey,
    pub key_id: String,
}

/// WIST-3 §3.4: `anchor.json` is self-signed under the genesis key it
/// declares.
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

#[derive(Debug)]
pub struct VerifiedEpoch {
    epoch_number: u64,
    tree_size: u64,
    root: String,
    sealed_at: String,
    entries: Vec<Value>,
    sealed_at_s: i64,
    octets: u64,
    rejected_parameters: Vec<usize>,
    recovery_window_days: i64,
    declaration_activation_epochs: i64,
    size_caps: wist_core::item::SizeCaps,
    pub(crate) limits: wist_core::collection::Limits,
    clock_skew_seconds: i64,
    rejected: Option<Vec<String>>,
    judgments: Vec<Option<Judgment>>,
    records_removed: Vec<Removed>,
}

impl VerifiedEpoch {
    pub fn epoch_number(&self) -> u64 {
        self.epoch_number
    }

    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

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

    /// WIST-3 §6: octets this Epoch's Entries occupy in entry bundles.
    pub fn octets(&self) -> u64 {
        self.octets
    }

    pub fn size_caps(&self) -> &wist_core::item::SizeCaps {
        &self.size_caps
    }

    pub fn limits(&self) -> &wist_core::collection::Limits {
        &self.limits
    }

    pub fn clock_skew_seconds(&self) -> i64 {
        self.clock_skew_seconds
    }

    pub fn rejected_parameters(&self) -> &[usize] {
        &self.rejected_parameters
    }

    /// WIST-3 §3.3: a rejected Epoch stays in the Log and applies nothing.
    pub fn rejected(&self) -> Option<&[String]> {
        self.rejected.as_deref()
    }

    pub fn judgments(&self) -> &[Option<Judgment>] {
        &self.judgments
    }

    pub fn records_removed(&self) -> &[Removed] {
        &self.records_removed
    }
}

pub struct History<'a> {
    db: &'a Db,
    head: Option<EpochRow>,
    log_id: String,
    registry: Registry,
    next_height: u64,
    previous: Option<Checkpoint>,
    prior_at: Option<i64>,
    largest: u64,
    schedule: Option<Schedule>,
    failed: bool,
    replay: Replay,
    suffix_lists: SuffixListReplay,
}

impl<'a> History<'a> {
    pub fn open(db: &'a Db, directory: &Path, head: Option<EpochRow>) -> Result<Self> {
        let anchor = anchor(directory)?;
        let genesis = GenesisKey {
            key_id: anchor.key_id.clone(),
            alg: "Ed25519".into(),
            public_key: anchor.key.to_b64u(),
        };
        Ok(Self {
            db,
            head,
            registry: Registry::from_genesis(&anchor.log_id, &genesis)?,
            log_id: anchor.log_id,
            next_height: 0,
            previous: None,
            prior_at: None,
            largest: 0,
            schedule: None,
            failed: false,
            replay: Replay::new(),
            suffix_lists: SuffixListReplay::new(),
        })
    }

    pub fn schedule(&self) -> Option<&Schedule> {
        self.schedule.as_ref()
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    pub fn height(&self) -> Option<u64> {
        self.next_height.checked_sub(1)
    }

    pub fn replay(&self) -> &Replay {
        &self.replay
    }

    pub fn key_registry(&self) -> &Registry {
        &self.registry
    }

    /// WIST-3 §7: removed keys included.
    pub fn key_entries(&self) -> Vec<AggregatorKeyEntry> {
        self.registry.entries()
    }

    pub fn next_epoch(&mut self) -> Result<Option<VerifiedEpoch>> {
        if self.failed {
            return Err(failure("history reader cannot continue after a failure"));
        }
        let result = self.read_next();
        self.failed = result.is_err();
        result
    }

    fn read_next(&mut self) -> Result<Option<VerifiedEpoch>> {
        let Some(head) = &self.head else {
            return Ok(None);
        };
        let height = self.next_height;
        if height > head.epoch_number {
            return Ok(None);
        }
        let row = self
            .db
            .epoch_at(height)?
            .ok_or_else(|| failure("the store is missing an Epoch below its head"))?;
        let note = self
            .db
            .checkpoint_note(height)?
            .ok_or_else(|| failure("the store is missing an Epoch's Checkpoint"))?;
        let checkpoint = Checkpoint::parse(&note).map_err(|e| failure(&e.to_string()))?;
        if checkpoint.epoch_number() != height
            || checkpoint.tree_size() != row.tree_size
            || checkpoint.root_token() != row.root
            || checkpoint.sealed_at() != row.sealed_at
        {
            return Err(Error::History(
                "WIST3-E02 the stored Checkpoint is not the Epoch the store records".into(),
            ));
        }
        if height == head.epoch_number && (row.root != head.root || row.sealed_at != head.sealed_at)
        {
            return Err(Error::History(
                "WIST3-E02 Epoch does not match the pinned history head".into(),
            ));
        }
        let at = checkpoint
            .sealed_at_s()
            .map_err(|e| failure(&e.to_string()))?;
        let mut schedule = self.schedule.clone().unwrap_or_else(|| Schedule::new(at));
        let cadence = schedule
            .value_at("epoch_cadence_seconds", self.prior_at.unwrap_or(at))
            .unwrap();
        checkpoint::check_sequence(self.previous.as_ref(), &checkpoint, cadence)
            .map_err(|e| failure(&e.to_string()))?;

        let previous_size = self.db.size_before(height)?;
        let entries = self.db.epoch_entries(height)?;
        let cap = schedule.epoch_size_bounds(at).1;
        let summary = wist_core::epoch::verify_epoch(
            previous_size,
            &checkpoint,
            &entries,
            &self.db.log_tree(),
            cap,
        )
        .map_err(|e| failure(&e.to_string()))?;

        let largest = self.largest.max(summary.octets);

        // WIST-3 §5: the keys that can speak for Epoch N are the ones the
        // Log establishes at N, so this Epoch's key acts are applied to the
        // registry — under the keys valid at N−1 (§3.4) — before the
        // Checkpoint's signature is verified under the keys valid at N.
        let mut registry = self.registry.clone();
        let acts: Vec<&Value> = entries
            .iter()
            .filter(|entry| entry["type"] == "registry_update")
            .map(|entry| &entry["body"])
            .collect();
        let key_outcomes = registry.apply_epoch(height, acts.iter().copied());
        let keys = registry.valid_at(height);
        checkpoint::verify(&checkpoint, &self.log_id, &keys, &[])
            .map_err(|e| failure(&e.to_string()))?;

        let mut rejected_parameters = Vec::new();
        let mut accepted_acts: Vec<&Value> = key_outcomes
            .iter()
            .zip(&acts)
            .filter(|(outcome, _)| outcome.is_accepted())
            .map(|(_, act)| *act)
            .collect();
        for (index, entry) in entries.iter().enumerate() {
            if entry["type"] != "registry_update"
                || entry["body"]["update"]["action"] != "parameter_change"
            {
                continue;
            }
            if accept_parameter(&keys, &mut schedule, entry, height, index, at, largest) {
                accepted_acts.push(&entry["body"]);
            } else {
                rejected_parameters.push(index);
            }
        }
        if largest > schedule.epoch_size_bounds(at).0 {
            return Err(failure("Epoch exceeds the accepted size schedule"));
        }
        let parameters = wist_core::sealing::Parameters::from_schedule(&schedule, at)?;
        let suffix_list = crate::suffix_list::in_force_at_epoch(self.db, height)?;
        let log_key = |key_id: &str| {
            keys.iter()
                .find(|key| key.key_id == key_id)
                .map(|key| key.public_key.clone())
        };
        let (rejected, judgments, records_removed) = match self
            .replay
            .epoch(&Epoch {
                height,
                root: &row.root,
                sealed_at: &row.sealed_at,
                parameters: &parameters,
                suffix_list: suffix_list.as_deref(),
                log_key: &log_key,
                entries: &entries,
            })
            .map_err(|e| failure(&e.to_string()))?
        {
            Outcome::Rejected { codes } => (Some(codes), Vec::new(), Vec::new()),
            Outcome::Accepted {
                entries,
                records_removed,
            } => (None, entries, records_removed),
        };
        if rejected.is_none() {
            let db = self.db;
            for act in &acts {
                let disposition = self.suffix_lists.apply(height, act, log_key, |identifier| {
                    db.suffix_list_bytes(identifier)
                        .ok()
                        .flatten()
                        .map_or(HeldFile::Absent, HeldFile::Bytes)
                });
                if matches!(disposition, Disposition::Accepted { .. }) {
                    accepted_acts.push(act);
                }
            }
            for act in accepted_acts {
                let update_id = wist_core::registry_updates::update_id(act)?;
                self.replay.accept_registry_update(&update_id, height);
            }
        }
        self.next_height = height
            .checked_add(1)
            .ok_or_else(|| failure("Epoch height overflow"))?;
        self.prior_at = Some(at);
        self.largest = largest;
        let recovery_window_days = schedule.value_at("recovery_window_days", at).unwrap();
        let declaration_activation_epochs = schedule
            .value_at("declaration_activation_epochs", at)
            .unwrap();
        let size_caps = crate::declaration::size_caps(&schedule, at)?;
        let limits = crate::declaration::limits(&schedule, at)?;
        let clock_skew_seconds = schedule.value_at("clock_skew_seconds", at).unwrap();
        self.schedule = Some(schedule);
        self.previous = Some(checkpoint);
        self.registry = registry;
        Ok(Some(VerifiedEpoch {
            epoch_number: height,
            tree_size: row.tree_size,
            root: row.root,
            sealed_at: row.sealed_at,
            entries,
            sealed_at_s: at,
            octets: summary.octets,
            rejected_parameters,
            recovery_window_days,
            declaration_activation_epochs,
            size_caps,
            limits,
            clock_skew_seconds,
            rejected,
            judgments,
            records_removed,
        }))
    }
}

/// WIST-4 §5.1: a `parameter_change` counts toward the schedule only when
/// its fields hold and it authenticates under a key valid at its Epoch.
fn accept_parameter(
    keys: &[AggregatorKey],
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
        || wist_core::aggregator_keys::authenticate(body, keys).is_err()
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
    let Ok(effective_at_s) = registry::unix(effective_at) else {
        return false;
    };
    registry::accept(
        schedule,
        Amendment {
            parameter: parameter.into(),
            value,
            epoch_number: height,
            entry_index: index as u64,
            sealed_at_s: at,
            effective_at_s,
        },
        largest,
    )
    .is_ok()
}

fn failure(message: &str) -> Error {
    Error::History(format!("WIST3-E03 {message}"))
}
