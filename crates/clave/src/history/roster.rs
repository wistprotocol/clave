use super::{History, VerifiedBlock};
use crate::db::BlockRow;
use crate::error::Result;
use crate::record::SigningBinding;
use serde_json::Value;
use std::path::Path;
use wist_core::crypto::PublicKey;

pub use wist_core::declarations::Position;
pub use wist_core::roster_replay::{
    classify, AcceptedAct, CheckpointCandidate, KeyBinding, Outcome, RejectedAct, Rejection,
    RosterCandidate, RosterEntry, RosterReplay, SealedCheckpoint, Tenure,
};

/// Core's roster replay over the aggregator's authenticated history, with
/// the Log Anchor hash and pinned head the extension replay reads.
#[derive(Clone)]
pub struct RosterHistory {
    anchor_hash: [u8; 32],
    through: Option<BlockRow>,
    replay: RosterReplay,
}

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
            replay: RosterReplay::new(history.log_id()),
        }
    }

    pub(crate) fn apply(
        &mut self,
        block: &VerifiedBlock,
        log_key_id: &str,
        log_key: &PublicKey,
    ) -> Result<()> {
        self.replay.apply_block(
            block.block().header.block_number,
            block.hash(),
            block.sealed_at_s(),
            &block.block().entries,
            log_key_id,
            log_key,
        )?;
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
        Ok(self
            .replay
            .apply_entries(height, sealed_at_s, entries, log_key_id, log_key)?)
    }

    pub fn anchor_hash(&self) -> &[u8; 32] {
        &self.anchor_hash
    }

    pub fn through(&self) -> Option<&BlockRow> {
        self.through.as_ref()
    }

    pub fn log_id(&self) -> &str {
        self.replay.log_id()
    }

    pub fn block_hash_at(&self, height: u64) -> Option<&[u8; 32]> {
        self.replay.block_hash_at(height)
    }

    pub fn admitted_key_at(&self, auditor_id: &str, sealed_at_s: i64) -> Option<KeyBinding<'_>> {
        self.replay.admitted_key_at(auditor_id, sealed_at_s)
    }

    pub fn registered_key_at(&self, observer_id: &str, sealed_at_s: i64) -> Option<KeyBinding<'_>> {
        self.replay.registered_key_at(observer_id, sealed_at_s)
    }

    pub fn admitted_at(&self, sealed_at_s: i64) -> Vec<(&str, &str)> {
        self.replay.admitted_at(sealed_at_s)
    }

    pub fn registered_at(&self, sealed_at_s: i64) -> Vec<(&str, &str)> {
        self.replay.registered_at(sealed_at_s)
    }

    pub fn tenure(&self, auditor_id: &str, key_id: &str) -> Option<Tenure> {
        self.replay.tenure(auditor_id, key_id)
    }

    pub fn signing_binding<'a>(
        &'a self,
        auditor_id: &'a str,
        sealed_at_s: i64,
    ) -> Option<SigningBinding<'a>> {
        let binding = self.replay.signing_binding(auditor_id, sealed_at_s)?;
        Some(SigningBinding {
            auditor_id: binding.auditor_id,
            key_id: binding.key_id,
            public_key: binding.public_key,
        })
    }

    pub fn registered_observers_at(&self, sealed_at_s: i64) -> Vec<(String, String, String, u64)> {
        self.replay.registered_observers_at(sealed_at_s)
    }

    pub fn checkpoints(&self) -> &[SealedCheckpoint] {
        self.replay.checkpoints()
    }

    pub fn idempotent(&self) -> &[Position] {
        self.replay.idempotent()
    }

    pub fn rejected(&self) -> &[RejectedAct] {
        self.replay.rejected()
    }
}
