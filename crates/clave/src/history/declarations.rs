use super::{History, VerifiedBlock};
use crate::db::BlockRow;
use crate::error::Result;
use std::path::Path;

pub use wist_core::declarations::{
    Declaration, Declarations, Domain, Effects, Installation, Position, Projection, RecoveryWindow,
    Settlement,
};

/// Replay over the authenticated Block history the aggregator retains.
pub trait DeclarationsReplay: Sized {
    fn reconstruct(directory: &Path, head: Option<BlockRow>) -> Result<Self>;
    fn apply(&mut self, verified: &VerifiedBlock) -> Result<Effects>;
}

impl DeclarationsReplay for Declarations {
    fn reconstruct(directory: &Path, head: Option<BlockRow>) -> Result<Self> {
        let mut history = History::open(directory, head)?;
        let mut state = Self::default();
        while let Some(block) = history.next_block()? {
            state.apply(&block)?;
        }
        Ok(state)
    }

    fn apply(&mut self, verified: &VerifiedBlock) -> Result<Effects> {
        let block = verified.block();
        Ok(self.apply_block(
            block.header.block_number,
            &block.header.prev_block_hash,
            verified.hash(),
            &block.header.sealed_at,
            verified.recovery_window_days,
            verified.declaration_activation_blocks,
            &block.entries,
        )?)
    }
}
