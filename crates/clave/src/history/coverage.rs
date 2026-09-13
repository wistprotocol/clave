use super::History;
use crate::db::BlockRow;
use crate::error::{Error, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageProfile {
    pub deadline_hours: u64,
    pub seal_blocks: u64,
}

#[derive(Clone)]
pub struct CoverageClock {
    anchor_hash: [u8; 32],
    duty_block: BlockRow,
    through: BlockRow,
    profile: CoverageProfile,
    deadline_s: i128,
    unattested_height: Option<u64>,
}

impl CoverageClock {
    pub fn reconstruct(directory: &Path, head: Option<BlockRow>, duty_hash: &str) -> Result<Self> {
        let mut history = History::open(directory, head.clone())?;
        let mut clock: Option<Self> = None;
        let mut successors = 0;
        while let Some(block) = history.next_block()? {
            if block.hash() == duty_hash {
                let profile = *block.coverage_profile();
                clock = Some(Self {
                    anchor_hash: history.anchor_hash,
                    duty_block: BlockRow {
                        block_number: block.block().header.block_number,
                        block_hash: block.hash().into(),
                        sealed_at: block.block().header.sealed_at.clone(),
                    },
                    through: head.clone().unwrap(),
                    profile,
                    deadline_s: i128::from(block.sealed_at_s())
                        + i128::from(profile.deadline_hours) * 3600,
                    unattested_height: None,
                });
            }
            if let Some(clock) = &mut clock {
                if clock.unattested_height.is_none()
                    && i128::from(block.sealed_at_s()) > clock.deadline_s
                {
                    successors += 1;
                    if successors == clock.profile.seal_blocks {
                        clock.unattested_height = Some(block.block().header.block_number);
                    }
                }
            }
        }
        clock.ok_or_else(|| {
            Error::History("coverage duty Block is absent from pinned history".into())
        })
    }

    pub fn anchor_hash(&self) -> &[u8; 32] {
        &self.anchor_hash
    }

    pub fn duty_block(&self) -> &BlockRow {
        &self.duty_block
    }

    pub fn through(&self) -> &BlockRow {
        &self.through
    }

    pub fn profile(&self) -> &CoverageProfile {
        &self.profile
    }

    pub fn deadline_s(&self) -> i128 {
        self.deadline_s
    }

    pub fn unattested_height(&self) -> Option<u64> {
        self.unattested_height
    }
}
