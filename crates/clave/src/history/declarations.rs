use super::{History, VerifiedEpoch};
use crate::db::{Db, EpochRow};
use crate::error::Result;
use std::path::Path;

pub use wist_core::declarations::{
    Declaration, Declarations, Domain, Effects, Installation, Position, Projection, RecoveryWindow,
    Settlement,
};

pub trait DeclarationsReplay: Sized {
    fn reconstruct(db: &Db, directory: &Path, head: Option<EpochRow>) -> Result<Self>;
    fn apply(&mut self, verified: &VerifiedEpoch) -> Result<Effects>;
}

impl DeclarationsReplay for Declarations {
    fn reconstruct(db: &Db, directory: &Path, head: Option<EpochRow>) -> Result<Self> {
        let mut history = History::open(db, directory, head)?;
        while history.next_epoch()?.is_some() {}
        Ok(history.replay().declarations().clone())
    }

    fn apply(&mut self, verified: &VerifiedEpoch) -> Result<Effects> {
        Ok(self.apply_epoch(
            verified.epoch_number(),
            verified.root(),
            verified.sealed_at(),
            verified.recovery_window_days,
            verified.declaration_activation_epochs,
            &verified.limits,
            verified.entries(),
        )?)
    }
}
