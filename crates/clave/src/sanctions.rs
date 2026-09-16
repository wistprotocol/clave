use crate::db::Db;
use crate::error::Result;
use wist_core::objects::SanctionDeadlineLabel;

pub fn sanction_level(db: &Db, domain: &str, at: &str) -> Result<u8> {
    Ok(sanction_state(db, domain, at)?.level)
}

/// The Aggregator's enforceable sanction state for a domain at an instant,
/// read from the derived state of the highest Block sealed at or before it:
/// WIST-4 §7's ladder with notice-scoped voids, bounded for rungs 3 and 4
/// by the accepted notice the Aggregator must seal before enforcing.
pub struct SanctionState {
    pub level: u8,
    pub effective_at: Option<String>,
    /// The Audit Record IDs of the active rungs' activations and each
    /// deadline still open against the state (WIST-3 §7's tuple).
    pub evidence: Vec<String>,
    pub deadlines: Vec<(SanctionDeadlineLabel, String)>,
}

pub fn sanction_state(db: &Db, domain: &str, at: &str) -> Result<SanctionState> {
    let Some(state) = crate::derived::publisher_state(db, domain, at)? else {
        return Ok(SanctionState {
            level: 0,
            effective_at: None,
            evidence: Vec::new(),
            deadlines: Vec::new(),
        });
    };
    if state.enforceable_level == 0 {
        return Ok(SanctionState {
            level: 0,
            effective_at: None,
            evidence: Vec::new(),
            deadlines: Vec::new(),
        });
    }
    let lapsed = state.deadlines.iter().any(|(label, when)| {
        matches!(
            label,
            SanctionDeadlineLabel::AppealSealing | SanctionDeadlineLabel::Ruling
        ) && when.as_str() <= at
    });
    let level = if lapsed {
        state.enforceable_level.min(state.fallback_level)
    } else {
        state.enforceable_level
    };
    Ok(SanctionState {
        level,
        effective_at: (level > 0).then_some(state.level_since),
        evidence: state.evidence,
        deadlines: state
            .deadlines
            .into_iter()
            .filter(|(_, when)| when.as_str() > at)
            .collect(),
    })
}
