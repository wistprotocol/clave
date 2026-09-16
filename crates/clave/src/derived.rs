use crate::db::{Db, DerivedAuditorRow, DerivedPublisherRow, DerivedPublisherState};
use crate::error::{Error, Result};
use crate::history::extension::ExtensionHistory;
use std::path::Path;
use wist_core::objects::SanctionDeadlineLabel;
use wist_core::reputation::PROVISIONAL_CAP_U;

type OwnedPublisherState = (
    String,
    u64,
    u8,
    u8,
    u8,
    String,
    Vec<String>,
    Vec<(SanctionDeadlineLabel, String)>,
);

fn instant(epoch: i128) -> Result<String> {
    let epoch = i64::try_from(epoch).map_err(|_| Error::History("instant out of range".into()))?;
    Ok(jiff::Timestamp::from_second(epoch)
        .map_err(|_| Error::History("instant out of range".into()))?
        .to_string())
}

pub fn refresh(db: &Db, data_dir: &Path) -> Result<()> {
    let Some(head) = db.last_block()? else {
        return Ok(());
    };
    let history = ExtensionHistory::reconstruct(data_dir, Some(head.clone()))?;
    let height = head.block_number;
    let sealed_at_s = crate::registry::epoch(&head.sealed_at)?;
    let mut owned: Vec<OwnedPublisherState> = Vec::new();
    for publisher in history.publishers() {
        let reputation_u = history
            .reputation(&publisher, height)
            .map_or(PROVISIONAL_CAP_U, |state| state.reputation_u);
        let level = history.sanction_level(&publisher, height);
        let enforceable = history.enforceable_level(&publisher, height);
        let mut since = height;
        let mut evidence = Vec::new();
        let mut deadlines = Vec::new();
        let mut fallback = 0u8;
        if let Some(processes) = history.processes(&publisher) {
            if let Some((at, _)) = processes.levels.iter().rev().find(|(h, _)| *h <= height) {
                since = *at;
            }
            if let Some((_, activations)) = processes
                .activations
                .iter()
                .rev()
                .find(|(h, _)| *h <= height)
            {
                evidence = activations.iter().flatten().cloned().collect();
                evidence.sort();
                evidence.dedup();
                fallback = if activations[1].is_some() {
                    2
                } else if activations[0].is_some() {
                    1
                } else {
                    0
                };
            }
            for process in &processes.accepted {
                if process.notice.block_number > height {
                    continue;
                }
                if process
                    .void_at_s
                    .is_some_and(|void| void <= i128::from(sealed_at_s))
                {
                    continue;
                }
                let now = i128::from(sealed_at_s);
                if process.appeal.is_none() && process.appeal_window_close_s > now {
                    deadlines.push((SanctionDeadlineLabel::Appeal, process.appeal_window_close_s));
                }
                if process.appeal.is_none()
                    && process.unappealed.is_none()
                    && process.seal_deadline_s > now
                {
                    deadlines.push((
                        SanctionDeadlineLabel::AppealSealing,
                        process.seal_deadline_s,
                    ));
                }
                if let Some(due) = process.ruling_deadline_s {
                    if process.merits.is_none() && due > now {
                        deadlines.push((SanctionDeadlineLabel::Ruling, due));
                    }
                }
            }
        }
        let level_since =
            instant(i128::from(history.block_sealed_at_s(since).ok_or_else(
                || Error::History("derived level has no Block".into()),
            )?))?;
        let deadlines = deadlines
            .into_iter()
            .map(|(label, at)| instant(at).map(|at| (label, at)))
            .collect::<Result<Vec<_>>>()?;
        owned.push((
            publisher,
            reputation_u,
            level,
            enforceable,
            fallback,
            level_since,
            evidence,
            deadlines,
        ));
    }
    let rows: Vec<DerivedPublisherRow> = owned
        .iter()
        .map(
            |(domain, reputation_u, level, enforceable, fallback, since, evidence, deadlines)| {
                DerivedPublisherRow {
                    domain,
                    reputation_u: *reputation_u,
                    level: *level,
                    enforceable_level: *enforceable,
                    fallback_level: *fallback,
                    level_since: since,
                    evidence,
                    deadlines,
                }
            },
        )
        .collect();
    let auditors: Vec<(String, bool)> = history
        .roster()
        .admitted_at(sealed_at_s)
        .into_iter()
        .map(|(auditor, _)| {
            (
                auditor.to_owned(),
                history.in_coverage_failure(auditor, height),
            )
        })
        .collect();
    let auditor_rows: Vec<DerivedAuditorRow> = auditors
        .iter()
        .map(|(auditor_id, coverage_failure)| DerivedAuditorRow {
            auditor_id,
            coverage_failure: *coverage_failure,
        })
        .collect();
    db.record_derived_state(height, &head.sealed_at, &rows, &auditor_rows)
}

pub fn publisher_state(db: &Db, domain: &str, at: &str) -> Result<Option<DerivedPublisherState>> {
    db.derived_publisher_state_at(domain, at)
}

pub fn reputation_for_day(db: &Db, domain: &str, at: &str) -> Result<u64> {
    let day_start = format!("{}T00:00:00Z", at.get(..10).unwrap_or(at));
    Ok(db
        .derived_publisher_state_before(domain, &day_start)?
        .map_or(PROVISIONAL_CAP_U, |state| state.reputation_u))
}
