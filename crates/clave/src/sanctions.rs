use crate::db::{Db, GovernanceEntry};
use crate::error::Result;
use crate::registry;
use wist_core::objects::SanctionDeadlineLabel;

const DAY: i64 = 86400;

fn epoch(ts: &str) -> i64 {
    ts.parse::<jiff::Timestamp>()
        .map(|t| t.as_second())
        .unwrap_or(i64::MAX)
}

fn appeal_process_alive(
    db: &Db,
    entries: &[GovernanceEntry],
    notice_id: &str,
    notice_sealed_at: &str,
    at_epoch: i64,
) -> Result<bool> {
    let notice_epoch = epoch(notice_sealed_at);
    let window_days = registry::effective(db, "appeal_window_days", notice_sealed_at)?;
    let seal_days = registry::effective(db, "appeal_seal_days", notice_sealed_at)?;
    let window_close = notice_epoch + window_days * DAY;
    let t_instant = window_close + seal_days * DAY;

    // WIST-4 §7: only an appeal sealed by T counts. A late one is recorded
    // but discharges nothing and starts no ruling deadline.
    let appeal = entries.iter().find(|e| {
        e.action == "appeal"
            && e.notice_id.as_deref() == Some(notice_id)
            && epoch(&e.sealed_at) <= t_instant
    });
    let ruling_for = |outcome_filter: Option<&str>| {
        entries.iter().find(|e| {
            e.action == "appeal_ruling"
                && e.notice_id.as_deref() == Some(notice_id)
                && outcome_filter.is_none_or(|o| e.outcome.as_deref() == Some(o))
        })
    };

    if let Some(ruling) = ruling_for(Some("overturned")) {
        if at_epoch >= epoch(&ruling.sealed_at) {
            return Ok(false);
        }
    }

    match appeal {
        Some(appeal_entry) => {
            let appeal_epoch = epoch(&appeal_entry.sealed_at);
            let ruling_days =
                registry::effective(db, "ruling_deadline_days", &appeal_entry.sealed_at)?;
            let deadline = appeal_epoch + ruling_days * DAY;
            let ruled = ruling_for(None).is_some_and(|r| epoch(&r.sealed_at) <= deadline);
            if !ruled && at_epoch >= deadline {
                return Ok(false);
            }
        }
        None => {
            let discharged = ruling_for(Some("unappealed")).is_some_and(|r| {
                epoch(&r.sealed_at) >= window_close && epoch(&r.sealed_at) <= t_instant
            });
            if !discharged && at_epoch >= t_instant {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// In-force sanction ladder level for a domain at instant `at`, derived
/// from sealed governance Entries under WIST-4 §7's void rules: a lapsed
/// T (window + sealing deadline), a lapsed ruling deadline, and an
/// "overturned" ruling each void the level-3 rejection or the level-4
/// exclusion and nothing below them; a lift clears the state.
///
/// The rungs are read from the sanctions the Log carries rather than
/// recomputed from Audit Records, so a voided level 3 or 4 falls back to
/// the highest rung at or below 2 that a sanction recorded, and to level
/// 1 otherwise: every sanction names evidence establishing at least one
/// Confirmed Inconsistency, which is §7's level-1 criterion.
pub fn sanction_level(db: &Db, domain: &str, at: &str) -> Result<u8> {
    Ok(sanction_state(db, domain, at)?.level)
}

/// The in-force level and the instant it took effect — the `sealed_at`
/// of the Block sealing the sanction that carries it, which WIST-3 §7
/// reads as the height from which level 3 stops materialization.
pub struct SanctionState {
    pub level: u8,
    pub effective_at: Option<String>,
    /// The Registry Update IDs establishing the state, and each deadline
    /// still open against it (WIST-3 §7's `sanction_state` tuple).
    pub evidence: Vec<String>,
    pub deadlines: Vec<(SanctionDeadlineLabel, String)>,
}

pub fn sanction_state(db: &Db, domain: &str, at: &str) -> Result<SanctionState> {
    let entries = db.governance_for_domain(domain)?;
    let at_epoch = epoch(at);

    let in_force = |e: &&GovernanceEntry| e.action == "sanction" && epoch(&e.sealed_at) <= at_epoch;
    let latest_sanction = entries.iter().rfind(in_force);
    let Some(sanction) = latest_sanction else {
        return Ok(SanctionState {
            level: 0,
            effective_at: None,
            evidence: Vec::new(),
            deadlines: Vec::new(),
        });
    };
    let lower_rung = entries
        .iter()
        .filter(in_force)
        .filter_map(|e| e.level)
        .filter(|l| *l <= 2)
        .max()
        .unwrap_or(1)
        .clamp(1, 2) as u8;
    let level = sanction.level.unwrap_or(0).clamp(0, 4) as u8;

    let lifted = entries.iter().any(|e| {
        e.action == "sanction_lift"
            && epoch(&e.sealed_at) >= epoch(&sanction.sealed_at)
            && epoch(&e.sealed_at) <= at_epoch
    });
    if lifted {
        return Ok(SanctionState {
            level: 0,
            effective_at: None,
            evidence: Vec::new(),
            deadlines: Vec::new(),
        });
    }

    if level >= 3 {
        if let Some(notice_id) = sanction.notice_id.as_deref() {
            let notice_sealed_at = entries
                .iter()
                .find(|e| e.update_id == notice_id)
                .map(|e| e.sealed_at.clone())
                .unwrap_or_else(|| sanction.sealed_at.clone());
            if !appeal_process_alive(db, &entries, notice_id, &notice_sealed_at, at_epoch)? {
                return Ok(SanctionState {
                    level: lower_rung,
                    effective_at: Some(sanction.sealed_at.clone()),
                    evidence: vec![sanction.update_id.clone()],
                    deadlines: Vec::new(),
                });
            }
        }
    }
    let mut deadlines = Vec::new();
    if level >= 3 {
        if let Some(notice_id) = sanction.notice_id.as_deref() {
            if let Some(notice) = entries.iter().find(|e| e.update_id == notice_id) {
                let window_days = registry::effective(db, "appeal_window_days", &notice.sealed_at)?;
                let seal_days = registry::effective(db, "appeal_seal_days", &notice.sealed_at)?;
                let opened = epoch(&notice.sealed_at);
                for (label, at) in [
                    (SanctionDeadlineLabel::Appeal, opened + window_days * DAY),
                    (
                        SanctionDeadlineLabel::AppealSealing,
                        opened + (window_days + seal_days) * DAY,
                    ),
                ] {
                    if at > at_epoch {
                        deadlines.push((label, instant(at)?));
                    }
                }
                if let Some(appeal) = entries
                    .iter()
                    .find(|e| e.action == "appeal" && e.notice_id.as_deref() == Some(notice_id))
                {
                    let ruling_days =
                        registry::effective(db, "ruling_deadline_days", &appeal.sealed_at)?;
                    let due = epoch(&appeal.sealed_at) + ruling_days * DAY;
                    if due > at_epoch {
                        deadlines.push((SanctionDeadlineLabel::Ruling, instant(due)?));
                    }
                }
            }
        }
    }
    Ok(SanctionState {
        level,
        effective_at: Some(sanction.sealed_at.clone()),
        evidence: vec![sanction.update_id.clone()],
        deadlines,
    })
}

fn instant(epoch: i64) -> Result<String> {
    jiff::Timestamp::from_second(epoch)
        .map(|t| t.to_string())
        .map_err(|_| crate::error::Error::Governance("deadline instant out of range".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::GovernanceRow;

    const DAY: i64 = 86400;

    fn ts(epoch: i64) -> String {
        jiff::Timestamp::from_second(epoch).unwrap().to_string()
    }

    fn open_db() -> (tempfile::TempDir, Db) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        (tmp, db)
    }

    const T0: i64 = 1_800_000_000;

    fn seal_gov(db: &Db, block: u64, sealed_epoch: i64, rows: &[GovernanceRow]) {
        db.commit_seal(
            &[],
            block,
            &format!("sha256:h{block}"),
            &ts(sealed_epoch),
            &[],
            &[],
            rows,
            &[],
        )
        .unwrap();
    }

    fn sanction_row<'a>(
        update_id: &'a str,
        level: i64,
        notice_id: Option<&'a str>,
    ) -> GovernanceRow<'a> {
        GovernanceRow {
            update_id,
            action: "sanction",
            domain: "example.com",
            level: Some(level),
            notice_id,
            outcome: None,
            kind: None,
        }
    }

    #[test]
    fn no_entries_means_level_zero() {
        let (_tmp, db) = open_db();
        assert_eq!(sanction_level(&db, "example.com", &ts(T0)).unwrap(), 0);
    }

    #[test]
    fn level_one_in_force_from_sealing() {
        let (_tmp, db) = open_db();
        seal_gov(&db, 0, T0, &[sanction_row("sha256:s1", 1, None)]);
        assert_eq!(sanction_level(&db, "example.com", &ts(T0 - 1)).unwrap(), 0);
        assert_eq!(
            sanction_level(&db, "example.com", &ts(T0 + 100)).unwrap(),
            1
        );
    }

    #[test]
    fn sanction_lift_clears_the_state() {
        let (_tmp, db) = open_db();
        seal_gov(&db, 0, T0, &[sanction_row("sha256:s1", 2, None)]);
        seal_gov(
            &db,
            1,
            T0 + 100,
            &[GovernanceRow {
                update_id: "sha256:l1",
                action: "sanction_lift",
                domain: "example.com",
                level: None,
                notice_id: None,
                outcome: None,
                kind: None,
            }],
        );
        assert_eq!(sanction_level(&db, "example.com", &ts(T0 + 50)).unwrap(), 2);
        assert_eq!(
            sanction_level(&db, "example.com", &ts(T0 + 200)).unwrap(),
            0
        );
    }

    #[test]
    fn a_voided_level_three_falls_back_to_the_rungs_below_it() {
        let (_tmp, db) = open_db();
        seal_gov(&db, 0, T0, &[sanction_row("sha256:s1", 2, None)]);
        seal_gov(&db, 1, T0 + 100, &[notice_row("sha256:n1")]);
        seal_gov(
            &db,
            2,
            T0 + 200,
            &[sanction_row("sha256:s2", 3, Some("sha256:n1"))],
        );
        assert_eq!(
            sanction_level(&db, "example.com", &ts(T0 + 300)).unwrap(),
            3
        );
        let after_t = T0 + 100 + 22 * DAY;
        assert_eq!(sanction_level(&db, "example.com", &ts(after_t)).unwrap(), 2);
    }

    #[test]
    fn a_voided_level_three_with_no_lower_rung_filed_keeps_level_one() {
        let (_tmp, db) = open_db();
        seal_gov(&db, 0, T0, &[notice_row("sha256:n1")]);
        seal_gov(
            &db,
            1,
            T0 + 100,
            &[sanction_row("sha256:s1", 3, Some("sha256:n1"))],
        );
        let after_t = T0 + 22 * DAY;
        assert_eq!(sanction_level(&db, "example.com", &ts(after_t)).unwrap(), 1);
    }

    fn notice_row(update_id: &str) -> GovernanceRow<'_> {
        GovernanceRow {
            update_id,
            action: "notice",
            domain: "example.com",
            level: None,
            notice_id: None,
            outcome: None,
            kind: None,
        }
    }

    #[test]
    fn level_three_voids_to_the_rung_below_at_t_when_nothing_discharges_it() {
        let (_tmp, db) = open_db();
        seal_gov(
            &db,
            0,
            T0,
            &[
                notice_row("sha256:n1"),
                sanction_row("sha256:s1", 3, Some("sha256:n1")),
            ],
        );
        let t_instant = T0 + (14 + 7) * DAY;
        assert_eq!(
            sanction_level(&db, "example.com", &ts(t_instant - 1)).unwrap(),
            3
        );
        assert_eq!(
            sanction_level(&db, "example.com", &ts(t_instant)).unwrap(),
            1
        );
    }

    #[test]
    fn unappealed_ruling_after_window_close_discharges_t() {
        let (_tmp, db) = open_db();
        seal_gov(
            &db,
            0,
            T0,
            &[
                notice_row("sha256:n1"),
                sanction_row("sha256:s1", 3, Some("sha256:n1")),
            ],
        );
        seal_gov(
            &db,
            1,
            T0 + 14 * DAY,
            &[GovernanceRow {
                update_id: "sha256:r1",
                action: "appeal_ruling",
                domain: "example.com",
                level: None,
                notice_id: Some("sha256:n1"),
                outcome: Some("unappealed"),
                kind: None,
            }],
        );
        let t_instant = T0 + (14 + 7) * DAY;
        assert_eq!(
            sanction_level(&db, "example.com", &ts(t_instant + DAY)).unwrap(),
            3
        );
    }

    #[test]
    fn appeal_without_ruling_voids_to_the_rung_below_at_the_ruling_deadline() {
        let (_tmp, db) = open_db();
        seal_gov(
            &db,
            0,
            T0,
            &[
                notice_row("sha256:n1"),
                sanction_row("sha256:s1", 3, Some("sha256:n1")),
            ],
        );
        let appeal_sealed = T0 + 7 * DAY;
        seal_gov(
            &db,
            1,
            appeal_sealed,
            &[GovernanceRow {
                update_id: "sha256:a1",
                action: "appeal",
                domain: "example.com",
                level: None,
                notice_id: Some("sha256:n1"),
                outcome: None,
                kind: None,
            }],
        );
        let deadline = appeal_sealed + 30 * DAY;
        assert_eq!(
            sanction_level(&db, "example.com", &ts(deadline - 1)).unwrap(),
            3
        );
        assert_eq!(
            sanction_level(&db, "example.com", &ts(deadline)).unwrap(),
            1
        );
    }

    #[test]
    fn overturned_ruling_voids_to_the_rung_below_and_upheld_keeps_the_state() {
        let (_tmp, db) = open_db();
        for (notice, sanction, ruling, outcome, block_base, dom_epoch) in [
            ("sha256:n1", "sha256:s1", "sha256:r1", "overturned", 0, T0),
            (
                "sha256:n2",
                "sha256:s2",
                "sha256:r2",
                "upheld",
                10,
                T0 + 200 * DAY,
            ),
        ] {
            seal_gov(
                &db,
                block_base,
                dom_epoch,
                &[notice_row(notice), sanction_row(sanction, 3, Some(notice))],
            );
            let appeal_sealed = dom_epoch + 7 * DAY;
            let appeal_id = format!("sha256:apl{block_base}");
            seal_gov(
                &db,
                block_base + 1,
                appeal_sealed,
                &[GovernanceRow {
                    update_id: &appeal_id,
                    action: "appeal",
                    domain: "example.com",
                    level: None,
                    notice_id: Some(notice),
                    outcome: None,
                    kind: None,
                }],
            );
            seal_gov(
                &db,
                block_base + 2,
                appeal_sealed + DAY,
                &[GovernanceRow {
                    update_id: ruling,
                    action: "appeal_ruling",
                    domain: "example.com",
                    level: None,
                    notice_id: Some(notice),
                    outcome: Some(outcome),
                    kind: None,
                }],
            );
            let probe = appeal_sealed + 2 * DAY;
            let expected = if outcome == "overturned" { 1 } else { 3 };
            assert_eq!(
                sanction_level(&db, "example.com", &ts(probe)).unwrap(),
                expected,
                "outcome {outcome}"
            );
        }
    }
}
