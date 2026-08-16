use crate::db::{Db, GovernanceEntry};
use crate::error::Result;
use crate::registry;

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
/// "overturned" ruling each void the state; a lift clears it.
pub fn sanction_level(db: &Db, domain: &str, at: &str) -> Result<u8> {
    let entries = db.governance_for_domain(domain)?;
    let at_epoch = epoch(at);

    let latest_sanction = entries
        .iter()
        .rfind(|e| e.action == "sanction" && epoch(&e.sealed_at) <= at_epoch);
    let Some(sanction) = latest_sanction else {
        return Ok(0);
    };
    let level = sanction.level.unwrap_or(0).clamp(0, 4) as u8;

    let lifted = entries.iter().any(|e| {
        e.action == "sanction_lift"
            && epoch(&e.sealed_at) >= epoch(&sanction.sealed_at)
            && epoch(&e.sealed_at) <= at_epoch
    });
    if lifted {
        return Ok(0);
    }

    if level >= 3 {
        if let Some(notice_id) = sanction.notice_id.as_deref() {
            let notice_sealed_at = entries
                .iter()
                .find(|e| e.update_id == notice_id)
                .map(|e| e.sealed_at.clone())
                .unwrap_or_else(|| sanction.sealed_at.clone());
            if !appeal_process_alive(db, &entries, notice_id, &notice_sealed_at, at_epoch)? {
                return Ok(0);
            }
        }
    }
    Ok(level)
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
            }],
        );
        assert_eq!(sanction_level(&db, "example.com", &ts(T0 + 50)).unwrap(), 2);
        assert_eq!(
            sanction_level(&db, "example.com", &ts(T0 + 200)).unwrap(),
            0
        );
    }

    fn notice_row(update_id: &str) -> GovernanceRow<'_> {
        GovernanceRow {
            update_id,
            action: "notice",
            domain: "example.com",
            level: None,
            notice_id: None,
            outcome: None,
        }
    }

    #[test]
    fn level_three_voids_at_t_when_nothing_discharges_it() {
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
            0
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
            }],
        );
        let t_instant = T0 + (14 + 7) * DAY;
        assert_eq!(
            sanction_level(&db, "example.com", &ts(t_instant + DAY)).unwrap(),
            3
        );
    }

    #[test]
    fn appeal_without_ruling_voids_at_the_ruling_deadline() {
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
            }],
        );
        let deadline = appeal_sealed + 30 * DAY;
        assert_eq!(
            sanction_level(&db, "example.com", &ts(deadline - 1)).unwrap(),
            3
        );
        assert_eq!(
            sanction_level(&db, "example.com", &ts(deadline)).unwrap(),
            0
        );
    }

    #[test]
    fn overturned_ruling_voids_and_upheld_keeps_the_state() {
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
                }],
            );
            let probe = appeal_sealed + 2 * DAY;
            let expected = if outcome == "overturned" { 0 } else { 3 };
            assert_eq!(
                sanction_level(&db, "example.com", &ts(probe)).unwrap(),
                expected,
                "outcome {outcome}"
            );
        }
    }
}
