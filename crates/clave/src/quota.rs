use crate::db::Db;
use crate::error::Result;

use crate::registry;

/// WIST-4 §5 and WIST-2 §4: every Registrable Domain's Ping quota for a
/// UTC day is `quota_base` in force at the instant, the same for every
/// Registrable Domain.
pub fn quota_q(db: &Db, at: &str) -> Result<i64> {
    registry::effective(db, "quota_base", at)
}

/// WIST-4 §3.1: the Registrable Domain under the snapshot in force at `at`,
/// shared by every host under it.
pub fn quota_remaining(db: &Db, host: &str, at: &str) -> Result<i64> {
    let day = at.get(..10).unwrap_or(at);
    let unit = crate::suffix_list::unit_at(db, host, at)?;
    let noise = db.noise_ping_count(&unit, day)?;
    Ok((quota_q(db, at)? - noise).max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_db() -> (tempfile::TempDir, Db) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        (tmp, db)
    }

    fn seal_quota_base(db: &Db, value: i64) {
        crate::db::tests::seal_epoch(
            db,
            0,
            "2026-08-01T00:00:00Z",
            &[crate::db::ParamChangeRow {
                entry_index: 0,
                parameter: "quota_base",
                value,
                effective_at: "2026-08-01T00:00:00Z",
            }],
        );
    }

    #[test]
    fn quota_q_is_the_registry_default() {
        let (_tmp, db) = open_db();
        assert_eq!(quota_q(&db, "2026-08-15T00:00:00Z").unwrap(), 1000);
    }

    #[test]
    fn quota_q_follows_quota_base() {
        let (_tmp, db) = open_db();
        seal_quota_base(&db, 10);
        assert_eq!(quota_q(&db, "2026-08-15T00:00:00Z").unwrap(), 10);
    }

    #[test]
    fn quota_remaining_subtracts_the_day_s_noise_pings() {
        let (_tmp, db) = open_db();
        seal_quota_base(&db, 2);
        for _ in 0..3 {
            db.bump_noise_ping("example.com", "2026-08-15").unwrap();
        }
        assert_eq!(
            quota_remaining(&db, "example.com", "2026-08-15T12:00:00Z").unwrap(),
            0
        );
        assert_eq!(
            quota_remaining(&db, "example.com", "2026-08-16T12:00:00Z").unwrap(),
            2
        );
        assert_eq!(
            quota_remaining(&db, "other.example", "2026-08-15T12:00:00Z").unwrap(),
            2
        );
    }
}
