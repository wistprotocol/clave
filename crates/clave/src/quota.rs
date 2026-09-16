use crate::db::Db;
use crate::error::Result;

use crate::registry;

/// WIST-4 §6.4: the quota for a UTC day reads `reputation_u` at the highest
/// Block sealed before the day began; a domain with no such Block reads the
/// empty Log, the new-domain value.
pub fn quota_q(db: &Db, domain: &str, at: &str) -> Result<i64> {
    let base = registry::effective(db, "quota_base", at)?;
    let slope = registry::effective(db, "quota_slope", at)?;
    let reputation_u = crate::derived::reputation_for_day(db, domain, at)? as i64;
    Ok(base + ((slope * reputation_u) / 1_000_000))
}

pub fn quota_remaining(db: &Db, domain: &str, at: &str) -> Result<i64> {
    let day = at.get(..10).unwrap_or(at);
    let noise = db.noise_ping_count(domain, day)?;
    Ok((quota_q(db, domain, at)? - noise).max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_db() -> (tempfile::TempDir, Db) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        (tmp, db)
    }

    #[test]
    fn quota_q_is_1100_at_registry_defaults() {
        let (_tmp, db) = open_db();
        assert_eq!(
            quota_q(&db, "example.com", "2026-08-15T00:00:00Z").unwrap(),
            1100
        );
    }

    #[test]
    fn quota_q_follows_quota_parameters() {
        let (_tmp, db) = open_db();
        db.set_param("quota_base", 10).unwrap();
        db.set_param("quota_slope", 500).unwrap();
        assert_eq!(
            quota_q(&db, "example.com", "2026-08-15T00:00:00Z").unwrap(),
            10 + 50
        );
    }

    #[test]
    fn quota_q_reads_the_reputation_derived_before_the_day_began() {
        let (_tmp, db) = open_db();
        let row = |reputation_u: u64| crate::db::DerivedPublisherRow {
            domain: "example.com",
            reputation_u,
            level: 0,
            enforceable_level: 0,
            fallback_level: 0,
            level_since: "2026-08-14T00:00:00Z",
            evidence: &[],
            deadlines: &[],
        };
        db.record_derived_state(3, "2026-08-14T23:00:00Z", &[row(500_000)], &[])
            .unwrap();
        db.record_derived_state(4, "2026-08-15T00:00:00Z", &[row(1_000_000)], &[])
            .unwrap();
        assert_eq!(
            quota_q(&db, "example.com", "2026-08-15T12:00:00Z").unwrap(),
            100 + 5_000,
            "the Block sealed at the day's first instant is not before the day began"
        );
        assert_eq!(
            quota_q(&db, "example.com", "2026-08-16T12:00:00Z").unwrap(),
            100 + 10_000
        );
        assert_eq!(
            quota_q(&db, "other.example", "2026-08-16T12:00:00Z").unwrap(),
            1100
        );
    }
}
