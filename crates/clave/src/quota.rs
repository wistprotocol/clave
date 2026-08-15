use crate::db::Db;
use crate::error::Result;

use crate::registry;
use wist_core::reputation::{apply_provisional_cap, base_u};

fn reputation_u() -> i64 {
    apply_provisional_cap(base_u(0), 0, 0) as i64
}

pub fn quota_q(db: &Db, at: &str) -> Result<i64> {
    let base = registry::effective(db, "quota_base", at)?;
    let slope = registry::effective(db, "quota_slope", at)?;
    Ok(base + ((slope * reputation_u()) / 1_000_000))
}

pub fn quota_remaining(db: &Db, domain: &str, at: &str) -> Result<i64> {
    let day = at.get(..10).unwrap_or(at);
    let noise = db.noise_ping_count(domain, day)?;
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

    #[test]
    fn quota_q_is_1100_at_registry_defaults() {
        let (_tmp, db) = open_db();
        assert_eq!(quota_q(&db, "2026-08-15T00:00:00Z").unwrap(), 1100);
    }

    #[test]
    fn quota_q_follows_quota_parameters() {
        let (_tmp, db) = open_db();
        db.set_param("quota_base", 10).unwrap();
        db.set_param("quota_slope", 500).unwrap();
        assert_eq!(quota_q(&db, "2026-08-15T00:00:00Z").unwrap(), 10 + 50);
    }

    #[test]
    fn quota_remaining_subtracts_same_day_noise_and_floors_at_zero() {
        let (_tmp, db) = open_db();
        let at = "2026-08-15T10:00:00Z";
        assert_eq!(quota_remaining(&db, "example.com", at).unwrap(), 1100);
        db.bump_noise_ping("example.com", "2026-08-15").unwrap();
        db.bump_noise_ping("example.com", "2026-08-15").unwrap();
        assert_eq!(quota_remaining(&db, "example.com", at).unwrap(), 1098);
        assert_eq!(
            quota_remaining(&db, "example.com", "2026-08-16T00:00:00Z").unwrap(),
            1100
        );
        db.set_param("quota_base", 0).unwrap();
        db.set_param("quota_slope", 0).unwrap();
        assert_eq!(quota_remaining(&db, "example.com", at).unwrap(), 0);
    }
}
