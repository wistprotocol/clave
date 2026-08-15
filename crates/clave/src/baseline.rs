use crate::db::Db;
use crate::error::Result;
use crate::fetch::Client;
use std::path::Path;
use wist_core::crypto::SigningKey;

/// WIST-2 §5: known feeds are polled at `baseline_poll_seconds`
/// regardless of Pings, and a budget-suspended walk resumes on a later
/// run rather than being treated as complete.
pub fn due_domains(db: &Db, now_epoch: i64) -> Result<Vec<String>> {
    let now = jiff::Timestamp::from_second(now_epoch)
        .map_err(|_| crate::error::Error::Governance("timestamp out of range".into()))?
        .to_string();
    let interval = crate::registry::effective(db, "baseline_poll_seconds", &now)?;
    let mut due = Vec::new();
    for (domain, last_pull_at) in db.list_publisher_pull_times()? {
        let stale = match &last_pull_at {
            None => true,
            Some(t) => t
                .parse::<jiff::Timestamp>()
                .map(|ts| now_epoch - ts.as_second() >= interval)
                .unwrap_or(true),
        };
        if stale || db.walk_suspended(&domain)? {
            due.push(domain);
        }
    }
    Ok(due)
}

pub fn run_pass(
    db: &Db,
    client: &Client,
    sk: &SigningKey,
    data_dir: &Path,
    now_epoch: i64,
) -> Result<Vec<String>> {
    let now = jiff::Timestamp::from_second(now_epoch)
        .map_err(|_| crate::error::Error::Governance("timestamp out of range".into()))?
        .to_string();
    let due = due_domains(db, now_epoch)?;
    for domain in &due {
        let _ = crate::ingest::run(db, client, data_dir, domain, &now);
    }
    crate::appeals::poll(db, client, sk, now_epoch)?;
    Ok(due)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn ts(epoch: i64) -> String {
        jiff::Timestamp::from_second(epoch).unwrap().to_string()
    }

    fn open_db() -> (tempfile::TempDir, Db) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        (tmp, db)
    }

    #[test]
    fn due_when_never_pulled_stale_or_suspended_but_not_when_fresh() {
        let (_tmp, db) = open_db();
        db.insert_publisher("never.example", b"{}", "k", "p")
            .unwrap();
        db.insert_publisher("stale.example", b"{}", "k", "p")
            .unwrap();
        db.insert_publisher("fresh.example", b"{}", "k", "p")
            .unwrap();
        db.insert_publisher("suspended.example", b"{}", "k", "p")
            .unwrap();
        db.set_publisher_pulled("stale.example", &ts(NOW - 90000))
            .unwrap();
        db.set_publisher_pulled("fresh.example", &ts(NOW - 60))
            .unwrap();
        db.set_publisher_pulled("suspended.example", &ts(NOW - 60))
            .unwrap();
        db.set_walk_suspended("suspended.example", true).unwrap();

        let mut due = due_domains(&db, NOW).unwrap();
        due.sort();
        assert_eq!(
            due,
            vec![
                "never.example".to_string(),
                "stale.example".to_string(),
                "suspended.example".to_string()
            ]
        );
    }

    #[test]
    fn baseline_interval_follows_the_parameter() {
        let (_tmp, db) = open_db();
        db.insert_publisher("a.example", b"{}", "k", "p").unwrap();
        db.set_publisher_pulled("a.example", &ts(NOW - 120))
            .unwrap();
        assert!(due_domains(&db, NOW).unwrap().is_empty());
        db.set_param("baseline_poll_seconds", 60).unwrap();
        assert_eq!(
            due_domains(&db, NOW).unwrap(),
            vec!["a.example".to_string()]
        );
    }
}
