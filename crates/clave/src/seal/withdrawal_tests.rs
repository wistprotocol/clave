use crate::ingest::stage_tests::{Log, Site};
use std::path::PathBuf;

const URL: &str = "https://localhost/a";
const BODY: &[u8] = b"withdrawable body";

fn unix(at: &str) -> i64 {
    crate::registry::unix(at).unwrap()
}

fn seal(log: &Log, at: &str) -> crate::error::Result<super::SealReport> {
    let signing = crate::keys::load(&log.data.path().join("keys/seed")).unwrap();
    super::run(&log.db, log.data.path(), &signing, unix(at))
}

fn withdrawn_log() -> (Site, Log, String) {
    let site = Site::new();
    let id = site.delta(
        URL,
        std::str::from_utf8(BODY).unwrap(),
        None,
        "2026-08-09T11:00:00Z",
    );
    site.feed(std::slice::from_ref(&id), "2026-08-09T11:30:00Z", None);
    let log = Log::onboard(&site);
    log.pull(&site).unwrap();
    seal(&log, "2026-08-09T13:00:00Z").unwrap();
    crate::snapshot::produce(&log.path(), log.data.path()).unwrap();
    let signing = crate::keys::load(&log.data.path().join("keys/seed")).unwrap();
    crate::governance::withdraw(
        &log.db,
        &signing,
        &site.host,
        &id,
        "court order",
        "DE",
        unix("2026-08-09T14:00:00Z"),
    )
    .unwrap();
    (site, log, id)
}

fn payload_path(log: &Log, id: &str) -> PathBuf {
    log.data
        .path()
        .join("payloads")
        .join(format!("{}.json", &id[7..]))
}

fn served_directories(log: &Log) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(log.data.path().join("snapshots"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "index.json")
        .collect();
    names.sort();
    names
}

fn listed_dates(log: &Log) -> Vec<String> {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(log.data.path().join("snapshots/index.json")).unwrap(),
    )
    .unwrap();
    index["index"]["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["snapshot_date"].as_str().unwrap().to_string())
        .collect()
}

fn head_epoch(log: &Log) -> u64 {
    let note = std::fs::read_to_string(log.data.path().join("checkpoint")).unwrap();
    wist_core::checkpoint::Checkpoint::parse(&note)
        .unwrap()
        .epoch_number()
}

fn withdrawal_height(log: &Log, id: &str) -> Option<u64> {
    log.db
        .withdrawal_state()
        .unwrap()
        .into_iter()
        .find(|(delta_id, _, _)| delta_id == id)
        .map(|(_, _, height)| height)
}

fn assert_removed(log: &Log, site: &Site, id: &str, when: &str) {
    assert!(
        !payload_path(log, id).exists(),
        "{when}: the Payload is served"
    );
    assert!(
        log.db.get_record(URL, &site.host).unwrap().is_none(),
        "{when}: the record is kept"
    );
    assert!(
        served_directories(log).is_empty(),
        "{when}: a Snapshot is served"
    );
    assert!(
        listed_dates(log).is_empty(),
        "{when}: the index lists a Snapshot"
    );
    assert!(
        log.db.pending_removals().unwrap().is_empty(),
        "{when}: the removal is still pending"
    );
}

#[test]
fn a_withdrawal_interrupted_at_any_commit_is_applied_before_its_checkpoint_is_served() {
    for commits in 0.. {
        let (site, log, id) = withdrawn_log();
        assert!(payload_path(&log, &id).exists());
        assert!(!served_directories(&log).is_empty());
        crate::db::interrupt::after(commits);
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            seal(&log, "2026-08-09T14:00:00Z")
        }));
        if crate::db::interrupt::disarm() {
            assert!(
                interrupted.is_ok_and(|sealed| sealed.is_ok()),
                "the seal ran to its end"
            );
            assert!(commits > 0, "the seal commits at least once");
            assert_removed(&log, &site, &id, "after an uninterrupted seal");
            for file in ["clave.sqlite", "clave.sqlite-wal"] {
                let held = std::fs::read(log.data.path().join(file)).unwrap_or_default();
                assert!(
                    !held.windows(BODY.len()).any(|window| window == BODY),
                    "{file} still holds the withdrawn content"
                );
            }
            break;
        }
        assert!(
            interrupted.is_err(),
            "the {commits}th commit interrupts the seal"
        );
        let height = withdrawal_height(&log, &id);
        if height.is_some() {
            assert!(
                log.db.get_record(URL, &site.host).unwrap().is_none(),
                "after the {commits}th commit: the record outlives the seal that withdrew it"
            );
        }
        if height.is_some_and(|height| head_epoch(&log) >= height) {
            assert_removed(
                &log,
                &site,
                &id,
                &format!("after the {commits}th commit, with the head served"),
            );
        }
        crate::publication::recover(&log.db, log.data.path()).unwrap();
        if height.is_none() {
            seal(&log, "2026-08-09T14:00:00Z").unwrap();
        }
        let height = withdrawal_height(&log, &id).expect("the withdrawal sealed");
        assert!(head_epoch(&log) >= height, "recovery served the head");
        assert_removed(
            &log,
            &site,
            &id,
            &format!("after recovery from the {commits}th commit"),
        );
    }
}
