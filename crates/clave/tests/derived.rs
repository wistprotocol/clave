mod common;

use common::{admit_auditor, AUDITOR_A, AUDITOR_A_SEED};

const NOW: i64 = 1_800_000_000;
const HOUR: i64 = 3600;

fn ts(epoch: i64) -> String {
    jiff::Timestamp::from_second(epoch).unwrap().to_string()
}

#[test]
fn a_silent_auditor_is_removed_for_cause_once_its_coverage_failures_pass_the_maximum() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("example-log.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    admit_auditor(&db, &sk, AUDITOR_A, "a1", &AUDITOR_A_SEED);
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    for height in 1..=119 {
        clave::seal::run(&db, data.path(), &sk, NOW + height * HOUR).unwrap();
        assert!(
            !db.auditor_in_coverage_failure(AUDITOR_A, &ts(NOW + height * HOUR))
                .unwrap(),
            "at Block {height}"
        );
    }
    assert_eq!(db.count_pending_entries("registry_update").unwrap(), 0);
    clave::seal::run(&db, data.path(), &sk, NOW + 120 * HOUR).unwrap();
    assert!(db
        .auditor_in_coverage_failure(AUDITOR_A, &ts(NOW + 120 * HOUR))
        .unwrap());
    assert_eq!(
        db.count_pending_entries("registry_update").unwrap(),
        1,
        "the removal is queued once the twenty-fifth failed duty is established"
    );
    let seal = clave::seal::run(&db, data.path(), &sk, NOW + 121 * HOUR).unwrap();
    assert_eq!(seal.entry_count, 1, "dropped {:?}", seal.dropped);
    let raw = std::fs::read(
        data.path()
            .join(format!("log/blocks/{:09}.json.zst", seal.block_number)),
    )
    .unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::stream::decode_all(&raw[..]).unwrap()).unwrap();
    let removal = &block["entries"][0]["body"]["update"];
    assert_eq!(removal["action"], "auditor_remove");
    assert_eq!(removal["subject"], AUDITOR_A);
    assert_eq!(removal["details"]["key_id"], "a1");
    assert_eq!(
        removal["evidence"].as_array().unwrap().len(),
        25,
        "the evidence names every failed Block counting at the head"
    );
    let roster =
        clave::history::roster::RosterHistory::reconstruct(data.path(), db.last_block().unwrap())
            .unwrap();
    let removed_at = NOW + 121 * HOUR;
    assert!(roster.admitted_key_at(AUDITOR_A, removed_at).is_none());
    assert!(roster
        .admitted_key_at(AUDITOR_A, removed_at - HOUR)
        .is_some());
    clave::seal::run(&db, data.path(), &sk, NOW + 122 * HOUR).unwrap();
    assert_eq!(
        db.count_pending_entries("registry_update").unwrap(),
        0,
        "a removed Auditor holds no duty and is not removed twice"
    );
}
