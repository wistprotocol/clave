mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86400;

fn ts(epoch: i64) -> String {
    jiff::Timestamp::from_second(epoch).unwrap().to_string()
}

fn setup() -> (
    tempfile::TempDir,
    clave::db::Db,
    wist_core::crypto::SigningKey,
) {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("example-log.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    (data, db, sk)
}

#[test]
fn sanction_level3_seals_notice_then_sanction_and_derives_in_force_state() {
    let (data, db, sk) = setup();
    let evidence = vec![
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
    ];
    let report = clave::governance::sanction(
        &db,
        &sk,
        "example.com",
        3,
        2,
        &evidence,
        Some("confirmed inconsistency"),
        NOW,
    )
    .unwrap();
    let notice_id = report
        .notice_id
        .clone()
        .expect("level 3 must seal a notice");

    let seal = clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    assert_eq!(seal.entry_count, 2);
    assert!(seal.dropped.is_empty());

    let gov = db.governance_for_domain("example.com").unwrap();
    assert_eq!(gov.len(), 2);
    let sanction = gov.iter().find(|g| g.action == "sanction").unwrap();
    assert_eq!(sanction.level, Some(3));
    assert_eq!(sanction.notice_id.as_deref(), Some(notice_id.as_str()));
    assert!(gov
        .iter()
        .any(|g| g.action == "notice" && g.update_id == notice_id));

    assert_eq!(
        clave::sanctions::sanction_level(&db, "example.com", &ts(NOW + 100)).unwrap(),
        3
    );
}

#[test]
fn level1_sanction_needs_no_notice() {
    let (data, db, sk) = setup();
    let evidence = vec![
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
    ];
    let report =
        clave::governance::sanction(&db, &sk, "example.com", 1, 1, &evidence, None, NOW).unwrap();
    assert!(report.notice_id.is_none());
    let seal = clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert_eq!(
        clave::sanctions::sanction_level(&db, "example.com", &ts(NOW + 1)).unwrap(),
        1
    );
}

#[test]
fn premature_unappealed_ruling_is_dropped_at_seal() {
    let (data, db, sk) = setup();
    let evidence = vec![
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
    ];
    let report = clave::governance::sanction(
        &db,
        &sk,
        "example.com",
        3,
        2,
        &evidence,
        Some("reason"),
        NOW,
    )
    .unwrap();
    let notice_id = report.notice_id.unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();

    clave::governance::rule(
        &db,
        &sk,
        "example.com",
        &notice_id,
        "unappealed",
        "window still open",
        NOW + DAY,
    )
    .unwrap();
    let seal = clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();
    assert_eq!(seal.entry_count, 0);
    assert_eq!(seal.dropped.len(), 1);
    assert!(seal.dropped[0].contains("unappealed"));

    let ok_epoch = NOW + 15 * DAY;
    clave::governance::rule(
        &db,
        &sk,
        "example.com",
        &notice_id,
        "unappealed",
        "window closed with no appeal",
        ok_epoch,
    )
    .unwrap();
    let seal = clave::seal::run(&db, data.path(), &sk, ok_epoch).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());
    assert_eq!(
        clave::sanctions::sanction_level(&db, "example.com", &ts(NOW + 22 * DAY)).unwrap(),
        3
    );
}

#[test]
fn payload_withdrawal_removes_payload_record_and_stale_snapshots() {
    let (listener, host) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "withdrawable body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    let client = clave::fetch::Client::new(true);
    clave::ingest::run(&db, &client, data.path(), &host, &ts(NOW)).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();

    let hex = id.strip_prefix("sha256:").unwrap();
    let payload_path = data.path().join("payloads").join(format!("{hex}.json"));
    assert!(payload_path.exists());
    let first_snapshot_dir = data.path().join("snapshots").join(&ts(NOW)[..10]);
    assert!(first_snapshot_dir.exists());
    assert!(db
        .get_record("https://example.com/a", &host)
        .unwrap()
        .is_some());

    clave::governance::withdraw(&db, &sk, &host, &id, "court order", "DE", NOW + 2 * DAY).unwrap();
    let seal = clave::seal::run(&db, data.path(), &sk, NOW + 2 * DAY).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());

    assert!(!payload_path.exists());
    assert!(db
        .get_record("https://example.com/a", &host)
        .unwrap()
        .is_none());
    assert!(
        !first_snapshot_dir.exists(),
        "snapshot containing withdrawn content must stop being served"
    );
    let new_snapshot_dir = data.path().join("snapshots").join(&ts(NOW + 2 * DAY)[..10]);
    assert!(new_snapshot_dir.exists());
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data.path().join("snapshots/index.json")).unwrap())
            .unwrap();
    let dates: Vec<&str> = index["index"]["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["snapshot_date"].as_str().unwrap())
        .collect();
    assert_eq!(dates, vec![&ts(NOW + 2 * DAY)[..10]]);
}

fn evidence() -> Vec<String> {
    vec![
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
    ]
}

fn ingested_publisher() -> (
    common::TestPub,
    tempfile::TempDir,
    clave::db::Db,
    wist_core::crypto::SigningKey,
    String,
    String,
) {
    let (listener, host) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "some body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    let client = clave::fetch::Client::new(true);
    clave::ingest::run(&db, &client, data.path(), &host, &ts(NOW)).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    (p, data, db, sk, host, id)
}

fn snapshot_weights(data: &std::path::Path, date: &str) -> Vec<(String, String)> {
    let conn =
        rusqlite::Connection::open(data.join("snapshots").join(date).join("tier0/index.sqlite"))
            .unwrap();
    let mut stmt = conn
        .prepare("SELECT url, weight FROM records ORDER BY url")
        .unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<(String, String)>>>()
        .unwrap();
    rows
}

#[test]
fn level2_marks_snapshot_records_reduced_weight() {
    let (_p, data, db, sk, host, _id) = ingested_publisher();
    clave::governance::sanction(&db, &sk, &host, 2, 1, &evidence(), None, NOW + DAY).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();
    let date = &ts(NOW + DAY)[..10];
    assert_eq!(
        snapshot_weights(data.path(), date),
        vec![("https://example.com/a".to_string(), "reduced".to_string())]
    );
}

#[test]
fn level4_excludes_domain_from_snapshots() {
    let (_p, data, db, sk, host, _id) = ingested_publisher();
    clave::governance::sanction(
        &db,
        &sk,
        &host,
        4,
        3,
        &evidence(),
        Some("three severity-3 findings"),
        NOW + DAY,
    )
    .unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();
    let date = &ts(NOW + DAY)[..10];
    assert!(snapshot_weights(data.path(), date).is_empty());
}

#[test]
fn level3_suspends_ingestion() {
    let (_p, data, db, sk, host, _id) = ingested_publisher();
    clave::governance::sanction(
        &db,
        &sk,
        &host,
        3,
        3,
        &evidence(),
        Some("severity-3 finding"),
        NOW + DAY,
    )
    .unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();
    let client = clave::fetch::Client::new(true);
    let before = db.ingest_bytes(&host, &ts(NOW + DAY)[..10]).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, &ts(NOW + DAY + 100)).unwrap();
    assert!(report.accepted.is_empty());
    assert_eq!(
        db.ingest_bytes(&host, &ts(NOW + DAY)[..10]).unwrap(),
        before,
        "a level-3 domain's feed must not be pulled at all"
    );
}

#[test]
fn appeal_poll_fetches_and_enqueues_a_served_appeal() {
    let (p, data, db, sk, host, _id) = ingested_publisher();
    let report = clave::governance::sanction(
        &db,
        &sk,
        &host,
        3,
        2,
        &evidence(),
        Some("confirmed inconsistency"),
        NOW + DAY,
    )
    .unwrap();
    let notice_id = report.notice_id.unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();

    let notice_hex = notice_id.strip_prefix("sha256:").unwrap();
    let appeal_update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "appeal",
        "subject": host,
        "details": {"notice": notice_id, "grounds": "the finding is wrong"},
        "effective_at": ts(NOW + 2 * DAY),
    });
    let envelope =
        wist_core::envelope::sign_envelope(&appeal_update, "update", "k1", &p.sk).unwrap();
    let appeals_dir = p.dir.path().join(".well-known/wist/appeals");
    std::fs::create_dir_all(&appeals_dir).unwrap();
    std::fs::write(
        appeals_dir.join(format!("{notice_hex}.json")),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();

    let client = clave::fetch::Client::new(true);
    let actions = clave::appeals::poll(&db, &client, &sk, NOW + 2 * DAY).unwrap();
    assert_eq!(actions.len(), 1);

    clave::seal::run(&db, data.path(), &sk, NOW + 2 * DAY).unwrap();
    let gov = db.governance_for_domain(&host).unwrap();
    assert!(gov
        .iter()
        .any(|g| g.action == "appeal" && g.notice_id.as_deref() == Some(notice_id.as_str())));

    let again = clave::appeals::poll(&db, &client, &sk, NOW + 3 * DAY).unwrap();
    assert!(
        again.is_empty(),
        "an already-sealed appeal must not re-enqueue"
    );
}

#[test]
fn appeal_poll_seals_unappealed_ruling_after_window_close() {
    let (_p, data, db, sk, host, _id) = ingested_publisher();
    let report = clave::governance::sanction(
        &db,
        &sk,
        &host,
        3,
        2,
        &evidence(),
        Some("confirmed inconsistency"),
        NOW + DAY,
    )
    .unwrap();
    let notice_id = report.notice_id.unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();

    let client = clave::fetch::Client::new(true);
    let during_window = clave::appeals::poll(&db, &client, &sk, NOW + 2 * DAY).unwrap();
    assert!(
        during_window.is_empty(),
        "no appeal served, window open: nothing to do"
    );

    let after_close = NOW + DAY + 15 * DAY;
    let actions = clave::appeals::poll(&db, &client, &sk, after_close).unwrap();
    assert_eq!(actions.len(), 1);
    let seal = clave::seal::run(&db, data.path(), &sk, after_close).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());
    let gov = db.governance_for_domain(&host).unwrap();
    assert!(gov.iter().any(|g| {
        g.action == "appeal_ruling"
            && g.outcome.as_deref() == Some("unappealed")
            && g.notice_id.as_deref() == Some(notice_id.as_str())
    }));
}

#[test]
fn late_appeal_is_recorded_but_discharges_nothing() {
    let (p, data, db, sk, host, _id) = ingested_publisher();
    let report = clave::governance::sanction(
        &db,
        &sk,
        &host,
        3,
        2,
        &evidence(),
        Some("confirmed inconsistency"),
        NOW + DAY,
    )
    .unwrap();
    let notice_id = report.notice_id.unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();

    // The window closes at day 15 and T falls at day 22; the Aggregator
    // discharges T on time with an "unappealed" ruling.
    let client = clave::fetch::Client::new(true);
    let actions = clave::appeals::poll(&db, &client, &sk, NOW + 16 * DAY).unwrap();
    assert_eq!(actions.len(), 1);
    clave::seal::run(&db, data.path(), &sk, NOW + 16 * DAY).unwrap();
    assert_eq!(
        clave::sanctions::sanction_level(&db, &host, &ts(NOW + 23 * DAY)).unwrap(),
        3
    );

    // The Publisher serves an appeal weeks after the window closed. It is
    // sealed as the fact it is, and changes nothing.
    let appeal_update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "appeal",
        "subject": host,
        "details": {"notice": notice_id, "grounds": "served long after the window"},
        "effective_at": ts(NOW + 40 * DAY),
    });
    let envelope =
        wist_core::envelope::sign_envelope(&appeal_update, "update", "k1", &p.sk).unwrap();
    db.insert_pending_entry("registry_update", "", &envelope, 0)
        .unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + 40 * DAY).unwrap();

    let gov = db.governance_for_domain(&host).unwrap();
    assert!(gov
        .iter()
        .any(|g| g.action == "appeal" && g.notice_id.as_deref() == Some(notice_id.as_str())));
    assert_eq!(
        clave::sanctions::sanction_level(&db, &host, &ts(NOW + 41 * DAY)).unwrap(),
        3,
        "a late appeal starts no ruling deadline, so the state stands"
    );
    assert_eq!(
        clave::sanctions::sanction_level(&db, &host, &ts(NOW + 80 * DAY)).unwrap(),
        3,
        "and no ruling deadline lapses later either"
    );
}
