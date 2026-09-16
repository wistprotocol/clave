mod common;

use common::{
    add_delta, admit_auditor, audit_record_entry, audit_record_id, auditor_draws,
    make_publisher_with_scope, reserve_addr, serve_static, write_feed, AUDITOR_A, AUDITOR_A_SEED,
    AUDITOR_B, AUDITOR_B_SEED,
};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86400;
const HOUR: i64 = 3600;
const PROVISIONAL_RATE: u64 = 2_900_000;

fn sealed_notice_id(db: &clave::db::Db, domain: &str) -> String {
    db.governance_for_domain(domain)
        .unwrap()
        .iter()
        .rev()
        .find(|e| e.action == "notice")
        .map(|e| e.update_id.clone())
        .expect("a sealed notice for the domain")
}

fn ts(epoch: i64) -> String {
    jiff::Timestamp::from_second(epoch).unwrap().to_string()
}

struct Scenario {
    p: common::TestPub,
    data: tempfile::TempDir,
    db: clave::db::Db,
    sk: wist_core::crypto::SigningKey,
    host: String,
    client: clave::fetch::Client,
    block0: clave::db::BlockRow,
    drawn: Vec<String>,
}

/// A Publisher with 192 sealed Deltas and two admitted independent Auditors,
/// sealed in Block 0 at NOW with a one-second cadence. `drawn` lists the
/// Deltas both Auditors' VRF draws select at the Provisional rate.
fn scenario() -> Scenario {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = (0..192)
        .map(|i| {
            add_delta(
                &p,
                &format!("https://example.com/p{i}"),
                &format!("body {i}"),
                None,
            )
        })
        .collect();
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, &ts(NOW)).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    admit_auditor(&db, &sk, AUDITOR_A, "a1", &AUDITOR_A_SEED);
    admit_auditor(&db, &sk, AUDITOR_B, "b1", &AUDITOR_B_SEED);
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    let block0 = db.last_block().unwrap().unwrap();
    let drawn: Vec<String> = ids
        .iter()
        .filter(|id| {
            auditor_draws(&AUDITOR_A_SEED, &block0, id, PROVISIONAL_RATE)
                && auditor_draws(&AUDITOR_B_SEED, &block0, id, PROVISIONAL_RATE)
        })
        .cloned()
        .collect();
    assert!(
        drawn.len() >= 3,
        "{} Deltas drawn by both Auditors",
        drawn.len()
    );
    Scenario {
        p,
        data,
        db,
        sk,
        host,
        client,
        block0,
        drawn,
    }
}

/// Seals a Confirmed Inconsistency for `delta`: the first Auditor's Record
/// in the Block sealed at `at`, the second's one hour later. Returns the
/// first and the confirming Record IDs.
fn confirm_finding(s: &Scenario, delta: &str, similarity: u64, at: i64) -> (String, String) {
    let first = audit_record_entry(
        &AUDITOR_A_SEED,
        AUDITOR_A,
        "a1",
        delta,
        &s.block0,
        "inconsistent",
        similarity,
        &ts(NOW + HOUR),
    );
    s.db.insert_pending_entry("audit_record", "", &first, 0)
        .unwrap();
    clave::seal::run(&s.db, s.data.path(), &s.sk, at).unwrap();
    let second = audit_record_entry(
        &AUDITOR_B_SEED,
        AUDITOR_B,
        "b1",
        delta,
        &s.block0,
        "inconsistent",
        similarity,
        &ts(NOW + HOUR),
    );
    s.db.insert_pending_entry("audit_record", "", &second, 0)
        .unwrap();
    clave::seal::run(&s.db, s.data.path(), &s.sk, at + HOUR).unwrap();
    (audit_record_id(&first), audit_record_id(&second))
}

/// A severity-3 finding confirmed at NOW + 2 hours and its level-3 notice
/// and sanction sealed at NOW + 3 hours. Returns the notice ID.
fn level3(s: &Scenario) -> String {
    let (first, confirming) = confirm_finding(s, &s.drawn[0], 10_000, NOW + HOUR);
    let report = clave::governance::sanction(
        &s.db,
        s.data.path(),
        &s.sk,
        &s.host,
        3,
        3,
        &confirming,
        &[first, confirming.clone()],
        Some("confirmed inconsistency"),
        NOW + 3 * HOUR,
    )
    .unwrap();
    assert!(report.notice_queued, "level 3 must seal a notice");
    let seal = clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 3 * HOUR).unwrap();
    assert_eq!(seal.entry_count, 2);
    assert!(seal.dropped.is_empty(), "{:?}", seal.dropped);
    sealed_notice_id(&s.db, &s.host)
}

#[test]
fn sanction_level3_seals_notice_then_sanction_and_derives_in_force_state() {
    let s = scenario();
    let (first, confirming) = confirm_finding(&s, &s.drawn[0], 10_000, NOW + HOUR);
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 2 * HOUR)).unwrap(),
        1,
        "before its notice seals, a derived level 3 is enforceable only to level 1"
    );
    let report = clave::governance::sanction(
        &s.db,
        s.data.path(),
        &s.sk,
        &s.host,
        3,
        3,
        &confirming,
        &[first.clone(), confirming.clone()],
        Some("confirmed inconsistency"),
        NOW + 3 * HOUR,
    )
    .unwrap();
    assert!(report.notice_queued);
    let seal = clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 3 * HOUR).unwrap();
    assert_eq!(seal.entry_count, 2);
    assert!(seal.dropped.is_empty());
    let notice_id = sealed_notice_id(&s.db, &s.host);
    let gov = s.db.governance_for_domain(&s.host).unwrap();
    let sanction = gov.iter().find(|g| g.action == "sanction").unwrap();
    assert_eq!(sanction.level, Some(3));
    assert_eq!(sanction.notice_id.as_deref(), Some(notice_id.as_str()));
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 3 * HOUR)).unwrap(),
        3
    );
    let state =
        clave::sanctions::sanction_state(&s.db, &s.host, &ts(NOW + 3 * HOUR + 100)).unwrap();
    assert_eq!(state.level, 3);
    assert_eq!(state.evidence, vec![confirming.clone()]);
    assert_eq!(
        state.effective_at,
        Some(ts(NOW + 2 * HOUR)),
        "the rung took effect at its confirming Block"
    );
    assert_eq!(
        state.deadlines.len(),
        2,
        "the appeal window and sealing deadline are open"
    );
    let raw = std::fs::read(
        s.data
            .path()
            .join(format!("log/blocks/{:09}.json.zst", seal.block_number)),
    )
    .unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::stream::decode_all(&raw[..]).unwrap()).unwrap();
    let notice = block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["body"]["update"]["action"] == "notice")
        .unwrap();
    assert_eq!(notice["body"]["update"]["details"]["level"], 3);
    assert_eq!(
        notice["body"]["update"]["details"]["activation"],
        confirming
    );
}

#[test]
fn level1_sanction_needs_no_notice() {
    let s = scenario();
    let (first, confirming) = confirm_finding(&s, &s.drawn[0], 100_000, NOW + HOUR);
    let report = clave::governance::sanction(
        &s.db,
        s.data.path(),
        &s.sk,
        &s.host,
        1,
        2,
        &confirming,
        &[first.clone(), confirming.clone()],
        None,
        NOW + 3 * HOUR,
    )
    .unwrap();
    assert!(!report.notice_queued);
    let seal = clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 3 * HOUR).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 3 * HOUR)).unwrap(),
        1
    );
}

#[test]
fn a_sanction_records_only_what_the_derived_ladder_shows() {
    let s = scenario();
    let (first, confirming) = confirm_finding(&s, &s.drawn[0], 100_000, NOW + HOUR);
    let evidence = vec![first.clone(), confirming.clone()];
    let attempt = |level: i64, severity: i64, finding: &str| {
        clave::governance::sanction(
            &s.db,
            s.data.path(),
            &s.sk,
            &s.host,
            level,
            severity,
            finding,
            &evidence,
            Some("reason"),
            NOW + 3 * HOUR,
        )
        .map(|_| ())
    };
    assert!(
        attempt(1, 2, &first).is_err(),
        "the first Record is not the confirming one"
    );
    assert!(
        attempt(1, 3, &confirming).is_err(),
        "severity is derived, not chosen"
    );
    assert!(
        attempt(3, 2, &confirming).is_err(),
        "one severity-2 finding reaches level 1 only"
    );
    assert!(attempt(1, 2, &confirming).is_ok());
}

#[test]
fn premature_unappealed_ruling_is_dropped_at_seal() {
    let s = scenario();
    let notice_id = level3(&s);
    clave::governance::rule(
        &s.db,
        &s.sk,
        &s.host,
        &notice_id,
        "unappealed",
        "window still open",
        NOW + 3 * HOUR + DAY,
    )
    .unwrap();
    let seal = clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 3 * HOUR + DAY).unwrap();
    assert_eq!(seal.entry_count, 0);
    assert_eq!(seal.dropped.len(), 1);
    assert!(seal.dropped[0].contains("unappealed"));

    let ok_epoch = NOW + 3 * HOUR + 15 * DAY;
    clave::governance::rule(
        &s.db,
        &s.sk,
        &s.host,
        &notice_id,
        "unappealed",
        "window closed with no appeal",
        ok_epoch,
    )
    .unwrap();
    let seal = clave::seal::run(&s.db, s.data.path(), &s.sk, ok_epoch).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 3 * HOUR + 22 * DAY)).unwrap(),
        3
    );
}

#[test]
fn payload_withdrawal_removes_payload_record_and_stale_snapshots() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "withdrawable body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
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
    let s = scenario();
    let mut findings = Vec::new();
    for delta in &s.drawn[..3] {
        let first = audit_record_entry(
            &AUDITOR_A_SEED,
            AUDITOR_A,
            "a1",
            delta,
            &s.block0,
            "inconsistent",
            100_000,
            &ts(NOW + HOUR),
        );
        s.db.insert_pending_entry("audit_record", "", &first, 0)
            .unwrap();
        findings.push(audit_record_id(&first));
    }
    clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + HOUR).unwrap();
    let mut confirming = Vec::new();
    for delta in &s.drawn[..3] {
        let second = audit_record_entry(
            &AUDITOR_B_SEED,
            AUDITOR_B,
            "b1",
            delta,
            &s.block0,
            "inconsistent",
            100_000,
            &ts(NOW + HOUR),
        );
        s.db.insert_pending_entry("audit_record", "", &second, 0)
            .unwrap();
        confirming.push(audit_record_id(&second));
    }
    clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 2 * HOUR).unwrap();
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 2 * HOUR)).unwrap(),
        2,
        "three findings inside 90 days reach level 2 without any sanction act"
    );
    clave::governance::sanction(
        &s.db,
        s.data.path(),
        &s.sk,
        &s.host,
        2,
        2,
        &confirming[0],
        &[findings[0].clone(), confirming[0].clone()],
        None,
        NOW + 3 * HOUR,
    )
    .unwrap();
    clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 3 * HOUR).unwrap();
    let weights = snapshot_weights(s.data.path(), &ts(NOW + 3 * HOUR)[..10]);
    assert!(!weights.is_empty());
    assert!(
        weights.iter().all(|(_, weight)| weight == "reduced"),
        "{weights:?}"
    );
}

#[test]
fn level4_excludes_domain_from_snapshots() {
    let s = scenario();
    let (l3_first, l3_confirming) = confirm_finding(&s, &s.drawn[0], 10_000, NOW + HOUR);
    let (first, further) = confirm_finding(&s, &s.drawn[1], 100_000, NOW + 3 * HOUR);
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 4 * HOUR)).unwrap(),
        1,
        "level 4 is derived but not yet enforceable: the notice is unsealed"
    );
    clave::governance::sanction(
        &s.db,
        s.data.path(),
        &s.sk,
        &s.host,
        4,
        2,
        &further,
        &[l3_first, l3_confirming, first.clone(), further.clone()],
        Some("a level-3 domain accrued a further finding"),
        NOW + 5 * HOUR,
    )
    .unwrap();
    clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 5 * HOUR).unwrap();
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 5 * HOUR)).unwrap(),
        4
    );
    assert!(snapshot_weights(s.data.path(), &ts(NOW + 5 * HOUR)[..10]).is_empty());
}

#[test]
fn level3_suspends_ingestion() {
    let s = scenario();
    level3(&s);
    let before =
        s.db.ingest_bytes(&s.host, &ts(NOW + 3 * HOUR)[..10])
            .unwrap();
    let report = clave::ingest::run(
        &s.db,
        &s.client,
        s.data.path(),
        &s.host,
        &ts(NOW + 3 * HOUR + 100),
    )
    .unwrap();
    assert!(report.accepted.is_empty());
    assert_eq!(
        s.db.ingest_bytes(&s.host, &ts(NOW + 3 * HOUR)[..10])
            .unwrap(),
        before,
        "a level-3 domain's feed must not be pulled at all"
    );
}

fn serve_appeal(s: &Scenario, notice_id: &str, at: i64) {
    let notice_hex = notice_id.strip_prefix("sha256:").unwrap();
    let appeal_update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "appeal",
        "subject": s.host,
        "details": {"notice": notice_id, "grounds": "the finding is wrong"},
        "effective_at": ts(at),
    });
    let envelope =
        wist_core::envelope::sign_envelope(&appeal_update, "update", "k1", &s.p.sk).unwrap();
    let appeals_dir = s.p.dir.path().join(".well-known/wist/appeals");
    std::fs::create_dir_all(&appeals_dir).unwrap();
    std::fs::write(
        appeals_dir.join(format!("{notice_hex}.json")),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
}

#[test]
fn appeal_poll_fetches_and_enqueues_a_served_appeal() {
    let s = scenario();
    let notice_id = level3(&s);
    serve_appeal(&s, &notice_id, NOW + 2 * DAY);
    let actions = clave::appeals::poll(&s.db, &s.client, &s.sk, NOW + 2 * DAY).unwrap();
    assert_eq!(actions.len(), 1);
    clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 2 * DAY).unwrap();
    let gov = s.db.governance_for_domain(&s.host).unwrap();
    assert!(gov
        .iter()
        .any(|g| g.action == "appeal" && g.notice_id.as_deref() == Some(notice_id.as_str())));
    let again = clave::appeals::poll(&s.db, &s.client, &s.sk, NOW + 3 * DAY).unwrap();
    assert!(
        again.is_empty(),
        "an already-sealed appeal must not re-enqueue"
    );
    let state = clave::sanctions::sanction_state(&s.db, &s.host, &ts(NOW + 2 * DAY)).unwrap();
    assert_eq!(state.level, 3);
    assert_eq!(
        state.deadlines.len(),
        1,
        "an accepted appeal leaves only the ruling deadline open"
    );
    assert!(matches!(
        state.deadlines[0].0,
        wist_core::objects::SanctionDeadlineLabel::Ruling
    ));
}

#[test]
fn appeal_poll_seals_unappealed_ruling_after_window_close() {
    let s = scenario();
    let notice_id = level3(&s);
    let during_window = clave::appeals::poll(&s.db, &s.client, &s.sk, NOW + 2 * DAY).unwrap();
    assert!(during_window.is_empty());
    let after_close = NOW + 3 * HOUR + 15 * DAY;
    let actions = clave::appeals::poll(&s.db, &s.client, &s.sk, after_close).unwrap();
    assert_eq!(actions.len(), 1);
    let seal = clave::seal::run(&s.db, s.data.path(), &s.sk, after_close).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());
    let gov = s.db.governance_for_domain(&s.host).unwrap();
    assert!(gov.iter().any(|g| {
        g.action == "appeal_ruling"
            && g.outcome.as_deref() == Some("unappealed")
            && g.notice_id.as_deref() == Some(notice_id.as_str())
    }));
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(after_close)).unwrap(),
        3
    );
}

#[test]
fn a_lapsed_sealing_deadline_voids_the_enforceable_state() {
    let s = scenario();
    level3(&s);
    let past_t = NOW + 3 * HOUR + 22 * DAY;
    clave::seal::run(&s.db, s.data.path(), &s.sk, past_t).unwrap();
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(past_t)).unwrap(),
        1,
        "nothing discharged T: the level-3 state is void from T"
    );
}

#[test]
fn late_appeal_is_recorded_but_discharges_nothing() {
    let s = scenario();
    let notice_id = level3(&s);
    let actions = clave::appeals::poll(&s.db, &s.client, &s.sk, NOW + 16 * DAY).unwrap();
    assert_eq!(actions.len(), 1);
    clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 16 * DAY).unwrap();
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 23 * DAY)).unwrap(),
        3
    );
    let appeal_update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "appeal",
        "subject": s.host,
        "details": {"notice": notice_id, "grounds": "served long after the window"},
        "effective_at": ts(NOW + 40 * DAY),
    });
    let envelope =
        wist_core::envelope::sign_envelope(&appeal_update, "update", "k1", &s.p.sk).unwrap();
    s.db.insert_pending_entry("registry_update", "", &envelope, 0)
        .unwrap();
    clave::seal::run(&s.db, s.data.path(), &s.sk, NOW + 40 * DAY).unwrap();
    let gov = s.db.governance_for_domain(&s.host).unwrap();
    assert!(gov
        .iter()
        .any(|g| g.action == "appeal" && g.notice_id.as_deref() == Some(notice_id.as_str())));
    assert_eq!(
        clave::sanctions::sanction_level(&s.db, &s.host, &ts(NOW + 41 * DAY)).unwrap(),
        3,
        "a late appeal starts no ruling deadline, so the state stands"
    );
}

#[test]
fn a_sanction_notice_restates_the_deadline_from_the_block_that_seals_it() {
    let s = scenario();
    let (first, confirming) = confirm_finding(&s, &s.drawn[0], 10_000, NOW + HOUR);
    let enqueued_at = NOW + 3 * HOUR;
    clave::governance::sanction(
        &s.db,
        s.data.path(),
        &s.sk,
        &s.host,
        3,
        3,
        &confirming,
        &[first.clone(), confirming.clone()],
        Some("confirmed inconsistency"),
        enqueued_at,
    )
    .unwrap();
    let seal = clave::seal::run(&s.db, s.data.path(), &s.sk, enqueued_at + HOUR).unwrap();
    let raw = std::fs::read(
        s.data
            .path()
            .join(format!("log/blocks/{:09}.json.zst", seal.block_number)),
    )
    .unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::stream::decode_all(&raw[..]).unwrap()).unwrap();
    let sealed_at = block["header"]["sealed_at"].as_str().unwrap();
    assert_ne!(sealed_at, ts(enqueued_at));
    let notice = block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["body"]["update"]["action"] == "notice")
        .expect("the Block seals the notice");
    let expected = ts(sealed_at.parse::<jiff::Timestamp>().unwrap().as_second() + 14 * DAY);
    assert_eq!(
        notice["body"]["update"]["details"]["appeal_deadline"],
        serde_json::Value::from(expected)
    );
    wist_core::envelope::verify_envelope(&notice["body"], "update", &s.sk.public()).unwrap();
}

#[test]
fn a_rotated_domains_appeal_verifies_under_the_notice_era_key_set() {
    let s = scenario();
    let notice_id = level3(&s);
    let after_t = NOW + 23 * DAY;
    let stored = common::current_declaration(&s.p);
    let rotated = serde_json::json!({
        "wist_version": "1.0.0", "domain": s.host,
        "subdomain_scope": ["example.com"],
        "keys": [common::key_entry("k2", &common::K2_SEED, &ts(after_t))],
        "seq": 1,
        "prev_declaration": common::declaration_hash(&stored),
    });
    common::write_declaration(&s.p, &rotated, "k1", &common::K1_SEED);
    clave::ingest::run(&s.db, &s.client, s.data.path(), &s.host, &ts(after_t)).unwrap();
    clave::seal::run(&s.db, s.data.path(), &s.sk, after_t).unwrap();
    assert_eq!(
        s.db.get_publisher(&s.host).unwrap().unwrap().key_id,
        "k2",
        "the rotation must be the Aggregator's present declaration"
    );
    serve_appeal(&s, &notice_id, after_t);
    let actions = clave::appeals::poll(&s.db, &s.client, &s.sk, after_t).unwrap();
    assert!(
        actions.iter().any(|a| a.starts_with("appeal enqueued")),
        "actions {actions:?}"
    );
}
