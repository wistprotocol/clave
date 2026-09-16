mod common;

use clave::history::declarations::DeclarationsReplay;
use common::*;

const T0: i64 = 1_786_276_800;
const DAY: i64 = 86400;

struct Rig {
    host: String,
    p: TestPub,
    data: tempfile::TempDir,
    db: clave::db::Db,
    client: clave::fetch::Client,
    sk: wist_core::crypto::SigningKey,
}

fn rig(p_for: fn(&str) -> TestPub) -> Rig {
    let (listener, host, client) = reserve_addr();
    let p = p_for(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    Rig {
        host,
        p,
        data,
        db,
        client,
        sk,
    }
}

fn ingest(r: &Rig, now: &str) -> clave::ingest::IngestReport {
    clave::ingest::run(&r.db, &r.client, r.data.path(), &r.host, now).unwrap()
}

fn rejection_codes(r: &Rig) -> Vec<String> {
    r.db.list_rejections(&r.host)
        .unwrap()
        .into_iter()
        .map(|x| x.code)
        .collect()
}

#[test]
fn rotation_extends_key_set_and_enforces_valid_from() {
    let r = rig(|h| make_publisher_with_scope(h, &["example.com"]));
    let d1 = add_delta(&r.p, "https://example.com/a", "alpha", None);
    write_feed(
        &r.p,
        &r.host,
        std::slice::from_ref(&d1),
        "2026-08-09T12:00:00Z",
    );
    let rep = ingest(&r, "2026-08-09T12:00:05Z");
    assert_eq!(rep.accepted, vec![d1]);

    let stored = current_declaration(&r.p);
    let rotated = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "subdomain_scope": ["example.com"],
        "keys": [
            key_entry("k1", &K1_SEED, "2026-08-09T00:00:00Z"),
            key_entry("k2", &K2_SEED, "2026-08-10T00:00:00Z"),
        ],
        "seq": 1,
        "prev_declaration": declaration_hash(&stored),
    });
    write_declaration(&r.p, &rotated, "k1", &K1_SEED);

    let d2 = add_delta_signed(
        &r.p,
        "https://example.com/b",
        "beta",
        None,
        "2026-08-10T09:00:00Z",
        "k2",
        &K2_SEED,
    );
    let d3 = add_delta_signed(
        &r.p,
        "https://example.com/c",
        "gamma",
        None,
        "2026-08-09T13:00:00Z",
        "k2",
        &K2_SEED,
    );
    let d4 = add_delta_signed(
        &r.p,
        "https://example.com/d",
        "delta",
        None,
        "2026-08-10T09:00:00Z",
        "kx",
        &X1_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        &[d2.clone(), d3.clone(), d4.clone()],
        "2026-08-10T09:00:00Z",
        "k1",
        &K1_SEED,
    );

    let rep = ingest(&r, "2026-08-10T09:00:05Z");
    assert_eq!(rep.accepted, vec![d2]);
    assert_eq!(
        rep.rejected,
        vec![(d3, "WIST1-E02".to_string()), (d4, "WIST1-E02".to_string())]
    );
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        2
    );
}

#[test]
fn fractional_key_bound_survives_ingest_reopen_and_sealing() {
    let r = rig(|h| make_publisher_with_scope(h, &["example.com"]));
    let mut declaration = current_declaration(&r.p)["publisher"].clone();
    declaration["keys"][0]["valid_from"] = "2026-08-09T12:00:00Z".into();
    write_declaration(&r.p, &declaration, "k1", &K1_SEED);
    let accepted = add_delta_signed(
        &r.p,
        "https://example.com/a",
        "alpha",
        None,
        "2026-08-09T12:00:00.5Z",
        "k1",
        &K1_SEED,
    );
    let rejected = add_delta_signed(
        &r.p,
        "https://example.com/b",
        "beta",
        None,
        "2026-08-09T11:59:59.999Z",
        "k1",
        &K1_SEED,
    );
    write_feed(
        &r.p,
        &r.host,
        &[accepted.clone(), rejected.clone()],
        "2026-08-09T12:00:00Z",
    );
    let report = ingest(&r, "2026-08-09T12:00:05Z");
    assert_eq!(report.accepted, vec![accepted.clone()]);
    assert_eq!(report.rejected, vec![(rejected, "WIST1-E02".into())]);
    drop(r.db);
    let db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    let now = "2026-08-09T13:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    clave::seal::run(&db, r.data.path(), &r.sk, now).unwrap();
    let record = db
        .get_record("https://example.com/a", &r.host)
        .unwrap()
        .unwrap();
    assert_eq!(record.delta_id, accepted);
    assert_eq!(record.observed_at, "2026-08-09T12:00:00.5Z");
    assert!(db
        .get_record("https://example.com/b", &r.host)
        .unwrap()
        .is_none());
}

#[test]
fn recovery_settlement_applies_the_followers_fractional_key_bound_after_reopen() {
    let r = rig(make_publisher_with_recovery);
    let opened_at = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    write_feed(&r.p, &r.host, &[], "2026-08-09T12:00:00Z");
    ingest(&r, "2026-08-09T12:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, opened_at).unwrap();
    let previous = current_declaration(&r.p);
    let mut recovery = previous["publisher"].clone();
    recovery["seq"] = 1.into();
    recovery["prev_declaration"] = declaration_hash(&previous).into();
    recovery["keys"] = serde_json::json!([key_entry("k2", &K2_SEED, "2026-08-09T12:00:00Z")]);
    write_declaration(&r.p, &recovery, "r1", &R1_SEED);
    let survivor = add_delta_signed(
        &r.p,
        "https://example.com/a",
        "alpha",
        None,
        "2026-08-09T13:00:00.5Z",
        "k2",
        &K2_SEED,
    );
    let rejected = add_delta_signed(
        &r.p,
        "https://example.com/b",
        "beta",
        None,
        "2026-08-09T12:59:59.9Z",
        "k2",
        &K2_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        &[survivor.clone(), rejected.clone()],
        "2026-08-09T13:00:00Z",
        "k2",
        &K2_SEED,
    );
    assert_eq!(
        ingest(&r, "2026-08-09T13:00:01Z").queued,
        vec![survivor.clone(), rejected.clone()]
    );
    clave::seal::run(&r.db, r.data.path(), &r.sk, opened_at + 3600).unwrap();
    let previous = current_declaration(&r.p);
    let mut follower = previous["publisher"].clone();
    follower["seq"] = 2.into();
    follower["prev_declaration"] = declaration_hash(&previous).into();
    follower["keys"][0]["valid_from"] = "2026-08-09T13:00:00Z".into();
    write_declaration(&r.p, &follower, "k2", &K2_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "k2", &K2_SEED);
    ingest(&r, "2026-08-09T14:00:01Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, opened_at + 7200).unwrap();
    assert!(r
        .db
        .get_record("https://example.com/a", &r.host)
        .unwrap()
        .is_none());
    drop(r.db);
    let db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    clave::seal::run(&db, r.data.path(), &r.sk, opened_at + 3600 + 7 * DAY).unwrap();
    assert!(db.get_recovery_window(&r.host).unwrap().is_none());
    assert_eq!(
        db.get_record("https://example.com/a", &r.host)
            .unwrap()
            .unwrap()
            .delta_id,
        survivor
    );
    assert!(db
        .get_record("https://example.com/b", &r.host)
        .unwrap()
        .is_none());
    assert!(db
        .list_rejections(&r.host)
        .unwrap()
        .iter()
        .any(|r| r.code == "WIST1-E13" && r.delta_id.as_ref() == Some(&rejected)));
}

#[test]
fn stale_declaration_is_e08_and_stored_set_stays() {
    let r = rig(|h| make_publisher_with_scope(h, &["example.com"]));
    let d1 = add_delta(&r.p, "https://example.com/a", "alpha", None);
    write_feed(
        &r.p,
        &r.host,
        std::slice::from_ref(&d1),
        "2026-08-09T12:00:00Z",
    );
    ingest(&r, "2026-08-09T12:00:05Z");

    let seq0 = current_declaration(&r.p);
    let rotated = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "subdomain_scope": ["example.com"],
        "keys": [
            key_entry("k1", &K1_SEED, "2026-08-09T00:00:00Z"),
            key_entry("k2", &K2_SEED, "2026-08-10T00:00:00Z"),
        ],
        "seq": 1,
        "prev_declaration": declaration_hash(&seq0),
    });
    write_declaration(&r.p, &rotated, "k1", &K1_SEED);
    ingest(&r, "2026-08-10T09:00:05Z");

    std::fs::write(
        r.p.dir.path().join(".well-known/wist/publisher.json"),
        serde_json::to_vec(&seq0).unwrap(),
    )
    .unwrap();
    let d2 = add_delta_signed(
        &r.p,
        "https://example.com/b",
        "beta",
        None,
        "2026-08-10T10:00:00Z",
        "k2",
        &K2_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        std::slice::from_ref(&d2),
        "2026-08-10T10:00:00Z",
        "k1",
        &K1_SEED,
    );
    let rep = ingest(&r, "2026-08-10T10:00:05Z");
    assert_eq!(rep.accepted, vec![d2]);
    assert!(rejection_codes(&r).contains(&"WIST1-E08".to_string()));
}

#[test]
fn recovery_flow_queues_settles_and_rejects_superseded_deltas() {
    let r = rig(make_publisher_with_recovery);
    let d1 = add_delta(&r.p, "https://example.com/a", "alpha", None);
    write_feed(
        &r.p,
        &r.host,
        std::slice::from_ref(&d1),
        "2026-08-09T12:00:00Z",
    );
    let rep = ingest(&r, "2026-08-09T12:00:05Z");
    assert_eq!(rep.accepted, vec![d1.clone()]);
    let b0 = clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();
    assert_eq!(b0.block_number, 0);

    let stored = current_declaration(&r.p);
    let recovery = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "subdomain_scope": ["example.com"],
        "keys": [key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")],
        "recovery_keys": [key_entry("r1", &R1_SEED, "2026-08-01T00:00:00Z")],
        "seq": 1,
        "prev_declaration": declaration_hash(&stored),
    });
    write_declaration(&r.p, &recovery, "r1", &R1_SEED);

    let d2 = add_delta_signed(
        &r.p,
        "https://example.com/b",
        "beta",
        None,
        "2026-08-09T14:00:00Z",
        "k1",
        &K1_SEED,
    );
    let d3 = add_delta_signed(
        &r.p,
        "https://example.com/c",
        "gamma",
        None,
        "2026-08-09T14:00:00Z",
        "k2",
        &K2_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        &[d2.clone(), d3.clone()],
        "2026-08-09T14:00:00Z",
        "k2",
        &K2_SEED,
    );
    let rep = ingest(&r, "2026-08-09T14:00:05Z");
    assert!(rep.accepted.is_empty());
    assert_eq!(rep.queued, vec![d2.clone(), d3.clone()]);
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_some());
    assert_eq!(r.db.count_pending_entries("publisher_delta").unwrap(), 0);

    let b1 = clave::seal::run(&r.db, r.data.path(), &r.sk, T0 + 7200).unwrap();
    assert_eq!(b1.block_number, 1);
    let w = r.db.get_recovery_window(&r.host).unwrap().unwrap();
    assert_eq!(w.opened_block, Some(1));
    let sealed_at = jiff::Timestamp::from_second(T0 + 7200).unwrap().to_string();
    let expected_end = jiff::Timestamp::from_second(T0 + 7200 + 7 * DAY)
        .unwrap()
        .to_string();
    assert_eq!(w.window_end.as_deref(), Some(expected_end.as_str()));
    let _ = sealed_at;
    assert_eq!(r.db.count_pending_entries("registry_update").unwrap(), 1);

    let sealed_at_b1 = jiff::Timestamp::from_second(T0 + 7200).unwrap().to_string();
    let state_raw = std::fs::read(
        r.data
            .path()
            .join(format!("snapshots/{}/state.json", &sealed_at_b1[..10])),
    )
    .unwrap();
    let state: serde_json::Value = serde_json::from_slice(&state_raw).unwrap();
    let window_entry = state["state"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e[0] == "recovery_window")
        .expect("snapshot state carries the open recovery window");
    assert_eq!(window_entry[1], serde_json::json!(r.host));
    assert_eq!(window_entry[2], serde_json::json!(1));
    assert_eq!(window_entry[3], serde_json::json!(expected_end));
    assert_eq!(window_entry[4]["publisher"]["seq"], serde_json::json!(1));
    assert_eq!(window_entry[5], serde_json::json!(1));
    let declaration_entry = state["state"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e[0] == "declaration" && e[1] == serde_json::json!(r.host))
        .expect("snapshot state carries the current Declaration");
    assert_eq!(
        declaration_entry[2]["publisher"]["seq"],
        serde_json::json!(1)
    );
    assert_eq!(declaration_entry[3], serde_json::json!(1));
    assert_eq!(declaration_entry[4], serde_json::json!(1));

    let d4 = add_delta_signed(
        &r.p,
        "https://example.com/e",
        "epsilon",
        None,
        "2026-08-10T09:00:00Z",
        "k2",
        &K2_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        &[d2.clone(), d3.clone(), d4.clone()],
        "2026-08-10T09:00:00Z",
        "k2",
        &K2_SEED,
    );
    let rep = ingest(&r, "2026-08-10T09:00:05Z");
    assert_eq!(rep.queued, vec![d4.clone()]);

    let b2 = clave::seal::run(&r.db, r.data.path(), &r.sk, T0 + 2 * 7200).unwrap();
    assert_eq!(b2.block_number, 2);
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_some());

    let b3 = clave::seal::run(&r.db, r.data.path(), &r.sk, T0 + 7200 + 7 * DAY + 3600).unwrap();
    assert_eq!(b3.block_number, 3);
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
    assert!(rejection_codes(&r).contains(&"WIST1-E13".to_string()));
    let e13: Vec<_> =
        r.db.list_rejections(&r.host)
            .unwrap()
            .into_iter()
            .filter(|x| x.code == "WIST1-E13")
            .collect();
    assert_eq!(e13.len(), 1);
    assert_eq!(e13[0].delta_id.as_deref(), Some(d2.as_str()));

    assert!(r
        .db
        .get_record("https://example.com/c", &r.host)
        .unwrap()
        .is_some());
    assert!(r
        .db
        .get_record("https://example.com/e", &r.host)
        .unwrap()
        .is_some());
    assert!(r
        .db
        .get_record("https://example.com/b", &r.host)
        .unwrap()
        .is_none());
}

#[test]
fn declaration_outside_the_recovery_chain_is_superseded_at_the_windows_end() {
    let r = rig(make_publisher_with_recovery);
    write_feed(&r.p, &r.host, &[], "2026-08-09T12:00:00Z");
    ingest(&r, "2026-08-09T12:00:05Z");

    let stored = current_declaration(&r.p);
    let recovery = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "subdomain_scope": ["example.com"],
        "keys": [key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")],
        "recovery_keys": [key_entry("r1", &R1_SEED, "2026-08-01T00:00:00Z")],
        "seq": 1,
        "prev_declaration": declaration_hash(&stored),
    });
    write_declaration(&r.p, &recovery, "r1", &R1_SEED);
    ingest(&r, "2026-08-09T14:00:05Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();

    let recovery_doc = current_declaration(&r.p);
    let thief = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "subdomain_scope": ["example.com"],
        "keys": [key_entry("kx", &X1_SEED, "2026-08-09T15:00:00Z")],
        "recovery_keys": [key_entry("r1", &R1_SEED, "2026-08-01T00:00:00Z")],
        "seq": 2,
        "prev_declaration": declaration_hash(&recovery_doc),
    });
    write_declaration(&r.p, &thief, "kx", &X1_SEED);
    ingest(&r, "2026-08-09T16:00:05Z");
    assert!(
        !rejection_codes(&r).contains(&"WIST1-E08".to_string()),
        "a Declaration sealed inside the window is accepted, not rejected"
    );
    let accepted = r.db.get_publisher_declaration(&r.host).unwrap().unwrap();
    let accepted: serde_json::Value = serde_json::from_slice(&accepted).unwrap();
    assert_eq!(accepted["publisher"]["seq"], 2);

    let d_thief = add_delta_signed(
        &r.p,
        "https://example.com/t",
        "tau",
        None,
        "2026-08-09T17:00:00Z",
        "kx",
        &X1_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        std::slice::from_ref(&d_thief),
        "2026-08-09T17:00:00Z",
        "kx",
        &X1_SEED,
    );
    ingest(&r, "2026-08-09T17:00:05Z");

    clave::seal::run(&r.db, r.data.path(), &r.sk, T0 + 7 * DAY + 7200).unwrap();
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());

    let settled = r.db.get_publisher_declaration(&r.host).unwrap().unwrap();
    let settled: serde_json::Value = serde_json::from_slice(&settled).unwrap();
    assert_eq!(
        settled["publisher"]["seq"], 1,
        "the window's end supersedes everything outside the recovery chain"
    );
    assert!(
        r.db.get_record("https://example.com/t", &r.host)
            .unwrap()
            .is_none(),
        "a Delta signed by the superseded key never seals"
    );
}

#[test]
fn recovery_notice_is_sealed_with_kind_recovery() {
    let r = rig(make_publisher_with_recovery);
    write_feed(&r.p, &r.host, &[], "2026-08-09T12:00:00Z");
    ingest(&r, "2026-08-09T12:00:05Z");

    let stored = current_declaration(&r.p);
    let recovery = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "subdomain_scope": ["example.com"],
        "keys": [key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")],
        "recovery_keys": [key_entry("r1", &R1_SEED, "2026-08-01T00:00:00Z")],
        "seq": 1,
        "prev_declaration": declaration_hash(&stored),
    });
    write_declaration(&r.p, &recovery, "r1", &R1_SEED);
    ingest(&r, "2026-08-09T14:00:05Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, T0 + 7200).unwrap();

    let raw = std::fs::read(r.data.path().join("log/blocks/000000001.json.zst")).unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
    let entries = block["entries"].as_array().unwrap();
    let notice = entries
        .iter()
        .find(|e| e["type"] == "registry_update" && e["body"]["update"]["action"] == "notice")
        .expect("recovery notice sealed");
    assert_eq!(notice["body"]["update"]["details"]["kind"], "recovery");
    assert_eq!(
        notice["body"]["update"]["subject"],
        serde_json::json!(r.host)
    );
}

#[test]
fn a_recovery_notice_is_never_polled_for_an_appeal() {
    let r = rig(make_publisher_with_recovery);
    write_feed(&r.p, &r.host, &[], "2026-08-09T12:00:00Z");
    ingest(&r, "2026-08-09T12:00:05Z");

    let stored = current_declaration(&r.p);
    let recovery = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "subdomain_scope": ["example.com"],
        "keys": [key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")],
        "recovery_keys": [key_entry("r1", &R1_SEED, "2026-08-01T00:00:00Z")],
        "seq": 1,
        "prev_declaration": declaration_hash(&stored),
    });
    write_declaration(&r.p, &recovery, "r1", &R1_SEED);
    ingest(&r, "2026-08-09T14:00:05Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, T0 + 7200).unwrap();

    let client = clave::fetch::Client::new(true);
    let actions = clave::appeals::poll(&r.db, &client, &r.sk, T0 + 100 * 86400).unwrap();
    assert!(actions.is_empty(), "actions {actions:?}");
}

#[test]
fn a_queued_delta_whose_key_the_sealing_blocks_key_set_retired_is_not_sealed() {
    let r = rig(make_publisher);
    let id = add_delta(&r.p, &format!("https://{}/a", r.host), "alpha body", None);
    write_feed(
        &r.p,
        &r.host,
        std::slice::from_ref(&id),
        "2026-08-09T12:00:00Z",
    );
    ingest(&r, "2026-08-09T12:00:05Z");

    let stored = current_declaration(&r.p);
    let rotated = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "keys": [key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")],
        "seq": 1,
        "prev_declaration": declaration_hash(&stored),
    });
    write_declaration(&r.p, &rotated, "k1", &K1_SEED);
    ingest(&r, "2026-08-09T14:00:05Z");

    clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();

    let raw = std::fs::read(r.data.path().join("log/blocks/000000000.json.zst")).unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
    let deltas: Vec<&str> = block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "publisher_delta")
        .map(|e| e["body"]["sig"]["key_id"].as_str().unwrap())
        .collect();
    assert!(deltas.is_empty(), "sealed deltas signed by {deltas:?}");
    assert!(
        rejection_codes(&r).contains(&"WIST1-E02".to_string()),
        "codes {:?}",
        rejection_codes(&r)
    );
}

#[test]
fn a_delta_pending_when_the_window_opens_is_queued_not_sealed() {
    let r = rig(make_publisher_with_recovery);
    let id = add_delta(&r.p, &format!("https://{}/a", r.host), "alpha body", None);
    write_feed(
        &r.p,
        &r.host,
        std::slice::from_ref(&id),
        "2026-08-09T12:00:00Z",
    );
    ingest(&r, "2026-08-09T12:00:05Z");

    let stored = current_declaration(&r.p);
    let recovery = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "keys": [key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")],
        "recovery_keys": [key_entry("r1", &R1_SEED, "2026-08-01T00:00:00Z")],
        "seq": 1,
        "prev_declaration": declaration_hash(&stored),
    });
    write_declaration(&r.p, &recovery, "r1", &R1_SEED);
    ingest(&r, "2026-08-09T14:00:05Z");

    clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();

    let raw = std::fs::read(r.data.path().join("log/blocks/000000000.json.zst")).unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
    let deltas = block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "publisher_delta")
        .count();
    assert_eq!(deltas, 0, "the Block that opens the window sealed a Delta");
    assert!(
        !rejection_codes(&r).contains(&"WIST1-E02".to_string()),
        "the Delta belongs in the window queue, not rejected at sealing: {:?}",
        rejection_codes(&r)
    );

    // The window settles against the recovery chain head, which is where
    // a Delta under the superseded key is rejected in the open.
    clave::seal::run(&r.db, r.data.path(), &r.sk, T0 + 8 * DAY).unwrap();
    assert!(
        rejection_codes(&r).contains(&"WIST1-E13".to_string()),
        "codes {:?}",
        rejection_codes(&r)
    );
}

#[test]
fn a_sealed_page_signed_by_a_since_retired_key_still_verifies() {
    let r = rig(make_publisher);
    write_feed(&r.p, &r.host, &[], "2026-08-09T11:00:00Z");
    ingest(&r, "2026-08-09T11:00:05Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();

    let stored = current_declaration(&r.p);
    let rotated = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "keys": [key_entry("k2", &K2_SEED, "2026-08-09T14:00:00Z")],
        "seq": 1,
        "prev_declaration": declaration_hash(&stored),
    });
    write_declaration(&r.p, &rotated, "k1", &K1_SEED);

    let paged = add_delta_signed(
        &r.p,
        &format!("https://{}/a", r.host),
        "alpha body",
        None,
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    let live = add_delta_signed(
        &r.p,
        &format!("https://{}/b", r.host),
        "beta body",
        None,
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    // The Page was cut before the rotation and is never re-signed, so it
    // still carries k1's signature.
    write_feed_page_signed(
        &r.p,
        &r.host,
        1,
        std::slice::from_ref(&paged),
        "2026-08-09T13:00:00Z",
        None,
        "k1",
        &K1_SEED,
    );
    let feed = serde_json::json!({
        "wist_version": "1.0.0", "domain": r.host,
        "generated_at": "2026-08-09T15:00:00Z",
        "deltas": [live],
        "next": page_url(&r.host, 1),
    });
    let sk2 = wist_core::crypto::SigningKey::from_seed(&K2_SEED);
    let env = wist_core::envelope::sign_envelope(&feed, "feed", "k2", &sk2).unwrap();
    std::fs::write(
        r.p.dir.path().join(".well-known/wist/feed.json"),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();

    let report = ingest(&r, "2026-08-09T15:00:05Z");
    assert!(
        report.accepted.contains(&paged),
        "accepted {:?}, codes {:?}",
        report.accepted,
        rejection_codes(&r)
    );
}

fn reopen_without_owner_column(r: &mut Rig) {
    let path = r.data.path().join("clave.sqlite");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "ALTER TABLE recovery_windows DROP COLUMN owner_declaration_json",
            [],
        )
        .unwrap();
    drop(connection);
    r.db = clave::db::Db::open(&path).unwrap();
}

#[test]
fn fixed_recovery_bindings_survive_followers_reopen_migration_and_settlement() {
    for migration in ["none", "pending", "sealed"] {
        let mut r = rig(make_publisher_with_recovery);
        let start = "2026-08-09T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second();
        write_feed(&r.p, &r.host, &[], "2026-08-09T12:00:00Z");
        ingest(&r, "2026-08-09T12:00:00Z");
        clave::seal::run(&r.db, r.data.path(), &r.sk, start).unwrap();
        let before = current_declaration(&r.p);
        let mut owner = before["publisher"].clone();
        owner["seq"] = 1.into();
        owner["prev_declaration"] = declaration_hash(&before).into();
        owner["keys"] = serde_json::json!([key_entry("k1", &K2_SEED, "2026-08-09T13:00:00Z")]);
        write_declaration(&r.p, &owner, "r1", &R1_SEED);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-09T13:00:00Z", "k1", &K2_SEED);
        ingest(&r, "2026-08-09T13:00:00Z");
        let owner = current_declaration(&r.p);
        if migration != "pending" {
            clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600).unwrap();
        }
        let mut follower = owner["publisher"].clone();
        follower["seq"] = 2.into();
        follower["prev_declaration"] = declaration_hash(&owner).into();
        follower["keys"] = serde_json::json!([
            key_entry("k1", &K2_SEED, "2026-08-09T15:00:00Z"),
            key_entry("k3", &X1_SEED, "2026-08-09T13:00:00Z")
        ]);
        write_declaration(&r.p, &follower, "k1", &K2_SEED);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "k3", &X1_SEED);
        let report = ingest(&r, "2026-08-09T14:00:00Z");
        assert_ne!(
            report.noise,
            Some("WIST2-E04"),
            "{migration}: {:?}",
            r.db.list_rejections(&r.host).unwrap()
        );
        let follower = current_declaration(&r.p);
        if migration != "pending" {
            clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
        }
        if migration == "none" {
            r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
        } else {
            reopen_without_owner_column(&mut r);
        }
        let window = r.db.get_recovery_window(&r.host).unwrap().unwrap();
        for (raw, expected) in [
            (&window.prior_declaration_json, &before),
            (&window.owner_declaration_json, &owner),
            (&window.declaration_json, &follower),
        ] {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(raw).unwrap(),
                *expected,
                "{migration}"
            );
        }
        let cases = [
            ("prior", "k1", &K1_SEED, "2026-08-09T14:00:00Z", None),
            ("owner", "k1", &K2_SEED, "2026-08-09T14:00:00Z", None),
            (
                "follower",
                "k3",
                &X1_SEED,
                "2026-08-09T14:00:00Z",
                Some("WIST1-E02"),
            ),
            (
                "wrong",
                "k1",
                &X1_SEED,
                "2026-08-09T14:00:00Z",
                Some("WIST1-E01"),
            ),
            ("survivor", "k1", &K2_SEED, "2026-08-09T15:00:00Z", None),
        ];
        let ids: Vec<_> = cases
            .iter()
            .map(|(name, key, seed, at, _)| {
                add_delta_signed(
                    &r.p,
                    &format!("https://example.com/{name}"),
                    name,
                    None,
                    at,
                    key,
                    seed,
                )
            })
            .collect();
        write_feed_signed(&r.p, &r.host, &ids, "2026-08-09T15:00:00Z", "k3", &X1_SEED);
        let report = ingest(&r, "2026-08-09T15:00:05Z");
        assert_eq!(
            report.queued,
            vec![ids[0].clone(), ids[1].clone(), ids[4].clone()],
            "{migration}"
        );
        assert_eq!(
            report.rejected,
            vec![
                (ids[2].clone(), "WIST1-E02".into()),
                (ids[3].clone(), "WIST1-E01".into())
            ],
            "{migration}"
        );
        write_feed_signed(&r.p, &r.host, &ids, "2026-08-09T15:00:00Z", "k1", &K1_SEED);
        assert_eq!(ingest(&r, "2026-08-09T15:00:06Z").noise, Some("WIST2-E04"));
        if migration == "pending" {
            clave::seal::run(&r.db, r.data.path(), &r.sk, start + 10800).unwrap();
        }
        r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + 8 * DAY).unwrap();
        assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
        for id in &ids[..2] {
            assert!(
                r.db.list_rejections(&r.host)
                    .unwrap()
                    .iter()
                    .any(|rejection| {
                        rejection.code == "WIST1-E13" && rejection.delta_id.as_ref() == Some(id)
                    }),
                "{migration}: {id}"
            );
        }
        assert_eq!(
            r.db.get_record("https://example.com/survivor", &r.host)
                .unwrap()
                .unwrap()
                .delta_id,
            ids[4],
            "{migration}"
        );
        let raw = std::fs::read(r.data.path().join(format!(
            "log/blocks/{:09}.json.zst",
            r.db.last_block().unwrap().unwrap().block_number
        )))
        .unwrap();
        let block: serde_json::Value =
            serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
        let deltas: Vec<_> = block["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["type"] == "publisher_delta")
            .collect();
        assert_eq!(deltas.len(), 1, "{migration}");
        assert_eq!(
            deltas[0]["body"]["delta"]["url"],
            "https://example.com/survivor"
        );
    }
}

#[test]
fn pending_owner_migration_rejects_missing_ambiguous_and_invalid_sources_atomically() {
    for mutation in ["missing", "ambiguous", "invalid", "duplicate"] {
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("clave.sqlite");
        let db = clave::db::Db::open(&path).unwrap();
        for domain in ["a.example.com", "b.example.com"] {
            let p = make_publisher_with_recovery(domain);
            let prior = current_declaration(&p);
            let mut owner = prior["publisher"].clone();
            owner["seq"] = 1.into();
            owner["prev_declaration"] = declaration_hash(&prior).into();
            owner["keys"] = serde_json::json!([key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")]);
            write_declaration(&p, &owner, "r1", &R1_SEED);
            let owner = current_declaration(&p);
            db.open_recovery_window(
                domain,
                &serde_json::to_vec(&owner).unwrap(),
                &serde_json::to_vec(&prior).unwrap(),
            )
            .unwrap();
            if domain == "a.example.com" || mutation != "missing" {
                let mut candidate = owner.clone();
                if domain == "b.example.com" && mutation == "invalid" {
                    candidate["publisher"]["contact"] = "altered@example.com".into();
                }
                db.insert_pending_entry("publisher_declaration", domain, &candidate, 0)
                    .unwrap();
            }
            if domain == "b.example.com" && matches!(mutation, "ambiguous" | "duplicate") {
                let mut competitor = owner["publisher"].clone();
                if mutation == "ambiguous" {
                    competitor["seq"] = 2.into();
                }
                write_declaration(&p, &competitor, "r1", &R1_SEED);
                db.insert_pending_entry(
                    "publisher_declaration",
                    domain,
                    &current_declaration(&p),
                    0,
                )
                .unwrap();
            }
        }
        drop(db);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "ALTER TABLE recovery_windows DROP COLUMN owner_declaration_json",
                [],
            )
            .unwrap();
        drop(connection);
        let restored = clave::db::Db::open(&path);
        assert_eq!(restored.is_ok(), mutation == "duplicate", "{mutation}");
        drop(restored);
        let connection = rusqlite::Connection::open(&path).unwrap();
        let missing: u64 = connection
            .query_row(
                "SELECT count(*) FROM recovery_windows WHERE owner_declaration_json IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            missing,
            if mutation == "duplicate" { 0 } else { 2 },
            "{mutation}"
        );
    }
}

#[test]
fn recovery_scope_sources_survive_reopen_and_gate_settlement() {
    let mut r = rig(make_publisher_with_recovery);
    let start = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let mut prior = current_declaration(&r.p)["publisher"].clone();
    prior["subdomain_scope"] = serde_json::json!(["old.example", "shared.example"]);
    write_declaration(&r.p, &prior, "k1", &K1_SEED);
    write_feed(&r.p, &r.host, &[], "2026-08-09T12:00:00Z");
    ingest(&r, "2026-08-09T12:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start).unwrap();
    let prior = current_declaration(&r.p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry("k1", &K2_SEED, "2026-08-09T13:00:00Z")]);
    owner["subdomain_scope"] = serde_json::json!(["owner.example", "shared.example"]);
    write_declaration(&r.p, &owner, "r1", &R1_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T13:00:00Z", "k1", &K2_SEED);
    ingest(&r, "2026-08-09T13:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600).unwrap();
    let owner = current_declaration(&r.p);
    let mut follower = owner["publisher"].clone();
    follower["seq"] = 2.into();
    follower["prev_declaration"] = declaration_hash(&owner).into();
    follower["subdomain_scope"] = serde_json::json!(["shared.example", "follower.example"]);
    write_declaration(&r.p, &follower, "k1", &K2_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "k1", &K2_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    let window = r.db.get_recovery_window(&r.host).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&window.prior_declaration_json).unwrap(),
        prior
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&window.owner_declaration_json).unwrap(),
        owner
    );
    let cases = [
        ("https://old.example/old", &K1_SEED, true),
        ("https://owner.example/owner", &K2_SEED, true),
        ("https://owner.example/crossed", &K1_SEED, false),
        ("https://old.example/crossed", &K2_SEED, false),
        ("https://follower.example/new", &K2_SEED, false),
        ("https://shared.example/survivor", &K2_SEED, true),
    ];
    let ids: Vec<_> = cases
        .iter()
        .map(|(url, key, _)| {
            add_delta_signed(&r.p, url, "body", None, "2026-08-09T15:00:00Z", "k1", key)
        })
        .collect();
    write_feed_signed(&r.p, &r.host, &ids, "2026-08-09T15:00:00Z", "k1", &K2_SEED);
    let report = ingest(&r, "2026-08-09T15:00:00Z");
    assert_eq!(
        report.queued,
        vec![ids[0].clone(), ids[1].clone(), ids[5].clone()]
    );
    assert_eq!(
        report.rejected,
        ids[2..5]
            .iter()
            .map(|id| (id.clone(), "WIST1-E03".into()))
            .collect::<Vec<_>>()
    );
    for (id, (url, _, accepted)) in ids.iter().zip(cases) {
        assert_eq!(r.db.is_delta_seen_for(id, &r.host).unwrap(), accepted);
        assert_eq!(
            r.db.url_tip(&r.host, url).unwrap().as_ref(),
            accepted.then_some(id)
        );
    }
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
    let rejected = r.db.list_rejections(&r.host).unwrap();
    for id in &ids[..2] {
        assert!(rejected
            .iter()
            .any(|rejection| rejection.code == "WIST1-E13"
                && rejection.delta_id.as_ref() == Some(id)));
    }
    assert_eq!(
        r.db.get_record("https://shared.example/survivor", &r.host)
            .unwrap()
            .unwrap()
            .delta_id,
        ids[5]
    );
    let head = r.db.last_block().unwrap().unwrap();
    let raw = std::fs::read(
        r.data
            .path()
            .join(format!("log/blocks/{:09}.json.zst", head.block_number)),
    )
    .unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
    let sealed: Vec<_> = block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["type"] == "publisher_delta")
        .map(|entry| wist_core::delta::delta_id(&entry["body"]["delta"]).unwrap())
        .collect();
    assert_eq!(sealed, vec![ids[5].clone()]);
}

#[test]
fn sealing_rechecks_scope_when_the_signing_key_is_retained() {
    let mut r = rig(|host| make_publisher_with_scope(host, &["example.com"]));
    let scoped = add_delta(&r.p, "https://example.com/scoped", "scoped", None);
    let local = add_delta(&r.p, &format!("https://{}/local", r.host), "local", None);
    write_feed(
        &r.p,
        &r.host,
        &[scoped.clone(), local.clone()],
        "2026-08-09T12:00:00Z",
    );
    assert_eq!(
        ingest(&r, "2026-08-09T12:00:00Z").accepted,
        vec![scoped.clone(), local.clone()]
    );
    let prior = current_declaration(&r.p);
    let mut replacement = prior["publisher"].clone();
    replacement["seq"] = 1.into();
    replacement["prev_declaration"] = declaration_hash(&prior).into();
    replacement
        .as_object_mut()
        .unwrap()
        .remove("subdomain_scope");
    write_declaration(&r.p, &replacement, "k1", &K1_SEED);
    write_feed(&r.p, &r.host, &[], "2026-08-09T13:00:00Z");
    ingest(&r, "2026-08-09T13:00:00Z");
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    let at = "2026-08-09T13:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let report = clave::seal::run(&r.db, r.data.path(), &r.sk, at).unwrap();
    assert!(report
        .dropped
        .iter()
        .any(|drop| drop.contains(&scoped) && drop.contains("WIST1-E03")));
    assert!(r
        .db
        .get_record("https://example.com/scoped", &r.host)
        .unwrap()
        .is_none());
    assert_eq!(
        r.db.get_record(&format!("https://{}/local", r.host), &r.host)
            .unwrap()
            .unwrap()
            .delta_id,
        local
    );
}

#[test]
fn signed_urls_reject_normalization_changes_before_admission() {
    let r = rig(|host| make_publisher_with_scope(host, &["example.com", "xn--bcher-kva.example"]));
    let rejected = [
        "https://EXAMPLE.com/a",
        "https://example.com:443/a",
        "https://example.com/a#fragment",
        "https://example.com/a/../b",
        "https://example.com/%zz",
        "https://bücher.example/a",
        "http://example.com/a",
    ];
    let accepted = [
        "https://example.com:8443/a",
        "https://xn--bcher-kva.example/a",
    ];
    let ids: Vec<_> = rejected
        .iter()
        .chain(&accepted)
        .map(|url| add_delta(&r.p, url, "body", None))
        .collect();
    write_feed(&r.p, &r.host, &ids, "2026-08-09T12:00:00Z");
    let report = ingest(&r, "2026-08-09T12:00:00Z");
    assert_eq!(
        report.rejected,
        ids[..rejected.len()]
            .iter()
            .map(|id| (id.clone(), "WIST1-E03".into()))
            .collect::<Vec<_>>()
    );
    assert_eq!(report.accepted, ids[rejected.len()..]);
    for (id, url) in ids.iter().zip(rejected) {
        assert!(!r.db.is_delta_seen_for(id, &r.host).unwrap());
        assert!(r.db.url_tip(&r.host, url).unwrap().is_none());
    }
}

fn sealed_recovery() -> (Rig, i64, serde_json::Value) {
    let r = rig(make_publisher_with_recovery);
    let start = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    write_feed(&r.p, &r.host, &[], "2026-08-09T12:00:00Z");
    ingest(&r, "2026-08-09T12:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start).unwrap();
    let prior = current_declaration(&r.p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &owner, "r1", &R1_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T13:00:00Z", "k2", &K2_SEED);
    ingest(&r, "2026-08-09T13:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600).unwrap();
    (r, start, owner)
}

fn stored_block(r: &Rig, height: u64) -> serde_json::Value {
    let bytes = std::fs::read(
        r.data
            .path()
            .join(format!("log/blocks/{height:09}.json.zst")),
    )
    .unwrap();
    serde_json::from_slice(&zstd::decode_all(bytes.as_slice()).unwrap()).unwrap()
}

#[test]
fn authenticated_sealing_separates_settlement_from_packed_authority() {
    for case in [
        "competitor",
        "deferred_follower",
        "deadline_key",
        "deadline_scope",
    ] {
        let (mut r, start, owner) = sealed_recovery();
        let survivor = add_delta_signed(
            &r.p,
            "https://example.com/survivor",
            "survivor",
            None,
            "2026-08-09T15:00:00Z",
            "k2",
            &K2_SEED,
        );
        let rejected = add_delta_signed(
            &r.p,
            "https://example.com/rejected",
            "rejected",
            None,
            "2026-08-09T15:00:00Z",
            "k1",
            &K1_SEED,
        );
        write_feed_signed(
            &r.p,
            &r.host,
            &[survivor.clone(), rejected.clone()],
            "2026-08-09T15:00:00Z",
            "k2",
            &K2_SEED,
        );
        assert_eq!(
            ingest(&r, "2026-08-09T15:00:00Z").queued,
            [survivor.clone(), rejected.clone()]
        );
        let mut replacement = owner.clone();
        replacement["seq"] = 2.into();
        replacement["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
        let (signer, seed) = if case == "competitor" {
            ("x1", &X1_SEED)
        } else {
            ("k2", &K2_SEED)
        };
        if case == "competitor" {
            replacement["keys"] =
                serde_json::json!([key_entry("x1", &X1_SEED, "2026-08-09T13:00:00Z")]);
        } else if case == "deadline_scope" {
            replacement["subdomain_scope"] = serde_json::json!([]);
        } else {
            replacement["keys"][0]["valid_from"] = "2026-08-10T00:00:00Z".into();
        }
        if case == "deferred_follower" {
            replacement["subdomain_scope"] =
                serde_json::json!(std::iter::once("example.com".to_string())
                    .chain((0..70).map(|i| format!("explicit-host-{i}.example.com")))
                    .collect::<Vec<_>>());
        }
        write_declaration(&r.p, &replacement, signer, seed);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-09T16:00:00Z", signer, seed);
        ingest(&r, "2026-08-09T16:00:00Z");
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            1,
            "{case}"
        );
        if case == "competitor" {
            clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
        }
        if case == "deferred_follower" {
            r.db.set_param("block_decompressed_cap_bytes", 1800)
                .unwrap();
        }
        r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
        let report = clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
        let block = stored_block(&r, report.block_number);
        wist_core::block::verify_block(&block, &r.sk.public()).unwrap();
        let state = clave::history::declarations::Declarations::reconstruct(
            r.data.path(),
            r.db.last_block().unwrap(),
        )
        .unwrap();
        let current = &state.domains()[&r.host];
        assert!(current.window().is_none(), "{case}");
        let should_seal = matches!(case, "competitor" | "deferred_follower");
        assert_eq!(
            r.db.get_record("https://example.com/survivor", &r.host)
                .unwrap()
                .is_some(),
            should_seal,
            "{case}"
        );
        assert_eq!(
            current.current().envelope()["publisher"]["seq"],
            if should_seal { 1 } else { 2 }
        );
        assert_eq!(
            current.highest_accepted_seq(),
            if case == "deferred_follower" { 1 } else { 2 }
        );
        assert!(
            r.db.list_rejections(&r.host)
                .unwrap()
                .iter()
                .any(|r| r.delta_id.as_ref() == Some(&rejected) && r.code == "WIST1-E13"),
            "{case}"
        );
        let codes: Vec<_> =
            r.db.list_rejections(&r.host)
                .unwrap()
                .into_iter()
                .filter(|r| r.delta_id.as_ref() == Some(&survivor))
                .map(|r| r.code)
                .collect();
        assert_eq!(
            codes,
            match case {
                "deadline_key" => vec!["WIST1-E02"],
                "deadline_scope" => vec!["WIST1-E03"],
                _ => vec![],
            },
            "{case}"
        );
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            i64::from(case == "deferred_follower"),
            "{case}"
        );
    }
}

#[test]
fn rejected_candidate_rolls_back_due_settlement_and_status() {
    let (mut r, start, owner) = sealed_recovery();
    let delta = add_delta_signed(
        &r.p,
        "https://example.com/rejected",
        "body",
        None,
        "2026-08-09T15:00:00Z",
        "k1",
        &K1_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        std::slice::from_ref(&delta),
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    assert_eq!(
        ingest(&r, "2026-08-09T15:00:00Z").queued,
        std::slice::from_ref(&delta)
    );
    let mut candidate = owner;
    candidate["seq"] = 2.into();
    candidate["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
    let invalid = wist_core::envelope::sign_envelope(
        &candidate,
        "publisher",
        "k2",
        &wist_core::crypto::SigningKey::from_seed(&X1_SEED),
    )
    .unwrap();
    r.db.insert_pending_entry("publisher_declaration", &r.host, &invalid, 0)
        .unwrap();
    let before =
        r.db.get_recovery_window(&r.host)
            .unwrap()
            .unwrap()
            .declaration_json;
    let pending = r.db.count_pending_entries("publisher_declaration").unwrap();
    let checkpoint = std::fs::read(r.data.path().join("log/checkpoint.json")).unwrap();
    assert!(clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).is_err());
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    assert_eq!(r.db.last_block().unwrap().unwrap().block_number, 1);
    assert_eq!(
        r.db.get_recovery_window(&r.host)
            .unwrap()
            .unwrap()
            .declaration_json,
        before
    );
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        pending
    );
    assert!(r.db.list_rejections(&r.host).unwrap().is_empty());
    assert!(r.db.is_delta_seen_for(&delta, &r.host).unwrap());
    assert_eq!(
        r.db.drain_queued_deltas(&r.host).unwrap()[0].delta_id,
        delta
    );
    assert_eq!(
        std::fs::read(r.data.path().join("log/checkpoint.json")).unwrap(),
        checkpoint
    );
    assert!(!r.data.path().join("log/blocks/000000002.json.zst").exists());
}

#[test]
fn corrupt_pinned_history_cannot_settle_a_queue() {
    let (mut r, start, _) = sealed_recovery();
    let delta = add_delta_signed(
        &r.p,
        "https://example.com/survivor",
        "body",
        None,
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        std::slice::from_ref(&delta),
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    assert_eq!(
        ingest(&r, "2026-08-09T15:00:00Z").queued,
        std::slice::from_ref(&delta)
    );
    let block = r.data.path().join("log/blocks/000000000.json.zst");
    let original = std::fs::read(&block).unwrap();
    std::fs::write(&block, b"invalid frame").unwrap();
    assert!(clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).is_err());
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_some());
    assert!(r.db.list_rejections(&r.host).unwrap().is_empty());
    assert_eq!(r.db.last_block().unwrap().unwrap().block_number, 1);
    std::fs::write(&block, original).unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
    assert_eq!(
        r.db.get_record("https://example.com/survivor", &r.host)
            .unwrap()
            .unwrap()
            .delta_id,
        delta
    );
}

#[test]
fn sealed_recovery_sources_ignore_corrupt_summaries_and_local_window_lengths() {
    let (mut r, start, _) = sealed_recovery();
    let delta = add_delta_signed(
        &r.p,
        "https://example.com/survivor",
        "body",
        None,
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        std::slice::from_ref(&delta),
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    assert_eq!(
        ingest(&r, "2026-08-09T15:00:00Z").queued,
        std::slice::from_ref(&delta)
    );
    r.db.set_param("recovery_window_days", 1).unwrap();
    let path = r.data.path().join("clave.sqlite");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute("UPDATE recovery_windows SET window_end = '2026-08-10T13:00:00Z', declaration_json = x'7b7d'", []).unwrap();
    connection
        .execute(
            "UPDATE sealed_declarations SET declaration_json = x'7b7d'",
            [],
        )
        .unwrap();
    drop(connection);
    r.db = clave::db::Db::open(&path).unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 2 * DAY).unwrap();
    assert!(r
        .db
        .get_record("https://example.com/survivor", &r.host)
        .unwrap()
        .is_none());
    assert_eq!(
        r.db.get_recovery_window(&r.host)
            .unwrap()
            .unwrap()
            .window_end
            .as_deref(),
        Some("2026-08-16T13:00:00Z")
    );
    assert!(r.db.list_rejections(&r.host).unwrap().is_empty());
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
    assert_eq!(
        r.db.get_record("https://example.com/survivor", &r.host)
            .unwrap()
            .unwrap()
            .delta_id,
        delta
    );
}

#[test]
fn recovery_preserves_cross_queue_order_and_defers_every_capped_copy() {
    for retain_old_key in [true, false] {
        let mut r = rig(make_publisher_with_recovery);
        let start = "2026-08-09T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second();
        write_feed(&r.p, &r.host, &[], "2026-08-09T12:00:00Z");
        ingest(&r, "2026-08-09T12:00:00Z");
        clave::seal::run(&r.db, r.data.path(), &r.sk, start).unwrap();
        let mut older = vec![
            add_delta(&r.p, "https://example.com/older-a", "a", None),
            add_delta(&r.p, "https://example.com/older-b", "b", None),
        ];
        older.sort_by_cached_key(|id| {
            let body: serde_json::Value = serde_json::from_slice(
                &std::fs::read(r.p.dir.path().join(format!(
                    ".well-known/wist/deltas/{}.json",
                    id.strip_prefix("sha256:").unwrap()
                )))
                .unwrap(),
            )
            .unwrap();
            std::cmp::Reverse(wist_core::merkle::leaf_hash(
                &wist_core::jcs::canonicalize(
                    &serde_json::json!({"type": "publisher_delta", "body": body}),
                )
                .unwrap(),
            ))
        });
        write_feed(&r.p, &r.host, &older, "2026-08-09T12:00:00Z");
        assert_eq!(ingest(&r, "2026-08-09T12:00:05Z").accepted, older);
        for entry in r.db.peek_pending_entries().unwrap().0 {
            r.db.set_turn_block(entry.rowid, 0).unwrap();
        }
        let prior = current_declaration(&r.p);
        let mut owner = prior["publisher"].clone();
        owner["seq"] = 1.into();
        owner["prev_declaration"] = declaration_hash(&prior).into();
        owner["keys"] = serde_json::json!([key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")]);
        if retain_old_key {
            owner["keys"]
                .as_array_mut()
                .unwrap()
                .push(prior["publisher"]["keys"][0].clone());
        }
        write_declaration(&r.p, &owner, "r1", &R1_SEED);
        let newer = add_delta_signed(
            &r.p,
            "https://example.com/newer",
            "newer",
            None,
            "2026-08-09T13:00:00Z",
            "k2",
            &K2_SEED,
        );
        write_feed_signed(
            &r.p,
            &r.host,
            std::slice::from_ref(&newer),
            "2026-08-09T13:00:00Z",
            "k2",
            &K2_SEED,
        );
        assert_eq!(
            ingest(&r, "2026-08-09T13:00:00Z").queued,
            vec![newer.clone()]
        );
        let mut opening = stored_block(&r, 0);
        opening["entries"][0]["body"] = current_declaration(&r.p);
        opening["header"]["prev_block_hash"] =
            r.db.last_block().unwrap().unwrap().block_hash.into();
        let cap = wist_core::jcs::canonicalize(&opening).unwrap().len() as i64;
        let normal_cap = r.db.param("block_decompressed_cap_bytes").unwrap();
        r.db.set_param("block_decompressed_cap_bytes", cap).unwrap();
        r.db.set_param("domain_block_entries_max", 1).unwrap();
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600).unwrap();
        r.db.set_param("block_decompressed_cap_bytes", normal_cap)
            .unwrap();
        assert_eq!(r.db.count_pending_entries("publisher_delta").unwrap(), 0);
        r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
        for hour in [2, 3, 4, 168] {
            assert!(
                clave::seal::run(&r.db, r.data.path(), &r.sk, start + hour * 3600)
                    .unwrap()
                    .late
                    .is_empty()
            );
        }
        let expected = if retain_old_key {
            vec![older[0].clone(), older[1].clone(), newer]
        } else {
            vec![newer]
        };
        for (index, id) in expected.iter().enumerate() {
            let height = 6 + index as u64;
            let report = clave::seal::run(
                &r.db,
                r.data.path(),
                &r.sk,
                start + (169 + index as i64) * 3600,
            )
            .unwrap();
            assert!(report.late.is_empty());
            let block = stored_block(&r, height);
            let ids: Vec<_> = block["entries"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|entry| entry["type"] == "publisher_delta")
                .map(|entry| wist_core::delta::delta_id(&entry["body"]["delta"]).unwrap())
                .collect();
            assert_eq!(ids, vec![id.clone()]);
            r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
        }
        if !retain_old_key {
            for id in older {
                assert!(!r.db.is_delta_seen_for(&id, &r.host).unwrap());
                assert!(r
                    .db
                    .list_rejections(&r.host)
                    .unwrap()
                    .iter()
                    .any(|rejection| rejection.delta_id.as_deref() == Some(&id)
                        && rejection.code == "WIST1-E13"));
            }
            assert!(r
                .db
                .url_tip(&r.host, "https://example.com/older-a")
                .unwrap()
                .is_none());
            assert!(r
                .db
                .url_tip(&r.host, "https://example.com/older-b")
                .unwrap()
                .is_none());
        }
    }
}

#[test]
fn settlement_rejects_dependent_copies_restores_tip_and_allows_reserving() {
    let mut r = rig(make_publisher_with_recovery);
    let start = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let url = "https://example.com/retry";
    let base = add_delta(&r.p, url, "base", None);
    write_feed(
        &r.p,
        &r.host,
        std::slice::from_ref(&base),
        "2026-08-09T12:00:00Z",
    );
    assert_eq!(
        ingest(&r, "2026-08-09T12:00:05Z").accepted,
        vec![base.clone()]
    );
    clave::seal::run(&r.db, r.data.path(), &r.sk, start).unwrap();
    let prior = current_declaration(&r.p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &owner, "r1", &R1_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T13:00:00Z", "k2", &K2_SEED);
    ingest(&r, "2026-08-09T13:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600).unwrap();
    let root = add_delta_signed(
        &r.p,
        url,
        "old authority",
        Some(&base),
        "2026-08-09T14:00:00Z",
        "k1",
        &K1_SEED,
    );
    let child = add_delta_signed(
        &r.p,
        url,
        "dependent",
        Some(&root),
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        &[root.clone(), child.clone()],
        "2026-08-09T15:00:00Z",
        "k2",
        &K2_SEED,
    );
    assert_eq!(
        ingest(&r, "2026-08-09T15:00:00Z").queued,
        vec![root.clone(), child.clone()]
    );
    for hour in [2, 169] {
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + hour * 3600).unwrap();
    }
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    assert_eq!(r.db.url_tip(&r.host, url).unwrap(), Some(base.clone()));
    assert!(r.db.is_delta_seen_for(&base, &r.host).unwrap());
    let rejected = r.db.list_rejections(&r.host).unwrap();
    for (id, code) in [(&root, "WIST1-E13"), (&child, "WIST1-E07")] {
        assert!(!r.db.is_delta_seen_for(id, &r.host).unwrap());
        assert!(rejected
            .iter()
            .any(|entry| entry.delta_id.as_deref() == Some(id) && entry.code == code));
    }
    assert_eq!(r.db.count_pending_entries("publisher_delta").unwrap(), 0);
    let predecessor = current_declaration(&r.p);
    let mut replacement = predecessor["publisher"].clone();
    replacement["seq"] = 2.into();
    replacement["prev_declaration"] = declaration_hash(&predecessor).into();
    replacement["keys"]
        .as_array_mut()
        .unwrap()
        .push(prior["publisher"]["keys"][0].clone());
    write_declaration(&r.p, &replacement, "k2", &K2_SEED);
    let report = ingest(&r, "2026-08-16T14:00:00Z");
    assert_eq!(report.accepted, vec![root.clone(), child.clone()]);
    assert!(report.rejected.is_empty());
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 170 * 3600).unwrap();
    assert_eq!(r.db.url_tip(&r.host, url).unwrap(), Some(child.clone()));
    assert_eq!(
        r.db.get_record(url, &r.host).unwrap().unwrap().delta_id,
        child
    );
    assert!(r.db.is_delta_seen_for(&root, &r.host).unwrap());
}

#[test]
fn pending_copy_in_an_expired_window_receives_settlement_rejection() {
    let (mut r, start, _) = sealed_recovery();
    let url = "https://example.com/deferred";
    let id = add_delta_signed(
        &r.p,
        url,
        "deferred",
        None,
        "2026-08-09T14:00:00Z",
        "k1",
        &K1_SEED,
    );
    let body: serde_json::Value = serde_json::from_slice(
        &std::fs::read(r.p.dir.path().join(format!(
            ".well-known/wist/deltas/{}.json",
            id.strip_prefix("sha256:").unwrap()
        )))
        .unwrap(),
    )
    .unwrap();
    r.db.record_accepted_delta(&r.host, &id, &body, 0, url, &id)
        .unwrap();
    for entry in r.db.peek_pending_entries().unwrap().0 {
        if entry.entry_type == "publisher_delta" {
            r.db.set_turn_block(entry.rowid, 0).unwrap();
        }
    }
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    let report = clave::seal::run(&r.db, r.data.path(), &r.sk, start + 169 * 3600).unwrap();
    assert!(report.late.is_empty());
    assert!(r.db.get_record(url, &r.host).unwrap().is_none());
    assert!(!r.db.is_delta_seen_for(&id, &r.host).unwrap());
    assert!(r.db.url_tip(&r.host, url).unwrap().is_none());
    let rejections = r.db.list_rejections(&r.host).unwrap();
    assert_eq!(rejections.len(), 1);
    assert_eq!(rejections[0].delta_id.as_deref(), Some(id.as_str()));
    assert_eq!(rejections[0].code, "WIST1-E13");
}

#[test]
fn admission_uses_both_heads_without_joining_a_competing_branch() {
    let (mut r, start, owner) = sealed_recovery();
    let owner_envelope = current_declaration(&r.p);
    let mut competitor = owner.clone();
    competitor["seq"] = 4.into();
    competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
    competitor["keys"] = serde_json::json!([
        key_entry("x1", &X1_SEED, "2026-08-09T13:00:00Z"),
        key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")
    ]);
    write_declaration(&r.p, &competitor, "x1", &X1_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "x1", &X1_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    let mut branch = competitor.clone();
    branch["seq"] = 6.into();
    branch["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
    write_declaration(&r.p, &branch, "k2", &K2_SEED);
    let branch_envelope = current_declaration(&r.p);
    ingest(&r, "2026-08-09T14:00:00Z");
    let recovery = r.db.get_recovery_window(&r.host).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&recovery.declaration_json).unwrap(),
        owner_envelope
    );
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(6)
    );
    r.db.update_recovery_chain_head(&r.host, &serde_json::to_vec(&branch_envelope).unwrap())
        .unwrap();
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();

    let mut follower = owner.clone();
    follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
    for seq in [5, 6] {
        follower["seq"] = seq.into();
        write_declaration(&r.p, &follower, "k2", &K2_SEED);
        ingest(&r, "2026-08-09T14:00:00Z");
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(6)
        );
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            2
        );
    }
    assert_eq!(
        rejection_codes(&r)
            .iter()
            .filter(|code| *code == "WIST1-E08")
            .count(),
        2
    );
    write_declaration(&r.p, &owner, "r1", &R1_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    assert_eq!(
        rejection_codes(&r)
            .iter()
            .filter(|code| *code == "WIST1-E08")
            .count(),
        3
    );
    let mut malformed = branch_envelope.clone();
    malformed["sig"]["value"] = "=".into();
    std::fs::write(
        r.p.dir.path().join(".well-known/wist/publisher.json"),
        serde_json::to_vec(&malformed).unwrap(),
    )
    .unwrap();
    ingest(&r, "2026-08-09T14:00:00Z");
    assert!(rejection_codes(&r).contains(&"WIST1-E14".into()));
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(6)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &r.db.get_publisher_declaration(&r.host).unwrap().unwrap()
        )
        .unwrap(),
        branch_envelope
    );
    follower["seq"] = 7.into();
    write_declaration(&r.p, &follower, "k2", &K2_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "k2", &K2_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(7)
    );
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        3
    );
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
    let history = clave::history::declarations::Declarations::reconstruct(
        r.data.path(),
        r.db.last_block().unwrap(),
    )
    .unwrap();
    assert_eq!(
        history.domains()[&r.host]
            .window()
            .unwrap()
            .head()
            .envelope(),
        &current_declaration(&r.p)
    );
}

#[test]
fn settled_admission_retains_the_floor_and_current_idempotence_after_migration() {
    for migrate in [false, true] {
        let (mut r, start, owner) = sealed_recovery();
        let owner_envelope = current_declaration(&r.p);
        let mut competitor = owner.clone();
        competitor["seq"] = 9.into();
        competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
        competitor["keys"] = serde_json::json!([key_entry("x1", &X1_SEED, "2026-08-09T13:00:00Z")]);
        write_declaration(&r.p, &competitor, "x1", &X1_SEED);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "x1", &X1_SEED);
        ingest(&r, "2026-08-09T14:00:00Z");
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
        let path = r.data.path().join("clave.sqlite");
        if migrate {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute("DROP TABLE declaration_floors", []).unwrap();
            conn.execute(
                "UPDATE sealed_declarations SET seq = seq + 100, declaration_json = x'7b7d'",
                [],
            )
            .unwrap();
        }
        r.db = clave::db::Db::open(&path).unwrap();
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(9)
        );
        write_declaration(&r.p, &owner, "r1", &R1_SEED);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-16T14:00:00Z", "k2", &K2_SEED);
        ingest(&r, "2026-08-16T14:00:00Z");
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            0
        );
        assert!(!rejection_codes(&r).contains(&"WIST1-E08".into()));
        let mut follower = owner.clone();
        follower["seq"] = 8.into();
        follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
        write_declaration(&r.p, &follower, "k2", &K2_SEED);
        ingest(&r, "2026-08-16T14:00:00Z");
        assert!(rejection_codes(&r).contains(&"WIST1-E08".into()));
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            0
        );
        follower["seq"] = 10.into();
        write_declaration(&r.p, &follower, "k2", &K2_SEED);
        ingest(&r, "2026-08-16T14:00:00Z");
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(10)
        );
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            1
        );
    }
}

#[test]
fn capped_recovery_siblings_preserve_sequences_and_progress_after_restart() {
    for oversized_lower in [false, true] {
        let (mut r, start, owner) = sealed_recovery();
        let owner_envelope = current_declaration(&r.p);
        let mut competitor = owner.clone();
        competitor["seq"] = 2.into();
        competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
        competitor["keys"] = serde_json::json!([key_entry("x1", &X1_SEED, "2026-08-09T13:00:00Z")]);
        write_declaration(&r.p, &competitor, "x1", &X1_SEED);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "x1", &X1_SEED);
        ingest(&r, "2026-08-09T14:00:00Z");
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();

        competitor["seq"] = 3.into();
        competitor["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
        competitor["subdomain_scope"] = serde_json::json!((0..70)
            .map(|i| format!("explicit-host-{i}.example.com"))
            .collect::<Vec<_>>());
        write_declaration(&r.p, &competitor, "x1", &X1_SEED);
        let lower = current_declaration(&r.p);
        ingest(&r, "2026-08-09T14:00:00Z");
        let mut follower = owner;
        follower["seq"] = 4.into();
        follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
        write_declaration(&r.p, &follower, "k2", &K2_SEED);
        let higher = current_declaration(&r.p);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-09T15:00:00Z", "k2", &K2_SEED);
        ingest(&r, "2026-08-09T15:00:00Z");
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(4)
        );
        let pending = r.db.peek_pending_entries().unwrap().0;
        assert_eq!(pending.len(), 2);
        let retained: Vec<_> = pending
            .iter()
            .map(|p| (p.rowid, p.entry_json.clone()))
            .collect();

        let mut candidate = stored_block(&r, 2);
        candidate["header"]["block_number"] = 3.into();
        candidate["header"]["entry_count"] = 1.into();
        let mut size_of = |declaration: &serde_json::Value| {
            candidate["entries"] = serde_json::json!([{
                "type": "publisher_declaration", "body": declaration
            }]);
            wist_core::jcs::canonicalize(&candidate).unwrap().len() as i64
        };
        let lower_cap = size_of(&lower);
        let higher_cap = size_of(&higher);
        assert!(lower_cap > higher_cap);
        r.db.set_param(
            "block_decompressed_cap_bytes",
            if oversized_lower {
                higher_cap
            } else {
                lower_cap
            },
        )
        .unwrap();
        let database = r.data.path().join("clave.sqlite");
        let first_height = if oversized_lower {
            let mut independent = lower["publisher"].clone();
            independent["domain"] = "zz-independent.example".into();
            independent["seq"] = 0.into();
            for field in ["prev_declaration", "subdomain_scope", "recovery_keys"] {
                independent.as_object_mut().unwrap().remove(field);
            }
            let independent = wist_core::envelope::sign_envelope(
                &independent,
                "publisher",
                "x1",
                &wist_core::crypto::SigningKey::from_seed(&X1_SEED),
            )
            .unwrap();
            assert!(size_of(&independent) <= higher_cap);
            r.db.record_publisher_declaration(
                "zz-independent.example",
                &serde_json::to_vec(&independent).unwrap(),
                "x1",
                independent["publisher"]["keys"][0]["public_key"]
                    .as_str()
                    .unwrap(),
                &independent,
            )
            .unwrap();
            for height in [3, 4] {
                r.db = clave::db::Db::open(&database).unwrap();
                let report =
                    clave::seal::run(&r.db, r.data.path(), &r.sk, start + height * 3600).unwrap();
                assert_eq!(report.entry_count, u64::from(height == 3));
                assert!(report.dropped.is_empty());
                if height == 3 {
                    assert_eq!(
                        stored_block(&r, 3)["entries"],
                        serde_json::json!([{
                            "type": "publisher_declaration", "body": independent
                        }])
                    );
                }
                assert_eq!(
                    r.db.peek_pending_entries()
                        .unwrap()
                        .0
                        .iter()
                        .map(|p| (p.rowid, p.entry_json.clone()))
                        .collect::<Vec<_>>(),
                    retained
                );
                assert_eq!(
                    r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
                    Some(4)
                );
                let state = clave::history::declarations::Declarations::reconstruct(
                    r.data.path(),
                    r.db.last_block().unwrap(),
                )
                .unwrap();
                assert_eq!(
                    state.domains()[&r.host].current().envelope()["publisher"]["seq"],
                    2
                );
                assert_eq!(
                    state.domains()[&r.host].window().unwrap().head().envelope(),
                    &owner_envelope
                );
            }
            r.db.set_param("block_decompressed_cap_bytes", lower_cap)
                .unwrap();
            5
        } else {
            3
        };
        for (height, expected) in [(first_height, &lower), (first_height + 1, &higher)] {
            r.db = clave::db::Db::open(&database).unwrap();
            let report =
                clave::seal::run(&r.db, r.data.path(), &r.sk, start + height * 3600).unwrap();
            assert_eq!(report.entry_count, 1);
            assert!(report.dropped.is_empty());
            let block = stored_block(&r, height as u64);
            assert_eq!(
                block["entries"],
                serde_json::json!([{"type": "publisher_declaration", "body": expected}])
            );
            assert!(wist_core::jcs::canonicalize(&block).unwrap().len() as i64 <= lower_cap);
            let state = clave::history::declarations::Declarations::reconstruct(
                r.data.path(),
                r.db.last_block().unwrap(),
            )
            .unwrap();
            assert_eq!(state.domains()[&r.host].current().envelope(), expected);
            assert_eq!(
                state.domains()[&r.host].window().unwrap().head().envelope(),
                if height == first_height {
                    &owner_envelope
                } else {
                    &higher
                }
            );
            assert_eq!(
                r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
                Some(4)
            );
            assert_eq!(
                r.db.peek_pending_entries().unwrap().0.len(),
                (first_height + 1 - height) as usize
            );
        }
        r.db = clave::db::Db::open(&database).unwrap();
        assert_eq!(
            clave::seal::run(
                &r.db,
                r.data.path(),
                &r.sk,
                start + (first_height + 2) * 3600
            )
            .unwrap()
            .entry_count,
            0
        );
        clave::history::declarations::Declarations::reconstruct(
            r.data.path(),
            r.db.last_block().unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn pending_recovery_followers_remain_eligible_after_partial_sealing() {
    let (mut r, start, owner) = sealed_recovery();
    let mut follower = owner.clone();
    follower["seq"] = 2.into();
    follower["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
    write_declaration(&r.p, &follower, "k2", &K2_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "k2", &K2_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    follower["seq"] = 3.into();
    follower["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
    follower["subdomain_scope"] = serde_json::json!((0..70)
        .map(|i| format!("long-explicit-host-{i}.example.com"))
        .collect::<Vec<_>>());
    write_declaration(&r.p, &follower, "k2", &K2_SEED);
    let pending_follower = current_declaration(&r.p);
    ingest(&r, "2026-08-09T14:00:00Z");
    r.db.set_param("block_decompressed_cap_bytes", 1800)
        .unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
    let window = r.db.get_recovery_window(&r.host).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&window.declaration_json).unwrap()["publisher"]
            ["seq"],
        2
    );
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    let mut competitor = follower.clone();
    competitor["seq"] = 4.into();
    competitor["prev_declaration"] = declaration_hash(&pending_follower).into();
    competitor["keys"] = serde_json::json!([key_entry("x1", &X1_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &competitor, "x1", &X1_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T15:00:00Z", "x1", &X1_SEED);
    ingest(&r, "2026-08-09T15:00:00Z");
    follower["seq"] = 5.into();
    follower["prev_declaration"] = declaration_hash(&pending_follower).into();
    write_declaration(&r.p, &follower, "k2", &K2_SEED);
    ingest(&r, "2026-08-09T15:00:00Z");
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(5)
    );
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        3
    );
    assert!(!rejection_codes(&r).contains(&"WIST1-E08".into()));
    r.db.set_param("block_decompressed_cap_bytes", 16_777_216)
        .unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 10800).unwrap();
    let state = clave::history::declarations::Declarations::reconstruct(
        r.data.path(),
        r.db.last_block().unwrap(),
    )
    .unwrap();
    assert_eq!(
        state.domains()[&r.host].window().unwrap().head().envelope()["publisher"]["seq"],
        5
    );
}

#[test]
fn floor_migration_authenticates_the_pinned_prefix_before_writing() {
    let (mut r, _, owner) = sealed_recovery();
    let owner_envelope = current_declaration(&r.p);
    let mut follower = owner.clone();
    follower["seq"] = 12.into();
    follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
    write_declaration(&r.p, &follower, "k2", &K2_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "k2", &K2_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    let database = r.data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&database).unwrap();
    conn.execute(
        "UPDATE publishers SET declaration_json = ?1",
        [serde_json::to_vec(&owner_envelope).unwrap()],
    )
    .unwrap();
    conn.execute("DROP TABLE declaration_floors", []).unwrap();
    let block = r.data.path().join("log/blocks/000000001.json.zst");
    let original = std::fs::read(&block).unwrap();
    std::fs::write(&block, b"corrupt").unwrap();
    assert!(clave::db::Db::open(&database).is_err());
    assert_eq!(
        conn.query_row("SELECT count(*) FROM declaration_floors", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
    std::fs::write(&block, original).unwrap();
    r.db = clave::db::Db::open(&database).unwrap();
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(12)
    );
}

#[test]
fn failed_recovery_head_write_rolls_back_declaration_floor_and_pending_entry() {
    let (mut r, _, owner) = sealed_recovery();
    let owner_envelope = current_declaration(&r.p);
    let mut follower = owner.clone();
    follower["seq"] = 2.into();
    follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
    write_declaration(&r.p, &follower, "k2", &K2_SEED);
    write_feed_signed(&r.p, &r.host, &[], "2026-08-09T14:00:00Z", "k2", &K2_SEED);
    let path = r.data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_changed_recovery_head AFTER UPDATE OF declaration_json ON recovery_windows WHEN NEW.declaration_json != OLD.declaration_json BEGIN SELECT RAISE(ABORT, 'injected head write failure'); END;").unwrap();
    let error = clave::ingest::run(
        &r.db,
        &r.client,
        r.data.path(),
        &r.host,
        "2026-08-09T14:00:00Z",
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected head write failure"));
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(1)
    );
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        0
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &r.db.get_publisher_declaration(&r.host).unwrap().unwrap()
        )
        .unwrap(),
        owner_envelope
    );
    assert!(r.db.list_rejections(&r.host).unwrap().is_empty());
    conn.execute("DROP TRIGGER fail_changed_recovery_head", [])
        .unwrap();
    r.db = clave::db::Db::open(&path).unwrap();
    ingest(&r, "2026-08-09T14:00:00Z");
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(2)
    );
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
}

#[test]
fn admission_deadline_preserves_pending_followers_and_later_replacements() {
    for recovery_follower in [false, true] {
        let (mut r, start, owner) = sealed_recovery();
        let owner_envelope = current_declaration(&r.p);
        let rejected = add_delta_signed(
            &r.p,
            "https://example.com/old",
            "old",
            None,
            "2026-08-09T14:00:00Z",
            "k1",
            &K1_SEED,
        );
        write_feed_signed(
            &r.p,
            &r.host,
            std::slice::from_ref(&rejected),
            "2026-08-09T14:00:00Z",
            "k2",
            &K2_SEED,
        );
        assert_eq!(
            ingest(&r, "2026-08-09T14:00:00Z").queued,
            vec![rejected.clone()]
        );
        let mut competitor = owner.clone();
        competitor["seq"] = 2.into();
        competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
        competitor["keys"] = serde_json::json!([key_entry("x1", &X1_SEED, "2026-08-09T13:00:00Z")]);
        write_declaration(&r.p, &competitor, "x1", &X1_SEED);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-09T15:00:00Z", "x1", &X1_SEED);
        ingest(&r, "2026-08-09T15:00:00Z");
        let mut follower = owner;
        follower["seq"] = 3.into();
        follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
        follower["keys"] = serde_json::json!([key_entry("k1", &K1_SEED, "2026-08-09T13:00:00Z")]);
        let (signer, seed) = if recovery_follower {
            ("r1", &R1_SEED)
        } else {
            ("k2", &K2_SEED)
        };
        write_declaration(&r.p, &follower, signer, seed);
        let follower_envelope = current_declaration(&r.p);
        write_feed_signed(&r.p, &r.host, &[], "2026-08-09T16:00:00Z", "k1", &K1_SEED);
        ingest(&r, "2026-08-09T16:00:00Z");
        let deadline = "2026-08-16T13:00:00Z";
        r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
        ingest(&r, deadline);
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            1
        );
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(3)
        );
        assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
        assert!(r
            .db
            .list_rejections(&r.host)
            .unwrap()
            .iter()
            .any(|rejection| rejection.delta_id.as_ref() == Some(&rejected)
                && rejection.code == "WIST1-E13"));
        assert!(!r.db.is_delta_seen_for(&rejected, &r.host).unwrap());
        assert!(r
            .db
            .url_tip(&r.host, "https://example.com/old")
            .unwrap()
            .is_none());
        competitor["seq"] = 4.into();
        competitor["prev_declaration"] = declaration_hash(&follower_envelope).into();
        write_declaration(&r.p, &competitor, "x1", &X1_SEED);
        let replacement = current_declaration(&r.p);
        let accepted = add_delta_signed(
            &r.p,
            "https://example.com/after",
            "after",
            None,
            deadline,
            "x1",
            &X1_SEED,
        );
        write_feed_signed(
            &r.p,
            &r.host,
            std::slice::from_ref(&accepted),
            deadline,
            "x1",
            &X1_SEED,
        );
        assert_eq!(ingest(&r, deadline).accepted, vec![accepted.clone()]);
        r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
        ingest(&r, deadline);
        let report = clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
        let state = clave::history::declarations::Declarations::reconstruct(
            r.data.path(),
            r.db.last_block().unwrap(),
        )
        .unwrap();
        assert_eq!(state.domains()[&r.host].current().envelope(), &replacement);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &r.db.get_publisher_declaration(&r.host).unwrap().unwrap()
            )
            .unwrap(),
            replacement
        );
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(4)
        );
        assert_eq!(
            r.db.get_record("https://example.com/after", &r.host)
                .unwrap()
                .is_some(),
            !recovery_follower
        );
        if recovery_follower {
            let window = state.domains()[&r.host].window().unwrap();
            assert_eq!(window.owner().envelope(), &follower_envelope);
            assert_eq!(window.owner().position().block_number, report.block_number);
            assert_eq!(
                r.db.drain_queued_deltas(&r.host).unwrap()[0].delta_id,
                accepted
            );
        } else {
            assert!(state.domains()[&r.host].window().is_none());
        }
    }
}

#[test]
fn failed_admission_settlement_rolls_back_every_database_effect() {
    let (mut r, _, _) = sealed_recovery();
    let rejected = add_delta_signed(
        &r.p,
        "https://example.com/old",
        "old",
        None,
        "2026-08-09T14:00:00Z",
        "k1",
        &K1_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        std::slice::from_ref(&rejected),
        "2026-08-09T14:00:00Z",
        "k2",
        &K2_SEED,
    );
    ingest(&r, "2026-08-09T14:00:00Z");
    let path = r.data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_settlement BEFORE INSERT ON recovery_settlements BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    assert!(clave::ingest::run(
        &r.db,
        &r.client,
        r.data.path(),
        &r.host,
        "2026-08-16T13:00:00Z"
    )
    .is_err());
    r.db = clave::db::Db::open(&path).unwrap();
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_some());
    assert!(r.db.is_delta_seen_for(&rejected, &r.host).unwrap());
    assert_eq!(
        r.db.url_tip(&r.host, "https://example.com/old")
            .unwrap()
            .as_deref(),
        Some(rejected.as_str())
    );
    assert!(r.db.list_rejections(&r.host).unwrap().is_empty());
    conn.execute_batch("DROP TRIGGER refuse_settlement;")
        .unwrap();
    ingest(&r, "2026-08-16T13:00:00Z");
    assert!(!r.db.is_delta_seen_for(&rejected, &r.host).unwrap());
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
}

#[test]
fn cadence_rounding_cannot_reopen_a_settled_admission_window() {
    let r = rig(make_publisher_with_recovery);
    let at = |seconds| jiff::Timestamp::from_second(seconds).unwrap().to_string();
    r.db.set_param("block_cadence_seconds", 3600).unwrap();
    write_feed(&r.p, &r.host, &[], &at(T0));
    ingest(&r, &at(T0));
    let effective = T0 + 30 * DAY;
    let update = wist_core::envelope::sign_envelope(&serde_json::json!({
        "wist_version": "1.0.0", "action": "parameter_change", "subject": "block_cadence_seconds",
        "details": {"parameter": "block_cadence_seconds", "value": 3599}, "effective_at": at(effective)
    }), "update", "log1", &r.sk).unwrap();
    r.db.insert_pending_entry("registry_update", "", &update, 0)
        .unwrap();
    let report = clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();
    assert!(report.dropped.is_empty(), "{:?}", report.dropped);
    clave::seal::run(&r.db, r.data.path(), &r.sk, effective).unwrap();
    let prior = current_declaration(&r.p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &owner, "r1", &R1_SEED);
    let opened = (effective.div_euclid(3599) + 1) * 3599;
    write_feed_signed(&r.p, &r.host, &[], &at(opened), "k2", &K2_SEED);
    ingest(&r, &at(opened));
    clave::seal::run(&r.db, r.data.path(), &r.sk, opened).unwrap();
    let survivor = add_delta_signed(
        &r.p,
        "https://example.com/survivor",
        "body",
        None,
        &at(opened),
        "k2",
        &K2_SEED,
    );
    write_feed_signed(
        &r.p,
        &r.host,
        std::slice::from_ref(&survivor),
        &at(opened),
        "k2",
        &K2_SEED,
    );
    assert_eq!(ingest(&r, &at(opened)).queued, vec![survivor.clone()]);
    let deadline = opened + 7 * DAY;
    ingest(&r, &at(deadline));
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
    let error = clave::seal::run(&r.db, r.data.path(), &r.sk, deadline)
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("predates completed recovery settlement"),
        "{error}"
    );
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
    assert_eq!(r.db.count_pending_entries("publisher_delta").unwrap(), 1);
    let next = (deadline.div_euclid(3599) + 1) * 3599;
    clave::seal::run(&r.db, r.data.path(), &r.sk, next).unwrap();
    assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
    assert_eq!(
        r.db.get_record("https://example.com/survivor", &r.host)
            .unwrap()
            .unwrap()
            .delta_id,
        survivor
    );
    clave::history::declarations::Declarations::reconstruct(
        r.data.path(),
        r.db.last_block().unwrap(),
    )
    .unwrap();
}

#[test]
fn pulls_crossing_the_deadline_refresh_authority_before_admission() {
    for crossing_call in [0, 1, 2, 3, 5] {
        let (r, _, _) = sealed_recovery();
        let delta = add_delta_signed(
            &r.p,
            "https://example.com/crossing",
            "body",
            None,
            "2026-08-16T12:59:59Z",
            "k1",
            &K1_SEED,
        );
        write_feed_signed(
            &r.p,
            &r.host,
            std::slice::from_ref(&delta),
            "2026-08-16T12:59:59Z",
            "k2",
            &K2_SEED,
        );
        let calls = std::cell::Cell::new(0);
        let report = clave::ingest::run_with_clock(
            &r.db,
            &r.client,
            r.data.path(),
            &r.host,
            "2026-08-16T12:59:59Z",
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call < crossing_call {
                    "2026-08-16T12:59:59Z"
                } else {
                    "2026-08-16T13:00:00Z"
                }
                .parse()
                .unwrap()
            },
        )
        .unwrap();
        assert_eq!(report.rejected, vec![(delta.clone(), "WIST1-E02".into())]);
        assert!(report.queued.is_empty());
        assert!(report.accepted.is_empty());
        assert!(r.db.get_recovery_window(&r.host).unwrap().is_none());
        assert!(!r.db.is_delta_seen_for(&delta, &r.host).unwrap());
        assert!(r
            .db
            .url_tip(&r.host, "https://example.com/crossing")
            .unwrap()
            .is_none());
    }
}

#[test]
fn deadline_retries_seen_copies_and_retrieves_a_settled_predecessor() {
    for with_child in [false, true] {
        let (r, _, _) = sealed_recovery();
        let url = "https://example.com/retry";
        let parent = add_delta_signed(
            &r.p,
            url,
            "parent",
            None,
            "2026-08-09T14:00:00Z",
            "k1",
            &K1_SEED,
        );
        write_feed_signed(
            &r.p,
            &r.host,
            std::slice::from_ref(&parent),
            "2026-08-09T14:00:00Z",
            "k2",
            &K2_SEED,
        );
        assert_eq!(
            ingest(&r, "2026-08-09T14:00:00Z").queued,
            vec![parent.clone()]
        );
        let path =
            r.p.dir
                .path()
                .join(format!(".well-known/wist/deltas/{}.json", &parent[7..]));
        let old: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let replacement = wist_core::envelope::sign_envelope(
            &old["delta"],
            "delta",
            "k2",
            &wist_core::crypto::SigningKey::from_seed(&K2_SEED),
        )
        .unwrap();
        std::fs::write(path, serde_json::to_vec(&replacement).unwrap()).unwrap();
        let requested = if with_child {
            add_delta_signed(
                &r.p,
                url,
                "child",
                Some(&parent),
                "2026-08-16T12:59:59Z",
                "k2",
                &K2_SEED,
            )
        } else {
            parent.clone()
        };
        write_feed_signed(
            &r.p,
            &r.host,
            std::slice::from_ref(&requested),
            "2026-08-16T12:59:59Z",
            "k2",
            &K2_SEED,
        );
        let calls = std::cell::Cell::new(0);
        let report = clave::ingest::run_with_clock(
            &r.db,
            &r.client,
            r.data.path(),
            &r.host,
            "2026-08-16T12:59:59Z",
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call < if with_child { 5 } else { 1 } {
                    "2026-08-16T12:59:59Z"
                } else {
                    "2026-08-16T13:00:00Z"
                }
                .parse()
                .unwrap()
            },
        )
        .unwrap();
        let expected = if with_child {
            vec![parent.clone(), requested.clone()]
        } else {
            vec![parent.clone()]
        };
        assert_eq!(report.accepted, expected);
        assert!(report.queued.is_empty());
        assert!(report.rejected.is_empty());
        assert_eq!(
            r.db.url_tip(&r.host, url).unwrap().as_deref(),
            Some(requested.as_str())
        );
        assert!(r
            .db
            .list_rejections(&r.host)
            .unwrap()
            .iter()
            .any(|rejection| rejection.delta_id.as_ref() == Some(&parent)
                && rejection.code == "WIST1-E13"));
    }
}
