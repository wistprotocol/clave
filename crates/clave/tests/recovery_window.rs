mod common;

use common::*;

const T0: i64 = 1_754_740_800; // 2026-08-09T12:00:00Z
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
    let (listener, host) = reserve_addr();
    let p = p_for(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    let client = clave::fetch::Client::new(true);
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

    let b3 = clave::seal::run(&r.db, r.data.path(), &r.sk, T0 + 7200 + 7 * DAY + 60).unwrap();
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
fn superseded_key_declaration_during_window_is_rejected() {
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
    assert!(rejection_codes(&r).contains(&"WIST1-E08".to_string()));

    let stored_after = r.db.get_publisher_declaration(&r.host).unwrap().unwrap();
    let stored_after: serde_json::Value = serde_json::from_slice(&stored_after).unwrap();
    assert_eq!(stored_after["publisher"]["seq"], 1);
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
