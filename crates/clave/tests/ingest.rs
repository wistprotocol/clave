mod common;

use clave::history::declarations::DeclarationsReplay;
use common::{
    add_delta, make_publisher, make_publisher_with_scope, reserve_addr, serve_static, write_feed,
};
use std::fs;

#[test]
fn ingest_accepts_valid_and_rejects_bad_commitment() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a", "alpha body", None);
    let id2 = add_delta(&p, "https://example.com/b", "beta body", None);
    let hex2 = id2.strip_prefix("sha256:").unwrap().to_string();
    let bad = p
        .dir
        .path()
        .join(format!(".well-known/wist/payloads/{hex2}.json"));
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&bad).unwrap()).unwrap();
    v["content"]["extract"] = "tampered".into();
    fs::write(&bad, serde_json::to_vec(&v).unwrap()).unwrap();
    write_feed(
        &p,
        &host,
        &[id1.clone(), id2.clone()],
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    assert_eq!(report.accepted, vec![id1.clone()]);
    assert_eq!(
        report.rejected,
        vec![(id2.clone(), "WIST2-E03".to_string())]
    );

    let hex1 = id1.strip_prefix("sha256:").unwrap();
    let src = fs::read(
        p.dir
            .path()
            .join(format!(".well-known/wist/payloads/{hex1}.json")),
    )
    .unwrap();
    let dst = fs::read(tmp.path().join(format!("payloads/{hex1}.json"))).unwrap();
    assert_eq!(src, dst);
    assert!(!tmp.path().join(format!("payloads/{hex2}.json")).exists());

    assert_eq!(
        db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);

    let report2 =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:10Z").unwrap();
    assert!(report2.accepted.is_empty());
    assert_eq!(report2.rejected, vec![(id2, "WIST2-E03".to_string())]);
}

#[test]
fn drain_pending_entries_orders_declaration_then_deltas_across_passes() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report1 =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(report1.accepted, vec![id1.clone()]);

    let id2 = add_delta(&p, "https://example.com/a", "alpha body v2", Some(&id1));
    write_feed(
        &p,
        &host,
        &[id1.clone(), id2.clone()],
        "2026-08-09T12:00:10Z",
    );
    let report2 =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:10Z").unwrap();
    assert_eq!(report2.accepted, vec![id2.clone()]);

    let entries = db.drain_pending_entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].entry_type, "publisher_declaration");
    assert_eq!(entries[1].entry_type, "publisher_delta");
    assert_eq!(
        wist_core::delta::delta_id(&entries[1].entry_json["delta"]).unwrap(),
        id1
    );
    assert_eq!(entries[2].entry_type, "publisher_delta");
    assert_eq!(
        wist_core::delta::delta_id(&entries[2].entry_json["delta"]).unwrap(),
        id2
    );

    assert!(db.drain_pending_entries().unwrap().is_empty());
}

#[test]
fn ingest_rejects_publisher_domain_mismatch() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher("not-the-host.example");
    let id1 = add_delta(&p, "https://not-the-host.example/a", "alpha body", None);
    write_feed(
        &p,
        "not-the-host.example",
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    assert!(report.accepted.is_empty());
    assert!(db.get_publisher(&host).unwrap().is_none());
    let rejections = db.list_rejections(&host).unwrap();
    assert_eq!(rejections.len(), 1);
    assert_eq!(rejections[0].code, "WIST2-E04");
}

#[test]
fn ingest_rejects_feed_domain_mismatch() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(
        &p,
        "different.example",
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    assert!(report.accepted.is_empty());
    assert!(
        db.get_publisher(&host).unwrap().is_some(),
        "onboarding itself succeeds; only the feed pull is rejected"
    );
    let rejections = db.list_rejections(&host).unwrap();
    assert_eq!(rejections[0].code, "WIST2-E04");
    assert_eq!(report.noise, Some("WIST2-E04"));
}

#[test]
fn ingest_rejects_delta_url_outside_publisher_scope() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let id1 = add_delta(&p, "https://not-in-scope.example/a", "alpha body", None);
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    assert!(report.accepted.is_empty());
    assert_eq!(report.rejected, vec![(id1, "WIST1-E03".to_string())]);
}

#[test]
fn ingest_accepts_delta_url_within_subdomain_scope() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["scoped.example"]);
    let id1 = add_delta(&p, "https://scoped.example/a", "alpha body", None);
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    assert_eq!(report.accepted, vec![id1]);
}

#[test]
fn ingest_walks_feed_pages_and_backfills_oldest_first() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a", "first content", None);
    let id2 = add_delta(&p, "https://example.com/a", "second content", Some(&id1));
    let id3 = add_delta(&p, "https://example.com/b", "other page", None);
    common::write_feed_page(
        &p,
        &host,
        0,
        std::slice::from_ref(&id1),
        "2026-08-09T10:00:00Z",
        None,
    );
    common::write_feed_page(
        &p,
        &host,
        1,
        std::slice::from_ref(&id2),
        "2026-08-09T11:00:00Z",
        Some(&common::page_url(&host, 0)),
    );
    common::write_feed_with_next(
        &p,
        &host,
        std::slice::from_ref(&id3),
        "2026-08-09T12:00:00Z",
        Some(&common::page_url(&host, 1)),
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    seal_page_authority(&db, &client, tmp.path(), &p);

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(report.accepted, vec![id1.clone(), id2.clone(), id3.clone()]);
    assert!(report.rejected.is_empty());
    assert!(!report.suspended);
    assert_eq!(report.noise, None);
    assert!(db.ingest_bytes(&host, "2026-08-09").unwrap() > 0);

    let again =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T13:00:00Z").unwrap();
    assert!(again.accepted.is_empty());
    assert_eq!(again.noise, Some("WIST2-E02"));
}

#[test]
fn ingest_budget_suspends_walk_and_resumes_when_budget_allows() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a", "first content", None);
    let id2 = add_delta(&p, "https://example.com/a", "second content", Some(&id1));
    common::write_feed_page(
        &p,
        &host,
        0,
        std::slice::from_ref(&id1),
        "2026-08-09T10:00:00Z",
        None,
    );
    common::write_feed_with_next(
        &p,
        &host,
        std::slice::from_ref(&id2),
        "2026-08-09T12:00:00Z",
        Some(&common::page_url(&host, 0)),
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    seal_page_authority(&db, &client, tmp.path(), &p);
    db.set_param("ingest_budget_bytes_day", 1).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert!(report.suspended);
    assert!(report.accepted.is_empty());
    assert!(db.walk_suspended(&host).unwrap());

    db.set_param("ingest_budget_bytes_day", 1_073_741_824)
        .unwrap();
    let resumed =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-10T00:00:05Z").unwrap();
    assert_eq!(resumed.accepted, vec![id1.clone(), id2.clone()]);
    assert!(!resumed.suspended);
    assert!(!db.walk_suspended(&host).unwrap());
}

#[test]
fn a_pull_suspends_at_its_work_limit_and_a_later_pull_resumes() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a", "first content", None);
    let id2 = add_delta(&p, "https://example.com/a", "second content", Some(&id1));
    common::write_feed_page(
        &p,
        &host,
        0,
        std::slice::from_ref(&id1),
        "2026-08-09T10:00:00Z",
        None,
    );
    common::write_feed_with_next(
        &p,
        &host,
        std::slice::from_ref(&id2),
        "2026-08-09T12:00:00Z",
        Some(&common::page_url(&host, 0)),
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    seal_page_authority(&db, &client, tmp.path(), &p);

    let clock = || "2026-08-09T12:00:05Z".parse::<jiff::Timestamp>().unwrap();
    let report = clave::ingest::run_bounded(
        &db,
        &client,
        tmp.path(),
        &host,
        "2026-08-09T12:00:05Z",
        clock,
        clave::ingest::PullLimits {
            work_bytes: u64::MAX,
            work_objects: 1,
        },
    )
    .unwrap();
    assert!(report.suspended);
    assert!(report.accepted.is_empty());
    assert!(db.walk_suspended(&host).unwrap());
    assert!(db.ingest_bytes(&host, "2026-08-09").unwrap() > 0);

    let resumed =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:10:05Z").unwrap();
    assert_eq!(resumed.accepted, vec![id1.clone(), id2.clone()]);
    assert!(!resumed.suspended);
    assert!(!db.walk_suspended(&host).unwrap());
}

fn seal_page_authority(
    db: &clave::db::Db,
    client: &clave::fetch::Client,
    directory: &std::path::Path,
    publisher: &common::TestPub,
) {
    let path = publisher.dir.path().join(".well-known/wist/feed.json");
    let feed = std::fs::read(&path).unwrap();
    write_feed(publisher, &publisher.domain, &[], "2026-08-09T09:00:00Z");
    let report = clave::ingest::run(
        db,
        client,
        directory,
        &publisher.domain,
        "2026-08-09T09:00:00Z",
    )
    .unwrap();
    assert!(report.rejected.is_empty());
    assert_eq!(report.noise, Some("WIST2-E02"));
    let signing = clave::keys::load(&directory.join("keys/seed")).unwrap();
    clave::seal::run(
        db,
        directory,
        &signing,
        "2026-08-09T09:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second(),
    )
    .unwrap();
    std::fs::write(path, feed).unwrap();
}

#[test]
fn ingest_onboard_failure_is_e04_noise() {
    let (listener, host, client) = reserve_addr();
    let empty = tempfile::tempdir().unwrap();
    serve_static(listener, empty.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(report.noise, Some("WIST2-E04"));
}

#[test]
fn a_feed_whose_signature_does_not_verify_is_e04_noise() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let id = add_delta(&p, &format!("https://{host}/a"), "alpha body", None);
    write_feed(&p, &host, &[id], "2026-08-09T12:00:00Z");

    let path = p.dir.path().join(".well-known/wist/feed.json");
    let mut env: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    env["feed"]["generated_at"] = "2026-08-09T12:00:01Z".into();
    fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    assert_eq!(report.noise, Some("WIST2-E04"));
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|r| r.code)
        .collect();
    assert!(codes.contains(&"WIST2-E04".to_string()), "codes {codes:?}");
    assert!(!codes.contains(&"WIST2-E01".to_string()), "codes {codes:?}");
}

#[test]
fn a_declaration_that_fails_verification_is_e01_and_an_unknown_key_is_e02() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let id = add_delta(&p, &format!("https://{host}/a"), "alpha body", None);
    write_feed(&p, &host, &[id], "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    let path = p.dir.path().join(".well-known/wist/publisher.json");
    let stored: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

    let mut tampered = stored.clone();
    tampered["publisher"]["seq"] = 1.into();
    tampered["publisher"]["prev_declaration"] = common::declaration_hash(&stored).as_str().into();
    fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T13:00:05Z").unwrap();
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|r| r.code)
        .collect();
    assert!(codes.contains(&"WIST1-E01".to_string()), "codes {codes:?}");

    let mut unknown = tampered.clone();
    unknown["sig"]["key_id"] = "kX".into();
    fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T14:00:05Z").unwrap();
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|r| r.code)
        .collect();
    assert!(codes.contains(&"WIST1-E02".to_string()), "codes {codes:?}");
}

#[test]
fn a_stale_key_set_cache_with_a_failed_rediscovery_fails_closed() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let id = add_delta(&p, &format!("https://{host}/a"), "alpha body", None);
    write_feed(&p, &host, &[id], "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    fs::remove_file(p.dir.path().join(".well-known/wist/publisher.json")).unwrap();

    let inside =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T20:00:00Z").unwrap();
    assert_eq!(inside.rejected, Vec::new());

    let id2 = add_delta(&p, &format!("https://{host}/b"), "beta body", None);
    write_feed(&p, &host, &[id2], "2026-08-11T12:00:00Z");
    let stale =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-11T12:00:05Z").unwrap();
    assert!(stale.accepted.is_empty(), "accepted {:?}", stale.accepted);
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|r| r.code)
        .collect();
    assert!(codes.contains(&"WIST1-E02".to_string()), "codes {codes:?}");
}

#[test]
fn an_unsealed_prev_is_retrieved_before_the_delta_naming_it() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let url = format!("https://{host}/a");
    let first = add_delta(&p, &url, "alpha body", None);
    let second = add_delta(&p, &url, "beta body", Some(&first));
    // The Feed lists only the newer Delta; the older one is reachable at
    // its own deltas/<id>.json.
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&second),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(
        report.accepted,
        vec![first, second],
        "rejected {:?}",
        report.rejected
    );
}

#[test]
fn a_redirect_chain_that_revisits_a_url_stops_at_the_repeat() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);

    let server = std::thread::spawn(move || {
        listener
            .set_nonblocking(false)
            .expect("blocking accept loop");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            counter.fetch_add(1, Ordering::SeqCst);
            let body = format!("HTTP/1.1 302 Found\r\nLocation: http://{addr}/loop.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });

    let client = clave::fetch::Client::new(true);
    let err = client
        .get_json(&format!("http://{addr}/loop.json"))
        .unwrap_err();
    assert!(
        err.to_string().contains("already fetched"),
        "unexpected error {err}"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the chain must stop at the repeat, not run to the hop bound"
    );
    drop(server);
}

#[test]
fn invalid_first_declarations_remain_e04_noise_without_persistence() {
    for (mutation, reason) in [
        ("duplicate", "WIST1-E08"),
        ("unknown", "WIST1-E02"),
        ("signature", "WIST1-E01"),
        ("shape", "WIST1-E14"),
        ("encoding", "WIST1-E14"),
        ("excluded", "WIST1-E02"),
        ("host", "WIST1-E14"),
        ("scope", "WIST1-E14"),
        ("timestamp", "WIST1-E14"),
        ("optional-null", "WIST1-E14"),
    ] {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher(&host);
        let path = publisher.dir.path().join(".well-known/wist/publisher.json");
        let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match mutation {
            "duplicate" => {
                let key = doc["publisher"]["keys"][0].clone();
                doc["publisher"]["keys"].as_array_mut().unwrap().push(key);
                doc = wist_core::envelope::sign_envelope(
                    &doc["publisher"],
                    "publisher",
                    &publisher.kid,
                    &publisher.sk,
                )
                .unwrap();
            }
            "unknown" => doc["sig"]["key_id"] = "unknown".into(),
            "signature" => {
                doc = wist_core::envelope::sign_envelope(
                    &doc["publisher"],
                    "publisher",
                    &publisher.kid,
                    &wist_core::crypto::SigningKey::from_seed(&[22; 32]),
                )
                .unwrap();
            }
            "encoding" => {
                let mut encoded = doc["sig"]["value"].as_str().unwrap().to_string();
                let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let last = encoded.pop().unwrap() as u8;
                let index = alphabet.iter().position(|byte| *byte == last).unwrap();
                encoded.push(alphabet[index + 1] as char);
                doc["sig"]["value"] = encoded.into();
            }
            "excluded" => {
                common::rekey(
                    &mut doc["publisher"]["keys"][0],
                    &wist_core::crypto::b64u_encode(&[0; 32]),
                );
                doc = wist_core::envelope::sign_envelope(
                    &doc["publisher"],
                    "publisher",
                    &publisher.kid,
                    &publisher.sk,
                )
                .unwrap();
            }
            "host" => doc["publisher"]["domain"] = format!("{host}:8080").into(),
            "scope" => doc["publisher"]["subdomain_scope"] = serde_json::json!(["EXAMPLE.com"]),
            "timestamp" => doc["publisher"]["keys"][0]["nbf"] = (-1).into(),
            "optional-null" => doc["publisher"]["contact"] = serde_json::Value::Null,
            _ => doc["extra"] = true.into(),
        }
        fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        serve_static(listener, publisher.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example", data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let report =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z").unwrap();
        assert!(report.accepted.is_empty());
        assert_eq!(report.noise, Some("WIST2-E04"));
        assert!(db.get_publisher(&host).unwrap().is_none());
        assert_eq!(
            db.count_pending_entries("publisher_declaration").unwrap(),
            0
        );
        let rejected = db.list_rejections(&host).unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].code, "WIST2-E04");
        assert!(rejected[0].detail.as_deref().unwrap().contains(reason));
    }
}

#[test]
fn unused_excluded_keys_survive_ingest_reopen_and_sealing_without_blocking_usable_keys() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher_with_scope(&host, &["example.com"]);
    let path = publisher.dir.path().join(".well-known/wist/publisher.json");
    let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut excluded = doc["publisher"]["keys"][0].clone();
    common::rekey(&mut excluded, &wist_core::crypto::b64u_encode(&[0; 32]));
    doc["publisher"]["keys"]
        .as_array_mut()
        .unwrap()
        .insert(0, excluded);
    let signed = wist_core::envelope::sign_envelope(
        &doc["publisher"],
        "publisher",
        &publisher.kid,
        &publisher.sk,
    )
    .unwrap();
    fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
    let id = add_delta(
        &publisher,
        "https://example.com/a",
        "eligible content",
        None,
    );
    write_feed(
        &publisher,
        &host,
        std::slice::from_ref(&id),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, publisher.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example", data.path()).unwrap();
    let database = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&database).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(report.accepted, vec![id.clone()]);
    assert!(report.rejected.is_empty());
    drop(db);
    let db = clave::db::Db::open(&database).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let at = "2026-08-09T13:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let sealed = clave::seal::run(&db, data.path(), &sk, at).unwrap();
    assert_eq!(sealed.entry_count, 2);
    let mut history =
        clave::history::History::open(&db, data.path(), db.last_block().unwrap()).unwrap();
    let block = history.next_block().unwrap().unwrap();
    assert_eq!(block.entries()[0]["body"], signed);
    assert!(history.next_block().unwrap().is_none());
    assert_eq!(
        db.get_record("https://example.com/a", &host)
            .unwrap()
            .unwrap()
            .delta_id,
        id
    );
    let state = clave::history::declarations::Declarations::reconstruct(
        &db,
        data.path(),
        db.last_block().unwrap(),
    )
    .unwrap();
    assert_eq!(*state.domains()[&host].current().envelope(), signed);
}

#[test]
fn declaration_field_rejections_preserve_signed_state_through_reopen_and_sealing() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher_with_scope(
        &host,
        &["example.com", "xn--bcher-kva.example", "-foo.example"],
    );
    let path = publisher.dir.path().join(".well-known/wist/publisher.json");
    let mut initial = common::current_declaration(&publisher)["publisher"].clone();
    initial["contact"] = "😀".repeat(256).into();
    initial["keys"][0]["nbf"] = 0.into();
    let signed =
        wist_core::envelope::sign_envelope(&initial, "publisher", &publisher.kid, &publisher.sk)
            .unwrap();
    fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
    let id = add_delta(
        &publisher,
        "https://example.com/fields",
        "validated fields",
        None,
    );
    write_feed(&publisher, &host, &[id], "2026-08-09T12:00:00Z");
    serve_static(listener, publisher.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example", data.path()).unwrap();
    let database = data.path().join("clave.sqlite");
    let mut db = clave::db::Db::open(&database).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(report.noise, None);
    assert_eq!(
        db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
    for field in [
        "signature",
        "timestamp",
        "hostname",
        "optional-null",
        "length",
    ] {
        let mut incoming = signed.clone();
        match field {
            "signature" => incoming["sig"]["alg"] = "other".into(),
            "timestamp" => incoming["publisher"]["keys"][0]["nbf"] = 253_402_300_800u64.into(),
            "hostname" => incoming["publisher"]["domain"] = "LOCALHOST".into(),
            "optional-null" => incoming["publisher"]["recovery_keys"] = serde_json::Value::Null,
            _ => incoming["publisher"]["contact"] = "😀".repeat(257).into(),
        }
        fs::write(&path, serde_json::to_vec(&incoming).unwrap()).unwrap();
        let before = db.list_rejections(&host).unwrap().len();
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:01:00Z").unwrap();
        let rejections = db.list_rejections(&host).unwrap();
        assert_eq!(rejections.len(), before + 1, "{field}");
        assert_eq!(rejections.last().unwrap().code, "WIST1-E14", "{field}");
        drop(db);
        db = clave::db::Db::open(&database).unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&db.get_publisher_declaration(&host).unwrap().unwrap()).unwrap();
        assert_eq!(stored, signed, "{field}");
        assert_eq!(
            db.count_pending_entries("publisher_declaration").unwrap(),
            1
        );
    }
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let at = "2026-08-09T13:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    assert_eq!(
        clave::seal::run(&db, data.path(), &sk, at)
            .unwrap()
            .entry_count,
        2
    );
    let state = clave::history::declarations::Declarations::reconstruct(
        &db,
        data.path(),
        db.last_block().unwrap(),
    )
    .unwrap();
    assert_eq!(*state.domains()[&host].current().envelope(), signed);
}
