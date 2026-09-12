mod common;

use clave::db::Db;
use common::*;
use serde_json::Value;
use std::sync::{Arc, Mutex};

const NOW: &str = "2026-08-09T14:00:00Z";
const EARLIER: &str = "2026-08-09T13:59:59Z";

fn retained(path: &std::path::Path, domain: &str) -> Option<i64> {
    use rusqlite::OptionalExtension;
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT generated_at_s FROM feed_observations WHERE domain = ?1",
            [domain],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
}

#[test]
fn signed_observation_sequences_survive_restart() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist2/feed-regression.json")).unwrap(),
    )
    .unwrap();
    let declaration = serde_json::to_vec(&vector["declaration"]).unwrap();
    let (listener, host, client) = reserve_addr();
    let response = Arc::new(Mutex::new(Vec::<u8>::new()));
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let serving = response.clone();
    let recorded = requests.clone();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                    recorded.lock().unwrap().push(uri.path().into());
                    let body = if uri.path().ends_with("/publisher.json") {
                        declaration.clone()
                    } else {
                        serving.lock().unwrap().clone()
                    };
                    async move { body }
                });
                axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                    .await
                    .unwrap();
            });
    });
    for case in vector["cases"].as_array().unwrap() {
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let mut expected_rejections = Vec::new();
        for event in case["observations"].as_array().unwrap() {
            let name = event["name"].as_str().unwrap();
            *response.lock().unwrap() = serde_json::to_vec(&event["envelope"]).unwrap();
            requests.lock().unwrap().clear();
            let db = Db::open(&path).unwrap();
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert!(
                report.accepted.is_empty() && report.queued.is_empty(),
                "{name}"
            );
            assert!(report.rejected.is_empty() && !report.suspended, "{name}");
            assert_eq!(report.noise, event["noise"].as_str(), "{name}");
            if let Some(code) = event["code"].as_str() {
                expected_rejections.push(code.to_string());
            }
            let rejections = db.list_rejections(&host).unwrap();
            assert_eq!(
                rejections.iter().map(|r| &r.code).collect::<Vec<_>>(),
                expected_rejections.iter().rev().collect::<Vec<_>>(),
                "{name}"
            );
            assert!(rejections.iter().all(|r| r.delta_id.is_none()));
            assert_eq!(
                requests.lock().unwrap().len(),
                2 + event["declaration_retries"].as_u64().unwrap() as usize,
                "{name}"
            );
            drop(db);
            assert_eq!(
                retained(&path, &host),
                event["retained_s"].as_i64(),
                "{name}"
            );
        }
    }
}

#[test]
fn regression_stops_page_delta_and_payload_work() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    serve_static(listener, publisher.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    write_feed(&publisher, &host, &[], NOW);
    let db = Db::open(&path).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    drop(db);
    let id = add_delta(&publisher, "https://localhost/a", "content", None);
    write_feed_with_next(
        &publisher,
        &host,
        std::slice::from_ref(&id),
        EARLIER,
        Some(&page_url(&host, 0)),
    );
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert!(report.accepted.is_empty() && report.queued.is_empty());
    assert!(report.noise.is_none());
    assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST2-E05");
    assert!(!db.is_delta_seen(&id).unwrap());
    assert!(!data
        .path()
        .join(format!("payloads/{}.json", &id[7..]))
        .exists());
    write_feed(&publisher, &host, std::slice::from_ref(&id), NOW);
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, [id]);
}

#[test]
fn downstream_failures_and_budget_suspension_preserve_the_observation() {
    for failure in ["page", "delta", "payload", "budget"] {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher(&host);
        serve_static(listener, publisher.dir.path().into());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let id = add_delta(&publisher, "https://localhost/a", "content", None);
        let next = (failure == "page").then(|| page_url(&host, 0));
        write_feed_with_next(
            &publisher,
            &host,
            std::slice::from_ref(&id),
            NOW,
            next.as_deref(),
        );
        if matches!(failure, "delta" | "payload") {
            let directory = if failure == "delta" {
                "deltas"
            } else {
                "payloads"
            };
            std::fs::remove_file(
                publisher
                    .dir
                    .path()
                    .join(format!(".well-known/wist/{directory}/{}.json", &id[7..])),
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        if failure == "budget" {
            let size = std::fs::metadata(publisher.dir.path().join(".well-known/wist/feed.json"))
                .unwrap()
                .len() as i64;
            db.set_param("ingest_budget_bytes_day", size).unwrap();
        }
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert!(
            report.accepted.is_empty() && report.queued.is_empty(),
            "{failure}"
        );
        assert_eq!(report.suspended, failure == "budget", "{failure}");
        assert_eq!(
            retained(&path, &host),
            Some(NOW.parse::<jiff::Timestamp>().unwrap().as_second()),
            "{failure}"
        );
        db.set_param("ingest_budget_bytes_day", 100_000_000)
            .unwrap();
        drop(db);
        write_feed(&publisher, &host, &[], EARLIER);
        let db = Db::open(&path).unwrap();
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert!(report.noise.is_none(), "{failure}");
        assert_eq!(
            db.list_rejections(&host).unwrap().first().unwrap().code,
            "WIST2-E05",
            "{failure}"
        );
    }
}

#[test]
fn observation_storage_failure_stops_admission() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    serve_static(listener, publisher.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let id = add_delta(&publisher, "https://localhost/a", "content", None);
    write_feed(&publisher, &host, std::slice::from_ref(&id), NOW);
    let db = Db::open(&path).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_feed_observation BEFORE INSERT ON feed_observations
         BEGIN SELECT RAISE(ABORT, 'observation storage unavailable'); END;",
        )
        .unwrap();
    assert!(clave::ingest::run(&db, &client, data.path(), &host, NOW).is_err());
    assert_eq!(retained(&path, &host), None);
    assert!(!db.is_delta_seen(&id).unwrap());
    assert!(!data
        .path()
        .join(format!("payloads/{}.json", &id[7..]))
        .exists());
}

#[test]
fn older_sealed_pages_do_not_regress_the_live_feed() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    serve_static(listener, publisher.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let opening = "2026-08-09T12:00:00Z";
    write_feed(&publisher, &host, &[], opening);
    clave::ingest::run(&db, &client, data.path(), &host, opening).unwrap();
    let signing = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(
        &db,
        data.path(),
        &signing,
        opening.parse::<jiff::Timestamp>().unwrap().as_second(),
    )
    .unwrap();
    let older = add_delta(&publisher, "https://localhost/older", "older", None);
    let newer = add_delta(&publisher, "https://localhost/newer", "newer", None);
    write_feed_page(
        &publisher,
        &host,
        0,
        std::slice::from_ref(&older),
        EARLIER,
        None,
    );
    write_feed_with_next(
        &publisher,
        &host,
        std::slice::from_ref(&newer),
        NOW,
        Some(&page_url(&host, 0)),
    );
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, [older, newer]);
    assert!(db.list_rejections(&host).unwrap().is_empty());
    assert_eq!(
        retained(&path, &host),
        Some(NOW.parse::<jiff::Timestamp>().unwrap().as_second())
    );
}

#[test]
fn declaration_rotation_and_identity_reset_preserve_the_observation() {
    for identity_reset in [false, true] {
        let (listener, host, client) = reserve_addr();
        let mut publisher = make_publisher(&host);
        serve_static(listener, publisher.dir.path().into());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        write_feed(&publisher, &host, &[], NOW);
        clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        let original = current_declaration(&publisher);
        let mut replacement = original["publisher"].clone();
        replacement["seq"] = 1.into();
        replacement["prev_declaration"] = declaration_hash(&original).into();
        let seed = [2u8; 32];
        replacement["keys"][0]["public_key"] = wist_core::crypto::b64u_encode(
            &ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        )
        .into();
        write_declaration(
            &publisher,
            &replacement,
            "k1",
            if identity_reset { &seed } else { &[1u8; 32] },
        );
        publisher.sk = wist_core::crypto::SigningKey::from_seed(&seed);
        write_feed(&publisher, &host, &[], EARLIER);
        drop(db);
        let db = Db::open(&path).unwrap();
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert!(report.noise.is_none(), "{identity_reset}");
        let accepted: Value =
            serde_json::from_slice(&db.get_publisher_declaration(&host).unwrap().unwrap()).unwrap();
        assert_eq!(accepted["publisher"], replacement);
        assert_eq!(
            db.list_rejections(&host).unwrap().first().unwrap().code,
            "WIST2-E05"
        );
        write_feed(&publisher, &host, &[], NOW);
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert_eq!(report.noise, Some("WIST2-E02"));
    }
}
