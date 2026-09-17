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
            let paths = requests.lock().unwrap().clone();
            assert_eq!(
                paths.len(),
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

#[test]
fn recovery_settlement_preserves_a_superseded_identitys_feed_maximum() {
    const MAXIMUM: &str = "9999-12-31T23:59:59Z";
    const DEADLINE: &str = "2026-08-16T13:00:00Z";
    for seal_settlement in [false, true] {
        for seal_competitor in [false, true] {
            let (listener, host, client) = reserve_addr();
            let publisher = make_publisher_with_recovery(&host);
            serve_static(listener, publisher.dir.path().into());
            let data = tempfile::tempdir().unwrap();
            clave::init::run(&host, data.path()).unwrap();
            let path = data.path().join("clave.sqlite");
            let mut db = Db::open(&path).unwrap();
            let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
            let initial = current_declaration(&publisher);
            let mut owner = initial["publisher"].clone();
            owner["seq"] = 1.into();
            owner["prev_declaration"] = declaration_hash(&initial).into();
            owner["keys"] = serde_json::json!([key_entry("k2", &K2_SEED, "2026-08-09T13:00:00Z")]);
            for (at, body, signer, seed, feed_signer, feed_seed) in [
                (
                    "2026-08-09T12:00:00Z",
                    &initial["publisher"],
                    "k1",
                    &K1_SEED,
                    "k1",
                    &K1_SEED,
                ),
                (
                    "2026-08-09T13:00:00Z",
                    &owner,
                    "r1",
                    &R1_SEED,
                    "k2",
                    &K2_SEED,
                ),
            ] {
                write_declaration(&publisher, body, signer, seed);
                write_feed_signed(&publisher, &host, &[], at, feed_signer, feed_seed);
                let report = clave::ingest::run(&db, &client, data.path(), &host, at).unwrap();
                assert_eq!(report.noise, Some("WIST2-E02"));
                clave::seal::run(
                    &db,
                    data.path(),
                    &key,
                    at.parse::<jiff::Timestamp>().unwrap().as_second(),
                )
                .unwrap();
            }
            let owner_envelope = current_declaration(&publisher);
            let mut competitor = owner.clone();
            competitor["seq"] = 2.into();
            competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
            competitor["keys"] =
                serde_json::json!([key_entry("x1", &X1_SEED, "2026-08-09T14:00:00Z")]);
            write_declaration(&publisher, &competitor, "x1", &X1_SEED);
            write_feed_signed(&publisher, &host, &[], MAXIMUM, "x1", &X1_SEED);
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert_eq!(report.noise, Some("WIST2-E02"));
            let accepted: Value =
                serde_json::from_slice(&db.get_publisher_declaration(&host).unwrap().unwrap())
                    .unwrap();
            assert_eq!(accepted["publisher"], competitor);
            assert_eq!(retained(&path, &host), Some(253_402_300_799));
            if seal_competitor {
                clave::seal::run(
                    &db,
                    data.path(),
                    &key,
                    NOW.parse::<jiff::Timestamp>().unwrap().as_second(),
                )
                .unwrap();
            }
            db = Db::open(&path).unwrap();
            assert!(db.get_recovery_window(&host).unwrap().is_some());
            if seal_settlement {
                clave::seal::run(
                    &db,
                    data.path(),
                    &key,
                    DEADLINE.parse::<jiff::Timestamp>().unwrap().as_second(),
                )
                .unwrap();
                db = Db::open(&path).unwrap();
            }
            write_declaration(&publisher, &owner, "r1", &R1_SEED);
            let id = add_delta_signed(
                &publisher,
                "https://localhost/recovered",
                "recovered content",
                None,
                DEADLINE,
                "k2",
                &K2_SEED,
            );
            write_feed_signed(
                &publisher,
                &host,
                std::slice::from_ref(&id),
                DEADLINE,
                "k2",
                &K2_SEED,
            );
            let report = clave::ingest::run(&db, &client, data.path(), &host, DEADLINE).unwrap();
            assert!(report.accepted.is_empty() && report.queued.is_empty());
            assert_eq!(report.noise, None);
            assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST2-E05");
            assert!(!db.is_delta_seen(&id).unwrap());
            assert!(db.get_recovery_window(&host).unwrap().is_none());
            let restored: Value =
                serde_json::from_slice(&db.get_publisher_declaration(&host).unwrap().unwrap())
                    .unwrap();
            assert_eq!(restored, owner_envelope);
            assert_eq!(db.highest_accepted_declaration_seq(&host).unwrap(), Some(2));
            db = Db::open(&path).unwrap();
            assert_eq!(retained(&path, &host), Some(253_402_300_799));
            write_feed_signed(
                &publisher,
                &host,
                std::slice::from_ref(&id),
                MAXIMUM,
                "k2",
                &K2_SEED,
            );
            let report = clave::ingest::run(&db, &client, data.path(), &host, DEADLINE).unwrap();
            assert_eq!(report.accepted, std::slice::from_ref(&id));
            assert!(report.queued.is_empty() && report.rejected.is_empty());
            let after_deadline = DEADLINE.parse::<jiff::Timestamp>().unwrap().as_second() + 3600;
            clave::seal::run(&db, data.path(), &key, after_deadline).unwrap();
            db = Db::open(&path).unwrap();
            assert_eq!(retained(&path, &host), Some(253_402_300_799));
            assert_eq!(
                db.get_record("https://localhost/recovered", &host)
                    .unwrap()
                    .unwrap()
                    .delta_id,
                id
            );
        }
    }
}
