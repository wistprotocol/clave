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
            "SELECT generated_at_s FROM label_feed_observations WHERE domain = ?1",
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
        let mut refusals = 0;
        for event in case["observations"].as_array().unwrap() {
            let name = event["name"].as_str().unwrap();
            *response.lock().unwrap() = serde_json::to_vec(&event["envelope"]).unwrap();
            requests.lock().unwrap().clear();
            let db = Db::open(&path).unwrap();
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert!(report.labels.is_empty(), "{name}");
            assert!(report.rejected.is_empty() && !report.suspended, "{name}");
            if event["disposition"] != "usable" {
                refusals += 1;
            }
            let rejections = db.list_rejections(&host).unwrap();
            assert_eq!(rejections.len(), refusals, "{name}");
            if let Some(code) = event["code"].as_str() {
                assert_eq!(rejections[0].code, code, "{name}");
            }
            assert!(rejections.iter().all(|r| r.id.is_none()));
            assert_eq!(
                requests.lock().unwrap().as_slice(),
                [
                    "/.well-known/wist/publisher.json",
                    "/.well-known/wist/label-feed.json"
                ],
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
fn regression_stops_page_and_label_work() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    let requests = serve_recording(listener, publisher.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    write_label_feed(&publisher, &host, &[], NOW);
    let db = Db::open(&path).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    drop(db);
    let id = add_label(
        &publisher,
        "https://other.example/a",
        "2026-08-09T13:00:00Z",
    );
    write_label_feed_with_next(
        &publisher,
        &host,
        std::slice::from_ref(&id),
        EARLIER,
        Some(&label_page_url(&host, 0)),
    );
    requests.lock().unwrap().clear();
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert!(report.labels.is_empty());
    assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST2-E05");
    assert!(!db.is_label_seen_for(&id, &host).unwrap());
    assert!(requests
        .lock()
        .unwrap()
        .iter()
        .all(|uri| !uri.contains("/label-feed/") && !uri.contains("/labels/")));
    write_label_feed(&publisher, &host, std::slice::from_ref(&id), NOW);
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.labels, [id]);
}

#[test]
fn downstream_failures_and_budget_suspension_preserve_the_observation() {
    for failure in ["page", "label", "budget"] {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher(&host);
        serve_static(listener, publisher.dir.path().into());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let id = add_label(
            &publisher,
            "https://other.example/a",
            "2026-08-09T13:00:00Z",
        );
        let next = (failure == "page").then(|| label_page_url(&host, 0));
        write_label_feed_with_next(
            &publisher,
            &host,
            std::slice::from_ref(&id),
            NOW,
            next.as_deref(),
        );
        if failure == "label" {
            std::fs::remove_file(
                publisher
                    .dir
                    .path()
                    .join(format!(".well-known/wist/labels/{}.json", &id[7..])),
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        if failure == "budget" {
            let size = std::fs::metadata(
                publisher
                    .dir
                    .path()
                    .join(".well-known/wist/label-feed.json"),
            )
            .unwrap()
            .len() as i64;
            db.set_param("ingest_budget_bytes_day", size).unwrap();
        }
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        let admitted: &[String] = match failure {
            "page" => std::slice::from_ref(&id),
            _ => &[],
        };
        assert_eq!(report.labels, admitted, "{failure}");
        assert_eq!(report.suspended, failure == "budget", "{failure}");
        assert_eq!(
            retained(&path, &host),
            Some(NOW.parse::<jiff::Timestamp>().unwrap().as_second()),
            "{failure}"
        );
        db.set_param("ingest_budget_bytes_day", 100_000_000)
            .unwrap();
        drop(db);
        write_label_feed(&publisher, &host, &[], EARLIER);
        let db = Db::open(&path).unwrap();
        clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
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
    let id = add_label(
        &publisher,
        "https://other.example/a",
        "2026-08-09T13:00:00Z",
    );
    write_label_feed(&publisher, &host, std::slice::from_ref(&id), NOW);
    let db = Db::open(&path).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_label_feed_observation BEFORE INSERT ON label_feed_observations
         BEGIN SELECT RAISE(ABORT, 'observation storage unavailable'); END;",
        )
        .unwrap();
    assert!(clave::ingest::run(&db, &client, data.path(), &host, NOW).is_err());
    assert_eq!(retained(&path, &host), None);
    assert!(!db.is_label_seen_for(&id, &host).unwrap());
    assert_eq!(db.count_pending_entries("label").unwrap(), 0);
}

#[test]
fn older_sealed_pages_do_not_regress_the_live_label_feed() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    serve_static(listener, publisher.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let opening = "2026-08-09T12:00:00Z";
    write_label_feed(&publisher, &host, &[], opening);
    clave::ingest::run(&db, &client, data.path(), &host, opening).unwrap();
    let signing = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(
        &db,
        data.path(),
        &signing,
        opening.parse::<jiff::Timestamp>().unwrap().as_second(),
    )
    .unwrap();
    let older = add_label(
        &publisher,
        "https://other.example/older",
        "2026-08-09T13:00:00Z",
    );
    let newer = add_label(
        &publisher,
        "https://other.example/newer",
        "2026-08-09T13:00:00Z",
    );
    write_label_feed_page(
        &publisher,
        &host,
        0,
        std::slice::from_ref(&older),
        EARLIER,
        None,
    );
    write_label_feed_with_next(
        &publisher,
        &host,
        std::slice::from_ref(&newer),
        NOW,
        Some(&label_page_url(&host, 0)),
    );
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.labels, [older, newer]);
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
        write_label_feed(&publisher, &host, &[], NOW);
        clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        let original = current_declaration(&publisher);
        let mut replacement = original["publisher"].clone();
        replacement["seq"] = 1.into();
        replacement["prev_declaration"] = declaration_hash(&original).into();
        let seed = [2u8; 32];
        rekey(&mut replacement["keys"][0], &seed_public_b64u(&seed));
        write_declaration(
            &publisher,
            &replacement,
            if identity_reset { &seed } else { &[1u8; 32] },
        );
        publisher.sk = wist_core::crypto::SigningKey::from_seed(&seed);
        publisher.kid = kid(&seed);
        write_label_feed(&publisher, &host, &[], EARLIER);
        drop(db);
        let db = Db::open(&path).unwrap();
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        let accepted: Value =
            serde_json::from_slice(&db.get_publisher_declaration(&host).unwrap().unwrap()).unwrap();
        if identity_reset {
            assert_eq!(
                accepted["publisher"], original["publisher"],
                "{identity_reset}"
            );
            let pending: Value =
                serde_json::from_slice(&db.get_pending_identity(&host).unwrap().unwrap()).unwrap();
            assert_eq!(pending["publisher"], replacement);
            assert_eq!(report.noise, None, "{identity_reset}");
            assert!(db
                .list_rejections(&host)
                .unwrap()
                .iter()
                .all(|rejection| rejection.code != "WIST2-E05"));
            assert_eq!(
                retained(&path, &host),
                Some(NOW.parse::<jiff::Timestamp>().unwrap().as_second())
            );
            continue;
        }
        assert!(report.noise.is_none(), "{identity_reset}");
        assert_eq!(accepted["publisher"], replacement);
        assert_eq!(
            db.list_rejections(&host).unwrap().first().unwrap().code,
            "WIST2-E05"
        );
        write_label_feed(&publisher, &host, &[], NOW);
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert_eq!(report.noise, Some("WIST2-E02"));
    }
}

#[test]
fn recovery_settlement_preserves_a_superseded_identitys_label_feed_maximum() {
    const MAXIMUM: &str = "9999-12-31T23:59:59Z";
    const DEADLINE: &str = "2026-08-16T13:00:00Z";
    for seal_settlement in [false, true] {
        for seal_competitor in [false, true] {
            let (listener, host, client) = reserve_addr();
            let mut publisher = make_publisher_with_recovery(&host);
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
            owner["keys"] = serde_json::json!([key_entry(&K2_SEED, "2026-08-09T13:00:00Z")]);
            for (at, body, seed, feed_seed) in [
                (
                    "2026-08-09T12:00:00Z",
                    &initial["publisher"],
                    &K1_SEED,
                    &K1_SEED,
                ),
                ("2026-08-09T13:00:00Z", &owner, &R1_SEED, &K2_SEED),
            ] {
                write_declaration(&publisher, body, seed);
                write_label_feed_signed(&publisher, &host, &[], at, feed_seed);
                let report = clave::ingest::run(&db, &client, data.path(), &host, at).unwrap();
                assert_eq!(report.noise, None);
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
            competitor["keys"] = serde_json::json!([key_entry(&X1_SEED, "2026-08-09T14:00:00Z")]);
            write_declaration(&publisher, &competitor, &X1_SEED);
            write_label_feed_signed(&publisher, &host, &[], MAXIMUM, &X1_SEED);
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert_eq!(report.noise, None);
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
            write_declaration(&publisher, &owner, &R1_SEED);
            publisher.sk = wist_core::crypto::SigningKey::from_seed(&K2_SEED);
            publisher.kid = kid(&K2_SEED);
            let id = add_label(&publisher, "https://other.example/recovered", DEADLINE);
            write_label_feed_signed(
                &publisher,
                &host,
                std::slice::from_ref(&id),
                DEADLINE,
                &K2_SEED,
            );
            let report = clave::ingest::run(&db, &client, data.path(), &host, DEADLINE).unwrap();
            assert!(report.labels.is_empty());
            assert_eq!(report.noise, Some("WIST2-E02"));
            assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST2-E05");
            assert!(!db.is_label_seen_for(&id, &host).unwrap());
            assert!(db.get_recovery_window(&host).unwrap().is_none());
            let restored: Value =
                serde_json::from_slice(&db.get_publisher_declaration(&host).unwrap().unwrap())
                    .unwrap();
            assert_eq!(restored, owner_envelope);
            assert_eq!(db.highest_accepted_declaration_seq(&host).unwrap(), Some(2));
            db = Db::open(&path).unwrap();
            assert_eq!(retained(&path, &host), Some(253_402_300_799));
            write_label_feed_signed(
                &publisher,
                &host,
                std::slice::from_ref(&id),
                MAXIMUM,
                &K2_SEED,
            );
            let report = clave::ingest::run(&db, &client, data.path(), &host, DEADLINE).unwrap();
            assert_eq!(report.labels, std::slice::from_ref(&id));
            assert!(report.rejected.is_empty());
            let after_deadline = DEADLINE.parse::<jiff::Timestamp>().unwrap().as_second() + 3600;
            clave::seal::run(&db, data.path(), &key, after_deadline).unwrap();
            db = Db::open(&path).unwrap();
            assert_eq!(retained(&path, &host), Some(253_402_300_799));
            assert!(db.sealed_label_subject(&id).unwrap().is_some());
        }
    }
}
