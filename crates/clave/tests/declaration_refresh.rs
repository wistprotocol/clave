mod common;

use clave::db::Db;
use common::*;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const NOW: &str = "2026-08-09T14:00:00Z";
const PREFIX: &str = "/.well-known/wist/";

type Response = (axum::http::StatusCode, Vec<u8>);

fn response(doc: &Value) -> Response {
    (axum::http::StatusCode::OK, serde_json::to_vec(doc).unwrap())
}

fn serve_sequence(
    listener: std::net::TcpListener,
    directory: std::path::PathBuf,
    declarations: Vec<Response>,
) -> Arc<Mutex<Vec<String>>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let declarations = Arc::new(Mutex::new(VecDeque::from(declarations)));
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                    let directory = directory.clone();
                    let recorded = recorded.clone();
                    let declarations = declarations.clone();
                    async move {
                        recorded.lock().unwrap().push(uri.path().into());
                        if uri.path() == format!("{PREFIX}publisher.json") {
                            let mut pending = declarations.lock().unwrap();
                            if pending.len() > 1 {
                                return pending.pop_front().unwrap();
                            }
                            return pending.front().unwrap().clone();
                        }
                        match std::fs::read(directory.join(uri.path().trim_start_matches('/'))) {
                            Ok(body) => (axum::http::StatusCode::OK, body),
                            Err(_) => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                        }
                    }
                });
                axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                    .await
                    .unwrap();
            });
    });
    requests
}

fn replacement(p: &TestPub, key_id: &str, recovery: bool) -> Value {
    let previous = current_declaration(p);
    let mut next = previous["publisher"].clone();
    next["seq"] = json!(1);
    next["prev_declaration"] = json!(declaration_hash(&previous));
    next["keys"] = json!([key_entry(key_id, &K2_SEED, "2026-08-09T00:00:00Z")]);
    let (signer, seed) = if recovery {
        ("r1", &R1_SEED)
    } else {
        ("k1", &K1_SEED)
    };
    wist_core::envelope::sign_envelope(
        &next,
        "publisher",
        signer,
        &wist_core::crypto::SigningKey::from_seed(seed),
    )
    .unwrap()
}

fn install(db: &Db, doc: &Value) {
    let key = &doc["publisher"]["keys"][0];
    let persist = if db.get_publisher("localhost").unwrap().is_some() {
        Db::update_publisher_declaration
    } else {
        Db::record_publisher_declaration
    };
    persist(
        db,
        "localhost",
        &serde_json::to_vec(doc).unwrap(),
        key["key_id"].as_str().unwrap(),
        key["public_key"].as_str().unwrap(),
        doc,
    )
    .unwrap();
    db.mark_declaration_fetched("localhost", NOW).unwrap();
}

fn stored(db: &Db) -> Value {
    serde_json::from_slice(&db.get_publisher_declaration("localhost").unwrap().unwrap()).unwrap()
}

#[test]
fn rotated_feed_retries_the_same_bytes_after_first_contact_or_cached_discovery() {
    for known in [false, true] {
        for key_id in ["k1", "k2"] {
            let (listener, host, client) = reserve_addr();
            let p = make_publisher_with_recovery(&host);
            let previous = current_declaration(&p);
            let next = replacement(&p, key_id, false);
            let id = add_delta_signed(
                &p,
                "https://localhost/a",
                "rotated",
                None,
                NOW,
                key_id,
                &K2_SEED,
            );
            write_feed_signed(&p, &host, std::slice::from_ref(&id), NOW, key_id, &K2_SEED);
            let requests = serve_sequence(
                listener,
                p.dir.path().into(),
                vec![response(&previous), response(&next)],
            );
            let data = tempfile::tempdir().unwrap();
            clave::init::run(&host, data.path()).unwrap();
            let path = data.path().join("clave.sqlite");
            let db = Db::open(&path).unwrap();
            if known {
                install(&db, &previous);
            }
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert_eq!(
                report.accepted,
                std::slice::from_ref(&id),
                "{known}/{key_id}: {report:?}"
            );
            assert!(report.rejected.is_empty());
            assert_eq!(report.noise, None);
            assert_eq!(stored(&db), next);
            assert_eq!(db.highest_accepted_declaration_seq(&host).unwrap(), Some(1));
            assert!(db.list_rejections(&host).unwrap().is_empty());
            assert_eq!(
                *requests.lock().unwrap(),
                [
                    format!("{PREFIX}publisher.json"),
                    format!("{PREFIX}feed.json"),
                    format!("{PREFIX}publisher.json"),
                    format!("{PREFIX}registry.json"),
                    format!("{PREFIX}deltas/{}.json", &id[7..]),
                    format!("{PREFIX}payloads/{}.json", &id[7..]),
                ]
            );
            drop(db);
            let db = Db::open(&path).unwrap();
            assert_eq!(stored(&db), next);
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert!(report.accepted.is_empty());
            assert_eq!(report.noise, Some("WIST2-E02"));
            assert!(db.is_delta_seen_for(&id, &host).unwrap());
        }
    }
}

#[test]
fn refresh_authenticates_recovery_and_queues_the_feed_deltas() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let next = replacement(&p, "k2", true);
    let id = add_delta_signed(
        &p,
        "https://localhost/a",
        "recovered",
        None,
        NOW,
        "k2",
        &K2_SEED,
    );
    write_feed_signed(&p, &host, std::slice::from_ref(&id), NOW, "k2", &K2_SEED);
    serve_sequence(
        listener,
        p.dir.path().into(),
        vec![response(&previous), response(&next)],
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.queued, [id]);
    assert!(report.accepted.is_empty());
    assert_eq!(report.noise, None);
    let window = db.get_recovery_window(&host).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&window.owner_declaration_json).unwrap(),
        next
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&window.prior_declaration_json).unwrap(),
        previous
    );
    drop(db);
    let db = Db::open(&path).unwrap();
    assert_eq!(stored(&db), next);
    assert!(db.get_recovery_window(&host).unwrap().is_some());
}

#[test]
fn unsuccessful_refresh_counts_one_feed_failure_without_installing_invalid_authority() {
    for failure in [
        "unchanged",
        "invalid_signature",
        "invalid_sequence",
        "invalid_fields",
        "unavailable",
        "non_json",
    ] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher_with_recovery(&host);
        let previous = current_declaration(&p);
        let mut next = replacement(&p, "k2", false);
        let refresh = match failure {
            "unchanged" => response(&previous),
            "invalid_signature" => {
                next["sig"]["value"] = json!(wist_core::crypto::b64u_encode(&[0; 64]));
                response(&next)
            }
            "invalid_sequence" => {
                next["publisher"]["seq"] = json!(0);
                response(&next)
            }
            "invalid_fields" => {
                next["publisher"]["extra"] = json!(true);
                response(&next)
            }
            "unavailable" => (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
            "non_json" => (axum::http::StatusCode::OK, b"invalid json".to_vec()),
            _ => unreachable!(),
        };
        let id = add_delta_signed(
            &p,
            "https://localhost/a",
            "rotated",
            None,
            NOW,
            "k2",
            &K2_SEED,
        );
        write_feed_signed(&p, &host, std::slice::from_ref(&id), NOW, "k2", &K2_SEED);
        let requests = serve_sequence(
            listener,
            p.dir.path().into(),
            vec![response(&previous), refresh],
        );
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert_eq!(report.noise, Some("WIST2-E04"), "{failure}: {report:?}");
        assert!(report.accepted.is_empty());
        assert!(report.queued.is_empty());
        assert_eq!(stored(&db), previous);
        assert_eq!(db.highest_accepted_declaration_seq(&host).unwrap(), Some(0));
        assert!(db.get_recovery_window(&host).unwrap().is_none());
        assert!(!db.is_delta_seen_for(&id, &host).unwrap());
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &id[7..]))
            .exists());
        assert_eq!(
            db.list_rejections(&host)
                .unwrap()
                .iter()
                .filter(|r| r.code == "WIST2-E04")
                .count(),
            1
        );
        assert_eq!(
            *requests.lock().unwrap(),
            [
                format!("{PREFIX}publisher.json"),
                format!("{PREFIX}feed.json"),
                format!("{PREFIX}publisher.json")
            ]
        );
    }
}

#[test]
fn exhausted_content_budget_allows_feed_refresh_and_resumes_after_restart() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let next = replacement(&p, "k2", false);
    let id = add_delta_signed(
        &p,
        "https://localhost/a",
        "rotated",
        None,
        NOW,
        "k2",
        &K2_SEED,
    );
    write_feed_signed(&p, &host, std::slice::from_ref(&id), NOW, "k2", &K2_SEED);
    let requests = serve_sequence(
        listener,
        p.dir.path().into(),
        vec![response(&previous), response(&next)],
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    db.set_param("ingest_budget_bytes_day", 1).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert!(report.suspended);
    assert_eq!(report.noise, None);
    assert!(report.accepted.is_empty());
    assert!(db.list_rejections(&host).unwrap().is_empty());
    assert_eq!(stored(&db), next);
    assert_eq!(
        *requests.lock().unwrap(),
        [
            format!("{PREFIX}publisher.json"),
            format!("{PREFIX}feed.json"),
            format!("{PREFIX}publisher.json")
        ]
    );
    drop(db);
    let db = Db::open(&path).unwrap();
    assert!(db.walk_suspended(&host).unwrap());
    db.set_param("ingest_budget_bytes_day", 1_073_741_824)
        .unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-10T14:00:00Z").unwrap();
    assert_eq!(report.accepted, [id]);
    assert!(!report.suspended);
    assert_eq!(report.noise, None);
    assert!(!db.walk_suspended(&host).unwrap());
}

#[test]
fn valid_refresh_does_not_authenticate_a_tampered_feed() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let next = replacement(&p, "k2", false);
    write_feed_signed(&p, &host, &[], NOW, "k2", &K2_SEED);
    let path = p.dir.path().join(".well-known/wist/feed.json");
    let mut feed: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    feed["feed"]["generated_at"] = json!("2026-08-09T14:00:01Z");
    std::fs::write(&path, serde_json::to_vec(&feed).unwrap()).unwrap();
    let requests = serve_sequence(
        listener,
        p.dir.path().into(),
        vec![response(&previous), response(&next)],
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.noise, Some("WIST2-E04"));
    assert_eq!(stored(&db), next);
    assert_eq!(db.list_rejections(&host).unwrap().len(), 1);
    assert_eq!(
        *requests.lock().unwrap(),
        [
            format!("{PREFIX}publisher.json"),
            format!("{PREFIX}feed.json"),
            format!("{PREFIX}publisher.json")
        ]
    );
}

#[test]
fn failed_refresh_persistence_rolls_back_authority_and_admission_state() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let next = replacement(&p, "k2", true);
    write_feed_signed(&p, &host, &[], NOW, "k2", &K2_SEED);
    serve_sequence(
        listener,
        p.dir.path().into(),
        vec![response(&previous), response(&next)],
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    install(&db, &previous);
    let pending = db.peek_pending_entries().unwrap().0.len();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_recovery BEFORE INSERT ON recovery_windows BEGIN SELECT RAISE(ABORT, 'recovery write unavailable'); END;").unwrap();
    let result = clave::ingest::run(&db, &client, data.path(), &host, NOW);
    assert!(result.is_err());
    assert_eq!(stored(&db), previous);
    assert_eq!(db.highest_accepted_declaration_seq(&host).unwrap(), Some(0));
    assert_eq!(db.peek_pending_entries().unwrap().0.len(), pending);
    assert!(db.get_recovery_window(&host).unwrap().is_none());
    assert!(db.list_rejections(&host).unwrap().is_empty());
    drop(db);
    let db = Db::open(&path).unwrap();
    assert_eq!(stored(&db), previous);
    assert_eq!(db.highest_accepted_declaration_seq(&host).unwrap(), Some(0));
    assert_eq!(db.peek_pending_entries().unwrap().0.len(), pending);
}

#[test]
fn page_retry_resets_after_restart_and_waits_for_declaration_inclusion() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let next = replacement(&p, "k2", false);
    let id = add_delta_signed(
        &p,
        "https://localhost/a",
        "rotated Page",
        None,
        NOW,
        "k2",
        &K2_SEED,
    );
    write_feed_page_signed(
        &p,
        &host,
        0,
        &[],
        "2026-08-09T12:30:00Z",
        None,
        "k2",
        &K2_SEED,
    );
    let page_path = p.dir.path().join(".well-known/wist/feed/0.json");
    let page = std::fs::read(&page_path).unwrap();
    let requests = serve_sequence(
        listener,
        p.dir.path().into(),
        vec![response(&previous), response(&next)],
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    install(&db, &previous);
    let signing = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(
        &db,
        data.path(),
        &signing,
        "2026-08-09T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second(),
    )
    .unwrap();
    drop(db);

    for (attempt, (key, seed)) in [("k1", &K1_SEED), ("k2", &K2_SEED)].into_iter().enumerate() {
        let feed = json!({"wist_version": "1.0.0", "domain": host, "generated_at": NOW,
            "deltas": [id], "next": page_url(&host, 0)});
        let envelope = wist_core::envelope::sign_envelope(
            &feed,
            "feed",
            key,
            &wist_core::crypto::SigningKey::from_seed(seed),
        )
        .unwrap();
        std::fs::write(
            p.dir.path().join(".well-known/wist/feed.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        let db = Db::open(&path).unwrap();
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert_eq!(report.noise, Some("WIST2-E04"));
        assert!(!report.suspended);
        assert!(report.accepted.is_empty());
        assert!(report.queued.is_empty());
        assert!(!db.is_delta_seen_for(&id, &host).unwrap());
        assert_eq!(stored(&db), next);
        assert_eq!(db.list_rejections(&host).unwrap().len(), attempt + 1);
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|path| **path == format!("{PREFIX}publisher.json"))
                .count(),
            2 * (attempt + 1)
        );
    }

    let db = Db::open(&path).unwrap();
    clave::seal::run(
        &db,
        data.path(),
        &signing,
        "2026-08-09T15:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second(),
    )
    .unwrap();
    drop(db);
    let db = Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T15:00:01Z").unwrap();
    assert_eq!(report.noise, None);
    assert_eq!(report.accepted, [id]);
    assert_eq!(db.list_rejections(&host).unwrap().len(), 2);
    assert_eq!(std::fs::read(page_path).unwrap(), page);
    let paths = requests.lock().unwrap();
    assert_eq!(
        paths
            .iter()
            .filter(|path| **path == format!("{PREFIX}publisher.json"))
            .count(),
        5
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| **path == format!("{PREFIX}feed/0.json"))
            .count(),
        3
    );
}

#[test]
fn signed_transport_vectors_refresh_authority_and_preserve_content_budgets() {
    let root = std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        });
    let vector: Value = serde_json::from_slice(
        &std::fs::read(root.join("vectors/wist2/declaration-refresh.json")).unwrap(),
    )
    .unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let (listener, host, client) = reserve_addr();
        let served = tempfile::tempdir().unwrap();
        let directory = served.path().join(".well-known/wist");
        std::fs::create_dir_all(directory.join("deltas")).unwrap();
        std::fs::create_dir_all(directory.join("payloads")).unwrap();
        let feed = wist_core::jcs::canonicalize(&case["feed"]).unwrap();
        std::fs::write(directory.join("feed.json"), &feed).unwrap();
        let page_bytes = if let Some(page) = case.get("page") {
            std::fs::create_dir_all(directory.join("feed")).unwrap();
            let bytes = wist_core::jcs::canonicalize(page).unwrap();
            std::fs::write(directory.join("feed/0.json"), &bytes).unwrap();
            bytes.len()
        } else {
            0
        };
        let mut delta_bytes = 0;
        for entry in case["deltas"].as_array().unwrap() {
            let hex = &entry["id"].as_str().unwrap()[7..];
            let delta = wist_core::jcs::canonicalize(&entry["envelope"]).unwrap();
            delta_bytes += delta.len();
            std::fs::write(directory.join(format!("deltas/{hex}.json")), delta).unwrap();
            std::fs::write(
                directory.join(format!("payloads/{hex}.json")),
                wist_core::jcs::canonicalize(&vector["payload"]).unwrap(),
            )
            .unwrap();
        }
        let mut responses = vec![response(&case["initial"])];
        responses.extend(case["responses"].as_array().unwrap().iter().map(|doc| {
            if doc.is_null() {
                (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new())
            } else {
                response(doc)
            }
        }));
        let requests = serve_sequence(listener, served.path().into(), responses);
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        if let Some(sealed) = case["sealed"].as_array() {
            let signing = clave::keys::load(&data.path().join("keys/seed")).unwrap();
            for entry in sealed {
                install(&db, &entry["envelope"]);
                clave::seal::run(
                    &db,
                    data.path(),
                    &signing,
                    entry["at"]
                        .as_str()
                        .unwrap()
                        .parse::<jiff::Timestamp>()
                        .unwrap()
                        .as_second(),
                )
                .unwrap();
            }
        }
        if case["cached"].as_bool().unwrap() {
            install(&db, &case["initial"]);
        }
        let budget = match case["content_budget"].as_str() {
            Some("feed") => Some(feed.len() as i64),
            Some("feed and deltas") => Some((feed.len() + delta_bytes) as i64),
            Some("feed and page") => Some((feed.len() + page_bytes) as i64),
            _ => case["content_budget"].as_i64(),
        };
        if let Some(budget) = budget {
            db.set_param("ingest_budget_bytes_day", budget.max(1))
                .unwrap();
            if budget == 0 {
                db.add_ingest_bytes(&host, &vector["now"].as_str().unwrap()[..10], 1)
                    .unwrap();
            }
        }
        let report = clave::ingest::run(
            &db,
            &client,
            data.path(),
            &host,
            vector["now"].as_str().unwrap(),
        )
        .unwrap();
        let expected = &case["expected"];
        assert_eq!(
            json!(report.accepted),
            expected["accepted"],
            "{}: {report:?}",
            case["name"]
        );
        assert_eq!(
            json!(report.rejected),
            expected["rejected"],
            "{}: {report:?}",
            case["name"]
        );
        assert_eq!(
            json!(report.suspended),
            expected["suspended"],
            "{}: {report:?}",
            case["name"]
        );
        assert_eq!(
            json!(report.noise),
            expected["noise"],
            "{}: {report:?}",
            case["name"]
        );
        if case.get("page").is_some() {
            assert_eq!(
                requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|path| **path == format!("{PREFIX}feed/0.json"))
                    .count(),
                1,
                "{}",
                case["name"],
            );
            assert_eq!(
                db.list_rejections(&host)
                    .unwrap()
                    .iter()
                    .filter(|rejection| rejection.code == "WIST2-E04")
                    .count(),
                usize::from(report.noise == Some("WIST2-E04")),
                "{}",
                case["name"],
            );
        }
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|p| **p == format!("{PREFIX}publisher.json"))
                .count(),
            expected["declaration_requests"].as_u64().unwrap() as usize,
            "{}",
            case["name"],
        );
        for entry in case["deltas"].as_array().unwrap() {
            let id = entry["id"].as_str().unwrap();
            let accepted = report.accepted.iter().any(|accepted| accepted == id);
            assert_eq!(db.is_delta_seen_for(id, &host).unwrap(), accepted);
            assert_eq!(
                data.path()
                    .join(format!("payloads/{}.json", &id[7..]))
                    .exists(),
                accepted
            );
        }
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.walk_suspended(&host).unwrap(), report.suspended);
        for id in report.accepted {
            assert!(db.is_delta_seen_for(&id, &host).unwrap());
        }
    }
}

#[test]
fn unsuccessful_delta_attempt_resets_after_restart_on_a_later_pull() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let next = replacement(&p, "k2", false);
    let id = add_delta_signed(&p, "https://localhost/a", "body", None, NOW, "k2", &K2_SEED);
    write_feed(&p, &host, std::slice::from_ref(&id), NOW);
    let requests = serve_sequence(
        listener,
        p.dir.path().into(),
        vec![
            response(&previous),
            response(&previous),
            response(&previous),
            response(&next),
        ],
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.rejected, [(id.clone(), "WIST1-E02".into())]);
    assert_eq!(report.noise, None);
    assert!(!db.is_delta_seen_for(&id, &host).unwrap());
    drop(db);
    let db = Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T14:01:00Z").unwrap();
    assert_eq!(report.accepted, [id]);
    assert_eq!(stored(&db), next);
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|p| **p == format!("{PREFIX}publisher.json"))
            .count(),
        4
    );
}

#[test]
fn delta_refresh_opens_recovery_but_a_follower_cannot_replace_frozen_sources() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let owner = replacement(&p, "k2", true);
    let mut body = owner["publisher"].clone();
    body["seq"] = json!(2);
    body["prev_declaration"] = json!(declaration_hash(&owner));
    body["keys"] = json!([key_entry("k3", &X1_SEED, "2026-08-09T00:00:00Z")]);
    let follower = wist_core::envelope::sign_envelope(
        &body,
        "publisher",
        "k2",
        &wist_core::crypto::SigningKey::from_seed(&K2_SEED),
    )
    .unwrap();
    let first = add_delta_signed(
        &p,
        "https://localhost/a",
        "owner",
        None,
        NOW,
        "k2",
        &K2_SEED,
    );
    write_feed(&p, &host, std::slice::from_ref(&first), NOW);
    let requests = serve_sequence(
        listener,
        p.dir.path().into(),
        vec![
            response(&previous),
            response(&owner),
            response(&owner),
            response(&follower),
        ],
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.queued, [first]);
    assert!(report.accepted.is_empty());
    let window = db.get_recovery_window(&host).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&window.owner_declaration_json).unwrap(),
        owner
    );
    let second = add_delta_signed(
        &p,
        "https://localhost/b",
        "follower",
        None,
        NOW,
        "k3",
        &X1_SEED,
    );
    write_feed_signed(
        &p,
        &host,
        std::slice::from_ref(&second),
        NOW,
        "k2",
        &K2_SEED,
    );
    drop(db);
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.rejected, [(second.clone(), "WIST1-E02".into())]);
    assert_eq!(report.noise, None);
    assert!(report.queued.is_empty());
    assert!(report.accepted.is_empty());
    assert_eq!(stored(&db), follower);
    assert!(!db.is_delta_seen_for(&second, &host).unwrap());
    let window = db.get_recovery_window(&host).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&window.owner_declaration_json).unwrap(),
        owner
    );
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|p| **p == format!("{PREFIX}publisher.json"))
            .count(),
        4
    );
}

#[test]
fn settlement_after_payload_fetch_retries_before_final_delta_admission() {
    for repaired in [false, true] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher_with_recovery(&host);
        let previous = current_declaration(&p);
        let owner = replacement(&p, "k2", true);
        let mut body = owner["publisher"].clone();
        body["seq"] = json!(2);
        body["prev_declaration"] = json!(declaration_hash(&owner));
        body["keys"] = json!([
            key_entry("k1", &K1_SEED, "2026-08-09T00:00:00Z"),
            key_entry("k2", &K2_SEED, "2026-08-09T00:00:00Z"),
        ]);
        let restored = wist_core::envelope::sign_envelope(
            &body,
            "publisher",
            "k2",
            &wist_core::crypto::SigningKey::from_seed(&K2_SEED),
        )
        .unwrap();
        let requests = serve_sequence(
            listener,
            p.dir.path().into(),
            vec![
                response(&previous),
                response(&owner),
                response(&owner),
                response(if repaired { &restored } else { &owner }),
            ],
        );
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        db.set_param("block_cadence_seconds", 1).unwrap();
        let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        for (at, key_id, seed) in [
            ("2026-08-09T12:00:00Z", "k1", &K1_SEED),
            ("2026-08-09T13:00:00Z", "k2", &K2_SEED),
        ] {
            write_feed_signed(&p, &host, &[], at, key_id, seed);
            clave::ingest::run(&db, &client, data.path(), &host, at).unwrap();
            clave::seal::run(
                &db,
                data.path(),
                &key,
                at.parse::<jiff::Timestamp>().unwrap().as_second(),
            )
            .unwrap();
        }
        let before = "2026-08-16T12:59:59Z";
        let deadline = "2026-08-16T13:00:00Z";
        let id = add_delta_signed(
            &p,
            "https://localhost/a",
            "body",
            None,
            before,
            "k1",
            &K1_SEED,
        );
        write_feed_signed(&p, &host, std::slice::from_ref(&id), before, "k2", &K2_SEED);
        let crossed = std::cell::Cell::new(false);
        let report =
            clave::ingest::run_with_clock(&db, &client, data.path(), &host, before, || {
                if requests
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|p| p.contains("/payloads/"))
                {
                    crossed.set(true);
                }
                if crossed.get() { deadline } else { before }
                    .parse()
                    .unwrap()
            })
            .unwrap();
        assert!(crossed.get());
        assert!(db.get_recovery_window(&host).unwrap().is_none());
        assert!(report.queued.is_empty());
        assert_eq!(report.noise, None);
        if repaired {
            assert_eq!(report.accepted, std::slice::from_ref(&id));
            assert!(report.rejected.is_empty());
            assert_eq!(stored(&db), restored);
        } else {
            assert!(report.accepted.is_empty());
            assert_eq!(report.rejected, [(id.clone(), "WIST1-E02".into())]);
            assert_eq!(stored(&db), owner);
        }
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|p| **p == format!("{PREFIX}publisher.json"))
                .count(),
            4
        );
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|p| p.contains("/payloads/"))
                .count(),
            1
        );
        assert_eq!(
            data.path()
                .join(format!("payloads/{}.json", &id[7..]))
                .exists(),
            repaired
        );
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.is_delta_seen_for(&id, &host).unwrap(), repaired);
    }
}

#[test]
fn delta_clock_stays_frozen_through_refresh_and_resets_after_restart() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let next = replacement(&p, "k2", false);
    let id = add_delta_signed(
        &p,
        "https://localhost/future",
        "future",
        None,
        "2026-08-09T14:10:00.00000000000000000001Z",
        "k2",
        &K2_SEED,
    );
    write_feed_signed(&p, &host, std::slice::from_ref(&id), NOW, "k1", &K1_SEED);
    let requests = serve_sequence(
        listener,
        p.dir.path().into(),
        vec![response(&previous), response(&next)],
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run_with_clock(&db, &client, data.path(), &host, NOW, || {
        let refreshed = requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with("publisher.json"))
            .count()
            >= 2;
        if refreshed {
            "2026-08-09T14:00:01Z"
        } else {
            NOW
        }
        .parse()
        .unwrap()
    })
    .unwrap();
    assert!(report.accepted.is_empty());
    assert_eq!(report.rejected, [(id.clone(), "WIST1-E06".into())]);
    assert_eq!(stored(&db), next);
    assert!(!db.is_delta_seen(&id).unwrap());
    assert!(!requests
        .lock()
        .unwrap()
        .iter()
        .any(|path| path.contains("/payloads/")));
    drop(db);
    let db = Db::open(&path).unwrap();
    write_feed_signed(
        &p,
        &host,
        std::slice::from_ref(&id),
        "2026-08-09T14:00:01Z",
        "k2",
        &K2_SEED,
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T14:00:01Z").unwrap();
    assert_eq!(report.accepted, [id]);
    assert!(report.rejected.is_empty());
}
