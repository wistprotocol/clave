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
    db.record_publisher_declaration(
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
fn exhausted_refresh_budget_suspends_without_noise_and_resumes_after_restart() {
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
    assert_eq!(stored(&db), previous);
    assert_eq!(
        *requests.lock().unwrap(),
        [
            format!("{PREFIX}publisher.json"),
            format!("{PREFIX}feed.json")
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
