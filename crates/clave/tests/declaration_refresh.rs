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

fn replacement(p: &TestPub, recovery: bool) -> Value {
    let previous = current_declaration(p);
    let mut next = previous["publisher"].clone();
    next["seq"] = json!(1);
    next["prev_declaration"] = json!(declaration_hash(&previous));
    next["keys"] = json!([key_entry(&K2_SEED, "2026-08-09T00:00:00Z")]);
    let seed = if recovery { &R1_SEED } else { &K1_SEED };
    let signer = &kid(seed);
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
        key["kid"].as_str().unwrap(),
        key["x"].as_str().unwrap(),
        doc,
    )
    .unwrap();
}

fn stored(db: &Db) -> Value {
    serde_json::from_slice(&db.get_publisher_declaration("localhost").unwrap().unwrap()).unwrap()
}

#[test]
fn failed_refresh_persistence_rolls_back_authority_and_admission_state() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let previous = current_declaration(&p);
    let next = replacement(&p, true);
    serve_sequence(listener, p.dir.path().into(), vec![response(&next)]);
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

fn jcs(value: &Value) -> Vec<u8> {
    wist_core::jcs::canonicalize(value).unwrap()
}

fn write_wk(root: &std::path::Path, relative: &str, octets: Option<Vec<u8>>) {
    let path = root.join(".well-known/wist").join(relative);
    match octets {
        Some(octets) => {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, octets).unwrap();
        }
        None => {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn serve_pull(root: &std::path::Path, pull: &Value) -> i64 {
    write_wk(
        root,
        "publisher.json",
        (!pull["declaration"].is_null()).then(|| jcs(&pull["declaration"])),
    );
    let catalog = jcs(&pull["catalog"]);
    write_wk(
        root,
        "collections/default/catalog.json",
        Some(catalog.clone()),
    );
    let tree = jcs(&json!({"items": []}));
    let hex = &pull["catalog"]["catalog"]["tree"].as_str().unwrap()["sha256:".len()..];
    write_wk(
        root,
        &format!("collections/default/tree/{hex}"),
        Some(tree.clone()),
    );
    let feed = jcs(&pull["label_feed"]);
    write_wk(root, "label-feed.json", Some(feed.clone()));
    let mut labels = 0;
    for label in pull["labels"].as_array().unwrap() {
        let inner = label.get("label").unwrap_or(&label["dispute"]);
        let id = wist_core::label::label_id(inner).unwrap();
        let octets = jcs(label);
        labels += octets.len() as i64;
        write_wk(root, &format!("labels/{}.json", &id[7..]), Some(octets));
    }
    write_wk(root, "label-feed/0.json", pull.get("page").map(jcs));
    let mut budget = 0;
    for object in pull["budget"].as_array().into_iter().flatten() {
        budget += match object.as_str().unwrap() {
            "catalog" => catalog.len() as i64,
            "tree" => tree.len() as i64,
            "label_feed" => feed.len() as i64,
            "labels" => labels,
            other => panic!("unknown budget object {other}"),
        };
    }
    if pull["budget"].is_null() {
        -1
    } else {
        budget
    }
}

fn assert_refresh_pull(
    name: &str,
    db: &Db,
    host: &str,
    report: &clave::ingest::IngestReport,
    requests: &[String],
    expected: &Value,
) {
    let requested = |path: &str| {
        requests
            .iter()
            .filter(|request| request.as_str() == format!("{PREFIX}{path}"))
            .count()
    };
    if let Some(count) = expected.get("declaration_requests") {
        assert_eq!(
            requested("publisher.json") as u64,
            count.as_u64().unwrap(),
            "{name}: Declaration requests"
        );
    }
    match expected["declaration"].as_str().unwrap() {
        "accepted" => assert_ne!(
            report.ended.as_deref(),
            Some("WIST2-E01"),
            "{name}: {report:?}"
        ),
        _ => assert_eq!(
            report.ended.as_deref(),
            expected["code"].as_str(),
            "{name}: {report:?}"
        ),
    }
    let catalog_requested = requested("collections/default/catalog.json") > 0;
    match expected["catalog"].as_str().unwrap() {
        "accepted" => assert_eq!(report.accepted.len(), 1, "{name}: {report:?}"),
        "idempotent" => assert!(
            catalog_requested && report.accepted.is_empty() && report.rejected.is_empty(),
            "{name}: {report:?}"
        ),
        "suspended" => assert!(
            report.suspended && report.accepted.is_empty(),
            "{name}: {report:?}"
        ),
        "not_pulled" => assert!(!catalog_requested, "{name}"),
        code => assert!(
            report
                .rejected
                .iter()
                .any(|(id, got)| id.starts_with("default/") && got == code),
            "{name}: {report:?}"
        ),
    }
    let feed_requested = requested("label-feed.json") > 0;
    match expected["label_walk"].as_str().unwrap() {
        "pulled" => assert!(feed_requested, "{name}"),
        "waits" => assert!(!feed_requested && !report.suspended, "{name}"),
        "suspended" => assert!(feed_requested && report.suspended, "{name}"),
        _ => assert!(!feed_requested, "{name}"),
    }
    if let Some(labels) = expected.get("labels_accepted") {
        assert_eq!(&json!(report.labels), labels, "{name}");
    }
    assert_eq!(
        report.suspended,
        expected["suspended"].as_bool().unwrap(),
        "{name}: {report:?}"
    );
    if let Some(page) = expected.get("page").and_then(Value::as_str) {
        let refused = db
            .list_rejections(host)
            .unwrap()
            .iter()
            .any(|rejection| rejection.code == "WIST2-E04");
        assert_eq!(refused, page == "WIST2-E04", "{name}: page {page}");
        assert_eq!(requested("label-feed/0.json"), 1, "{name}: page fetched");
    }
}

#[test]
fn every_declaration_refresh_case_replays_over_loopback() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist2/declaration-refresh.json")).unwrap(),
    )
    .unwrap();
    let clock = vector["clock"].as_str().unwrap();
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 22);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let (listener, host, client) = reserve_addr();
        assert_eq!(host, vector["domain"]);
        let served = tempfile::tempdir().unwrap();
        let requests = serve_recording(listener, served.path().into());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
        let signing = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        for entry in case["sealed"].as_array().into_iter().flatten() {
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
        for (pull, expected) in case["pulls"]
            .as_array()
            .unwrap()
            .iter()
            .zip(case["expected"].as_array().unwrap())
        {
            let budget = serve_pull(served.path(), pull);
            let day = &clock[..10];
            let spent = db.ingest_bytes(&host, day).unwrap();
            let budget = if budget < 0 { 1 << 30 } else { spent + budget };
            db.set_param("ingest_budget_bytes_day", budget.max(1))
                .unwrap();
            if budget == 0 {
                db.add_ingest_bytes(&host, day, 1).unwrap();
            }
            requests.lock().unwrap().clear();
            let report = clave::ingest::run(&db, &client, data.path(), &host, clock).unwrap();
            let requests = requests.lock().unwrap().clone();
            assert_refresh_pull(name, &db, &host, &report, &requests, expected);
        }
    }
}
