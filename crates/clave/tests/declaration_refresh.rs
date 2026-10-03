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
