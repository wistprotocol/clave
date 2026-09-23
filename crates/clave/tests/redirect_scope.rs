mod common;

use axum::http::{HeaderMap, StatusCode, Uri};
use common::{
    add_delta, add_delta_signed, current_declaration, declaration_hash, key_entry, kid,
    make_publisher, make_publisher_with_recovery, write_declaration, write_feed, write_feed_signed,
    K1_SEED, K2_SEED, R1_SEED, X1_SEED,
};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const FEED: &str = "/.well-known/wist/feed.json";
const PUBLISHER: &str = "/.well-known/wist/publisher.json";

fn serve_redirecting(
    listener: std::net::TcpListener,
    dir: std::path::PathBuf,
    port: u16,
) -> Arc<Mutex<Vec<String>>> {
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = requests.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |headers: HeaderMap, uri: Uri| {
                let host = headers
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                recorded
                    .lock()
                    .unwrap()
                    .push(format!("{host}{}", uri.path()));
                let redirect = uri.path() == FEED && host.starts_with("localhost");
                let body = std::fs::read(dir.join(uri.path().trim_start_matches('/')));
                async move {
                    if redirect {
                        return (
                            StatusCode::FOUND,
                            [("Location", format!("http://www.localhost:{port}{FEED}"))],
                            Vec::new(),
                        );
                    }
                    let location = [("Location", String::new())];
                    match body {
                        Ok(bytes) => (StatusCode::OK, location, bytes),
                        Err(_) => (StatusCode::NOT_FOUND, location, Vec::new()),
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

fn serve_retry_redirect(
    listener: std::net::TcpListener,
    dir: std::path::PathBuf,
    port: u16,
    declarations: Vec<Value>,
) -> Arc<Mutex<Vec<String>>> {
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = requests.clone();
    let pending = Arc::new(Mutex::new(VecDeque::from(declarations)));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |headers: HeaderMap, uri: Uri| {
                let host = headers
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let mut log = recorded.lock().unwrap();
                log.push(format!("{host}{}", uri.path()));
                let payloaded = log.iter().any(|request| request.contains("/payloads/"));
                drop(log);
                let declaration = uri.path() == PUBLISHER;
                let redirect = declaration && host.starts_with("localhost") && payloaded;
                let body = if declaration && !redirect {
                    let mut pending = pending.lock().unwrap();
                    let doc = if pending.len() > 1 {
                        pending.pop_front().unwrap()
                    } else {
                        pending.front().unwrap().clone()
                    };
                    Ok(serde_json::to_vec(&doc).unwrap())
                } else {
                    std::fs::read(dir.join(uri.path().trim_start_matches('/')))
                };
                async move {
                    if redirect {
                        return (
                            StatusCode::FOUND,
                            [(
                                "Location",
                                format!("http://www.localhost:{port}{PUBLISHER}"),
                            )],
                            Vec::new(),
                        );
                    }
                    let location = [("Location", String::new())];
                    match body {
                        Ok(bytes) => (StatusCode::OK, location, bytes),
                        Err(_) => (StatusCode::NOT_FOUND, location, Vec::new()),
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

fn sign_declaration(body: &Value, seed: &[u8; 32]) -> Value {
    wist_core::envelope::sign_envelope(
        body,
        "publisher",
        &kid(seed),
        &wist_core::crypto::SigningKey::from_seed(seed),
    )
    .unwrap()
}

fn redeclare(p: &common::TestPub, seq: u64, scope: Option<&[&str]>) -> serde_json::Value {
    let previous = current_declaration(p);
    let mut next = previous["publisher"].clone();
    next["seq"] = serde_json::json!(seq);
    next["prev_declaration"] = serde_json::json!(declaration_hash(&previous));
    match scope {
        Some(scope) => next["subdomain_scope"] = serde_json::json!(scope),
        None => {
            next.as_object_mut().unwrap().remove("subdomain_scope");
        }
    }
    write_declaration(p, &next, &[1u8; 32]);
    current_declaration(p)
}

#[test]
fn a_redirect_is_authorized_by_the_declaration_current_at_each_request() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve("localhost", addr)
            .resolve("www.localhost", addr),
    );
    let host = "localhost";
    let p = make_publisher(host);
    let id1 = add_delta(&p, "https://localhost/a", "first content", None);
    write_feed(&p, host, std::slice::from_ref(&id1), "2026-08-09T10:00:00Z");
    let requests = serve_redirecting(listener, p.dir.path().to_path_buf(), addr.port());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let first = clave::ingest::run(&db, &client, tmp.path(), host, "2026-08-09T12:00:05Z").unwrap();
    assert!(first.accepted.is_empty());
    assert!(db
        .list_rejections(host)
        .unwrap()
        .iter()
        .any(|r| r.code == "WIST2-E01"));
    assert!(
        !requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.starts_with("www.localhost")),
        "before any accepted Declaration the redirect stays on the requested host"
    );

    let granted = redeclare(&p, 1, Some(&["www.localhost"]));
    write_feed(&p, host, std::slice::from_ref(&id1), "2026-08-09T12:05:00Z");
    let second =
        clave::ingest::run(&db, &client, tmp.path(), host, "2026-08-09T12:10:05Z").unwrap();
    assert_eq!(second.accepted, vec![id1.clone()]);
    let stored: serde_json::Value =
        serde_json::from_slice(&db.get_publisher_declaration(host).unwrap().unwrap()).unwrap();
    assert_eq!(stored, granted);
    assert!(requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r == &format!("www.localhost:{}{FEED}", addr.port())));

    redeclare(&p, 2, None);
    let id2 = add_delta(&p, "https://localhost/a", "second content", Some(&id1));
    write_feed(
        &p,
        host,
        &[id1.clone(), id2.clone()],
        "2026-08-09T12:15:00Z",
    );
    let before = requests.lock().unwrap().len();
    let third = clave::ingest::run(&db, &client, tmp.path(), host, "2026-08-09T12:20:05Z").unwrap();
    assert!(third.accepted.is_empty());
    let rejections = db.list_rejections(host).unwrap();
    assert_eq!(rejections[0].code, "WIST2-E01");
    assert!(
        !requests.lock().unwrap()[before..]
            .iter()
            .any(|r| r.starts_with("www.localhost")),
        "a scope the replacement withdrew no longer authorizes the redirect"
    );
}

#[test]
fn a_delta_declaration_retry_uses_the_scope_in_force_when_its_request_is_issued() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve("localhost", addr)
            .resolve("www.localhost", addr),
    );
    let host = "localhost";
    let p = make_publisher_with_recovery(host);
    let prior = current_declaration(&p);

    let mut body = prior["publisher"].clone();
    body["seq"] = json!(1);
    body["prev_declaration"] = json!(declaration_hash(&prior));
    body["keys"] = json!([key_entry(&K2_SEED, "2026-08-09T00:00:00Z")]);
    body["subdomain_scope"] = json!(["www.localhost"]);
    let owner = sign_declaration(&body, &R1_SEED);

    let mut body = owner["publisher"].clone();
    body["seq"] = json!(2);
    body["prev_declaration"] = json!(declaration_hash(&owner));
    body["keys"] = json!([key_entry(&X1_SEED, "2026-08-09T00:00:00Z")]);
    body.as_object_mut().unwrap().remove("subdomain_scope");
    let unscoped = sign_declaration(&body, &X1_SEED);

    let mut body = owner["publisher"].clone();
    body["seq"] = json!(3);
    body["prev_declaration"] = json!(declaration_hash(&owner));
    body["keys"] = json!([
        key_entry(&K1_SEED, "2026-08-01T00:00:00Z"),
        key_entry(&K2_SEED, "2026-08-09T00:00:00Z")
    ]);
    let restored = sign_declaration(&body, &K2_SEED);

    let requests = serve_retry_redirect(
        listener,
        p.dir.path().to_path_buf(),
        addr.port(),
        vec![prior, owner, unscoped.clone(), restored.clone()],
    );

    let data = tempfile::tempdir().unwrap();
    clave::init::run(host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let signing = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    for (at, seed) in [
        ("2026-08-09T12:00:00Z", &K1_SEED),
        ("2026-08-09T13:00:00Z", &K2_SEED),
    ] {
        write_feed_signed(&p, host, &[], at, seed);
        clave::ingest::run(&db, &client, data.path(), host, at).unwrap();
        clave::seal::run(
            &db,
            data.path(),
            &signing,
            at.parse::<jiff::Timestamp>().unwrap().as_second(),
        )
        .unwrap();
    }
    assert!(db
        .get_recovery_window(host)
        .unwrap()
        .is_some_and(|window| window.opened_epoch.is_some()));

    let before = "2026-08-16T12:59:59Z";
    let deadline = "2026-08-16T13:00:00Z";
    let id = add_delta_signed(&p, "https://localhost/a", "body", None, before, &K1_SEED);
    write_feed_signed(&p, host, std::slice::from_ref(&id), before, &X1_SEED);
    let crossed = std::cell::Cell::new(false);
    let report = clave::ingest::run_with_clock(&db, &client, data.path(), host, before, || {
        if requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.contains("/payloads/"))
        {
            crossed.set(true);
        }
        if crossed.get() { deadline } else { before }
            .parse()
            .unwrap()
    })
    .unwrap();

    assert!(crossed.get());
    let stored: Value =
        serde_json::from_slice(&db.get_publisher_declaration(host).unwrap().unwrap()).unwrap();
    assert!(
        db.get_recovery_window(host).unwrap().is_none(),
        "the settlement closed the window between the retry's scope and its request"
    );
    assert_ne!(
        stored, unscoped,
        "the settlement replaced the Declaration the retry would have read its scope from"
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| *request == format!("www.localhost:{}{PUBLISHER}", addr.port())),
        "the retry follows the redirect its scope authorizes at the instant it is issued"
    );
    assert_eq!(report.accepted, [id], "{report:?}");
    assert!(report.rejected.is_empty(), "{report:?}");
    assert_eq!(report.noise, None);
    assert_eq!(stored, restored);
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| **request == format!("localhost{PUBLISHER}"))
            .count(),
        4
    );
}
