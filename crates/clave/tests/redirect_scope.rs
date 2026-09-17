mod common;

use axum::http::{HeaderMap, StatusCode, Uri};
use common::{
    add_delta, current_declaration, declaration_hash, make_publisher, write_declaration, write_feed,
};
use std::sync::{Arc, Mutex};

const FEED: &str = "/.well-known/wist/feed.json";

/// Serves the publisher directory to `localhost` and `www.localhost`,
/// answering the Feed request on `localhost` with a redirect to
/// `www.localhost`, and records every request with its host.
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
