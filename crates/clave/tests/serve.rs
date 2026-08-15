mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn spawn_server(data_dir: &Path) -> String {
    let bind = free_addr();
    let data_dir = data_dir.to_path_buf();
    let db_path = data_dir.join("clave.sqlite");
    std::thread::spawn(move || {
        clave::serve::run(data_dir, db_path, bind, true).unwrap();
    });
    let addr = format!("http://{bind}");
    let client = reqwest::blocking::Client::new();
    for _ in 0..200 {
        if client
            .get(format!("{addr}/status/readiness-probe"))
            .send()
            .is_ok()
        {
            return addr;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("server at {addr} did not become ready in time");
}

#[test]
fn ingest_endpoint_and_status_and_static() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    std::fs::write(tmp.path().join("log/checkpoint.json"), b"{}").unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let r = c
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": "127.0.0.1:9"}))
        .send()
        .unwrap();
    assert_eq!(r.status(), 202);
    let r = c
        .post(format!("{addr}/ingest"))
        .body("notjson")
        .header("content-type", "application/json")
        .send()
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = c
        .get(format!("{addr}/status/unknown.example"))
        .send()
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = c.get(format!("{addr}/log/checkpoint.json")).send().unwrap();
    assert_eq!(r.status(), 200);
}

#[test]
fn serve_exposes_only_public_subtrees() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    std::fs::write(tmp.path().join("log/checkpoint.json"), b"{}").unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();

    let r = c.get(format!("{addr}/keys/seed")).send().unwrap();
    assert_eq!(r.status(), 404, "private signing seed must not be served");

    let r = c.get(format!("{addr}/clave.sqlite")).send().unwrap();
    assert_eq!(r.status(), 404, "aggregator database must not be served");

    let r = c.get(format!("{addr}/log/checkpoint.json")).send().unwrap();
    assert_eq!(r.status(), 200);

    let r = c.get(format!("{addr}/anchor.json")).send().unwrap();
    assert_eq!(r.status(), 200);
}

#[test]
fn ingest_rejects_non_bare_authority_host() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();

    for bad in [
        "example.com/../../etc/passwd",
        "trusted.example@evil.example",
        "https://example.com",
        "example.com#frag",
        "example.com?x=1",
    ] {
        let r = c
            .post(format!("{addr}/ingest"))
            .json(&serde_json::json!({"host": bad}))
            .send()
            .unwrap();
        assert_eq!(r.status(), 400, "expected 400 for host {bad:?}");
    }
}

#[test]
fn ingest_rejects_unknown_fields() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let r = c
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": "127.0.0.1:9", "extra": true}))
        .send()
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[test]
fn status_reports_last_pull_and_quota_after_ingest() {
    let (listener, host) = reserve_addr();
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
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();

    let r = c
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": host}))
        .send()
        .unwrap();
    assert_eq!(r.status(), 202);

    let mut body = serde_json::Value::Null;
    for _ in 0..200 {
        let resp = c.get(format!("{addr}/status/{host}")).send().unwrap();
        if resp.status() == 200 {
            body = resp.json().unwrap();
            if body["last_pull_at"] != serde_json::Value::Null {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(body["wist_version"], "1.0.0");
    assert_eq!(body["domain"], host);
    assert_eq!(body["quota_remaining"], 1100);
    assert_eq!(body["state"], "active");
    assert_eq!(body["rejections"].as_array().unwrap().len(), 0);
}

#[test]
fn ingest_ping_over_quota_gets_429_with_retry_after() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    {
        let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.set_param("quota_base", 0).unwrap();
        db.set_param("quota_slope", 0).unwrap();
    }
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let r = c
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": "127.0.0.1:9"}))
        .send()
        .unwrap();
    assert_eq!(r.status(), 429);
    let retry_after: i64 = r
        .headers()
        .get("retry-after")
        .expect("429 must carry Retry-After")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry_after > 0 && retry_after <= 86400);
}

#[test]
fn noise_ping_decrements_quota() {
    let (listener, host) = reserve_addr();
    let empty = tempfile::tempdir().unwrap();
    serve_static(listener, empty.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let r = c
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": host}))
        .send()
        .unwrap();
    assert_eq!(r.status(), 202);
    let day = {
        let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        let mut n = 0;
        for _ in 0..200 {
            n = db
                .noise_ping_count(&host, &jiff::Timestamp::now().to_string()[..10])
                .unwrap();
            if n > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        n
    };
    assert_eq!(
        day, 1,
        "E04 first-contact failure must count as one noise ping"
    );
}

#[test]
fn status_reports_real_quota_remaining() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    {
        let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.insert_publisher("example.com", b"{}", "k1", "pk")
            .unwrap();
        db.set_param("quota_base", 50).unwrap();
        db.set_param("quota_slope", 0).unwrap();
        let day = &jiff::Timestamp::now().to_string()[..10];
        db.bump_noise_ping("example.com", day).unwrap();
        db.bump_noise_ping("example.com", day).unwrap();
    }
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let body: serde_json::Value = c
        .get(format!("{addr}/status/example.com"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(body["quota_remaining"], 48);
}

#[test]
fn ingest_rejects_host_with_no_canonicalization() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let r = c
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": "under_score.example"}))
        .send()
        .unwrap();
    assert_eq!(r.status(), 400);
}
