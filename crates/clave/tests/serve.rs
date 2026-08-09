mod common;

use common::{add_delta, make_publisher, serve_static, write_feed};
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
    let p = make_publisher("127.0.0.1");
    let id1 = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(
        &p,
        "127.0.0.1",
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    let host = serve_static(p.dir.path().to_path_buf());

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
