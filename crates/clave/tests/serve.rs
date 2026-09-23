mod common;

use common::{
    add_delta, make_publisher_with_scope, reserve_addr, serve_recording, serve_static, write_feed,
};
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
    spawn_server_with_client(data_dir, clave::fetch::Client::new(true))
}

fn spawn_server_with_client(data_dir: &Path, transport: clave::fetch::Client) -> String {
    spawn_server_with_options(data_dir, transport, unsealed())
}

fn unsealed() -> clave::serve::ServeOptions {
    clave::serve::ServeOptions {
        seal: false,
        ..clave::serve::ServeOptions::default()
    }
}

fn spawn_server_with_options(
    data_dir: &Path,
    transport: clave::fetch::Client,
    options: clave::serve::ServeOptions,
) -> String {
    let bind = free_addr();
    let data_dir = data_dir.to_path_buf();
    let db_path = data_dir.join("clave.sqlite");
    std::thread::spawn(move || {
        clave::serve::run_with_options(data_dir, db_path, bind, transport, options).unwrap();
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
    std::fs::write(tmp.path().join("checkpoint"), b"note\n").unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let r = c
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": "127.0.0.1"}))
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
    let r = c.get(format!("{addr}/checkpoint")).send().unwrap();
    assert_eq!(r.status(), 200);
}

#[test]
fn serve_exposes_only_public_subtrees() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    std::fs::write(tmp.path().join("checkpoint"), b"note\n").unwrap();
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();

    let r = c.get(format!("{addr}/keys/seed")).send().unwrap();
    assert_eq!(r.status(), 404, "private signing seed must not be served");

    let r = c.get(format!("{addr}/clave.sqlite")).send().unwrap();
    assert_eq!(r.status(), 404, "aggregator database must not be served");

    let r = c.get(format!("{addr}/checkpoint")).send().unwrap();
    assert_eq!(r.status(), 200);

    let r = c.get(format!("{addr}/log/anchor.json")).send().unwrap();
    assert_eq!(r.status(), 200);

    let r = c.get(format!("{addr}/tile/../keys/seed")).send().unwrap();
    assert_ne!(
        r.status(),
        200,
        "a tile path must not reach outside the tile directory"
    );
}

#[test]
fn the_log_serves_checkpoints_as_text_and_full_tiles_as_immutable_octets() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&tmp.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, tmp.path(), &sk, 1_786_276_800).unwrap();
    let size = db.last_epoch().unwrap().unwrap().tree_size;
    drop(db);

    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let header = |response: &reqwest::blocking::Response, name: &str| {
        response
            .headers()
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    };

    for path in ["/checkpoint", "/log/checkpoints/000000000"] {
        let r = c.get(format!("{addr}{path}")).send().unwrap();
        assert_eq!(r.status(), 200, "{path}");
        assert_eq!(
            header(&r, "content-type").as_deref(),
            Some("text/plain; charset=utf-8"),
            "{path}"
        );
        assert_eq!(
            header(&r, "cache-control").as_deref(),
            Some("no-store"),
            "{path}"
        );
    }

    let partial = format!("/tile/entries/000.p/{size}");
    let r = c.get(format!("{addr}{partial}")).send().unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        header(&r, "content-type").as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(header(&r, "cache-control").as_deref(), Some("no-store"));

    let full = tmp.path().join("tile/entries/000");
    std::fs::write(&full, b"full bundle").unwrap();
    let r = c.get(format!("{addr}/tile/entries/000")).send().unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        header(&r, "content-type").as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(
        header(&r, "cache-control").as_deref(),
        Some("public, max-age=604800, immutable")
    );
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
        .json(&serde_json::json!({"host": "127.0.0.1", "extra": true}))
        .send()
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[test]
fn status_reports_last_pull_and_quota_after_ingest() {
    let (listener, host, client) = reserve_addr();
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
    let addr = spawn_server_with_client(tmp.path(), client);
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
    assert_eq!(body["quota_remaining"], 1000);
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
    }
    let addr = spawn_server(tmp.path());
    let c = reqwest::blocking::Client::new();
    let r = c
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": "127.0.0.1"}))
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
    let (listener, host, client) = reserve_addr();
    let empty = tempfile::tempdir().unwrap();
    serve_static(listener, empty.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let addr = spawn_server_with_client(tmp.path(), client);
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
        let publisher = common::make_publisher("example.com");
        let doc = common::current_declaration(&publisher);
        db.record_publisher_declaration(
            "example.com",
            &serde_json::to_vec(&doc).unwrap(),
            &publisher.kid,
            doc["publisher"]["keys"][0]["x"].as_str().unwrap(),
            &doc,
        )
        .unwrap();
        db.set_param("quota_base", 50).unwrap();
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

fn idle_server(data_dir: &Path, allow_http: bool) -> String {
    spawn_server_with_options(
        data_dir,
        clave::fetch::Client::new(allow_http),
        clave::serve::ServeOptions {
            max_concurrent_ingests: 0,
            max_partitions: 0,
            ..unsealed()
        },
    )
}

fn assert_nothing_started(data_dir: &Path, sent: &str, hosts: [&str; 2]) {
    let db = store(data_dir);
    let day = jiff::Timestamp::now().to_string()[..10].to_string();
    for host in hosts {
        assert_eq!(
            db.scheduled_pull(host).unwrap(),
            None,
            "{sent:?} scheduled a pull for {host:?}"
        );
        assert_eq!(
            db.noise_ping_count(host, &day).unwrap(),
            0,
            "{sent:?} counted against {host:?}'s quota"
        );
        assert!(
            db.list_rejections(host).unwrap().is_empty(),
            "{sent:?} recorded a rejection against {host:?}"
        );
        assert!(
            db.get_publisher_status(host).unwrap().is_none(),
            "{sent:?} made {host:?} a known domain"
        );
    }
}

fn ping(addr: &str, host: &str) -> u16 {
    reqwest::blocking::Client::new()
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": host}))
        .send()
        .unwrap()
        .status()
        .as_u16()
}

#[test]
fn a_ping_whose_host_is_not_byte_identical_to_its_canonical_form_is_rejected_and_starts_nothing() {
    for allow_http in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
        let addr = idle_server(tmp.path(), allow_http);
        for (sent, canonical) in [
            ("EXAMPLE.com", "example.com"),
            ("example.com.", "example.com"),
            ("bücher.example", "xn--bcher-kva.example"),
            ("example.com:8443", "example.com"),
            ("LOCALHOST:8080", "localhost"),
        ] {
            assert_eq!(
                ping(&addr, sent),
                400,
                "a non-canonical host {sent:?} must be rejected (allow_http: {allow_http})"
            );
            assert_nothing_started(tmp.path(), sent, [sent, canonical]);
        }
    }
}

#[test]
fn a_ported_loopback_ping_host_is_admitted_only_under_the_loopback_http_opt_in() {
    let strict = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", strict.path()).unwrap();
    let addr = idle_server(strict.path(), false);
    assert_eq!(
        ping(&addr, "127.0.0.1:9"),
        400,
        "a ported authority is no Canonical Host without the opt-in"
    );
    assert_nothing_started(strict.path(), "127.0.0.1:9", ["127.0.0.1:9", "127.0.0.1"]);

    let relaxed = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", relaxed.path()).unwrap();
    let addr = idle_server(relaxed.path(), true);
    assert_eq!(
        ping(&addr, "127.0.0.1:9"),
        202,
        "the loopback deployment extension admits a ported loopback authority"
    );
    let db = store(relaxed.path());
    assert_eq!(
        db.scheduled_pull("127.0.0.1:9")
            .unwrap()
            .map(|pull| pull.reason),
        Some(clave::db::Reason::Ping),
        "the pull is scheduled under the ported authority"
    );
    assert_eq!(
        db.scheduled_pull("127.0.0.1").unwrap(),
        None,
        "the ported authority is not stored port-free"
    );
}

#[test]
fn a_ping_whose_host_is_already_its_canonical_form_is_accepted_with_202() {
    for allow_http in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
        let addr = idle_server(tmp.path(), allow_http);
        for host in [
            "example.com",
            "xn--bcher-kva.example",
            "127.0.0.1",
            "localhost",
        ] {
            assert_eq!(
                ping(&addr, host),
                202,
                "a canonical host {host:?} must be accepted (allow_http: {allow_http})"
            );
            assert_eq!(
                store(tmp.path())
                    .scheduled_pull(host)
                    .unwrap()
                    .map(|pull| pull.reason),
                Some(clave::db::Reason::Ping),
                "{host:?} scheduled no pull"
            );
        }
    }
}

#[test]
fn pings_beyond_the_pending_bound_are_refused_with_retry_after() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let addr = spawn_server_with_options(
        tmp.path(),
        clave::fetch::Client::new(true),
        clave::serve::ServeOptions {
            max_concurrent_ingests: 0,
            max_pending_ingests: 2,
            max_partitions: 0,
            ..unsealed()
        },
    );
    let c = reqwest::blocking::Client::new();
    let ping = |n: u8| {
        c.post(format!("{addr}/ingest"))
            .json(&serde_json::json!({"host": format!("127.0.0.{n}")}))
            .send()
            .unwrap()
    };
    let statuses: Vec<u16> = (2..=5).map(|n| ping(n).status().as_u16()).collect();
    assert_eq!(statuses, vec![202, 202, 503, 503]);
    let refused = ping(6);
    assert_eq!(refused.status(), 503);
    assert_eq!(
        refused.headers().get("Retry-After").unwrap(),
        &clave::serve::OVERLOAD_RETRY_AFTER_SECS.to_string()
    );
    assert_eq!(
        ping(2).status(),
        202,
        "a host already waiting is not new work"
    );
    let r = c
        .get(format!("{addr}/status/unknown.example"))
        .send()
        .unwrap();
    assert_eq!(
        r.status(),
        404,
        "status answers while the gate is saturated"
    );
}

fn store(data_dir: &Path) -> clave::db::Db {
    clave::db::Db::connect(&data_dir.join("clave.sqlite")).unwrap()
}

const ALL: usize = clave::db::PARTITIONS as usize;

fn unix_now() -> i64 {
    jiff::Timestamp::now().as_second()
}

#[test]
fn a_pull_in_flight_at_restart_is_dispatched_once_and_rescheduled_one_baseline_later() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    let requests = serve_recording(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    {
        let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.set_param("baseline_poll_seconds", 3600).unwrap();
        let crashed_at = unix_now() - clave::db::PARTITION_LEASE_SECONDS;
        db.schedule_ping(&host, crashed_at, 4).unwrap();
        let claimed = db
            .claim_pulls(crashed_at, 1, "crashed-process", ALL, &[], &mut true, true)
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            db.pull_lease(&host).unwrap().unwrap().owner,
            "crashed-process"
        );
    }
    spawn_server_with_client(tmp.path(), client);

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let last_pull = loop {
        let db = store(tmp.path());
        if let Some(row) = db.get_publisher_status(&host).unwrap() {
            if let Some(at) = row.last_pull_at {
                if db.pull_lease(&host).unwrap().is_none() {
                    break at;
                }
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the reclaimed pull never completed"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let last_pull = wist_core::timestamp::log_seconds(&last_pull).unwrap();
    assert_eq!(
        store(tmp.path()).scheduled_pull(&host).unwrap(),
        Some(clave::db::DuePull {
            domain: host.clone(),
            due_at: last_pull + 3600,
            reason: clave::db::Reason::Baseline,
            attempts: 0,
            pinged_at: None,
        })
    );
    std::thread::sleep(Duration::from_millis(2500));
    let feeds = requests
        .lock()
        .unwrap()
        .iter()
        .filter(|uri| uri.ends_with("/feed.json"))
        .count();
    assert_eq!(feeds, 1, "the reclaimed pull ran more than once");
}

#[test]
fn a_ping_moves_a_scheduled_pull_earlier_never_later_and_takes_no_new_slot() {
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let domain = "example.com";
    let baseline_due = {
        let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        let publisher = common::make_publisher(domain);
        let doc = common::current_declaration(&publisher);
        db.record_publisher_declaration(
            domain,
            &serde_json::to_vec(&doc).unwrap(),
            &publisher.kid,
            doc["publisher"]["keys"][0]["x"].as_str().unwrap(),
            &doc,
        )
        .unwrap();
        db.set_param("baseline_poll_seconds", 3600).unwrap();
        let now = unix_now();
        let task = db
            .claim_pulls(
                now - clave::db::PARTITION_LEASE_SECONDS,
                1,
                "earlier-process",
                ALL,
                &[],
                &mut false,
                true,
            )
            .unwrap()
            .remove(0);
        db.complete_pull(
            &task,
            "earlier-process",
            now,
            clave::db::PullOutcome::Pulled { suspended: false },
            0.0,
            now,
        )
        .unwrap();
        db.scheduled_pull(domain).unwrap().unwrap().due_at
    };
    let addr = spawn_server_with_options(
        tmp.path(),
        clave::fetch::Client::new(true),
        clave::serve::ServeOptions {
            max_concurrent_ingests: 0,
            max_pending_ingests: 2,
            max_partitions: 0,
            ..unsealed()
        },
    );
    let c = reqwest::blocking::Client::new();
    let ping = |host: &str| {
        c.post(format!("{addr}/ingest"))
            .json(&serde_json::json!({"host": host}))
            .send()
            .unwrap()
            .status()
            .as_u16()
    };

    let before = unix_now();
    assert_eq!(ping(domain), 202);
    let pinged = store(tmp.path()).scheduled_pull(domain).unwrap().unwrap();
    assert_eq!(pinged.reason, clave::db::Reason::Ping);
    assert!(pinged.due_at >= before && pinged.due_at < baseline_due);

    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(ping(domain), 202);
    assert_eq!(
        store(tmp.path()).scheduled_pull(domain).unwrap(),
        Some(pinged.clone()),
        "a later Ping moved the due time later"
    );

    assert_eq!(ping("other.example"), 202);
    assert_eq!(ping("third.example"), 503);
    assert_eq!(ping(domain), 202, "a waiting domain takes no new slot");

    let db = store(tmp.path());
    let claimed = db
        .claim_pulls(unix_now(), 1, "elsewhere", ALL, &[], &mut true, true)
        .unwrap();
    assert_eq!(claimed[0].domain, domain);
    assert_eq!(ping(domain), 202, "a domain in flight takes no new slot");
    assert_eq!(ping("third.example"), 503);
}

fn serve_static_slow(listener: std::net::TcpListener, dir: std::path::PathBuf, delay: Duration) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                let body = std::fs::read(dir.join(uri.path().trim_start_matches('/')));
                async move {
                    tokio::time::sleep(delay).await;
                    match body {
                        Ok(bytes) => (axum::http::StatusCode::OK, bytes),
                        Err(_) => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                    }
                }
            });
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                .await
                .unwrap();
        });
    });
}

#[test]
fn a_slow_domain_blocks_neither_other_domains_nor_status() {
    let slow_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let fast_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    let fast_addr = fast_listener.local_addr().unwrap();
    slow_listener.set_nonblocking(true).unwrap();
    fast_listener.set_nonblocking(true).unwrap();
    let slow = make_publisher_with_scope("localhost", &["example.com"]);
    let fast = make_publisher_with_scope("www.localhost", &["example.com"]);
    let slow_id = add_delta(&slow, "https://example.com/slow", "slow content", None);
    let fast_id = add_delta(&fast, "https://example.com/fast", "fast content", None);
    write_feed(&slow, "localhost", &[slow_id], "2026-08-09T12:00:00Z");
    write_feed(
        &fast,
        "www.localhost",
        std::slice::from_ref(&fast_id),
        "2026-08-09T12:00:00Z",
    );
    serve_static_slow(
        slow_listener,
        slow.dir.path().to_path_buf(),
        Duration::from_secs(1),
    );
    serve_static(fast_listener, fast.dir.path().to_path_buf());
    let transport = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve("localhost", slow_addr)
            .resolve("www.localhost", fast_addr),
    );

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let addr = spawn_server_with_client(tmp.path(), transport);
    let c = reqwest::blocking::Client::new();
    let ping = |host: &str| {
        c.post(format!("{addr}/ingest"))
            .json(&serde_json::json!({"host": host}))
            .send()
            .unwrap()
            .status()
    };
    let started = std::time::Instant::now();
    assert_eq!(ping("localhost"), 202);
    assert_eq!(ping("www.localhost"), 202);
    let status = c
        .get(format!("{addr}/status/unknown.example"))
        .send()
        .unwrap()
        .status();
    assert_eq!(status, 404);
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "pings and status waited on the slow pull: {:?}",
        started.elapsed()
    );
    let deadline = started + Duration::from_millis(1800);
    loop {
        let r = c
            .get(format!("{addr}/status/www.localhost"))
            .send()
            .unwrap();
        if r.status() == 200 {
            let status: serde_json::Value = r.json().unwrap();
            if status["last_pull_at"].is_string() {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the fast domain's pull waited on the slow one"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let r = c.get(format!("{addr}/status/localhost")).send().unwrap();
        if r.status() == 200 {
            let status: serde_json::Value = r.json().unwrap();
            if status["last_pull_at"].is_string() {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the slow domain's pull never completed"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn a_slow_domain_yields_its_slot_and_lighter_domains_go_first() {
    let slow_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    slow_listener.set_nonblocking(true).unwrap();
    let slow = make_publisher_with_scope("localhost", &["example.com"]);
    let ids: Vec<String> = (0..60)
        .map(|n| {
            add_delta(
                &slow,
                &format!("https://example.com/slow/{n}"),
                "slow content",
                None,
            )
        })
        .collect();
    write_feed(&slow, "localhost", &ids, "2026-08-09T12:00:00Z");
    serve_static_slow(
        slow_listener,
        slow.dir.path().to_path_buf(),
        Duration::from_millis(200),
    );
    let fast_hosts = ["a.localhost", "b.localhost", "c.localhost", "d.localhost"];
    let mut builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .resolve("localhost", slow_addr);
    let mut fast_publishers = Vec::new();
    for host in fast_hosts {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        builder = builder.resolve(host, listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let publisher = make_publisher_with_scope(host, &["example.com"]);
        let id = add_delta(
            &publisher,
            &format!("https://example.com/{host}"),
            "fast content",
            None,
        );
        write_feed(&publisher, host, &[id], "2026-08-09T12:00:00Z");
        serve_static(listener, publisher.dir.path().to_path_buf());
        fast_publishers.push(publisher);
    }
    let transport = clave::fetch::Client::with_builder(true, builder);

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let defaults = unsealed();
    let addr = spawn_server_with_options(
        tmp.path(),
        transport,
        clave::serve::ServeOptions {
            max_concurrent_ingests: 1,
            pull_limits: clave::ingest::PullLimits {
                work_seconds: 1,
                ..defaults.pull_limits
            },
            ..defaults
        },
    );
    let c = reqwest::blocking::Client::new();
    let last_pull_at = |host: &str| {
        let r = c.get(format!("{addr}/status/{host}")).send().unwrap();
        if r.status() != 200 {
            return None;
        }
        let status: serde_json::Value = r.json().unwrap();
        status["last_pull_at"].as_str().map(str::to_string)
    };
    let started = std::time::Instant::now();
    assert_eq!(ping(&addr, "localhost"), 202);
    for host in fast_hosts {
        assert_eq!(ping(&addr, host), 202);
    }
    let deadline = started + Duration::from_secs(10);
    let mut waiting = fast_hosts.to_vec();
    while !waiting.is_empty() {
        waiting.retain(|host| last_pull_at(host).is_none());
        assert!(
            std::time::Instant::now() < deadline || waiting.is_empty(),
            "{waiting:?} waited on the slow domain's pull"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let deadline = started + Duration::from_secs(90);
    while last_pull_at("localhost").is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "the slow domain's pull never completed"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let db = store(tmp.path());
    for id in &ids {
        assert!(
            db.is_delta_seen_for(id, "localhost").unwrap(),
            "{id} of the slow domain was not admitted"
        );
    }
}

fn sealed_epochs(data_dir: &Path) -> Vec<clave::db::EpochRow> {
    let db = clave::db::Db::connect(&data_dir.join("clave.sqlite")).unwrap();
    (0..).map_while(|n| db.epoch_at(n).unwrap()).collect()
}

fn init_with_cadence(data_dir: &Path, cadence: i64) {
    clave::init::run("127.0.0.1:0", data_dir).unwrap();
    let db = clave::db::Db::open(&data_dir.join("clave.sqlite")).unwrap();
    let sk = clave::keys::load(&data_dir.join("keys/seed")).unwrap();
    let day = 86_400;
    let now = jiff::Timestamp::now().as_second();
    let start = now.div_euclid(3600) * 3600 - 8 * day;
    let effective_at = start + 7 * day;
    let effective = clave::registry::instant(effective_at).unwrap();
    clave::param_change::run(
        &db,
        &sk,
        "epoch_cadence_seconds",
        cadence,
        Some(&effective),
        start,
    )
    .unwrap();
    clave::seal::run(&db, data_dir, &sk, start).unwrap();
    clave::seal::run(&db, data_dir, &sk, effective_at).unwrap();
    assert_eq!(
        clave::registry::effective(&db, "epoch_cadence_seconds", &effective).unwrap(),
        cadence
    );
}

#[test]
fn serve_seals_consecutive_grid_instants_as_consecutive_empty_epochs() {
    let cadence = 2;
    let tmp = tempfile::tempdir().unwrap();
    init_with_cadence(tmp.path(), cadence);
    spawn_server_with_options(
        tmp.path(),
        clave::fetch::Client::new(true),
        clave::serve::ServeOptions::default(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut epochs = sealed_epochs(tmp.path());
    while epochs.len() < 5 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        epochs = sealed_epochs(tmp.path());
    }
    assert!(epochs.len() >= 5, "sealed {} Epochs", epochs.len());
    let scheduled = &epochs[2..];
    let instants: Vec<i64> = scheduled
        .iter()
        .map(|epoch| wist_core::timestamp::log_seconds(&epoch.sealed_at).unwrap())
        .collect();
    let tree_size = epochs[1].tree_size;
    for (n, (epoch, instant)) in (2..).zip(scheduled.iter().zip(&instants)) {
        assert_eq!(epoch.epoch_number, n);
        assert_eq!(epoch.tree_size, tree_size, "Epoch {n} is not empty");
        assert_eq!(
            instant.rem_euclid(cadence),
            0,
            "{} is off the grid",
            epoch.sealed_at
        );
    }
    for pair in instants.windows(2) {
        assert_eq!(pair[1] - pair[0], cadence, "{instants:?}");
    }
}

#[test]
fn serve_without_sealing_seals_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    init_with_cadence(tmp.path(), 1);
    spawn_server_with_options(tmp.path(), clave::fetch::Client::new(true), unsealed());
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(sealed_epochs(tmp.path()).len(), 2);
}

#[test]
fn two_serving_processes_on_one_store_seal_each_grid_instant_once_under_one_sealer_lease() {
    let cadence = 2;
    let tmp = tempfile::tempdir().unwrap();
    init_with_cadence(tmp.path(), cadence);
    for instance in ["first", "second"] {
        spawn_server_with_options(
            tmp.path(),
            clave::fetch::Client::new(true),
            clave::serve::ServeOptions {
                instance: instance.to_string(),
                ..clave::serve::ServeOptions::default()
            },
        );
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut epochs = sealed_epochs(tmp.path());
    while epochs.len() < 6 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        epochs = sealed_epochs(tmp.path());
    }
    assert!(epochs.len() >= 6, "sealed {} Epochs", epochs.len());
    let instants: Vec<i64> = epochs[2..]
        .iter()
        .map(|epoch| wist_core::timestamp::log_seconds(&epoch.sealed_at).unwrap())
        .collect();
    for pair in instants.windows(2) {
        assert_eq!(pair[1] - pair[0], cadence, "{instants:?}");
    }
    let lease = store(tmp.path()).sealer_lease().unwrap();
    assert!(lease.owner.is_some());
    assert_eq!(lease.token, 1, "the sealer lease changed hands");
}

#[test]
fn demand_pulls_wait_while_the_sealing_backlog_is_full_and_resume_once_sealed() {
    let hosts = ["a.localhost", "b.localhost", "c.localhost"];
    let mut builder = reqwest::blocking::Client::builder().no_proxy();
    let mut publishers = Vec::new();
    for host in hosts {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        builder = builder.resolve(host, listener.local_addr().unwrap());
        let p = make_publisher_with_scope(host, &["example.com"]);
        let id = add_delta(&p, &format!("https://example.com/{host}"), host, None);
        write_feed(&p, host, &[id], "2026-08-09T12:00:00Z");
        serve_static(listener, p.dir.path().to_path_buf());
        publishers.push(p);
    }
    let tmp = tempfile::tempdir().unwrap();
    init_with_cadence(tmp.path(), 1);
    let addr = spawn_server_with_options(
        tmp.path(),
        clave::fetch::Client::with_builder(true, builder),
        clave::serve::ServeOptions {
            max_concurrent_ingests: 1,
            backlog_entries: 4,
            ..unsealed()
        },
    );
    for host in hosts {
        assert_eq!(ping(&addr, host), 202);
    }
    let pulled = || {
        let db = store(tmp.path());
        hosts
            .into_iter()
            .filter(|host| {
                db.get_publisher_status(host)
                    .unwrap()
                    .is_some_and(|row| row.last_pull_at.is_some())
            })
            .collect::<Vec<_>>()
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while pulled().len() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "the first two pulls never completed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(2500));
    let done = pulled();
    assert_eq!(done.len(), 2, "a Ping was pulled past a full backlog");
    let waiting = hosts.into_iter().find(|host| !done.contains(host)).unwrap();
    assert_eq!(
        store(tmp.path()).sealing_backlog().unwrap().0,
        4,
        "each first pull leaves its Declaration's entry and its Delta's"
    );
    let row = store(tmp.path()).scheduled_pull(waiting).unwrap().unwrap();
    assert_eq!(row.reason, clave::db::Reason::Ping);

    let db = store(tmp.path());
    let sk = clave::keys::load(&tmp.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, tmp.path(), &sk, unix_now()).unwrap();
    assert_eq!(db.sealing_backlog().unwrap().0, 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while pulled().len() < 3 {
        assert!(
            std::time::Instant::now() < deadline,
            "the waiting Ping was never pulled once the backlog was sealed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
