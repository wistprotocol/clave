mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, write_feed};
use std::sync::mpsc;
use std::time::Duration;

const ALL: usize = clave::db::PARTITIONS as usize;

/// Serves the publisher directory, signalling the first Delta request and
/// holding it for `hold` before answering.
fn serve_holding_deltas(
    listener: std::net::TcpListener,
    dir: std::path::PathBuf,
    hold: Duration,
) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                let body = std::fs::read(dir.join(uri.path().trim_start_matches('/')));
                let delta = uri.path().contains("/deltas/");
                let tx = tx.clone();
                async move {
                    let first = if delta {
                        tx.lock().unwrap().take()
                    } else {
                        None
                    };
                    if let Some(tx) = first {
                        let _ = tx.send(());
                        tokio::time::sleep(hold).await;
                    }
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
    rx
}

fn payload_files(data_dir: &std::path::Path) -> usize {
    std::fs::read_dir(data_dir.join("payloads")).map_or(0, |dir| dir.count())
}

#[test]
fn a_pull_whose_partition_is_taken_over_mid_pull_writes_nothing_and_the_new_holder_admits_once() {
    let (listener, host, client) = reserve_addr();
    let origin = listener.local_addr().unwrap();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "first content", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    let delta_requested = serve_holding_deltas(
        listener,
        p.dir.path().to_path_buf(),
        Duration::from_millis(1500),
    );

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let path = tmp.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let now = jiff::Timestamp::now().as_second();
    let claimed_at = now - clave::db::PARTITION_LEASE_SECONDS;
    db.schedule_ping(&host, claimed_at, 4).unwrap();
    let old = db
        .claim_pulls(claimed_at, 1, "old", ALL, &[], &mut true, true)
        .unwrap()
        .remove(0);
    let at = jiff::Timestamp::from_second(now).unwrap().to_string();

    let puller = {
        let (path, data, host, at, fence) = (
            path.clone(),
            tmp.path().to_path_buf(),
            host.clone(),
            at.clone(),
            old.fence(),
        );
        std::thread::spawn(move || {
            let db = clave::db::Db::connect(&path).unwrap().fenced(fence);
            clave::ingest::run(&db, &client, &data, &host, &at)
        })
    };
    delta_requested
        .recv_timeout(Duration::from_secs(10))
        .expect("the pull requested the Delta");
    let new = db
        .claim_pulls(now, 1, "new", ALL, &[], &mut true, true)
        .unwrap()
        .remove(0);
    assert_eq!(new.domain, host);
    assert_eq!(new.token, old.token + 1);

    let outcome = puller.join().unwrap();
    assert!(
        matches!(outcome, Err(clave::Error::Fenced)),
        "{:?}",
        outcome.map(|report| report.accepted)
    );
    assert!(!db.is_delta_seen_for(&id, &host).unwrap());
    assert!(db.list_rejections(&host).unwrap().is_empty());
    assert_eq!(payload_files(tmp.path()), 0);
    assert!(db
        .get_publisher_status(&host)
        .unwrap()
        .is_some_and(|status| status.last_pull_at.is_none()));
    assert!(matches!(
        db.complete_pull(
            &old,
            "old",
            claimed_at,
            clave::db::PullOutcome::Failed,
            0.0,
            now
        ),
        Err(clave::Error::Fenced)
    ));
    assert_eq!(db.scheduled_pull(&host).unwrap(), None);
    assert_eq!(db.pull_lease(&host).unwrap().unwrap().owner, "new");

    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve("localhost", origin),
    );
    let pull = clave::db::Db::connect(&path).unwrap().fenced(new.fence());
    let report = clave::ingest::run(&pull, &client, tmp.path(), &host, &at).unwrap();
    assert_eq!(report.accepted, vec![id.clone()]);
    pull.complete_pull(
        &new,
        "new",
        now,
        clave::db::PullOutcome::Pulled {
            suspended: report.suspended,
        },
        0.0,
        now,
    )
    .unwrap();
    assert!(db.is_delta_seen_for(&id, &host).unwrap());
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
    assert_eq!(payload_files(tmp.path()), 1);
    assert!(db.scheduled_pull(&host).unwrap().is_some());
}

/// Serves the publisher directory, recording every request path and
/// holding the first Delta request for `hold` before answering.
fn serve_recording_holding_deltas(
    listener: std::net::TcpListener,
    dir: std::path::PathBuf,
    hold: Duration,
) -> (
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    mpsc::Receiver<()>,
) {
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let recorded = requests.clone();
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                recorded.lock().unwrap().push(uri.path().to_string());
                let body = std::fs::read(dir.join(uri.path().trim_start_matches('/')));
                let delta = uri.path().contains("/deltas/");
                let tx = tx.clone();
                async move {
                    let first = if delta {
                        tx.lock().unwrap().take()
                    } else {
                        None
                    };
                    if let Some(tx) = first {
                        let _ = tx.send(());
                        tokio::time::sleep(hold).await;
                    }
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
    (requests, rx)
}

fn open_runs(path: &std::path::Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pull_runs", [], |row| row.get(0))
        .unwrap()
}

fn served_bytes(publisher: &common::TestPub, paths: &[String]) -> i64 {
    paths
        .iter()
        .map(|path| {
            std::fs::metadata(publisher.dir.path().join(".well-known/wist").join(path))
                .unwrap()
                .len() as i64
        })
        .sum()
}

#[test]
fn a_new_holder_fetches_feed_json_again_and_admits_each_delta_once() {
    let (listener, host, client) = reserve_addr();
    let origin = listener.local_addr().unwrap();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "first content", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    let (requests, delta_requested) = serve_recording_holding_deltas(
        listener,
        p.dir.path().to_path_buf(),
        Duration::from_millis(1500),
    );

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let path = tmp.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let now = jiff::Timestamp::now().as_second();
    let claimed_at = now - clave::db::PARTITION_LEASE_SECONDS;
    db.schedule_ping(&host, claimed_at, 4).unwrap();
    let old = db
        .claim_pulls(claimed_at, 1, "old", ALL, &[], &mut true, true)
        .unwrap()
        .remove(0);
    let at = jiff::Timestamp::from_second(now).unwrap().to_string();

    let puller = {
        let (path, data, host, at, fence) = (
            path.clone(),
            tmp.path().to_path_buf(),
            host.clone(),
            at.clone(),
            old.fence(),
        );
        std::thread::spawn(move || {
            let db = clave::db::Db::connect(&path).unwrap().fenced(fence);
            clave::ingest::run(&db, &client, &data, &host, &at)
        })
    };
    delta_requested
        .recv_timeout(Duration::from_secs(10))
        .expect("the pull requested the Delta");
    let new = db
        .claim_pulls(now, 1, "new", ALL, &[], &mut true, true)
        .unwrap()
        .remove(0);
    assert!(matches!(puller.join().unwrap(), Err(clave::Error::Fenced)));
    assert_eq!(
        open_runs(&path),
        1,
        "the taken-over pull leaves its run behind"
    );

    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve("localhost", origin),
    );
    let pull = clave::db::Db::connect(&path).unwrap().fenced(new.fence());
    let run = clave::ingest::open_pull(
        &pull,
        &client,
        tmp.path(),
        &host,
        &at,
        jiff::Timestamp::now,
        clave::ingest::PullLimits::default(),
    )
    .unwrap();
    let report = clave::ingest::finish_pull(&pull, &new, "new", now, run, now).unwrap();

    assert_eq!(report.accepted, vec![id.clone()]);
    assert!(db.is_delta_seen_for(&id, &host).unwrap());
    assert_eq!(
        db.count_pending_entries("publisher_delta").unwrap(),
        1,
        "the Delta is admitted exactly once"
    );
    assert_eq!(payload_files(tmp.path()), 1);
    assert_eq!(open_runs(&path), 0, "the completed run is closed");
    assert!(db.scheduled_pull(&host).unwrap().is_some());

    let requests = requests.lock().unwrap().clone();
    let hex = id.strip_prefix("sha256:").unwrap();
    let counted = |suffix: String| requests.iter().filter(|path| **path == suffix).count();
    assert_eq!(
        counted("/.well-known/wist/feed.json".into()),
        2,
        "the new holder fetches the live Feed again rather than continuing the run"
    );
    assert_eq!(
        counted(format!("/.well-known/wist/deltas/{hex}.json")),
        2,
        "the Delta the taken-over pull never persisted is requested again"
    );
    assert_eq!(
        db.ingest_bytes(&host, &at[..10]).unwrap(),
        served_bytes(
            &p,
            &[
                "feed.json".into(),
                "feed.json".into(),
                format!("deltas/{hex}.json"),
                format!("payloads/{hex}.json"),
            ]
        ),
        "each pull is metered for what it read, and the reservation of the abandoned request returns to the budget"
    );
}

#[test]
fn a_takeover_before_a_pull_completes_leaves_its_run_and_its_next_pull_unwritten() {
    let (listener, host, client) = reserve_addr();
    let origin = listener.local_addr().unwrap();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "first content", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    common::serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", tmp.path()).unwrap();
    let path = tmp.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let now = jiff::Timestamp::now().as_second();
    let claimed_at = now - clave::db::PARTITION_LEASE_SECONDS;
    db.schedule_ping(&host, claimed_at, 4).unwrap();
    let old = db
        .claim_pulls(claimed_at, 1, "old", ALL, &[], &mut true, true)
        .unwrap()
        .remove(0);
    let at = jiff::Timestamp::from_second(now).unwrap().to_string();
    let pull = clave::db::Db::connect(&path).unwrap().fenced(old.fence());
    let run = clave::ingest::open_pull(
        &pull,
        &client,
        tmp.path(),
        &host,
        &at,
        jiff::Timestamp::now,
        clave::ingest::PullLimits::default(),
    )
    .unwrap();
    assert!(run.is_some());

    let new = db
        .claim_pulls(now, 1, "new", ALL, &[], &mut true, true)
        .unwrap()
        .remove(0);
    assert!(matches!(
        clave::ingest::finish_pull(&pull, &old, "old", claimed_at, run, now),
        Err(clave::Error::Fenced)
    ));
    assert_eq!(open_runs(&path), 1, "the run the pull left stays behind");
    assert!(db
        .get_publisher_status(&host)
        .unwrap()
        .is_some_and(|status| status.last_pull_at.is_none()));
    assert_eq!(db.scheduled_pull(&host).unwrap(), None);

    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve("localhost", origin),
    );
    let pull = clave::db::Db::connect(&path).unwrap().fenced(new.fence());
    let fresh = clave::ingest::open_pull(
        &pull,
        &client,
        tmp.path(),
        &host,
        &at,
        jiff::Timestamp::now,
        clave::ingest::PullLimits::default(),
    )
    .unwrap();
    assert_ne!(fresh, run, "the new holder begins a fresh run");
    let report = clave::ingest::finish_pull(&pull, &new, "new", now, fresh, now).unwrap();
    assert!(
        report.accepted.is_empty(),
        "the Delta the taken-over pull admitted is seen and admitted no second time"
    );
    assert!(db.is_delta_seen_for(&id, &host).unwrap());
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
    assert_eq!(open_runs(&path), 0);
    assert!(db
        .get_publisher_status(&host)
        .unwrap()
        .is_some_and(|status| status.last_pull_at.is_some()));
    assert!(db.scheduled_pull(&host).unwrap().is_some());
}
