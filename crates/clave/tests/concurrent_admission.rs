mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, write_feed};
use std::sync::mpsc;
use std::time::Duration;

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
                    if delta {
                        if let Some(tx) = tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
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

#[test]
fn a_sanction_landing_mid_pull_stops_admission_before_persistence() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "first content", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    let delta_requested = serve_holding_deltas(
        listener,
        p.dir.path().to_path_buf(),
        Duration::from_millis(1500),
    );

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let path = tmp.path().join("clave.sqlite");
    drop(clave::db::Db::open(&path).unwrap());

    let puller = {
        let path = path.clone();
        let data = tmp.path().to_path_buf();
        let host = host.clone();
        std::thread::spawn(move || {
            let db = clave::db::Db::connect(&path).unwrap();
            clave::ingest::run(&db, &client, &data, &host, "2026-08-09T12:00:05Z").unwrap()
        })
    };
    delta_requested
        .recv_timeout(Duration::from_secs(10))
        .expect("the pull requested the Delta");
    let other = clave::db::Db::connect(&path).unwrap();
    let row = clave::db::DerivedPublisherRow {
        domain: &host,
        reputation_u: 0,
        level: 3,
        enforceable_level: 3,
        fallback_level: 3,
        level_since: "2026-08-09T11:00:00Z",
        evidence: &[],
        deadlines: &[],
    };
    other
        .record_derived_state(1, "2026-08-09T11:00:00Z", &[row], &[])
        .unwrap();
    assert_eq!(
        clave::sanctions::sanction_level(&other, &host, "2026-08-09T12:00:05Z").unwrap(),
        3
    );

    let report = puller.join().unwrap();
    assert!(report.accepted.is_empty(), "{:?}", report.accepted);
    assert!(report.queued.is_empty());
    assert!(report.rejected.is_empty());
    assert!(!other.is_delta_seen_for(&id, &host).unwrap());
    assert!(other
        .get_publisher_status(&host)
        .unwrap()
        .is_some_and(|s| s.last_pull_at.is_none()));
}
