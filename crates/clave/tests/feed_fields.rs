mod common;

use clave::db::Db;
use common::*;
use serde_json::Value;
use std::sync::{Arc, Mutex};

const NOW: &str = "2026-08-09T14:00:00Z";

#[test]
fn signed_field_dispositions_and_retry_counts_survive_restart() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist2/feed-fields.json")).unwrap(),
    )
    .unwrap();
    let declaration = serde_json::to_vec(&vector["declaration"]).unwrap();
    let (listener, host, client) = reserve_addr();
    let response = Arc::new(Mutex::new(Vec::<u8>::new()));
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let serving = response.clone();
    let recorded = requests.clone();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                    recorded.lock().unwrap().push(uri.path().into());
                    let body = if uri.path().ends_with("/publisher.json") {
                        declaration.clone()
                    } else {
                        serving.lock().unwrap().clone()
                    };
                    async move { body }
                });
                axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                    .await
                    .unwrap();
            });
    });

    for case in vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["live"] == true)
    {
        let name = case["name"].as_str().unwrap();
        let raw = serde_json::to_vec(&case["envelope"]).unwrap();
        *response.lock().unwrap() = raw.clone();
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        for attempt in 1..=2 {
            requests.lock().unwrap().clear();
            let db = Db::open(&path).unwrap();
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert!(
                report.accepted.is_empty() && report.queued.is_empty(),
                "{name}"
            );
            assert!(report.rejected.is_empty() && !report.suspended, "{name}");
            assert_eq!(
                report.noise,
                if case["expected"] == "accepted" {
                    Some("WIST2-E02")
                } else if case["rejection_noise"] == true {
                    Some("WIST2-E04")
                } else {
                    None
                },
                "{name}"
            );
            let rejections = db.list_rejections(&host).unwrap();
            if let Some(code) = case["code"].as_str() {
                assert_eq!(rejections.len(), attempt, "{name}");
                assert!(rejections.iter().all(|entry| entry.code == code), "{name}");
                assert!(
                    rejections.iter().all(|entry| entry.delta_id.is_none()),
                    "{name}"
                );
                if case["expected"] == "domain" {
                    assert!(rejections[0].detail.as_ref().unwrap().contains("domain"));
                }
            } else {
                assert!(rejections.is_empty(), "{name}: {rejections:?}");
            }
            let paths = requests.lock().unwrap();
            assert_eq!(
                paths
                    .iter()
                    .filter(|path| path.ends_with("/publisher.json"))
                    .count(),
                1 + case["declaration_retries"].as_u64().unwrap() as usize,
                "{name}: {paths:?}"
            );
            assert_eq!(
                paths
                    .iter()
                    .filter(|path| path.ends_with("/feed.json"))
                    .count(),
                1
            );
            let label_feed = usize::from(case["expected"] == "accepted");
            assert_eq!(
                paths.len(),
                2 + case["declaration_retries"].as_u64().unwrap() as usize + label_feed,
                "{name}: {paths:?}"
            );
            assert_eq!(db.count_pending_entries("delta").unwrap(), 0);
            assert_eq!(*response.lock().unwrap(), raw);
        }
    }
}

#[test]
fn invalid_page_fields_stop_the_walk_before_source_replay_and_the_pages_deltas() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    serve_static(listener, publisher.dir.path().into());
    let id = add_delta(&publisher, "https://localhost/a", "content", None);
    let paged = add_delta(&publisher, "https://localhost/b", "paged", None);
    let directory = tempfile::tempdir().unwrap();
    clave::init::run(&host, directory.path()).unwrap();
    let path = directory.path().join("clave.sqlite");
    for (number, cut) in [
        "2026-08-09T14:00:00.0Z",
        "2026-08-09T14:00:00+00:00",
        "2026-02-29T14:00:00Z",
    ]
    .iter()
    .enumerate()
    {
        let lead = add_delta(
            &publisher,
            &format!("https://localhost/lead/{number}"),
            "lead",
            None,
        );
        write_feed_with_next(
            &publisher,
            &host,
            std::slice::from_ref(&lead),
            NOW,
            Some(&page_url(&host, 0)),
        );
        write_feed_page(
            &publisher,
            &host,
            0,
            std::slice::from_ref(&paged),
            cut,
            None,
        );
        let db = Db::open(&path).unwrap();
        let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
        assert!(report.noise.is_none());
        assert_eq!(
            report.accepted,
            [lead],
            "the Deltas of the Feed the walk read proceed"
        );
        assert_eq!(report.ended.as_deref(), Some("WIST2-E01"));
        assert!(!db.is_delta_seen(&paged).unwrap());
        assert!(db
            .list_rejections(&host)
            .unwrap()
            .iter()
            .all(|entry| entry.code == "WIST2-E01"));
        assert!(!directory
            .path()
            .join(format!("payloads/{}.json", &paged[7..]))
            .exists());
    }
    write_feed_with_next(&publisher, &host, std::slice::from_ref(&id), NOW, None);
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, [id]);
    assert_eq!(report.ended, None);
}
