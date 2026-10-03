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
                    let collection = uri.path().contains("/collections/");
                    if !collection {
                        recorded.lock().unwrap().push(uri.path().into());
                    }
                    let body = if uri.path().ends_with("/publisher.json") {
                        declaration.clone()
                    } else {
                        serving.lock().unwrap().clone()
                    };
                    async move {
                        if collection {
                            (axum::http::StatusCode::NOT_FOUND, Vec::new())
                        } else {
                            (axum::http::StatusCode::OK, body)
                        }
                    }
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
        let accepted = case["expected"] == "accepted";
        for attempt in 1..=2 {
            requests.lock().unwrap().clear();
            let db = Db::open(&path).unwrap();
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert!(report.labels.is_empty(), "{name}");
            assert!(
                report
                    .rejected
                    .iter()
                    .all(|(id, _)| id.starts_with("default/"))
                    && !report.suspended,
                "{name}"
            );
            assert_eq!(report.ended, None, "{name}");
            if attempt == 2 && accepted {
                assert_eq!(report.noise, Some("WIST2-E02"), "{name}");
            }
            let rejections: Vec<_> = db
                .list_rejections(&host)
                .unwrap()
                .into_iter()
                .filter(|rejection| rejection.collection.is_none())
                .collect();
            if accepted {
                assert!(rejections.is_empty(), "{name}: {rejections:?}");
            } else {
                assert_eq!(rejections.len(), attempt, "{name}");
                assert!(rejections.iter().all(|entry| entry.id.is_none()), "{name}");
                if case["expected"] == "domain" {
                    assert!(rejections[0].detail.as_ref().unwrap().contains("domain"));
                }
            }
            let paths = requests.lock().unwrap();
            assert_eq!(
                paths.as_slice(),
                [
                    "/.well-known/wist/publisher.json",
                    "/.well-known/wist/label-feed.json"
                ],
                "{name}"
            );
            assert_eq!(db.count_pending_entries("label").unwrap(), 0);
            assert_eq!(*response.lock().unwrap(), raw);
        }
    }
}

#[test]
fn invalid_page_fields_stop_the_label_walk_before_the_pages_labels() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    serve_static(listener, publisher.dir.path().into());
    let id = add_label(
        &publisher,
        "https://other.example/a",
        "2026-08-09T13:00:00Z",
    );
    let paged = add_label(
        &publisher,
        "https://other.example/b",
        "2026-08-09T13:00:00Z",
    );
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
        let lead = add_label(
            &publisher,
            &format!("https://other.example/lead/{number}"),
            "2026-08-09T13:00:00Z",
        );
        write_label_feed_with_next(
            &publisher,
            &host,
            std::slice::from_ref(&lead),
            NOW,
            Some(&label_page_url(&host, 0)),
        );
        write_label_feed_page(
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
            report.labels,
            [lead],
            "the Labels of the Label Feed the walk read proceed"
        );
        assert!(!db.is_label_seen_for(&paged, &host).unwrap());
        assert!(db.list_rejections(&host).unwrap().iter().any(|entry| entry
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("timestamp"))));
    }
    write_label_feed_with_next(&publisher, &host, std::slice::from_ref(&id), NOW, None);
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.labels, [id]);
    assert_eq!(report.ended, None);
}
