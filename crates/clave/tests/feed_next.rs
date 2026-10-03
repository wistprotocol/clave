mod common;

use clave::db::Db;
use common::*;

const NOW: &str = "2026-08-09T14:00:00Z";

fn page_requests(requests: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
    requests
        .lock()
        .unwrap()
        .iter()
        .filter(|uri| uri.contains("/label-feed/"))
        .cloned()
        .collect()
}

fn e01_count(db: &Db, host: &str) -> usize {
    db.list_rejections(host)
        .unwrap()
        .iter()
        .filter(|entry| entry.code == "WIST2-E01" && entry.id.is_none())
        .count()
}

#[test]
fn a_failing_target_records_e01_keeps_the_label_feed_labels_and_fetches_nothing() {
    for target in [
        "https://localhost/.well-known/wist/label-feed/../label-feed/0.json",
        "https://localhost/.well-known/wist/%2E%2E/wist/label-feed/0.json",
        "https://localhost:443/.well-known/wist/label-feed/0.json",
        "https://www.localhost/.well-known/wist/label-feed/0.json",
        "https://localhost/.well-known/wist%2Flabel-feed/0.json",
    ] {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher_with_scope(&host, &["www.localhost"]);
        let requests = serve_recording(listener, publisher.dir.path().into());
        let older = add_label(
            &publisher,
            "https://other.example/older",
            "2026-08-09T13:00:00Z",
        );
        let newer = add_label(
            &publisher,
            "https://other.example/newer",
            "2026-08-09T13:00:00Z",
        );
        write_label_feed_page(
            &publisher,
            &host,
            0,
            std::slice::from_ref(&older),
            NOW,
            None,
        );
        write_label_feed_with_next(
            &publisher,
            &host,
            std::slice::from_ref(&newer),
            NOW,
            Some(target),
        );
        let directory = tempfile::tempdir().unwrap();
        clave::init::run(&host, directory.path()).unwrap();
        let db = Db::open(&directory.path().join("clave.sqlite")).unwrap();
        let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
        assert_eq!(report.labels, std::slice::from_ref(&newer), "{target}");
        assert!(report.noise.is_none(), "{target}");
        assert_eq!(e01_count(&db, &host), 1, "{target}");
        assert!(!db.is_label_seen_for(&older, &host).unwrap(), "{target}");
        assert!(page_requests(&requests).is_empty(), "{target}");
    }
}

#[test]
fn a_valid_target_is_fetched_as_written_with_its_query() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    let requests = serve_recording(listener, publisher.dir.path().into());
    let directory = tempfile::tempdir().unwrap();
    clave::init::run(&host, directory.path()).unwrap();
    let db = Db::open(&directory.path().join("clave.sqlite")).unwrap();
    let opening = "2026-08-09T12:00:00Z";
    write_label_feed(&publisher, &host, &[], opening);
    clave::ingest::run(&db, &client, directory.path(), &host, opening).unwrap();
    let signing = clave::keys::load(&directory.path().join("keys/seed")).unwrap();
    clave::seal::run(
        &db,
        directory.path(),
        &signing,
        opening.parse::<jiff::Timestamp>().unwrap().as_second(),
    )
    .unwrap();
    let older = add_label(
        &publisher,
        "https://other.example/older",
        "2026-08-09T13:00:00Z",
    );
    let newer = add_label(
        &publisher,
        "https://other.example/newer",
        "2026-08-09T13:00:00Z",
    );
    write_label_feed_page(
        &publisher,
        &host,
        0,
        std::slice::from_ref(&older),
        NOW,
        None,
    );
    let target = format!("{}?v=2&x=%2F", label_page_url(&host, 0));
    write_label_feed_with_next(
        &publisher,
        &host,
        std::slice::from_ref(&newer),
        NOW,
        Some(&target),
    );
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.labels, [older, newer]);
    assert_eq!(e01_count(&db, &host), 0);
    assert_eq!(
        page_requests(&requests),
        ["/.well-known/wist/label-feed/0.json?v=2&x=%2F"]
    );
}

#[test]
fn next_is_not_read_when_the_object_lists_nothing_unseen() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    let requests = serve_recording(listener, publisher.dir.path().into());
    let bad = "https://localhost/.well-known/wist/label-feed/../label-feed/0.json";
    write_label_feed_with_next(&publisher, &host, &[], NOW, Some(bad));
    let directory = tempfile::tempdir().unwrap();
    clave::init::run(&host, directory.path()).unwrap();
    let path = directory.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.noise, None);
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.noise, Some("WIST2-E02"));
    assert_eq!(e01_count(&db, &host), 0);

    let id = add_label(
        &publisher,
        "https://other.example/a",
        "2026-08-09T13:00:00Z",
    );
    write_label_feed_with_next(&publisher, &host, std::slice::from_ref(&id), NOW, None);
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.labels, std::slice::from_ref(&id));

    write_label_feed_with_next(&publisher, &host, std::slice::from_ref(&id), NOW, Some(bad));
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert!(report.labels.is_empty());
    assert_eq!(e01_count(&db, &host), 0);
    assert!(page_requests(&requests).is_empty());
}
