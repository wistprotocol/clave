mod common;

use clave::db::Db;
use common::*;

const NOW: &str = "2026-08-09T14:00:00Z";

fn page_requests(requests: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
    requests
        .lock()
        .unwrap()
        .iter()
        .filter(|uri| uri.contains("/feed/"))
        .cloned()
        .collect()
}

fn e01_count(db: &Db, host: &str) -> usize {
    db.list_rejections(host)
        .unwrap()
        .iter()
        .filter(|entry| entry.code == "WIST2-E01" && entry.delta_id.is_none())
        .count()
}

#[test]
fn a_failing_target_records_e01_keeps_the_feed_deltas_and_fetches_nothing() {
    for target in [
        "https://localhost/.well-known/wist/feed/../feed/0.json",
        "https://localhost/.well-known/wist/%2E%2E/wist/feed/0.json",
        "https://localhost:443/.well-known/wist/feed/0.json",
        "https://www.localhost/.well-known/wist/feed/0.json",
        "https://localhost/.well-known/wist%2Ffeed/0.json",
    ] {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher_with_scope(&host, &["www.localhost"]);
        let requests = serve_recording(listener, publisher.dir.path().into());
        let older = add_delta(&publisher, "https://localhost/older", "older", None);
        let newer = add_delta(&publisher, "https://localhost/newer", "newer", None);
        write_feed_page(
            &publisher,
            &host,
            0,
            std::slice::from_ref(&older),
            NOW,
            None,
        );
        write_feed_with_next(
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
        assert_eq!(report.accepted, std::slice::from_ref(&newer), "{target}");
        assert!(report.noise.is_none(), "{target}");
        assert_eq!(e01_count(&db, &host), 1, "{target}");
        assert!(!db.is_delta_seen(&older).unwrap(), "{target}");
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
    write_feed(&publisher, &host, &[], opening);
    clave::ingest::run(&db, &client, directory.path(), &host, opening).unwrap();
    let signing = clave::keys::load(&directory.path().join("keys/seed")).unwrap();
    clave::seal::run(
        &db,
        directory.path(),
        &signing,
        opening.parse::<jiff::Timestamp>().unwrap().as_second(),
    )
    .unwrap();
    let older = add_delta(&publisher, "https://localhost/older", "older", None);
    let newer = add_delta(&publisher, "https://localhost/newer", "newer", None);
    write_feed_page(
        &publisher,
        &host,
        0,
        std::slice::from_ref(&older),
        NOW,
        None,
    );
    let target = format!("{}?v=2&x=%2F", page_url(&host, 0));
    write_feed_with_next(
        &publisher,
        &host,
        std::slice::from_ref(&newer),
        NOW,
        Some(&target),
    );
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, [older, newer]);
    assert_eq!(e01_count(&db, &host), 0);
    assert_eq!(
        page_requests(&requests),
        ["/.well-known/wist/feed/0.json?v=2&x=%2F"]
    );
}

#[test]
fn next_is_not_read_when_the_object_lists_nothing_unseen() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    let requests = serve_recording(listener, publisher.dir.path().into());
    let bad = "https://localhost/.well-known/wist/feed/../feed/0.json";
    write_feed_with_next(&publisher, &host, &[], NOW, Some(bad));
    let directory = tempfile::tempdir().unwrap();
    clave::init::run(&host, directory.path()).unwrap();
    let path = directory.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.noise, Some("WIST2-E02"));
    assert_eq!(e01_count(&db, &host), 0);

    let id = add_delta(&publisher, "https://localhost/a", "content", None);
    write_feed_with_next(&publisher, &host, std::slice::from_ref(&id), NOW, None);
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&id));

    write_feed_with_next(&publisher, &host, std::slice::from_ref(&id), NOW, Some(bad));
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, directory.path(), &host, NOW).unwrap();
    assert!(report.accepted.is_empty());
    assert_eq!(e01_count(&db, &host), 0);
    assert!(page_requests(&requests).is_empty());
}
