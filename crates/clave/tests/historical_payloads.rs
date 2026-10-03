mod common;

use clave::history::payloads::{PayloadLocation, PayloadSource};
use common::*;
use serde_json::{json, Value};

fn sealed(extract: &str) -> (Rig, Value, Vec<u8>) {
    let r = Rig::new();
    let (item, payload) = r.page("page", extract);
    r.publish(
        &[(item.clone(), Some(payload.clone()))],
        "2026-08-09T12:00:00Z",
        None,
    );
    r.pull("2026-08-09T12:00:05Z");
    r.seal("2026-08-09T13:00:00Z");
    (r, item, wist_core::jcs::canonicalize(&payload).unwrap())
}

fn source(r: &Rig, item: &Value) -> clave::error::Result<PayloadSource> {
    PayloadSource::reconstruct(
        &r.db,
        r.data.path(),
        r.db.last_epoch().unwrap(),
        &item_id(item),
    )
}

#[test]
fn a_historical_source_is_the_item_of_the_epoch_that_sealed_it_valid() {
    let (r, item, _) = sealed("body");
    let found = source(&r, &item).unwrap();
    assert_eq!(found.item(), &item);
    assert_eq!(found.epoch_number(), 0);
    let (waiting, _) = r.page("waiting", "not sealed");
    assert!(source(&r, &waiting).is_err());
    let head = r.db.last_epoch().unwrap();
    r.seal("2026-08-09T14:00:00Z");
    assert!(PayloadSource::reconstruct(&r.db, r.data.path(), head, &item_id(&item)).is_ok());
}

#[test]
fn historical_sources_require_the_entire_pinned_prefix_before_returning() {
    let (r, item, _) = sealed("body");
    r.seal("2026-08-09T14:00:00Z");
    let connection = rusqlite::Connection::open(r.data.path().join("clave.sqlite")).unwrap();
    let last = r.db.tree_size().unwrap() - 1;
    let original: Vec<u8> = connection
        .query_row(
            "SELECT entry_json FROM log_entries WHERE leaf_index = ?1",
            [last as i64],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = ?2",
            rusqlite::params![br#"{"type":"label","body":{}}"#.as_slice(), last as i64],
        )
        .unwrap();
    assert!(source(&r, &item).is_err());
    connection
        .execute(
            "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = ?2",
            rusqlite::params![original, last as i64],
        )
        .unwrap();
    assert!(source(&r, &item).is_ok());
}

#[test]
fn a_withdrawn_item_names_no_historical_payload() {
    let (r, item, _) = sealed("withdrawn body");
    clave::governance::withdraw(
        &r.db,
        &r.sk,
        &r.host,
        &item_id(&item),
        "court order",
        "DE",
        wist_core::timestamp::log_seconds("2026-08-09T13:30:00Z").unwrap(),
    )
    .unwrap();
    r.seal("2026-08-09T14:00:00Z");
    assert!(source(&r, &item).is_err());
}

#[test]
fn historical_payload_retrieval_retries_independent_copies_without_rewriting_state() {
    let (r, item, raw) = sealed("body");
    let epoch_entries = r.db.epoch_entries(0).unwrap();
    let copies = tempfile::tempdir().unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, copies.path().to_owned());
    let url = format!("http://{host}/copy.json");
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["content"]["extract"] = json!("substitution");
    let wrong = serde_json::to_vec(&wrong).unwrap();
    let mut original = b" \n".to_vec();
    original.extend_from_slice(&raw);
    original.extend_from_slice(b"\n ");
    let empty = tempfile::tempdir().unwrap();
    for _ in 0..2 {
        let source = source(&r, &item).unwrap();
        assert!(matches!(
            source.read(empty.path()),
            Err(clave::Error::Io(_))
        ));
        assert!(matches!(
            source.fetch(&client, &url),
            Err(clave::Error::Fetch(_))
        ));
        for rejected in [b"not JSON".as_slice(), wrong.as_slice()] {
            std::fs::write(copies.path().join("copy.json"), rejected).unwrap();
            let code = if rejected == wrong {
                "WIST1-E10"
            } else {
                "WIST1-E05"
            };
            assert!(
                matches!(source.fetch(&client, &url), Err(clave::Error::Payload(actual)) if actual == code)
            );
            assert_eq!(
                std::fs::read(copies.path().join("copy.json")).unwrap(),
                rejected
            );
        }
        std::fs::write(copies.path().join("copy.json"), &original).unwrap();
        let copy = source.fetch(&client, &url).unwrap();
        assert_eq!(copy.raw(), original);
        assert_eq!(copy.payload().content.extract, "body");
        assert_eq!(copy.source().item(), &item);
        std::fs::remove_file(copies.path().join("copy.json")).unwrap();
        assert_eq!(r.db.epoch_entries(0).unwrap(), epoch_entries);
    }
}

#[test]
fn historical_payload_fallback_preserves_failures_and_the_publisher_location() {
    let (r, item, raw) = sealed("body");
    let mirror = tempfile::tempdir().unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, mirror.path().to_owned());
    let relative = format!("payloads/{}.json", &item_id(&item)[7..]);
    let retained_path = r.data.path().join(&relative);
    let distributed_path = mirror.path().join(&relative);
    let published_path = collection_dir(&r.p, "default").join(&relative);
    std::fs::create_dir_all(distributed_path.parent().unwrap()).unwrap();
    let mut original = b" \n".to_vec();
    original.extend_from_slice(&raw);
    original.extend_from_slice(b"\n ");
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["content"]["extract"] = json!("substitution");
    let wrong = serde_json::to_vec(&wrong).unwrap();
    let source = source(&r, &item).unwrap();
    let locations = vec![
        source.retained_location(r.data.path()),
        source
            .distribution_location(&format!("http://{host}/"))
            .unwrap(),
        PayloadLocation::Url(format!(
            "http://{}/.well-known/wist/collections/default/{relative}",
            r.host
        )),
    ];
    assert_eq!(locations[0], PayloadLocation::File(retained_path.clone()));
    assert_eq!(
        std::fs::read(&retained_path).unwrap(),
        raw,
        "the served copy is the retained one"
    );
    std::fs::write(&retained_path, b"not JSON").unwrap();
    std::fs::write(&distributed_path, &wrong).unwrap();
    let published = std::fs::read(&published_path).unwrap();
    std::fs::remove_file(&published_path).unwrap();
    let failed = source.retrieve(&client, locations.clone()).err().unwrap();
    assert_eq!(failed.attempts.len(), 3);
    for (attempt, location) in failed.attempts.iter().zip(&locations) {
        assert_eq!(&attempt.location, location);
    }
    assert!(matches!(
        failed.attempts[0].error,
        clave::Error::Payload("WIST1-E05")
    ));
    assert!(matches!(
        failed.attempts[1].error,
        clave::Error::Payload("WIST1-E10")
    ));
    assert!(matches!(failed.attempts[2].error, clave::Error::Fetch(_)));
    std::fs::write(&published_path, &published).unwrap();
    let candidates = locations
        .clone()
        .into_iter()
        .chain(std::iter::once_with(|| {
            panic!("candidate after the first verified copy must not be selected")
        }));
    let copy = r.client.clone();
    let copy = source.retrieve(&copy, candidates).unwrap();
    assert_eq!(copy.location(), &locations[2]);
    assert_eq!(copy.failed_attempts().len(), 2);
    assert_eq!(copy.payload().content.extract, "body");
    assert_eq!(std::fs::read(&retained_path).unwrap(), b"not JSON");
    std::fs::write(&retained_path, &original).unwrap();
    let candidates = std::iter::once(locations[0].clone()).chain(std::iter::once_with(|| {
        panic!("a verified retained copy must stop fallback")
    }));
    let copy = source.retrieve(&client, candidates).unwrap();
    assert_eq!(copy.location(), &locations[0]);
    assert!(copy.failed_attempts().is_empty());
    assert!(source
        .retrieve(&client, [])
        .err()
        .unwrap()
        .attempts
        .is_empty());
}

#[test]
fn historical_payload_distribution_locations_require_origins_and_preserve_ports() {
    let (r, item, _) = sealed("body");
    let source = source(&r, &item).unwrap();
    let relative = format!("payloads/{}.json", &item_id(&item)[7..]);
    assert_eq!(
        source
            .distribution_location("https://mirror.example:8443/")
            .unwrap(),
        PayloadLocation::Url(format!("https://mirror.example:8443/{relative}"))
    );
    for origin in [
        "ftp://mirror.example/",
        "https://user@mirror.example/",
        "https://mirror.example/sub/",
        "https://mirror.example/?q",
        "https://mirror.example/#f",
        "not a url",
    ] {
        assert!(source.distribution_location(origin).is_err(), "{origin}");
    }
}
