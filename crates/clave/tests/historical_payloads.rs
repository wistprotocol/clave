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

fn relative(item: &Value) -> String {
    format!("payloads/{}.json", &item_id(item)[7..])
}

#[test]
fn historical_payload_discovery_uses_independent_origins_mirror_hints_and_the_publisher() {
    let (r, item, raw) = sealed("body");
    let epoch_entries = r.db.epoch_entries(0).unwrap();
    let client = r.client.clone();
    let mirror = tempfile::tempdir().unwrap();
    let (mirror_listener, _, _) = reserve_addr();
    let mirror_origin = format!("http://{}/", mirror_listener.local_addr().unwrap());
    serve_static(mirror_listener, mirror.path().to_owned());
    let relative = relative(&item);
    let retained = r.data.path().join(&relative);
    let distributed = r.p.dir.path().join(&relative);
    let mirrored = mirror.path().join(&relative);
    std::fs::create_dir_all(distributed.parent().unwrap()).unwrap();
    std::fs::create_dir_all(mirrored.parent().unwrap()).unwrap();
    let mirror_file = r.data.path().join("log/mirrors.json");
    let hints = json!({"mirrors":{"mirror_urls":[
        "http://localhost/", mirror_origin, "https://user@unusable.example/", mirror_origin
    ]},"sig":{"value":"untrusted"}});
    let hint_bytes = serde_json::to_vec(&hints).unwrap();
    std::fs::write(&mirror_file, &hint_bytes).unwrap();
    for _ in 0..2 {
        let source = source(&r, &item).unwrap();
        let discovered = source.discover(
            &client,
            r.data.path(),
            &["file:///invalid/".into(), "http://LOCALHOST:80/".into()],
        );
        assert_eq!(
            discovered.locations(),
            &[
                PayloadLocation::File(retained.clone()),
                PayloadLocation::Url(format!("http://localhost/{relative}")),
                PayloadLocation::Url(format!("{mirror_origin}{relative}")),
                PayloadLocation::Url(format!(
                    "http://localhost/.well-known/wist/collections/default/{relative}"
                )),
            ],
        );
        assert_eq!(discovered.discovery_failures().len(), 2);
        assert_eq!(
            discovered.discovery_failures()[0].location,
            PayloadLocation::Url("file:///invalid/".into()),
        );
        assert_eq!(
            discovered.discovery_failures()[1].location,
            PayloadLocation::Url("https://user@unusable.example/".into()),
        );
        assert!(discovered
            .discovery_failures()
            .iter()
            .all(|failure| matches!(failure.error, clave::Error::Fetch(_))));
        for local_valid in [false, true] {
            std::fs::write(
                &retained,
                if local_valid {
                    raw.as_slice()
                } else {
                    b"bad local"
                },
            )
            .unwrap();
            std::fs::write(&distributed, b"bad distributed").unwrap();
            std::fs::write(&mirrored, b"bad mirror").unwrap();
            let copy = source
                .retrieve(&client, discovered.locations().iter().cloned())
                .unwrap();
            let selected = if local_valid { 0 } else { 3 };
            assert_eq!(copy.location(), &discovered.locations()[selected]);
            assert_eq!(copy.failed_attempts().len(), selected);
            assert_eq!(copy.raw(), raw);
            assert_eq!(copy.source().item(), &item);
            assert_eq!(std::fs::read(&distributed).unwrap(), b"bad distributed");
        }
        std::fs::remove_file(&retained).unwrap();
        std::fs::write(&distributed, &raw).unwrap();
        let copy = source
            .retrieve(&client, discovered.locations().iter().cloned())
            .unwrap();
        assert_eq!(copy.location(), &discovered.locations()[1]);
        assert_eq!(copy.failed_attempts().len(), 1);
        std::fs::remove_file(&distributed).unwrap();
        std::fs::write(&mirrored, &raw).unwrap();
        let copy = source
            .retrieve(&client, discovered.locations().iter().cloned())
            .unwrap();
        assert_eq!(copy.location(), &discovered.locations()[2]);
        assert_eq!(copy.failed_attempts().len(), 2);
        assert_eq!(copy.raw(), raw);
        assert!(!retained.exists());
        assert_eq!(std::fs::read(&mirror_file).unwrap(), hint_bytes);
        assert_eq!(r.db.epoch_entries(0).unwrap(), epoch_entries);
    }
}

#[test]
fn historical_payload_discovery_preserves_fallback_when_optional_mirror_hints_fail() {
    let (r, item, raw) = sealed("body");
    let client = r.client.clone();
    std::fs::remove_file(r.data.path().join(relative(&item))).unwrap();
    let path = r.data.path().join("log/mirrors.json");
    let _ = std::fs::remove_file(&path);
    let source = source(&r, &item).unwrap();
    for hints in [
        None,
        Some("not JSON"),
        Some("{}"),
        Some(r#"{"mirrors":{"mirror_urls":["https://mirror.example/",false]}}"#),
        Some(r#"{"mirrors":{"mirror_urls":[],"mirror_urls":[]}}"#),
    ] {
        if let Some(raw) = hints {
            std::fs::write(&path, raw).unwrap();
        }
        let discovered = source.discover(&client, r.data.path(), &[]);
        assert_eq!(discovered.locations().len(), 2);
        assert_eq!(
            discovered.discovery_failures().len(),
            usize::from(hints.is_some())
        );
        if let Some(failure) = discovered.discovery_failures().first() {
            assert_eq!(failure.location, PayloadLocation::File(path.clone()));
            assert!(matches!(failure.error, clave::Error::Json(_)));
        }
        let copy = source
            .retrieve(&client, discovered.locations().iter().cloned())
            .unwrap();
        assert_eq!(copy.location(), &source.publisher_location(&client));
        assert_eq!(copy.raw(), raw);
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let discovered = source.discover(&client, r.data.path(), &[]);
    assert!(matches!(
        discovered.discovery_failures()[0].error,
        clave::Error::Io(_)
    ));
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(
        &path,
        r#"{"mirrors":{"mirror_urls":["http://localhost/"]}}"#,
    )
    .unwrap();
    let repaired = source.discover(&client, r.data.path(), &[]);
    assert!(repaired.discovery_failures().is_empty());
    assert_eq!(repaired.locations().len(), 3);
}

#[test]
fn remote_mirror_hints_preserve_payload_authentication_fallback_and_restart() {
    let (r, item, raw) = sealed("body");
    let epoch_entries = r.db.epoch_entries(0).unwrap();
    let client = r.client.clone();
    let relative = relative(&item);
    std::fs::remove_file(r.data.path().join(&relative)).unwrap();
    let mirror = tempfile::tempdir().unwrap();
    let (listener, _, _) = reserve_addr();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    serve_static(listener, mirror.path().to_owned());
    let mirrored = mirror.path().join(&relative);
    std::fs::create_dir_all(mirrored.parent().unwrap()).unwrap();
    let independent = r.p.dir.path().join(&relative);
    std::fs::create_dir_all(independent.parent().unwrap()).unwrap();
    std::fs::write(&independent, b"bad independent copy").unwrap();
    let list = r.p.dir.path().join("log/mirrors.json");
    std::fs::create_dir_all(list.parent().unwrap()).unwrap();
    let hints = serde_json::to_vec(&json!({"mirrors":{
        "updated_at":"not a trusted clock",
        "mirror_urls":["http://LOCALHOST:80/", origin, "https://bad.example/path", origin]
    },"sig":{"value":"untrusted"}}))
    .unwrap();
    std::fs::write(&list, &hints).unwrap();
    std::fs::write(
        r.data.path().join("log/mirrors.json"),
        r#"{"mirrors":{"mirror_urls":["http://localhost/"]}}"#,
    )
    .unwrap();
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["content"]["extract"] = json!("substitution");
    for _ in 0..2 {
        let source = source(&r, &item).unwrap();
        let discovered = source.discover_with_remote_mirrors(
            &client,
            r.data.path(),
            &["http://localhost/".into()],
            &["http://localhost/".into(), "http://LOCALHOST:80/".into()],
        );
        assert_eq!(
            discovered.locations(),
            &[
                source.retained_location(r.data.path()),
                PayloadLocation::Url(format!("http://localhost/{relative}")),
                PayloadLocation::Url(format!("{origin}{relative}")),
                source.publisher_location(&client),
            ]
        );
        assert_eq!(discovered.discovery_failures().len(), 1);
        assert_eq!(
            discovered.discovery_failures()[0].location,
            PayloadLocation::Url("https://bad.example/path".into())
        );
        for valid in [false, true] {
            std::fs::write(
                &mirrored,
                if valid {
                    raw.clone()
                } else {
                    serde_json::to_vec(&wrong).unwrap()
                },
            )
            .unwrap();
            let copy = source
                .retrieve(&client, discovered.locations().iter().cloned())
                .unwrap();
            let selected = if valid { 2 } else { 3 };
            assert_eq!(copy.location(), &discovered.locations()[selected]);
            assert_eq!(copy.failed_attempts().len(), selected);
            if !valid {
                assert!(matches!(
                    copy.failed_attempts()[2].error,
                    clave::Error::Payload("WIST1-E10")
                ));
            }
            assert_eq!(copy.raw(), raw);
            assert_eq!(copy.source().item(), &item);
        }
        assert_eq!(std::fs::read(&list).unwrap(), hints);
        assert_eq!(r.db.epoch_entries(0).unwrap(), epoch_entries);
        assert!(!r.data.path().join(&relative).exists());
    }
    std::fs::write(&list, r#"{"mirrors":{"mirror_urls":[]}}"#).unwrap();
    let source = source(&r, &item).unwrap();
    let repaired = source.discover_with_remote_mirrors(
        &client,
        r.data.path(),
        &[],
        &["http://localhost/".into()],
    );
    assert!(repaired.discovery_failures().is_empty());
    assert_eq!(repaired.locations().len(), 3);
}

#[test]
fn remote_mirror_list_failures_preserve_other_lists_and_publisher_fallback() {
    let (r, item, raw) = sealed("body");
    let client = r.client.clone();
    std::fs::remove_file(r.data.path().join(relative(&item))).unwrap();
    let _ = std::fs::remove_file(r.data.path().join("log/mirrors.json"));
    let other = tempfile::tempdir().unwrap();
    let (listener, _, _) = reserve_addr();
    let other_origin = format!("http://{}/", listener.local_addr().unwrap());
    serve_static(listener, other.path().to_owned());
    std::fs::create_dir_all(other.path().join("log")).unwrap();
    std::fs::write(
        other.path().join("log/mirrors.json"),
        r#"{"mirrors":{"mirror_urls":["http://localhost/"]}}"#,
    )
    .unwrap();
    let path = r.p.dir.path().join("log/mirrors.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let source = source(&r, &item).unwrap();
    for hints in [
        None,
        Some("not JSON"),
        Some("{}"),
        Some(r#"{"mirrors":{"mirror_urls":["https://ignored.example/",false]}}"#),
        Some(r#"{"mirrors":{"mirror_urls":[],"mirror_urls":["https://ignored.example/"]}}"#),
    ] {
        if let Some(hints) = hints {
            std::fs::write(&path, hints).unwrap();
        }
        let discovered = source.discover_with_remote_mirrors(
            &client,
            r.data.path(),
            &[],
            &[
                "http://localhost/".into(),
                "http://LOCALHOST:80/".into(),
                other_origin.clone(),
            ],
        );
        assert_eq!(discovered.discovery_failures().len(), 1);
        let failure = &discovered.discovery_failures()[0];
        assert_eq!(
            failure.location,
            PayloadLocation::Url("http://localhost/log/mirrors.json".into())
        );
        if hints.is_none() {
            assert!(matches!(failure.error, clave::Error::Fetch(_)));
        } else {
            assert!(matches!(failure.error, clave::Error::Json(_)));
        }
        assert_eq!(discovered.locations().len(), 3);
        assert_eq!(
            discovered.locations()[1],
            source.distribution_location("http://localhost/").unwrap()
        );
        let copy = source
            .retrieve(&client, discovered.locations().iter().cloned())
            .unwrap();
        assert_eq!(copy.location(), &source.publisher_location(&client));
        assert_eq!(copy.raw(), raw);
    }
    let invalid = [
        "file:///tmp/",
        "https://user@invalid.example/",
        "https://invalid.example/path",
        "http://invalid.example/",
    ];
    let discovered = source.discover_with_remote_mirrors(
        &client,
        r.data.path(),
        &[],
        &invalid.map(String::from),
    );
    assert_eq!(discovered.locations().len(), 2);
    assert_eq!(discovered.discovery_failures().len(), invalid.len());
    assert!(discovered
        .discovery_failures()
        .iter()
        .all(|failure| matches!(failure.error, clave::Error::Fetch(_))));
    let no_http = source.discover_with_remote_mirrors(
        &clave::fetch::Client::new(false),
        r.data.path(),
        &[],
        std::slice::from_ref(&other_origin),
    );
    assert_eq!(no_http.discovery_failures().len(), 1);
    assert!(matches!(
        no_http.discovery_failures()[0].error,
        clave::Error::Fetch(_)
    ));
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"mirrors":{"mirror_urls":[other_origin]}})).unwrap(),
    )
    .unwrap();
    let repaired = source.discover_with_remote_mirrors(
        &client,
        r.data.path(),
        &[],
        &["http://localhost/".into()],
    );
    assert!(repaired.discovery_failures().is_empty());
    assert_eq!(repaired.locations().len(), 3);
}

#[test]
fn remote_mirror_discovery_fetches_only_distinct_explicit_list_origins() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let (r, item, _) = sealed("body");
    let _ = std::fs::remove_file(r.data.path().join("log/mirrors.json"));
    let (listener, _, client) = reserve_addr();
    let requests = Arc::new(AtomicUsize::new(0));
    let served_requests = requests.clone();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                let requests = served_requests.clone();
                async move {
                    assert_eq!(uri.path(), "/log/mirrors.json");
                    requests.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({"mirrors":{"mirror_urls":["http://localhost/", "https://unrequested.example/"]}}))
                }
            });
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app).await.unwrap();
        });
    });
    let source = source(&r, &item).unwrap();
    let independent = ["http://localhost/".into()];
    source.discover(&client, r.data.path(), &independent);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    for expected in 1..=2 {
        let discovered = source.discover_with_remote_mirrors(
            &client,
            r.data.path(),
            &independent,
            &["http://localhost/".into(), "http://LOCALHOST:80/".into()],
        );
        assert!(discovered.discovery_failures().is_empty());
        assert_eq!(discovered.locations().len(), 4);
        assert_eq!(requests.load(Ordering::SeqCst), expected);
    }
}
