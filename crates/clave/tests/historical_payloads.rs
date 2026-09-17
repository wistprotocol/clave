mod common;

use clave::db::BlockRow;
use clave::history::{
    deltas::DeltaSource,
    payloads::{PayloadLocation, PayloadSource},
};
use common::*;
use serde_json::{json, Value};
use wist_core::{block, crypto, envelope, jcs, merkle};

struct Fixture {
    data: tempfile::TempDir,
    head: Option<BlockRow>,
}

impl Fixture {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example", data.path()).unwrap();
        Self { data, head: None }
    }

    fn path(&self, height: u64) -> std::path::PathBuf {
        self.data
            .path()
            .join(format!("log/blocks/{height:09}.json.zst"))
    }

    fn append(&mut self, entries: Vec<Value>) {
        let height = self.head.as_ref().map_or(0, |head| head.block_number + 1);
        self.append_at(entries, height as i64 * 3600);
    }

    fn append_at(&mut self, mut entries: Vec<Value>, offset_s: i64) {
        entries.sort_by_key(|entry| {
            (
                match entry["type"].as_str().unwrap() {
                    "publisher_declaration" => 0,
                    "registry_update" => 1,
                    "publisher_delta" => 2,
                    _ => 3,
                },
                merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()),
            )
        });
        let height = self.head.as_ref().map_or(0, |head| head.block_number + 1);
        let at = jiff::Timestamp::from_second(1_800_000_000 + offset_s)
            .unwrap()
            .to_string();
        let leaves: Vec<_> = entries
            .iter()
            .map(|entry| merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()))
            .collect();
        let root = if leaves.is_empty() {
            merkle::leaf_hash(&[])
        } else {
            merkle::merkle_root(&leaves).unwrap()
        };
        let header = json!({"wist_version":"1.0.0", "block_number":height,
            "prev_block_hash":self.head.as_ref().map_or("sha256:genesis", |head| &head.block_hash),
            "sealed_at":at, "entry_count":entries.len(), "merkle_root":format!("sha256:{}", crypto::hex_encode(&root))});
        let key = clave::keys::load(&self.data.path().join("keys/seed")).unwrap();
        let doc = json!({"sig":{"key_id":"log1", "alg":"Ed25519", "value":key.sign(&jcs::canonicalize(&header).unwrap())}, "header":header, "entries":entries});
        std::fs::write(
            self.path(height),
            zstd::bulk::compress(&jcs::canonicalize(&doc).unwrap(), 1).unwrap(),
        )
        .unwrap();
        self.head = Some(BlockRow {
            block_number: height,
            block_hash: block::block_hash(&header).unwrap(),
            sealed_at: at,
        });
    }

    fn delta_source(&self, delta: &Value) -> Result<DeltaSource, clave::Error> {
        DeltaSource::reconstruct(
            self.data.path(),
            self.head.clone(),
            &wist_core::delta::delta_id(&delta["delta"]).unwrap(),
        )
    }

    fn source(&self, delta: &Value) -> Result<PayloadSource, clave::Error> {
        PayloadSource::reconstruct(
            self.data.path(),
            self.head.clone(),
            &wist_core::delta::delta_id(&delta["delta"]).unwrap(),
        )
    }
}

fn entry(kind: &str, body: &Value) -> Value {
    json!({"type":kind, "body":body})
}

fn content(p: &TestPub) -> (Value, Vec<u8>) {
    let id = add_delta(p, "https://shared.example/page", "body", None);
    let base = p.dir.path().join(".well-known/wist");
    let delta = serde_json::from_slice(
        &std::fs::read(base.join(format!("deltas/{}.json", &id[7..]))).unwrap(),
    )
    .unwrap();
    let payload = std::fs::read(base.join(format!("payloads/{}.json", &id[7..]))).unwrap();
    (delta, payload)
}

#[test]
fn historical_payloads_apply_raw_fields_integrity_and_numeric_value_rules() {
    let copies = tempfile::tempdir().unwrap();
    std::fs::create_dir(copies.path().join("payloads")).unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, copies.path().to_owned());
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/payload-fields.json")).unwrap(),
    )
    .unwrap();
    let declarations: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/declaration-fields.json")).unwrap(),
    )
    .unwrap();
    let mut cases = 0;
    for case in vector["cases"].as_array().unwrap() {
        if case.get("caps").is_some() {
            continue;
        }
        let mut f = Fixture::new();
        f.append(vec![
            entry("publisher_declaration", &declarations["stored"]),
            entry("publisher_delta", &case["envelope"]),
        ]);
        let source = f.source(&case["envelope"]).unwrap();
        let raw = case["payload_json"]
            .as_str()
            .map(|raw| raw.as_bytes().to_vec())
            .unwrap_or_else(|| serde_json::to_vec(&case["payload"]).unwrap());
        let original = raw.clone();
        let result = source.validate(&raw);
        let allowed = case["allowed"].as_array().unwrap();
        let name = format!("payloads/{}.json", &source.delta_source().id()[7..]);
        std::fs::write(copies.path().join(&name), &raw).unwrap();
        for retrieved in [
            source.read(copies.path()),
            source.fetch(&client, &format!("http://{host}/{name}")),
        ] {
            match retrieved {
                Ok(copy) => {
                    assert!(allowed.is_empty(), "{}", case["name"]);
                    assert_eq!(copy.raw(), raw);
                    assert!(std::ptr::eq(copy.source(), &source));
                    assert_eq!(
                        jcs::canonicalize(&json!(copy.payload())).unwrap(),
                        jcs::canonicalize(&case["payload"]).unwrap(),
                    );
                }
                Err(clave::Error::Payload(code)) => assert!(
                    allowed.iter().any(|value| value == code),
                    "{}: {code}",
                    case["name"],
                ),
                Err(error) => panic!("{}: {error}", case["name"]),
            }
        }
        match result {
            Ok(payload) => {
                assert!(allowed.is_empty(), "{}", case["name"]);
                assert_eq!(
                    jcs::canonicalize(&json!(payload)).unwrap(),
                    jcs::canonicalize(&case["payload"]).unwrap()
                );
            }
            Err(code) => assert!(
                allowed.iter().any(|value| value == code),
                "{}: {code}",
                case["name"]
            ),
        }
        assert_eq!(raw, original);
        assert_eq!(std::fs::read(copies.path().join(name)).unwrap(), raw);
        assert_eq!(source.envelope(), &case["envelope"]);
        cases += 1;
    }
    assert_eq!(cases, 103);
}

#[test]
fn historical_payload_retrieval_retries_independent_copies_without_rewriting_state() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let block_bytes = std::fs::read(f.path(0)).unwrap();
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
    for _ in 0..2 {
        let source = f.source(&delta).unwrap();
        assert!(matches!(
            source.read(f.data.path()),
            Err(clave::Error::Io(_))
        ));
        assert!(matches!(
            source.fetch(&client, &url),
            Err(clave::Error::Fetch(_))
        ));
        assert!(matches!(
            source.fetch(&client, "http://parent.example/copy.json"),
            Err(clave::Error::Fetch(_)),
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
        assert_eq!(copy.source().envelope(), &delta);
        assert_eq!(
            std::fs::read_dir(f.data.path().join("payloads"))
                .unwrap()
                .count(),
            0
        );
        std::fs::remove_file(copies.path().join("copy.json")).unwrap();
        assert_eq!(copy.raw(), original);
        assert_eq!(std::fs::read(f.path(0)).unwrap(), block_bytes);
    }
}

#[test]
fn historical_payload_fallback_preserves_failures_and_the_signed_publisher_location() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let block_bytes = std::fs::read(f.path(0)).unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let relative = format!(
        "payloads/{}.json",
        &wist_core::delta::delta_id(&delta["delta"]).unwrap()[7..],
    );
    let published_path = p.dir.path().join(".well-known/wist").join(&relative);
    let retained_path = f.data.path().join(&relative);
    let distributed_path = p.dir.path().join(&relative);
    std::fs::create_dir_all(distributed_path.parent().unwrap()).unwrap();
    let mut original = b" \n".to_vec();
    original.extend_from_slice(&raw);
    original.extend_from_slice(b"\n ");
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["content"]["extract"] = json!("substitution");
    let wrong = serde_json::to_vec(&wrong).unwrap();
    for _ in 0..2 {
        let source = f.source(&delta).unwrap();
        let locations = vec![
            source.retained_location(f.data.path()),
            source
                .distribution_location(&format!("http://{host}/"))
                .unwrap(),
            source.publisher_location(&client),
        ];
        assert_eq!(locations[0], PayloadLocation::File(retained_path.clone()));
        assert_eq!(
            locations[2],
            PayloadLocation::Url(format!("http://localhost/.well-known/wist/{relative}")),
        );
        assert_eq!(
            source.publisher_location(&clave::fetch::Client::new(false)),
            PayloadLocation::Url(format!("https://localhost/.well-known/wist/{relative}")),
        );
        std::fs::write(&retained_path, b"not JSON").unwrap();
        std::fs::write(&distributed_path, &wrong).unwrap();
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
        std::fs::write(&published_path, &original).unwrap();
        let candidates = locations
            .clone()
            .into_iter()
            .chain(std::iter::once_with(|| {
                panic!("candidate after the first verified copy must not be selected")
            }));
        let copy = source.retrieve(&client, candidates).unwrap();
        assert_eq!(copy.location(), &locations[2]);
        assert_eq!(copy.failed_attempts().len(), 2);
        assert_eq!(copy.raw(), original);
        assert_eq!(copy.payload().content.extract, "body");
        assert_eq!(copy.source().envelope(), &delta);
        assert_eq!(std::fs::read(&retained_path).unwrap(), b"not JSON");
        assert_eq!(std::fs::read(&distributed_path).unwrap(), wrong);
        assert_eq!(std::fs::read(f.path(0)).unwrap(), block_bytes);
        std::fs::write(&retained_path, &original).unwrap();
        let candidates = std::iter::once(locations[0].clone()).chain(std::iter::once_with(|| {
            panic!("a verified retained copy must stop fallback")
        }));
        let copy = source.retrieve(&client, candidates).unwrap();
        assert_eq!(copy.location(), &locations[0]);
        assert!(copy.failed_attempts().is_empty());
        std::fs::remove_file(&retained_path).unwrap();
        let failed = source
            .retrieve(&client, [locations[0].clone()])
            .err()
            .unwrap();
        assert!(matches!(failed.attempts[0].error, clave::Error::Io(_)));
        assert!(source
            .retrieve(&client, [])
            .err()
            .unwrap()
            .attempts
            .is_empty());
    }
}

#[test]
fn historical_payload_discovery_uses_independent_origins_mirror_hints_and_signed_publisher() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let block_bytes = std::fs::read(f.path(0)).unwrap();
    let (listener, _, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let mirror = tempfile::tempdir().unwrap();
    let (mirror_listener, _, _) = reserve_addr();
    let mirror_origin = format!("http://{}/", mirror_listener.local_addr().unwrap());
    serve_static(mirror_listener, mirror.path().to_owned());
    let relative = format!(
        "payloads/{}.json",
        &wist_core::delta::delta_id(&delta["delta"]).unwrap()[7..],
    );
    let retained = f.data.path().join(&relative);
    let distributed = p.dir.path().join(&relative);
    let mirrored = mirror.path().join(&relative);
    std::fs::create_dir_all(distributed.parent().unwrap()).unwrap();
    std::fs::create_dir_all(mirrored.parent().unwrap()).unwrap();
    let mirror_file = f.data.path().join("log/mirrors.json");
    let hints = json!({"mirrors":{"mirror_urls":[
        "http://localhost/", mirror_origin, "https://user@unusable.example/", mirror_origin
    ]},"sig":{"value":"untrusted"}});
    let hint_bytes = serde_json::to_vec(&hints).unwrap();
    std::fs::write(&mirror_file, &hint_bytes).unwrap();
    for _ in 0..2 {
        let source = f.source(&delta).unwrap();
        let discovered = source.discover(
            &client,
            f.data.path(),
            &["file:///invalid/".into(), "http://LOCALHOST:80/".into()],
        );
        assert_eq!(
            discovered.locations(),
            &[
                PayloadLocation::File(retained.clone()),
                PayloadLocation::Url(format!("http://localhost/{relative}")),
                PayloadLocation::Url(format!("{mirror_origin}{relative}")),
                PayloadLocation::Url(format!("http://localhost/.well-known/wist/{relative}")),
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
            assert_eq!(copy.source().envelope(), &delta);
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
        assert_eq!(std::fs::read(f.path(0)).unwrap(), block_bytes);
    }
}

#[test]
fn historical_payload_discovery_preserves_fallback_when_optional_mirror_hints_fail() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let (listener, _, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let path = f.data.path().join("log/mirrors.json");
    let source = f.source(&delta).unwrap();
    for hints in [
        None,
        Some("not JSON"),
        Some("{}"),
        Some(r#"{"mirrors":{"mirror_urls":["https://mirror.example/",false]}}"#),
        Some(r#"{"mirrors":{"mirror_urls":[],"mirror\u005furls":[]}}"#),
    ] {
        if let Some(raw) = hints {
            std::fs::write(&path, raw).unwrap();
        }
        let discovered = source.discover(&client, f.data.path(), &[]);
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
    let discovered = source.discover(&client, f.data.path(), &[]);
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
    let repaired = source.discover(&client, f.data.path(), &[]);
    assert!(repaired.discovery_failures().is_empty());
    assert_eq!(repaired.locations().len(), 3);
}

#[test]
fn remote_mirror_hints_preserve_payload_authentication_fallback_and_restart() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let block_bytes = std::fs::read(f.path(0)).unwrap();
    let (listener, _, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let mirror = tempfile::tempdir().unwrap();
    let (listener, _, _) = reserve_addr();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    serve_static(listener, mirror.path().to_owned());
    let relative = format!(
        "payloads/{}.json",
        &wist_core::delta::delta_id(&delta["delta"]).unwrap()[7..],
    );
    let mirrored = mirror.path().join(&relative);
    std::fs::create_dir_all(mirrored.parent().unwrap()).unwrap();
    let independent = p.dir.path().join(&relative);
    std::fs::create_dir_all(independent.parent().unwrap()).unwrap();
    std::fs::write(&independent, b"bad independent copy").unwrap();
    let list = p.dir.path().join("log/mirrors.json");
    std::fs::create_dir_all(list.parent().unwrap()).unwrap();
    let hints = serde_json::to_vec(&json!({"mirrors":{
        "updated_at":"not a trusted clock",
        "mirror_urls":["http://LOCALHOST:80/", origin, "https://bad.example/path", origin]
    },"sig":{"value":"untrusted"}}))
    .unwrap();
    std::fs::write(&list, &hints).unwrap();
    let local = f.data.path().join("log/mirrors.json");
    std::fs::write(
        &local,
        r#"{"mirrors":{"mirror_urls":["http://localhost/"]}}"#,
    )
    .unwrap();
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["content"]["extract"] = json!("substitution");
    for _ in 0..2 {
        let source = f.source(&delta).unwrap();
        let discovered = source.discover_with_remote_mirrors(
            &client,
            f.data.path(),
            &["http://localhost/".into()],
            &["http://localhost/".into(), "http://LOCALHOST:80/".into()],
        );
        assert_eq!(
            discovered.locations(),
            &[
                source.retained_location(f.data.path()),
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
            assert_eq!(copy.source().envelope(), &delta);
        }
        assert_eq!(std::fs::read(&list).unwrap(), hints);
        assert_eq!(std::fs::read(f.path(0)).unwrap(), block_bytes);
        assert!(!f.data.path().join(&relative).exists());
    }
    std::fs::write(&list, r#"{"mirrors":{"mirror_urls":[]}}"#).unwrap();
    let source = f.source(&delta).unwrap();
    let repaired = source.discover_with_remote_mirrors(
        &client,
        f.data.path(),
        &[],
        &["http://localhost/".into()],
    );
    assert!(repaired.discovery_failures().is_empty());
    assert_eq!(repaired.locations().len(), 3);
}

#[test]
fn remote_mirror_list_failures_preserve_other_lists_and_publisher_fallback() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let (listener, _, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
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
    let path = p.dir.path().join("log/mirrors.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let source = f.source(&delta).unwrap();
    for hints in [
        None,
        Some("not JSON"),
        Some("{}"),
        Some(r#"{"mirrors":{"mirror_urls":["https://ignored.example/",false]}}"#),
        Some(r#"{"mirrors":{"mirror_urls":[],"mirror\u005furls":["https://ignored.example/"]}}"#),
    ] {
        if let Some(hints) = hints {
            std::fs::write(&path, hints).unwrap();
        }
        let discovered = source.discover_with_remote_mirrors(
            &client,
            f.data.path(),
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
        f.data.path(),
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
        f.data.path(),
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
        f.data.path(),
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

    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, _) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
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
    let source = f.source(&delta).unwrap();
    let independent = ["http://localhost/".into()];
    source.discover(&client, f.data.path(), &independent);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    for expected in 1..=2 {
        let discovered = source.discover_with_remote_mirrors(
            &client,
            f.data.path(),
            &independent,
            &["http://localhost/".into(), "http://LOCALHOST:80/".into()],
        );
        assert!(discovered.discovery_failures().is_empty());
        assert_eq!(discovered.locations().len(), 4);
        assert_eq!(requests.load(Ordering::SeqCst), expected);
    }
}

#[test]
fn historical_payload_distribution_locations_require_origins_and_preserve_ports() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, _) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let source = f.source(&delta).unwrap();
    let path = format!("payloads/{}.json", &source.delta_source().id()[7..]);
    assert_eq!(
        source
            .distribution_location("https://mirror.example:8443/")
            .unwrap(),
        PayloadLocation::Url(format!("https://mirror.example:8443/{path}")),
    );
    assert_eq!(
        source.publisher_location(&clave::fetch::Client::new(true)),
        PayloadLocation::Url(format!("https://parent.example/.well-known/wist/{path}")),
    );
    for origin in [
        "invalid",
        "file:///tmp/",
        "ftp://mirror.example/",
        "https://mirror.example/log/",
        "https://mirror.example/?query",
        "https://mirror.example/#fragment",
        "https://user@mirror.example/",
        "https://user:password@mirror.example/",
    ] {
        assert!(source.distribution_location(origin).is_err(), "{origin}");
    }
}

#[test]
fn historical_sources_freeze_signed_authority_and_scope_at_inclusion() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, payload) = content(&p);
    for fault in ["none", "signature", "scope", "key_time", "absent_source"] {
        let mut f = Fixture::new();
        let mut declaration = current_declaration(&p);
        if fault == "scope" {
            declaration["publisher"]["subdomain_scope"] = json!([]);
        }
        if fault == "key_time" {
            declaration["publisher"]["keys"][0]["valid_from"] = json!("9999-01-01T00:00:00Z");
        }
        declaration =
            envelope::sign_envelope(&declaration["publisher"], "publisher", "k1", &p.sk).unwrap();
        let mut target = delta.clone();
        if fault == "signature" {
            target = envelope::sign_envelope(
                &target["delta"],
                "delta",
                "k1",
                &crypto::SigningKey::from_seed(&[99; 32]),
            )
            .unwrap();
        }
        let mut entries = vec![entry("publisher_delta", &target)];
        if fault != "absent_source" {
            entries.push(entry("publisher_declaration", &declaration));
        }
        f.append(entries);
        if fault != "none" {
            assert!(f.source(&target).is_err(), "{fault}");
            continue;
        }
        let mut replacement = declaration["publisher"].clone();
        replacement["seq"] = json!(1);
        replacement["prev_declaration"] = json!(declaration_hash(&declaration));
        replacement["subdomain_scope"] = json!([]);
        replacement["keys"] = json!([key_entry("k2", &K2_SEED, "2026-08-09T00:00:00Z")]);
        let replacement = envelope::sign_envelope(
            &replacement,
            "publisher",
            "k2",
            &crypto::SigningKey::from_seed(&K2_SEED),
        )
        .unwrap();
        f.append(vec![entry("publisher_declaration", &replacement)]);
        for _ in 0..2 {
            let source = f.source(&target).unwrap();
            assert_eq!(source.block_number(), 0);
            assert_eq!(source.envelope(), &target);
            source.validate(&payload).unwrap();
            let mut corrupt: Value = serde_json::from_slice(&payload).unwrap();
            corrupt["content"]["extract"] = json!("fake");
            assert_eq!(
                source
                    .validate(&serde_json::to_vec(&corrupt).unwrap())
                    .err(),
                Some("WIST1-E10")
            );
            source.validate(&payload).unwrap();
        }
    }
}

#[test]
fn historical_sources_require_the_entire_pinned_prefix_before_returning() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, payload) = content(&p);
    for fault in ["missing", "corrupt", "head", "declaration", "duplicate"] {
        let mut f = Fixture::new();
        f.append(vec![
            entry("publisher_declaration", &current_declaration(&p)),
            entry("publisher_delta", &delta),
        ]);
        let prefix = f.head.clone();
        let entries = match fault {
            "declaration" => {
                let mut bad = current_declaration(&p);
                bad["publisher"]["seq"] = json!(1);
                vec![entry("publisher_declaration", &bad)]
            }
            "duplicate" => vec![entry("publisher_delta", &delta)],
            _ => vec![],
        };
        f.append(entries);
        let path = f.path(1);
        let bytes = std::fs::read(&path).unwrap();
        let head = f.head.clone();
        match fault {
            "missing" => std::fs::remove_file(&path).unwrap(),
            "corrupt" => std::fs::write(&path, b"broken").unwrap(),
            "head" => f.head.as_mut().unwrap().block_hash = "sha256:wrong".into(),
            _ => (),
        }
        for _ in 0..2 {
            assert!(f.source(&delta).is_err(), "{fault}");
        }
        std::fs::write(path, bytes).unwrap();
        f.head = if matches!(fault, "declaration" | "duplicate") {
            prefix
        } else {
            head
        };
        f.source(&delta).unwrap().validate(&payload).unwrap();
    }
    let mut f = Fixture::new();
    f.append(vec![entry(
        "publisher_declaration",
        &current_declaration(&p),
    )]);
    assert!(f
        .source(&delta)
        .err()
        .unwrap()
        .to_string()
        .contains("absent"));
    let mut attest = delta["delta"].clone();
    attest["change_type"] = json!("attest");
    attest["observed_at"] = json!("2026-08-09T12:00:01Z");
    attest["prev"] = json!(wist_core::delta::delta_id(&delta["delta"]).unwrap());
    attest.as_object_mut().unwrap().remove("payload");
    let attest = envelope::sign_envelope(&attest, "delta", "k1", &p.sk).unwrap();
    f.append(vec![
        entry("publisher_delta", &delta),
        entry("publisher_delta", &attest),
    ]);
    assert!(f
        .source(&attest)
        .err()
        .unwrap()
        .to_string()
        .contains("no Payload commitment"));
}

#[test]
fn historical_sources_apply_recovery_windows_and_deadline_scope() {
    let p = make_publisher_with_recovery("parent.example");
    let (delta, payload) = content(&p);
    let mut initial = current_declaration(&p)["publisher"].clone();
    initial["subdomain_scope"] = json!(["shared.example"]);
    let initial = envelope::sign_envelope(&initial, "publisher", "k1", &p.sk).unwrap();
    let mut recovery = initial["publisher"].clone();
    recovery["seq"] = json!(1);
    recovery["prev_declaration"] = json!(declaration_hash(&initial));
    recovery["keys"] = json!([key_entry("k2", &K2_SEED, "2026-08-09T00:00:00Z")]);
    let recovery = envelope::sign_envelope(
        &recovery,
        "publisher",
        "r1",
        &crypto::SigningKey::from_seed(&R1_SEED),
    )
    .unwrap();
    let delta = envelope::sign_envelope(
        &delta["delta"],
        "delta",
        "k2",
        &crypto::SigningKey::from_seed(&K2_SEED),
    )
    .unwrap();
    for state in ["open", "settled", "deadline_scope"] {
        let mut f = Fixture::new();
        f.append(vec![entry("publisher_declaration", &initial)]);
        f.append(vec![entry("publisher_declaration", &recovery)]);
        if state != "open" {
            for _ in 2..169 {
                f.append(vec![]);
            }
        }
        let mut entries = vec![entry("publisher_delta", &delta)];
        if state == "deadline_scope" {
            let mut replacement = recovery["publisher"].clone();
            replacement["seq"] = json!(2);
            replacement["prev_declaration"] = json!(declaration_hash(&recovery));
            replacement["subdomain_scope"] = json!([]);
            let replacement = envelope::sign_envelope(
                &replacement,
                "publisher",
                "k2",
                &crypto::SigningKey::from_seed(&K2_SEED),
            )
            .unwrap();
            entries.push(entry("publisher_declaration", &replacement));
        }
        f.append(entries);
        for _ in 0..2 {
            match state {
                "settled" => {
                    f.source(&delta).unwrap().validate(&payload).unwrap();
                }
                "open" => assert!(f
                    .source(&delta)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("eligible Declaration")),
                _ => assert!(f
                    .source(&delta)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("WIST1-E03")),
            }
        }
    }
}

#[test]
fn historical_delta_sources_check_exact_predecessor_vectors_in_chain_order() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/declaration-fields.json")).unwrap(),
    )
    .unwrap();
    let mut count = 0;
    for case in vector["relation_cases"].as_array().unwrap() {
        if case["kind"] != "predecessor" {
            continue;
        }
        count += 1;
        for same_block in [false, true] {
            let mut f = Fixture::new();
            let mut entries = vec![
                entry("publisher_declaration", &vector["stored"]),
                entry("publisher_delta", &case["predecessor"]),
            ];
            if !same_block {
                f.append(entries);
                entries = vec![];
            }
            entries.push(entry("publisher_delta", &case["envelope"]));
            f.append(entries);
            for _ in 0..2 {
                match f.delta_source(&case["envelope"]) {
                    Ok(source) => {
                        assert_eq!(case["expected"], "relation_satisfied", "{}", case["name"]);
                        assert_eq!(source.envelope(), &case["envelope"]);
                        assert_eq!(source.declaration().envelope(), &vector["stored"]);
                        assert_eq!(source.position().block_number, u64::from(!same_block));
                    }
                    Err(error) => assert!(
                        error
                            .to_string()
                            .contains(case["expected"].as_str().unwrap()),
                        "{}: {error}",
                        case["name"]
                    ),
                }
            }
        }
    }
    assert_eq!(count, 3);
}

#[test]
fn historical_payloads_require_authenticated_ancestors_and_all_later_delta_chains() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (root, _) = content(&p);
    let root_id = wist_core::delta::delta_id(&root["delta"]).unwrap();
    let next_id = add_delta(&p, "https://shared.example/page", "next", Some(&root_id));
    let next: Value = serde_json::from_slice(
        &std::fs::read(
            p.dir
                .path()
                .join(format!(".well-known/wist/deltas/{}.json", &next_id[7..])),
        )
        .unwrap(),
    )
    .unwrap();
    for fault in [
        "none",
        "missing",
        "signature",
        "scope",
        "publisher",
        "url",
        "late_fork",
        "late_signature",
        "late_fields",
        "late_missing",
    ] {
        let mut f = Fixture::new();
        let mut predecessor = root.clone();
        match fault {
            "signature" => predecessor["sig"]["value"] = json!(crypto::b64u_encode(&[0; 64])),
            "scope" => predecessor["delta"]["url"] = json!("https://outside.example/page"),
            "publisher" => predecessor["delta"]["publisher"] = json!("other.example"),
            "url" => predecessor["delta"]["url"] = json!("https://shared.example/other"),
            _ => (),
        }
        if matches!(fault, "scope" | "publisher" | "url") {
            predecessor =
                envelope::sign_envelope(&predecessor["delta"], "delta", "k1", &p.sk).unwrap();
        }
        let mut target = next.clone();
        target["delta"]["prev"] = json!(wist_core::delta::delta_id(&predecessor["delta"]).unwrap());
        target = envelope::sign_envelope(&target["delta"], "delta", "k1", &p.sk).unwrap();
        let mut entries = vec![entry("publisher_declaration", &current_declaration(&p))];
        if fault != "missing" {
            entries.push(entry("publisher_delta", &predecessor));
        }
        f.append(entries);
        f.append(vec![entry("publisher_delta", &target)]);
        let good_prefix = f.head.clone();
        if fault.starts_with("late_") {
            let mut later = next["delta"].clone();
            later["observed_at"] = json!("2026-08-09T12:00:02Z");
            if fault != "late_fork" {
                later["url"] = json!("https://shared.example/other");
                later["change_type"] = json!("new");
                if fault != "late_missing" {
                    later.as_object_mut().unwrap().remove("prev");
                }
            }
            if fault == "late_fields" {
                later["meta"]["unknown"] = json!(true);
            }
            let mut later = envelope::sign_envelope(&later, "delta", "k1", &p.sk).unwrap();
            if fault == "late_signature" {
                later["sig"]["value"] = json!(crypto::b64u_encode(&[0; 64]));
            }
            f.append(vec![entry("publisher_delta", &later)]);
        }
        for _ in 0..2 {
            assert_eq!(f.source(&target).is_ok(), fault == "none", "{fault}");
        }
        if fault.starts_with("late_") {
            f.head = good_prefix;
            f.source(&target).unwrap();
        }
    }
}

#[test]
fn historical_sources_preserve_chain_ownership_across_identity_resets() {
    let a = make_publisher_with_scope("a.example", &["shared.example"]);
    let b = make_publisher_with_scope("b.example", &["shared.example"]);
    let (root_a, _) = content(&a);
    let (root_b, _) = content(&b);
    let reset_key = crypto::SigningKey::from_seed(&[9; 32]);
    let mut replacement = current_declaration(&a)["publisher"].clone();
    replacement["seq"] = json!(1);
    replacement["prev_declaration"] = json!(declaration_hash(&current_declaration(&a)));
    replacement["keys"][0]["public_key"] = json!(reset_key.public().to_b64u());
    let replacement = envelope::sign_envelope(&replacement, "publisher", "k1", &reset_key).unwrap();
    for fault in ["none", "restart", "foreign", "equal", "decreasing"] {
        let mut f = Fixture::new();
        f.append(vec![
            entry("publisher_declaration", &current_declaration(&a)),
            entry("publisher_declaration", &current_declaration(&b)),
            entry("publisher_delta", &root_a),
            entry("publisher_delta", &root_b),
        ]);
        let mut next = root_a["delta"].clone();
        next["observed_at"] = json!(match fault {
            "equal" => "2026-08-09T09:00:00.000-03:00",
            "decreasing" => "2026-08-09T11:59:59.99999999999999999999Z",
            _ => "2026-08-09T12:00:00.00000000000000000001Z",
        });
        if fault != "restart" {
            let predecessor = if fault == "foreign" { &root_b } else { &root_a };
            next["prev"] = json!(wist_core::delta::delta_id(&predecessor["delta"]).unwrap());
        }
        let next = envelope::sign_envelope(&next, "delta", "k1", &reset_key).unwrap();
        f.append(vec![
            entry("publisher_declaration", &replacement),
            entry("publisher_delta", &next),
        ]);
        for _ in 0..2 {
            if fault == "none" {
                let source = f.source(&next).unwrap();
                let delta = source.delta_source();
                assert_eq!(delta.envelope(), &next);
                assert_eq!(delta.declaration().envelope(), &replacement);
                assert_eq!(delta.identity_start(), delta.declaration().position());
                assert_eq!(delta.identity_start().block_number, 1);
                for (root, publisher) in [(&root_a, &a), (&root_b, &b)] {
                    let earlier = f.delta_source(root).unwrap();
                    assert_eq!(earlier.identity_start(), earlier.declaration().position());
                    assert_eq!(earlier.identity_start().block_number, 0);
                    assert_eq!(
                        earlier.declaration().envelope(),
                        &current_declaration(publisher)
                    );
                }
            } else {
                assert!(f.source(&next).is_err(), "{fault}");
            }
        }
    }
}

#[test]
fn historical_sources_resolve_contentless_deltas_and_recreation_in_chain_order() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (root, payload) = content(&p);
    let mut chain = vec![root];
    for (i, kind) in ["attest", "delete", "new"].into_iter().enumerate() {
        let mut next = chain[0]["delta"].clone();
        next["change_type"] = json!(kind);
        next["observed_at"] = json!(format!("2026-08-09T12:00:0{}Z", i + 1));
        next["prev"] = json!(wist_core::delta::delta_id(&chain.last().unwrap()["delta"]).unwrap());
        if kind != "new" {
            next.as_object_mut().unwrap().remove("payload");
        }
        chain.push(envelope::sign_envelope(&next, "delta", "k1", &p.sk).unwrap());
    }
    for same_block in [false, true] {
        let mut f = Fixture::new();
        let mut entries = vec![entry("publisher_declaration", &current_declaration(&p))];
        for delta in &chain {
            entries.push(entry("publisher_delta", delta));
            if !same_block {
                f.append(entries);
                entries = vec![];
            }
        }
        if same_block {
            f.append(entries);
        }
        for (i, delta) in chain.iter().enumerate() {
            let source = f.delta_source(delta).unwrap();
            assert_eq!(source.envelope(), delta);
            assert_eq!(
                source.position().block_number,
                if same_block { 0 } else { i as u64 }
            );
            if i == 0 || i == 3 {
                f.source(delta).unwrap().validate(&payload).unwrap();
            } else {
                assert!(f
                    .source(delta)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("no Payload commitment"));
            }
        }
    }
}
