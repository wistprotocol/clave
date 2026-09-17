mod common;

use clave::db::Db;
use common::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use wist_core::{block, crypto, jcs, merkle};

const START: i64 = 1_800_000_000;

struct Fixture {
    directory: tempfile::TempDir,
    db: Db,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        clave::init::run("log.example", directory.path()).unwrap();
        let db = Db::open(&directory.path().join("clave.sqlite")).unwrap();
        Self { directory, db }
    }

    fn connection(&self) -> Connection {
        Connection::open(self.directory.path().join("clave.sqlite")).unwrap()
    }

    fn reopen(&self) -> Result<Db, clave::Error> {
        Db::open(&self.directory.path().join("clave.sqlite"))
    }

    fn append(&self, mut entries: Vec<Value>) {
        entries.sort_by_key(|entry| {
            (
                if entry["type"] == "publisher_declaration" {
                    0
                } else {
                    2
                },
                merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()),
            )
        });
        let head = self.db.last_block().unwrap();
        let height = head.as_ref().map_or(0, |head| head.block_number + 1);
        let at = jiff::Timestamp::from_second(START + height as i64 * 3600)
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
            "prev_block_hash":head.map_or("sha256:genesis".into(), |head| head.block_hash),
            "sealed_at":at, "entry_count":entries.len(), "merkle_root":format!("sha256:{}", crypto::hex_encode(&root))});
        let key = clave::keys::load(&self.directory.path().join("keys/seed")).unwrap();
        let doc = json!({"sig":{"key_id":"log1", "alg":"Ed25519", "value":key.sign(&jcs::canonicalize(&header).unwrap())}, "header":header, "entries":entries});
        let bytes = jcs::canonicalize(&doc).unwrap();
        std::fs::write(
            self.directory
                .path()
                .join(format!("log/blocks/{height:09}.json.zst")),
            zstd::bulk::compress(&bytes, 3).unwrap(),
        )
        .unwrap();
        self.db
            .commit_seal(
                &[],
                height,
                &block::block_hash(&header).unwrap(),
                &at,
                &[],
                &[],
                &[],
                &[],
                &[],
                bytes.len() as u64,
            )
            .unwrap();
    }

    fn legacy(&self) {
        self.connection()
            .execute_batch("DROP TABLE delta_index_reconciliation;")
            .unwrap();
    }
}

fn declaration(publisher: &TestPub) -> Value {
    json!({"type":"publisher_declaration", "body":serde_json::from_slice::<Value>(&std::fs::read(publisher.dir.path().join(".well-known/wist/publisher.json")).unwrap()).unwrap()})
}

fn delta(publisher: &TestPub, url: &str, text: &str, prev: Option<&str>) -> (String, Value) {
    let id = add_delta(publisher, url, text, prev);
    let mut body: Value = serde_json::from_slice(
        &std::fs::read(
            publisher
                .dir
                .path()
                .join(format!(".well-known/wist/deltas/{}.json", &id[7..])),
        )
        .unwrap(),
    )
    .unwrap();
    let count = std::fs::read_dir(publisher.dir.path().join(".well-known/wist/deltas"))
        .unwrap()
        .count();
    body["delta"]["observed_at"] = json!(jiff::Timestamp::from_second(START - 3600 + count as i64)
        .unwrap()
        .to_string());
    let body =
        wist_core::envelope::sign_envelope(&body["delta"], "delta", "k1", &publisher.sk).unwrap();
    (wist_core::delta::delta_id(&body["delta"]).unwrap(), body)
}

fn entry(body: Value) -> Value {
    json!({"type":"publisher_delta", "body":body})
}

#[test]
fn restores_overwritten_publisher_tips_and_releases_discarded_ids() {
    let f = Fixture::new();
    let url = "https://shared.example/page";
    let a = make_publisher_with_scope("a.example", &["shared.example"]);
    let b = make_publisher_with_scope("b.example", &["shared.example"]);
    let (a0, a_body) = delta(&a, url, "a", None);
    let (a1, a_next) = (0..100)
        .map(|n| delta(&a, url, &format!("a next {n}"), Some(&a0)))
        .find(|(_, body)| {
            merkle::leaf_hash(&jcs::canonicalize(&entry(body.clone())).unwrap())
                < merkle::leaf_hash(&jcs::canonicalize(&entry(a_body.clone())).unwrap())
        })
        .expect("a successor stored before its predecessor");
    let (b0, b_body) = delta(&b, url, "b", None);
    f.append(vec![
        declaration(&a),
        declaration(&b),
        entry(a_next),
        entry(b_body),
        entry(a_body),
    ]);
    let (pending, pending_body) = delta(&a, url, "pending", Some(&a1));
    f.db.record_accepted_delta(&a.domain, &pending, &pending_body, 0, url, &pending)
        .unwrap();
    let (queued, queued_body) = delta(&a, url, "queued", Some(&pending));
    f.db.queue_delta(&a.domain, &queued, &queued_body, url, &queued, 1)
        .unwrap();
    f.db.insert_seen_delta("discarded", &a.domain).unwrap();
    f.db.set_url_tip("https://a.example/gone", &a.domain, "discarded")
        .unwrap();
    let connection = f.connection();
    connection.execute_batch("DROP TABLE url_tips; CREATE TABLE url_tips(url TEXT PRIMARY KEY, domain TEXT NOT NULL, tip TEXT NOT NULL);").unwrap();
    connection
        .execute(
            "INSERT INTO url_tips VALUES (?1, ?2, 'discarded')",
            (url, &b.domain),
        )
        .unwrap();
    f.legacy();
    for _ in 0..2 {
        let db = f.reopen().unwrap();
        assert_eq!(
            db.url_tip(&a.domain, url).unwrap().as_deref(),
            Some(queued.as_str())
        );
        assert_eq!(
            db.url_tip(&b.domain, url).unwrap().as_deref(),
            Some(b0.as_str())
        );
        assert!(!db.is_delta_seen("discarded").unwrap());
        for id in [&a0, &a1, &pending, &queued] {
            assert!(db.is_delta_seen_for(id, &a.domain).unwrap());
        }
        assert!(db.is_delta_seen_for(&b0, &b.domain).unwrap());
        assert_eq!(db.peek_pending_entries().unwrap().0.len(), 1);
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM queued_deltas", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
    assert_eq!(f.db.list_url_tips().unwrap().len(), 2);
}

#[test]
fn empty_unsealed_history_removes_only_index_residue() {
    let f = Fixture::new();
    f.db.insert_seen_delta("discarded", "example.com").unwrap();
    f.db.set_url_tip("https://example.com/", "example.com", "discarded")
        .unwrap();
    f.legacy();
    let db = f.reopen().unwrap();
    assert!(!db.is_delta_seen("discarded").unwrap());
    assert!(db.list_url_tips().unwrap().is_empty());
}

#[test]
fn missing_or_corrupt_pinned_history_preserves_indexes_and_can_retry() {
    for corruption in ["missing", "bytes", "head"] {
        let f = Fixture::new();
        let publisher = make_publisher("example.com");
        let (id, body) = delta(&publisher, "https://example.com/", "body", None);
        f.append(vec![declaration(&publisher), entry(body)]);
        f.append(vec![]);
        f.db.insert_seen_delta("residue", &publisher.domain)
            .unwrap();
        f.db.set_url_tip("https://example.com/", &publisher.domain, "residue")
            .unwrap();
        f.legacy();
        let path = f.directory.path().join("log/blocks/000000001.json.zst");
        let bytes = std::fs::read(&path).unwrap();
        let head = f.db.last_block().unwrap().unwrap();
        match corruption {
            "missing" => std::fs::remove_file(&path).unwrap(),
            "bytes" => std::fs::write(&path, b"broken").unwrap(),
            _ => {
                f.connection()
                    .execute(
                        "UPDATE blocks SET block_hash = 'sha256:wrong' WHERE block_number = 1",
                        [],
                    )
                    .unwrap();
            }
        }
        for _ in 0..2 {
            assert!(f.reopen().is_err(), "{corruption}");
            assert!(f.db.is_delta_seen("residue").unwrap());
            assert!(!f.db.is_delta_seen(&id).unwrap());
            assert_eq!(
                f.db.url_tip(&publisher.domain, "https://example.com/")
                    .unwrap()
                    .as_deref(),
                Some("residue")
            );
        }
        std::fs::write(path, bytes).unwrap();
        f.connection()
            .execute(
                "UPDATE blocks SET block_hash = ?1 WHERE block_number = 1",
                [head.block_hash],
            )
            .unwrap();
        assert!(f.reopen().unwrap().is_delta_seen(&id).unwrap());
    }
}

#[test]
fn failed_index_write_rolls_back_deletes_inserts_and_completion_marker() {
    let f = Fixture::new();
    let publisher = make_publisher("example.com");
    let (id, body) = delta(&publisher, "https://example.com/", "body", None);
    f.append(vec![declaration(&publisher), entry(body)]);
    f.db.insert_seen_delta("residue", &publisher.domain)
        .unwrap();
    f.db.set_url_tip("https://example.com/", &publisher.domain, "residue")
        .unwrap();
    f.legacy();
    f.connection().execute_batch("CREATE TRIGGER fail_tip BEFORE INSERT ON url_tips BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    assert!(f.reopen().is_err());
    assert!(f.db.is_delta_seen("residue").unwrap());
    assert!(!f.db.is_delta_seen(&id).unwrap());
    assert_eq!(
        f.db.url_tip(&publisher.domain, "https://example.com/")
            .unwrap()
            .as_deref(),
        Some("residue")
    );
    f.connection()
        .execute_batch("DROP TRIGGER fail_tip;")
        .unwrap();
    assert!(f.reopen().unwrap().is_delta_seen(&id).unwrap());
}

#[test]
fn retained_copies_require_complete_chains_and_consistent_admission_rows() {
    for fault in ["missing", "domain", "url", "id", "order"] {
        let f = Fixture::new();
        let publisher = make_publisher("example.com");
        let url = "https://example.com/";
        let (id, body) = delta(&publisher, url, "root", None);
        let (child, child_body) = delta(&publisher, url, "child", Some(&id));
        if fault != "missing" {
            f.db.record_accepted_delta(&publisher.domain, &id, &body, 0, url, &id)
                .unwrap();
        }
        f.db.queue_delta(&publisher.domain, &child, &child_body, url, &child, 1)
            .unwrap();
        match fault {
            "domain" => f.connection().execute("UPDATE queued_deltas SET domain = 'wrong.example'", []).unwrap(),
            "url" => f.connection().execute("UPDATE queued_deltas SET url = 'https://example.com/wrong'", []).unwrap(),
            "id" => f.connection().execute("UPDATE queued_deltas SET delta_id = 'wrong'", []).unwrap(),
            "order" => f.connection().execute("UPDATE queued_deltas SET acceptance_order = (SELECT acceptance_order FROM pending_entries)", []).unwrap(),
            _ => 0,
        };
        f.legacy();
        assert!(f.reopen().is_err(), "{fault}");
        assert!(f.db.is_delta_seen(&child).unwrap());
        assert_eq!(
            f.db.url_tip(&publisher.domain, url).unwrap().as_deref(),
            Some(child.as_str())
        );
    }
}

#[test]
fn log_signature_does_not_authorize_a_forged_delta_or_wrong_scope() {
    for fault in ["signature", "scope", "fork", "duplicate"] {
        let f = Fixture::new();
        let publisher = make_publisher("example.com");
        let url = if fault == "scope" {
            "https://other.example/"
        } else {
            "https://example.com/"
        };
        let (_, mut body) = delta(&publisher, url, "root", None);
        if fault == "signature" {
            body["sig"]["value"] = json!(crypto::b64u_encode(&[0u8; 64]));
        }
        let mut entries = vec![declaration(&publisher), entry(body.clone())];
        if fault == "fork" {
            entries.push(entry(delta(&publisher, url, "fork", None).1));
        }
        if fault == "duplicate" {
            entries.push(entry(body));
        }
        f.append(entries);
        f.db.insert_seen_delta("residue", &publisher.domain)
            .unwrap();
        f.legacy();
        assert!(f.reopen().is_err(), "{fault}");
        assert!(f.db.is_delta_seen("residue").unwrap());
    }
}

#[test]
fn discarded_copy_can_be_served_again_after_upgrade_and_restart() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    let id = add_delta(&publisher, "https://localhost/page", "body", None);
    write_feed(
        &publisher,
        &host,
        std::slice::from_ref(&id),
        "2026-08-09T12:00:01Z",
    );
    serve_static(listener, publisher.dir.path().to_path_buf());
    let f = Fixture::new();
    f.append(vec![declaration(&publisher)]);
    f.db.insert_seen_delta(&id, &host).unwrap();
    f.db.set_url_tip("https://localhost/page", &host, &id)
        .unwrap();
    f.legacy();
    drop(f.reopen().unwrap());
    let db = f.reopen().unwrap();
    let report = clave::ingest::run(
        &db,
        &client,
        f.directory.path(),
        &host,
        "2027-01-15T08:00:00Z",
    )
    .unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&id));
    assert!(report.rejected.is_empty(), "{report:?}");
    assert!(db.is_delta_seen_for(&id, &host).unwrap());
    assert_eq!(
        db.url_tip(&host, "https://localhost/page")
            .unwrap()
            .as_deref(),
        Some(id.as_str())
    );
}

#[test]
fn supported_versions_restore_chains_across_sealed_and_both_unsealed_stores() {
    for version in [
        "1.0.1".into(),
        "1.1.0".into(),
        format!("1.{}.{}", "9".repeat(80), "9".repeat(80)),
    ] {
        let f = Fixture::new();
        let publisher = make_publisher("example.com");
        let url = "https://example.com/";
        let mut chain = Vec::new();
        for state in ["sealed", "pending", "recovery"] {
            let prev = chain.last().map(|(id, _): &(String, Value)| id.as_str());
            let (_, mut envelope) = delta(&publisher, url, state, prev);
            envelope["delta"]["wist_version"] = json!(version);
            let envelope = wist_core::envelope::sign_envelope(
                &envelope["delta"],
                "delta",
                "k1",
                &publisher.sk,
            )
            .unwrap();
            let id = wist_core::delta::delta_id(&envelope["delta"]).unwrap();
            match state {
                "sealed" => f.append(vec![declaration(&publisher), entry(envelope.clone())]),
                "pending" => {
                    f.db.record_accepted_delta(&publisher.domain, &id, &envelope, 0, url, &id)
                        .unwrap()
                }
                _ => {
                    f.db.queue_delta(&publisher.domain, &id, &envelope, url, &id, 1)
                        .unwrap()
                }
            }
            chain.push((id, envelope));
        }
        let block_path = f.directory.path().join("log/blocks/000000000.json.zst");
        let block_bytes = std::fs::read(&block_path).unwrap();
        f.connection()
            .execute_batch("DELETE FROM seen_deltas; DELETE FROM url_tips;")
            .unwrap();
        f.legacy();
        for _ in 0..2 {
            let db = f.reopen().unwrap();
            for (id, _) in &chain {
                assert!(
                    db.is_delta_seen_for(id, &publisher.domain).unwrap(),
                    "{version}"
                );
            }
            assert_eq!(
                db.url_tip(&publisher.domain, url).unwrap().as_deref(),
                Some(chain[2].0.as_str())
            );
            assert_eq!(std::fs::read(&block_path).unwrap(), block_bytes);
            assert_eq!(
                db.peek_pending_entries().unwrap().0[0].entry_json,
                chain[1].1
            );
            let raw: Vec<u8> = f
                .connection()
                .query_row("SELECT entry_json FROM queued_deltas", [], |row| row.get(0))
                .unwrap();
            assert_eq!(raw, serde_json::to_vec(&chain[2].1).unwrap());
            let completed: i64 = f
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM delta_index_reconciliation",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(completed, 1);
        }
    }
}

#[test]
fn retained_version_and_field_failures_preserve_indexes_and_precedence() {
    for state in ["sealed", "pending", "recovery"] {
        for (version, malformed_field, expected) in [
            ("2.0.0".into(), false, "WIST1-E15"),
            (format!("{}.0.0", "9".repeat(80)), false, "WIST1-E15"),
            ("1.01.0".into(), false, "WIST1-E14"),
            ("1.0.0+build".into(), false, "WIST1-E14"),
            ("1.0.0".into(), true, "WIST1-E14"),
            ("2.0.0".into(), true, "WIST1-E14"),
        ] {
            let f = Fixture::new();
            let publisher = make_publisher("example.com");
            let url = "https://example.com/";
            let (_, mut envelope) = delta(&publisher, url, "body", None);
            envelope["delta"]["wist_version"] = json!(version);
            if malformed_field {
                envelope["delta"]["meta"]["lang"] = json!("EN");
            }
            let envelope = wist_core::envelope::sign_envelope(
                &envelope["delta"],
                "delta",
                "k1",
                &publisher.sk,
            )
            .unwrap();
            let id = wist_core::delta::delta_id(&envelope["delta"]).unwrap();
            match state {
                "sealed" => f.append(vec![declaration(&publisher), entry(envelope)]),
                "pending" => {
                    f.db.record_accepted_delta(&publisher.domain, &id, &envelope, 0, url, &id)
                        .unwrap()
                }
                _ => {
                    f.db.queue_delta(&publisher.domain, &id, &envelope, url, &id, 0)
                        .unwrap()
                }
            }
            f.connection()
                .execute_batch("DELETE FROM seen_deltas; DELETE FROM url_tips;")
                .unwrap();
            f.db.insert_seen_delta("residue", &publisher.domain)
                .unwrap();
            f.db.set_url_tip(url, &publisher.domain, "residue").unwrap();
            f.legacy();
            for _ in 0..2 {
                let error = match f.reopen() {
                    Ok(_) => panic!("accepted {state}: {version}, malformed={malformed_field}"),
                    Err(error) => error.to_string(),
                };
                assert!(
                    error.contains(expected),
                    "{state}: {version}, malformed={malformed_field}: {error}"
                );
                assert!(f.db.is_delta_seen("residue").unwrap());
                assert!(!f.db.is_delta_seen(&id).unwrap());
                assert_eq!(
                    f.db.url_tip(&publisher.domain, url).unwrap().as_deref(),
                    Some("residue")
                );
                let completed: bool = f.connection().query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'delta_index_reconciliation')", [], |row| row.get(0)).unwrap();
                assert!(!completed);
            }
        }
    }
}

#[test]
fn missing_content_and_predecessor_vectors_stop_restoration_atomically() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/delta-fields.json")).unwrap(),
    )
    .unwrap();
    let sources: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/declaration-fields.json")).unwrap(),
    )
    .unwrap();
    let mut cases = 0;
    for case in vector["cases"].as_array().unwrap() {
        let allowed = case["allowed"].as_array().unwrap();
        if !allowed
            .iter()
            .any(|code| code == "WIST1-E09" || code == "WIST1-E07")
        {
            continue;
        }
        cases += 1;
        for store in ["sealed", "pending", "recovery"] {
            let f = Fixture::new();
            let body = &case["envelope"];
            let domain = body["delta"]["publisher"].as_str().unwrap();
            let url = body["delta"]["url"].as_str().unwrap();
            let id = case["id"].as_str().unwrap();
            f.append(vec![
                json!({"type":"publisher_declaration", "body":sources["stored"]}),
            ]);
            match store {
                "sealed" => f.append(vec![entry(body.clone())]),
                "pending" => {
                    f.db.record_accepted_delta(domain, id, body, 0, url, id)
                        .unwrap()
                }
                _ => f.db.queue_delta(domain, id, body, url, id, 0).unwrap(),
            }
            f.connection()
                .execute_batch("DELETE FROM seen_deltas; DELETE FROM url_tips;")
                .unwrap();
            f.db.insert_seen_delta("residue", domain).unwrap();
            f.db.set_url_tip(url, domain, "residue").unwrap();
            f.legacy();
            for _ in 0..2 {
                let context = format!("{}: {store}", case["name"]);
                let error = f.reopen().err().expect(&context).to_string();
                assert!(
                    allowed
                        .iter()
                        .any(|code| error.contains(code.as_str().unwrap())),
                    "{context}: {error}"
                );
                assert!(f.db.is_delta_seen("residue").unwrap(), "{context}");
                assert!(!f.db.is_delta_seen(id).unwrap(), "{context}");
                assert_eq!(
                    f.db.url_tip(domain, url).unwrap().as_deref(),
                    Some("residue"),
                    "{context}"
                );
                let marker: bool = f.connection().query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'delta_index_reconciliation')", [], |row| row.get(0)).unwrap();
                assert!(!marker, "{context}");
                let retained = match store {
                    "sealed" => {
                        let bytes =
                            std::fs::read(f.directory.path().join("log/blocks/000000001.json.zst"))
                                .unwrap();
                        let block: Value =
                            serde_json::from_slice(&zstd::decode_all(&bytes[..]).unwrap()).unwrap();
                        block["entries"][0]["body"].clone()
                    }
                    _ => {
                        let query = if store == "pending" {
                            "SELECT entry_json FROM pending_entries"
                        } else {
                            "SELECT entry_json FROM queued_deltas"
                        };
                        let bytes: Vec<u8> = f
                            .connection()
                            .query_row(query, [], |row| row.get(0))
                            .unwrap();
                        serde_json::from_slice(&bytes).unwrap()
                    }
                };
                assert_eq!(retained, *body, "{context}");
            }
        }
    }
    assert_eq!(cases, 10);
}

#[test]
fn retained_change_types_require_content_and_preserve_contentless_successors() {
    for store in ["sealed", "pending", "recovery"] {
        for (kind, with_payload, with_prev, expected) in [
            ("update", true, false, Some("WIST1-E07")),
            ("update", false, true, Some("WIST1-E09")),
            ("new", false, true, Some("WIST1-E09")),
            ("delete", false, true, None),
            ("attest", false, true, None),
            ("new", true, true, None),
            ("update", true, true, None),
        ] {
            let f = Fixture::new();
            let publisher = make_publisher("example.com");
            let url = "https://example.com/";
            let (prior_id, prior) = delta(&publisher, url, "first", None);
            f.append(vec![declaration(&publisher), entry(prior)]);
            let (_, mut body) = delta(&publisher, url, "second", Some(&prior_id));
            body["delta"]["change_type"] = json!(kind);
            if !with_payload {
                body["delta"].as_object_mut().unwrap().remove("payload");
            }
            if !with_prev {
                body["delta"].as_object_mut().unwrap().remove("prev");
            }
            let body =
                wist_core::envelope::sign_envelope(&body["delta"], "delta", "k1", &publisher.sk)
                    .unwrap();
            let id = wist_core::delta::delta_id(&body["delta"]).unwrap();
            match store {
                "sealed" => f.append(vec![entry(body)]),
                "pending" => {
                    f.db.record_accepted_delta(&publisher.domain, &id, &body, 0, url, &id)
                        .unwrap()
                }
                _ => {
                    f.db.queue_delta(&publisher.domain, &id, &body, url, &id, 0)
                        .unwrap()
                }
            }
            f.legacy();
            for _ in 0..2 {
                let context = format!("{store}: {kind}, payload={with_payload}, prev={with_prev}");
                if let Some(code) = expected {
                    let error = f.reopen().err().expect(&context).to_string();
                    assert!(error.contains(code), "{context}: {error}");
                } else {
                    let db = f.reopen().unwrap();
                    assert_eq!(
                        db.url_tip(&publisher.domain, url).unwrap().as_deref(),
                        Some(id.as_str()),
                        "{context}"
                    );
                    assert!(
                        db.is_delta_seen_for(&prior_id, &publisher.domain).unwrap(),
                        "{context}"
                    );
                    assert!(
                        db.is_delta_seen_for(&id, &publisher.domain).unwrap(),
                        "{context}"
                    );
                }
            }
        }
    }
}

#[test]
fn signed_predecessor_times_reconcile_across_sealed_and_retained_chains() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/declaration-fields.json")).unwrap(),
    )
    .unwrap();
    let mut cases = 0;
    for case in vector["relation_cases"].as_array().unwrap() {
        if case["kind"] != "predecessor" {
            continue;
        }
        cases += 1;
        for (prior_store, next_store) in [
            ("same_block", "same_block"),
            ("sealed", "sealed"),
            ("sealed", "pending"),
            ("sealed", "recovery"),
            ("pending", "pending"),
            ("pending", "recovery"),
            ("recovery", "pending"),
            ("recovery", "recovery"),
        ] {
            let f = Fixture::new();
            let domain = case["envelope"]["delta"]["publisher"].as_str().unwrap();
            let url = case["envelope"]["delta"]["url"].as_str().unwrap();
            let predecessor = &case["predecessor"];
            let envelope = &case["envelope"];
            let prior_id = wist_core::delta::delta_id(&predecessor["delta"]).unwrap();
            let id = wist_core::delta::delta_id(&envelope["delta"]).unwrap();
            f.append(vec![
                json!({"type":"publisher_declaration", "body":vector["stored"]}),
            ]);
            if prior_store == "same_block" {
                f.append(vec![entry(predecessor.clone()), entry(envelope.clone())]);
            } else {
                for (store, id, body) in [
                    (prior_store, &prior_id, predecessor),
                    (next_store, &id, envelope),
                ] {
                    match store {
                        "sealed" => f.append(vec![entry(body.clone())]),
                        "pending" => {
                            f.db.record_accepted_delta(domain, id, body, 0, url, id)
                                .unwrap()
                        }
                        _ => f.db.queue_delta(domain, id, body, url, id, 1).unwrap(),
                    }
                }
            }
            f.connection()
                .execute_batch("DELETE FROM seen_deltas; DELETE FROM url_tips;")
                .unwrap();
            f.db.insert_seen_delta("residue", domain).unwrap();
            f.db.set_url_tip(url, domain, "residue").unwrap();
            f.legacy();
            let stored: Vec<(String, Vec<u8>)> = f
                .connection()
                .prepare("SELECT 'pending', entry_json FROM pending_entries UNION ALL SELECT 'recovery', entry_json FROM queued_deltas")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            for _ in 0..2 {
                let context = format!("{}: {prior_store} -> {next_store}", case["name"]);
                if case["expected"] == "relation_satisfied" {
                    let db = f.reopen().unwrap();
                    assert!(
                        db.is_delta_seen_for(&prior_id, domain).unwrap(),
                        "{context}"
                    );
                    assert!(db.is_delta_seen_for(&id, domain).unwrap(), "{context}");
                    assert!(!db.is_delta_seen("residue").unwrap(), "{context}");
                    assert_eq!(
                        db.url_tip(domain, url).unwrap().as_deref(),
                        Some(id.as_str()),
                        "{context}"
                    );
                } else {
                    let error = f.reopen().err().expect(&context).to_string();
                    assert!(error.contains("WIST1-E07"), "{context}: {error}");
                    assert!(f.db.is_delta_seen("residue").unwrap(), "{context}");
                    assert!(!f.db.is_delta_seen(&prior_id).unwrap(), "{context}");
                    assert!(!f.db.is_delta_seen(&id).unwrap(), "{context}");
                    assert_eq!(
                        f.db.url_tip(domain, url).unwrap().as_deref(),
                        Some("residue"),
                        "{context}"
                    );
                    let marker: bool = f.connection().query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'delta_index_reconciliation')", [], |row| row.get(0)).unwrap();
                    assert!(!marker, "{context}");
                }
                let retained: Vec<(String, Vec<u8>)> = f
                    .connection()
                    .prepare("SELECT 'pending', entry_json FROM pending_entries UNION ALL SELECT 'recovery', entry_json FROM queued_deltas")
                    .unwrap()
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                assert_eq!(retained, stored, "{context}");
            }
        }
    }
    assert_eq!(cases, 3);
}

#[test]
fn observation_history_stays_with_its_publisher_through_identity_reset() {
    for (at, accepted) in [
        ("2027-01-15T07:00:00.00000000000000000001Z", true),
        ("2027-01-15T04:00:00.000-03:00", false),
        ("2027-01-15T06:59:59.99999999999999999999Z", false),
    ] {
        let f = Fixture::new();
        let url = "https://shared.example/page";
        let a = make_publisher_with_scope("a.example", &["shared.example"]);
        let b = make_publisher_with_scope("b.example", &["shared.example"]);
        let mut roots = Vec::new();
        for (publisher, at) in [(&a, "2027-01-15T07:00:00Z"), (&b, "2027-01-15T07:00:01Z")] {
            let (_, mut body) = delta(publisher, url, "root", None);
            body["delta"]["observed_at"] = json!(at);
            let body =
                wist_core::envelope::sign_envelope(&body["delta"], "delta", "k1", &publisher.sk)
                    .unwrap();
            let id = wist_core::delta::delta_id(&body["delta"]).unwrap();
            roots.push((id, body));
        }
        f.append(vec![
            declaration(&a),
            declaration(&b),
            entry(roots[0].1.clone()),
            entry(roots[1].1.clone()),
        ]);
        let key = crypto::SigningKey::from_seed(&[2; 32]);
        let mut replacement = declaration(&a)["body"]["publisher"].clone();
        replacement["seq"] = json!(1);
        replacement["prev_declaration"] =
            json!(clave::declaration::inner_hash(&declaration(&a)["body"]).unwrap());
        replacement["keys"][0]["public_key"] = json!(seed_public_b64u(&[2; 32]));
        let replacement =
            wist_core::envelope::sign_envelope(&replacement, "publisher", "k1", &key).unwrap();
        let (_, mut body) = delta(&a, url, "after reset", Some(&roots[0].0));
        body["delta"]["observed_at"] = json!(at);
        let body = wist_core::envelope::sign_envelope(&body["delta"], "delta", "k1", &key).unwrap();
        let id = wist_core::delta::delta_id(&body["delta"]).unwrap();
        f.append(vec![
            json!({"type":"publisher_declaration", "body":replacement}),
            entry(body),
        ]);
        f.legacy();
        if accepted {
            let db = f.reopen().unwrap();
            assert_eq!(
                db.url_tip(&a.domain, url).unwrap().as_deref(),
                Some(id.as_str())
            );
            assert_eq!(
                db.url_tip(&b.domain, url).unwrap().as_deref(),
                Some(roots[1].0.as_str())
            );
        } else {
            assert!(f.reopen().err().unwrap().to_string().contains("WIST1-E07"));
        }
    }
}
