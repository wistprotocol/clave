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
