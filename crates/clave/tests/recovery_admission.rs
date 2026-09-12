mod common;

use clave::db::Db;
use clave::declaration::{evaluate_with_heads, Decision};
use clave::history::declarations::Declarations;
use serde_json::{json, Value};
use wist_core::{block, envelope, jcs};

const DOMAIN: &str = "example.com";

fn store(db: &Db, doc: &Value) {
    let key = &doc["publisher"]["keys"][0];
    let raw = serde_json::to_vec(doc).unwrap();
    if db.get_publisher(DOMAIN).unwrap().is_none() {
        db.record_publisher_declaration(
            DOMAIN,
            &raw,
            key["key_id"].as_str().unwrap(),
            key["public_key"].as_str().unwrap(),
            doc,
        )
        .unwrap();
    } else {
        db.update_publisher_declaration(
            DOMAIN,
            &raw,
            key["key_id"].as_str().unwrap(),
            key["public_key"].as_str().unwrap(),
            doc,
        )
        .unwrap();
    }
}

fn append(db: &Db, path: &std::path::Path, doc: &Value) {
    let height = doc["header"]["block_number"].as_u64().unwrap();
    let bytes = jcs::canonicalize(doc).unwrap();
    std::fs::write(
        path.join(format!("log/blocks/{height:09}.json.zst")),
        zstd::bulk::compress(&bytes, 1).unwrap(),
    )
    .unwrap();
    let pending = db.peek_pending_entries().unwrap().0;
    let rowids = pending
        .iter()
        .filter(|row| {
            doc["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["body"] == row.entry_json)
        })
        .map(|row| row.rowid)
        .collect::<Vec<_>>();
    db.commit_seal(
        &rowids,
        height,
        &block::block_hash(&doc["header"]).unwrap(),
        doc["header"]["sealed_at"].as_str().unwrap(),
        &[],
        &[],
        &[],
        &[],
        bytes.len() as u64,
    )
    .unwrap();
}

fn current(db: &Db) -> Value {
    serde_json::from_slice(&db.get_publisher_declaration(DOMAIN).unwrap().unwrap()).unwrap()
}

#[test]
fn signed_pending_declaration_settlement_vectors_survive_reopen_and_repeat() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist1/recovery-admission.json")).unwrap(),
    )
    .unwrap();
    let declarations = &vector["declarations"];
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example.com", data.path()).unwrap();
        let key = wist_core::crypto::SigningKey::from_seed(&std::array::from_fn(|i| i as u8));
        let anchor = envelope::sign_envelope(
            &json!({
                "wist_version": "1.0.0", "log_id": "log.example.com",
                "genesis_key": {"key_id": "test-log-k1", "alg": "Ed25519",
                    "public_key": vector["log_key"]["public_key"]},
                "created_at": "2026-08-02T00:00:00Z"
            }),
            "anchor",
            "test-log-k1",
            &key,
        )
        .unwrap();
        std::fs::write(
            data.path().join("anchor.json"),
            jcs::canonicalize(&anchor).unwrap(),
        )
        .unwrap();
        let database = data.path().join("clave.sqlite");
        let mut db = Db::open(&database).unwrap();
        for block in vector["blocks"].as_array().unwrap() {
            for entry in block["entries"].as_array().unwrap() {
                store(&db, &entry["body"]);
            }
            append(&db, data.path(), block);
        }
        assert_eq!(
            db.last_block().unwrap().unwrap().block_hash,
            vector["pinned_head"]
        );
        db.open_recovery_window(
            DOMAIN,
            &serde_json::to_vec(&declarations["owner"]).unwrap(),
            &serde_json::to_vec(&declarations["initial"]).unwrap(),
        )
        .unwrap();
        db.activate_recovery_window(DOMAIN, 1, vector["deadline"].as_str().unwrap())
            .unwrap();
        for declaration in case["admitted"].as_array().unwrap() {
            store(&db, &declarations[declaration.as_str().unwrap()]);
        }
        append(&db, data.path(), &case["last_inside_block"]);
        assert_eq!(
            db.last_block().unwrap().unwrap().block_hash,
            case["last_inside_pin"]
        );
        db = Db::open(&database).unwrap();
        let before = current(&db);
        clave::recovery::settle(&db, data.path(), "2026-08-11T00:59:59.999999999Z").unwrap();
        assert_eq!(current(&db), before, "{name}");
        let deadline = vector["deadline"].as_str().unwrap();
        clave::recovery::settle(&db, data.path(), deadline).unwrap();
        db = Db::open(&database).unwrap();
        let expected = &case["expected_settlement"];
        assert_eq!(
            current(&db),
            declarations[expected["current"].as_str().unwrap()],
            "{name}"
        );
        assert_eq!(
            db.highest_accepted_declaration_seq(DOMAIN).unwrap(),
            expected["floor"].as_u64(),
            "{name}"
        );
        assert!(db.get_recovery_window(DOMAIN).unwrap().is_none(), "{name}");
        let retained = expected["retained"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| declarations[name.as_str().unwrap()].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            db.peek_pending_entries()
                .unwrap()
                .0
                .into_iter()
                .map(|row| row.entry_json)
                .collect::<Vec<_>>(),
            retained,
            "{name}"
        );
        for probe in case["at_deadline"].as_array().unwrap() {
            let doc = &declarations[probe["declaration"].as_str().unwrap()];
            let result = evaluate_with_heads(
                &current(&db),
                None,
                db.highest_accepted_declaration_seq(DOMAIN)
                    .unwrap()
                    .unwrap(),
                doc,
            );
            let outcome = match result {
                Ok(Decision::FreshIdentity) => {
                    store(&db, doc);
                    "fresh_identity"
                }
                Err((code, _)) => code,
                other => panic!("{name}: {other:?}"),
            };
            assert_eq!(outcome, probe["expected"], "{name}");
        }
        db = Db::open(&database).unwrap();
        clave::recovery::settle(&db, data.path(), deadline).unwrap();
        let expected = &case["expected_after_repeat"];
        assert_eq!(
            current(&db),
            declarations[expected["current"].as_str().unwrap()],
            "{name}"
        );
        assert_eq!(
            db.highest_accepted_declaration_seq(DOMAIN).unwrap(),
            expected["floor"].as_u64(),
            "{name}"
        );
        let mut pending = db
            .peek_pending_entries()
            .unwrap()
            .0
            .into_iter()
            .map(|row| json!({"type": row.entry_type, "body": row.entry_json}))
            .collect::<Vec<_>>();
        pending
            .sort_by_key(|entry| wist_core::merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()));
        let history = Declarations::reconstruct(data.path(), db.last_block().unwrap()).unwrap();
        let entries = pending
            .iter()
            .map(|entry| serde_json::from_value(entry.clone()).unwrap())
            .collect::<Vec<_>>();
        let projection = history.project(deadline, 7, &entries).unwrap();
        let state = &projection.domains()[DOMAIN];
        assert_eq!(
            state.current().envelope(),
            &declarations[case["expected_log"]["current"].as_str().unwrap()],
            "{name}"
        );
        assert_eq!(
            state.highest_accepted_seq(),
            case["expected_log"]["floor"].as_u64().unwrap(),
            "{name}"
        );
        if let Some(owner) = case["expected_window_owner"].as_str() {
            assert_eq!(
                state.window().unwrap().owner().envelope(),
                &declarations[owner],
                "{name}"
            );
        } else {
            assert!(state.window().is_none(), "{name}");
        }
    }
}
