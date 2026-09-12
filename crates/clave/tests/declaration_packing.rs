use clave::history::declarations::Declarations;
use serde_json::{json, Value};
use wist_core::crypto::SigningKey;
use wist_core::{block, envelope, jcs, merkle};

fn entry(declaration: &Value) -> Value {
    json!({"type": "publisher_declaration", "body": declaration})
}

fn leaf(declaration: &Value) -> [u8; 32] {
    merkle::leaf_hash(&jcs::canonicalize(&entry(declaration)).unwrap())
}

fn read_block(directory: &std::path::Path, height: u64) -> Value {
    let compressed =
        std::fs::read(directory.join(format!("log/blocks/{height:09}.json.zst"))).unwrap();
    serde_json::from_slice(&zstd::decode_all(&compressed[..]).unwrap()).unwrap()
}

#[test]
fn capped_declaration_chains_progress_when_successor_hashes_first() {
    check_capped_chain(false);
}

#[test]
fn smaller_successor_waits_until_its_predecessor_fits() {
    check_capped_chain(true);
}

fn check_capped_chain(oversized_predecessor: bool) {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example.com", data.path()).unwrap();
    let database = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&database).unwrap();
    let publisher_key = SigningKey::from_seed(&[71; 32]);
    let public_key = wist_core::crypto::b64u_encode(
        &ed25519_dalek::SigningKey::from_bytes(&[71; 32])
            .verifying_key()
            .to_bytes(),
    );
    let initial = envelope::sign_envelope(
        &json!({
            "wist_version": "1.0.0",
            "domain": "example.com",
            "seq": 0,
            "keys": [{"key_id": "k1", "alg": "Ed25519", "public_key": public_key,
                "valid_from": "2026-08-01T00:00:00Z"}]
        }),
        "publisher",
        "k1",
        &publisher_key,
    )
    .unwrap();
    db.record_publisher_declaration(
        "example.com",
        &serde_json::to_vec(&initial).unwrap(),
        "k1",
        &public_key,
        &initial,
    )
    .unwrap();
    let log_key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let start = 1_800_000_000;
    clave::seal::run(&db, data.path(), &log_key, start).unwrap();

    let mut predecessor_body = initial["publisher"].clone();
    predecessor_body["seq"] = json!(1);
    predecessor_body["prev_declaration"] = clave::declaration::inner_hash(&initial).unwrap().into();
    if oversized_predecessor {
        predecessor_body["subdomain_scope"] = json!((0..32)
            .map(|n| format!("s{n}.example.com"))
            .collect::<Vec<_>>());
    }
    let predecessor =
        envelope::sign_envelope(&predecessor_body, "publisher", "k1", &publisher_key).unwrap();
    let successor = (0..256)
        .find_map(|nonce| {
            let mut body = predecessor_body.clone();
            body["seq"] = json!(2);
            body["prev_declaration"] = clave::declaration::inner_hash(&predecessor).unwrap().into();
            body["subdomain_scope"] = json!([format!("s{nonce}.example.com")]);
            let candidate =
                envelope::sign_envelope(&body, "publisher", "k1", &publisher_key).unwrap();
            (leaf(&candidate) < leaf(&predecessor)).then_some(candidate)
        })
        .expect("a deterministic successor hashes before its predecessor");
    clave::declaration::evaluate(&initial, &predecessor).unwrap();
    clave::declaration::evaluate(&predecessor, &successor).unwrap();

    let mut candidate = read_block(data.path(), 0);
    candidate["header"]["prev_block_hash"] =
        block::block_hash(&candidate["header"]).unwrap().into();
    candidate["header"]["block_number"] = json!(1);
    candidate["header"]["entry_count"] = json!(1);
    candidate["entries"] = json!([entry(&predecessor)]);
    let predecessor_bytes = jcs::canonicalize(&candidate).unwrap().len();
    candidate["entries"] = json!([entry(&successor)]);
    let successor_bytes = jcs::canonicalize(&candidate).unwrap().len();
    let cap = predecessor_bytes.max(successor_bytes);
    candidate["entries"] = json!([entry(&successor), entry(&predecessor)]);
    candidate["header"]["entry_count"] = json!(2);
    assert!(jcs::canonicalize(&candidate).unwrap().len() > cap);
    let initial_cap = if oversized_predecessor {
        assert!(predecessor_bytes > successor_bytes);
        successor_bytes
    } else {
        cap
    };
    db.set_param("block_decompressed_cap_bytes", initial_cap as i64)
        .unwrap();
    for declaration in [&predecessor, &successor] {
        db.update_publisher_declaration(
            "example.com",
            &serde_json::to_vec(declaration).unwrap(),
            "k1",
            &public_key,
            declaration,
        )
        .unwrap();
    }
    drop(db);

    let first_height = if oversized_predecessor {
        let db = clave::db::Db::open(&database).unwrap();
        let report = clave::seal::run(&db, data.path(), &log_key, start + 3600).unwrap();
        assert_eq!(report.entry_count, 0);
        assert_eq!(read_block(data.path(), 1)["entries"], json!([]));
        assert_eq!(db.peek_pending_entries().unwrap().0.len(), 2);
        let reconstructed =
            Declarations::reconstruct(data.path(), db.last_block().unwrap()).unwrap();
        assert_eq!(
            reconstructed.domains()["example.com"].current().envelope(),
            &initial
        );
        db.set_param("block_decompressed_cap_bytes", cap as i64)
            .unwrap();
        2
    } else {
        1
    };
    for (height, expected) in [(first_height, &predecessor), (first_height + 1, &successor)] {
        let db = clave::db::Db::open(&database).unwrap();
        let report =
            clave::seal::run(&db, data.path(), &log_key, start + height as i64 * 3600).unwrap();
        assert_eq!(report.entry_count, 1);
        let sealed = read_block(data.path(), height);
        assert_eq!(sealed["entries"], json!([entry(expected)]));
        assert!(jcs::canonicalize(&sealed).unwrap().len() <= cap);
        block::verify_block(&sealed, &log_key.public()).unwrap();
        let reconstructed =
            Declarations::reconstruct(data.path(), db.last_block().unwrap()).unwrap();
        assert_eq!(
            reconstructed.domains()["example.com"].current().envelope(),
            expected
        );
        assert_eq!(
            db.peek_pending_entries().unwrap().0.len(),
            (first_height + 1 - height) as usize
        );
    }
}
