mod common;

use clave::db::BlockRow;
use clave::history::payloads::PayloadSource;
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

    fn append(&mut self, mut entries: Vec<Value>) {
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
        let height = self.head.as_ref().map_or(0, |head| head.block_number + 1);
        let at = jiff::Timestamp::from_second(1_800_000_000 + height as i64 * 3600)
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
        assert_eq!(source.envelope(), &case["envelope"]);
        cases += 1;
    }
    assert_eq!(cases, 103);
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
