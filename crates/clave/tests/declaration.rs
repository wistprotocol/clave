use clave::declaration::{evaluate, Decision};
use serde_json::{json, Value};
use wist_core::crypto::SigningKey;

fn key_json(key_id: &str, seed: &[u8; 32], valid_from: &str) -> Value {
    let public_key = wist_core::crypto::b64u_encode(
        &ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    );
    json!({"key_id": key_id, "alg": "Ed25519", "public_key": public_key, "valid_from": valid_from})
}

fn declaration(
    seq: u64,
    prev: Option<&str>,
    keys: Vec<Value>,
    recovery_keys: Option<Vec<Value>>,
    signer: (&str, &[u8; 32]),
) -> Value {
    let mut publisher = json!({
        "wist_version": "1.0.0",
        "domain": "example.com",
        "keys": keys,
        "seq": seq,
    });
    if let Some(p) = prev {
        publisher["prev_declaration"] = p.into();
    }
    if let Some(r) = recovery_keys {
        publisher["recovery_keys"] = Value::Array(r);
    }
    let sk = SigningKey::from_seed(signer.1);
    serde_json::to_value(
        wist_core::envelope::sign_envelope(&publisher, "publisher", signer.0, &sk).unwrap(),
    )
    .unwrap()
}

fn hash_of(doc: &Value) -> String {
    use sha2::Digest;
    let canonical = wist_core::jcs::canonicalize(&doc["publisher"]).unwrap();
    format!(
        "sha256:{}",
        wist_core::crypto::hex_encode(&sha2::Sha256::digest(&canonical))
    )
}

const K1: [u8; 32] = [1u8; 32];
const K2: [u8; 32] = [2u8; 32];
const R1: [u8; 32] = [3u8; 32];
const X1: [u8; 32] = [4u8; 32];

fn base() -> Value {
    declaration(
        0,
        None,
        vec![key_json("k1", &K1, "2026-08-01T00:00:00Z")],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("k1", &K1),
    )
}

#[test]
fn unchanged_when_same_seq_and_content() {
    let stored = base();
    assert_eq!(
        evaluate(&stored, &stored.clone(), false).unwrap(),
        Decision::Unchanged
    );
}

#[test]
fn same_seq_different_content_is_rejected() {
    let stored = base();
    let mutated = declaration(
        0,
        None,
        vec![key_json("k1", &K1, "2026-08-02T00:00:00Z")],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("k1", &K1),
    );
    assert!(evaluate(&stored, &mutated, false).is_err());
}

#[test]
fn lower_seq_is_rejected() {
    let stored = declaration(
        2,
        Some("sha256:aa"),
        vec![key_json("k1", &K1, "2026-08-01T00:00:00Z")],
        None,
        ("k1", &K1),
    );
    let stale = declaration(
        1,
        Some("sha256:bb"),
        vec![key_json("k1", &K1, "2026-08-01T00:00:00Z")],
        None,
        ("k1", &K1),
    );
    assert!(evaluate(&stored, &stale, false).is_err());
}

#[test]
fn prev_declaration_mismatch_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some("sha256:0000"),
        vec![
            key_json("k1", &K1, "2026-08-01T00:00:00Z"),
            key_json("k2", &K2, "2026-08-10T00:00:00Z"),
        ],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("k1", &K1),
    );
    assert!(evaluate(&stored, &next, false).is_err());
}

#[test]
fn ordinary_rotation_signed_by_stored_key() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![
            key_json("k1", &K1, "2026-08-01T00:00:00Z"),
            key_json("k2", &K2, "2026-08-10T00:00:00Z"),
        ],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("k1", &K1),
    );
    assert_eq!(evaluate(&stored, &next, false).unwrap(), Decision::Ordinary);
}

#[test]
fn signature_not_matching_named_key_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("k2", &K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("k1", &K2),
    );
    assert!(evaluate(&stored, &next, false).is_err());
}

#[test]
fn recovery_rotation_signed_by_stored_recovery_key() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("k2", &K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("r1", &R1),
    );
    assert_eq!(evaluate(&stored, &next, false).unwrap(), Decision::Recovery);
}

#[test]
fn recovery_signed_declaration_may_replace_recovery_keys() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("k2", &K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json("r2", &X1, "2026-08-10T00:00:00Z")]),
        ("r1", &R1),
    );
    assert_eq!(evaluate(&stored, &next, false).unwrap(), Decision::Recovery);
}

#[test]
fn fresh_identity_signed_by_own_new_key() {
    let stored = declaration(
        0,
        None,
        vec![key_json("k1", &K1, "2026-08-01T00:00:00Z")],
        None,
        ("k1", &K1),
    );
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("kx", &X1, "2026-08-10T00:00:00Z")],
        None,
        ("kx", &X1),
    );
    assert_eq!(
        evaluate(&stored, &next, false).unwrap(),
        Decision::FreshIdentity
    );
}

#[test]
fn unknown_signer_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("k2", &K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("nope", &X1),
    );
    assert!(evaluate(&stored, &next, false).is_err());
}

#[test]
fn altering_recovery_keys_without_recovery_signature_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("k1", &K1, "2026-08-01T00:00:00Z")],
        Some(vec![key_json("r2", &X1, "2026-08-10T00:00:00Z")]),
        ("k1", &K1),
    );
    assert!(evaluate(&stored, &next, false).is_err());
}

#[test]
fn dropping_recovery_keys_without_recovery_signature_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("k1", &K1, "2026-08-01T00:00:00Z")],
        None,
        ("k1", &K1),
    );
    assert!(evaluate(&stored, &next, false).is_err());
}

#[test]
fn establishing_recovery_keys_with_ordinary_signature_is_allowed() {
    let stored = declaration(
        0,
        None,
        vec![key_json("k1", &K1, "2026-08-01T00:00:00Z")],
        None,
        ("k1", &K1),
    );
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("k1", &K1, "2026-08-01T00:00:00Z")],
        Some(vec![key_json("r1", &R1, "2026-08-10T00:00:00Z")]),
        ("k1", &K1),
    );
    assert_eq!(evaluate(&stored, &next, false).unwrap(), Decision::Ordinary);
}

#[test]
fn fresh_identity_must_carry_recovery_keys_byte_identical() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json("kx", &X1, "2026-08-10T00:00:00Z")],
        None,
        ("kx", &X1),
    );
    assert!(evaluate(&stored, &next, false).is_err());
}

#[test]
fn fresh_identity_is_rejected_while_recovery_window_open() {
    let stored = declaration(
        1,
        Some("sha256:aa"),
        vec![key_json("k2", &K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("r1", &R1),
    );
    let thief = declaration(
        2,
        Some(&hash_of(&stored)),
        vec![key_json("kx", &X1, "2026-08-11T00:00:00Z")],
        Some(vec![key_json("r1", &R1, "2026-08-01T00:00:00Z")]),
        ("kx", &X1),
    );
    assert!(evaluate(&stored, &thief, true).is_err());
    assert!(evaluate(&stored, &thief, false).is_ok());
}

#[test]
fn domain_change_is_rejected() {
    let stored = base();
    let mut publisher = stored["publisher"].clone();
    publisher["domain"] = "other.example".into();
    publisher["seq"] = 1.into();
    publisher["prev_declaration"] = hash_of(&stored).into();
    let sk = SigningKey::from_seed(&K1);
    let next = serde_json::to_value(
        wist_core::envelope::sign_envelope(&publisher, "publisher", "k1", &sk).unwrap(),
    )
    .unwrap();
    assert!(evaluate(&stored, &next, false).is_err());
}

fn spec_dir() -> std::path::PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
}

#[test]
fn spec_declaration_sequence_vector() {
    let path = spec_dir().join("vectors/wist1/declaration-sequence.json");
    let vector: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let window_open = vector["recovery_window_open"].as_bool().unwrap();
    let cases = vector["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let got = evaluate(&case["stored"], &case["fetched"], window_open);
        match case["expected"].as_str().unwrap() {
            "idempotent" => assert_eq!(got.as_ref().ok(), Some(&Decision::Unchanged), "{name}"),
            "ordinary_rotation" => {
                assert_eq!(got.as_ref().ok(), Some(&Decision::Ordinary), "{name}")
            }
            "recovery_rotation" => {
                assert_eq!(got.as_ref().ok(), Some(&Decision::Recovery), "{name}")
            }
            "fresh_identity" => {
                assert_eq!(got.as_ref().ok(), Some(&Decision::FreshIdentity), "{name}")
            }
            "WIST1-E08" => assert!(got.is_err(), "{name}: expected WIST1-E08, got {got:?}"),
            other => panic!("{name}: unknown expected outcome {other}"),
        }
    }
}
