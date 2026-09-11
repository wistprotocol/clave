mod common;
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
        evaluate(&stored, &stored.clone()).unwrap(),
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
    assert!(evaluate(&stored, &mutated).is_err());
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
    assert!(evaluate(&stored, &stale).is_err());
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
    assert!(evaluate(&stored, &next).is_err());
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
    assert_eq!(evaluate(&stored, &next).unwrap(), Decision::Ordinary);
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
    assert!(evaluate(&stored, &next).is_err());
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
    assert_eq!(evaluate(&stored, &next).unwrap(), Decision::Recovery);
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
    assert_eq!(evaluate(&stored, &next).unwrap(), Decision::Recovery);
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
    assert_eq!(evaluate(&stored, &next).unwrap(), Decision::FreshIdentity);
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
    assert!(evaluate(&stored, &next).is_err());
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
    assert!(evaluate(&stored, &next).is_err());
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
    assert!(evaluate(&stored, &next).is_err());
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
    assert_eq!(evaluate(&stored, &next).unwrap(), Decision::Ordinary);
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
    assert!(evaluate(&stored, &next).is_err());
}

#[test]
fn fresh_identity_is_accepted_and_left_to_the_windows_settlement() {
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
    assert_eq!(
        evaluate(&stored, &thief).unwrap(),
        Decision::FreshIdentity,
        "an open window does not change acceptance; supersession happens at its end"
    );
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
    assert!(evaluate(&stored, &next).is_err());
}

#[test]
fn spec_declaration_sequence_vector() {
    let path = common::spec_dir().join("vectors/wist1/declaration-sequence.json");
    let vector: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let cases = vector["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let got = evaluate(&case["stored"], &case["fetched"]);
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

#[test]
fn spec_declaration_binding_vectors() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist1/declaration-binding.json")).unwrap(),
    )
    .unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let result = if case["stored"].is_null() {
            clave::declaration::evaluate_initial(&case["fetched"]).map(|_| "initial")
        } else {
            evaluate(&case["stored"], &case["fetched"]).map(|decision| match decision {
                Decision::Ordinary => "ordinary_rotation",
                Decision::Recovery => "recovery_rotation",
                Decision::FreshIdentity => "fresh_identity",
                Decision::Unchanged => "idempotent",
            })
        };
        let outcome = result.unwrap_or_else(|(code, _)| code);
        assert_eq!(
            outcome,
            case["expected"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn recovery_chain_membership_uses_authenticated_public_key() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist1/declaration-binding.json")).unwrap(),
    )
    .unwrap();
    for case in vector["cases"].as_array().unwrap() {
        if matches!(
            case["expected"].as_str(),
            Some(
                "ordinary_rotation"
                    | "recovery_rotation"
                    | "fresh_identity"
                    | "WIST1-E01"
                    | "WIST1-E02"
            )
        ) {
            assert_eq!(
                clave::declaration::follows_chain_head(&case["stored"], &case["fetched"]),
                matches!(
                    case["expected"].as_str(),
                    Some("ordinary_rotation" | "recovery_rotation")
                ),
                "{}",
                case["name"]
            );
        }
    }
}

#[test]
fn signed_delta_key_bound_orders_rfc3339_instants_exactly() {
    let sk = SigningKey::from_seed(&K1);
    let cases = [
        ("2026-08-04T10:00:00Z", "2026-08-04T10:00:00.5Z", true),
        ("2026-08-04T10:00:00.5Z", "2026-08-04T10:00:00Z", false),
        ("2026-08-04T10:00:00Z", "2026-08-04T10:00:00.0000Z", true),
        ("2026-08-04T10:00:00.10Z", "2026-08-04T10:00:00.1Z", true),
        (
            "2026-08-04T10:00:00.0000000001Z",
            "2026-08-04T10:00:00.0000000000Z",
            false,
        ),
        (
            "2026-08-04T10:00:00.0000000001Z",
            "2026-08-04T10:00:00.0000000002Z",
            true,
        ),
        (
            "2026-08-04T10:00:00.1000000000000000000000000001Z",
            "2026-08-04T10:00:00.1Z",
            false,
        ),
        ("2026-08-04T10:00:00Z", "2026-08-04T11:00:00+01:00", true),
        ("2026-08-04T10:00:00Z", "2026-08-04T10:30:00+01:00", false),
        ("2026-08-04T10:00:00Z", "2026-08-04T09:30:00-01:00", true),
        ("2026-08-04T10:00:00Z", "2026-08-04t10:00:00z", true),
        ("2026-08-04T10:00:00Z", "2026-08-04T10:00:00-00:00", true),
        ("2026-08-04T10:00:00+00:00", "2026-08-04T10:00:00Z", true),
        ("2026-08-04T00:00:00Z", "2026-08-03T23:59:59-00:01", true),
        (
            "2016-12-31T23:59:59.999999999999Z",
            "2016-12-31T23:59:60Z",
            true,
        ),
        (
            "2016-12-31T23:59:60Z",
            "2016-12-31T23:59:59.999999999999Z",
            false,
        ),
        (
            "2017-01-01T00:00:00Z",
            "2016-12-31T23:59:60.999999999999Z",
            false,
        ),
        (
            "2016-12-31T23:59:60.999999999999Z",
            "2017-01-01T00:00:00Z",
            true,
        ),
        (
            "2016-12-31T23:59:60.5Z",
            "2017-01-01T00:59:60.50+01:00",
            true,
        ),
        (
            "2016-12-31T23:59:60.5Z",
            "2016-12-31T18:29:60.4-05:30",
            false,
        ),
        ("0000-02-28T23:59:59Z", "0000-02-29T00:00:00Z", true),
        ("2000-02-29T23:59:59Z", "2000-03-01T00:00:00Z", true),
        ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00+23:59", false),
        ("9999-12-31T23:59:59Z", "9999-12-31T23:59:59-23:59", true),
    ];
    for (valid_from, observed_at, eligible) in cases {
        let key = serde_json::from_value(key_json("k1", &K1, valid_from)).unwrap();
        let delta = json!({"wist_version":"1.0.0", "url":"https://example.com/a", "change_type":"delete", "observed_at":observed_at, "prev":format!("sha256:{}", "0".repeat(64)), "meta":{"lang":"en"}});
        let signed = wist_core::envelope::sign_envelope(&delta, "delta", "k1", &sk).unwrap();
        assert_eq!(
            clave::declaration::verify_signed(&[&key], &signed, "delta", Some(observed_at)),
            if eligible { Ok(()) } else { Err("WIST1-E02") },
            "valid_from={valid_from}, observed_at={observed_at}"
        );
        if eligible {
            let mut tampered = signed;
            tampered["delta"]["url"] = "https://example.com/b".into();
            assert_eq!(
                clave::declaration::verify_signed(&[&key], &tampered, "delta", Some(observed_at)),
                Err("WIST1-E01")
            );
        }
    }
}
