mod common;
use clave::declaration::{evaluate, Decision};
use serde_json::{json, Value};
use wist_core::crypto::SigningKey;

fn public_of(seed: &[u8; 32]) -> String {
    wist_core::crypto::b64u_encode(
        &ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    )
}

fn kid(seed: &[u8; 32]) -> String {
    wist_core::objects::publisher::thumbprint(&public_of(seed))
}

fn nbf(at: &str) -> u64 {
    u64::try_from(wist_core::timestamp::log_seconds(at).unwrap()).unwrap()
}

fn key_json(seed: &[u8; 32], valid_from: &str) -> Value {
    serde_json::to_value(wist_core::objects::PublisherKey::new(
        &public_of(seed),
        nbf(valid_from),
        None,
    ))
    .unwrap()
}

fn declaration(
    seq: u64,
    prev: Option<&str>,
    keys: Vec<Value>,
    recovery_keys: Option<Vec<Value>>,
    signer: &[u8; 32],
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
    let sk = SigningKey::from_seed(signer);
    serde_json::to_value(
        wist_core::envelope::sign_envelope(&publisher, "publisher", &kid(signer), &sk).unwrap(),
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
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &K1,
    )
}

#[test]
fn unchanged_when_same_seq_and_content() {
    let stored = base();
    assert_eq!(
        evaluate(&stored, &stored.clone(), &Default::default()).unwrap(),
        Decision::Unchanged
    );
}

#[test]
fn same_seq_different_content_is_rejected() {
    let stored = base();
    let mutated = declaration(
        0,
        None,
        vec![key_json(&K1, "2026-08-02T00:00:00Z")],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &K1,
    );
    assert!(evaluate(&stored, &mutated, &Default::default()).is_err());
}

#[test]
fn lower_seq_is_rejected() {
    let stored = declaration(
        2,
        Some(&format!("sha256:{}", "a".repeat(64))),
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        None,
        &K1,
    );
    let stale = declaration(
        1,
        Some("sha256:bb"),
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        None,
        &K1,
    );
    assert!(evaluate(&stored, &stale, &Default::default()).is_err());
}

#[test]
fn prev_declaration_mismatch_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some("sha256:0000"),
        vec![
            key_json(&K1, "2026-08-01T00:00:00Z"),
            key_json(&K2, "2026-08-10T00:00:00Z"),
        ],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &K1,
    );
    assert!(evaluate(&stored, &next, &Default::default()).is_err());
}

#[test]
fn ordinary_rotation_signed_by_stored_key() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![
            key_json(&K1, "2026-08-01T00:00:00Z"),
            key_json(&K2, "2026-08-10T00:00:00Z"),
        ],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &K1,
    );
    assert_eq!(
        evaluate(&stored, &next, &Default::default()).unwrap(),
        Decision::Ordinary
    );
}

#[test]
fn signature_not_verifying_under_the_named_entry_is_rejected() {
    let stored = base();
    let mut next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &K2,
    );
    next["sig"]["key_id"] = kid(&K1).into();
    assert!(evaluate(&stored, &next, &Default::default()).is_err());
}

#[test]
fn recovery_rotation_signed_by_stored_recovery_key() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &R1,
    );
    assert_eq!(
        evaluate(&stored, &next, &Default::default()).unwrap(),
        Decision::Recovery
    );
}

#[test]
fn recovery_signed_declaration_may_replace_recovery_keys() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json(&X1, "2026-08-10T00:00:00Z")]),
        &R1,
    );
    assert_eq!(
        evaluate(&stored, &next, &Default::default()).unwrap(),
        Decision::Recovery
    );
}

#[test]
fn fresh_identity_signed_by_own_new_key() {
    let stored = declaration(
        0,
        None,
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        None,
        &K1,
    );
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&X1, "2026-08-10T00:00:00Z")],
        None,
        &X1,
    );
    assert_eq!(
        evaluate(&stored, &next, &Default::default()).unwrap(),
        Decision::FreshIdentity
    );
}

#[test]
fn unknown_signer_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &X1,
    );
    assert!(evaluate(&stored, &next, &Default::default()).is_err());
}

#[test]
fn altering_recovery_keys_without_recovery_signature_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        Some(vec![key_json(&X1, "2026-08-10T00:00:00Z")]),
        &K1,
    );
    assert!(evaluate(&stored, &next, &Default::default()).is_err());
}

#[test]
fn dropping_recovery_keys_without_recovery_signature_is_rejected() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        None,
        &K1,
    );
    assert!(evaluate(&stored, &next, &Default::default()).is_err());
}

#[test]
fn establishing_recovery_keys_with_ordinary_signature_is_allowed() {
    let stored = declaration(
        0,
        None,
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        None,
        &K1,
    );
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        Some(vec![key_json(&R1, "2026-08-10T00:00:00Z")]),
        &K1,
    );
    assert_eq!(
        evaluate(&stored, &next, &Default::default()).unwrap(),
        Decision::Ordinary
    );
}

#[test]
fn fresh_identity_must_carry_recovery_keys_byte_identical() {
    let stored = base();
    let next = declaration(
        1,
        Some(&hash_of(&stored)),
        vec![key_json(&X1, "2026-08-10T00:00:00Z")],
        None,
        &X1,
    );
    assert!(evaluate(&stored, &next, &Default::default()).is_err());
}

#[test]
fn fresh_identity_is_accepted_and_left_to_the_windows_settlement() {
    let stored = declaration(
        1,
        Some(&format!("sha256:{}", "a".repeat(64))),
        vec![key_json(&K2, "2026-08-10T00:00:00Z")],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &R1,
    );
    let thief = declaration(
        2,
        Some(&hash_of(&stored)),
        vec![key_json(&X1, "2026-08-11T00:00:00Z")],
        Some(vec![key_json(&R1, "2026-08-01T00:00:00Z")]),
        &X1,
    );
    assert_eq!(
        evaluate(&stored, &thief, &Default::default()).unwrap(),
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
        wist_core::envelope::sign_envelope(&publisher, "publisher", &kid(&K1), &sk).unwrap(),
    )
    .unwrap();
    assert!(evaluate(&stored, &next, &Default::default()).is_err());
}

#[test]
fn spec_declaration_sequence_vector() {
    let path = common::spec_dir().join("vectors/wist1/declaration-sequence.json");
    let vector: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let cases = vector["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let got = evaluate(&case["stored"], &case["fetched"], &Default::default());
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
            clave::declaration::evaluate_initial(&case["fetched"], &Default::default())
                .map(|_| "initial")
        } else {
            evaluate(&case["stored"], &case["fetched"], &Default::default()).map(|decision| {
                match decision {
                    Decision::Ordinary => "ordinary_rotation",
                    Decision::Recovery => "recovery_rotation",
                    Decision::FreshIdentity => "fresh_identity",
                    Decision::Unchanged => "idempotent",
                }
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
fn spec_canonical_encoding_and_usable_key_vectors() {
    for name in ["base64url", "declaration-key-eligibility"] {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(common::spec_dir().join(format!("vectors/wist1/{name}.json"))).unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let fetched = case.get("fetched").unwrap_or(&case["envelope"]);
            let before = fetched.clone();
            let result = if case["stored"].is_null() {
                clave::declaration::evaluate_initial(fetched, &Default::default())
                    .map(|_| "initial")
            } else {
                evaluate(&case["stored"], fetched, &Default::default()).map(|decision| {
                    match decision {
                        Decision::Ordinary => "ordinary_rotation",
                        Decision::Recovery => "recovery_rotation",
                        Decision::FreshIdentity => "fresh_identity",
                        Decision::Unchanged => "idempotent",
                    }
                })
            };
            assert_eq!(
                result.unwrap_or_else(|(code, _)| code),
                case["expected"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            if let Some(expected) = case.get("expected_usable") {
                let publisher = serde_json::from_value::<wist_core::objects::PublisherEnvelope>(
                    fetched.clone(),
                )
                .unwrap()
                .publisher;
                for (field, keys) in [
                    ("keys", publisher.keys.as_slice()),
                    (
                        "recovery_keys",
                        publisher.recovery_keys.as_deref().unwrap_or(&[]),
                    ),
                ] {
                    let usable: Vec<_> = clave::declaration::usable_keys(keys).collect();
                    assert_eq!(
                        serde_json::to_value(usable).unwrap(),
                        expected[field],
                        "{} {field}",
                        case["name"]
                    );
                }
            }
            assert_eq!(*fetched, before);
        }
    }
}

#[test]
fn signed_objects_exclude_unusable_keys_before_signature_verification() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist1/declaration-key-eligibility.json"))
            .unwrap(),
    )
    .unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let publisher = serde_json::from_value::<wist_core::objects::PublisherEnvelope>(
            case["fetched"].clone(),
        )
        .unwrap()
        .publisher;
        for key in &publisher.keys {
            if !clave::declaration::usable_keys(std::slice::from_ref(key)).any(|_| true) {
                let doc = wist_core::envelope::sign_envelope(
                    &json!({"wist_version":"1.0.0", "domain":publisher.domain, "generated_at":"2026-08-04T12:00:00Z", "deltas":[], "next":null}),
                    "feed",
                    &key.kid,
                    &SigningKey::from_seed(&K1),
                )
                .unwrap();
                assert_eq!(
                    clave::declaration::verify_signed(&[key], &doc, "feed"),
                    Err("WIST1-E02"),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn every_key_and_signature_encoding_boundary_is_checked_before_authentication() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist1/base64url.json")).unwrap(),
    )
    .unwrap();
    let baseline = &vector["cases"][0]["envelope"];
    for case in vector["fields"].as_array().unwrap() {
        let paths: &[&str] = match case["kind"].as_str().unwrap() {
            "x" => &["/publisher/keys/0/x", "/publisher/recovery_keys/0/x"],
            "signature" => &["/sig/value"],
            "salt" => continue,
            other => panic!("unexpected encoding kind {other}"),
        };
        for path in paths {
            let mut candidate = baseline.clone();
            *candidate.pointer_mut(path).unwrap() = case["encoded"].clone();
            if let Some(entry) = candidate.pointer_mut(path.trim_end_matches("/x")) {
                // `kid` is the thumbprint of `x` as written (WIST-1 §5.1), so
                // it follows the substitution and leaves only the encoding
                // under test.
                if let Some(x) = entry["x"].as_str().map(str::to_owned) {
                    entry["kid"] = wist_core::objects::publisher::thumbprint(&x).into();
                }
            }
            let result = clave::declaration::validate_fields(&candidate, None)
                .map(|_| "well_formed")
                .unwrap_or_else(|(code, _)| code);
            assert_eq!(
                result,
                case["expected"].as_str().unwrap(),
                "{} {path}",
                case["name"]
            );
        }
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
fn complete_signed_declaration_fields_match_the_specification_vectors() {
    for name in ["declaration-fields", "declaration-hosts"] {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(common::spec_dir().join(format!("vectors/wist1/{name}.json"))).unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let incoming = &case["envelope"];
            let original = incoming.clone();
            let result = if name == "declaration-hosts" {
                clave::declaration::evaluate_initial(incoming, &Default::default())
                    .map(|_| "initial")
            } else {
                evaluate(&vector["stored"], incoming, &Default::default()).map(|decision| {
                    match decision {
                        Decision::Ordinary => "ordinary_rotation",
                        Decision::Recovery => "recovery_rotation",
                        Decision::FreshIdentity => "fresh_identity",
                        Decision::Unchanged => "idempotent",
                    }
                })
            };
            assert_eq!(
                result.unwrap_or_else(|(code, _)| code),
                case["expected"].as_str().unwrap(),
                "{name}: {}",
                case["name"]
            );
            assert_eq!(*incoming, original);
        }
    }
}

#[test]
fn declaration_numeric_spellings_and_unicode_string_bounds_preserve_signed_bytes() {
    let sk = SigningKey::from_seed(&K1);
    let original = declaration(
        0,
        None,
        vec![key_json(&K1, "2026-08-01T00:00:00Z")],
        None,
        &K1,
    );
    for literal in ["0", "0.0", "-0", "-0.0", "0e5"] {
        let mut inner = original["publisher"].clone();
        inner["seq"] = serde_json::from_str(literal).unwrap();
        inner["contact"] = "😀".repeat(256).into();
        let doc = wist_core::envelope::sign_envelope(&inner, "publisher", &kid(&K1), &sk).unwrap();
        let before = doc.clone();
        assert_eq!(
            clave::declaration::evaluate_initial(&doc, &Default::default())
                .unwrap()
                .seq,
            0,
            "{literal}"
        );
        assert_eq!(doc, before);
    }
    for version in [
        "01.0.0",
        "1.00.0",
        "1.0.00",
        "1.0.0\n",
        "1.0.0-alpha",
        "١.0.0",
    ] {
        let mut inner = original["publisher"].clone();
        inner["wist_version"] = version.into();
        let doc = wist_core::envelope::sign_envelope(&inner, "publisher", &kid(&K1), &sk).unwrap();
        assert_eq!(
            clave::declaration::evaluate_initial(&doc, &Default::default())
                .unwrap_err()
                .0,
            "WIST1-E14",
            "{version:?}"
        );
    }
}
