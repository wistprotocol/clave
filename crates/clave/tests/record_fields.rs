mod common;

use clave::record::{Duty, RecordEnvelope, ReplayContext, SigningBinding};
use common::spec_dir;
use serde_json::Value;
use wist_core::crypto::PublicKey;

#[test]
fn signed_record_vectors_separate_diagnostics_from_coverage_discharge() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist4/record-fields.json")).unwrap(),
    )
    .unwrap();
    let public_key = PublicKey::from_b64u(vectors["public_key"].as_str().unwrap()).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let raw = case["record_json"].as_str().unwrap();
        let allowed = case["allowed"].as_array().unwrap();
        let (diagnostic, discharge) = match RecordEnvelope::parse(raw.as_bytes()) {
            Err(code) => (Some(code), false),
            Ok(record) => {
                let original: Value = serde_json::from_str(raw).unwrap();
                assert_eq!(*record.envelope(), original, "{}", case["name"]);
                let context = &case["context"];
                let replay = ReplayContext {
                    signing: (context["identity"] == true).then(|| SigningBinding {
                        auditor_id: original["record"]["auditor_id"].as_str().unwrap_or(""),
                        key_id: original["sig"]["key_id"].as_str().unwrap_or(""),
                        public_key: &public_key,
                    }),
                    duty: if context["duty"] != true {
                        Duty::Absent
                    } else if context["removed"] == true {
                        Duty::RemovedAfterAnchor
                    } else {
                        Duty::Active
                    },
                    coverage_failure: context["coverage_failure"] == true,
                    semantic_evidence_error: context["semantic_evidence_error"] == true,
                };
                let disposition = record.disposition(&replay);
                assert_eq!(*record.envelope(), original, "{}", case["name"]);
                (disposition.diagnostic, disposition.discharges_coverage)
            }
        };
        assert_eq!(
            diagnostic.is_none(),
            allowed.is_empty(),
            "{}: {diagnostic:?}",
            case["name"]
        );
        if let Some(code) = diagnostic {
            assert!(
                allowed.iter().any(|value| value == code),
                "{}: {code}",
                case["name"]
            );
        }
        assert_eq!(discharge, case["discharge"], "{}", case["name"]);
    }
}

#[test]
fn signature_binding_requires_both_admitted_identity_and_key_id() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist4/record-fields.json")).unwrap(),
    )
    .unwrap();
    let public_key = PublicKey::from_b64u(vectors["public_key"].as_str().unwrap()).unwrap();
    let record = RecordEnvelope::parse(
        vectors["cases"][0]["record_json"]
            .as_str()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    for (auditor_id, key_id) in [
        ("different.example", "test-aud-k1"),
        ("audit.example.net", "different-key"),
    ] {
        let disposition = record.disposition(&ReplayContext {
            signing: Some(SigningBinding {
                auditor_id,
                key_id,
                public_key: &public_key,
            }),
            duty: Duty::Active,
            coverage_failure: false,
            semantic_evidence_error: false,
        });
        assert_eq!(disposition.diagnostic, Some("WIST4-E01"));
        assert!(!disposition.discharges_coverage);
    }
}
