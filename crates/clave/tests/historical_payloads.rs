mod common;

use clave::db::BlockRow;
use clave::history::{deltas::DeltaSource, payloads::PayloadSource};
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

fn profile_change(f: &Fixture, parameter: &str, value: i64, effective_s: i64) -> Value {
    let key = clave::keys::load(&f.data.path().join("keys/seed")).unwrap();
    envelope::sign_envelope(
        &json!({"wist_version":"1.0.0", "action":"parameter_change",
            "subject":parameter, "details":{"parameter":parameter,"value":value},
            "effective_at":jiff::Timestamp::from_second(1_800_000_000 + effective_s).unwrap().to_string()}),
        "update",
        "log1",
        &key,
    )
    .unwrap()
}

#[test]
fn authenticated_audit_profiles_reproduce_vectors_across_amendments_and_restart() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist4/canary.json")).unwrap(),
    )
    .unwrap();
    let cases = vector["scoring_profile"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let p = make_publisher_with_scope("parent.example", &["shared.example"]);
        let (delta, _) = content(&p);
        let mut f = Fixture::new();
        let parameter = case["change"]["parameter"].as_str().unwrap();
        let change = profile_change(
            &f,
            parameter,
            case["change"]["value"].as_i64().unwrap(),
            case["change"]["effective_at_s"].as_i64().unwrap(),
        );
        f.append_at(
            vec![
                entry("publisher_declaration", &current_declaration(&p)),
                entry("registry_update", &change),
            ],
            0,
        );
        f.append_at(
            vec![entry("publisher_delta", &delta)],
            case["audited_delta_sealed_at_s"].as_i64().unwrap(),
        );
        let frozen = *f.delta_source(&delta).unwrap().audit_profile();
        let id = wist_core::delta::delta_id(&delta["delta"]).unwrap();
        let reference_id = add_delta_signed(
            &p,
            "https://shared.example/page",
            case["reference_extract"].as_str().unwrap(),
            Some(&id),
            "2026-08-09T12:00:01Z",
            "k1",
            &K1_SEED,
        );
        let base = p.dir.path().join(".well-known/wist");
        let reference: Value = serde_json::from_slice(
            &std::fs::read(base.join(format!("deltas/{}.json", &reference_id[7..]))).unwrap(),
        )
        .unwrap();
        let raw =
            std::fs::read(base.join(format!("payloads/{}.json", &reference_id[7..]))).unwrap();
        let reset = profile_change(
            &f,
            parameter,
            vector["scoring_profile"]["defaults"][parameter]
                .as_i64()
                .unwrap(),
            15 * 86_400,
        );
        f.append_at(
            vec![
                entry("publisher_delta", &reference),
                entry("registry_update", &reset),
            ],
            8 * 86_400,
        );
        f.append_at(vec![], 15 * 86_400);
        for _ in 0..2 {
            let source = f.delta_source(&delta).unwrap();
            let profile = source.audit_profile();
            assert_eq!(*profile, frozen);
            assert_eq!(
                json!({"shingle_size":profile.shingle_size,
                    "min_observed_words":profile.min_observed_words,
                    "similarity_consistent":profile.similarity_consistent,
                    "similarity_variance_floor":profile.similarity_variance_floor}),
                case["expected"]["profile"],
                "{}",
                case["label"],
            );
            let reference_source = f.source(&reference).unwrap();
            let payload = reference_source.validate(&raw).unwrap();
            if case["audited_delta_sealed_at_s"].as_i64().unwrap() < 604800 {
                assert_ne!(profile, reference_source.delta_source().audit_profile());
            }
            let served = crypto::hex_decode(case["served_bytes_hex"].as_str().unwrap()).unwrap();
            let similarity = profile.derived_similarity(
                &served,
                &payload.content.extract,
                wist_core::verdict::ChangeType::New,
            );
            assert_eq!(json!(similarity), case["expected"]["derived_similarity"]);
            assert_eq!(
                profile.hard_hit(
                    case["credit_reproduces"].as_bool().unwrap(),
                    match case["verdict"].as_str().unwrap() {
                        "consistent" => wist_core::verdict::Verdict::Consistent,
                        "inconsistent" => wist_core::verdict::Verdict::Inconsistent,
                        other => panic!("unexpected vector verdict: {other}"),
                    },
                    similarity,
                ),
                case["expected"]["hard_hit"].as_bool().unwrap(),
            );
        }
        let path = f.path(3);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"broken").unwrap();
        assert!(f.delta_source(&delta).is_err());
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(*f.delta_source(&delta).unwrap().audit_profile(), frozen);
    }
}

#[test]
fn rejected_parameter_entries_cannot_supply_audit_profiles() {
    for fault in ["signature", "value", "grace"] {
        let p = make_publisher_with_scope("parent.example", &["shared.example"]);
        let (delta, _) = content(&p);
        let mut f = Fixture::new();
        let mut change = profile_change(
            &f,
            "shingle_size",
            if fault == "value" { 0 } else { 1 },
            if fault == "grace" { 86_400 } else { 7 * 86_400 },
        );
        if fault == "signature" {
            change = envelope::sign_envelope(&change["update"], "update", "log1", &p.sk).unwrap();
        }
        f.append_at(
            vec![
                entry("publisher_declaration", &current_declaration(&p)),
                entry("registry_update", &change),
            ],
            0,
        );
        f.append_at(vec![entry("publisher_delta", &delta)], 7 * 86_400);
        assert_eq!(
            f.delta_source(&delta).unwrap().audit_profile().shingle_size,
            8,
            "{fault}"
        );
    }
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
