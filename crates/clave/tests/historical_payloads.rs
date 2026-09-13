mod common;

use clave::db::BlockRow;
use clave::history::{
    deltas::DeltaSource,
    payloads::{PayloadLocation, PayloadSource},
    records::IncludedRecord,
    references::AuditChain,
};
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

fn reference_record(audited: &str, reference: &str, fetched_at: &str) -> Value {
    let commitment = format!("sha256:{}", "a".repeat(64));
    envelope::sign_envelope(
        &json!({"wist_version":"1.0.0", "auditor_id":"audit.independent.test",
            "audited_delta":audited, "reference_delta":reference,
            "fetched_at":fetched_at, "response_commitment":commitment,
            "ref_extract_commitment":commitment, "credit_commitment":commitment,
            "evidence_commitment":commitment, "similarity":950_000,
            "verdict":"consistent", "vrf_proof":"A".repeat(107), "prev_record":null}),
        "record",
        "r1",
        &crypto::SigningKey::from_seed(&[17; 32]),
    )
    .unwrap()
}

fn score_record(
    audited: &str,
    reference: &str,
    fetched_at: &str,
    verdict: &str,
    similarity: Option<Value>,
    link: Option<Value>,
) -> Value {
    let mut body = reference_record(audited, reference, fetched_at)["record"].clone();
    body["verdict"] = json!(verdict);
    for (field, value) in [("similarity", similarity), ("link_agreement", link)] {
        if let Some(value) = value {
            body[field] = value;
        } else {
            body.as_object_mut().unwrap().remove(field);
        }
    }
    if matches!(verdict, "unreachable" | "not_auditable") {
        for field in [
            "response_commitment",
            "ref_extract_commitment",
            "credit_commitment",
            "evidence_commitment",
        ] {
            body.as_object_mut().unwrap().remove(field);
        }
    }
    if verdict == "not_auditable" {
        body["unmeasured"] = json!("observed");
    }
    envelope::sign_envelope(
        &body,
        "record",
        "r1",
        &crypto::SigningKey::from_seed(&[17; 32]),
    )
    .unwrap()
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
fn historical_sampling_inputs_freeze_at_the_audited_block() {
    use wist_core::sampling::{self, SamplingConstants};

    for (parameter, value, expected, rate) in [
        (
            "sampling_floor",
            400_000,
            SamplingConstants {
                floor_1e7: 400_000,
                ..SamplingConstants::default()
            },
            1_900_000,
        ),
        (
            "sampling_floor",
            100_000,
            SamplingConstants {
                floor_1e7: 100_000,
                ..SamplingConstants::default()
            },
            1_600_000,
        ),
        (
            "sampling_ceiling",
            6_000_000,
            SamplingConstants {
                ceiling_1e7: 6_000_000,
                ..SamplingConstants::default()
            },
            1_700_000,
        ),
        (
            "sampling_ceiling",
            4_000_000,
            SamplingConstants {
                ceiling_1e7: 4_000_000,
                ..SamplingConstants::default()
            },
            1_700_000,
        ),
        (
            "sampling_slope",
            1,
            SamplingConstants {
                slope_per_micro: 1,
                ..SamplingConstants::default()
            },
            700_000,
        ),
        (
            "sampling_slope",
            7,
            SamplingConstants {
                slope_per_micro: 7,
                ..SamplingConstants::default()
            },
            3_700_000,
        ),
        (
            "sampling_slope",
            -9_007_199_254_740_991,
            SamplingConstants {
                slope_per_micro: -9_007_199_254_740_991,
                ..SamplingConstants::default()
            },
            200_000,
        ),
        (
            "sampling_slope",
            0,
            SamplingConstants {
                slope_per_micro: 0,
                ..SamplingConstants::default()
            },
            200_000,
        ),
    ] {
        for offset in [-3600, 0, 3600] {
            let p = make_publisher_with_scope("parent.example", &["shared.example"]);
            let (delta, _) = content(&p);
            let mut f = Fixture::new();
            let change = profile_change(&f, parameter, value, 604_800);
            f.append_at(
                vec![
                    entry("publisher_declaration", &current_declaration(&p)),
                    entry("registry_update", &change),
                ],
                0,
            );
            f.append_at(vec![entry("publisher_delta", &delta)], 604_800 + offset);
            let audited_head = f.head.clone().unwrap();
            let frozen = f.delta_source(&delta).unwrap();
            let constants = if offset < 0 {
                SamplingConstants::default()
            } else {
                expected
            };
            assert_eq!(
                *frozen.sampling_constants(),
                constants,
                "{parameter} at {offset}"
            );
            assert_eq!(frozen.block_hash(), audited_head.block_hash);
            let alpha = sampling::alpha_from_block_hash(frozen.block_hash()).unwrap();
            let proof = wist_core::vrf::prove(&K1_SEED, &alpha).unwrap();
            let public_key: [u8; 32] = crypto::b64u_decode(&p.sk.public().to_b64u())
                .unwrap()
                .try_into()
                .unwrap();
            let beta = wist_core::vrf::verify(&public_key, &alpha, &proof).unwrap();
            let draw = sampling::draw(&beta, frozen.id());
            assert_eq!(
                sampling::p_1e7(500_000, false, false, &constants),
                if offset < 0 { 1_700_000 } else { rate }
            );
            for (sanction, escalation) in [(true, false), (false, true), (true, true)] {
                assert_eq!(
                    sampling::p_1e7(1_000_000, sanction, escalation, &constants),
                    constants.ceiling_1e7
                );
            }
            let reset = profile_change(
                &f,
                parameter,
                clave::registry::spec(parameter).unwrap().default.unwrap(),
                1_296_000,
            );
            let mut successor = delta["delta"].clone();
            successor["prev"] = json!(frozen.id());
            successor["observed_at"] = json!("2026-08-09T12:00:01Z");
            let successor = envelope::sign_envelope(&successor, "delta", "k1", &p.sk).unwrap();
            f.append_at(
                vec![
                    entry("registry_update", &reset),
                    entry("publisher_delta", &successor),
                ],
                691_200,
            );
            let reference_head = f.head.clone().unwrap();
            f.append_at(vec![], 1_296_000);
            for _ in 0..2 {
                let chain =
                    AuditChain::reconstruct(f.data.path(), f.head.clone(), frozen.id()).unwrap();
                let audited = chain.audited();
                assert_eq!(*audited.sampling_constants(), constants);
                assert_eq!(audited.block_hash(), audited_head.block_hash);
                assert_eq!(
                    sampling::draw(
                        &wist_core::vrf::verify(
                            &public_key,
                            &sampling::alpha_from_block_hash(audited.block_hash()).unwrap(),
                            &proof
                        )
                        .unwrap(),
                        audited.id()
                    ),
                    draw
                );
                let reference = chain
                    .resolve(
                        &wist_core::delta::delta_id(&successor["delta"]).unwrap(),
                        &f.head.as_ref().unwrap().sealed_at,
                    )
                    .unwrap();
                assert_eq!(*reference.delta().sampling_constants(), expected);
                assert_eq!(reference.delta().block_hash(), reference_head.block_hash);
                assert!(wist_core::vrf::verify(
                    &public_key,
                    &sampling::alpha_from_block_hash(reference.delta().block_hash()).unwrap(),
                    &proof
                )
                .is_err());
                let mut history =
                    clave::history::History::open(f.data.path(), f.head.clone()).unwrap();
                let mut profiles = Vec::new();
                while let Some(block) = history.next_block().unwrap() {
                    profiles.push(*block.sampling_constants());
                }
                assert_eq!(
                    profiles,
                    [
                        SamplingConstants::default(),
                        constants,
                        expected,
                        SamplingConstants::default()
                    ]
                );
            }
            let path = f.path(3);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::write(&path, b"corrupt").unwrap();
            assert!(f.delta_source(&delta).is_err());
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(
                *f.delta_source(&delta).unwrap().sampling_constants(),
                constants
            );
            assert_eq!(*frozen.sampling_constants(), constants);
            assert_eq!(frozen.block_hash(), audited_head.block_hash);
        }
    }
}

#[test]
fn historical_sampling_defaults_match_rate_vectors() {
    use wist_core::sampling;

    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, _) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let source = f.delta_source(&delta).unwrap();
    assert_eq!(source.position().block_number, 0);
    assert_eq!(source.block_hash(), f.head.as_ref().unwrap().block_hash);
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist4/sampling.json")).unwrap(),
    )
    .unwrap();
    for case in vector["rate_cases"].as_array().unwrap() {
        let elevated = case["level1_or_escalation"].as_bool().unwrap();
        for (sanction, escalation) in [(elevated, false), (false, elevated)] {
            assert_eq!(
                sampling::p_1e7(
                    case["reputation_u"].as_u64().unwrap(),
                    sanction,
                    escalation,
                    source.sampling_constants()
                ),
                case["p_1e7"].as_u64().unwrap(),
                "{}",
                case["label"]
            );
        }
    }
}

#[test]
fn rejected_amendments_cannot_supply_sampling_constants() {
    for (parameter, value, invalid) in [
        ("sampling_floor", 400_000, 0),
        ("sampling_ceiling", 6_000_000, 100_000),
        ("sampling_slope", 1, 0),
    ] {
        for fault in ["signature", "value", "grace"] {
            let p = make_publisher_with_scope("parent.example", &["shared.example"]);
            let (delta, _) = content(&p);
            let mut f = Fixture::new();
            let mut change = profile_change(
                &f,
                parameter,
                if fault == "value" { invalid } else { value },
                if fault == "grace" { 86_400 } else { 604_800 },
            );
            if fault == "value" && parameter == "sampling_slope" {
                change["update"]["details"]["value"] = json!("1");
                let key = clave::keys::load(&f.data.path().join("keys/seed")).unwrap();
                change =
                    envelope::sign_envelope(&change["update"], "update", "log1", &key).unwrap();
            }
            if fault == "signature" {
                change =
                    envelope::sign_envelope(&change["update"], "update", "log1", &p.sk).unwrap();
            }
            f.append_at(
                vec![
                    entry("publisher_declaration", &current_declaration(&p)),
                    entry("registry_update", &change),
                ],
                0,
            );
            f.append_at(vec![entry("publisher_delta", &delta)], 604_800);
            assert_eq!(
                *f.delta_source(&delta).unwrap().sampling_constants(),
                wist_core::sampling::SamplingConstants::default(),
                "{parameter}: {fault}"
            );
        }
    }
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
            let thresholds = source.verdict_thresholds();
            assert_eq!(
                thresholds.similarity_consistent,
                profile.similarity_consistent
            );
            assert_eq!(
                thresholds.similarity_variance_floor,
                profile.similarity_variance_floor
            );
            assert_eq!(thresholds.min_observed_words, profile.min_observed_words);
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
            let chain = AuditChain::reconstruct(f.data.path(), f.head.clone(), &id).unwrap();
            let resolved = chain
                .resolve(&reference_id, &f.head.as_ref().unwrap().sealed_at)
                .unwrap();
            assert_eq!(chain.audited().audit_profile(), profile);
            let reference_source = resolved.payload_source().unwrap();
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

fn thresholds_json(thresholds: &wist_core::verdict::Thresholds) -> Value {
    json!({"similarity_consistent": thresholds.similarity_consistent,
        "similarity_variance_floor": thresholds.similarity_variance_floor,
        "link_agreement_consistent": thresholds.link_agreement_consistent,
        "link_variance_floor": thresholds.link_variance_floor,
        "min_observed_words": thresholds.min_observed_words})
}

#[test]
fn authenticated_verdict_thresholds_follow_the_audited_block() {
    use wist_core::verdict::{self, ChangeType, Observation, Reference, Verdict};

    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist4/link-agreement.json")).unwrap(),
    )
    .unwrap();
    let cases = vector["verdict_profiles"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let p = make_publisher_with_scope("parent.example", &["shared.example"]);
        let (delta, _) = content(&p);
        let audited_id = wist_core::delta::delta_id(&delta["delta"]).unwrap();
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
        let source = f.delta_source(&delta).unwrap();
        let frozen = thresholds_json(source.verdict_thresholds());
        assert_eq!(frozen, case["expected_profile"], "{}", case["label"]);
        let reference_id = add_delta_signed(
            &p,
            "https://shared.example/page",
            "later reference",
            Some(&audited_id),
            "2026-08-09T12:00:01Z",
            "k1",
            &K1_SEED,
        );
        let reference: Value = serde_json::from_slice(
            &std::fs::read(p.dir.path().join(format!(
                ".well-known/wist/deltas/{}.json",
                &reference_id[7..]
            )))
            .unwrap(),
        )
        .unwrap();
        let reset = profile_change(
            &f,
            parameter,
            case["reset"]["value"].as_i64().unwrap(),
            case["reset"]["effective_at_s"].as_i64().unwrap(),
        );
        f.append_at(
            vec![
                entry("publisher_delta", &reference),
                entry("registry_update", &reset),
            ],
            case["reference_delta_sealed_at_s"].as_i64().unwrap(),
        );
        let fetched_at =
            jiff::Timestamp::from_second(1_800_000_000 + case["fetched_at_s"].as_i64().unwrap())
                .unwrap()
                .to_string();
        let mut score_probes = Vec::new();
        for reading in case["readings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|reading| reading["reference_change"] == "update")
        {
            for expected in [true, false] {
                let verdict = if expected {
                    reading["verdict"].as_str().unwrap()
                } else if reading["verdict"] == "inconsistent" {
                    "consistent"
                } else {
                    "inconsistent"
                };
                score_probes.push((
                    score_record(
                        &audited_id,
                        &reference_id,
                        &fetched_at,
                        verdict,
                        Some(reading["similarity"].clone()),
                        Some(reading["link_agreement"].clone()),
                    ),
                    expected,
                ));
            }
        }
        f.append_at(
            score_probes
                .iter()
                .map(|(record, _)| entry("audit_record", record))
                .collect(),
            case["query_sealed_at_s"].as_i64().unwrap(),
        );
        assert_eq!(thresholds_json(source.verdict_thresholds()), frozen);
        for _ in 0..2 {
            let included = IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).unwrap();
            for (record, expected) in &score_probes {
                let bound = included
                    .iter()
                    .find(|included| included.envelope() == record)
                    .unwrap()
                    .resolve_reference(f.data.path())
                    .unwrap();
                let result = bound.validate_verdict_scores();
                assert_eq!(result.is_ok(), *expected, "{}: {record}", case["label"]);
                if let Err(error) = result {
                    assert!(error.to_string().contains("WIST4-E02"));
                }
            }
            let bound = included[0].resolve_reference(f.data.path()).unwrap();
            assert_eq!(
                thresholds_json(bound.audited().verdict_thresholds()),
                frozen
            );
            assert_eq!(bound.audited().identity_start(), source.identity_start());
            assert_eq!(bound.audited().block_hash(), source.block_hash());
            assert_eq!(bound.reference().id(), reference_id);
            assert_eq!(
                bound.payload_source().unwrap().delta_source().id(),
                reference_id
            );
            let chain =
                AuditChain::reconstruct(f.data.path(), f.head.clone(), &audited_id).unwrap();
            let thresholds = chain.audited().verdict_thresholds();
            assert_eq!(thresholds_json(thresholds), frozen);
            let fetched_at = jiff::Timestamp::from_second(
                1_800_000_000 + case["fetched_at_s"].as_i64().unwrap(),
            )
            .unwrap()
            .to_string();
            let resolved = chain.resolve(&reference_id, &fetched_at).unwrap();
            let reference_profile = thresholds_json(resolved.delta().verdict_thresholds());
            assert_eq!(reference_profile[parameter], case["change"]["value"]);
            if case["audited_delta_sealed_at_s"].as_i64().unwrap() < 604_800 {
                assert_ne!(reference_profile, frozen);
            }
            for reading in case["readings"].as_array().unwrap() {
                let change = match reading["reference_change"].as_str().unwrap() {
                    "new" => ChangeType::New,
                    "update" => ChangeType::Update,
                    "attest" => ChangeType::Attest,
                    "delete" => ChangeType::Delete,
                    other => panic!("unexpected change: {other}"),
                };
                let expected = match reading["verdict"].as_str().unwrap() {
                    "consistent" => Verdict::Consistent,
                    "dynamic_variance" => Verdict::DynamicVariance,
                    "inconsistent" => Verdict::Inconsistent,
                    "link_variance" => Verdict::LinkVariance,
                    "link_inconsistent" => Verdict::LinkInconsistent,
                    other => panic!("unexpected verdict: {other}"),
                };
                assert_eq!(
                    verdict::resolve(
                        change,
                        Reference::Available,
                        Observation::Html {
                            observed_words: 100,
                            similarity: reading["similarity"].as_u64().unwrap(),
                            link_agreement: reading["link_agreement"].as_u64(),
                        },
                        thresholds
                    ),
                    expected,
                    "{}: {reading}",
                    case["label"]
                );
            }
        }
        let path = f.path(3);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"broken").unwrap();
        assert!(AuditChain::reconstruct(f.data.path(), f.head.clone(), &audited_id).is_err());
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(
            thresholds_json(f.delta_source(&delta).unwrap().verdict_thresholds()),
            frozen
        );
    }
}

#[test]
fn rejected_parameter_entries_cannot_supply_verdict_thresholds() {
    for parameter in ["link_agreement_consistent", "link_variance_floor"] {
        for fault in ["signature", "value", "grace"] {
            let p = make_publisher_with_scope("parent.example", &["shared.example"]);
            let (delta, _) = content(&p);
            let mut f = Fixture::new();
            let mut change = profile_change(
                &f,
                parameter,
                if fault == "value" { 1_000_001 } else { 500_000 },
                if fault == "grace" { 86_400 } else { 7 * 86_400 },
            );
            if fault == "signature" {
                change =
                    envelope::sign_envelope(&change["update"], "update", "log1", &p.sk).unwrap();
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
                thresholds_json(f.delta_source(&delta).unwrap().verdict_thresholds()),
                thresholds_json(&wist_core::verdict::Thresholds::default()),
                "{parameter}: {fault}"
            );
        }
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
    let copies = tempfile::tempdir().unwrap();
    std::fs::create_dir(copies.path().join("payloads")).unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, copies.path().to_owned());
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
        let name = format!("payloads/{}.json", &source.delta_source().id()[7..]);
        std::fs::write(copies.path().join(&name), &raw).unwrap();
        for retrieved in [
            source.read(copies.path()),
            source.fetch(&client, &format!("http://{host}/{name}")),
        ] {
            match retrieved {
                Ok(copy) => {
                    assert!(allowed.is_empty(), "{}", case["name"]);
                    assert_eq!(copy.raw(), raw);
                    assert!(std::ptr::eq(copy.source(), &source));
                    assert_eq!(
                        jcs::canonicalize(&json!(copy.payload())).unwrap(),
                        jcs::canonicalize(&case["payload"]).unwrap(),
                    );
                }
                Err(clave::Error::Payload(code)) => assert!(
                    allowed.iter().any(|value| value == code),
                    "{}: {code}",
                    case["name"],
                ),
                Err(error) => panic!("{}: {error}", case["name"]),
            }
        }
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
        assert_eq!(std::fs::read(copies.path().join(name)).unwrap(), raw);
        assert_eq!(source.envelope(), &case["envelope"]);
        cases += 1;
    }
    assert_eq!(cases, 103);
}

#[test]
fn historical_payload_retrieval_retries_independent_copies_without_rewriting_state() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let block_bytes = std::fs::read(f.path(0)).unwrap();
    let copies = tempfile::tempdir().unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, copies.path().to_owned());
    let url = format!("http://{host}/copy.json");
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["content"]["extract"] = json!("substitution");
    let wrong = serde_json::to_vec(&wrong).unwrap();
    let mut original = b" \n".to_vec();
    original.extend_from_slice(&raw);
    original.extend_from_slice(b"\n ");
    for _ in 0..2 {
        let source = f.source(&delta).unwrap();
        assert!(matches!(
            source.read(f.data.path()),
            Err(clave::Error::Io(_))
        ));
        assert!(matches!(
            source.fetch(&client, &url),
            Err(clave::Error::Fetch(_))
        ));
        assert!(matches!(
            source.fetch(&client, "http://parent.example/copy.json"),
            Err(clave::Error::Fetch(_)),
        ));
        for rejected in [b"not JSON".as_slice(), wrong.as_slice()] {
            std::fs::write(copies.path().join("copy.json"), rejected).unwrap();
            let code = if rejected == wrong {
                "WIST1-E10"
            } else {
                "WIST1-E05"
            };
            assert!(
                matches!(source.fetch(&client, &url), Err(clave::Error::Payload(actual)) if actual == code)
            );
            assert_eq!(
                std::fs::read(copies.path().join("copy.json")).unwrap(),
                rejected
            );
        }
        std::fs::write(copies.path().join("copy.json"), &original).unwrap();
        let copy = source.fetch(&client, &url).unwrap();
        assert_eq!(copy.raw(), original);
        assert_eq!(copy.payload().content.extract, "body");
        assert_eq!(copy.source().envelope(), &delta);
        assert_eq!(
            std::fs::read_dir(f.data.path().join("payloads"))
                .unwrap()
                .count(),
            0
        );
        std::fs::remove_file(copies.path().join("copy.json")).unwrap();
        assert_eq!(copy.raw(), original);
        assert_eq!(std::fs::read(f.path(0)).unwrap(), block_bytes);
    }
}

#[test]
fn historical_payload_fallback_preserves_failures_and_the_signed_publisher_location() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let block_bytes = std::fs::read(f.path(0)).unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let relative = format!(
        "payloads/{}.json",
        &wist_core::delta::delta_id(&delta["delta"]).unwrap()[7..],
    );
    let published_path = p.dir.path().join(".well-known/wist").join(&relative);
    let retained_path = f.data.path().join(&relative);
    let distributed_path = p.dir.path().join(&relative);
    std::fs::create_dir_all(distributed_path.parent().unwrap()).unwrap();
    let mut original = b" \n".to_vec();
    original.extend_from_slice(&raw);
    original.extend_from_slice(b"\n ");
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["content"]["extract"] = json!("substitution");
    let wrong = serde_json::to_vec(&wrong).unwrap();
    for _ in 0..2 {
        let source = f.source(&delta).unwrap();
        let locations = vec![
            source.retained_location(f.data.path()),
            source
                .distribution_location(&format!("http://{host}/"))
                .unwrap(),
            source.publisher_location(&client),
        ];
        assert_eq!(locations[0], PayloadLocation::File(retained_path.clone()));
        assert_eq!(
            locations[2],
            PayloadLocation::Url(format!("http://localhost/.well-known/wist/{relative}")),
        );
        assert_eq!(
            source.publisher_location(&clave::fetch::Client::new(false)),
            PayloadLocation::Url(format!("https://localhost/.well-known/wist/{relative}")),
        );
        std::fs::write(&retained_path, b"not JSON").unwrap();
        std::fs::write(&distributed_path, &wrong).unwrap();
        std::fs::remove_file(&published_path).unwrap();
        let failed = source.retrieve(&client, locations.clone()).err().unwrap();
        assert_eq!(failed.attempts.len(), 3);
        for (attempt, location) in failed.attempts.iter().zip(&locations) {
            assert_eq!(&attempt.location, location);
        }
        assert!(matches!(
            failed.attempts[0].error,
            clave::Error::Payload("WIST1-E05")
        ));
        assert!(matches!(
            failed.attempts[1].error,
            clave::Error::Payload("WIST1-E10")
        ));
        assert!(matches!(failed.attempts[2].error, clave::Error::Fetch(_)));
        std::fs::write(&published_path, &original).unwrap();
        let candidates = locations
            .clone()
            .into_iter()
            .chain(std::iter::once_with(|| {
                panic!("candidate after the first verified copy must not be selected")
            }));
        let copy = source.retrieve(&client, candidates).unwrap();
        assert_eq!(copy.location(), &locations[2]);
        assert_eq!(copy.failed_attempts().len(), 2);
        assert_eq!(copy.raw(), original);
        assert_eq!(copy.payload().content.extract, "body");
        assert_eq!(copy.source().envelope(), &delta);
        assert_eq!(std::fs::read(&retained_path).unwrap(), b"not JSON");
        assert_eq!(std::fs::read(&distributed_path).unwrap(), wrong);
        assert_eq!(std::fs::read(f.path(0)).unwrap(), block_bytes);
        std::fs::write(&retained_path, &original).unwrap();
        let candidates = std::iter::once(locations[0].clone()).chain(std::iter::once_with(|| {
            panic!("a verified retained copy must stop fallback")
        }));
        let copy = source.retrieve(&client, candidates).unwrap();
        assert_eq!(copy.location(), &locations[0]);
        assert!(copy.failed_attempts().is_empty());
        std::fs::remove_file(&retained_path).unwrap();
        let failed = source
            .retrieve(&client, [locations[0].clone()])
            .err()
            .unwrap();
        assert!(matches!(failed.attempts[0].error, clave::Error::Io(_)));
        assert!(source
            .retrieve(&client, [])
            .err()
            .unwrap()
            .attempts
            .is_empty());
    }
}

#[test]
fn historical_payload_discovery_uses_independent_origins_mirror_hints_and_signed_publisher() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let block_bytes = std::fs::read(f.path(0)).unwrap();
    let (listener, _, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let mirror = tempfile::tempdir().unwrap();
    let (mirror_listener, _, _) = reserve_addr();
    let mirror_origin = format!("http://{}/", mirror_listener.local_addr().unwrap());
    serve_static(mirror_listener, mirror.path().to_owned());
    let relative = format!(
        "payloads/{}.json",
        &wist_core::delta::delta_id(&delta["delta"]).unwrap()[7..],
    );
    let retained = f.data.path().join(&relative);
    let distributed = p.dir.path().join(&relative);
    let mirrored = mirror.path().join(&relative);
    std::fs::create_dir_all(distributed.parent().unwrap()).unwrap();
    std::fs::create_dir_all(mirrored.parent().unwrap()).unwrap();
    let mirror_file = f.data.path().join("log/mirrors.json");
    let hints = json!({"mirrors":{"mirror_urls":[
        "http://localhost/", mirror_origin, "https://user@unusable.example/", mirror_origin
    ]},"sig":{"value":"untrusted"}});
    let hint_bytes = serde_json::to_vec(&hints).unwrap();
    std::fs::write(&mirror_file, &hint_bytes).unwrap();
    for _ in 0..2 {
        let source = f.source(&delta).unwrap();
        let discovered = source.discover(
            &client,
            f.data.path(),
            &["file:///invalid/".into(), "http://LOCALHOST:80/".into()],
        );
        assert_eq!(
            discovered.locations(),
            &[
                PayloadLocation::File(retained.clone()),
                PayloadLocation::Url(format!("http://localhost/{relative}")),
                PayloadLocation::Url(format!("{mirror_origin}{relative}")),
                PayloadLocation::Url(format!("http://localhost/.well-known/wist/{relative}")),
            ],
        );
        assert_eq!(discovered.discovery_failures().len(), 2);
        assert_eq!(
            discovered.discovery_failures()[0].location,
            PayloadLocation::Url("file:///invalid/".into()),
        );
        assert_eq!(
            discovered.discovery_failures()[1].location,
            PayloadLocation::Url("https://user@unusable.example/".into()),
        );
        assert!(discovered
            .discovery_failures()
            .iter()
            .all(|failure| matches!(failure.error, clave::Error::Fetch(_))));
        for local_valid in [false, true] {
            std::fs::write(
                &retained,
                if local_valid {
                    raw.as_slice()
                } else {
                    b"bad local"
                },
            )
            .unwrap();
            std::fs::write(&distributed, b"bad distributed").unwrap();
            std::fs::write(&mirrored, b"bad mirror").unwrap();
            let copy = source
                .retrieve(&client, discovered.locations().iter().cloned())
                .unwrap();
            let selected = if local_valid { 0 } else { 3 };
            assert_eq!(copy.location(), &discovered.locations()[selected]);
            assert_eq!(copy.failed_attempts().len(), selected);
            assert_eq!(copy.raw(), raw);
            assert_eq!(copy.source().envelope(), &delta);
            assert_eq!(std::fs::read(&distributed).unwrap(), b"bad distributed");
        }
        std::fs::remove_file(&retained).unwrap();
        std::fs::write(&distributed, &raw).unwrap();
        let copy = source
            .retrieve(&client, discovered.locations().iter().cloned())
            .unwrap();
        assert_eq!(copy.location(), &discovered.locations()[1]);
        assert_eq!(copy.failed_attempts().len(), 1);
        std::fs::remove_file(&distributed).unwrap();
        std::fs::write(&mirrored, &raw).unwrap();
        let copy = source
            .retrieve(&client, discovered.locations().iter().cloned())
            .unwrap();
        assert_eq!(copy.location(), &discovered.locations()[2]);
        assert_eq!(copy.failed_attempts().len(), 2);
        assert_eq!(copy.raw(), raw);
        assert!(!retained.exists());
        assert_eq!(std::fs::read(&mirror_file).unwrap(), hint_bytes);
        assert_eq!(std::fs::read(f.path(0)).unwrap(), block_bytes);
    }
}

#[test]
fn historical_payload_discovery_preserves_fallback_when_optional_mirror_hints_fail() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let (listener, _, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let path = f.data.path().join("log/mirrors.json");
    let source = f.source(&delta).unwrap();
    for hints in [
        None,
        Some("not JSON"),
        Some("{}"),
        Some(r#"{"mirrors":{"mirror_urls":["https://mirror.example/",false]}}"#),
        Some(r#"{"mirrors":{"mirror_urls":[],"mirror\u005furls":[]}}"#),
    ] {
        if let Some(raw) = hints {
            std::fs::write(&path, raw).unwrap();
        }
        let discovered = source.discover(&client, f.data.path(), &[]);
        assert_eq!(discovered.locations().len(), 2);
        assert_eq!(
            discovered.discovery_failures().len(),
            usize::from(hints.is_some())
        );
        if let Some(failure) = discovered.discovery_failures().first() {
            assert_eq!(failure.location, PayloadLocation::File(path.clone()));
            assert!(matches!(failure.error, clave::Error::Json(_)));
        }
        let copy = source
            .retrieve(&client, discovered.locations().iter().cloned())
            .unwrap();
        assert_eq!(copy.location(), &source.publisher_location(&client));
        assert_eq!(copy.raw(), raw);
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let discovered = source.discover(&client, f.data.path(), &[]);
    assert!(matches!(
        discovered.discovery_failures()[0].error,
        clave::Error::Io(_)
    ));
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(
        &path,
        r#"{"mirrors":{"mirror_urls":["http://localhost/"]}}"#,
    )
    .unwrap();
    let repaired = source.discover(&client, f.data.path(), &[]);
    assert!(repaired.discovery_failures().is_empty());
    assert_eq!(repaired.locations().len(), 3);
}

#[test]
fn remote_mirror_hints_preserve_payload_authentication_fallback_and_restart() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let block_bytes = std::fs::read(f.path(0)).unwrap();
    let (listener, _, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let mirror = tempfile::tempdir().unwrap();
    let (listener, _, _) = reserve_addr();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    serve_static(listener, mirror.path().to_owned());
    let relative = format!(
        "payloads/{}.json",
        &wist_core::delta::delta_id(&delta["delta"]).unwrap()[7..],
    );
    let mirrored = mirror.path().join(&relative);
    std::fs::create_dir_all(mirrored.parent().unwrap()).unwrap();
    let independent = p.dir.path().join(&relative);
    std::fs::create_dir_all(independent.parent().unwrap()).unwrap();
    std::fs::write(&independent, b"bad independent copy").unwrap();
    let list = p.dir.path().join("log/mirrors.json");
    std::fs::create_dir_all(list.parent().unwrap()).unwrap();
    let hints = serde_json::to_vec(&json!({"mirrors":{
        "updated_at":"not a trusted clock",
        "mirror_urls":["http://LOCALHOST:80/", origin, "https://bad.example/path", origin]
    },"sig":{"value":"untrusted"}}))
    .unwrap();
    std::fs::write(&list, &hints).unwrap();
    let local = f.data.path().join("log/mirrors.json");
    std::fs::write(
        &local,
        r#"{"mirrors":{"mirror_urls":["http://localhost/"]}}"#,
    )
    .unwrap();
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["content"]["extract"] = json!("substitution");
    for _ in 0..2 {
        let source = f.source(&delta).unwrap();
        let discovered = source.discover_with_remote_mirrors(
            &client,
            f.data.path(),
            &["http://localhost/".into()],
            &["http://localhost/".into(), "http://LOCALHOST:80/".into()],
        );
        assert_eq!(
            discovered.locations(),
            &[
                source.retained_location(f.data.path()),
                PayloadLocation::Url(format!("http://localhost/{relative}")),
                PayloadLocation::Url(format!("{origin}{relative}")),
                source.publisher_location(&client),
            ]
        );
        assert_eq!(discovered.discovery_failures().len(), 1);
        assert_eq!(
            discovered.discovery_failures()[0].location,
            PayloadLocation::Url("https://bad.example/path".into())
        );
        for valid in [false, true] {
            std::fs::write(
                &mirrored,
                if valid {
                    raw.clone()
                } else {
                    serde_json::to_vec(&wrong).unwrap()
                },
            )
            .unwrap();
            let copy = source
                .retrieve(&client, discovered.locations().iter().cloned())
                .unwrap();
            let selected = if valid { 2 } else { 3 };
            assert_eq!(copy.location(), &discovered.locations()[selected]);
            assert_eq!(copy.failed_attempts().len(), selected);
            if !valid {
                assert!(matches!(
                    copy.failed_attempts()[2].error,
                    clave::Error::Payload("WIST1-E10")
                ));
            }
            assert_eq!(copy.raw(), raw);
            assert_eq!(copy.source().envelope(), &delta);
        }
        assert_eq!(std::fs::read(&list).unwrap(), hints);
        assert_eq!(std::fs::read(f.path(0)).unwrap(), block_bytes);
        assert!(!f.data.path().join(&relative).exists());
    }
    std::fs::write(&list, r#"{"mirrors":{"mirror_urls":[]}}"#).unwrap();
    let source = f.source(&delta).unwrap();
    let repaired = source.discover_with_remote_mirrors(
        &client,
        f.data.path(),
        &[],
        &["http://localhost/".into()],
    );
    assert!(repaired.discovery_failures().is_empty());
    assert_eq!(repaired.locations().len(), 3);
}

#[test]
fn remote_mirror_list_failures_preserve_other_lists_and_publisher_fallback() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let (listener, _, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let other = tempfile::tempdir().unwrap();
    let (listener, _, _) = reserve_addr();
    let other_origin = format!("http://{}/", listener.local_addr().unwrap());
    serve_static(listener, other.path().to_owned());
    std::fs::create_dir_all(other.path().join("log")).unwrap();
    std::fs::write(
        other.path().join("log/mirrors.json"),
        r#"{"mirrors":{"mirror_urls":["http://localhost/"]}}"#,
    )
    .unwrap();
    let path = p.dir.path().join("log/mirrors.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let source = f.source(&delta).unwrap();
    for hints in [
        None,
        Some("not JSON"),
        Some("{}"),
        Some(r#"{"mirrors":{"mirror_urls":["https://ignored.example/",false]}}"#),
        Some(r#"{"mirrors":{"mirror_urls":[],"mirror\u005furls":["https://ignored.example/"]}}"#),
    ] {
        if let Some(hints) = hints {
            std::fs::write(&path, hints).unwrap();
        }
        let discovered = source.discover_with_remote_mirrors(
            &client,
            f.data.path(),
            &[],
            &[
                "http://localhost/".into(),
                "http://LOCALHOST:80/".into(),
                other_origin.clone(),
            ],
        );
        assert_eq!(discovered.discovery_failures().len(), 1);
        let failure = &discovered.discovery_failures()[0];
        assert_eq!(
            failure.location,
            PayloadLocation::Url("http://localhost/log/mirrors.json".into())
        );
        if hints.is_none() {
            assert!(matches!(failure.error, clave::Error::Fetch(_)));
        } else {
            assert!(matches!(failure.error, clave::Error::Json(_)));
        }
        assert_eq!(discovered.locations().len(), 3);
        assert_eq!(
            discovered.locations()[1],
            source.distribution_location("http://localhost/").unwrap()
        );
        let copy = source
            .retrieve(&client, discovered.locations().iter().cloned())
            .unwrap();
        assert_eq!(copy.location(), &source.publisher_location(&client));
        assert_eq!(copy.raw(), raw);
    }
    let invalid = [
        "file:///tmp/",
        "https://user@invalid.example/",
        "https://invalid.example/path",
        "http://invalid.example/",
    ];
    let discovered = source.discover_with_remote_mirrors(
        &client,
        f.data.path(),
        &[],
        &invalid.map(String::from),
    );
    assert_eq!(discovered.locations().len(), 2);
    assert_eq!(discovered.discovery_failures().len(), invalid.len());
    assert!(discovered
        .discovery_failures()
        .iter()
        .all(|failure| matches!(failure.error, clave::Error::Fetch(_))));
    let no_http = source.discover_with_remote_mirrors(
        &clave::fetch::Client::new(false),
        f.data.path(),
        &[],
        std::slice::from_ref(&other_origin),
    );
    assert_eq!(no_http.discovery_failures().len(), 1);
    assert!(matches!(
        no_http.discovery_failures()[0].error,
        clave::Error::Fetch(_)
    ));
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"mirrors":{"mirror_urls":[other_origin]}})).unwrap(),
    )
    .unwrap();
    let repaired = source.discover_with_remote_mirrors(
        &client,
        f.data.path(),
        &[],
        &["http://localhost/".into()],
    );
    assert!(repaired.discovery_failures().is_empty());
    assert_eq!(repaired.locations().len(), 3);
}

#[test]
fn remote_mirror_discovery_fetches_only_distinct_explicit_list_origins() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, _) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let (listener, _, client) = reserve_addr();
    let requests = Arc::new(AtomicUsize::new(0));
    let served_requests = requests.clone();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                let requests = served_requests.clone();
                async move {
                    assert_eq!(uri.path(), "/log/mirrors.json");
                    requests.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({"mirrors":{"mirror_urls":["http://localhost/", "https://unrequested.example/"]}}))
                }
            });
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app).await.unwrap();
        });
    });
    let source = f.source(&delta).unwrap();
    let independent = ["http://localhost/".into()];
    source.discover(&client, f.data.path(), &independent);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    for expected in 1..=2 {
        let discovered = source.discover_with_remote_mirrors(
            &client,
            f.data.path(),
            &independent,
            &["http://localhost/".into(), "http://LOCALHOST:80/".into()],
        );
        assert!(discovered.discovery_failures().is_empty());
        assert_eq!(discovered.locations().len(), 4);
        assert_eq!(requests.load(Ordering::SeqCst), expected);
    }
}

#[test]
fn historical_payload_distribution_locations_require_origins_and_preserve_ports() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, _) = content(&p);
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let source = f.source(&delta).unwrap();
    let path = format!("payloads/{}.json", &source.delta_source().id()[7..]);
    assert_eq!(
        source
            .distribution_location("https://mirror.example:8443/")
            .unwrap(),
        PayloadLocation::Url(format!("https://mirror.example:8443/{path}")),
    );
    assert_eq!(
        source.publisher_location(&clave::fetch::Client::new(true)),
        PayloadLocation::Url(format!("https://parent.example/.well-known/wist/{path}")),
    );
    for origin in [
        "invalid",
        "file:///tmp/",
        "ftp://mirror.example/",
        "https://mirror.example/log/",
        "https://mirror.example/?query",
        "https://mirror.example/#fragment",
        "https://user@mirror.example/",
        "https://user:password@mirror.example/",
    ] {
        assert!(source.distribution_location(origin).is_err(), "{origin}");
    }
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
            assert_eq!(
                AuditChain::reconstruct(
                    f.data.path(),
                    f.head.clone(),
                    &wist_core::delta::delta_id(&target["delta"]).unwrap(),
                )
                .is_ok(),
                fault == "none",
                "{fault}",
            );
        }
        if fault.starts_with("late_") {
            f.head = good_prefix;
            f.source(&target).unwrap();
            AuditChain::reconstruct(
                f.data.path(),
                f.head.clone(),
                &wist_core::delta::delta_id(&target["delta"]).unwrap(),
            )
            .unwrap();
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
                let chain = AuditChain::reconstruct(
                    f.data.path(),
                    f.head.clone(),
                    &wist_core::delta::delta_id(&root_a["delta"]).unwrap(),
                )
                .unwrap();
                let at = &f.head.as_ref().unwrap().sealed_at;
                let reference = chain.resolve(delta.id(), at).unwrap();
                assert_eq!(reference.delta().declaration().envelope(), &replacement);
                assert_eq!(
                    chain.audited().declaration().envelope(),
                    &current_declaration(&a)
                );
                assert!(chain
                    .resolve(&wist_core::delta::delta_id(&root_b["delta"]).unwrap(), at,)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("WIST4-E02"));
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
        let references = AuditChain::reconstruct(
            f.data.path(),
            f.head.clone(),
            &wist_core::delta::delta_id(&chain[0]["delta"]).unwrap(),
        )
        .unwrap();
        let at = &f.head.as_ref().unwrap().sealed_at;
        assert_eq!(
            references.newest_at(at).unwrap().unwrap().envelope(),
            chain.last().unwrap()
        );
        for (i, delta) in chain.iter().enumerate() {
            let source = f.delta_source(delta).unwrap();
            assert_eq!(source.envelope(), delta);
            assert_eq!(
                source.position().block_number,
                if same_block { 0 } else { i as u64 }
            );
            let reference = references.resolve(source.id(), at).unwrap();
            let anchor = reference.payload_source().unwrap();
            assert_eq!(anchor.envelope(), if i == 3 { delta } else { &chain[0] });
            anchor.validate(&payload).unwrap();
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

#[test]
fn included_record_evidence_fields_enforce_measured_and_unmeasured_contracts() {
    let example: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("examples/audit-record.json")).unwrap(),
    )
    .unwrap();
    let commitments: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist4/audit-commitments.json")).unwrap(),
    )
    .unwrap();
    let unmeasured: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist4/unauditable.json")).unwrap(),
    )
    .unwrap();
    let fields = [
        "response_commitment",
        "credit_commitment",
        "ref_extract_commitment",
        "evidence_commitment",
    ];
    for field in fields {
        assert_eq!(
            example["record"][field],
            commitments["commitments"][field]["value"]
        );
    }
    let mut probes = std::collections::BTreeMap::new();
    let mut push = |label: String, body: Value, expected: bool| {
        let record = envelope::sign_envelope(
            &body,
            "record",
            "r1",
            &crypto::SigningKey::from_seed(&[17; 32]),
        )
        .unwrap();
        probes.insert(
            jcs::canonicalize(&record).unwrap(),
            (label, record, expected),
        );
    };
    for verdict in [
        "consistent",
        "dynamic_variance",
        "inconsistent",
        "link_variance",
        "link_inconsistent",
        "unreachable",
        "not_auditable",
    ] {
        let measured = !matches!(verdict, "unreachable" | "not_auditable");
        let mut base = example["record"].clone();
        base["verdict"] = json!(verdict);
        base.as_object_mut().unwrap().remove("link_agreement");
        if matches!(verdict, "link_variance" | "link_inconsistent") {
            base["link_agreement"] = json!(0);
        }
        if !measured {
            for field in fields.into_iter().chain(["similarity"]) {
                base.as_object_mut().unwrap().remove(field);
            }
        }
        if verdict == "not_auditable" {
            base["unmeasured"] = json!("observed");
        }
        push(verdict.into(), base.clone(), true);
        for field in fields {
            let mut missing = base.clone();
            missing.as_object_mut().unwrap().remove(field);
            push(format!("{verdict}/{field}/absent"), missing, !measured);
            for value in [
                Value::Null,
                json!(false),
                json!(0),
                json!([]),
                json!({}),
                json!(""),
                json!(format!("sha256:{}", "a".repeat(64))),
                json!(format!("hmac-sha256:{}", "A".repeat(64))),
                json!(format!("hmac-sha256:{}", "a".repeat(63))),
                json!(format!("hmac-sha256:{}", "a".repeat(65))),
                json!(format!("hmac-sha256:{}\n", "a".repeat(64))),
                json!(format!("hmac-sha256:{}", "g".repeat(64))),
                example["record"][field].clone(),
            ] {
                let valid = value == example["record"][field];
                let mut body = base.clone();
                body[field] = value;
                push(format!("{verdict}/{field}"), body, measured && valid);
            }
        }
        for field in ["similarity", "link_agreement"] {
            let mut missing = base.clone();
            missing.as_object_mut().unwrap().remove(field);
            let optional = if field == "similarity" {
                !measured
            } else {
                !matches!(verdict, "link_variance" | "link_inconsistent")
            };
            push(format!("{verdict}/{field}/absent"), missing, optional);
            for literal in [
                "0",
                "-0",
                "0.0",
                "6e5",
                "1000000.0",
                "1000001",
                "-1",
                "0.5",
                "null",
                "false",
                "[]",
                "{}",
                "\"600000\"",
            ] {
                let value: Value = serde_json::from_str(literal).unwrap();
                let valid = matches!(literal, "0" | "-0" | "0.0" | "6e5" | "1000000.0");
                let mut body = base.clone();
                body[field] = value;
                push(
                    format!("{verdict}/{field}/{literal}"),
                    body,
                    measured && valid,
                );
            }
        }
        for value in [
            json!(true),
            json!(false),
            Value::Null,
            json!("true"),
            json!(1),
        ] {
            let mut body = base.clone();
            body["robots_excluded"] = value.clone();
            push(
                format!("{verdict}/robots_excluded"),
                body,
                verdict == "unreachable" && value == true,
            );
        }
        let mut absent = base.clone();
        absent.as_object_mut().unwrap().remove("unmeasured");
        push(
            format!("{verdict}/unmeasured/absent"),
            absent,
            verdict != "not_auditable",
        );
        for value in [
            json!("observed"),
            json!("reference"),
            json!("mirror"),
            Value::Null,
            json!(false),
        ] {
            let mut body = base.clone();
            body["unmeasured"] = value.clone();
            push(
                format!("{verdict}/unmeasured"),
                body,
                verdict == "not_auditable"
                    && matches!(value.as_str(), Some("observed" | "reference")),
            );
        }
    }
    for value in [
        Value::Null,
        json!("unknown"),
        json!(1),
        json!([]),
        json!({}),
    ] {
        let mut body = example["record"].clone();
        body["verdict"] = value;
        push("invalid verdict".into(), body, false);
    }
    for side in unmeasured["fetch_budget"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(unmeasured["fetch_transport"]["cases"].as_array().unwrap())
    {
        let mut body = example["record"].clone();
        for field in fields.into_iter().chain(["similarity", "link_agreement"]) {
            body.as_object_mut().unwrap().remove(field);
        }
        for (field, value) in side["record"].as_object().unwrap() {
            body[field] = value.clone();
        }
        push("unauditable vector".into(), body, true);
    }
    let mut forged = example.clone();
    forged["sig"]["value"] = json!("A".repeat(86));
    probes.insert(
        jcs::canonicalize(&forged).unwrap(),
        ("forged signature".into(), forged, true),
    );
    let mut f = Fixture::new();
    f.append(
        probes
            .values()
            .map(|(_, record, _)| entry("audit_record", record))
            .collect(),
    );
    let retained = std::fs::read(f.path(0)).unwrap();
    for _ in 0..2 {
        let records = IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).unwrap();
        assert_eq!(records.len(), probes.len());
        for record in records {
            let raw = jcs::canonicalize(record.envelope()).unwrap();
            let (label, _, expected) = &probes[&raw];
            let signature = envelope::verify_envelope(
                record.envelope(),
                "record",
                &crypto::SigningKey::from_seed(&[17; 32]).public(),
            );
            assert_eq!(signature.is_ok(), label != "forged signature");
            assert_eq!(
                record.evidence_fields_valid(),
                *expected,
                "{label}: {}",
                record.envelope()
            );
            assert_eq!(jcs::canonicalize(record.envelope()).unwrap(), raw);
        }
        assert_eq!(std::fs::read(f.path(0)).unwrap(), retained);
    }
}

#[test]
fn included_record_scores_use_reference_change_and_reject_malformed_readings() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (root, _) = content(&p);
    let root_id = wist_core::delta::delta_id(&root["delta"]).unwrap();
    let at = jiff::Timestamp::from_second(1_800_003_600)
        .unwrap()
        .to_string();
    for kind in ["new", "update", "attest", "delete"] {
        let mut f = Fixture::new();
        f.append(vec![
            entry("publisher_declaration", &current_declaration(&p)),
            entry("publisher_delta", &root),
        ]);
        let mut reference = root["delta"].clone();
        let mut entries = Vec::new();
        if kind != "new" {
            reference["change_type"] = json!(kind);
            reference["prev"] = json!(root_id);
            reference["observed_at"] = json!("2026-08-09T12:00:01Z");
            if kind != "update" {
                reference.as_object_mut().unwrap().remove("payload");
            }
            entries.push(entry(
                "publisher_delta",
                &envelope::sign_envelope(&reference, "delta", "k1", &p.sk).unwrap(),
            ));
        }
        let reference_id = wist_core::delta::delta_id(&reference).unwrap();
        let mut probes = Vec::new();
        for (similarity, verdict) in [
            (0, "inconsistent"),
            (299_999, "inconsistent"),
            (300_000, "dynamic_variance"),
            (599_999, "dynamic_variance"),
            (600_000, "consistent"),
            (1_000_000, "consistent"),
        ] {
            let raw = if kind == "delete" {
                1_000_000 - similarity
            } else {
                similarity
            };
            for claimed in [
                "consistent",
                "dynamic_variance",
                "inconsistent",
                "link_variance",
                "link_inconsistent",
            ] {
                probes.push((
                    score_record(
                        &root_id,
                        &reference_id,
                        &at,
                        claimed,
                        Some(json!(raw)),
                        None,
                    ),
                    claimed == verdict,
                ));
            }
        }
        for verdict in ["unreachable", "not_auditable"] {
            probes.push((
                score_record(&root_id, &reference_id, &at, verdict, None, None),
                true,
            ));
            for value in [json!(0), Value::Null] {
                probes.push((
                    score_record(
                        &root_id,
                        &reference_id,
                        &at,
                        verdict,
                        Some(value.clone()),
                        None,
                    ),
                    false,
                ));
                probes.push((
                    score_record(&root_id, &reference_id, &at, verdict, None, Some(value)),
                    false,
                ));
            }
        }
        let high = if kind == "delete" { 0 } else { 1_000_000 };
        for invalid in [
            Value::Null,
            json!(-1),
            json!(1_000_001),
            json!(0.5),
            json!("600000"),
            json!(true),
            json!([]),
            json!({}),
        ] {
            probes.push((
                score_record(
                    &root_id,
                    &reference_id,
                    &at,
                    "consistent",
                    Some(invalid.clone()),
                    None,
                ),
                false,
            ));
            probes.push((
                score_record(
                    &root_id,
                    &reference_id,
                    &at,
                    "consistent",
                    Some(json!(high)),
                    Some(invalid),
                ),
                false,
            ));
        }
        probes.push((
            score_record(&root_id, &reference_id, &at, "consistent", None, None),
            false,
        ));
        probes.push((
            score_record(
                &root_id,
                &reference_id,
                &at,
                "unknown",
                Some(json!(high)),
                None,
            ),
            false,
        ));
        probes.push((
            score_record(
                &root_id,
                &reference_id,
                &at,
                "consistent",
                Some(json!(high)),
                Some(json!(1_000_000)),
            ),
            kind != "delete",
        ));
        let mut forged = probes.iter().find(|(_, valid)| *valid).unwrap().0.clone();
        forged["sig"]["value"] = json!("A".repeat(86));
        probes.push((forged, true));
        entries.extend(
            probes
                .iter()
                .map(|(record, _)| entry("audit_record", record)),
        );
        f.append(entries);
        for _ in 0..2 {
            let included = IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).unwrap();
            for (record, expected) in &probes {
                let bound = included
                    .iter()
                    .find(|included| included.envelope() == record)
                    .unwrap()
                    .resolve_reference(f.data.path())
                    .unwrap();
                let result = bound.validate_verdict_scores();
                assert_eq!(result.is_ok(), *expected, "{kind}: {record}");
                if let Err(error) = result {
                    assert!(error.to_string().contains("WIST4-E02"));
                }
            }
        }
    }
}

#[test]
fn included_record_references_enforce_fetch_boundaries_and_required_inputs() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, payload) = content(&p);
    let id = wist_core::delta::delta_id(&delta["delta"]).unwrap();
    let mut f = Fixture::new();
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ]);
    let mut probes = Vec::new();
    for offset in [-1, 0, 1, 3599, 3600, 3601] {
        let at = jiff::Timestamp::from_second(1_800_000_000 + offset)
            .unwrap()
            .to_string();
        probes.push((
            reference_record(&id, &id, &at),
            (0..=3600).contains(&offset),
        ));
    }
    let valid = probes[1].0.clone();
    for timestamp in [
        "2027-01-15T08:00:60Z",
        "2027-01-15T08:00:00.0Z",
        "2027-01-15T08:00:00+00:00",
        "2027-02-29T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
    ] {
        probes.push((reference_record(&id, &id, timestamp), false));
    }
    for field in ["audited_delta", "reference_delta", "fetched_at"] {
        for replacement in [None, Some(Value::Null), Some(json!(42)), Some(json!(""))] {
            let mut body = valid["record"].clone();
            if let Some(value) = replacement {
                body[field] = value;
            } else {
                body.as_object_mut().unwrap().remove(field);
            }
            probes.push((
                envelope::sign_envelope(
                    &body,
                    "record",
                    "r1",
                    &crypto::SigningKey::from_seed(&[17; 32]),
                )
                .unwrap(),
                false,
            ));
        }
    }
    let mut forged = valid.clone();
    forged["sig"]["value"] = json!("A".repeat(86));
    probes.push((forged, true));
    f.append(
        probes
            .iter()
            .map(|(doc, _)| entry("audit_record", doc))
            .collect(),
    );
    for _ in 0..2 {
        let records = IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).unwrap();
        for (doc, expected) in &probes {
            let included = records.iter().find(|r| r.envelope() == doc).unwrap();
            let resolved = included.resolve_reference(f.data.path());
            assert_eq!(
                resolved.is_ok(),
                *expected,
                "{doc}: {}",
                resolved.err().map_or(String::new(), |e| e.to_string())
            );
            if *expected {
                let resolved = included.resolve_reference(f.data.path()).unwrap();
                assert_eq!(resolved.record().envelope(), doc);
                assert_eq!(resolved.reference().id(), id);
                assert_eq!(resolved.audited().id(), id);
                resolved
                    .payload_source()
                    .unwrap()
                    .validate(&payload)
                    .unwrap();
            }
        }
    }
}

#[test]
fn included_record_references_pin_history_and_recover_after_file_repair() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (delta, _) = content(&p);
    let id = wist_core::delta::delta_id(&delta["delta"]).unwrap();
    let mut f = Fixture::new();
    let first = vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
    ];
    f.append(first.clone());
    let record = reference_record(&id, &id, &f.head.as_ref().unwrap().sealed_at);
    let pinned = f.head.clone();
    f.append(vec![entry("audit_record", &record)]);
    let records = IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).unwrap();
    let included = &records[0];
    for height in 0..=1 {
        let path = f.path(height);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(included.resolve_reference(f.data.path()).is_err());
        std::fs::write(&path, b"broken").unwrap();
        assert!(included.resolve_reference(f.data.path()).is_err());
        std::fs::write(path, bytes).unwrap();
        included.resolve_reference(f.data.path()).unwrap();
    }
    let bytes = std::fs::read(f.path(1)).unwrap();
    f.head = pinned;
    f.append(vec![]);
    assert!(included.resolve_reference(f.data.path()).is_err());
    std::fs::write(f.path(1), bytes).unwrap();
    f.head = Some(BlockRow {
        block_number: included.position().block_number,
        block_hash: included.block_hash().into(),
        sealed_at: jiff::Timestamp::from_second(included.sealed_at_s())
            .unwrap()
            .to_string(),
    });
    included.resolve_reference(f.data.path()).unwrap();

    let mut other = Fixture::new();
    other.append(first);
    other.append(vec![entry("audit_record", &record)]);
    assert_eq!(
        other.head.as_ref().unwrap().block_hash,
        included.block_hash()
    );
    assert!(included.resolve_reference(other.data.path()).is_err());
    for name in [
        "anchor.json",
        "log/blocks/000000000.json.zst",
        "log/blocks/000000001.json.zst",
    ] {
        std::fs::copy(f.data.path().join(name), other.data.path().join(name)).unwrap();
    }
    included.resolve_reference(other.data.path()).unwrap();

    let anchor_path = f.data.path().join("anchor.json");
    let anchor: Value = serde_json::from_slice(&std::fs::read(&anchor_path).unwrap()).unwrap();
    let mut renamed = anchor["anchor"].clone();
    renamed["log_id"] = json!("another.example");
    let key = clave::keys::load(&f.data.path().join("keys/seed")).unwrap();
    let renamed = envelope::sign_envelope(&renamed, "anchor", "log1", &key).unwrap();
    std::fs::write(&anchor_path, serde_json::to_vec(&renamed).unwrap()).unwrap();
    assert!(included.resolve_reference(f.data.path()).is_err());
    std::fs::write(&anchor_path, serde_json::to_vec_pretty(&anchor).unwrap()).unwrap();
    included.resolve_reference(f.data.path()).unwrap();

    let (later, _) = content(&p);
    f.append(vec![entry("publisher_delta", &later)]);
    assert!(AuditChain::reconstruct(f.data.path(), f.head.clone(), &id).is_err());
    included.resolve_reference(f.data.path()).unwrap();
    std::fs::write(f.path(2), b"broken later Block").unwrap();
    assert!(IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).is_err());
    included.resolve_reference(f.data.path()).unwrap();
}

#[test]
fn included_record_payload_retrieval_preserves_failures_and_retries_after_reopen() {
    let p = make_publisher_with_scope("localhost", &["shared.example"]);
    let (delta, raw) = content(&p);
    let id = wist_core::delta::delta_id(&delta["delta"]).unwrap();
    let name = format!("payloads/{}.json", &id[7..]);
    let published = p.dir.path().join(".well-known/wist").join(&name);
    let (listener, host, client) = reserve_addr();
    serve_static(listener, p.dir.path().to_owned());
    let mut f = Fixture::new();
    let amendment = profile_change(&f, "extract_cap_bytes", 2, 604_800);
    f.append(vec![
        entry("publisher_declaration", &current_declaration(&p)),
        entry("publisher_delta", &delta),
        entry("registry_update", &amendment),
    ]);
    let mut record = reference_record(&id, &id, &f.head.as_ref().unwrap().sealed_at);
    record["sig"]["value"] = json!("forged");
    f.append_at(vec![entry("audit_record", &record)], 604_800);
    let retained = f.data.path().join(&name);
    let local_list = f.data.path().join("log/mirrors.json");
    let remote_list = p.dir.path().join("log/mirrors.json");
    let remote_payload = p.dir.path().join(&name);
    std::fs::create_dir_all(remote_list.parent().unwrap()).unwrap();
    std::fs::create_dir_all(remote_payload.parent().unwrap()).unwrap();
    let blocks: Vec<_> = (0..=1)
        .map(|height| std::fs::read(f.path(height)).unwrap())
        .collect();
    let origins = ["http://unrequested.example/".into()];
    let lists = [format!("http://{host}/")];
    let mut exact = b" \n".to_vec();
    exact.extend_from_slice(&raw);
    exact.extend_from_slice(b"\n ");
    for _ in 0..2 {
        let records = IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).unwrap();
        let bound = records[0].resolve_reference(f.data.path()).unwrap();
        let source = bound.payload_source().unwrap();
        assert!(source.size_caps().extract_cap_bytes > 2);
        let mut history = clave::history::History::open(f.data.path(), f.head.clone()).unwrap();
        history.next_block().unwrap();
        assert_eq!(
            history
                .next_block()
                .unwrap()
                .unwrap()
                .delta_size_caps()
                .extract_cap_bytes,
            2
        );
        std::fs::write(&retained, b"not JSON").unwrap();
        std::fs::write(&local_list, b"not JSON").unwrap();
        std::fs::write(&remote_list, br#"{"mirrors":{"mirror_urls":[null]}}"#).unwrap();
        std::fs::write(&published, &exact).unwrap();
        let retrieval = bound
            .retrieve_payload(&client, f.data.path(), &origins, &lists)
            .unwrap();
        assert!(std::ptr::eq(retrieval.reference(), &bound));
        assert_eq!(retrieval.reference().record().envelope(), &record);
        assert_eq!(retrieval.locations().discovery_failures().len(), 2);
        let copy = retrieval.result().unwrap();
        assert_eq!(copy.location(), &source.publisher_location(&client));
        assert_eq!(copy.raw(), exact);
        assert_eq!(copy.failed_attempts().len(), 2);
        assert!(matches!(
            copy.failed_attempts()[0].error,
            clave::Error::Payload("WIST1-E05")
        ));
        assert!(matches!(
            copy.failed_attempts()[1].error,
            clave::Error::Fetch(_)
        ));
        assert!(std::ptr::eq(copy.source(), source));

        std::fs::remove_file(&published).unwrap();
        let exhausted = bound
            .retrieve_payload(&client, f.data.path(), &origins, &lists)
            .unwrap();
        let failure = exhausted.result().err().unwrap();
        assert_eq!(failure.attempts.len(), 3);
        assert_eq!(exhausted.locations().discovery_failures().len(), 2);
        for (attempt, location) in failure
            .attempts
            .iter()
            .zip(exhausted.locations().locations())
        {
            assert_eq!(&attempt.location, location);
        }
        assert_eq!(bound.record().envelope(), &record);

        std::fs::remove_file(&local_list).unwrap();
        std::fs::write(
            &remote_list,
            serde_json::to_vec(&json!({"mirrors":{"mirror_urls":[format!("http://{host}/")]}}))
                .unwrap(),
        )
        .unwrap();
        std::fs::write(&remote_payload, &exact).unwrap();
        let repaired = bound
            .retrieve_payload(&client, f.data.path(), &origins, &lists)
            .unwrap();
        assert!(repaired.locations().discovery_failures().is_empty());
        let copy = repaired.result().unwrap();
        assert_eq!(
            copy.location(),
            &source
                .distribution_location(&format!("http://{host}/"))
                .unwrap()
        );
        assert_eq!(copy.raw(), exact);
        assert_eq!(copy.failed_attempts().len(), 2);
        assert_eq!(std::fs::read(&retained).unwrap(), b"not JSON");

        std::fs::write(&retained, &exact).unwrap();
        let local = bound
            .retrieve_payload(&client, f.data.path(), &origins, &[])
            .unwrap();
        let copy = local.result().unwrap();
        assert_eq!(copy.location(), &source.retained_location(f.data.path()));
        assert!(copy.failed_attempts().is_empty());
        assert_eq!(copy.raw(), exact);
        for (height, original) in blocks.iter().enumerate() {
            assert_eq!(&std::fs::read(f.path(height as u64)).unwrap(), original);
        }
    }
}

#[test]
fn included_record_references_resolve_same_block_contentless_sources() {
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let (root, payload) = content(&p);
    for kind in ["new", "attest", "delete"] {
        let mut body = root["delta"].clone();
        body["change_type"] = json!(kind);
        if kind != "new" {
            body.as_object_mut().unwrap().remove("payload");
            body["prev"] = json!(wist_core::delta::delta_id(&root["delta"]).unwrap());
            body["observed_at"] = json!("2026-08-09T12:00:01Z");
        }
        let delta = envelope::sign_envelope(&body, "delta", "k1", &p.sk).unwrap();
        let id = wist_core::delta::delta_id(&body).unwrap();
        let at = jiff::Timestamp::from_second(1_800_000_000)
            .unwrap()
            .to_string();
        let mut f = Fixture::new();
        let mut entries = vec![
            entry("publisher_declaration", &current_declaration(&p)),
            entry("publisher_delta", &delta),
            entry("audit_record", &reference_record(&id, &id, &at)),
        ];
        if kind != "new" {
            entries.push(entry("publisher_delta", &root));
        }
        f.append(entries);
        let included = IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).unwrap();
        let bound = included[0].resolve_reference(f.data.path()).unwrap();
        assert_eq!(bound.record().position().block_number, 0);
        assert_eq!(bound.reference().position().block_number, 0);
        assert_eq!(bound.reference().id(), id);
        bound.payload_source().unwrap().validate(&payload).unwrap();
        assert_eq!(
            bound.payload_source().unwrap().delta_source().id(),
            wist_core::delta::delta_id(&root["delta"]).unwrap(),
        );
    }
}

#[test]
fn authenticated_reference_vectors_resolve_named_and_newest_deltas() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist4/superseded-audit.json")).unwrap(),
    )
    .unwrap();
    let p = make_publisher_with_scope("parent.example", &["shared.example"]);
    let mut f = Fixture::new();
    let missing = tempfile::tempdir().unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, f.data.path().to_owned());
    std::fs::write(
        f.data.path().join("log/mirrors.json"),
        serde_json::to_vec(&json!({"mirrors":{"mirror_urls":[format!("http://{host}/")]}}))
            .unwrap(),
    )
    .unwrap();
    let (root, _) = content(&p);
    let mut other_root = root["delta"].clone();
    other_root["url"] = json!("https://shared.example/other");
    let other_root = envelope::sign_envelope(&other_root, "delta", "k1", &p.sk).unwrap();
    f.append_at(
        vec![
            entry("publisher_declaration", &current_declaration(&p)),
            entry("publisher_delta", &root),
            entry("publisher_delta", &other_root),
        ],
        -3600,
    );
    let mut named = std::collections::BTreeMap::<String, Value>::new();
    let mut payloads = std::collections::BTreeMap::<String, Vec<u8>>::new();
    for (name, url, first) in [
        ("chain", "https://shared.example/page", &root),
        ("other_chain", "https://shared.example/other", &other_root),
    ] {
        let mut prev = wist_core::delta::delta_id(&first["delta"]).unwrap();
        for (i, description) in vector[name].as_array().unwrap().iter().enumerate() {
            let content_name = description["payload"].as_str().unwrap_or("unused");
            let id = add_delta_signed(
                &p,
                url,
                content_name,
                Some(&prev),
                &format!("2026-08-09T12:00:{:02}Z", i + 1),
                "k1",
                &K1_SEED,
            );
            let base = p.dir.path().join(".well-known/wist");
            let doc: Value = serde_json::from_slice(
                &std::fs::read(base.join(format!("deltas/{}.json", &id[7..]))).unwrap(),
            )
            .unwrap();
            let mut body = doc["delta"].clone();
            body["change_type"] = description["change"].clone();
            if description["payload"].is_null() {
                body.as_object_mut().unwrap().remove("payload");
            } else {
                payloads.insert(
                    content_name.into(),
                    std::fs::read(base.join(format!("payloads/{}.json", &id[7..]))).unwrap(),
                );
            }
            prev = wist_core::delta::delta_id(&body).unwrap();
            named.insert(
                description["id"].as_str().unwrap().into(),
                envelope::sign_envelope(&body, "delta", "k1", &p.sk).unwrap(),
            );
        }
    }
    let id = |name: &str| wist_core::delta::delta_id(&named[name]["delta"]).unwrap();
    let cases = vector["cases"].as_array().unwrap();
    let record_envelopes: Vec<_> = cases
        .iter()
        .map(|case| {
            reference_record(
                &id(case["audited"].as_str().unwrap()),
                &id(case["reference"].as_str().unwrap()),
                &jiff::Timestamp::from_second(
                    1_800_000_000 + case["fetched_at_s"].as_i64().unwrap(),
                )
                .unwrap()
                .to_string(),
            )
        })
        .collect();
    for height in 1..=10 {
        let mut entries: Vec<_> = vector["chain"]
            .as_array()
            .unwrap()
            .iter()
            .chain(vector["other_chain"].as_array().unwrap())
            .filter(|description| description["height"] == height)
            .map(|description| {
                entry(
                    "publisher_delta",
                    &named[description["id"].as_str().unwrap()],
                )
            })
            .collect();
        entries.extend(
            cases
                .iter()
                .zip(&record_envelopes)
                .filter(|(case, _)| case["record_height"] == height)
                .map(|(_, record)| entry("audit_record", record)),
        );
        f.append_at(entries, (height - 1) * 3600);
    }
    assert_eq!(cases.len(), 10);
    for _ in 0..2 {
        let records = IncludedRecord::reconstruct_all(f.data.path(), f.head.clone()).unwrap();
        assert_eq!(records.len(), cases.len());
        for (case, record_envelope) in cases.iter().zip(&record_envelopes) {
            let included = records
                .iter()
                .find(|record| record.envelope() == record_envelope)
                .unwrap();
            envelope::verify_envelope(
                included.envelope(),
                "record",
                &crypto::SigningKey::from_seed(&[17; 32]).public(),
            )
            .unwrap();
            assert_eq!(
                included.sealed_at_s(),
                1_800_000_000 + case["record_sealed_at_s"].as_i64().unwrap(),
            );
            let bound = included.resolve_reference(f.data.path());
            let chain = AuditChain::reconstruct(
                f.data.path(),
                f.head.clone(),
                &id(case["audited"].as_str().unwrap()),
            )
            .unwrap();
            let at = jiff::Timestamp::from_second(
                1_800_000_000 + case["fetched_at_s"].as_i64().unwrap(),
            )
            .unwrap()
            .to_string();
            assert_eq!(
                chain.newest_at(&at).unwrap().unwrap().id(),
                id(case["expected_reference"].as_str().unwrap()),
                "{}",
                case["label"],
            );
            let result = chain.resolve(&id(case["reference"].as_str().unwrap()), &at);
            if case["valid"] != true {
                assert!(bound.err().unwrap().to_string().contains("WIST4-E02"));
                assert!(result.err().unwrap().to_string().contains("WIST4-E02"));
                continue;
            }
            let bound = bound.unwrap();
            assert_eq!(bound.record().envelope(), included.envelope());
            assert_eq!(bound.record().block_hash(), included.block_hash());
            assert_eq!(
                bound.record().confirmation_profile(),
                included.confirmation_profile(),
            );
            assert_eq!(bound.audited().id(), id(case["audited"].as_str().unwrap()));
            let reference = result.unwrap();
            assert_eq!(bound.reference().id(), reference.delta().id());
            assert_eq!(
                reference.delta().envelope()["delta"]["change_type"],
                case["reading_change"],
            );
            let payload_name = case["resolved_payload"].as_str().unwrap();
            let source = reference.payload_source().unwrap();
            let bound_source = bound.payload_source().unwrap();
            assert_eq!(bound_source.delta_source().id(), source.delta_source().id());
            assert_eq!(
                bound_source
                    .validate(&payloads[payload_name])
                    .unwrap()
                    .content
                    .extract,
                payload_name,
            );
            let name = format!("payloads/{}.json", &source.delta_source().id()[7..]);
            std::fs::write(f.data.path().join(&name), &payloads[payload_name]).unwrap();
            if reference.delta().id() != source.delta_source().id() {
                std::fs::write(
                    f.data
                        .path()
                        .join(format!("payloads/{}.json", &reference.delta().id()[7..])),
                    b"contentless reference has no Payload of its own",
                )
                .unwrap();
            }
            let discovered = source.discover(&client, missing.path(), &[format!("http://{host}/")]);
            assert!(discovered.discovery_failures().is_empty());
            let remote = source.discover_with_remote_mirrors(
                &client,
                missing.path(),
                &[],
                &[format!("http://{host}/")],
            );
            assert!(remote.discovery_failures().is_empty());
            assert_eq!(remote.locations(), discovered.locations());
            for (origins, lists) in [
                (vec![format!("http://{host}/")], vec![]),
                (vec![], vec![format!("http://{host}/")]),
            ] {
                let retrieval = bound
                    .retrieve_payload(&client, missing.path(), &origins, &lists)
                    .unwrap();
                assert!(std::ptr::eq(retrieval.reference(), &bound));
                assert!(retrieval.locations().discovery_failures().is_empty());
                assert_eq!(retrieval.locations().locations(), discovered.locations());
                let copy = retrieval.result().unwrap();
                assert_eq!(copy.raw(), payloads[payload_name]);
                assert_eq!(copy.failed_attempts().len(), 1);
                assert!(std::ptr::eq(copy.source(), bound_source));
            }
            for copy in [
                source.read(f.data.path()).unwrap(),
                source
                    .retrieve(&client, discovered.locations().iter().cloned())
                    .unwrap(),
                source
                    .retrieve(&client, remote.locations().iter().cloned())
                    .unwrap(),
                source
                    .fetch(&client, &format!("http://{host}/{name}"))
                    .unwrap(),
            ] {
                assert_eq!(copy.payload().content.extract, payload_name);
                assert_eq!(copy.raw(), payloads[payload_name]);
                assert_eq!(
                    copy.source().delta_source().id(),
                    source.delta_source().id()
                );
            }
            assert_eq!(
                source
                    .validate(&payloads[payload_name])
                    .unwrap()
                    .content
                    .extract,
                payload_name,
            );
            let wrong = if payload_name == "P1" { "P2" } else { "P1" };
            assert!(source.validate(&payloads[wrong]).is_err());
        }
    }
    let chain = AuditChain::reconstruct(f.data.path(), f.head.clone(), &id("d1")).unwrap();
    assert!(chain.newest_at("0000-01-01T00:00:00Z").unwrap().is_none());
    assert_eq!(
        chain
            .newest_at("9999-12-31T23:59:59Z")
            .unwrap()
            .unwrap()
            .id(),
        id("d5")
    );
    for at in [
        "2026-08-09T12:00:60Z",
        "2026-08-09T12:00:00.0Z",
        "2026-08-09T12:00:00+00:00",
    ] {
        assert!(chain.newest_at(at).is_err());
        assert!(chain.resolve(&id("d1"), at).is_err());
    }
    let path = f.path(10);
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"broken").unwrap();
    for _ in 0..2 {
        assert!(AuditChain::reconstruct(f.data.path(), f.head.clone(), &id("d1")).is_err());
    }
    std::fs::write(path, bytes).unwrap();
    AuditChain::reconstruct(f.data.path(), f.head.clone(), &id("d1")).unwrap();
}
