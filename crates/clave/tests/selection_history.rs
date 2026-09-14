mod common;

use clave::db::BlockRow;
use clave::history::records::IncludedRecord;
use clave::history::roster::RosterHistory;
use clave::history::selection::{Disposition, SamplingState, SelectionDomain, SelectionFailure};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::sampling::{self, SamplingConstants};
use wist_core::{block, envelope, jcs, merkle, vrf};

const START: i64 = 1_800_000_000;
const HOUR: i64 = 3_600;
const WEEK: i64 = 7 * 86_400;

fn ts(at: i64) -> String {
    jiff::Timestamp::from_second(at).unwrap().to_string()
}

fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(format!("selection-history:{label}").as_bytes()).into()
}

fn key(label: &str) -> SigningKey {
    SigningKey::from_seed(&seed(label))
}

fn public(label: &str) -> String {
    key(label).public().to_b64u()
}

fn sorted(mut entries: Vec<Value>) -> Vec<Value> {
    entries.sort_by_key(|entry| {
        let rank = match entry["type"].as_str().unwrap() {
            "publisher_declaration" => 0,
            "registry_update" => 1,
            "publisher_delta" => 2,
            "audit_record" => 3,
            _ => 4,
        };
        (rank, merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()))
    });
    entries
}

struct Fixture {
    data: tempfile::TempDir,
    head: Option<BlockRow>,
    sk: SigningKey,
}

impl Fixture {
    fn new(log_id: &str) -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run(log_id, data.path()).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        Self {
            data,
            head: None,
            sk,
        }
    }

    fn path(&self, height: u64) -> std::path::PathBuf {
        self.data
            .path()
            .join(format!("log/blocks/{height:09}.json.zst"))
    }

    fn append(&mut self, at: i64, entries: Vec<Value>) -> BlockRow {
        let entries = sorted(entries);
        let height = self.head.as_ref().map_or(0, |head| head.block_number + 1);
        let leaves: Vec<_> = entries
            .iter()
            .map(|entry| merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()))
            .collect();
        let root = if leaves.is_empty() {
            merkle::leaf_hash(&[])
        } else {
            merkle::merkle_root(&leaves).unwrap()
        };
        let header = json!({
            "wist_version": "1.0.0", "block_number": height,
            "prev_block_hash": self.head.as_ref().map_or("sha256:genesis".into(), |head| head.block_hash.clone()),
            "sealed_at": ts(at), "entry_count": entries.len(),
            "merkle_root": format!("sha256:{}", hex_encode(&root)),
        });
        let signature = self.sk.sign(&jcs::canonicalize(&header).unwrap());
        let doc = json!({
            "header": header, "entries": entries,
            "sig": {"key_id": "log1", "alg": "Ed25519", "value": signature},
        });
        std::fs::write(
            self.path(height),
            zstd::bulk::compress(&jcs::canonicalize(&doc).unwrap(), 3).unwrap(),
        )
        .unwrap();
        let row = BlockRow {
            block_number: height,
            block_hash: block::block_hash(&doc["header"]).unwrap(),
            sealed_at: ts(at),
        };
        self.head = Some(row.clone());
        row
    }

    fn roster(&self) -> RosterHistory {
        RosterHistory::reconstruct(self.data.path(), self.head.clone()).unwrap()
    }

    fn domain(&self, block: &BlockRow) -> Result<SelectionDomain, clave::Error> {
        SelectionDomain::reconstruct(self.data.path(), self.head.clone(), &block.block_hash)
    }

    fn log_signed(&self, update: Value) -> Value {
        json!({
            "type": "registry_update",
            "body": envelope::sign_envelope(&update, "update", "log1", &self.sk).unwrap(),
        })
    }

    fn admit(&self, subject: &str, key_id: &str, public_key: &str) -> Value {
        self.log_signed(json!({
            "wist_version": "1.0.0", "action": "auditor_admit", "subject": subject,
            "details": {"key_id": key_id, "alg": "Ed25519", "public_key": public_key},
            "effective_at": ts(START),
        }))
    }

    fn remove(&self, subject: &str, key_id: &str, evidence: Option<Vec<&str>>) -> Value {
        let mut update = json!({
            "wist_version": "1.0.0", "action": "auditor_remove", "subject": subject,
            "details": {"key_id": key_id}, "effective_at": ts(START),
        });
        if let Some(evidence) = evidence {
            update["evidence"] = json!(evidence);
        }
        self.log_signed(update)
    }

    fn parameter(&self, name: &str, value: i64, effective: i64) -> Value {
        self.log_signed(json!({
            "wist_version": "1.0.0", "action": "parameter_change", "subject": name,
            "details": {"parameter": name, "value": value}, "effective_at": ts(effective),
        }))
    }
}

fn declaration(domain: &str, scope: &[&str], key_label: &str) -> Value {
    let mut publisher = json!({
        "wist_version": "1.0.0", "domain": domain,
        "keys": [{"key_id": "k1", "alg": "Ed25519", "public_key": public(key_label), "valid_from": "2026-08-01T00:00:00Z"}],
        "seq": 0,
    });
    if !scope.is_empty() {
        publisher["subdomain_scope"] = json!(scope);
    }
    json!({
        "type": "publisher_declaration",
        "body": envelope::sign_envelope(&publisher, "publisher", "k1", &key(key_label)).unwrap(),
    })
}

fn delta(publisher: &str, url: &str, key_label: &str) -> Value {
    let salt = wist_core::crypto::b64u_encode(&[5u8; 16]);
    let content = json!({"extract": format!("body of {url}"), "links": {"total": 0, "urls": []}, "summary": {"title": url}});
    let body = json!({
        "wist_version": "1.0.0", "publisher": publisher, "url": url, "change_type": "new",
        "observed_at": "2026-08-09T12:00:00Z",
        "payload": {
            "commitment": wist_core::delta::make_commitment(&salt, &content).unwrap(),
            "alg": "HMAC-SHA256",
            "bytes": wist_core::delta::content_bytes(&content).unwrap(),
        },
        "meta": {"lang": "en"},
    });
    json!({
        "type": "publisher_delta",
        "body": envelope::sign_envelope(&body, "delta", "k1", &key(key_label)).unwrap(),
    })
}

fn delta_id(entry: &Value) -> String {
    wist_core::delta::delta_id(&entry["body"]["delta"]).unwrap()
}

fn proof(key_label: &str, block: &BlockRow) -> [u8; vrf::PROOF_LEN] {
    let alpha = sampling::alpha_from_block_hash(&block.block_hash).unwrap();
    vrf::prove(&seed(key_label), &alpha).unwrap()
}

fn record(
    auditor: &str,
    key_label: &str,
    audited: &str,
    proof_hex: &str,
    fetched_at: i64,
) -> Value {
    let commitment = |tag: &str| {
        format!(
            "hmac-sha256:{}",
            hex_encode(&Sha256::digest(format!("{auditor}:{tag}").as_bytes()))
        )
    };
    let body = json!({
        "wist_version": "1.0.0",
        "audited_delta": audited,
        "reference_delta": audited,
        "auditor_id": auditor,
        "fetched_at": ts(fetched_at),
        "verdict": "consistent",
        "similarity": 950000,
        "link_agreement": 1000000,
        "response_commitment": commitment("response"),
        "credit_commitment": commitment("credit"),
        "ref_extract_commitment": commitment("ref"),
        "evidence_commitment": commitment("evidence"),
        "vrf_proof": proof_hex,
        "prev_record": null,
    });
    json!({
        "type": "audit_record",
        "body": envelope::sign_envelope(&body, "record", "k1", &key(key_label)).unwrap(),
    })
}

fn state(reputation_u: u64) -> impl Fn(&str) -> SamplingState {
    move |_| SamplingState {
        reputation_u,
        level1_sanction: false,
        escalated_sampling: false,
    }
}

fn expected_selected(
    key_label: &str,
    block: &BlockRow,
    deltas: &[Value],
    p_1e7: u64,
) -> BTreeSet<String> {
    let alpha = sampling::alpha_from_block_hash(&block.block_hash).unwrap();
    let pi = vrf::prove(&seed(key_label), &alpha).unwrap();
    let public_key: [u8; 32] = wist_core::crypto::b64u_decode(&public(key_label))
        .unwrap()
        .try_into()
        .unwrap();
    let beta = vrf::verify(&public_key, &alpha, &pi).unwrap();
    deltas
        .iter()
        .map(delta_id)
        .filter(|id| sampling::selected(sampling::draw(&beta, id), p_1e7))
        .collect()
}

fn selected_ids(set: &clave::history::selection::SelectionSet<'_>) -> BTreeSet<String> {
    set.selected().map(|delta| delta.id.clone()).collect()
}

#[test]
fn selection_domain_vectors_replay_in_signed_histories() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/selection-domain.json")).unwrap(),
    )
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let height = case["block_height"].as_u64().unwrap();
        let entries = case["entries"].as_array().unwrap();
        let mut fx = Fixture::new("log.example.test");
        let scope: Vec<&str> = entries
            .iter()
            .map(|entry| entry["url_host"].as_str().unwrap())
            .filter(|host| *host != "example.com")
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut by_height = BTreeMap::<u64, Vec<Value>>::new();
        by_height
            .entry(0)
            .or_default()
            .push(declaration("example.com", &scope, "example.com"));
        for declared in case["declarations"].as_array().unwrap() {
            let domain = declared["domain"].as_str().unwrap();
            by_height
                .entry(declared["seq0_height"].as_u64().unwrap())
                .or_default()
                .push(declaration(domain, &[], domain));
        }
        let deltas: Vec<Value> = entries
            .iter()
            .map(|entry| {
                let publisher = entry["publisher"].as_str().unwrap();
                delta(
                    publisher,
                    &format!(
                        "https://{}/{}",
                        entry["url_host"].as_str().unwrap(),
                        entry["delta_id"].as_str().unwrap()
                    ),
                    publisher,
                )
            })
            .collect();
        by_height.entry(height).or_default().extend(deltas.clone());
        let mut audited = None;
        for h in 0..=height {
            let row = fx.append(
                START + h as i64 * HOUR,
                by_height.remove(&h).unwrap_or_default(),
            );
            if h == height {
                audited = Some(row);
            }
        }
        let audited = audited.unwrap();
        let expected: BTreeSet<String> = case["excluded_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| delta_id(&deltas[i.as_u64().unwrap() as usize]))
            .collect();
        for attempt in 0..2 {
            let domain = fx.domain(&audited).unwrap();
            assert_eq!(domain.block().block_hash, audited.block_hash, "{label}");
            assert_eq!(domain.deltas().len(), entries.len(), "{label}");
            let excluded: BTreeSet<String> = domain
                .deltas()
                .iter()
                .filter(|delta| delta.excluded)
                .map(|delta| delta.id.clone())
                .collect();
            assert_eq!(excluded, expected, "{label} (attempt {attempt})");
            for delta in domain.deltas() {
                let entry = entries
                    .iter()
                    .find(|entry| {
                        delta.url_host == entry["url_host"].as_str().unwrap()
                            && delta.publisher == entry["publisher"].as_str().unwrap()
                    })
                    .unwrap();
                let seq0 = case["declarations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|d| d["domain"] == entry["url_host"])
                    .map(|d| d["seq0_height"].as_u64().unwrap())
                    .filter(|seq0| *seq0 <= height)
                    .or((delta.url_host == "example.com").then_some(0));
                assert_eq!(delta.host_seq0_height, seq0, "{label}: {}", delta.id);
                assert_eq!(delta.publisher, entry["publisher"], "{label}");
            }
        }
    }
}

#[test]
fn self_audit_vectors_bar_the_signed_publisher_from_the_auditors_draw() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/selection-domain.json")).unwrap(),
    )
    .unwrap();
    let cases = vectors["self_audit_cases"].as_array().unwrap();
    let mut fx = Fixture::new("log.example.test");
    let auditors: BTreeSet<&str> = cases
        .iter()
        .map(|case| case["auditor_id"].as_str().unwrap())
        .collect();
    let publishers: BTreeSet<&str> = cases
        .iter()
        .map(|case| case["publisher"].as_str().unwrap())
        .collect();
    let mut genesis: Vec<Value> = auditors
        .iter()
        .map(|auditor| fx.admit(auditor, &format!("key:{auditor}"), &public(auditor)))
        .collect();
    genesis.extend(
        publishers
            .iter()
            .map(|publisher| declaration(publisher, &[], &format!("pub:{publisher}"))),
    );
    fx.append(START, genesis);
    let deltas: Vec<Value> = publishers
        .iter()
        .map(|publisher| {
            delta(
                publisher,
                &format!("https://{publisher}/page"),
                &format!("pub:{publisher}"),
            )
        })
        .collect();
    let audited = fx.append(START + HOUR, deltas.clone());
    let roster = fx.roster();
    assert!(roster.rejected().is_empty(), "{:?}", roster.rejected());
    let domain = fx.domain(&audited).unwrap();
    let ceiling = |_: &str| SamplingState {
        reputation_u: 0,
        level1_sanction: true,
        escalated_sampling: false,
    };
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let auditor = case["auditor_id"].as_str().unwrap();
        let publisher = case["publisher"].as_str().unwrap();
        let set = domain
            .selection_set(&roster, auditor, &proof(auditor, &audited), &ceiling)
            .unwrap()
            .unwrap();
        let id = deltas
            .iter()
            .map(delta_id)
            .zip(publishers.iter())
            .find(|(_, p)| **p == publisher)
            .unwrap()
            .0;
        let disposition = set.disposition(&id).unwrap();
        if case["barred"].as_bool().unwrap() {
            assert_eq!(disposition, Disposition::SelfAudit, "{label}");
        } else {
            assert!(
                matches!(disposition, Disposition::Selected | Disposition::NotDrawn),
                "{label}: {disposition:?}"
            );
        }
        let draw = set.draws().iter().find(|draw| draw.delta.id == id).unwrap();
        assert_eq!(
            draw.d.is_some(),
            !case["barred"].as_bool().unwrap(),
            "{label}"
        );
        assert_eq!(
            draw.p_1e7,
            (!case["barred"].as_bool().unwrap()).then_some(5_000_000),
            "{label}"
        );
    }
}

#[test]
fn draws_follow_the_key_held_at_the_block_and_the_blocks_sampling_constants() {
    let mut fx = Fixture::new("log.example.test");
    fx.append(
        START,
        vec![
            fx.admit("audit.example.org", "k1", &public("a1")),
            declaration("site.example.net", &[], "site"),
            declaration("press.example.com", &[], "press"),
            fx.parameter("sampling_slope", 0, START + WEEK),
        ],
    );
    let page = |height: u64, publisher: &str, i: usize| {
        delta(
            publisher,
            &format!("https://{publisher}/b{height}/p{i}"),
            publisher.split('.').next().unwrap(),
        )
    };
    let deltas_1: Vec<Value> = (0..12)
        .flat_map(|i| {
            [
                page(1, "site.example.net", i),
                page(1, "press.example.com", i),
            ]
        })
        .collect();
    let block_1 = fx.append(START + HOUR, deltas_1.clone());
    let deltas_2: Vec<Value> = (0..12)
        .flat_map(|i| {
            [
                page(2, "site.example.net", i),
                page(2, "press.example.com", i),
            ]
        })
        .collect();
    let block_2 = fx.append(START + WEEK, deltas_2.clone());
    let roster = fx.roster();
    let domain_1 = fx.domain(&block_1).unwrap();
    let domain_2 = fx.domain(&block_2).unwrap();
    assert_eq!(*domain_1.sampling_constants(), SamplingConstants::default());
    assert_eq!(
        *domain_2.sampling_constants(),
        SamplingConstants {
            slope_per_micro: 0,
            ..SamplingConstants::default()
        }
    );
    let pi_1 = proof("a1", &block_1);
    let provisional = domain_1
        .selection_set(&roster, "audit.example.org", &pi_1, &state(100_000))
        .unwrap()
        .unwrap();
    let established = domain_1
        .selection_set(&roster, "audit.example.org", &pi_1, &state(900_000))
        .unwrap()
        .unwrap();
    assert_eq!(
        selected_ids(&provisional),
        expected_selected("a1", &block_1, &deltas_1, 2_900_000)
    );
    assert_eq!(
        selected_ids(&established),
        expected_selected("a1", &block_1, &deltas_1, 500_000)
    );
    assert_ne!(selected_ids(&provisional), selected_ids(&established));
    assert!(selected_ids(&established).is_subset(&selected_ids(&provisional)));
    assert_eq!(provisional.key_id(), "k1");
    assert_eq!(provisional.public_key(), public("a1"));
    assert!(provisional
        .draws()
        .iter()
        .all(|draw| draw.p_1e7 == Some(2_900_000) && draw.d.is_some()));
    let sanctioned = |publisher: &str| SamplingState {
        reputation_u: 1_000_000,
        level1_sanction: publisher == "site.example.net",
        escalated_sampling: publisher == "press.example.com",
    };
    let displaced = domain_1
        .selection_set(&roster, "audit.example.org", &pi_1, &sanctioned)
        .unwrap()
        .unwrap();
    assert_eq!(
        selected_ids(&displaced),
        expected_selected("a1", &block_1, &deltas_1, 5_000_000)
    );
    assert!(displaced
        .draws()
        .iter()
        .all(|draw| draw.p_1e7 == Some(5_000_000)));
    let pi_2 = proof("a1", &block_2);
    for reputation in [0, 100_000, 900_000, 1_000_000] {
        let set = domain_2
            .selection_set(&roster, "audit.example.org", &pi_2, &state(reputation))
            .unwrap()
            .unwrap();
        assert_eq!(
            selected_ids(&set),
            expected_selected("a1", &block_2, &deltas_2, 200_000),
            "reputation {reputation}"
        );
        assert!(set.draws().iter().all(|draw| draw.p_1e7 == Some(200_000)));
    }
    assert_eq!(
        domain_2
            .selection_set(&roster, "audit.example.org", &pi_1, &state(0))
            .unwrap()
            .unwrap_err(),
        SelectionFailure::ProofDoesNotVerify
    );
    assert_eq!(
        domain_1
            .selection_set(&roster, "checker.sample.org", &pi_1, &state(0))
            .unwrap()
            .unwrap_err(),
        SelectionFailure::NoKeyAtBlock
    );

    fx.append(
        START + WEEK + HOUR,
        vec![
            fx.remove("audit.example.org", "k1", None),
            fx.admit("audit.example.org", "k2", &public("a2")),
        ],
    );
    let deltas_4: Vec<Value> = (0..8).map(|i| page(4, "site.example.net", i)).collect();
    let block_4 = fx.append(START + WEEK + 2 * HOUR, deltas_4.clone());
    fx.append(
        START + WEEK + 3 * HOUR,
        vec![fx.remove("audit.example.org", "k2", Some(vec!["sha256:failed"]))],
    );
    let block_6 = fx.append(
        START + WEEK + 4 * HOUR,
        vec![page(6, "site.example.net", 0)],
    );
    let roster = fx.roster();
    assert!(roster.rejected().is_empty(), "{:?}", roster.rejected());
    for attempt in 0..2 {
        let domain_1 = fx.domain(&block_1).unwrap();
        let domain_4 = fx.domain(&block_4).unwrap();
        let domain_6 = fx.domain(&block_6).unwrap();
        let old_key = domain_1
            .selection_set(&roster, "audit.example.org", &pi_1, &state(100_000))
            .unwrap()
            .unwrap();
        assert_eq!(
            selected_ids(&old_key),
            selected_ids(&provisional),
            "attempt {attempt}"
        );
        assert_eq!(old_key.beta(), provisional.beta());
        assert_eq!(
            domain_1
                .selection_set(
                    &roster,
                    "audit.example.org",
                    &proof("a2", &block_1),
                    &state(0)
                )
                .unwrap()
                .unwrap_err(),
            SelectionFailure::ProofDoesNotVerify
        );
        let rotated = domain_4
            .selection_set(
                &roster,
                "audit.example.org",
                &proof("a2", &block_4),
                &state(0),
            )
            .unwrap()
            .unwrap();
        assert_eq!(rotated.key_id(), "k2");
        assert_eq!(
            selected_ids(&rotated),
            expected_selected("a2", &block_4, &deltas_4, 200_000)
        );
        assert_eq!(
            domain_4
                .selection_set(
                    &roster,
                    "audit.example.org",
                    &proof("a1", &block_4),
                    &state(0)
                )
                .unwrap()
                .unwrap_err(),
            SelectionFailure::ProofDoesNotVerify
        );
        assert_eq!(
            domain_6
                .selection_set(
                    &roster,
                    "audit.example.org",
                    &proof("a2", &block_6),
                    &state(0)
                )
                .unwrap()
                .unwrap_err(),
            SelectionFailure::NoKeyAtBlock
        );
    }
}

#[test]
fn lexically_valid_unusable_keys_verify_no_proof() {
    let mut fx = Fixture::new("log.example.test");
    let identity = wist_core::crypto::b64u_encode(&{
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes
    });
    let noncanonical = wist_core::crypto::b64u_encode(&{
        let mut bytes = [0xffu8; 32];
        bytes[0] = 0xee;
        bytes[31] = 0x7f;
        bytes
    });
    fx.append(
        START,
        vec![
            fx.admit("weak.example.org", "weak", &identity),
            fx.admit("odd.sample.net", "odd", &noncanonical),
            fx.admit("audit.example.net", "k1", &public("k1")),
            declaration("site.example.com", &[], "site"),
        ],
    );
    let audited = fx.append(
        START + HOUR,
        vec![delta(
            "site.example.com",
            "https://site.example.com/page",
            "site",
        )],
    );
    let roster = fx.roster();
    assert!(roster.rejected().is_empty(), "{:?}", roster.rejected());
    let domain = fx.domain(&audited).unwrap();
    for auditor in ["weak.example.org", "odd.sample.net"] {
        assert!(roster.admitted_key_at(auditor, START + HOUR).is_some());
        assert_eq!(
            domain
                .selection_set(&roster, auditor, &proof("k1", &audited), &state(0))
                .unwrap()
                .unwrap_err(),
            SelectionFailure::ProofDoesNotVerify,
            "{auditor}"
        );
    }
    assert!(domain
        .selection_set(
            &roster,
            "audit.example.net",
            &proof("k1", &audited),
            &state(0)
        )
        .unwrap()
        .is_ok());
    let mut tampered = proof("k1", &audited);
    tampered[3] ^= 1;
    assert_eq!(
        domain
            .selection_set(&roster, "audit.example.net", &tampered, &state(0))
            .unwrap()
            .unwrap_err(),
        SelectionFailure::ProofDoesNotVerify
    );
}

#[test]
fn selection_domains_require_the_complete_pinned_prefix_and_matching_rosters() {
    let mut fx = Fixture::new("log.example.test");
    fx.append(
        START,
        vec![
            fx.admit("audit.example.net", "k1", &public("k1")),
            declaration("site.example.com", &[], "site"),
        ],
    );
    let audited = fx.append(
        START + HOUR,
        vec![delta(
            "site.example.com",
            "https://site.example.com/page",
            "site",
        )],
    );
    let later = fx.append(
        START + 2 * HOUR,
        vec![delta(
            "site.example.com",
            "https://site.example.com/other",
            "site",
        )],
    );
    let original = std::fs::read(fx.path(2)).unwrap();
    std::fs::write(fx.path(2), b"corrupt").unwrap();
    assert!(fx.domain(&audited).is_err());
    std::fs::write(fx.path(2), original).unwrap();
    let domain = fx.domain(&audited).unwrap();
    assert_eq!(domain.deltas().len(), 1);
    assert!(SelectionDomain::reconstruct(
        fx.data.path(),
        fx.head.clone(),
        &format!("sha256:{}", "0".repeat(64))
    )
    .is_err());
    let pinned = RosterHistory::reconstruct(fx.data.path(), Some(audited.clone())).unwrap();
    assert!(domain
        .selection_set(
            &pinned,
            "audit.example.net",
            &proof("k1", &audited),
            &state(0)
        )
        .unwrap()
        .is_ok());
    let short = RosterHistory::reconstruct(
        fx.data.path(),
        Some(BlockRow {
            block_number: 0,
            block_hash: {
                let bytes = zstd::decode_all(std::fs::File::open(fx.path(0)).unwrap()).unwrap();
                let doc: Value = serde_json::from_slice(&bytes).unwrap();
                block::block_hash(&doc["header"]).unwrap()
            },
            sealed_at: ts(START),
        }),
    )
    .unwrap();
    assert!(domain
        .selection_set(
            &short,
            "audit.example.net",
            &proof("k1", &audited),
            &state(0)
        )
        .is_err());
    let mut other = Fixture::new("log.example.test");
    other.append(
        START,
        vec![other.admit("audit.example.net", "k1", &public("k1"))],
    );
    other.append(START + HOUR, vec![]);
    assert!(domain
        .selection_set(
            &other.roster(),
            "audit.example.net",
            &proof("k1", &audited),
            &state(0)
        )
        .is_err());
    let full = fx.roster();
    let from_later = fx.domain(&later).unwrap();
    assert_eq!(from_later.block().block_number, 2);
    assert!(from_later
        .selection_set(&full, "audit.example.net", &proof("k1", &later), &state(0))
        .unwrap()
        .is_ok());
}

#[test]
fn included_records_carry_proofs_that_bind_to_selection_sets() {
    let mut fx = Fixture::new("log.example.test");
    let genesis = fx.append(
        START,
        vec![
            fx.admit("audit.example.org", "k1", &public("a1")),
            declaration("example.com", &["blog.example.com"], "example.com"),
            declaration("blog.example.com", &[], "blog.example.com"),
        ],
    );
    let own: Vec<Value> = (0..16)
        .map(|i| {
            delta(
                "example.com",
                &format!("https://example.com/p{i}"),
                "example.com",
            )
        })
        .collect();
    let parent_for_blog = delta(
        "example.com",
        "https://blog.example.com/post",
        "example.com",
    );
    let mut entries = own.clone();
    entries.push(parent_for_blog.clone());
    let audited = fx.append(START + HOUR, entries);
    let expected = expected_selected("a1", &audited, &own, 2_900_000);
    let chosen = expected.iter().next().unwrap().clone();
    let not_drawn = own
        .iter()
        .map(delta_id)
        .find(|id| !expected.contains(id))
        .unwrap();
    let pi = hex_encode(&proof("a1", &audited));
    let sealed = fx.append(
        START + 2 * HOUR,
        vec![
            record("audit.example.org", "a1", &chosen, &pi, START + HOUR + 1),
            record("audit.example.org", "a1", &not_drawn, &pi, START + HOUR + 2),
            record(
                "audit.example.org",
                "a1",
                &delta_id(&parent_for_blog),
                &pi,
                START + HOUR + 3,
            ),
            record(
                "audit.example.org",
                "a1",
                &chosen,
                &hex_encode(&proof("a1", &genesis)),
                START + HOUR + 4,
            ),
            record(
                "audit.example.org",
                "a1",
                &chosen,
                &pi[..158],
                START + HOUR + 5,
            ),
        ],
    );
    let roster = fx.roster();
    let domain = fx.domain(&audited).unwrap();
    let records = IncludedRecord::reconstruct_all(fx.data.path(), fx.head.clone()).unwrap();
    assert_eq!(records.len(), 5);
    let mut seen = BTreeMap::new();
    for included in &records {
        let audited_id = included.envelope()["record"]["audited_delta"]
            .as_str()
            .unwrap()
            .to_owned();
        let fetched = included.envelope()["record"]["fetched_at"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(included.position().block_number, sealed.block_number);
        let Some(proof) = included.vrf_proof() else {
            assert_eq!(fetched, ts(START + HOUR + 5));
            assert_eq!(included.field_validation().diagnostic(), Some("WIST4-E09"));
            continue;
        };
        let outcome = domain
            .selection_set(&roster, "audit.example.org", &proof, &state(100_000))
            .unwrap()
            .map(|set| set.disposition(&audited_id).unwrap());
        seen.insert(fetched, outcome);
    }
    assert_eq!(
        seen.remove(&ts(START + HOUR + 1)),
        Some(Ok(Disposition::Selected))
    );
    assert_eq!(
        seen.remove(&ts(START + HOUR + 2)),
        Some(Ok(Disposition::NotDrawn))
    );
    assert_eq!(
        seen.remove(&ts(START + HOUR + 3)),
        Some(Ok(Disposition::OutsideDomain))
    );
    assert_eq!(
        seen.remove(&ts(START + HOUR + 4)),
        Some(Err(SelectionFailure::ProofDoesNotVerify))
    );
    assert!(seen.is_empty());
}
