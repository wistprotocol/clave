use clave::db::{BlockRow, Db};
use clave::history::declarations::Position;
use clave::history::records::IncludedRecord;
use clave::history::roster::RosterHistory;
use clave::record::{Duty, ReplayContext};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wist_core::crypto::{hex_encode, PublicKey, SigningKey};
use wist_core::{block, envelope, jcs, merkle};

mod common;

const START: i64 = 1_800_000_000;
const HOUR: i64 = 3_600;

struct Fixture {
    data: tempfile::TempDir,
    db: Db,
    sk: SigningKey,
}

fn ts(at: i64) -> String {
    jiff::Timestamp::from_second(at).unwrap().to_string()
}

fn key(label: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(format!("roster-history:{label}").as_bytes()).into();
    SigningKey::from_seed(&seed)
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

fn wrap(body: Value) -> Value {
    json!({"type": "registry_update", "body": body})
}

impl Fixture {
    fn new(log_id: &str) -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run(log_id, data.path()).unwrap();
        let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        Self { data, db, sk }
    }

    fn path(&self, height: u64) -> std::path::PathBuf {
        self.data
            .path()
            .join(format!("log/blocks/{height:09}.json.zst"))
    }

    fn append(&self, at: i64, entries: Vec<Value>) -> Value {
        let entries = sorted(entries);
        let head = self.db.last_block().unwrap();
        let height = head.as_ref().map_or(0, |b| b.block_number + 1);
        let leaves: Vec<_> = entries
            .iter()
            .map(|e| merkle::leaf_hash(&jcs::canonicalize(e).unwrap()))
            .collect();
        let root = if leaves.is_empty() {
            merkle::leaf_hash(&[])
        } else {
            merkle::merkle_root(&leaves).unwrap()
        };
        let header = json!({
            "wist_version": "1.0.0", "block_number": height,
            "prev_block_hash": head.map_or("sha256:genesis".into(), |b| b.block_hash),
            "sealed_at": ts(at), "entry_count": entries.len(),
            "merkle_root": format!("sha256:{}", hex_encode(&root)),
        });
        let signature = self.sk.sign(&jcs::canonicalize(&header).unwrap());
        let doc = json!({
            "header": header, "entries": entries,
            "sig": {"key_id":"log1", "alg":"Ed25519", "value": signature},
        });
        let bytes = jcs::canonicalize(&doc).unwrap();
        std::fs::write(self.path(height), zstd::bulk::compress(&bytes, 3).unwrap()).unwrap();
        self.db
            .commit_seal(
                &[],
                height,
                &block::block_hash(&header).unwrap(),
                &ts(at),
                &[],
                &[],
                &[],
                &[],
                bytes.len() as u64,
            )
            .unwrap();
        doc
    }

    fn head(&self) -> Option<BlockRow> {
        self.db.last_block().unwrap()
    }

    fn roster(&self) -> RosterHistory {
        RosterHistory::reconstruct(self.data.path(), self.head()).unwrap()
    }

    fn log_signed(&self, update: Value) -> Value {
        wrap(envelope::sign_envelope(&update, "update", "log1", &self.sk).unwrap())
    }

    fn admit(&self, subject: &str, key_id: &str, public_key: &str) -> Value {
        self.log_signed(admit_update(subject, key_id, public_key, None, START))
    }

    fn remove(&self, subject: &str, key_id: &str, evidence: Option<Vec<&str>>) -> Value {
        self.remove_at(subject, key_id, evidence, START)
    }

    fn remove_at(
        &self,
        subject: &str,
        key_id: &str,
        evidence: Option<Vec<&str>>,
        effective: i64,
    ) -> Value {
        let mut update = json!({
            "wist_version": "1.0.0", "action": "auditor_remove", "subject": subject,
            "details": {"key_id": key_id}, "effective_at": ts(effective),
        });
        if let Some(evidence) = evidence {
            update["evidence"] = json!(evidence);
        }
        self.log_signed(update)
    }

    fn parameter(&self, name: &str, value: i64, effective: i64) -> Value {
        self.log_signed(json!({
            "wist_version":"1.0.0", "action":"parameter_change", "subject":name,
            "details":{"parameter":name,"value":value}, "effective_at":ts(effective),
        }))
    }
}

fn admit_update(
    subject: &str,
    key_id: &str,
    public_key: &str,
    track_record: Option<Value>,
    effective: i64,
) -> Value {
    let mut details = json!({"key_id": key_id, "alg": "Ed25519", "public_key": public_key});
    if let Some(track_record) = track_record {
        details["track_record"] = track_record;
    }
    json!({
        "wist_version": "1.0.0", "action": "auditor_admit", "subject": subject,
        "details": details, "effective_at": ts(effective),
    })
}

fn track_record(checkpoint: &Value) -> Value {
    json!({
        "checkpoint": wist_core::delta::delta_id(&checkpoint["body"]["update"]).unwrap(),
        "scoreboard": {"provisional": [0, 0, 0], "standing": [0, 0, 0], "mature": [0, 0, 0]},
    })
}

fn register(subject: &str, key_id: &str, key_label: &str) -> Value {
    let update = json!({
        "wist_version": "1.0.0", "action": "observer_register", "subject": subject,
        "details": {"key_id": key_id, "alg": "Ed25519", "public_key": public(key_label)},
        "effective_at": ts(START),
    });
    wrap(envelope::sign_envelope(&update, "update", key_id, &key(key_label)).unwrap())
}

fn checkpoint(subject: &str, key_id: &str, key_label: &str, head: &str) -> Value {
    let update = json!({
        "wist_version": "1.0.0", "action": "observer_checkpoint", "subject": subject,
        "details": {"head": head}, "effective_at": ts(START),
    });
    wrap(envelope::sign_envelope(&update, "update", key_id, &key(key_label)).unwrap())
}

fn digest(tag: &str) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(tag.as_bytes())))
}

fn record(auditor: &str, key_id: &str, key_label: &str, fetched_at: i64) -> Value {
    let commitment = |tag: &str| {
        format!(
            "hmac-sha256:{}",
            hex_encode(&Sha256::digest(format!("{auditor}:{tag}").as_bytes()))
        )
    };
    let body = json!({
        "wist_version": "1.0.0",
        "audited_delta": digest("audited"),
        "reference_delta": digest("audited"),
        "auditor_id": auditor,
        "fetched_at": ts(fetched_at),
        "verdict": "consistent",
        "similarity": 950000,
        "link_agreement": 1000000,
        "response_commitment": commitment("response"),
        "credit_commitment": commitment("credit"),
        "ref_extract_commitment": commitment("ref"),
        "evidence_commitment": commitment("evidence"),
        "vrf_proof": "ab".repeat(80),
        "prev_record": null,
    });
    json!({
        "type": "audit_record",
        "body": envelope::sign_envelope(&body, "record", key_id, &key(key_label)).unwrap(),
    })
}

fn positions_of(blocks: &[Value], entries: &[Value]) -> BTreeSet<Position> {
    entries
        .iter()
        .map(|wanted| {
            blocks
                .iter()
                .find_map(|block| {
                    block["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .position(|entry| entry == wanted)
                        .map(|entry_index| Position {
                            block_number: block["header"]["block_number"].as_u64().unwrap(),
                            entry_index,
                        })
                })
                .expect("entry is sealed")
        })
        .collect()
}

fn rejected_positions(roster: &RosterHistory) -> BTreeSet<Position> {
    roster.rejected().iter().map(|r| r.position).collect()
}

fn vector_act(fx: &Fixture, entry: &Value) -> Value {
    let subject = entry["auditor_id"].as_str().unwrap();
    let key_id = entry["key_id"].as_str().unwrap();
    let effective = START + entry["sealed_at_s"].as_i64().unwrap();
    match entry["action"].as_str().unwrap() {
        "auditor_admit" => fx.log_signed(admit_update(
            subject,
            key_id,
            &public(entry["public_key"].as_str().unwrap()),
            None,
            effective,
        )),
        "auditor_remove" => fx.remove_at(
            subject,
            key_id,
            entry["evidence"]
                .as_array()
                .map(|ids| ids.iter().map(|id| id.as_str().unwrap()).collect()),
            effective,
        ),
        other => panic!("unexpected roster action {other}"),
    }
}

#[test]
fn roster_vectors_replay_in_signed_histories() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/roster.json")).unwrap(),
    )
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let fx = Fixture::new(case["log_id"].as_str().unwrap());
        let entries: Vec<Value> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| vector_act(&fx, entry))
            .collect();
        let mut blocks = Vec::new();
        let mut start = 0;
        let vector_entries = case["entries"].as_array().unwrap();
        while start < entries.len() {
            let at = vector_entries[start]["sealed_at_s"].as_i64().unwrap();
            let len = vector_entries[start..]
                .iter()
                .take_while(|entry| entry["sealed_at_s"].as_i64().unwrap() == at)
                .count();
            blocks.push(fx.append(START + at, entries[start..start + len].to_vec()));
            start += len;
        }
        let expected: Vec<Value> = case["rejected_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| entries[i.as_u64().unwrap() as usize].clone())
            .collect();
        for attempt in 0..2 {
            let roster = fx.roster();
            assert_eq!(
                rejected_positions(&roster),
                positions_of(&blocks, &expected),
                "{label} (attempt {attempt}): {:?}",
                roster.rejected()
            );
            assert!(
                roster
                    .rejected()
                    .iter()
                    .all(|r| r.code == "WIST4-E07" && r.reason.contains("WIST4-E07")),
                "{label}: {:?}",
                roster.rejected()
            );
            for query in case["admitted_key_at"].as_array().unwrap() {
                let auditor_id = query["auditor_id"].as_str().unwrap();
                let at = START + query["sealed_at_s"].as_i64().unwrap();
                let binding = roster.admitted_key_at(auditor_id, at);
                assert_eq!(
                    binding.map(|b| b.key_id),
                    query["key_id"].as_str(),
                    "{label}: {auditor_id} at {at}"
                );
                if let Some(binding) = binding {
                    let admitted = vector_entries
                        .iter()
                        .find(|e| {
                            e["action"] == "auditor_admit"
                                && e["auditor_id"] == auditor_id
                                && e["key_id"] == binding.key_id
                        })
                        .unwrap();
                    assert_eq!(
                        binding.public_key,
                        public(admitted["public_key"].as_str().unwrap()),
                        "{label}"
                    );
                    assert!(roster.signing_binding(auditor_id, at).is_some(), "{label}");
                }
            }
        }
    }
}

#[test]
fn roster_batch_vectors_replay_in_signed_histories() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/roster.json")).unwrap(),
    )
    .unwrap();
    for case in vectors["batch_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let fx = Fixture::new("log.example.org");
        let initial = &case["initial_after_removals"];
        let mut seeds = Vec::new();
        let mut removals = Vec::new();
        for (subject, held) in initial["auditors"].as_object().unwrap() {
            seeds.push(fx.admit(
                subject,
                held["key_id"].as_str().unwrap(),
                &public(held["public_key"].as_str().unwrap()),
            ));
        }
        let mut checkpoints = BTreeMap::new();
        for (subject, held) in initial["observers"].as_object().unwrap() {
            let key_id = held["key_id"].as_str().unwrap();
            let key_label = held["public_key"].as_str().unwrap();
            seeds.push(register(subject, key_id, key_label));
            let sealed = checkpoint(subject, key_id, key_label, &digest(subject));
            removals.push(sealed.clone());
            checkpoints.insert(subject.as_str(), sealed);
        }
        for (i, key_id) in initial["retired_key_ids"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let subject = format!("retired{i}.seed.example");
            let key_id = key_id.as_str().unwrap();
            seeds.push(fx.admit(&subject, key_id, &public(&format!("retired key {i}"))));
            removals.push(fx.remove(&subject, key_id, None));
        }
        for (i, public_key) in initial["retired_public_keys"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let subject = format!("retiredpk{i}.seed.example");
            let key_id = format!("retired-pk-{i}");
            seeds.push(fx.admit(&subject, &key_id, &public(public_key.as_str().unwrap())));
            removals.push(fx.remove(&subject, &key_id, None));
        }
        for (i, subject) in initial["barred"].as_array().unwrap().iter().enumerate() {
            let subject = subject.as_str().unwrap();
            let key_id = format!("barred-{i}");
            seeds.push(fx.admit(subject, &key_id, &public(&format!("barred key {i}"))));
            removals.push(fx.remove(subject, &key_id, Some(vec!["sha256:void-record"])));
        }
        fx.append(START, seeds);
        fx.append(START + HOUR, removals);
        let seeded = fx.roster();
        assert!(
            seeded.rejected().is_empty(),
            "{label}: {:?}",
            seeded.rejected()
        );
        assert_eq!(seeded.checkpoints().len(), checkpoints.len(), "{label}");

        let acts: Vec<Value> = case["acts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|act| {
                let subject = act["subject"].as_str().unwrap();
                let key_id = act["key_id"].as_str().unwrap();
                let public_key = act["public_key"].as_str().unwrap();
                match act["action"].as_str().unwrap() {
                    "auditor_admit" => fx.log_signed(admit_update(
                        subject,
                        key_id,
                        &public(public_key),
                        checkpoints.get(subject).map(track_record),
                        START,
                    )),
                    "observer_register" => register(subject, key_id, public_key),
                    other => panic!("unexpected batch action {other}"),
                }
            })
            .collect();
        let at = START + 2 * HOUR;
        let block = fx.append(at, acts.clone());
        let expected = &case["expected"];
        let wanted: Vec<Value> = expected["rejected_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| acts[i.as_u64().unwrap() as usize].clone())
            .collect();
        let roster = fx.roster();
        assert_eq!(
            rejected_positions(&roster),
            positions_of(&[block], &wanted),
            "{label}: {:?}",
            roster.rejected()
        );
        let admitted: BTreeMap<&str, &str> = roster.admitted_at(at).into_iter().collect();
        let expected_auditors: BTreeMap<&str, &str> = expected["auditors"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(subject, held)| (subject.as_str(), held["key_id"].as_str().unwrap()))
            .collect();
        assert_eq!(admitted, expected_auditors, "{label}");
        let registered: BTreeMap<&str, &str> = roster.registered_at(at).into_iter().collect();
        let expected_observers: BTreeMap<&str, &str> = expected["observers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(subject, held)| (subject.as_str(), held["key_id"].as_str().unwrap()))
            .collect();
        assert_eq!(registered, expected_observers, "{label}");
        for (subject, held) in expected["auditors"].as_object().unwrap() {
            assert_eq!(
                roster.admitted_key_at(subject, at).unwrap().public_key,
                public(held["public_key"].as_str().unwrap()),
                "{label}"
            );
        }
        for (subject, held) in expected["observers"].as_object().unwrap() {
            assert_eq!(
                roster.registered_key_at(subject, at).unwrap().public_key,
                public(held["public_key"].as_str().unwrap()),
                "{label}"
            );
        }
    }
}

#[test]
fn admission_evidence_vectors_replay_in_signed_histories() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/roster.json")).unwrap(),
    )
    .unwrap();
    let admission = &vectors["admission"];
    for case in admission["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let fx = Fixture::new("log.example.org");
        let admission_height = case["admission_height"].as_u64().unwrap();
        let history = case["history"].as_array().unwrap();
        let mut blocks = Vec::new();
        for height in 0..admission_height {
            let entries: Vec<Value> = history
                .iter()
                .filter(|entry| entry["height"].as_u64().unwrap() == height)
                .map(|entry| wrap(entry["envelope"].clone()))
                .collect();
            blocks.push(fx.append(START + height as i64 * HOUR, entries));
        }
        let admit = fx.log_signed(case["envelope"]["update"].clone());
        let at = START + admission_height as i64 * HOUR;
        blocks.push(fx.append(at, vec![admit.clone()]));
        let roster = fx.roster();
        let subject = case["envelope"]["update"]["subject"].as_str().unwrap();
        match case["error"].as_str() {
            None => assert!(
                roster.rejected().is_empty(),
                "{label}: {:?}",
                roster.rejected()
            ),
            Some(code) => {
                assert_eq!(
                    rejected_positions(&roster),
                    positions_of(&blocks, std::slice::from_ref(&admit)),
                    "{label}: {:?}",
                    roster.rejected()
                );
                let rejected = &roster.rejected()[0];
                assert_eq!(rejected.code, code, "{label}");
                assert!(
                    rejected.reason.contains(code),
                    "{label}: {}",
                    rejected.reason
                );
                assert_eq!(rejected.subject, subject, "{label}");
            }
        }
        assert_eq!(
            roster.admitted_key_at(subject, at).map(|b| b.key_id),
            case["admitted_key"].as_str(),
            "{label}"
        );
        let checkpoints = history
            .iter()
            .filter(|entry| entry["envelope"]["update"]["action"] == "observer_checkpoint")
            .count();
        assert_eq!(roster.checkpoints().len(), checkpoints, "{label}");
        if history.is_empty() {
            assert!(roster.registered_at(at - HOUR).is_empty(), "{label}");
        } else {
            assert_eq!(
                roster
                    .registered_key_at(subject, at - HOUR)
                    .map(|b| b.key_id),
                Some("observer-k1"),
                "{label}"
            );
        }
        if case["error"].is_null() {
            assert!(roster.registered_key_at(subject, at).is_none(), "{label}");
        }
    }
}

#[test]
fn malformed_and_misattributed_roster_acts_are_rejected_without_changing_the_roster() {
    let fx = Fixture::new("log.example.test");
    let foreign = SigningKey::from_seed(&[33; 32]);
    let padded = format!("{}=", public("padded"));
    let entries = vec![
        fx.admit("audit.example.net", "good", &public("good")),
        wrap(
            envelope::sign_envelope(
                &admit_update("forged.example.org", "forged", &public("forged"), None, START),
                "update",
                "log1",
                &foreign,
            )
            .unwrap(),
        ),
        fx.admit("padded.example.org", "padded", &padded),
        fx.log_signed(json!({
            "wist_version": "1.0.0", "action": "auditor_admit", "subject": "noalg.example.org",
            "details": {"key_id": "noalg", "public_key": public("noalg")}, "effective_at": ts(START),
        })),
        fx.admit("single", "single", &public("single")),
        fx.log_signed(json!({
            "wist_version": "2.0.0", "action": "auditor_admit", "subject": "major.example.org",
            "details": {"key_id": "major", "alg": "Ed25519", "public_key": public("major")},
            "effective_at": ts(START),
        })),
        fx.log_signed(json!({
            "wist_version": "1.0.0", "action": "auditor_admit", "subject": "extra.example.org",
            "details": {"key_id": "extra", "alg": "Ed25519", "public_key": public("extra")},
            "effective_at": ts(START), "note": "unknown member",
        })),
        fx.log_signed(json!({
            "wist_version": "1.0.0", "action": "auditor_admit", "subject": "leap.example.org",
            "details": {"key_id": "leap", "alg": "Ed25519", "public_key": public("leap")},
            "effective_at": "2027-06-30T23:59:60Z",
        })),
        wrap(
            envelope::sign_envelope(
                &json!({
                    "wist_version": "1.0.0", "action": "observer_register", "subject": "watch.sample.net",
                    "details": {"key_id": "w1", "alg": "Ed25519", "public_key": public("w1")},
                    "effective_at": ts(START),
                }),
                "update",
                "other",
                &key("w1"),
            )
            .unwrap(),
        ),
        wrap(
            envelope::sign_envelope(
                &json!({
                    "wist_version": "1.0.0", "action": "observer_register", "subject": "watch.sample.org",
                    "details": {"key_id": "w2", "alg": "Ed25519", "public_key": public("w2")},
                    "effective_at": ts(START),
                }),
                "update",
                "w2",
                &key("not-w2"),
            )
            .unwrap(),
        ),
        register("watch.example.info", "w3", "w3"),
        checkpoint("watch.example.info", "w3", "w3", "not-an-id"),
        checkpoint("watch.example.biz", "w4", "w4", &digest("head")),
        fx.parameter("confirm_auditors", 3, START + HOUR),
    ];
    let block = fx.append(START, entries.clone());
    let roster = fx.roster();
    let codes: BTreeMap<String, &'static str> = roster
        .rejected()
        .iter()
        .map(|r| (r.subject.clone(), r.code))
        .collect();
    let expected: BTreeMap<String, &'static str> = [
        ("forged.example.org", "WIST4-E11"),
        ("padded.example.org", "WIST4-E04"),
        ("noalg.example.org", "WIST4-E04"),
        ("single", "WIST4-E04"),
        ("major.example.org", "WIST4-E11"),
        ("extra.example.org", "WIST4-E11"),
        ("leap.example.org", "WIST4-E11"),
        ("watch.sample.net", "WIST4-E11"),
        ("watch.sample.org", "WIST4-E11"),
        ("watch.example.info", "WIST4-E04"),
        ("watch.example.biz", "WIST4-E07"),
    ]
    .into_iter()
    .map(|(subject, code)| (subject.to_string(), code))
    .collect();
    assert_eq!(codes, expected, "{:?}", roster.rejected());
    let wanted: Vec<Value> = entries
        .iter()
        .enumerate()
        .filter(|(i, _)| !matches!(i, 0 | 10 | 13))
        .map(|(_, e)| e.clone())
        .collect();
    assert_eq!(rejected_positions(&roster), positions_of(&[block], &wanted));
    assert_eq!(
        roster.admitted_at(START),
        vec![("audit.example.net", "good")]
    );
    assert_eq!(
        roster.registered_at(START),
        vec![("watch.example.info", "w3")]
    );
    assert!(roster.checkpoints().is_empty());
    assert!(roster.signing_binding("audit.example.net", START).is_some());
    assert!(roster
        .signing_binding("forged.example.org", START)
        .is_none());
}

#[test]
fn removal_evidence_and_checkpoint_keys_follow_the_batch_rules() {
    let fx = Fixture::new("log.example.test");
    fx.append(
        START,
        vec![
            fx.admit("audit.example.net", "k1", &public("k1")),
            register("watch.sample.net", "w1", "w1"),
        ],
    );
    let block = fx.append(
        START + HOUR,
        vec![
            fx.remove("audit.example.net", "k1", Some(vec![])),
            register("watch.sample.net", "w2", "w2"),
            checkpoint("watch.sample.net", "w2", "w2", &digest("head-new")),
            checkpoint("watch.sample.net", "w1", "w1", &digest("head-old")),
        ],
    );
    let roster = fx.roster();
    let rejected: BTreeSet<(&str, &str)> = roster
        .rejected()
        .iter()
        .map(|r| (r.action.as_str(), r.code))
        .collect();
    assert_eq!(
        rejected,
        BTreeSet::from([
            ("auditor_remove", "WIST4-E04"),
            ("observer_checkpoint", "WIST4-E07"),
        ]),
        "{:?}",
        roster.rejected()
    );
    let old_checkpoint = block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .position(|e| {
            e["body"]["sig"]["key_id"] == "w1"
                && e["body"]["update"]["action"] == "observer_checkpoint"
        })
        .unwrap();
    assert!(roster.rejected().iter().any(|r| r.position
        == Position {
            block_number: 1,
            entry_index: old_checkpoint
        }));
    assert_eq!(
        roster
            .admitted_key_at("audit.example.net", START + 2 * HOUR)
            .map(|b| b.key_id),
        Some("k1")
    );
    assert_eq!(
        roster
            .registered_key_at("watch.sample.net", START + HOUR)
            .map(|b| b.key_id),
        Some("w2")
    );
    assert_eq!(roster.checkpoints().len(), 1);
    assert_eq!(roster.checkpoints()[0].observer_id, "watch.sample.net");
    assert_eq!(roster.checkpoints()[0].height, 1);
}

#[test]
fn record_signing_bindings_follow_the_key_held_at_the_records_block() {
    let fx = Fixture::new("log.example.test");
    fx.append(
        START,
        vec![
            fx.admit("audit.example.net", "k1", &public("k1")),
            fx.admit("checker.sample.org", "c1", &public("c1")),
            register("watch.example.info", "w1", "w1"),
        ],
    );
    fx.append(
        START + HOUR,
        vec![
            record("audit.example.net", "k1", "k1", START + 1),
            record("watch.example.info", "w1", "w1", START + 2),
            record("unknown.example.org", "u1", "u1", START + 3),
            record("audit.example.net", "c1", "c1", START + 4),
        ],
    );
    fx.append(
        START + 2 * HOUR,
        vec![
            fx.remove("audit.example.net", "k1", None),
            fx.admit("audit.example.net", "k2", &public("k2")),
        ],
    );
    fx.append(
        START + 3 * HOUR,
        vec![
            record("audit.example.net", "k2", "k2", START + 2 * HOUR + 1),
            record("audit.example.net", "k1", "k1", START + 2 * HOUR + 2),
        ],
    );
    let roster = fx.roster();
    assert!(roster.rejected().is_empty(), "{:?}", roster.rejected());
    let records = IncludedRecord::reconstruct_all(fx.data.path(), fx.head()).unwrap();
    assert_eq!(records.len(), 6);
    let context = |signing| ReplayContext {
        signing,
        duty: Duty::Active,
        coverage_failure: false,
        semantic_evidence_error: false,
    };
    let by_key = |key_id: &str| {
        records
            .iter()
            .find(|r| {
                r.envelope()["sig"]["key_id"] == key_id
                    && r.envelope()["record"]["auditor_id"] != "unknown.example.org"
            })
            .unwrap()
    };

    let first = records
        .iter()
        .find(|r| r.envelope()["sig"]["key_id"] == "k1" && r.position().block_number == 1)
        .unwrap();
    let binding = first.signing_binding(&roster).unwrap().unwrap();
    assert_eq!(
        (binding.auditor_id, binding.key_id),
        ("audit.example.net", "k1")
    );
    let disposition = first.disposition(&context(Some(binding)));
    assert_eq!(disposition.diagnostic, None);
    assert!(disposition.discharges_coverage);

    let observer = by_key("w1");
    assert!(observer.signing_binding(&roster).unwrap().is_none());
    let disposition = observer.disposition(&context(None));
    assert_eq!(disposition.diagnostic, Some("WIST4-E01"));
    assert!(!disposition.discharges_coverage);

    let unknown = records
        .iter()
        .find(|r| r.envelope()["record"]["auditor_id"] == "unknown.example.org")
        .unwrap();
    assert!(unknown.signing_binding(&roster).unwrap().is_none());

    let misattributed = by_key("c1");
    let binding = misattributed.signing_binding(&roster).unwrap().unwrap();
    assert_eq!(binding.key_id, "k1");
    let disposition = misattributed.disposition(&context(Some(binding)));
    assert_eq!(disposition.diagnostic, Some("WIST4-E01"));
    assert!(!disposition.discharges_coverage);

    let rotated = by_key("k2");
    let binding = rotated.signing_binding(&roster).unwrap().unwrap();
    assert_eq!(binding.key_id, "k2");
    assert_eq!(
        rotated.disposition(&context(Some(binding))).diagnostic,
        None
    );

    let stale = records
        .iter()
        .find(|r| r.envelope()["sig"]["key_id"] == "k1" && r.position().block_number == 3)
        .unwrap();
    let standing = stale.signing_binding(&roster).unwrap().unwrap();
    assert_eq!(standing.key_id, "k2");
    let disposition = stale.disposition(&context(Some(standing)));
    assert_eq!(disposition.diagnostic, Some("WIST4-E01"));
    assert!(!disposition.discharges_coverage);
    let duty_key = roster
        .signing_binding("audit.example.net", START + HOUR)
        .unwrap();
    assert_eq!(duty_key.key_id, "k1");
    assert_eq!(
        roster.tenure("audit.example.net", "k1").unwrap().until_s,
        Some(START + 2 * HOUR)
    );
    let disposition = stale.disposition(&ReplayContext {
        signing: Some(duty_key),
        duty: Duty::RemovedAfterAnchor,
        coverage_failure: false,
        semantic_evidence_error: false,
    });
    assert_eq!(disposition.diagnostic, Some("WIST4-E01"));
    assert!(disposition.discharges_coverage);

    let shorter = RosterHistory::reconstruct(
        fx.data.path(),
        Some(BlockRow {
            block_number: 0,
            block_hash: roster_block_hash(&fx, 0),
            sealed_at: ts(START),
        }),
    )
    .unwrap();
    assert!(first.signing_binding(&shorter).is_err());
    assert!(shorter
        .admitted_key_at("audit.example.net", START + 2 * HOUR)
        .is_some());

    let other = Fixture::new("log.example.test");
    other.append(
        START,
        vec![other.admit("audit.example.net", "k1", &public("k1"))],
    );
    other.append(START + HOUR, vec![]);
    assert!(first.signing_binding(&other.roster()).is_err());
}

fn roster_block_hash(fx: &Fixture, height: u64) -> String {
    let bytes = zstd::decode_all(std::fs::File::open(fx.path(height)).unwrap()).unwrap();
    let doc: Value = serde_json::from_slice(&bytes).unwrap();
    block::block_hash(&doc["header"]).unwrap()
}

#[test]
fn lexically_valid_small_order_keys_are_admitted_but_verify_nothing() {
    let fx = Fixture::new("log.example.test");
    let identity = wist_core::crypto::b64u_encode(&{
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes
    });
    fx.append(START, vec![fx.admit("weak.example.org", "weak", &identity)]);
    let roster = fx.roster();
    assert!(roster.rejected().is_empty(), "{:?}", roster.rejected());
    assert_eq!(
        roster
            .admitted_key_at("weak.example.org", START)
            .map(|b| b.key_id),
        Some("weak")
    );
    assert!(roster.signing_binding("weak.example.org", START).is_none());
}

#[test]
fn roster_reconstruction_requires_the_complete_pinned_prefix_and_can_retry() {
    let fx = Fixture::new("log.example.test");
    fx.append(
        START,
        vec![fx.admit("audit.example.net", "k1", &public("k1"))],
    );
    fx.append(START + HOUR, vec![]);
    fx.append(
        START + 2 * HOUR,
        vec![fx.admit("checker.sample.org", "c1", &public("c1"))],
    );
    let original = std::fs::read(fx.path(1)).unwrap();
    std::fs::write(fx.path(1), b"corrupt").unwrap();
    assert!(RosterHistory::reconstruct(fx.data.path(), fx.head()).is_err());
    std::fs::write(fx.path(1), original).unwrap();
    let roster = fx.roster();
    assert_eq!(roster.admitted_at(START + 2 * HOUR).len(), 2);
    assert_eq!(roster.through().unwrap().block_number, 2);
    let pinned = RosterHistory::reconstruct(
        fx.data.path(),
        Some(BlockRow {
            block_number: 1,
            block_hash: roster_block_hash(&fx, 1),
            sealed_at: ts(START + HOUR),
        }),
    )
    .unwrap();
    assert_eq!(
        pinned.admitted_at(START + 2 * HOUR),
        vec![("audit.example.net", "k1")]
    );
    assert!(pinned.block_hash_at(2).is_none());
    assert!(RosterHistory::reconstruct(fx.data.path(), None)
        .unwrap()
        .admitted_at(START)
        .is_empty());
}

fn resign_log_act(
    fx: &Fixture,
    mut envelope: Value,
    log_key_id: &str,
    log_key: &PublicKey,
) -> Value {
    let verifies = envelope["sig"]["key_id"] == log_key_id
        && envelope["sig"]["value"].as_str().is_some_and(|value| {
            wist_core::crypto::verify(
                log_key,
                &jcs::canonicalize(&envelope["update"]).unwrap(),
                value,
            )
            .is_ok()
        });
    if verifies {
        let fresh = envelope::sign_envelope(&envelope["update"], "update", "log1", &fx.sk).unwrap();
        envelope["sig"]["key_id"] = json!("log1");
        envelope["sig"]["value"] = fresh["sig"]["value"].clone();
    }
    envelope
}

fn raw_block_file(fx: &Fixture, at: i64, raw_entries: &[String]) {
    let head = fx.db.last_block().unwrap();
    let height = head.as_ref().map_or(0, |b| b.block_number + 1);
    let header = json!({
        "wist_version": "1.0.0", "block_number": height,
        "prev_block_hash": head.map_or("sha256:genesis".into(), |b| b.block_hash),
        "sealed_at": ts(at), "entry_count": raw_entries.len(),
        "merkle_root": format!("sha256:{}", hex_encode(&merkle::leaf_hash(&[]))),
    });
    let signature = fx.sk.sign(&jcs::canonicalize(&header).unwrap());
    let entries = raw_entries
        .iter()
        .map(|raw| format!("{{\"body\":{raw},\"type\":\"registry_update\"}}"))
        .collect::<Vec<_>>()
        .join(",");
    let header_text = String::from_utf8(jcs::canonicalize(&header).unwrap()).unwrap();
    let text = format!(
        "{{\"entries\":[{entries}],\"header\":{header_text},\"sig\":{{\"alg\":\"Ed25519\",\"key_id\":\"log1\",\"value\":\"{signature}\"}}}}"
    );
    std::fs::write(
        fx.path(height),
        zstd::bulk::compress(text.as_bytes(), 3).unwrap(),
    )
    .unwrap();
    fx.db
        .commit_seal(
            &[],
            height,
            &block::block_hash(&header).unwrap(),
            &ts(at),
            &[],
            &[],
            &[],
            &[],
            text.len() as u64,
        )
        .unwrap();
}

#[test]
fn roster_act_vectors_replay_in_signed_histories() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/roster-acts.json")).unwrap(),
    )
    .unwrap();
    let log_id = vectors["log_id"].as_str().unwrap();
    let log_key_id = vectors["log_key"]["key_id"].as_str().unwrap();
    let log_key = PublicKey::from_b64u(vectors["log_key"]["public_key"].as_str().unwrap()).unwrap();
    let codes = |value: &Value| -> BTreeMap<String, String> {
        value
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect()
    };
    let mut seen = BTreeSet::new();
    for case in vectors["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let fx = Fixture::new(log_id);
        fx.append(START, vec![]);
        let raw_invalid = case["blocks"].as_array().unwrap().iter().any(|block| {
            block["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["expect"] == "WIST1-E05")
        });
        if raw_invalid {
            for block in case["blocks"].as_array().unwrap() {
                let height = block["height"].as_u64().unwrap();
                let raw: Vec<String> = block["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| entry["envelope_json"].as_str().unwrap().to_string())
                    .collect();
                raw_block_file(&fx, START + height as i64 * HOUR, &raw);
            }
            let error = match RosterHistory::reconstruct(fx.data.path(), fx.head()) {
                Ok(_) => panic!("{label}: a Block with a duplicate member was accepted"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("duplicate"), "{label}: {error}");
            seen.insert("WIST1-E05".to_string());
            continue;
        }
        let mut blocks = Vec::new();
        let mut expectations: Vec<(usize, Value, String)> = Vec::new();
        let mut last_at = START;
        for block in case["blocks"].as_array().unwrap() {
            let height = block["height"].as_u64().unwrap();
            last_at = START + height as i64 * HOUR;
            let block_index = blocks.len();
            let entries: Vec<Value> = block["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    let envelope: Value =
                        serde_json::from_str(entry["envelope_json"].as_str().unwrap()).unwrap();
                    let wrapped = wrap(resign_log_act(&fx, envelope, log_key_id, &log_key));
                    expectations.push((
                        block_index,
                        wrapped.clone(),
                        entry["expect"].as_str().unwrap().to_string(),
                    ));
                    wrapped
                })
                .collect();
            blocks.push(fx.append(last_at, entries));
        }
        let roster = fx.roster();
        let rejected: BTreeMap<Position, &str> = roster
            .rejected()
            .iter()
            .map(|r| (r.position, r.code))
            .collect();
        for (block_index, wrapped, expect) in &expectations {
            let position = positions_of(
                &blocks[*block_index..=*block_index],
                std::slice::from_ref(wrapped),
            )
            .into_iter()
            .next()
            .unwrap();
            let got = if roster.idempotent().contains(&position) {
                "idempotent"
            } else {
                rejected.get(&position).copied().unwrap_or("accepted")
            };
            assert_eq!(got, expect, "{label}: {:?}", roster.rejected());
            if let Some(rejection) = roster.rejected().iter().find(|r| r.position == position) {
                assert!(
                    rejection.reason.contains(expect),
                    "{label}: {}",
                    rejection.reason
                );
            }
            seen.insert(expect.clone());
        }
        let auditors: BTreeMap<String, String> = roster
            .admitted_at(last_at)
            .into_iter()
            .map(|(s, k)| (s.to_string(), k.to_string()))
            .collect();
        assert_eq!(auditors, codes(&case["auditors_after"]), "{label}");
        let observers: BTreeMap<String, String> = roster
            .registered_at(last_at)
            .into_iter()
            .map(|(s, k)| (s.to_string(), k.to_string()))
            .collect();
        assert_eq!(observers, codes(&case["observers_after"]), "{label}");
        let mut sealed: Vec<&clave::history::roster::SealedCheckpoint> =
            roster.checkpoints().iter().collect();
        sealed.sort_by(|a, b| (a.height, a.id.as_bytes()).cmp(&(b.height, b.id.as_bytes())));
        let checkpoints: Vec<&str> = sealed.iter().map(|c| c.id.as_str()).collect();
        let expected: Vec<&str> = case["checkpoints_after"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap())
            .collect();
        assert_eq!(checkpoints, expected, "{label}");
        if label == "small order key is admitted as a string" {
            let probe = vectors["record_probe"]["envelope"].clone();
            let subject = probe["record"]["auditor_id"].as_str().unwrap();
            let at = START + HOUR + 1;
            let held = roster.admitted_key_at(subject, at).unwrap();
            assert_eq!(held.key_id, probe["sig"]["key_id"]);
            assert!(roster.signing_binding(subject, at).is_none(), "{label}");
            let fx = Fixture::new(log_id);
            fx.append(START, vec![]);
            let first = case["blocks"][0]["entries"][0]["envelope_json"]
                .as_str()
                .unwrap();
            let admit: Value = serde_json::from_str(first).unwrap();
            fx.append(
                START + HOUR,
                vec![wrap(resign_log_act(&fx, admit, log_key_id, &log_key))],
            );
            fx.append(
                START + 2 * HOUR,
                vec![json!({"type": "audit_record", "body": probe})],
            );
            let roster = fx.roster();
            assert!(
                roster.rejected().is_empty(),
                "{label}: {:?}",
                roster.rejected()
            );
            let records = IncludedRecord::reconstruct_all(fx.data.path(), fx.head()).unwrap();
            assert_eq!(records.len(), 1);
            assert!(records[0].signing_binding(&roster).unwrap().is_none());
            let disposition = records[0].disposition(&ReplayContext {
                signing: None,
                duty: Duty::Active,
                coverage_failure: false,
                semantic_evidence_error: false,
            });
            assert_eq!(
                Some(disposition.diagnostic.unwrap()),
                vectors["record_probe"]["expect"].as_str()
            );
            assert!(!disposition.discharges_coverage);
        }
    }
    assert_eq!(
        seen,
        [
            "accepted",
            "idempotent",
            "WIST1-E05",
            "WIST4-E04",
            "WIST4-E07",
            "WIST4-E11"
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );
}
