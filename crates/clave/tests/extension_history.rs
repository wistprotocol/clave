mod common;

use clave::db::BlockRow;
use clave::history::declarations::Position;
use clave::history::extension::{ExtensionHistory, RecordStanding, Standing, Trigger, VoidReason};
use clave::record::Duty;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wist_core::confirmation::independent;
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::sampling;
use wist_core::verdict::Verdict;
use wist_core::{block, envelope, jcs, merkle, vrf};

const START: i64 = 1_800_000_000;
const HOUR: i64 = 3_600;
const CEILING: u64 = 5_000_000;
const PROVISIONAL: u64 = 2_900_000;
const PUBLISHER: &str = "site.example.com";

fn ts(at: i64) -> String {
    jiff::Timestamp::from_second(at).unwrap().to_string()
}

fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(format!("extension-history:{label}").as_bytes()).into()
}

fn key(label: &str) -> SigningKey {
    SigningKey::from_seed(&seed(label))
}

fn public(label: &str) -> String {
    key(label).public().to_b64u()
}

fn key_id(auditor: &str) -> String {
    format!("key:{auditor}")
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
    rows: Vec<BlockRow>,
    sk: SigningKey,
    attest_empty: bool,
    labels: std::cell::RefCell<BTreeMap<String, String>>,
    roster: BTreeMap<String, (String, String)>,
}

impl Fixture {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example.test", data.path()).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        Self {
            data,
            head: None,
            rows: Vec::new(),
            sk,
            attest_empty: false,
            labels: std::cell::RefCell::new(BTreeMap::new()),
            roster: BTreeMap::new(),
        }
    }

    fn attestations_for_previous_block(&self) -> Vec<Value> {
        let Some(previous) = self.head.as_ref() else {
            return Vec::new();
        };
        self.roster
            .iter()
            .map(|(subject, (key_id, label))| {
                coverage_attestation(subject, label, key_id, previous, None)
            })
            .collect()
    }

    fn track_roster(&mut self, entries: &[Value]) {
        for entry in entries {
            if entry["type"] != "registry_update" {
                continue;
            }
            let update = &entry["body"]["update"];
            let subject = update["subject"].as_str().unwrap_or("").to_owned();
            match update["action"].as_str() {
                Some("auditor_remove") => {
                    self.roster.remove(&subject);
                }
                Some("auditor_admit") => {
                    let public_key = update["details"]["public_key"].as_str().unwrap();
                    let label = self.labels.borrow()[public_key].clone();
                    let key_id = update["details"]["key_id"].as_str().unwrap().to_owned();
                    self.roster.insert(subject, (key_id, label));
                }
                _ => {}
            }
        }
    }

    fn path(&self, height: u64) -> std::path::PathBuf {
        self.data
            .path()
            .join(format!("log/blocks/{height:09}.json.zst"))
    }

    fn append(&mut self, at: i64, mut entries: Vec<Value>) -> BlockRow {
        if self.attest_empty {
            entries.extend(self.attestations_for_previous_block());
        }
        self.track_roster(&entries);
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
        self.rows.push(row.clone());
        row
    }

    fn hourly(&mut self, height: u64, entries: Vec<Value>) -> BlockRow {
        assert_eq!(
            self.rows.len() as u64,
            height,
            "Blocks are appended in order"
        );
        self.append(START + height as i64 * HOUR, entries)
    }

    fn reconstruct(&self) -> Result<ExtensionHistory, clave::Error> {
        ExtensionHistory::reconstruct(self.data.path(), self.head.clone())
    }

    fn record_body(&self, position: Position) -> Value {
        let bytes =
            zstd::decode_all(std::fs::File::open(self.path(position.block_number)).unwrap())
                .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        doc["entries"][position.entry_index]["body"]["record"].clone()
    }

    fn log_signed(&self, update: Value) -> Value {
        json!({
            "type": "registry_update",
            "body": envelope::sign_envelope(&update, "update", "log1", &self.sk).unwrap(),
        })
    }

    fn admit(&self, subject: &str, key_label: &str, key_id: &str) -> Value {
        self.labels
            .borrow_mut()
            .insert(public(key_label), key_label.to_owned());
        self.log_signed(json!({
            "wist_version": "1.0.0", "action": "auditor_admit", "subject": subject,
            "details": {"key_id": key_id, "alg": "Ed25519", "public_key": public(key_label)},
            "effective_at": ts(START),
        }))
    }

    fn admit_own(&self, subject: &str) -> Value {
        self.admit(subject, subject, &key_id(subject))
    }

    fn remove(&self, subject: &str, key_id: &str) -> Value {
        self.log_signed(json!({
            "wist_version": "1.0.0", "action": "auditor_remove", "subject": subject,
            "details": {"key_id": key_id}, "effective_at": ts(START),
        }))
    }

    fn pull(&self, subject: &str, block: &BlockRow, found: &[String]) -> Value {
        self.log_signed(json!({
            "wist_version": "1.0.0", "action": "pull_attestation", "subject": subject,
            "details": {"block": block.block_hash, "found": found}, "effective_at": ts(START),
        }))
    }
}

fn coverage_attestation(
    subject: &str,
    key_label: &str,
    key_id: &str,
    block: &BlockRow,
    prev_record: Option<&str>,
) -> Value {
    let update = json!({
        "wist_version": "1.0.0", "action": "coverage_attestation", "subject": subject,
        "details": {
            "block": block.block_hash,
            "vrf_proof": hex_encode(&proof(key_label, block)),
            "prev_record": prev_record,
        },
        "effective_at": ts(START),
    });
    json!({
        "type": "registry_update",
        "body": envelope::sign_envelope(&update, "update", key_id, &key(key_label)).unwrap(),
    })
}

fn declaration(domain: &str, scope: &[&str], key_label: &str) -> Value {
    declaration_seq(domain, scope, key_label, 0)
}

fn declaration_seq(domain: &str, scope: &[&str], key_label: &str, seq: u64) -> Value {
    declaration_after(domain, scope, key_label, seq, None)
}

fn declaration_after(
    domain: &str,
    scope: &[&str],
    key_label: &str,
    seq: u64,
    previous: Option<&Value>,
) -> Value {
    let mut publisher = json!({
        "wist_version": "1.0.0", "domain": domain,
        "keys": [{"key_id": "k1", "alg": "Ed25519", "public_key": public(key_label), "valid_from": "2026-08-01T00:00:00Z"}],
        "seq": seq,
    });
    if let Some(previous) = previous {
        publisher["prev_declaration"] = json!(format!(
            "sha256:{}",
            hex_encode(&Sha256::digest(
                jcs::canonicalize(&previous["body"]["publisher"]).unwrap()
            ))
        ));
    }
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

fn pages(publisher: &str, key_label: &str, tag: &str, count: usize) -> Vec<Value> {
    (0..count)
        .map(|i| {
            delta(
                publisher,
                &format!("https://{publisher}/{tag}/p{i}"),
                key_label,
            )
        })
        .collect()
}

fn delta_id(entry: &Value) -> String {
    wist_core::delta::delta_id(&entry["body"]["delta"]).unwrap()
}

fn proof(key_label: &str, block: &BlockRow) -> [u8; vrf::PROOF_LEN] {
    let alpha = sampling::alpha_from_block_hash(&block.block_hash).unwrap();
    vrf::prove(&seed(key_label), &alpha).unwrap()
}

fn beta(key_label: &str, block: &BlockRow) -> [u8; 64] {
    let alpha = sampling::alpha_from_block_hash(&block.block_hash).unwrap();
    let public_key: [u8; 32] = wist_core::crypto::b64u_decode(&public(key_label))
        .unwrap()
        .try_into()
        .unwrap();
    vrf::verify(&public_key, &alpha, &proof(key_label, block)).unwrap()
}

fn drawn(beta: &[u8; 64], id: &str, p_1e7: u64) -> bool {
    sampling::selected(sampling::draw(beta, id), p_1e7)
}

fn pick(deltas: &[Value], want: &dyn Fn(&str) -> bool) -> Vec<String> {
    deltas.iter().map(delta_id).filter(|id| want(id)).collect()
}

fn first(deltas: &[Value], want: &dyn Fn(&str) -> bool) -> String {
    pick(deltas, want)
        .into_iter()
        .next()
        .expect("a sealed Delta with the required draws")
}

#[derive(Clone, Copy)]
struct Audit<'a> {
    auditor: &'a str,
    audited: &'a str,
    proof_over: &'a BlockRow,
    fetched_at: i64,
    verdict: &'a str,
}

impl Audit<'_> {
    fn scores(&self) -> (u64, Option<u64>) {
        match self.verdict {
            "consistent" => (950_000, None),
            "inconsistent" => (100_000, None),
            "link_inconsistent" => (950_000, Some(100_000)),
            other => panic!("unsupported test verdict {other}"),
        }
    }
}

fn record_signed(audit: &Audit<'_>, key_label: &str, key_id: &str, proof_hex: &str) -> Value {
    let commitment = |tag: &str| {
        format!(
            "hmac-sha256:{}",
            hex_encode(&Sha256::digest(
                format!("{}:{}:{tag}", audit.auditor, audit.audited).as_bytes()
            ))
        )
    };
    let (similarity, link_agreement) = audit.scores();
    let mut body = json!({
        "wist_version": "1.0.0",
        "audited_delta": audit.audited,
        "reference_delta": audit.audited,
        "auditor_id": audit.auditor,
        "fetched_at": ts(audit.fetched_at),
        "verdict": audit.verdict,
        "similarity": similarity,
        "response_commitment": commitment("response"),
        "credit_commitment": commitment("credit"),
        "ref_extract_commitment": commitment("ref"),
        "evidence_commitment": commitment("evidence"),
        "vrf_proof": proof_hex,
        "prev_record": null,
    });
    if let Some(link_agreement) = link_agreement {
        body["link_agreement"] = json!(link_agreement);
    }
    json!({
        "type": "audit_record",
        "body": envelope::sign_envelope(&body, "record", key_id, &key(key_label)).unwrap(),
    })
}

fn record(audit: &Audit<'_>) -> Value {
    record_signed(
        audit,
        audit.auditor,
        &key_id(audit.auditor),
        &hex_encode(&proof(audit.auditor, audit.proof_over)),
    )
}

fn standing_of<'a>(
    history: &'a ExtensionHistory,
    height: u64,
    auditor: &str,
) -> &'a RecordStanding {
    history
        .records()
        .iter()
        .find(|record| record.position.block_number == height && record.auditor_id == auditor)
        .unwrap_or_else(|| panic!("no Record by {auditor} at Block {height}"))
}

fn standing_of_proof<'a>(
    history: &'a ExtensionHistory,
    fx: &Fixture,
    height: u64,
    auditor: &str,
    pi: &[u8; vrf::PROOF_LEN],
) -> &'a RecordStanding {
    let hex = hex_encode(pi);
    history
        .records()
        .iter()
        .find(|record| {
            record.position.block_number == height
                && record.auditor_id == auditor
                && fx.record_body(record.position)["vrf_proof"] == hex
        })
        .unwrap_or_else(|| panic!("no Record by {auditor} at Block {height} with that proof"))
}

fn trigger_at<'a>(history: &'a ExtensionHistory, height: u64, delta_id: &str) -> &'a Trigger {
    history
        .triggers()
        .iter()
        .find(|trigger| trigger.position.block_number == height && trigger.delta_id == delta_id)
        .unwrap_or_else(|| panic!("no trigger for {delta_id} at Block {height}"))
}

#[test]
fn records_bind_to_the_block_their_proof_is_over() {
    let mut fx = Fixture::new();
    fx.hourly(
        0,
        vec![
            fx.admit_own("audit.example.net"),
            fx.admit_own("checker.example.org"),
            declaration(PUBLISHER, &[], "site"),
        ],
    );
    let deltas = pages(PUBLISHER, "site", "a", 64);
    let audited = fx.hourly(1, deltas.clone());
    let (filer_beta, peer_beta) = (
        beta("audit.example.net", &audited),
        beta("checker.example.org", &audited),
    );
    let d = first(&deltas, &|id| {
        drawn(&filer_beta, id, PROVISIONAL) && !drawn(&peer_beta, id, PROVISIONAL)
    });
    let trigger = fx.hourly(
        2,
        vec![record(&Audit {
            auditor: "audit.example.net",
            audited: &d,
            proof_over: &audited,
            fetched_at: START + HOUR,
            verdict: "inconsistent",
        })],
    );
    let rotated_id = "key:checker.example.org:2";
    let rotated = fx.hourly(
        3,
        vec![
            fx.remove("checker.example.org", &key_id("checker.example.org")),
            fx.admit("checker.example.org", "checker-rotated", rotated_id),
        ],
    );
    let peer = Audit {
        auditor: "checker.example.org",
        audited: &d,
        proof_over: &trigger,
        fetched_at: START + 2 * HOUR,
        verdict: "consistent",
    };
    let old_over_trigger = proof("checker.example.org", &trigger);
    let old_over_audited = proof("checker.example.org", &audited);
    let new_over_rotated = proof("checker-rotated", &rotated);
    let new_over_trigger = proof("checker-rotated", &trigger);
    let filer_over_trigger = proof("audit.example.net", &trigger);
    let filer_over_audited = proof("audit.example.net", &audited);
    let peer_signed = |pi: &[u8; vrf::PROOF_LEN]| {
        record_signed(&peer, "checker-rotated", rotated_id, &hex_encode(pi))
    };
    let filer = Audit {
        auditor: "audit.example.net",
        ..peer
    };
    let filer_signed = |pi: &[u8; vrf::PROOF_LEN]| {
        record_signed(
            &filer,
            "audit.example.net",
            &key_id("audit.example.net"),
            &hex_encode(pi),
        )
    };
    fx.hourly(
        4,
        vec![
            peer_signed(&old_over_trigger),
            peer_signed(&old_over_audited),
            peer_signed(&new_over_rotated),
            peer_signed(&new_over_trigger),
            filer_signed(&filer_over_trigger),
            filer_signed(&filer_over_audited),
        ],
    );
    for attempt in 0..2 {
        let history = fx.reconstruct().unwrap();
        assert_eq!(
            history.through().map(|row| row.block_number),
            Some(4),
            "attempt {attempt}"
        );
        let trigger_entry = trigger_at(&history, 2, &d);
        assert!(trigger_entry.summons);
        assert_eq!(
            trigger_entry.summoned,
            vec!["checker.example.org".to_owned()]
        );
        assert_eq!(
            trigger_entry.deadline_s,
            i128::from(START + 2 * HOUR + 36 * HOUR)
        );
        assert_eq!(trigger_entry.verdict, Verdict::Inconsistent);
        assert_eq!(trigger_entry.publisher, PUBLISHER);
        let duties = history.named("checker.example.org", 2);
        assert_eq!(duties.len(), 1);
        assert_eq!(duties[0].delta_id, d);
        assert_eq!(duties[0].publisher, PUBLISHER);
        assert_eq!(duties[0].deadline_s, trigger_entry.deadline_s);
        assert!(history.named("audit.example.net", 2).is_empty());
        let filer_record = standing_of(&history, 2, "audit.example.net");
        assert_eq!(filer_record.standing, Standing::Selected);
        assert_eq!(filer_record.audited_height, Some(1));
        assert_eq!(filer_record.publisher.as_deref(), Some(PUBLISHER));
        assert_eq!(filer_record.duty, Duty::Active);
        assert!(
            filer_record.evidence() && filer_record.authentic && filer_record.discharges_coverage
        );
        let peer_of = |pi: &[u8; vrf::PROOF_LEN]| {
            standing_of_proof(&history, &fx, 4, "checker.example.org", pi)
        };
        let extension = peer_of(&old_over_trigger);
        assert_eq!(
            extension.standing,
            Standing::Extension { trigger_height: 2 },
            "the proof is under the key held at B₁, the signature under the key held at the Record's Block"
        );
        assert_eq!(extension.duty, Duty::Active);
        assert!(extension.authentic && extension.evidence() && extension.discharges_coverage);
        for (pi, reason) in [
            (
                &old_over_audited,
                "the audited Block's draw did not select the Delta",
            ),
            (
                &new_over_rotated,
                "a proof over an unrelated Block earns nothing",
            ),
            (&new_over_trigger, "the rotated key was not held at B₁"),
        ] {
            let void = peer_of(pi);
            assert_eq!(
                void.standing,
                Standing::Void(VoidReason::ProofWithoutStanding),
                "{reason}"
            );
            assert_eq!(void.diagnostic, Some("WIST4-E01"), "{reason}");
            assert_eq!(void.duty, Duty::Absent, "{reason}");
            assert!(void.authentic && !void.discharges_coverage, "{reason}");
        }
        let filer_extension =
            standing_of_proof(&history, &fx, 4, "audit.example.net", &filer_over_trigger);
        assert_eq!(
            filer_extension.standing,
            Standing::Void(VoidReason::ProofWithoutStanding),
            "the filer is not summoned by its own trigger"
        );
        let filer_draw =
            standing_of_proof(&history, &fx, 4, "audit.example.net", &filer_over_audited);
        assert_eq!(filer_draw.standing, Standing::Selected);
        assert!(filer_draw.evidence());
        assert!(history.escalations().is_empty());
        assert_eq!(history.triggers().len(), 1);
    }
}

#[test]
fn triggers_follow_log_order_ration_and_independence() {
    let publisher = "www.publisher.example";
    let roster = [
        "audit.example.net",
        "checker.example.org",
        "watch.sample.net",
        "peer.example.net",
        "watch.publisher.example",
        "eye.sample.net",
    ];
    let mut fx = Fixture::new();
    fx.attest_empty = true;
    let mut genesis: Vec<Value> = roster.iter().map(|auditor| fx.admit_own(auditor)).collect();
    genesis.push(declaration(publisher, &[], "site"));
    fx.hourly(0, genesis);
    let deltas = pages(publisher, "site", "t", 192);
    let audited = fx.hourly(1, deltas.clone());
    let betas: BTreeMap<&str, [u8; 64]> = roster
        .iter()
        .map(|auditor| (*auditor, beta(auditor, &audited)))
        .collect();
    let by = |auditor: &str, id: &str| drawn(&betas[auditor], id, PROVISIONAL);
    let filer_only = pick(&deltas, &|id| {
        by("audit.example.net", id) && !by("checker.example.org", id)
    });
    let filer_and_checker = pick(&deltas, &|id| {
        by("audit.example.net", id) && by("checker.example.org", id)
    });
    let eye_and_checker = pick(&deltas, &|id| {
        by("eye.sample.net", id) && by("checker.example.org", id) && !by("audit.example.net", id)
    });
    assert!(
        filer_only.len() >= 5 && !filer_and_checker.is_empty() && !eye_and_checker.is_empty(),
        "{} {} {}",
        filer_only.len(),
        filer_and_checker.len(),
        eye_and_checker.len()
    );
    let (p1, p2, a, b, b2, c) = (
        &filer_only[0],
        &filer_only[1],
        &filer_and_checker[0],
        &filer_only[2],
        &filer_only[3],
        &filer_only[4],
    );
    let e = &eye_and_checker[0];
    let filed = |auditor: &'static str, id: &str, verdict: &'static str| {
        record(&Audit {
            auditor,
            audited: id,
            proof_over: &audited,
            fetched_at: START + HOUR,
            verdict,
        })
    };
    fx.hourly(2, vec![filed("audit.example.net", p1, "inconsistent")]);
    fx.hourly(3, vec![filed("audit.example.net", p2, "inconsistent")]);
    for height in 4..10 {
        fx.hourly(height, vec![]);
    }
    fx.hourly(
        10,
        vec![
            filed("audit.example.net", a, "inconsistent"),
            filed("audit.example.net", b, "inconsistent"),
            filed("eye.sample.net", e, "inconsistent"),
        ],
    );
    fx.hourly(
        11,
        vec![filed("checker.example.org", a, "link_inconsistent")],
    );
    for height in 12..84 {
        fx.hourly(height, vec![]);
    }
    fx.hourly(
        84,
        vec![
            filed("checker.example.org", e, "inconsistent"),
            filed("audit.example.net", b2, "inconsistent"),
        ],
    );
    let reset_height = 10 + 30 * 24 + 1;
    for height in 85..reset_height {
        fx.hourly(height, vec![]);
    }
    fx.hourly(
        reset_height,
        vec![filed("audit.example.net", c, "inconsistent")],
    );
    let history = fx.reconstruct().unwrap();
    assert!(history.roster().rejected().is_empty());
    let prior: Vec<&Trigger> = history
        .triggers()
        .iter()
        .filter(|trigger| trigger.position.block_number < 10)
        .collect();
    assert_eq!(prior.len(), 2);
    for trigger in &prior {
        assert!(trigger.summons);
        assert_eq!(
            trigger.summoned,
            vec!["checker.example.org", "eye.sample.net", "watch.sample.net"],
            "peers dependent on the filer or the Publisher are never summoned"
        );
    }
    let at_10: Vec<&Trigger> = history
        .triggers()
        .iter()
        .filter(|trigger| trigger.position.block_number == 10)
        .collect();
    let filer_triggers: Vec<&&Trigger> = at_10
        .iter()
        .filter(|trigger| trigger.auditor_id == "audit.example.net")
        .collect();
    assert_eq!(
        filer_triggers.len(),
        2,
        "both of the filer's Deltas trigger"
    );
    assert!(filer_triggers[0].position.entry_index < filer_triggers[1].position.entry_index);
    assert!(
        filer_triggers[0].summons,
        "the earlier Entry spends the last slot"
    );
    assert_eq!(
        filer_triggers[0].summoned,
        vec!["checker.example.org", "eye.sample.net", "watch.sample.net"]
    );
    assert!(!filer_triggers[1].summons);
    assert!(filer_triggers[1].summoned.is_empty());
    assert!(
        !history
            .triggers()
            .iter()
            .any(|trigger| trigger.position.block_number == 11),
        "a link_inconsistent Record inside the window of the same Delta's trigger is no trigger"
    );
    let checker_link = standing_of(&history, 11, "checker.example.org");
    assert_eq!(checker_link.standing, Standing::Selected);
    assert!(checker_link.evidence());
    assert_eq!(checker_link.verdict, Some(Verdict::LinkInconsistent));
    let eye = at_10
        .iter()
        .find(|trigger| trigger.auditor_id == "eye.sample.net")
        .unwrap();
    assert!(eye.summons);
    assert_eq!(
        eye.summoned,
        vec![
            "audit.example.net",
            "checker.example.org",
            "peer.example.net"
        ]
    );
    let at_84: Vec<&Trigger> = history
        .triggers()
        .iter()
        .filter(|trigger| trigger.position.block_number == 84)
        .collect();
    assert_eq!(at_84.len(), 2);
    let second_e = at_84.iter().find(|trigger| trigger.delta_id == *e).unwrap();
    assert!(
        second_e.summons,
        "past the window the Delta triggers again; the ration is per Auditor"
    );
    assert_eq!(
        second_e.summoned,
        vec!["audit.example.net", "peer.example.net"],
        "peers dependent on any earlier filer are excluded"
    );
    let rationed = at_84
        .iter()
        .find(|trigger| trigger.delta_id == *b2)
        .unwrap();
    assert!(
        !rationed.summons,
        "three summoning triggers inside 30 days exhaust the ration"
    );
    assert!(rationed.summoned.is_empty());
    let reset = trigger_at(&history, reset_height, c);
    assert!(reset.summons, "summons age out of the 30-day ration window");
    assert_eq!(
        history
            .duties()
            .iter()
            .filter(|duty| duty.auditor_id == "checker.example.org" && duty.trigger_height == 10)
            .map(|duty| duty.delta_id.clone())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([filer_triggers[0].delta_id.clone(), e.clone()]),
        "the summoning filer trigger and the eye trigger name the peer at Block 10"
    );
    for trigger in history.triggers() {
        assert_eq!(
            trigger.deadline_s,
            i128::from(trigger.sealed_at_s + 36 * HOUR)
        );
        if trigger.position.block_number + 73 <= reset_height {
            let outcome = trigger.outcome.unwrap();
            assert_eq!(
                outcome.closing_block.unwrap().height,
                trigger.position.block_number + 73
            );
            assert!(!outcome.consistent_quorum);
            assert!(outcome.establishing_block.is_none());
        } else {
            assert!(trigger.outcome.is_none());
        }
    }
    assert!(history.escalations().is_empty());
}

#[test]
fn contradiction_vectors_escalate_the_domain_from_the_closing_block() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/extension.json")).unwrap(),
    )
    .unwrap();
    let offset = 990u64;
    let audited_height = 5u64;
    let trigger_height = 10u64;
    for case in vectors["contradiction_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let trigger_auditor = case["trigger"]["auditor"].as_str().unwrap();
        assert_eq!(
            case["trigger"]["height"].as_u64().unwrap() - offset,
            trigger_height,
            "{label}"
        );
        let summoned_case = case["summoned"].as_bool().unwrap();
        let records = case["records"].as_array().unwrap();
        let mut auditors: BTreeSet<&str> = [
            trigger_auditor,
            "checker.example.org",
            "watch.sample.net",
            "peer.example.net",
            "eye.example.org",
        ]
        .into_iter()
        .collect();
        auditors.extend(
            records
                .iter()
                .map(|record| record["auditor"].as_str().unwrap()),
        );
        let mut fx = Fixture::new();
        let mut genesis: Vec<Value> = auditors
            .iter()
            .map(|auditor| fx.admit_own(auditor))
            .collect();
        genesis.push(declaration(PUBLISHER, &[], "site"));
        fx.hourly(0, genesis);
        let earlier = pages(PUBLISHER, "site", "prior", 32);
        let earlier_row = fx.hourly(1, earlier.clone());
        let earlier_beta = beta(trigger_auditor, &earlier_row);
        let prior_deltas = pick(&earlier, &|id| drawn(&earlier_beta, id, PROVISIONAL));
        assert!(prior_deltas.len() >= 3, "{label}");
        for height in 2..=4 {
            let entries = if summoned_case {
                Vec::new()
            } else {
                vec![record(&Audit {
                    auditor: trigger_auditor,
                    audited: &prior_deltas[height as usize - 2],
                    proof_over: &earlier_row,
                    fetched_at: START + HOUR,
                    verdict: "inconsistent",
                })]
            };
            fx.hourly(height, entries);
        }
        let deltas = pages(PUBLISHER, "site", "d", 512);
        let audited = fx.hourly(audited_height, deltas.clone());
        let vrf_auditors: BTreeSet<&str> = std::iter::once(trigger_auditor)
            .chain(records.iter().filter_map(|record| {
                let auditor = record["auditor"].as_str().unwrap();
                let vrf = !summoned_case
                    || record["height"].as_u64().unwrap() - offset == trigger_height
                    || !independent(auditor, trigger_auditor)
                    || !independent(auditor, PUBLISHER);
                vrf.then_some(auditor)
            }))
            .collect();
        let betas: Vec<[u8; 64]> = vrf_auditors
            .iter()
            .map(|auditor| beta(auditor, &audited))
            .collect();
        let d = first(&deltas, &|id| {
            betas.iter().all(|beta| drawn(beta, id, PROVISIONAL))
        });
        for height in audited_height + 1..trigger_height {
            fx.hourly(height, vec![]);
        }
        let mut by_height: BTreeMap<u64, Vec<(String, String)>> = BTreeMap::new();
        for record in records {
            by_height
                .entry(record["height"].as_u64().unwrap() - offset)
                .or_default()
                .push((
                    record["auditor"].as_str().unwrap().to_owned(),
                    record["verdict"].as_str().unwrap().to_owned(),
                ));
        }
        let probes = case["escalation_at"].as_array().unwrap();
        let last = probes
            .iter()
            .map(|probe| probe["height"].as_u64().unwrap() - offset)
            .max()
            .unwrap();
        let mut trigger_row: Option<BlockRow> = None;
        for height in trigger_height..=last {
            let mut entries = Vec::new();
            if height == trigger_height {
                entries.push(record(&Audit {
                    auditor: trigger_auditor,
                    audited: &d,
                    proof_over: &audited,
                    fetched_at: START + audited_height as i64 * HOUR,
                    verdict: "inconsistent",
                }));
            }
            for (auditor, verdict) in by_height.remove(&height).unwrap_or_default() {
                let over = if vrf_auditors.contains(auditor.as_str()) {
                    audited.clone()
                } else {
                    trigger_row.clone().unwrap()
                };
                entries.push(record(&Audit {
                    auditor: &auditor,
                    audited: &d,
                    proof_over: &over,
                    fetched_at: START + over.block_number as i64 * HOUR,
                    verdict: &verdict,
                }));
            }
            let row = fx.hourly(height, entries);
            if height == trigger_height {
                trigger_row = Some(row);
            }
        }
        let history = fx.reconstruct().unwrap();
        assert!(history.roster().rejected().is_empty(), "{label}");
        let trigger = trigger_at(&history, trigger_height, &d);
        assert_eq!(trigger.summons, summoned_case, "{label}");
        let outcome = trigger
            .outcome
            .unwrap_or_else(|| panic!("{label}: extension never closed"));
        assert_eq!(
            outcome.closing_block.map(|block| block.height),
            Some(case["closes_at_height"].as_u64().unwrap() - offset),
            "{label}"
        );
        assert_eq!(
            outcome.confirmed,
            case["confirmed"].as_bool().unwrap(),
            "{label}"
        );
        assert_eq!(
            outcome.consistent_quorum,
            case["independent_consistent_pair"].as_bool().unwrap(),
            "{label}"
        );
        let establishing = case["establishing_height"].as_u64().map(|h| h - offset);
        assert_eq!(
            outcome.establishing_block.map(|block| block.height),
            establishing,
            "{label}"
        );
        assert_eq!(
            outcome.establishing_block.is_some(),
            case["contradicted"].as_bool().unwrap(),
            "{label}"
        );
        let escalations: Vec<(String, u64)> = history
            .escalations()
            .iter()
            .map(|record| (record.publisher.clone(), record.establishing_height))
            .collect();
        assert_eq!(
            escalations,
            establishing
                .map(|height| vec![(PUBLISHER.to_owned(), height)])
                .unwrap_or_default(),
            "{label}"
        );
        for probe in probes {
            let height = probe["height"].as_u64().unwrap() - offset;
            assert_eq!(
                history.escalated_sampling(PUBLISHER, height),
                probe["in_force"].as_bool().unwrap(),
                "{label} at {}",
                probe["height"]
            );
            assert!(!history.escalated_sampling("other.example.org", height));
        }
        for record in records {
            let auditor = record["auditor"].as_str().unwrap();
            let standing = standing_of(
                &history,
                record["height"].as_u64().unwrap() - offset,
                auditor,
            );
            assert!(
                standing.evidence(),
                "{label}: {auditor} {:?}",
                standing.diagnostic
            );
            let expected = if vrf_auditors.contains(auditor) {
                Standing::Selected
            } else {
                Standing::Extension { trigger_height }
            };
            assert_eq!(standing.standing, expected, "{label}: {auditor}");
        }
    }
}

#[test]
fn escalation_displaces_the_formula_for_later_blocks_of_the_domain_only() {
    let mut fx = Fixture::new();
    fx.hourly(
        0,
        vec![
            fx.admit_own("audit.example.net"),
            fx.admit_own("checker.example.org"),
            fx.admit_own("watch.sample.net"),
            declaration(PUBLISHER, &[], "site"),
            declaration("other.example.org", &[], "other"),
        ],
    );
    let deltas = pages(PUBLISHER, "site", "first", 96);
    let audited = fx.hourly(1, deltas.clone());
    let filer_beta = beta("audit.example.net", &audited);
    let d = first(&deltas, &|id| drawn(&filer_beta, id, PROVISIONAL));
    let trigger = fx.hourly(
        2,
        vec![record(&Audit {
            auditor: "audit.example.net",
            audited: &d,
            proof_over: &audited,
            fetched_at: START + HOUR,
            verdict: "inconsistent",
        })],
    );
    let consistent = |auditor: &'static str| {
        record(&Audit {
            auditor,
            audited: &d,
            proof_over: &trigger,
            fetched_at: START + 2 * HOUR,
            verdict: "consistent",
        })
    };
    fx.hourly(3, vec![consistent("checker.example.org")]);
    fx.hourly(4, vec![consistent("watch.sample.net")]);
    let closing = 75u64;
    for height in 5..closing {
        fx.hourly(height, vec![]);
    }
    let last_in_force = closing + 30 * 24 - 1;
    let closing_pages = pages(PUBLISHER, "site", "closing", 96);
    let at_closing = fx.hourly(closing, closing_pages.clone());
    let after_pages = pages(PUBLISHER, "site", "after", 96);
    let other_pages = pages("other.example.org", "other", "after", 96);
    let after = fx.hourly(
        closing + 1,
        [after_pages.clone(), other_pages.clone()].concat(),
    );
    for height in closing + 2..=last_in_force {
        fx.hourly(height, vec![]);
    }
    let edge_pages = pages(PUBLISHER, "site", "edge", 96);
    let edge = fx.hourly(last_in_force + 1, edge_pages.clone());
    let expired_pages = pages(PUBLISHER, "site", "expired", 96);
    let expired = fx.hourly(last_in_force + 2, expired_pages.clone());
    let between = |block: &BlockRow, deltas: &[Value]| {
        let filer_beta = beta("audit.example.net", block);
        first(deltas, &|id| {
            !drawn(&filer_beta, id, PROVISIONAL) && drawn(&filer_beta, id, CEILING)
        })
    };
    let probes = [
        (at_closing.clone(), between(&at_closing, &closing_pages)),
        (after.clone(), between(&after, &after_pages)),
        (after.clone(), between(&after, &other_pages)),
        (edge.clone(), between(&edge, &edge_pages)),
        (expired.clone(), between(&expired, &expired_pages)),
    ];
    let probe_height = last_in_force + 3;
    fx.hourly(
        probe_height,
        probes
            .iter()
            .map(|(block, audited)| {
                record(&Audit {
                    auditor: "audit.example.net",
                    audited,
                    proof_over: block,
                    fetched_at: START + block.block_number as i64 * HOUR,
                    verdict: "consistent",
                })
            })
            .collect(),
    );
    let history = fx.reconstruct().unwrap();
    assert_eq!(history.escalations().len(), 1);
    assert_eq!(history.escalations()[0].establishing_height, closing);
    assert_eq!(history.escalations()[0].publisher, PUBLISHER);
    assert_eq!(history.escalations()[0].trigger.block_number, 2);
    assert!(!history.escalated_sampling(PUBLISHER, closing - 1));
    assert!(history.escalated_sampling(PUBLISHER, closing));
    assert!(history.escalated_sampling(PUBLISHER, last_in_force));
    assert!(!history.escalated_sampling(PUBLISHER, last_in_force + 1));
    assert!(!history.escalated_sampling("other.example.org", closing));
    let observed: Vec<(u64, Option<String>, Standing)> = history
        .records()
        .iter()
        .filter(|record| record.position.block_number == probe_height)
        .map(|record| {
            (
                record.audited_height.unwrap(),
                record.publisher.clone(),
                record.standing,
            )
        })
        .collect();
    let expect = |height: u64, publisher: &str, standing: Standing| {
        assert!(
            observed.contains(&(height, Some(publisher.to_owned()), standing)),
            "{height} {publisher}: {observed:?}"
        );
    };
    let void = Standing::Void(VoidReason::ProofWithoutStanding);
    expect(closing, PUBLISHER, void);
    expect(closing + 1, PUBLISHER, Standing::Selected);
    expect(closing + 1, "other.example.org", void);
    expect(last_in_force + 1, PUBLISHER, Standing::Selected);
    expect(last_in_force + 2, PUBLISHER, void);
}

#[test]
fn void_and_rejected_records_trigger_nothing() {
    let mut fx = Fixture::new();
    fx.hourly(
        0,
        vec![
            fx.admit_own("audit.example.net"),
            fx.admit_own("checker.example.org"),
            fx.admit_own("kin.example.com"),
            fx.admit_own("gone.sample.net"),
            declaration(PUBLISHER, &["blog.example.com"], "site"),
            declaration("blog.example.com", &[], "blog"),
        ],
    );
    let own = pages(PUBLISHER, "site", "own", 128);
    let parent_for_blog = delta(PUBLISHER, "https://blog.example.com/post", "site");
    let audited = fx.hourly(1, [own.clone(), vec![parent_for_blog.clone()]].concat());
    let (filer_beta, gone_beta) = (
        beta("audit.example.net", &audited),
        beta("gone.sample.net", &audited),
    );
    let d = first(&own, &|id| {
        drawn(&filer_beta, id, PROVISIONAL) && drawn(&gone_beta, id, PROVISIONAL)
    });
    fx.hourly(
        2,
        vec![fx.remove("gone.sample.net", &key_id("gone.sample.net"))],
    );
    fn make<'a>(auditor: &'a str, id: &'a str, over: &'a BlockRow, fetched_at: i64) -> Audit<'a> {
        Audit {
            auditor,
            audited: id,
            proof_over: over,
            fetched_at,
            verdict: "inconsistent",
        }
    }
    let filer_id = key_id("audit.example.net");
    let bad_scores = {
        let mut entry = record(&make("audit.example.net", &d, &audited, START + HOUR));
        let mut body = entry["body"]["record"].clone();
        body["similarity"] = json!(950_000);
        entry["body"] =
            envelope::sign_envelope(&body, "record", &filer_id, &key("audit.example.net")).unwrap();
        entry
    };
    let tampered = {
        let mut pi = proof("audit.example.net", &audited);
        pi[7] ^= 1;
        record_signed(
            &make("audit.example.net", &d, &audited, START + HOUR + 1),
            "audit.example.net",
            &filer_id,
            &hex_encode(&pi),
        )
    };
    let foreign_signature = record_signed(
        &make("audit.example.net", &d, &audited, START + HOUR + 2),
        "checker.example.org",
        &filer_id,
        &hex_encode(&proof("audit.example.net", &audited)),
    );
    let unknown_id = format!("sha256:{}", "1".repeat(64));
    let unknown_delta = record(&make(
        "audit.example.net",
        &unknown_id,
        &audited,
        START + HOUR + 3,
    ));
    let early_fetch = record(&make("audit.example.net", &d, &audited, START + HOUR - 1));
    let blog_id = delta_id(&parent_for_blog);
    let outside_domain = record(&make(
        "audit.example.net",
        &blog_id,
        &audited,
        START + HOUR + 4,
    ));
    let self_audit = record(&make("kin.example.com", &d, &audited, START + HOUR + 5));
    let removed_key = record(&make("gone.sample.net", &d, &audited, START + HOUR + 6));
    let malformed = {
        let mut entry = record(&make("audit.example.net", &d, &audited, START + HOUR + 7));
        entry["body"]["record"]["vrf_proof"] = json!("0011");
        entry
    };
    fx.hourly(
        3,
        vec![
            bad_scores,
            tampered,
            foreign_signature,
            unknown_delta,
            early_fetch,
            outside_domain,
            self_audit,
            removed_key,
            malformed,
        ],
    );
    let history = fx.reconstruct().unwrap();
    assert!(history.triggers().is_empty());
    assert!(history.duties().is_empty());
    assert!(history.escalations().is_empty());
    let at_3: Vec<&RecordStanding> = history
        .records()
        .iter()
        .filter(|record| record.position.block_number == 3)
        .collect();
    assert_eq!(at_3.len(), 9);
    let by_fetch = |fetched_at: i64| -> &RecordStanding {
        at_3.iter()
            .copied()
            .find(|record| fx.record_body(record.position)["fetched_at"] == ts(fetched_at))
            .unwrap()
    };
    let scores = by_fetch(START + HOUR);
    assert_eq!(scores.standing, Standing::Selected);
    assert_eq!(scores.diagnostic, Some("WIST4-E02"));
    assert!(scores.authentic && scores.discharges_coverage && !scores.evidence());
    let tampered = by_fetch(START + HOUR + 1);
    assert_eq!(
        tampered.standing,
        Standing::Void(VoidReason::ProofWithoutStanding)
    );
    assert_eq!(tampered.diagnostic, Some("WIST4-E01"));
    assert!(!tampered.discharges_coverage);
    let foreign = by_fetch(START + HOUR + 2);
    assert_eq!(foreign.standing, Standing::Selected);
    assert!(!foreign.authentic);
    assert_eq!(foreign.diagnostic, Some("WIST4-E01"));
    assert!(!foreign.discharges_coverage);
    let unknown = by_fetch(START + HOUR + 3);
    assert_eq!(unknown.standing, Standing::Void(VoidReason::UnknownDelta));
    assert_eq!(unknown.diagnostic, Some("WIST4-E01"));
    assert_eq!(unknown.publisher, None);
    let early = by_fetch(START + HOUR - 1);
    assert_eq!(early.standing, Standing::Selected);
    assert_eq!(early.diagnostic, Some("WIST4-E02"));
    let outside = by_fetch(START + HOUR + 4);
    assert_eq!(outside.standing, Standing::Void(VoidReason::OutsideDomain));
    assert_eq!(outside.duty, Duty::Absent);
    assert_eq!(outside.diagnostic, Some("WIST4-E01"));
    let kin = by_fetch(START + HOUR + 5);
    assert_eq!(kin.standing, Standing::Void(VoidReason::SelfAudit));
    assert_eq!(kin.diagnostic, Some("WIST4-E01"));
    let removed = by_fetch(START + HOUR + 6);
    assert_eq!(removed.standing, Standing::Selected);
    assert_eq!(removed.duty, Duty::RemovedAfterAnchor);
    assert!(removed.authentic);
    assert_eq!(removed.diagnostic, Some("WIST4-E01"));
    assert!(removed.discharges_coverage);
    let malformed = by_fetch(START + HOUR + 7);
    assert_eq!(malformed.standing, Standing::Void(VoidReason::Malformed));
    assert_eq!(malformed.diagnostic, Some("WIST4-E09"));
    assert!(!malformed.discharges_coverage);
}

#[test]
fn reconstruction_requires_the_complete_pinned_prefix_and_rereads_repaired_files() {
    let mut fx = Fixture::new();
    fx.hourly(
        0,
        vec![
            fx.admit_own("audit.example.net"),
            fx.admit_own("checker.example.org"),
            declaration(PUBLISHER, &[], "site"),
        ],
    );
    let deltas = pages(PUBLISHER, "site", "r", 32);
    let audited = fx.hourly(1, deltas.clone());
    let filer_beta = beta("audit.example.net", &audited);
    let d = first(&deltas, &|id| drawn(&filer_beta, id, PROVISIONAL));
    let trigger = fx.hourly(
        2,
        vec![record(&Audit {
            auditor: "audit.example.net",
            audited: &d,
            proof_over: &audited,
            fetched_at: START + HOUR,
            verdict: "inconsistent",
        })],
    );
    let later = fx.hourly(
        3,
        vec![record(&Audit {
            auditor: "checker.example.org",
            audited: &d,
            proof_over: &trigger,
            fetched_at: START + 2 * HOUR,
            verdict: "consistent",
        })],
    );
    let original = std::fs::read(fx.path(2)).unwrap();
    std::fs::write(fx.path(2), b"corrupt").unwrap();
    assert!(fx.reconstruct().is_err());
    std::fs::write(fx.path(2), original).unwrap();
    let full = fx.reconstruct().unwrap();
    assert_eq!(full.triggers().len(), 1);
    assert_eq!(full.records().len(), 2);
    assert_eq!(
        standing_of(&full, 3, "checker.example.org").standing,
        Standing::Extension { trigger_height: 2 }
    );
    let pinned = ExtensionHistory::reconstruct(fx.data.path(), Some(audited.clone())).unwrap();
    assert!(pinned.triggers().is_empty() && pinned.records().is_empty());
    assert_eq!(pinned.through().map(|row| row.block_number), Some(1));
    let through_trigger =
        ExtensionHistory::reconstruct(fx.data.path(), Some(trigger.clone())).unwrap();
    assert_eq!(through_trigger.triggers().len(), 1);
    assert!(through_trigger.triggers()[0].outcome.is_none());
    assert_eq!(through_trigger.named("checker.example.org", 2).len(), 1);
    assert!(ExtensionHistory::reconstruct(
        fx.data.path(),
        Some(BlockRow {
            block_hash: format!("sha256:{}", "0".repeat(64)),
            ..later.clone()
        }),
    )
    .is_err());
    assert_eq!(full.anchor_hash(), through_trigger.anchor_hash());
}

fn vector_verdict(name: &str) -> Verdict {
    match name {
        "consistent" => Verdict::Consistent,
        "inconsistent" => Verdict::Inconsistent,
        "link_inconsistent" => Verdict::LinkInconsistent,
        other => panic!("unsupported vector verdict {other}"),
    }
}

fn evidence_vectors() -> Value {
    serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/extension.json")).unwrap(),
    )
    .unwrap()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn candidate(r: &Value) -> wist_core::confirmation::CandidateRecord<'_> {
    wist_core::confirmation::CandidateRecord {
        block_height: r["block_height"].as_u64().unwrap(),
        entry_index: r["entry_index"].as_u64().unwrap(),
        block_sealed_at_s: r["sealed_at_s"].as_i64().unwrap(),
        auditor_id: r["auditor"].as_str().unwrap(),
        effective_similarity: 0,
    }
}

#[test]
fn evidence_vectors_derive_rejection_from_signed_records() {
    use clave::record::{RecordEnvelope, ReplayContext, SigningBinding};
    use wist_core::coverage::Block;
    use wist_core::crypto::PublicKey;
    use wist_core::extension::{
        evaluate, rationed_summons, summoned, trigger_indices, ExtensionClaim, ExtensionRecord,
    };
    use wist_core::verdict::{record_scores_valid, ChangeType, Thresholds};

    let vectors = evidence_vectors();
    let window = vectors["confirm_window_hours"].as_u64().unwrap();
    let triggers_max = vectors["extension_triggers_max"].as_u64().unwrap();
    let ration_days = vectors["ration_window_days"].as_u64().unwrap();
    let roster = strings(&vectors["evidence_roster"]);
    let roster: Vec<&str> = roster.iter().map(String::as_str).collect();
    let publisher = vectors["evidence_publisher"].as_str().unwrap();
    let keys: BTreeMap<String, (String, PublicKey)> = vectors["evidence_keys"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(auditor, key)| {
            (
                auditor.clone(),
                (
                    key["key_id"].as_str().unwrap().to_owned(),
                    PublicKey::from_b64u(key["public_key"].as_str().unwrap()).unwrap(),
                ),
            )
        })
        .collect();
    let th = &vectors["evidence_thresholds"];
    let thresholds = Thresholds {
        similarity_consistent: th["similarity_consistent"].as_u64().unwrap(),
        similarity_variance_floor: th["similarity_variance_floor"].as_u64().unwrap(),
        link_agreement_consistent: th["link_agreement_consistent"].as_u64().unwrap(),
        link_variance_floor: th["link_variance_floor"].as_u64().unwrap(),
        ..Thresholds::default()
    };
    let blocks: Vec<Block> = vectors["contradiction_blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|block| Block {
            height: block["height"].as_u64().unwrap(),
            sealed_at_s: block["sealed_at_s"].as_i64().unwrap(),
        })
        .collect();
    let cases = vectors["evidence_cases"].as_array().unwrap();
    assert!(cases.len() >= 16);
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let records = case["records"].as_array().unwrap();
        let mut evidence: Vec<bool> = Vec::new();
        for record in records {
            let raw = record["record_json"].as_str().unwrap();
            let rejected = strings(&record["rejected"]);
            let diagnostic = match RecordEnvelope::parse(raw.as_bytes()) {
                Err(code) => Some(code),
                Ok(envelope) => {
                    let original: Value = serde_json::from_str(raw).unwrap();
                    let body = &original["record"];
                    let auditor = body["auditor_id"].as_str().unwrap_or("");
                    let binding = keys
                        .get(auditor)
                        .map(|(key_id, public_key)| SigningBinding {
                            auditor_id: auditor,
                            key_id,
                            public_key,
                        });
                    let scores_valid = body["verdict"].as_str().is_some_and(|verdict| {
                        record_scores_valid(
                            ChangeType::New,
                            vector_verdict(verdict),
                            body["similarity"].as_u64(),
                            body["link_agreement"].as_u64(),
                            &thresholds,
                        )
                    });
                    let context = &record["context"];
                    let duty = if context["standing"] != true {
                        Duty::Absent
                    } else if context["removed"] == true {
                        Duty::RemovedAfterAnchor
                    } else {
                        Duty::Active
                    };
                    envelope
                        .disposition(&ReplayContext {
                            signing: binding,
                            duty,
                            coverage_failure: context["coverage_failure"] == true,
                            semantic_evidence_error: !scores_valid,
                        })
                        .diagnostic
                }
            };
            assert_eq!(
                diagnostic.is_none(),
                rejected.is_empty(),
                "{label}: {} {diagnostic:?}",
                record["mutation"]
            );
            if let Some(code) = diagnostic {
                assert!(
                    rejected.iter().any(|value| value == code),
                    "{label}: {code}"
                );
            }
            evidence.push(diagnostic.is_none());
        }
        let mut summoning: Vec<(&str, i64)> = Vec::new();
        let mut expected_triggers = case["triggers"].as_array().unwrap().iter();
        for (i, record) in records.iter().enumerate() {
            let verdict = vector_verdict(record["verdict"].as_str().unwrap());
            let delta = record["delta"].as_str().unwrap();
            let such = |r: &Value| {
                r["delta"] == delta
                    && matches!(
                        vector_verdict(r["verdict"].as_str().unwrap()),
                        Verdict::Inconsistent | Verdict::LinkInconsistent
                    )
            };
            let prior: Vec<&Value> = records[..i]
                .iter()
                .zip(&evidence)
                .filter(|(r, ok)| **ok && such(r))
                .map(|(r, _)| r)
                .collect();
            let eligible = evidence[i]
                && matches!(verdict, Verdict::Inconsistent | Verdict::LinkInconsistent)
                && {
                    let sequence: Vec<_> = prior
                        .iter()
                        .map(|r| candidate(r))
                        .chain(std::iter::once(candidate(record)))
                        .collect();
                    trigger_indices(&sequence, window)
                        .unwrap()
                        .contains(&(sequence.len() - 1))
                };
            assert_eq!(eligible, record["eligible"], "{label} record {i}");
            let summons = eligible && {
                summoning.push((
                    record["auditor"].as_str().unwrap(),
                    record["sealed_at_s"].as_i64().unwrap(),
                ));
                let fired = *rationed_summons(&summoning, ration_days, triggers_max)
                    .last()
                    .unwrap();
                if !fired {
                    summoning.pop();
                }
                fired
            };
            assert_eq!(summons, record["summons"], "{label} record {i}");
            let filers: Vec<&str> = prior
                .iter()
                .map(|r| r["auditor"].as_str().unwrap())
                .chain(std::iter::once(record["auditor"].as_str().unwrap()))
                .collect();
            let peers: Vec<&str> = if summons {
                summoned(&roster, &filers, publisher)
                    .into_iter()
                    .map(|index| roster[index])
                    .collect()
            } else {
                Vec::new()
            };
            assert_eq!(
                peers,
                strings(&record["summoned_auditors"]),
                "{label} record {i}"
            );
            if !eligible {
                continue;
            }
            let expected = expected_triggers.next().unwrap();
            assert_eq!(
                expected["record_index"].as_u64().unwrap() as usize,
                i,
                "{label}"
            );
            let same: Vec<ExtensionRecord> = records
                .iter()
                .zip(&evidence)
                .filter(|(r, ok)| {
                    **ok && r["delta"] == delta
                        && r["sealed_at_s"].as_i64() >= record["sealed_at_s"].as_i64()
                })
                .map(|(r, _)| ExtensionRecord {
                    position: candidate(r),
                    verdict: match vector_verdict(r["verdict"].as_str().unwrap()) {
                        Verdict::Consistent => wist_core::objects::audit::Verdict::Consistent,
                        Verdict::Inconsistent => wist_core::objects::audit::Verdict::Inconsistent,
                        _ => wist_core::objects::audit::Verdict::LinkInconsistent,
                    },
                })
                .collect();
            let trigger_index = same
                .iter()
                .position(|r| {
                    r.position.block_height == record["block_height"].as_u64().unwrap()
                        && r.position.entry_index == record["entry_index"].as_u64().unwrap()
                })
                .unwrap();
            let outcome = evaluate(
                &ExtensionClaim {
                    trigger_index,
                    summoned: summons,
                    confirm_window_hours: window,
                    confirm_auditors: 2,
                },
                &same,
                &blocks,
            )
            .unwrap();
            assert_eq!(
                outcome.closing_block.map(|block| block.height),
                expected["closes_at_height"].as_u64(),
                "{label}"
            );
            assert_eq!(outcome.confirmed, expected["confirmed"], "{label}");
            assert_eq!(
                outcome.consistent_quorum, expected["independent_consistent_pair"],
                "{label}"
            );
            assert_eq!(
                outcome.establishing_block.map(|block| block.height),
                expected["establishing_height"].as_u64(),
                "{label}"
            );
            assert_eq!(
                outcome.establishing_block.is_some(),
                expected["contradicted"],
                "{label}"
            );
        }
        assert!(expected_triggers.next().is_none(), "{label}");
    }
}

#[test]
fn evidence_vectors_replay_as_signed_histories() {
    let vectors = evidence_vectors();
    let offset = 990u64;
    let audited_height = 5u64;
    let trigger_height = 10u64;
    let last_height = 90u64;
    let roster = strings(&vectors["evidence_roster"]);
    let publisher = vectors["evidence_publisher"].as_str().unwrap();
    let mut exercised: BTreeSet<String> = BTreeSet::new();
    for case in vectors["evidence_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let records = case["records"].as_array().unwrap();
        if records
            .iter()
            .any(|record| record["mutation"] == "coverage-failure")
        {
            continue;
        }
        let mut fx = Fixture::new();
        let mut genesis: Vec<Value> = roster.iter().map(|auditor| fx.admit_own(auditor)).collect();
        genesis.push(declaration(publisher, &[], "site"));
        fx.hourly(0, genesis);
        for height in 1..audited_height {
            fx.hourly(height, vec![]);
        }
        let deltas = pages(publisher, "site", "e", 160);
        let audited = fx.hourly(audited_height, deltas.clone());
        let height_of = |record: &Value| record["block_height"].as_u64().unwrap() - offset;
        let proof_height: Vec<Option<u64>> = records
            .iter()
            .enumerate()
            .map(|(i, record)| {
                records[..i].iter().find_map(|earlier| {
                    (earlier["delta"] == record["delta"]
                        && earlier["summons"] == true
                        && strings(&earlier["summoned_auditors"])
                            .contains(&record["auditor"].as_str().unwrap().to_owned()))
                    .then(|| height_of(earlier))
                })
            })
            .collect();
        let mut delta_of: BTreeMap<String, String> = BTreeMap::new();
        let mut used: BTreeSet<String> = BTreeSet::new();
        for record in records {
            let vector_delta = record["delta"].as_str().unwrap().to_owned();
            if delta_of.contains_key(&vector_delta) {
                continue;
            }
            let vrf_auditors: Vec<&str> = records
                .iter()
                .zip(&proof_height)
                .filter(|(r, over)| r["delta"] == vector_delta && over.is_none())
                .map(|(r, _)| r["auditor"].as_str().unwrap())
                .collect();
            let betas: Vec<[u8; 64]> = vrf_auditors
                .iter()
                .map(|auditor| beta(auditor, &audited))
                .collect();
            let chosen = first(&deltas, &|id| {
                !used.contains(id) && betas.iter().all(|beta| drawn(beta, id, PROVISIONAL))
            });
            used.insert(chosen.clone());
            delta_of.insert(vector_delta, chosen);
        }
        let removed: Vec<&str> = records
            .iter()
            .filter(|record| record["mutation"] == "removed")
            .map(|record| record["auditor"].as_str().unwrap())
            .collect();
        for height in audited_height + 1..trigger_height {
            let entries = match height {
                7 => removed
                    .iter()
                    .map(|auditor| fx.remove(auditor, &key_id(auditor)))
                    .collect(),
                8 => removed
                    .iter()
                    .map(|auditor| {
                        fx.admit(
                            auditor,
                            &format!("{auditor}#readmitted"),
                            &format!("key:{auditor}:2"),
                        )
                    })
                    .collect(),
                _ => Vec::new(),
            };
            fx.hourly(height, entries);
        }
        let mut rows: BTreeMap<u64, BlockRow> = BTreeMap::new();
        rows.insert(audited_height, audited.clone());
        for height in trigger_height..=last_height {
            let mut entries = Vec::new();
            for (i, item) in records.iter().enumerate() {
                if height_of(item) != height {
                    continue;
                }
                let auditor = item["auditor"].as_str().unwrap();
                let mutation = item["mutation"].as_str().unwrap();
                exercised.insert(mutation.to_owned());
                let over = match proof_height[i] {
                    Some(trigger) => rows[&trigger].clone(),
                    None => audited.clone(),
                };
                let audit = Audit {
                    auditor,
                    audited: &delta_of[item["delta"].as_str().unwrap()],
                    proof_over: &over,
                    fetched_at: START + over.block_number as i64 * HOUR,
                    verdict: item["verdict"].as_str().unwrap(),
                };
                let own_id = key_id(auditor);
                let resigned = |mut entry: Value, edit: &dyn Fn(&mut Value)| {
                    let mut body = entry["body"]["record"].clone();
                    edit(&mut body);
                    entry["body"] =
                        envelope::sign_envelope(&body, "record", &own_id, &key(auditor)).unwrap();
                    entry
                };
                let entry = match mutation {
                    "none" | "removed" => record(&audit),
                    "mis-scored" => resigned(record(&audit), &|body| {
                        body["similarity"] = json!(if audit.verdict == "inconsistent" {
                            940_000
                        } else {
                            250_000
                        });
                    }),
                    "missing-evidence" => resigned(record(&audit), &|body| {
                        body.as_object_mut().unwrap().remove("evidence_commitment");
                    }),
                    "unsupported-major" => resigned(record(&audit), &|body| {
                        body["wist_version"] = json!("2.0.0");
                    }),
                    "unknown-member" => {
                        let mut entry = record(&audit);
                        entry["body"]["unknown"] = json!(true);
                        entry
                    }
                    "forged" => {
                        let mut entry = record(&audit);
                        entry["body"]["sig"]["value"] =
                            json!(wist_core::crypto::b64u_encode(&[0u8; 64]));
                        entry
                    }
                    "wrong-signer" => {
                        let other = roster.iter().find(|peer| *peer != auditor).unwrap();
                        record_signed(
                            &audit,
                            other,
                            &key_id(other),
                            &hex_encode(&proof(auditor, &over)),
                        )
                    }
                    "no-standing" => {
                        let mut pi = proof(auditor, &over);
                        pi[7] ^= 1;
                        record_signed(&audit, auditor, &own_id, &hex_encode(&pi))
                    }
                    other => panic!("{label}: unsupported mutation {other}"),
                };
                entries.push(entry);
            }
            let row = fx.hourly(height, entries);
            rows.insert(height, row);
        }
        let history = fx.reconstruct().unwrap();
        assert!(history.roster().rejected().is_empty(), "{label}");
        let mut expected_triggers = case["triggers"].as_array().unwrap().iter();
        for (i, record) in records.iter().enumerate() {
            let auditor = record["auditor"].as_str().unwrap();
            let height = height_of(record);
            let delta = &delta_of[record["delta"].as_str().unwrap()];
            let standing = history
                .records()
                .iter()
                .find(|r| {
                    r.position.block_number == height
                        && r.auditor_id == auditor
                        && r.audited_delta == *delta
                })
                .unwrap_or_else(|| panic!("{label}: no Record by {auditor} at Block {height}"));
            let rejected = strings(&record["rejected"]);
            assert_eq!(
                standing.evidence(),
                rejected.is_empty(),
                "{label}: {} {:?}",
                record["mutation"],
                standing.diagnostic
            );
            if let Some(code) = standing.diagnostic {
                assert!(
                    rejected.iter().any(|value| value == code),
                    "{label}: {code}"
                );
            }
            match record["mutation"].as_str().unwrap() {
                "removed" => {
                    assert_eq!(standing.duty, Duty::RemovedAfterAnchor, "{label}");
                    assert!(
                        standing.authentic && standing.discharges_coverage,
                        "{label}"
                    );
                }
                "no-standing" => assert_eq!(
                    standing.standing,
                    Standing::Void(VoidReason::ProofWithoutStanding),
                    "{label}"
                ),
                "unknown-member" => assert_eq!(
                    standing.standing,
                    Standing::Void(VoidReason::Malformed),
                    "{label}"
                ),
                _ => assert_eq!(
                    standing.standing,
                    match proof_height[i] {
                        Some(trigger_height) => Standing::Extension { trigger_height },
                        None => Standing::Selected,
                    },
                    "{label}"
                ),
            }
            let trigger = history.triggers().iter().find(|trigger| {
                trigger.position.block_number == height
                    && trigger.delta_id == *delta
                    && trigger.auditor_id == auditor
            });
            assert_eq!(trigger.is_some(), record["eligible"], "{label} record {i}");
            let Some(trigger) = trigger else {
                continue;
            };
            assert_eq!(trigger.summons, record["summons"], "{label} record {i}");
            assert_eq!(
                trigger.summoned.iter().cloned().collect::<BTreeSet<_>>(),
                strings(&record["summoned_auditors"])
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                "{label} record {i}"
            );
            let expected = expected_triggers.next().unwrap();
            assert_eq!(
                expected["record_index"].as_u64().unwrap() as usize,
                i,
                "{label}"
            );
            if expected["closes_at_height"].is_null() {
                assert!(
                    trigger.outcome.is_none(),
                    "{label}: the extension is still open"
                );
                continue;
            }
            let outcome = trigger
                .outcome
                .unwrap_or_else(|| panic!("{label}: extension never closed"));
            assert_eq!(
                outcome.closing_block.map(|block| block.height + offset),
                expected["closes_at_height"].as_u64(),
                "{label}"
            );
            assert_eq!(outcome.confirmed, expected["confirmed"], "{label}");
            assert_eq!(
                outcome.consistent_quorum, expected["independent_consistent_pair"],
                "{label}"
            );
            assert_eq!(
                outcome
                    .establishing_block
                    .map(|block| block.height + offset),
                expected["establishing_height"].as_u64(),
                "{label}"
            );
        }
        assert!(expected_triggers.next().is_none(), "{label}");
        let contradicted: Vec<u64> = case["triggers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|trigger| trigger["establishing_height"].as_u64())
            .map(|height| height - offset)
            .collect();
        assert_eq!(
            history
                .escalations()
                .iter()
                .map(|escalation| escalation.establishing_height)
                .collect::<Vec<_>>(),
            contradicted,
            "{label}"
        );
    }
    assert_eq!(
        exercised,
        BTreeSet::from_iter(
            [
                "none",
                "mis-scored",
                "missing-evidence",
                "unsupported-major",
                "unknown-member",
                "forged",
                "wrong-signer",
                "no-standing",
                "removed",
            ]
            .map(str::to_owned)
        )
    );
}

fn coverage_vectors() -> Value {
    serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/coverage.json")).unwrap(),
    )
    .unwrap()
}

fn update_id(entry: &Value) -> String {
    wist_core::delta::delta_id(&entry["body"]["update"]).unwrap()
}

#[test]
fn unpublished_duties_fail_at_the_fallback_and_exclude_records_past_the_maximum() {
    let mut fx = Fixture::new();
    fx.hourly(
        0,
        vec![
            fx.admit_own("audit.example.net"),
            fx.admit_own("checker.example.org"),
            declaration(PUBLISHER, &[], "site"),
        ],
    );
    for height in 1..100 {
        fx.hourly(height, vec![]);
    }
    let deltas = pages(PUBLISHER, "site", "c", 64);
    let audited = fx.hourly(100, deltas.clone());
    let filer_beta = beta("audit.example.net", &audited);
    let d = first(&deltas, &|id| drawn(&filer_beta, id, PROVISIONAL));
    for height in 101..=130 {
        let entries = if height == 119 || height == 120 {
            vec![record(&Audit {
                auditor: "audit.example.net",
                audited: &d,
                proof_over: &audited,
                fetched_at: START + 100 * HOUR + (height - 118) as i64,
                verdict: "consistent",
            })]
        } else {
            Vec::new()
        };
        fx.hourly(height, entries);
    }
    let history = fx.reconstruct().unwrap();
    assert!(history.rejected_acts().is_empty());
    let silent = history.coverage_duty("audit.example.net", 5).unwrap();
    assert!(!silent.published());
    assert_eq!(silent.selection, None);
    assert_eq!(silent.deadline_s, i128::from(START + 5 * HOUR + 72 * HOUR));
    assert_eq!(silent.unattested_height, Some(101));
    assert_eq!(silent.establishing_height(), Some(101));
    assert_eq!(silent.complete_at, None);
    assert_eq!(
        history.counting_failures("audit.example.net", 95),
        Vec::<u64>::new()
    );
    assert_eq!(history.counting_failures("audit.example.net", 96), vec![0]);
    assert_eq!(
        history.counting_failures("audit.example.net", 120),
        (0..=24).collect::<Vec<u64>>()
    );
    assert!(!history.in_coverage_failure("audit.example.net", 119));
    assert!(history.in_coverage_failure("audit.example.net", 120));
    assert!(history.in_coverage_failure("checker.example.org", 130));
    let audited_pair = history.coverage_duty("audit.example.net", 100).unwrap();
    assert!(audited_pair.published());
    assert!(audited_pair.selection.as_ref().unwrap().contains(&d));
    assert_eq!(audited_pair.discharged.get(&d), Some(&119));
    let timely = standing_of(&history, 119, "audit.example.net");
    assert!(timely.evidence() && timely.discharges_coverage && !timely.coverage_failure);
    let late = standing_of(&history, 120, "audit.example.net");
    assert!(late.coverage_failure && !late.evidence() && late.discharges_coverage);
    assert_eq!(late.diagnostic, Some("WIST4-E01"));
    assert_eq!(late.standing, Standing::Selected);
}

#[test]
fn coverage_attestations_discharge_empty_selections_and_pulls_establish_at_their_block() {
    let mut fx = Fixture::new();
    fx.hourly(
        0,
        vec![
            fx.admit_own("audit.example.net"),
            fx.admit_own("checker.example.org"),
            declaration(PUBLISHER, &[], "site"),
        ],
    );
    let filer = "audit.example.net";
    let checker = "checker.example.org";
    let mut rows: BTreeMap<u64, BlockRow> = BTreeMap::new();
    for height in 1..=100 {
        let previous = |h: u64| rows[&h].clone();
        let entries = match height {
            10 => vec![coverage_attestation(
                filer,
                filer,
                &key_id(filer),
                &previous(5),
                None,
            )],
            12 => {
                let mut tampered =
                    coverage_attestation(filer, filer, &key_id(filer), &previous(7), None);
                let mut update = tampered["body"]["update"].clone();
                let mut hex = update["details"]["vrf_proof"].as_str().unwrap().to_owned();
                hex.replace_range(0..2, if hex.starts_with("00") { "01" } else { "00" });
                update["details"]["vrf_proof"] = json!(hex);
                tampered["body"] =
                    envelope::sign_envelope(&update, "update", &key_id(filer), &key(filer))
                        .unwrap();
                let unknown = BlockRow {
                    block_number: 8,
                    block_hash: format!("sha256:{}", "1".repeat(64)),
                    sealed_at: ts(START + 8 * HOUR),
                };
                let mut stale =
                    coverage_attestation(filer, filer, &key_id(filer), &previous(9), None);
                let mut update = stale["body"]["update"].clone();
                update["wist_version"] = json!("2.0.0");
                stale["body"] =
                    envelope::sign_envelope(&update, "update", &key_id(filer), &key(filer))
                        .unwrap();
                vec![
                    coverage_attestation(filer, checker, &key_id(checker), &previous(6), None),
                    tampered,
                    coverage_attestation(filer, filer, &key_id(filer), &unknown, None),
                    stale,
                    fx.pull("nobody.example.net", &previous(5), &[]),
                    {
                        let update = json!({
                            "wist_version": "1.0.0", "action": "pull_attestation", "subject": checker,
                            "details": {"block": previous(6).block_hash, "found": []}, "effective_at": ts(START),
                        });
                        json!({"type": "registry_update", "body": envelope::sign_envelope(&update, "update", &key_id(filer), &key(filer)).unwrap()})
                    },
                    {
                        let mut malformed = fx.pull(checker, &previous(7), &[]);
                        malformed["body"]["update"]["details"]["found"] = json!(["not an id"]);
                        malformed
                    },
                    {
                        let mut unchained =
                            coverage_attestation(filer, filer, &key_id(filer), &previous(11), None);
                        let mut update = unchained["body"]["update"].clone();
                        update["details"]
                            .as_object_mut()
                            .unwrap()
                            .remove("prev_record");
                        unchained["body"] =
                            envelope::sign_envelope(&update, "update", &key_id(filer), &key(filer))
                                .unwrap();
                        unchained
                    },
                ]
            }
            80 => vec![fx.pull(checker, &previous(5), &[])],
            90 => vec![coverage_attestation(
                checker,
                checker,
                &key_id(checker),
                &previous(5),
                None,
            )],
            _ => Vec::new(),
        };
        let row = fx.hourly(height, entries);
        rows.insert(height, row);
    }
    let history = fx.reconstruct().unwrap();
    let attested = history.coverage_duty(filer, 5).unwrap();
    assert_eq!(attested.selection.as_deref(), Some(&[][..]));
    assert_eq!(attested.attested_empty_at, Some(10));
    assert_eq!(attested.complete_at, Some(10));
    assert_eq!(
        history.counting_failures(filer, 100),
        vec![0, 1, 2, 3, 4],
        "pairs establish at the fallback 96 Blocks after their Block; the attested pair is complete"
    );
    let mut codes: Vec<(u64, String, &str, String)> = history
        .rejected_acts()
        .iter()
        .map(|r| {
            (
                r.position.block_number,
                r.action.clone(),
                r.code,
                r.subject.clone(),
            )
        })
        .collect();
    codes.sort();
    assert_eq!(
        codes,
        vec![
            (
                12,
                "coverage_attestation".to_owned(),
                "WIST4-E01",
                filer.to_owned()
            ),
            (
                12,
                "coverage_attestation".to_owned(),
                "WIST4-E04",
                filer.to_owned()
            ),
            (
                12,
                "coverage_attestation".to_owned(),
                "WIST4-E04",
                filer.to_owned()
            ),
            (
                12,
                "coverage_attestation".to_owned(),
                "WIST4-E11",
                filer.to_owned()
            ),
            (
                12,
                "coverage_attestation".to_owned(),
                "WIST4-E11",
                filer.to_owned()
            ),
            (
                12,
                "pull_attestation".to_owned(),
                "WIST4-E04",
                checker.to_owned()
            ),
            (
                12,
                "pull_attestation".to_owned(),
                "WIST4-E04",
                "nobody.example.net".to_owned()
            ),
            (
                12,
                "pull_attestation".to_owned(),
                "WIST4-E11",
                checker.to_owned()
            ),
        ]
    );
    for height in [6, 7, 9, 11] {
        assert_eq!(
            history.coverage_duty(filer, height).unwrap().complete_at,
            None,
            "{height}"
        );
    }
    let pulled = history.coverage_duty(checker, 5).unwrap();
    assert_eq!(pulled.pull.as_ref().unwrap().position.block_number, 80);
    assert_eq!(pulled.unattested_height, None);
    assert_eq!(pulled.establishing_height(), Some(80));
    assert_eq!(pulled.complete_at, Some(90));
    assert!(!history.counting_failures(checker, 79).contains(&5));
    assert!(history.counting_failures(checker, 80).contains(&5));
    assert!(history.counting_failures(checker, 89).contains(&5));
    assert!(!history.counting_failures(checker, 90).contains(&5));
    assert_eq!(history.coverage_duty(checker, 6).unwrap().pull, None);
    assert_eq!(history.coverage_duty(checker, 7).unwrap().pull, None);
}

#[test]
fn records_discharge_selected_and_named_deltas_and_partial_completion_fails() {
    let mut fx = Fixture::new();
    fx.attest_empty = true;
    let (filer, checker, watcher) = (
        "audit.example.net",
        "checker.example.org",
        "watch.sample.net",
    );
    fx.hourly(
        0,
        vec![
            fx.admit_own(filer),
            fx.admit_own(checker),
            fx.admit_own(watcher),
            declaration(PUBLISHER, &[], "site"),
        ],
    );
    let deltas = pages(PUBLISHER, "site", "s", 48);
    let audited = fx.hourly(1, deltas.clone());
    let filer_beta = beta(filer, &audited);
    let selected: Vec<String> = pick(&deltas, &|id| drawn(&filer_beta, id, PROVISIONAL));
    assert!(selected.len() >= 3);
    let (last, rest) = selected.split_last().unwrap();
    let filed = |id: &str, fetched_at: i64| {
        record(&Audit {
            auditor: filer,
            audited: id,
            proof_over: &audited,
            fetched_at,
            verdict: "consistent",
        })
    };
    fx.hourly(2, rest.iter().map(|id| filed(id, START + HOUR)).collect());
    let checked = fx.hourly(3, vec![filed(last, START + HOUR + 1)]);
    let checker_beta = beta(checker, &audited);
    let e = first(&deltas, &|id| drawn(&checker_beta, id, PROVISIONAL));
    let trigger = fx.hourly(
        4,
        vec![record(&Audit {
            auditor: checker,
            audited: &e,
            proof_over: &audited,
            fetched_at: START + HOUR + 2,
            verdict: "inconsistent",
        })],
    );
    fx.hourly(5, vec![]);
    fx.hourly(
        6,
        vec![record(&Audit {
            auditor: filer,
            audited: &e,
            proof_over: &trigger,
            fetched_at: START + 4 * HOUR,
            verdict: "consistent",
        })],
    );
    for height in 7..=100 {
        fx.hourly(height, vec![]);
    }
    let history = fx.reconstruct().unwrap();
    assert!(history.rejected_acts().is_empty());
    let pair = history.coverage_duty(filer, 1).unwrap();
    let mut expected = selected.clone();
    expected.sort();
    assert_eq!(pair.selection.as_ref(), Some(&expected));
    assert_eq!(pair.attested_empty_at, Some(2));
    assert_eq!(pair.discharged.len(), selected.len());
    assert_eq!(pair.discharged[last], 3);
    assert_eq!(pair.complete_at, Some(checked.block_number));
    let partial = ExtensionHistory::reconstruct(fx.data.path(), Some(fx.rows[2].clone())).unwrap();
    let open = partial.coverage_duty(filer, 1).unwrap();
    assert_eq!(open.discharged.len(), selected.len() - 1);
    assert_eq!(
        open.complete_at, None,
        "an attested nonempty selection is not complete"
    );
    let summoned = history.coverage_duty(filer, 4).unwrap();
    assert_eq!(summoned.selection.as_deref(), Some(&[][..]));
    assert_eq!(summoned.named, vec![e.clone()]);
    assert_eq!(summoned.duty_set(), Some(vec![e.clone()]));
    assert_eq!(summoned.attested_empty_at, Some(5));
    assert_eq!(summoned.discharged.get(&e), Some(&6));
    assert_eq!(summoned.complete_at, Some(6));
    let extension = standing_of(&history, 6, filer);
    assert_eq!(
        extension.standing,
        Standing::Extension { trigger_height: 4 }
    );
    let idle = history.coverage_duty(watcher, 4).unwrap();
    assert_eq!(idle.named, vec![e.clone()]);
    assert_eq!(idle.complete_at, None);
    assert_eq!(idle.establishing_height(), Some(100));
    assert!(!history.counting_failures(watcher, 99).contains(&4));
    assert!(history.counting_failures(watcher, 100).contains(&4));
    assert_eq!(history.counting_failures(filer, 100), Vec::<u64>::new());
    assert_eq!(history.counting_failures(checker, 100), vec![1]);
}

#[test]
fn pair_specific_exemption_reads_the_aggregators_receipt() {
    let vectors = coverage_vectors();
    let (filer, checker) = ("audit.example.net", "checker.example.org");
    let mut exercised = 0;
    for case in vectors["attribution_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        if case["successor"]["log"] != case["log"] {
            continue;
        }
        exercised += 1;
        let mut fx = Fixture::new();
        fx.hourly(
            0,
            vec![
                fx.admit_own(filer),
                fx.admit_own(checker),
                declaration(PUBLISHER, &[], "site"),
            ],
        );
        let mut rows: BTreeMap<u64, BlockRow> = BTreeMap::new();
        for height in 1..=9 {
            rows.insert(height, fx.hourly(height, vec![]));
        }
        let missing_a = coverage_attestation(filer, filer, &key_id(filer), &rows[&6], None);
        let missing_b = coverage_attestation(filer, filer, &key_id(filer), &rows[&7], None);
        let id_of = |name: &str| match name {
            "missing a" => update_id(&missing_a),
            "missing b" => update_id(&missing_b),
            other => panic!("{label}: unknown ID {other}"),
        };
        let found: Vec<String> = case["pull"]["found"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| id_of(name.as_str().unwrap()))
            .collect();
        let pull_height = case["pull"]["height"].as_u64().unwrap();
        let successor = &case["successor"];
        let successor_height = successor["height"].as_u64().unwrap();
        let successor_auditor = successor["auditor"].as_str().unwrap();
        let prev = id_of(successor["prev_record"].as_str().unwrap());
        let predecessor_height = case["predecessor_sealed_height"].as_u64();
        let n_height = case["n_height"].as_u64().unwrap();
        let last = n_height.max(successor_height) + 1;
        for height in 10..=last {
            let mut entries = Vec::new();
            if height == pull_height {
                entries.push(fx.pull(filer, &rows[&5], &found));
            }
            if height == successor_height {
                entries.push(coverage_attestation(
                    successor_auditor,
                    successor_auditor,
                    &key_id(successor_auditor),
                    &rows[&8],
                    Some(&prev),
                ));
            }
            if predecessor_height == Some(height) {
                entries.push(missing_a.clone());
            }
            rows.insert(height, fx.hourly(height, entries));
        }
        let history = fx.reconstruct().unwrap();
        assert!(history.rejected_acts().is_empty(), "{label}");
        let pair = history.coverage_duty(filer, 5).unwrap();
        assert_eq!(
            pair.pull.as_ref().unwrap().position.block_number,
            pull_height,
            "{label}"
        );
        assert_eq!(pair.complete_at, None, "{label}");
        let counts = history.counting_failures(filer, n_height).contains(&5);
        assert_eq!(
            counts,
            !case["chain_contradicts"].as_bool().unwrap(),
            "{label}"
        );
    }
    assert_eq!(exercised, 8);
}

#[test]
fn late_discharge_vectors_replay_as_signed_histories() {
    let vectors = coverage_vectors();
    let filer = "audit.example.net";
    let offset = 1u64;
    let mut exercised = 0;
    for case in vectors["late_discharge_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        assert_eq!(case["audited_height"].as_u64().unwrap(), 0, "{label}");
        assert_eq!(case["record_seal_blocks"].as_u64().unwrap(), 24, "{label}");
        assert_eq!(case["deadline_height"].as_u64().unwrap(), 72, "{label}");
        let selected: Vec<&str> = case["selected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        let mut fx = Fixture::new();
        fx.hourly(
            0,
            vec![fx.admit_own(filer), declaration(PUBLISHER, &[], "site")],
        );
        let deltas = if selected.is_empty() {
            Vec::new()
        } else {
            pages(PUBLISHER, "site", "l", 64)
        };
        let audited = fx.hourly(offset, deltas.clone());
        let filer_beta = beta(filer, &audited);
        let drawn_ids = pick(&deltas, &|id| drawn(&filer_beta, id, PROVISIONAL));
        assert!(
            selected.is_empty() || drawn_ids.len() > selected.len(),
            "{label}"
        );
        let mapped: BTreeMap<&str, &String> = selected.iter().copied().zip(&drawn_ids).collect();
        let filed = |id: &str, fetched_at: i64, tampered: bool| {
            let audit = Audit {
                auditor: filer,
                audited: id,
                proof_over: &audited,
                fetched_at,
                verdict: "consistent",
            };
            if tampered {
                let mut pi = proof(filer, &audited);
                pi[7] ^= 1;
                record_signed(&audit, filer, &key_id(filer), &hex_encode(&pi))
            } else {
                record(&audit)
            }
        };
        let last = case["probes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|probe| probe["height"].as_u64().unwrap())
            .max()
            .unwrap()
            + offset;
        for height in offset + 1..=last {
            let mut entries = Vec::new();
            if height == offset + 1 {
                for id in drawn_ids.iter().skip(selected.len()) {
                    entries.push(filed(id, START + offset as i64 * HOUR, false));
                }
            }
            if case["pull_height"].as_u64() == Some(height - offset) {
                entries.push(fx.pull(filer, &audited, &[]));
            }
            for sealed in case["records"].as_array().unwrap() {
                if sealed["sealed_height"].as_u64().unwrap() + offset == height {
                    let tampered = sealed["void"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|reason| reason == "bad_vrf_proof");
                    entries.push(filed(
                        mapped[sealed["delta"].as_str().unwrap()],
                        START + offset as i64 * HOUR + height as i64,
                        tampered,
                    ));
                }
            }
            if case["coverage_attestation_height"].as_u64() == Some(height - offset) {
                entries.push(coverage_attestation(
                    filer,
                    filer,
                    &key_id(filer),
                    &audited,
                    None,
                ));
            }
            fx.hourly(height, entries);
        }
        let history = fx.reconstruct().unwrap();
        assert!(history.rejected_acts().is_empty(), "{label}");
        let pair = history.coverage_duty(filer, offset).unwrap();
        let mut expected: Vec<String> = drawn_ids.clone();
        expected.sort();
        assert_eq!(pair.selection.as_ref(), Some(&expected), "{label}");
        for probe in case["probes"].as_array().unwrap() {
            let height = probe["height"].as_u64().unwrap() + offset;
            let complete = pair.complete_at.is_some_and(|at| at <= height);
            assert_eq!(complete, probe["complete"], "{label} at {height}");
            let counts = history.counting_failures(filer, height).contains(&offset);
            assert_eq!(counts, probe["counts"], "{label} at {height}");
        }
        exercised += 1;
    }
    assert_eq!(exercised, 5);
}

fn lift(fx: &Fixture, subject: &str) -> Value {
    fx.log_signed(json!({
        "wist_version": "1.0.0", "action": "sanction_lift", "subject": subject,
        "details": {"reason": "discretionary"}, "effective_at": ts(START),
    }))
}

#[test]
fn reputation_and_the_first_rung_derive_from_evidence_findings_and_lifts() {
    use wist_core::reputation::{base_u, reputation_formula_u, DecayTable};
    let mut fx = Fixture::new();
    fx.attest_empty = true;
    let (filer, checker, watcher) = (
        "audit.example.net",
        "checker.example.org",
        "watch.sample.net",
    );
    fx.hourly(
        0,
        vec![
            fx.admit_own(filer),
            fx.admit_own(checker),
            fx.admit_own(watcher),
            declaration(PUBLISHER, &[], "site"),
        ],
    );
    let deltas = pages(PUBLISHER, "site", "r", 64);
    let audited = fx.hourly(1, deltas.clone());
    let betas: BTreeMap<&str, [u8; 64]> = [filer, checker, watcher]
        .into_iter()
        .map(|auditor| (auditor, beta(auditor, &audited)))
        .collect();
    let by = |auditor: &str, id: &str| drawn(&betas[auditor], id, PROVISIONAL);
    let shared = pick(&deltas, &|id| by(filer, id) && by(checker, id));
    let linked = pick(&deltas, &|id| {
        by(checker, id) && by(watcher, id) && !shared.contains(&id.to_owned())
    });
    let filer_only: Vec<String> = pick(&deltas, &|id| by(filer, id))
        .into_iter()
        .filter(|id| !shared.contains(id) && !linked.contains(id))
        .take(3)
        .collect();
    assert!(!shared.is_empty() && !linked.is_empty() && filer_only.len() == 3);
    let (d0, d1) = (&shared[0], &linked[0]);
    let audit =
        |auditor: &'static str, id: &str, verdict: &'static str, over: &BlockRow, at: i64| {
            record(&Audit {
                auditor,
                audited: id,
                proof_over: over,
                fetched_at: at,
                verdict,
            })
        };
    fx.hourly(
        2,
        filer_only
            .iter()
            .map(|id| audit(filer, id, "consistent", &audited, START + HOUR))
            .collect(),
    );
    fx.hourly(
        3,
        vec![audit(filer, d0, "inconsistent", &audited, START + HOUR + 1)],
    );
    let confirming = fx.hourly(
        4,
        vec![
            audit(checker, d0, "inconsistent", &audited, START + HOUR + 2),
            audit(checker, d1, "link_inconsistent", &audited, START + HOUR + 3),
        ],
    );
    fx.hourly(
        5,
        vec![audit(
            watcher,
            d1,
            "link_inconsistent",
            &audited,
            START + HOUR + 4,
        )],
    );
    let later = pages(PUBLISHER, "site", "later", 64);
    let escalated_block = fx.hourly(6, later.clone());
    let filer_later = beta(filer, &escalated_block);
    let e = first(&later, &|id| {
        drawn(&filer_later, id, CEILING) && !drawn(&filer_later, id, PROVISIONAL)
    });
    fx.hourly(
        7,
        vec![audit(
            filer,
            &e,
            "consistent",
            &escalated_block,
            START + 6 * HOUR,
        )],
    );
    fx.hourly(8, vec![lift(&fx, PUBLISHER)]);
    fx.hourly(9, {
        let update = json!({
            "wist_version": "1.0.0", "action": "sanction_lift", "subject": PUBLISHER,
            "details": {}, "effective_at": ts(START),
        });
        vec![json!({"type": "registry_update", "body": envelope::sign_envelope(&update, "update", &key_id(filer), &key(filer)).unwrap()})]
    });
    let after = pages(PUBLISHER, "site", "after", 64);
    let lifted_block = fx.hourly(10, after.clone());
    let penalised = reputation_formula_u(base_u(0), 3, 3 * DecayTable::builtin().decay(0) as u128);
    let lifted_rate = 200_000 + 3 * (1_000_000 - penalised);
    let filer_after = beta(filer, &lifted_block);
    let f = first(&after, &|id| {
        drawn(&filer_after, id, CEILING) && !drawn(&filer_after, id, lifted_rate)
    });
    fx.hourly(
        11,
        vec![audit(
            filer,
            &f,
            "consistent",
            &lifted_block,
            START + 10 * HOUR,
        )],
    );
    for height in 12..=30 {
        fx.hourly(height, vec![]);
    }
    let history = fx.reconstruct().unwrap();
    let findings = history.findings();
    assert_eq!(findings.len(), 2);
    let extract = &findings[0];
    assert_eq!(
        (extract.delta_id.as_str(), extract.link, extract.severity),
        (d0.as_str(), false, 2)
    );
    assert_eq!(extract.confirming.block_number, 4);
    assert_eq!(extract.audited_height, 1);
    assert_eq!(extract.publisher, PUBLISHER);
    let link = &findings[1];
    assert_eq!(
        (link.delta_id.as_str(), link.link, link.severity),
        (d1.as_str(), true, 1)
    );
    assert_eq!(link.confirming.block_number, 5);
    let clean = history.reputation(PUBLISHER, 3).unwrap();
    assert_eq!(
        (
            clean.age_days,
            clean.c,
            clean.penalty_n,
            clean.provisional,
            clean.reputation_u
        ),
        (0, 3, 0, true, 100_000)
    );
    let at_confirmation = history.reputation(PUBLISHER, 4).unwrap();
    assert_eq!(
        at_confirmation.penalty_n,
        2 * DecayTable::builtin().decay(0) as u128
    );
    assert_eq!(
        at_confirmation.reputation_u,
        reputation_formula_u(base_u(0), 3, at_confirmation.penalty_n)
    );
    let both = history.reputation(PUBLISHER, 5).unwrap();
    assert_eq!(both.penalty_n, 3 * DecayTable::builtin().decay(0) as u128);
    assert_eq!(both.reputation_u, penalised);
    let aged = history.reputation(PUBLISHER, 29).unwrap();
    assert_eq!(aged.age_days, 1);
    assert_eq!(aged.penalty_n, 3 * DecayTable::builtin().decay(1) as u128);
    assert_eq!(
        history
            .reputation("other.example.org", 29)
            .unwrap()
            .reputation_u,
        100_000
    );
    assert!(!history.level1_sanction(PUBLISHER, 3));
    assert!(history.level1_sanction(PUBLISHER, 4));
    assert!(history.level1_sanction(PUBLISHER, 7));
    assert!(!history.level1_sanction(PUBLISHER, 8));
    assert!(!history.level1_sanction(PUBLISHER, 30));
    assert_eq!(
        history
            .rejected_acts()
            .iter()
            .map(|r| (r.position.block_number, r.action.as_str(), r.code))
            .collect::<Vec<_>>(),
        vec![(9, "sanction_lift", "WIST4-E11")]
    );
    assert!(history.prior_state(PUBLISHER, Some(5)).level1_sanction);
    assert_eq!(history.prior_state(PUBLISHER, None).reputation_u, 100_000);
    let escalated = standing_of(&history, 7, filer);
    assert_eq!(
        escalated.standing,
        Standing::Selected,
        "the first rung raises the draw to the ceiling"
    );
    assert!(escalated.evidence());
    let relapsed = standing_of(&history, 11, filer);
    assert_eq!(
        relapsed.standing,
        Standing::Void(VoidReason::ProofWithoutStanding),
        "after the lift the formula rate applies"
    );
    assert_eq!(
        history
            .coverage_duty(filer, 6)
            .unwrap()
            .selection
            .as_ref()
            .map(|s| s.contains(&e)),
        Some(true)
    );
    assert_eq!(
        history
            .coverage_duty(filer, 10)
            .unwrap()
            .selection
            .as_ref()
            .map(|s| s.contains(&f)),
        Some(false)
    );
    assert_eq!(confirming.block_number, 4);
}

#[test]
fn a_fresh_identity_resets_reputation_inputs_and_rungs() {
    let mut fx = Fixture::new();
    fx.attest_empty = true;
    let (filer, checker) = ("audit.example.net", "checker.example.org");
    let genesis_declaration = declaration(PUBLISHER, &[], "site");
    fx.hourly(
        0,
        vec![
            fx.admit_own(filer),
            fx.admit_own(checker),
            genesis_declaration.clone(),
        ],
    );
    let deltas = pages(PUBLISHER, "site", "i", 64);
    let audited = fx.hourly(1, deltas.clone());
    let (filer_beta, checker_beta) = (beta(filer, &audited), beta(checker, &audited));
    let d = first(&deltas, &|id| {
        drawn(&filer_beta, id, PROVISIONAL) && drawn(&checker_beta, id, PROVISIONAL)
    });
    let audit =
        |auditor: &'static str, id: &str, verdict: &'static str, over: &BlockRow, at: i64| {
            record(&Audit {
                auditor,
                audited: id,
                proof_over: over,
                fetched_at: at,
                verdict,
            })
        };
    fx.hourly(
        2,
        vec![audit(filer, &d, "inconsistent", &audited, START + HOUR)],
    );
    fx.hourly(
        3,
        vec![audit(
            checker,
            &d,
            "inconsistent",
            &audited,
            START + HOUR + 1,
        )],
    );
    for height in 4..8 {
        fx.hourly(height, vec![]);
    }
    fx.hourly(
        8,
        vec![declaration_after(
            PUBLISHER,
            &[],
            "site-fresh",
            1,
            Some(&genesis_declaration),
        )],
    );
    let fresh = pages(PUBLISHER, "site-fresh", "fresh", 8);
    fx.hourly(9, fresh.clone());
    let d2 = first(&deltas, &|id| {
        *id != d && drawn(&filer_beta, id, PROVISIONAL) && drawn(&checker_beta, id, PROVISIONAL)
    });
    let late = fx.hourly(
        10,
        vec![
            audit(checker, &d, "inconsistent", &audited, START + HOUR + 2),
            audit(filer, &d2, "inconsistent", &audited, START + HOUR + 3),
        ],
    );
    fx.hourly(
        11,
        vec![audit(
            checker,
            &d2,
            "inconsistent",
            &audited,
            START + HOUR + 4,
        )],
    );
    for height in 12..=40 {
        fx.hourly(height, vec![]);
    }
    let history = fx.reconstruct().unwrap();
    assert_eq!(
        history.findings().len(),
        2,
        "a pre-reset Delta still confirms after the reset"
    );
    assert_eq!(history.findings()[1].confirming.block_number, 11);
    assert!(
        !history.level1_sanction(PUBLISHER, 11),
        "a finding for a Delta sealed below the reset arms no rung of the fresh identity"
    );
    assert_eq!(history.sanction_level(PUBLISHER, 11), 0);
    assert_eq!(history.reputation(PUBLISHER, 11).unwrap().penalty_n, 0);
    assert!(history.level1_sanction(PUBLISHER, 7));
    let before = history.reputation(PUBLISHER, 7).unwrap();
    assert!(before.penalty_n > 0 && before.age_days == 0);
    assert!(
        !history.level1_sanction(PUBLISHER, 8),
        "a fresh identity lifts every rung at its Block"
    );
    let reset = history.reputation(PUBLISHER, 8).unwrap();
    assert_eq!(
        (reset.penalty_n, reset.c, reset.age_days, reset.reputation_u),
        (0, 0, 0, 100_000)
    );
    let aged = history.reputation(PUBLISHER, 40).unwrap();
    assert_eq!(
        aged.age_days, 1,
        "age is measured from the fresh identity's first accepted Delta"
    );
    assert_eq!(
        aged.penalty_n, 0,
        "a finding for a Delta sealed below the reset never returns"
    );
    assert!(!history.level1_sanction(PUBLISHER, 40));
    assert_eq!(late.block_number, 10);
    assert!(standing_of(&history, 10, checker).evidence());
}

fn vector_signer<'a>(
    doc: &Value,
    keys: &'a [(String, wist_core::crypto::PublicKey)],
) -> Option<&'a str> {
    keys.iter()
        .find(|(key_id, public_key)| {
            doc["sig"]["key_id"] == key_id.as_str()
                && envelope::verify_envelope(doc, "update", public_key).is_ok()
        })
        .map(|(key_id, _)| key_id.as_str())
}

fn resign(update: &Value, key_id: &str, signer: &SigningKey) -> Value {
    json!({
        "type": "registry_update",
        "body": envelope::sign_envelope(update, "update", key_id, signer).unwrap(),
    })
}

#[test]
fn attestation_vectors_replay_as_signed_histories() {
    let vectors = coverage_vectors();
    let log_key_id = vectors["attestation_log_key"]["key_id"].as_str().unwrap();
    let mut keys: Vec<(String, wist_core::crypto::PublicKey)> = vec![(
        log_key_id.to_owned(),
        wist_core::crypto::PublicKey::from_b64u(
            vectors["attestation_log_key"]["public_key"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    )];
    let auditors: Vec<(String, String)> = vectors["attestation_auditors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            keys.push((
                a["key_id"].as_str().unwrap().to_owned(),
                wist_core::crypto::PublicKey::from_b64u(a["public_key"].as_str().unwrap()).unwrap(),
            ));
            (
                a["auditor_id"].as_str().unwrap().to_owned(),
                a["key_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let duty_hash = vectors["attestation_duty_block"].as_str().unwrap();
    let (filer, checker) = (auditors[0].0.as_str(), auditors[1].0.as_str());
    let filer_key_id = auditors[0].1.as_str();
    let mut exercised = BTreeSet::new();
    for case in vectors["attestation_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let doc: Value = serde_json::from_str(
            case["record_json"]
                .as_str()
                .unwrap_or(case["envelope_json"].as_str().unwrap()),
        )
        .unwrap();
        let context = &case["context"];
        let admitted = context["subject_admitted_at_block"] == true;
        let held_at_block = context["key_held_at_block"] == true;
        let held_at_duty = context["key_held_at_duty_block"] == true;
        let empty = context["duty_set_empty"] == true;
        let mut fx = Fixture::new();
        let mut genesis = vec![fx.admit_own(checker), declaration(PUBLISHER, &[], "site")];
        if admitted {
            genesis.push(fx.admit_own(filer));
        }
        fx.hourly(0, genesis);
        let deltas = if empty {
            Vec::new()
        } else {
            pages(PUBLISHER, "site", "a", 32)
        };
        let duty = fx.hourly(1, deltas);
        let rotated_label = format!("{filer}#rotated");
        let mut block_two = Vec::new();
        if !admitted {
            block_two.push(fx.admit_own(filer));
        } else if !held_at_block && held_at_duty {
            block_two.push(fx.remove(filer, &key_id(filer)));
            block_two.push(fx.admit(filer, &rotated_label, &format!("key:{filer}:2")));
        }
        fx.hourly(2, block_two);
        let mut update = doc["update"].clone();
        let unsealed = context["block_sealed_below"] != true;
        let named = if unsealed {
            format!("sha256:{}", "1".repeat(64))
        } else {
            duty.block_hash.clone()
        };
        if update["details"].get("block").is_some() && update["details"]["block"] == duty_hash {
            update["details"]["block"] = json!(named);
        }
        if let Some(hex) = update["details"]["vrf_proof"].as_str().map(str::to_owned) {
            let bytes = wist_core::crypto::hex_decode(&hex).ok();
            let proof_key = bytes.as_ref().and_then(|bytes| {
                <[u8; vrf::PROOF_LEN]>::try_from(bytes.as_slice())
                    .ok()
                    .and_then(|pi| {
                        keys.iter().skip(1).find(|(_, public_key)| {
                            let alpha = sampling::alpha_from_block_hash(duty_hash).unwrap();
                            let raw: [u8; 32] =
                                wist_core::crypto::b64u_decode(&public_key.to_b64u())
                                    .unwrap()
                                    .try_into()
                                    .unwrap();
                            vrf::verify(&raw, &alpha, &pi).is_ok()
                        })
                    })
            });
            let replacement = match proof_key.map(|(key_id, _)| key_id.as_str()) {
                Some(id) if id == filer_key_id => Some(hex_encode(&proof(filer, &duty))),
                Some(_) => Some(hex_encode(&proof(checker, &duty))),
                None if hex.len() == 2 * vrf::PROOF_LEN => {
                    Some(hex_encode(&proof(filer, &fx.rows[0].clone())))
                }
                None => None,
            };
            if let Some(replacement) = replacement {
                update["details"]["vrf_proof"] = json!(replacement);
            }
        }
        let signer =
            vector_signer(&doc, &keys).unwrap_or(if case["action"] == "pull_attestation" {
                log_key_id
            } else {
                filer_key_id
            });
        let entry = if signer == log_key_id {
            resign(&update, "log1", &fx.sk)
        } else if signer == filer_key_id {
            if held_at_block || held_at_duty || !admitted {
                resign(&update, &key_id(filer), &key(filer))
            } else {
                resign(&update, "key:stranger", &key("stranger"))
            }
        } else {
            resign(&update, &key_id(checker), &key(checker))
        };
        fx.hourly(3, vec![entry]);
        for height in 4..=6 {
            fx.hourly(height, vec![]);
        }
        let history = fx.reconstruct().unwrap();
        let rejected: Vec<(u64, String, &str)> = history
            .rejected_acts()
            .iter()
            .map(|r| (r.position.block_number, r.action.clone(), r.code))
            .collect();
        match case["code"].as_str() {
            Some(code) => assert_eq!(
                rejected,
                vec![(3, case["action"].as_str().unwrap().to_owned(), code)],
                "{label}"
            ),
            None => assert!(rejected.is_empty(), "{label}: {rejected:?}"),
        }
        let pair = history.coverage_duty(filer, 1);
        match case["effect"].as_str().unwrap() {
            "attested" => assert_eq!(
                pair.unwrap().pull.as_ref().map(|p| p.position.block_number),
                Some(3),
                "{label}"
            ),
            "discharged" => {
                let pair = pair.unwrap();
                assert_eq!(
                    (pair.attested_empty_at, pair.complete_at),
                    (Some(3), Some(3)),
                    "{label}"
                );
            }
            "draw" => {
                let pair = pair.unwrap();
                assert!(
                    pair.beta.is_some() && pair.attested_empty_at == Some(3),
                    "{label}"
                );
                assert!(
                    !pair.selection.as_ref().unwrap().is_empty() && pair.complete_at.is_none(),
                    "{label}"
                );
            }
            "ignored" => {
                if let Some(pair) = pair {
                    assert!(
                        pair.pull.is_none() && pair.attested_empty_at.is_none(),
                        "{label}"
                    );
                }
            }
            other => panic!("{label}: unknown effect {other}"),
        }
        exercised.insert(case["effect"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        exercised,
        BTreeSet::from_iter(["attested", "discharged", "draw", "ignored"].map(str::to_owned))
    );
}

#[test]
fn lift_vectors_replay_as_signed_histories() {
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/sanctions.json")).unwrap(),
    )
    .unwrap();
    let log_key_id = vectors["lift_log_key"]["key_id"].as_str().unwrap();
    let log_key = wist_core::crypto::PublicKey::from_b64u(
        vectors["lift_log_key"]["public_key"].as_str().unwrap(),
    )
    .unwrap();
    let (filer, checker) = ("audit.example.net", "checker.example.org");
    let mut seen = BTreeSet::new();
    for case in vectors["lift_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let doc: Value = serde_json::from_str(case["envelope_json"].as_str().unwrap()).unwrap();
        let subject = doc["update"]["subject"].as_str().unwrap();
        let mut fx = Fixture::new();
        fx.attest_empty = true;
        let mut genesis = vec![fx.admit_own(filer), fx.admit_own(checker)];
        let hosted = crate_host_ok(subject);
        if hosted {
            genesis.push(declaration(subject, &[], "site"));
        }
        fx.hourly(0, genesis);
        let deltas = if hosted {
            pages(subject, "site", "l", 48)
        } else {
            Vec::new()
        };
        let audited = fx.hourly(1, deltas.clone());
        let (fb, cb) = (beta(filer, &audited), beta(checker, &audited));
        let d = if hosted {
            Some(first(&deltas, &|id| {
                drawn(&fb, id, PROVISIONAL) && drawn(&cb, id, PROVISIONAL)
            }))
        } else {
            None
        };
        let audit = |auditor: &'static str, id: &str, at: i64| {
            record(&Audit {
                auditor,
                audited: id,
                proof_over: &audited,
                fetched_at: at,
                verdict: "inconsistent",
            })
        };
        fx.hourly(
            2,
            d.iter().map(|id| audit(filer, id, START + HOUR)).collect(),
        );
        fx.hourly(
            3,
            d.iter()
                .map(|id| audit(checker, id, START + HOUR + 1))
                .collect(),
        );
        let entry = if doc["sig"]["key_id"] == log_key_id
            && envelope::verify_envelope(&doc, "update", &log_key).is_ok()
        {
            resign(&doc["update"], "log1", &fx.sk)
        } else {
            resign(&doc["update"], &key_id(filer), &key(filer))
        };
        fx.hourly(4, vec![entry]);
        fx.hourly(5, vec![]);
        let history = fx.reconstruct().unwrap();
        let codes: Vec<(u64, &str)> = history
            .rejected_acts()
            .iter()
            .map(|r| (r.position.block_number, r.code))
            .collect();
        match case["code"].as_str() {
            Some(code) => assert_eq!(codes, vec![(4, code)], "{label}"),
            None => assert!(codes.is_empty(), "{label}: {codes:?}"),
        }
        if hosted {
            assert!(history.level1_sanction(subject, 3), "{label}");
            assert_eq!(
                history.level1_sanction(subject, 4),
                case["code"].as_str().is_some(),
                "{label}: an accepted lift clears the rung, a rejected one clears nothing"
            );
        }
        seen.insert(case["code"].as_str().map(str::to_owned));
    }
    assert_eq!(seen.len(), 3);
}

fn crate_host_ok(subject: &str) -> bool {
    !subject.is_empty()
        && subject
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.'))
}

#[test]
fn exemptions_after_the_fallback_and_forged_successors() {
    let (filer, checker) = ("audit.example.net", "checker.example.org");
    let mut fx = Fixture::new();
    fx.hourly(
        0,
        vec![
            fx.admit_own(filer),
            fx.admit_own(checker),
            declaration(PUBLISHER, &[], "site"),
        ],
    );
    let mut rows: BTreeMap<u64, BlockRow> = BTreeMap::new();
    for height in 1..=9 {
        rows.insert(height, fx.hourly(height, vec![]));
    }
    let missing_x = coverage_attestation(filer, filer, &key_id(filer), &rows[&7], None);
    let missing_y = coverage_attestation(filer, filer, &key_id(filer), &rows[&8], None);
    let (x, y) = (update_id(&missing_x), update_id(&missing_y));
    for height in 10..=110 {
        let mut entries = Vec::new();
        match height {
            80 => entries.push(fx.pull(filer, &rows[&6], std::slice::from_ref(&y))),
            81 => {
                let mut forged =
                    coverage_attestation(filer, filer, &key_id(filer), &rows[&9], Some(&y));
                forged["body"]["sig"]["value"] = json!(wist_core::crypto::b64u_encode(&[0u8; 64]));
                entries.push(forged);
            }
            105 => entries.push(fx.pull(filer, &rows[&5], std::slice::from_ref(&x))),
            106 => entries.push(coverage_attestation(
                filer,
                filer,
                &key_id(filer),
                &rows[&9],
                Some(&x),
            )),
            _ => {}
        }
        rows.insert(height, fx.hourly(height, entries));
    }
    let history = fx.reconstruct().unwrap();
    assert_eq!(
        history
            .rejected_acts()
            .iter()
            .map(|r| (r.position.block_number, r.code))
            .collect::<Vec<_>>(),
        vec![(81, "WIST4-E11")],
        "the forged successor is rejected"
    );
    let five = history.coverage_duty(filer, 5).unwrap();
    assert_eq!(five.unattested_height, Some(101));
    assert_eq!(
        five.pull.as_ref().map(|p| p.position.block_number),
        Some(105)
    );
    assert_eq!(five.establishing_height(), Some(101));
    assert!(history.counting_failures(filer, 104).contains(&5));
    assert!(history.counting_failures(filer, 105).contains(&5));
    assert!(
        !history.counting_failures(filer, 106).contains(&5),
        "an attested pair is exempt while contradicted even after the fallback established it"
    );
    assert!(!history.counting_failures(filer, 110).contains(&5));
    let six = history.coverage_duty(filer, 6).unwrap();
    assert_eq!(six.establishing_height(), Some(80));
    assert!(
        history.counting_failures(filer, 90).contains(&6),
        "a forged successor supplies no exemption"
    );
}

#[test]
fn same_block_discharges_settle_before_the_blocks_records_are_weighed() {
    let filer = "audit.example.net";
    let mut fx = Fixture::new();
    fx.hourly(
        0,
        vec![fx.admit_own(filer), declaration(PUBLISHER, &[], "site")],
    );
    let mut rows: BTreeMap<u64, BlockRow> = BTreeMap::new();
    for height in 1..100 {
        rows.insert(height, fx.hourly(height, vec![]));
    }
    let deltas = pages(PUBLISHER, "site", "s", 64);
    let audited = fx.hourly(100, deltas.clone());
    let filer_beta = beta(filer, &audited);
    let d = first(&deltas, &|id| drawn(&filer_beta, id, PROVISIONAL));
    let genesis = fx.rows[0].clone();
    for height in 101..=125 {
        let entries = if height == 120 {
            vec![
                coverage_attestation(filer, filer, &key_id(filer), &genesis, None),
                coverage_attestation(filer, filer, &key_id(filer), &rows[&1], None),
                record(&Audit {
                    auditor: filer,
                    audited: &d,
                    proof_over: &audited,
                    fetched_at: START + 100 * HOUR,
                    verdict: "consistent",
                }),
            ]
        } else {
            Vec::new()
        };
        fx.hourly(height, entries);
    }
    let history = fx.reconstruct().unwrap();
    assert!(history.rejected_acts().is_empty());
    assert_eq!(
        history.coverage_duty(filer, 0).unwrap().complete_at,
        Some(120)
    );
    assert_eq!(history.counting_failures(filer, 120).len(), 23);
    assert!(!history.in_coverage_failure(filer, 120));
    let weighed = standing_of(&history, 120, filer);
    assert!(weighed.evidence() && !weighed.coverage_failure);
    assert_eq!(history.counting_failures(filer, 121).len(), 24);
    assert!(!history.in_coverage_failure(filer, 121));
    assert!(history.in_coverage_failure(filer, 122));
}

fn record_id_of(entry: &Value) -> String {
    wist_core::delta::delta_id(&entry["body"]["record"]).unwrap()
}

fn audit_with_similarity(audit: &Audit<'_>, similarity: u64) -> Value {
    let mut entry = record(audit);
    let mut body = entry["body"]["record"].clone();
    body["similarity"] = json!(similarity);
    entry["body"] =
        envelope::sign_envelope(&body, "record", &key_id(audit.auditor), &key(audit.auditor))
            .unwrap();
    entry
}

fn notice(
    fx: &Fixture,
    subject: &str,
    level: u64,
    activation: &str,
    evidence: &[String],
    deadline: i64,
) -> Value {
    fx.log_signed(json!({
        "wist_version": "1.0.0", "action": "notice", "subject": subject,
        "details": {"kind": "sanction", "level": level, "activation": activation,
                    "reason": "confirmed finding", "appeal_deadline": ts(deadline)},
        "evidence": evidence, "effective_at": ts(START),
    }))
}

fn appeal(subject: &str, notice_id: &str, key_label: &str, key_id: &str) -> Value {
    let update = json!({
        "wist_version": "1.0.0", "action": "appeal", "subject": subject,
        "details": {"notice": notice_id, "statement": "the reference was stale"},
        "effective_at": ts(START),
    });
    json!({
        "type": "registry_update",
        "body": envelope::sign_envelope(&update, "update", key_id, &key(key_label)).unwrap(),
    })
}

fn ruling(fx: &Fixture, subject: &str, notice_id: &str, outcome: &str) -> Value {
    fx.log_signed(json!({
        "wist_version": "1.0.0", "action": "appeal_ruling", "subject": subject,
        "details": {"notice": notice_id, "outcome": outcome, "reasoning": "decided"},
        "effective_at": ts(START),
    }))
}

fn sanction_act(
    fx: &Fixture,
    subject: &str,
    level: u64,
    severity: u64,
    finding: &str,
    evidence: &[String],
) -> Value {
    fx.log_signed(json!({
        "wist_version": "1.0.0", "action": "sanction", "subject": subject,
        "details": {"level": level, "severity": severity, "finding": finding},
        "evidence": evidence, "effective_at": ts(START),
    }))
}

#[test]
fn notice_processes_replay_with_voids_and_enforceable_levels() {
    use clave::history::extension::ProcessSummary;
    use wist_core::sanctions::Outcome;
    let (filer, checker) = ("audit.example.net", "checker.example.org");
    let mut fx = Fixture::new();
    fx.attest_empty = true;
    fx.hourly(
        0,
        vec![
            fx.admit_own(filer),
            fx.admit_own(checker),
            declaration(PUBLISHER, &[], "site"),
        ],
    );
    let deltas = pages(PUBLISHER, "site", "n", 48);
    let audited = fx.hourly(1, deltas.clone());
    let (fb, cb) = (beta(filer, &audited), beta(checker, &audited));
    let d = first(&deltas, &|id| {
        drawn(&fb, id, PROVISIONAL) && drawn(&cb, id, PROVISIONAL)
    });
    let first_record = audit_with_similarity(
        &Audit {
            auditor: filer,
            audited: &d,
            proof_over: &audited,
            fetched_at: START + HOUR,
            verdict: "inconsistent",
        },
        10_000,
    );
    let confirming_record = audit_with_similarity(
        &Audit {
            auditor: checker,
            audited: &d,
            proof_over: &audited,
            fetched_at: START + HOUR + 1,
            verdict: "inconsistent",
        },
        10_000,
    );
    let (first_id, confirming_id) = (
        record_id_of(&first_record),
        record_id_of(&confirming_record),
    );
    fx.hourly(2, vec![first_record]);
    fx.hourly(3, vec![confirming_record]);
    let evidence = vec![first_id.clone(), confirming_id.clone()];
    let notice_entry = notice(
        &fx,
        PUBLISHER,
        3,
        &confirming_id,
        &evidence,
        START + 4 * HOUR + 14 * 86_400,
    );
    let notice_id = update_id(&notice_entry);
    let wrong_level = notice(
        &fx,
        PUBLISHER,
        4,
        &confirming_id,
        &evidence,
        START + 4 * HOUR + 14 * 86_400,
    );
    fx.hourly(
        4,
        vec![
            notice_entry,
            wrong_level.clone(),
            sanction_act(&fx, PUBLISHER, 3, 3, &confirming_id, &evidence),
            sanction_act(&fx, PUBLISHER, 3, 2, &confirming_id, &evidence),
            sanction_act(
                &fx,
                PUBLISHER,
                1,
                3,
                &confirming_id,
                &[first_id.clone(), format!("sha256:{}", "7".repeat(64))],
            ),
        ],
    );
    let unknown_notice = format!("sha256:{}", "5".repeat(64));
    fx.hourly(
        5,
        vec![
            appeal(PUBLISHER, &notice_id, "site", "k1"),
            appeal(PUBLISHER, &notice_id, "stranger", "k1"),
            appeal(PUBLISHER, &notice_id, "site", "kx"),
            ruling(&fx, PUBLISHER, &unknown_notice, "upheld"),
        ],
    );
    fx.hourly(6, vec![ruling(&fx, PUBLISHER, &notice_id, "overturned")]);
    for height in 7..=10 {
        fx.hourly(height, vec![]);
    }
    let history = fx.reconstruct().unwrap();
    assert_eq!(history.findings().len(), 1);
    assert_eq!(history.findings()[0].severity, 3);
    assert_eq!(history.findings()[0].confirming_record_id, confirming_id);
    assert_eq!(history.sanction_level(PUBLISHER, 2), 0);
    assert_eq!(history.sanction_level(PUBLISHER, 3), 3);
    assert_eq!(history.sanction_level(PUBLISHER, 5), 3);
    assert_eq!(
        history.sanction_level(PUBLISHER, 6),
        1,
        "an overturned ruling voids the level-3 activation"
    );
    assert_eq!(history.sanction_level(PUBLISHER, 10), 1);
    assert_eq!(
        history.enforceable_level(PUBLISHER, 3),
        1,
        "no notice yet: only rungs 1-2 are enforceable"
    );
    assert_eq!(history.enforceable_level(PUBLISHER, 4), 3);
    assert_eq!(history.enforceable_level(PUBLISHER, 5), 3);
    assert_eq!(history.enforceable_level(PUBLISHER, 6), 1);
    let processes = history.processes(PUBLISHER).unwrap();
    assert_eq!(processes.accepted.len(), 1);
    let process: &ProcessSummary = &processes.accepted[0];
    assert_eq!(process.notice.block_number, 4);
    assert_eq!(process.id, notice_id);
    assert_eq!(
        (process.level, process.activation.as_str()),
        (3, confirming_id.as_str())
    );
    assert_eq!(process.appeal.map(|p| p.block_number), Some(5));
    assert_eq!(
        process.merits.map(|(p, outcome)| (p.block_number, outcome)),
        Some((6, Outcome::Overturned))
    );
    assert_eq!(process.unappealed, None);
    assert_eq!(process.void_at_s, Some(i128::from(START + 6 * HOUR)));
    assert_eq!(
        process.retention_end_at_s,
        Some(i128::from(START + 6 * HOUR))
    );
    let rejected: Vec<(u64, &str)> = processes
        .rejected
        .iter()
        .map(|(p, code)| (p.block_number, *code))
        .collect();
    assert_eq!(
        rejected,
        vec![(4, "WIST4-E05"), (5, "WIST4-E05")],
        "the level-4 notice and the ruling for an unknown notice"
    );
    let mut acts: Vec<(u64, &str, &str)> = history
        .rejected_acts()
        .iter()
        .map(|r| (r.position.block_number, r.action.as_str(), r.code))
        .collect();
    acts.sort();
    assert_eq!(
        acts,
        vec![(5, "appeal", "WIST1-E01"), (5, "appeal", "WIST4-E05")]
    );
    let mut sanctions: Vec<(u8, u8, Option<&str>, bool)> = processes
        .sanctions
        .iter()
        .map(|s| (s.level, s.severity, s.diagnostic, s.noticed))
        .collect();
    sanctions.sort();
    assert_eq!(
        sanctions,
        vec![
            (1, 3, Some("WIST4-E05"), false),
            (3, 2, Some("WIST4-E05"), true),
            (3, 3, None, true),
        ]
    );
    assert_eq!(processes.levels, vec![(0, 0), (3, 3), (6, 1)]);
    assert_eq!(
        processes.activations.last().unwrap().1,
        [Some(confirming_id.clone()), None, None, None]
    );
}

#[test]
fn lapsed_appeal_sealing_deadline_voids_state_unless_an_unappealed_ruling_discharges_it() {
    let (filer, checker) = ("audit.example.net", "checker.example.org");
    for discharged in [false, true] {
        let mut fx = Fixture::new();
        fx.hourly(
            0,
            vec![
                fx.admit_own(filer),
                fx.admit_own(checker),
                declaration(PUBLISHER, &[], "site"),
            ],
        );
        let deltas = pages(PUBLISHER, "site", "v", 48);
        let audited = fx.hourly(1, deltas.clone());
        let (fb, cb) = (beta(filer, &audited), beta(checker, &audited));
        let d = first(&deltas, &|id| {
            drawn(&fb, id, PROVISIONAL) && drawn(&cb, id, PROVISIONAL)
        });
        let first_record = audit_with_similarity(
            &Audit {
                auditor: filer,
                audited: &d,
                proof_over: &audited,
                fetched_at: START + HOUR,
                verdict: "inconsistent",
            },
            10_000,
        );
        let confirming_record = audit_with_similarity(
            &Audit {
                auditor: checker,
                audited: &d,
                proof_over: &audited,
                fetched_at: START + HOUR + 1,
                verdict: "inconsistent",
            },
            10_000,
        );
        let evidence = vec![
            record_id_of(&first_record),
            record_id_of(&confirming_record),
        ];
        let activation = evidence[1].clone();
        fx.hourly(2, vec![first_record]);
        fx.hourly(3, vec![confirming_record]);
        let notice_entry = notice(
            &fx,
            PUBLISHER,
            3,
            &activation,
            &evidence,
            START + 4 * HOUR + 14 * 86_400,
        );
        let notice_id = update_id(&notice_entry);
        fx.hourly(4, vec![notice_entry]);
        let window_close = 4 + 14 * 24;
        let seal_deadline = window_close + 7 * 24;
        for height in 5..=seal_deadline + 2 {
            let entries = if discharged && height == window_close {
                vec![ruling(&fx, PUBLISHER, &notice_id, "unappealed")]
            } else {
                Vec::new()
            };
            fx.hourly(height, entries);
        }
        let history = fx.reconstruct().unwrap();
        assert!(history.rejected_acts().is_empty(), "{discharged}");
        let processes = history.processes(PUBLISHER).unwrap();
        assert!(processes.rejected.is_empty(), "{discharged}");
        let process = &processes.accepted[0];
        assert_eq!(
            history.sanction_level(PUBLISHER, seal_deadline - 1),
            3,
            "{discharged}"
        );
        if discharged {
            assert_eq!(
                process.unappealed.map(|p| p.block_number),
                Some(window_close)
            );
            assert_eq!(process.void_at_s, None);
            assert_eq!(history.sanction_level(PUBLISHER, seal_deadline + 2), 3);
            assert_eq!(history.enforceable_level(PUBLISHER, seal_deadline + 2), 3);
        } else {
            assert_eq!(
                process.void_at_s,
                Some(i128::from(START + seal_deadline as i64 * HOUR))
            );
            assert_eq!(
                history.sanction_level(PUBLISHER, seal_deadline),
                1,
                "silence voids the state at T"
            );
            assert_eq!(history.enforceable_level(PUBLISHER, seal_deadline), 1);
        }
        assert_eq!(
            process.retention_end_at_s,
            Some(i128::from(START + seal_deadline as i64 * HOUR))
        );
    }
}
