mod common;

use clave::db::BlockRow;
use clave::history::declarations::Position;
use clave::history::extension::{
    ExtensionHistory, PriorState, RecordStanding, Standing, Trigger, VoidReason,
};
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
const FLOOR: u64 = 200_000;
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

    fn reconstruct(
        &self,
        prior: &dyn Fn(&str, u64) -> PriorState,
    ) -> Result<ExtensionHistory, clave::Error> {
        ExtensionHistory::reconstruct(self.data.path(), self.head.clone(), prior)
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

fn ceiling(_: &str, _: u64) -> PriorState {
    PriorState {
        reputation_u: 0,
        level1_sanction: true,
    }
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
        drawn(&filer_beta, id, CEILING) && !drawn(&peer_beta, id, CEILING)
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
        let history = fx.reconstruct(&ceiling).unwrap();
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
    let mut genesis: Vec<Value> = roster.iter().map(|auditor| fx.admit_own(auditor)).collect();
    genesis.push(declaration(publisher, &[], "site"));
    fx.hourly(0, genesis);
    let deltas = pages(publisher, "site", "t", 96);
    let audited = fx.hourly(1, deltas.clone());
    let betas: BTreeMap<&str, [u8; 64]> = roster
        .iter()
        .map(|auditor| (*auditor, beta(auditor, &audited)))
        .collect();
    let by = |auditor: &str, id: &str| drawn(&betas[auditor], id, CEILING);
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
    let history = fx.reconstruct(&ceiling).unwrap();
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
        let prior_deltas = pick(&earlier, &|id| drawn(&earlier_beta, id, CEILING));
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
        let deltas = pages(PUBLISHER, "site", "d", 96);
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
            betas.iter().all(|beta| drawn(beta, id, CEILING))
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
        let history = fx.reconstruct(&ceiling).unwrap();
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
    let d = first(&deltas, &|id| {
        drawn(&filer_beta, id, CEILING) && !drawn(&filer_beta, id, FLOOR)
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
            !drawn(&filer_beta, id, FLOOR) && drawn(&filer_beta, id, CEILING)
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
    let established = |_: &str, _: u64| PriorState {
        reputation_u: 1_000_000,
        level1_sanction: false,
    };
    let sanctioned_first = |_: &str, height: u64| PriorState {
        reputation_u: 1_000_000,
        level1_sanction: height == 1,
    };
    let unselected = fx.reconstruct(&established).unwrap();
    assert!(
        unselected.escalations().is_empty() && unselected.triggers().is_empty(),
        "at the floor the filer's own draw did not select the Delta"
    );
    assert_eq!(
        standing_of(&unselected, 2, "audit.example.net").standing,
        Standing::Void(VoidReason::ProofWithoutStanding)
    );
    let history = fx.reconstruct(&sanctioned_first).unwrap();
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
    let own = pages(PUBLISHER, "site", "own", 64);
    let parent_for_blog = delta(PUBLISHER, "https://blog.example.com/post", "site");
    let audited = fx.hourly(1, [own.clone(), vec![parent_for_blog.clone()]].concat());
    let (filer_beta, gone_beta) = (
        beta("audit.example.net", &audited),
        beta("gone.sample.net", &audited),
    );
    let d = first(&own, &|id| {
        drawn(&filer_beta, id, CEILING) && drawn(&gone_beta, id, CEILING)
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
    let history = fx.reconstruct(&ceiling).unwrap();
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
    let d = first(&deltas, &|id| drawn(&filer_beta, id, CEILING));
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
    assert!(fx.reconstruct(&ceiling).is_err());
    std::fs::write(fx.path(2), original).unwrap();
    let full = fx.reconstruct(&ceiling).unwrap();
    assert_eq!(full.triggers().len(), 1);
    assert_eq!(full.records().len(), 2);
    assert_eq!(
        standing_of(&full, 3, "checker.example.org").standing,
        Standing::Extension { trigger_height: 2 }
    );
    let pinned =
        ExtensionHistory::reconstruct(fx.data.path(), Some(audited.clone()), &ceiling).unwrap();
    assert!(pinned.triggers().is_empty() && pinned.records().is_empty());
    assert_eq!(pinned.through().map(|row| row.block_number), Some(1));
    let through_trigger =
        ExtensionHistory::reconstruct(fx.data.path(), Some(trigger.clone()), &ceiling).unwrap();
    assert_eq!(through_trigger.triggers().len(), 1);
    assert!(through_trigger.triggers()[0].outcome.is_none());
    assert_eq!(through_trigger.named("checker.example.org", 2).len(), 1);
    assert!(ExtensionHistory::reconstruct(
        fx.data.path(),
        Some(BlockRow {
            block_hash: format!("sha256:{}", "0".repeat(64)),
            ..later.clone()
        }),
        &ceiling
    )
    .is_err());
    assert_eq!(full.anchor_hash(), through_trigger.anchor_hash());
}
