use clave::db::{BlockRow, Db};
use clave::history::coverage::{CoverageClock, CoverageProfile};
use clave::history::records::IncludedRecord;
use clave::history::History;
use serde_json::{json, Value};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::{block, envelope, jcs, merkle};

const START: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

struct Fixture {
    data: tempfile::TempDir,
    db: Db,
    sk: SigningKey,
}

fn ts(at: i64) -> String {
    jiff::Timestamp::from_second(at).unwrap().to_string()
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

impl Fixture {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example.test", data.path()).unwrap();
        let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        Self { data, db, sk }
    }

    fn path(&self, height: u64) -> std::path::PathBuf {
        self.data
            .path()
            .join(format!("log/blocks/{height:09}.json.zst"))
    }

    fn write(&self, height: u64, doc: &Value) {
        let bytes = jcs::canonicalize(doc).unwrap();
        std::fs::write(self.path(height), zstd::bulk::compress(&bytes, 3).unwrap()).unwrap();
    }

    fn append(&self, at: i64, entries: Vec<Value>) -> Value {
        self.append_at(&ts(at), entries)
    }

    fn append_at(&self, at: &str, entries: Vec<Value>) -> Value {
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
            "sealed_at": at, "entry_count": entries.len(),
            "merkle_root": format!("sha256:{}", hex_encode(&root)),
        });
        let signature = self.sk.sign(&jcs::canonicalize(&header).unwrap());
        let doc = json!({
            "header": header, "entries": entries,
            "sig": {"key_id":"log1", "alg":"Ed25519", "value": signature},
        });
        self.write(height, &doc);
        self.db
            .commit_seal(
                &[],
                height,
                &block::block_hash(&header).unwrap(),
                at,
                &[],
                &[],
                &[],
                &[],
                jcs::canonicalize(&doc).unwrap().len() as u64,
            )
            .unwrap();
        doc
    }

    fn history(&self) -> History {
        History::open(self.data.path(), self.db.last_block().unwrap()).unwrap()
    }

    fn parameter(&self, name: &str, value: i64, effective: i64) -> Value {
        self.parameter_at(name, value, &ts(effective))
    }

    fn parameter_at(&self, name: &str, value: i64, effective: &str) -> Value {
        let body = envelope::sign_envelope(
            &json!({
                "wist_version":"1.0.0", "action":"parameter_change", "subject":name,
                "details":{"parameter":name,"value":value}, "effective_at":effective,
            }),
            "update",
            "log1",
            &self.sk,
        )
        .unwrap();
        json!({"type":"registry_update", "body":body})
    }

    fn record(&self, auditor: &str, at: i64) -> Value {
        let body = envelope::sign_envelope(
            &json!({"auditor_id":auditor, "fetched_at":ts(at),
                "audited_delta":format!("sha256:{}", "a".repeat(64)),
                "verdict":"inconsistent", "similarity":10_000}),
            "record",
            "record1",
            &SigningKey::from_seed(&[17; 32]),
        )
        .unwrap();
        json!({"type":"audit_record", "body":body})
    }
}

#[test]
fn coverage_clocks_freeze_signed_vector_profiles() {
    let spec = std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        });
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(spec.join("vectors/wist4/parameter-combinations.json")).unwrap(),
    )
    .unwrap();
    let mut exercised = 0;
    for case in vectors["clock_cases"].as_array().unwrap() {
        if !matches!(
            case["label"].as_str().unwrap(),
            "coverage retains deadline"
                | "coverage retains seal count"
                | "effective at anchor is included"
        ) {
            continue;
        }
        exercised += 1;
        let f = Fixture::new();
        let base = START + 8 * DAY;
        let parameter = case["parameter"].as_str().unwrap();
        if parameter == "record_seal_blocks" {
            f.append(START, vec![f.parameter("confirm_window_hours", 96, base)]);
        }
        for change in case["changes"].as_array().unwrap() {
            f.append(
                START + 7200,
                vec![f.parameter(
                    change["parameter"].as_str().unwrap(),
                    change["value"].as_i64().unwrap(),
                    base + change["effective_at_s"].as_i64().unwrap() * 3600,
                )],
            );
        }
        let at = base + case["anchor_s"].as_i64().unwrap() * 3600;
        let doc = f.append(at, vec![]);
        let duty = block::block_hash(&doc["header"]).unwrap();
        let frozen =
            CoverageClock::reconstruct(f.data.path(), f.db.last_block().unwrap(), &duty).unwrap();
        f.append(base + case["query_s"].as_i64().unwrap() * 3600, vec![]);
        let reopened = Db::open(&f.data.path().join("clave.sqlite")).unwrap();
        let clock =
            CoverageClock::reconstruct(f.data.path(), reopened.last_block().unwrap(), &duty)
                .unwrap();
        let value = if parameter == "coverage_deadline_hours" {
            clock.profile().deadline_hours
        } else {
            clock.profile().seal_blocks
        };
        assert_eq!(
            value,
            case["selected_value"].as_u64().unwrap(),
            "{}",
            case["label"]
        );
        assert_eq!(clock.profile(), frozen.profile());
        assert_eq!(clock.deadline_s(), frozen.deadline_s());
        assert_eq!(
            clock.deadline_s(),
            i128::from(at) + i128::from(clock.profile().deadline_hours) * 3600
        );
        assert_eq!(clock.anchor_hash(), frozen.anchor_hash());
        assert_eq!(clock.duty_block().block_hash, duty);
        assert_eq!(
            clock.through().block_hash,
            reopened.last_block().unwrap().unwrap().block_hash
        );
        assert_eq!(clock.unattested_height(), None);
        let mut history = f.history();
        while let Some(block) = history.next_block().unwrap() {
            assert!(block.rejected_parameters().is_empty(), "{}", case["label"]);
            if block.hash() == duty {
                assert_eq!(block.coverage_profile(), clock.profile());
            }
        }
    }
    assert_eq!(exercised, 3);
}

#[test]
fn coverage_unattested_height_matches_signed_history_vectors() {
    let spec = std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        });
    let vectors: Value =
        serde_json::from_slice(&std::fs::read(spec.join("vectors/wist4/coverage.json")).unwrap())
            .unwrap();
    let mut exercised = 0;
    for case in vectors["establishing_cases"].as_array().unwrap() {
        if !case["attestation_height"].is_null() {
            continue;
        }
        exercised += 1;
        let f = Fixture::new();
        let base = START + 8 * DAY;
        let seal_blocks = case["record_seal_blocks"].as_u64().unwrap();
        f.append(
            START,
            vec![f.parameter("record_seal_blocks", seal_blocks as i64, base)],
        );
        let anchor_height = case["audited_block"]["height"].as_u64().unwrap();
        let last_height = case["blocks"].as_array().unwrap().last().unwrap()["height"]
            .as_u64()
            .unwrap();
        let mut duty = String::new();
        for height in 1..=last_height {
            let doc = f.append(base + height as i64 * 3600, vec![]);
            if height == anchor_height {
                duty = block::block_hash(&doc["header"]).unwrap();
            }
        }
        let clock =
            CoverageClock::reconstruct(f.data.path(), f.db.last_block().unwrap(), &duty).unwrap();
        assert_eq!(
            clock.unattested_height(),
            case["establishing_height"].as_u64(),
            "{}",
            case["label"]
        );
        assert_eq!(
            clock.deadline_s(),
            i128::from(base + case["coverage_deadline_s"].as_i64().unwrap())
        );
        assert_eq!(
            clock.profile(),
            &CoverageProfile {
                deadline_hours: case["coverage_deadline_hours"].as_u64().unwrap(),
                seal_blocks,
            }
        );
        for probe in case["counts_at"].as_array().unwrap() {
            let height = probe["height"].as_u64().unwrap();
            let raw = std::fs::read(f.path(height)).unwrap();
            let doc: Value = serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
            let head = BlockRow {
                block_number: height,
                block_hash: block::block_hash(&doc["header"]).unwrap(),
                sealed_at: doc["header"]["sealed_at"].as_str().unwrap().into(),
            };
            let prefix = CoverageClock::reconstruct(f.data.path(), Some(head), &duty).unwrap();
            assert_eq!(
                prefix.unattested_height().is_some(),
                probe["counts"].as_bool().unwrap()
            );
        }
    }
    assert_eq!(exercised, 2);
}

#[test]
fn coverage_clocks_count_actual_blocks_through_cadence_changes_and_later_reductions() {
    let f = Fixture::new();
    let effective = START + 8 * DAY;
    f.append(START, vec![f.parameter("record_seal_blocks", 4, effective)]);
    f.append(
        START + 3600,
        vec![f.parameter("confirm_window_hours", 48, effective + 3600)],
    );
    f.append(
        START + 7200,
        sorted(vec![
            f.parameter("record_seal_blocks", 2, effective + 3600),
            f.parameter("coverage_deadline_hours", 48, effective + 3600),
        ]),
    );
    f.append(
        START + 10800,
        vec![f.parameter("block_cadence_seconds", 1800, effective + 3600)],
    );
    let mut duties = Vec::new();
    for at in [
        effective - 3600,
        effective,
        effective + 3600,
        effective + 5400,
    ] {
        let doc = f.append(at, vec![]);
        duties.push(block::block_hash(&doc["header"]).unwrap());
    }
    let deadline = effective + 72 * 3600;
    f.append(deadline, vec![]);
    let exact = f.db.last_block().unwrap().unwrap().block_number;
    for (offset, expected) in [
        (1800, None),
        (7200, None),
        (9000, None),
        (14400, Some(exact + 4)),
    ] {
        f.append(deadline + offset, vec![]);
        let clock =
            CoverageClock::reconstruct(f.data.path(), f.db.last_block().unwrap(), &duties[1])
                .unwrap();
        assert_eq!(clock.deadline_s(), i128::from(deadline));
        assert_eq!(clock.profile().seal_blocks, 4);
        assert_eq!(clock.unattested_height(), expected);
    }
    for (duty, profile) in duties.iter().zip([
        CoverageProfile {
            deadline_hours: 72,
            seal_blocks: 24,
        },
        CoverageProfile {
            deadline_hours: 72,
            seal_blocks: 4,
        },
        CoverageProfile {
            deadline_hours: 48,
            seal_blocks: 2,
        },
        CoverageProfile {
            deadline_hours: 48,
            seal_blocks: 2,
        },
    ]) {
        let clock =
            CoverageClock::reconstruct(f.data.path(), f.db.last_block().unwrap(), duty).unwrap();
        assert_eq!(*clock.profile(), profile);
    }
    let mut history = f.history();
    while let Some(block) = history.next_block().unwrap() {
        assert!(block.rejected_parameters().is_empty());
    }
}

#[test]
fn coverage_clocks_reject_invalid_prefixes_and_retry_repaired_files() {
    let f = Fixture::new();
    assert!(CoverageClock::reconstruct(f.data.path(), None, "absent").is_err());
    let duty = f.append(START, vec![]);
    let duty = block::block_hash(&duty["header"]).unwrap();
    f.append(START + 72 * 3600, vec![]);
    for hour in 73..=97 {
        f.append(START + hour * 3600, vec![]);
    }
    let head = f.db.last_block().unwrap();
    let clock = CoverageClock::reconstruct(f.data.path(), head.clone(), &duty).unwrap();
    assert_eq!(clock.unattested_height(), Some(25));
    assert!(CoverageClock::reconstruct(f.data.path(), head.clone(), "absent").is_err());
    for height in [0, 12, 26] {
        let path = f.path(height);
        let raw = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(CoverageClock::reconstruct(f.data.path(), head.clone(), &duty).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(CoverageClock::reconstruct(f.data.path(), head.clone(), &duty).is_err());
        std::fs::write(&path, raw).unwrap();
        let reopened = Db::open(&f.data.path().join("clave.sqlite")).unwrap();
        let replayed =
            CoverageClock::reconstruct(f.data.path(), reopened.last_block().unwrap(), &duty)
                .unwrap();
        assert_eq!(replayed.unattested_height(), clock.unattested_height());
        assert_eq!(replayed.deadline_s(), clock.deadline_s());
    }
}

#[test]
fn rejected_amendments_cannot_supply_coverage_clocks() {
    for (parameter, value) in [("coverage_deadline_hours", 96), ("record_seal_blocks", 4)] {
        for rejection in ["signature", "value", "grace"] {
            let f = Fixture::new();
            let effective = START + 8 * DAY;
            let change = match rejection {
                "signature" => {
                    let mut change = f.parameter(parameter, value, effective);
                    change["body"]["sig"]["value"] = json!("invalid");
                    change
                }
                "value" => f.parameter(parameter, 0, effective),
                "grace" => f.parameter(parameter, value, START + DAY),
                _ => unreachable!(),
            };
            f.append(START, vec![change]);
            let doc = f.append(effective, vec![]);
            let duty = block::block_hash(&doc["header"]).unwrap();
            let clock =
                CoverageClock::reconstruct(f.data.path(), f.db.last_block().unwrap(), &duty)
                    .unwrap();
            assert_eq!(
                *clock.profile(),
                CoverageProfile {
                    deadline_hours: 72,
                    seal_blocks: 24
                }
            );
            assert_eq!(
                f.history()
                    .next_block()
                    .unwrap()
                    .unwrap()
                    .rejected_parameters(),
                &[0]
            );
        }
    }
}

#[test]
fn included_records_bind_confirmation_clock_vectors_to_signed_history() {
    let spec = std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        });
    let vectors: Value = serde_json::from_slice(
        &std::fs::read(spec.join("vectors/wist4/parameter-combinations.json")).unwrap(),
    )
    .unwrap();
    for case in vectors["confirmation_clock_cases"].as_array().unwrap() {
        let f = Fixture::new();
        let base = START + 8 * DAY;
        f.append(START, vec![f.parameter("record_seal_blocks", 1, base)]);
        let mut changes = Vec::new();
        for change in case["changes"].as_array().unwrap() {
            changes.push(f.parameter(
                change["parameter"].as_str().unwrap(),
                change["value"].as_i64().unwrap(),
                base + change["effective_at_s"].as_i64().unwrap(),
            ));
        }
        f.append(START + 3600, sorted(changes));
        let mut expected = Vec::new();
        for (index, at) in case["record_times_s"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let at = base + at.as_i64().unwrap();
            let entry = f.record(&format!("audit.site{index}.test"), at);
            let doc = f.append(at, vec![entry.clone()]);
            expected.push((
                entry["body"].clone(),
                block::block_hash(&doc["header"]).unwrap(),
            ));
        }
        let head = f.db.last_block().unwrap();
        let records = IncludedRecord::reconstruct_all(f.data.path(), head.clone()).unwrap();
        assert_eq!(records.len(), expected.len());
        let mut candidates = Vec::new();
        let mut confirming = None;
        for (index, source) in records.iter().enumerate() {
            assert_eq!(source.envelope(), &expected[index].0);
            assert_eq!(source.block_hash(), expected[index].1);
            assert_eq!(source.position().block_number, index as u64 + 2);
            assert_eq!(source.position().entry_index, 0);
            let relative = source.sealed_at_s() - base;
            let expected_parameter = |name: &str, default| {
                case["changes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|change| {
                        change["parameter"] == name
                            && change["effective_at_s"].as_i64().unwrap() <= relative
                    })
                    .map_or(default, |change| change["value"].as_u64().unwrap())
            };
            let profile = source.confirmation_profile();
            assert_eq!(profile.auditors, expected_parameter("confirm_auditors", 2));
            assert_eq!(
                profile.window_hours,
                expected_parameter("confirm_window_hours", 72)
            );
            candidates.push(wist_core::confirmation::CandidateRecord {
                block_height: source.position().block_number,
                entry_index: source.position().entry_index as u64,
                block_sealed_at_s: source.sealed_at_s(),
                auditor_id: source.envelope()["record"]["auditor_id"].as_str().unwrap(),
                effective_similarity: 10_000,
            });
            if confirming.is_none()
                && wist_core::confirmation::confirming_index_with_quorum(
                    &candidates,
                    profile.window_hours,
                    profile.auditors,
                )
                .unwrap()
                    == Some(index)
            {
                confirming = Some(index);
            }
        }
        assert_eq!(
            confirming,
            case["confirming_index"].as_u64().map(|i| i as usize),
            "{}",
            case["label"]
        );
        let mut history = f.history();
        while let Some(block) = history.next_block().unwrap() {
            assert!(block.rejected_parameters().is_empty(), "{}", case["label"]);
        }
        f.db.set_param("confirm_auditors", 99).unwrap();
        drop(f.db);
        let reopened = Db::open(&f.data.path().join("clave.sqlite")).unwrap();
        let replayed =
            IncludedRecord::reconstruct_all(f.data.path(), reopened.last_block().unwrap()).unwrap();
        for (source, replayed) in records.iter().zip(replayed) {
            assert_eq!(source.envelope(), replayed.envelope());
            assert_eq!(
                source.confirmation_profile(),
                replayed.confirmation_profile()
            );
            assert_eq!(source.block_hash(), replayed.block_hash());
        }
    }
}

#[test]
fn included_records_preserve_entries_without_claiming_authorship_or_eligibility() {
    let f = Fixture::new();
    let mut forged = f.record("audit.example.test", START);
    forged["body"]["sig"]["value"] = json!("invalid");
    let malformed = json!({"type":"audit_record", "body":{"unparsed":true}});
    let declaration = json!({"type":"publisher_declaration", "body":{"unparsed":true}});
    let doc = f.append(START, sorted(vec![forged, malformed, declaration]));
    let pinned = f.db.last_block().unwrap();
    let expected: Vec<_> = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry["type"] == "audit_record")
        .collect();
    let records = IncludedRecord::reconstruct_all(f.data.path(), pinned.clone()).unwrap();
    assert_eq!(records.len(), 2);
    for (record, (index, entry)) in records.iter().zip(expected) {
        assert_eq!(record.position().entry_index, index);
        assert_eq!(record.envelope(), &entry["body"]);
    }
    f.append(
        START + 3600,
        vec![f.record("later.example.test", START + 3600)],
    );
    assert_eq!(
        IncludedRecord::reconstruct_all(f.data.path(), pinned)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        IncludedRecord::reconstruct_all(f.data.path(), f.db.last_block().unwrap())
            .unwrap()
            .len(),
        3
    );
    assert!(IncludedRecord::reconstruct_all(f.data.path(), None)
        .unwrap()
        .is_empty());
}

#[test]
fn confirmation_profiles_freeze_activation_boundaries_and_later_reductions() {
    let f = Fixture::new();
    let first = START + 7 * DAY;
    let second = START + 14 * DAY;
    f.append(
        START,
        sorted(vec![
            f.parameter("confirm_auditors", 4, first),
            f.parameter("confirm_window_hours", 48, first),
        ]),
    );
    for at in [first - 3600, first, first + 3600] {
        f.append(at, vec![f.record("audit.example.test", at)]);
    }
    f.append(
        first + 7200,
        sorted(vec![
            f.parameter("confirm_auditors", 2, second + 7200),
            f.parameter("confirm_window_hours", 72, second + 7200),
        ]),
    );
    for at in [second + 3600, second + 7200, second + 10800] {
        f.append(at, vec![f.record("audit.example.test", at)]);
    }
    let expected = [(2, 72), (4, 48), (4, 48), (4, 48), (2, 72), (2, 72)];
    let records =
        IncludedRecord::reconstruct_all(f.data.path(), f.db.last_block().unwrap()).unwrap();
    assert_eq!(records.len(), expected.len());
    for (source, (auditors, window_hours)) in records.iter().zip(expected) {
        assert_eq!(source.confirmation_profile().auditors, auditors);
        assert_eq!(source.confirmation_profile().window_hours, window_hours);
    }
    let mut history = f.history();
    while let Some(block) = history.next_block().unwrap() {
        assert!(block.rejected_parameters().is_empty());
    }
}

#[test]
fn rejected_amendments_supply_no_record_confirmation_profile() {
    for parameter in ["confirm_auditors", "confirm_window_hours"] {
        for rejection in ["signature", "value", "grace"] {
            let f = Fixture::new();
            let effective = START + 7 * DAY;
            let mut change = f.parameter(
                parameter,
                if parameter == "confirm_auditors" {
                    3
                } else {
                    48
                },
                effective,
            );
            match rejection {
                "signature" => change["body"]["sig"]["value"] = json!("invalid"),
                "value" => change = f.parameter(parameter, 0, effective),
                "grace" => {
                    change = f.parameter(
                        parameter,
                        if parameter == "confirm_auditors" {
                            3
                        } else {
                            48
                        },
                        START + DAY,
                    )
                }
                _ => unreachable!(),
            }
            f.append(START, vec![change]);
            f.append(effective, vec![f.record("audit.example.test", effective)]);
            let mut history = f.history();
            assert_eq!(
                history.next_block().unwrap().unwrap().rejected_parameters(),
                &[0]
            );
            let block = history.next_block().unwrap().unwrap();
            let records =
                IncludedRecord::reconstruct_all(f.data.path(), f.db.last_block().unwrap()).unwrap();
            assert_eq!(
                records[0].confirmation_profile(),
                block.confirmation_profile()
            );
            assert_eq!(records[0].confirmation_profile().auditors, 2);
            assert_eq!(records[0].confirmation_profile().window_hours, 72);
        }
    }
}

#[test]
fn included_record_reconstruction_requires_the_complete_pinned_prefix_and_can_retry() {
    let f = Fixture::new();
    f.append(START, vec![f.record("audit.example.test", START)]);
    f.append(START + 3600, vec![]);
    let final_block = f.append(START + 7200, vec![]);
    let head = f.db.last_block().unwrap();
    let retained = std::fs::read(f.path(2)).unwrap();
    std::fs::remove_file(f.path(2)).unwrap();
    assert!(IncludedRecord::reconstruct_all(f.data.path(), head.clone()).is_err());
    let mut corrupt = final_block.clone();
    corrupt["sig"]["value"] = json!("invalid");
    f.write(2, &corrupt);
    assert!(IncludedRecord::reconstruct_all(f.data.path(), head.clone()).is_err());
    std::fs::write(f.path(2), retained).unwrap();
    let records = IncludedRecord::reconstruct_all(f.data.path(), head.clone()).unwrap();
    assert_eq!(records.len(), 1);
    let mut wrong_head = head.unwrap();
    wrong_head.block_hash = format!("sha256:{}", "0".repeat(64));
    assert!(IncludedRecord::reconstruct_all(f.data.path(), Some(wrong_head)).is_err());
}

#[test]
fn real_seals_replay_complete_envelopes_and_positions_after_reopen() {
    let f = Fixture::new();
    let mut expected = Vec::new();
    for (kind, inner) in [
        ("publisher_declaration", "publisher"),
        ("registry_update", "update"),
        ("audit_record", "record"),
    ] {
        let object = if inner == "publisher" {
            json!({"wist_version":"1.0.0", "domain":"example.com", "seq":0,
                "keys":[{"key_id":"log1", "alg":"Ed25519", "public_key":f.sk.public().to_b64u(), "valid_from":"2026-08-01T00:00:00Z"}]})
        } else {
            json!({"preserved":"complete signed content"})
        };
        let body = envelope::sign_envelope(&object, inner, "log1", &f.sk).unwrap();
        f.db.insert_pending_entry(kind, "", &body, 0).unwrap();
        expected.push(json!({"type":kind,"body":body}));
    }
    clave::seal::run(&f.db, f.data.path(), &f.sk, START).unwrap();
    clave::seal::run(&f.db, f.data.path(), &f.sk, START + 3600).unwrap();
    let path = f.data.path().join("clave.sqlite");
    drop(f.db);
    let db = Db::open(&path).unwrap();
    let mut reader = History::open(f.data.path(), db.last_block().unwrap()).unwrap();
    let first = reader.next_block().unwrap().unwrap();
    assert_eq!(first.block().header.block_number, 0);
    assert_eq!(first.block().entries, sorted(expected));
    let second = reader.next_block().unwrap().unwrap();
    assert!(second.block().entries.is_empty());
    assert_eq!(second.block().header.prev_block_hash, first.hash());
    assert_eq!(second.sealed_at_s(), START + 3600);
    assert!(reader.next_block().unwrap().is_none());
}

#[test]
fn parameters_come_from_signed_envelopes_not_database_summaries_or_overrides() {
    let f = Fixture::new();
    let valid = f.parameter("confirm_auditors", 3, START + 7 * DAY);
    let mut forged = f.parameter("confirm_window_hours", 48, START + 7 * DAY);
    forged["body"]["update"]["details"]["value"] = json!(36);
    let invalid = f.parameter("confirm_auditors", 1, START + 7 * DAY);
    let entries = sorted(vec![valid.clone(), forged.clone(), invalid.clone()]);
    f.append(START, entries.clone());
    f.append(START + 7 * DAY, vec![]);
    f.db.set_param("confirm_auditors", 99).unwrap();
    assert!(f
        .db
        .parameter_schedule(START)
        .unwrap()
        .accepted()
        .is_empty());
    let mut history = f.history();
    let first = history.next_block().unwrap().unwrap();
    let rejected: Vec<_> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| **e == forged || **e == invalid)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(first.rejected_parameters(), rejected);
    let schedule = history.schedule().unwrap();
    assert_eq!(schedule.accepted().len(), 1);
    assert_eq!(
        schedule.accepted()[0].entry_index as usize,
        entries.iter().position(|e| *e == valid).unwrap()
    );
    assert_eq!(schedule.value_at("confirm_auditors", START), Some(2));
    history.next_block().unwrap().unwrap();
    assert_eq!(
        history
            .schedule()
            .unwrap()
            .value_at("confirm_auditors", START + 7 * DAY),
        Some(3)
    );
}

#[test]
fn extra_frames_fail_history_and_legacy_restoration_without_rewriting_files() {
    for suffix in [
        zstd::bulk::compress(b"", 3).unwrap(),
        zstd::bulk::compress(b"x", 3).unwrap(),
        vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
        vec![0],
    ] {
        let f = Fixture::new();
        f.append(START, vec![]);
        let mut raw = std::fs::read(f.path(0)).unwrap();
        raw.extend(suffix);
        std::fs::write(f.path(0), &raw).unwrap();
        let mut history = f.history();
        assert!(history
            .next_block()
            .unwrap_err()
            .to_string()
            .contains("WIST3-E03"));
        assert!(history.schedule().is_none());
        let path = f.data.path().join("clave.sqlite");
        drop(f.db);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE blocks SET decompressed_bytes = NULL", [])
            .unwrap();
        drop(conn);
        let error = match Db::open(&path) {
            Ok(_) => panic!("restoration accepted extra frame data"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("WIST3-E03"));
        let conn = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row("SELECT decompressed_bytes FROM blocks", [], |r| r
                .get::<_, Option<u64>>(0))
                .unwrap(),
            None
        );
        assert_eq!(
            std::fs::read(f.data.path().join("log/blocks/000000000.json.zst")).unwrap(),
            raw
        );
    }
}

#[test]
fn signed_leap_second_blocks_are_rejected_without_normalization() {
    let f = Fixture::new();
    let at = 1_483_225_200;
    let mut doc = f.append(at, vec![]);
    doc["header"]["sealed_at"] = json!("2016-12-31T23:59:60Z");
    doc["sig"]["value"] = json!(f.sk.sign(&jcs::canonicalize(&doc["header"]).unwrap()));
    f.write(0, &doc);
    let mut history = History::open(
        f.data.path(),
        Some(BlockRow {
            block_number: 0,
            block_hash: block::block_hash(&doc["header"]).unwrap(),
            sealed_at: "2016-12-31T23:59:60Z".into(),
        }),
    )
    .unwrap();
    let error = history.next_block().unwrap_err().to_string();
    assert!(error.contains("WIST3-E03"));
    assert!(error.contains("timestamp must be whole-second UTC"));
    assert!(history.schedule().is_none());
}

#[test]
fn signed_history_reaches_the_last_gregorian_second_after_reopen() {
    let f = Fixture::new();
    let lifetime = f.parameter_at("canary_lifetime_blocks", 1_000_000, "9999-12-08T00:00:00Z");
    f.append_at("9999-12-01T00:00:00Z", vec![lifetime.clone()]);
    let reveal = f.parameter_at("canary_reveal_min_blocks", 300_000, "9999-12-08T01:00:00Z");
    f.append_at("9999-12-01T01:00:00Z", vec![reveal.clone()]);
    let amendment = f.parameter_at("block_cadence_seconds", 1, "9999-12-30T23:00:00Z");
    f.append_at("9999-12-23T00:00:00Z", vec![amendment.clone()]);
    let cases = [
        ("9999-12-30T21:00:00Z", 253_402_203_600),
        ("9999-12-30T22:00:00Z", 253_402_207_200),
        ("9999-12-30T23:00:00Z", 253_402_210_800),
        ("9999-12-30T23:00:01Z", 253_402_210_801),
        ("9999-12-31T23:59:59Z", 253_402_300_799),
    ];
    for (at, _) in cases {
        f.append_at(at, vec![]);
    }
    let path = f.data.path().join("clave.sqlite");
    drop(f.db);
    let db = Db::open(&path).unwrap();
    let mut history = History::open(f.data.path(), db.last_block().unwrap()).unwrap();
    for expected in [lifetime, reveal, amendment] {
        let verified = history.next_block().unwrap().unwrap();
        assert_eq!(verified.block().entries, [expected]);
        assert!(verified.rejected_parameters().is_empty());
    }
    assert_eq!(history.schedule().unwrap().accepted().len(), 3);
    assert_eq!(
        history
            .schedule()
            .unwrap()
            .value_at("block_cadence_seconds", 253_402_210_799),
        Some(3600)
    );
    assert_eq!(
        history
            .schedule()
            .unwrap()
            .value_at("block_cadence_seconds", 253_402_210_800),
        Some(1)
    );
    for (at, seconds) in cases {
        let verified = history.next_block().unwrap().unwrap();
        assert_eq!(verified.block().header.sealed_at, at);
        assert_eq!(verified.sealed_at_s(), seconds);
    }
    assert!(history.next_block().unwrap().is_none());
}

#[test]
fn signed_calendar_boundaries_preserve_timestamp_and_cadence_rejections() {
    for (at, expected) in [
        ("0000-01-01T00:00:00Z", Ok(-62_167_219_200)),
        ("0000-02-29T00:00:00Z", Ok(-62_162_121_600)),
        ("9999-12-31T23:00:00Z", Ok(253_402_297_200)),
        ("9999-12-31T23:59:59Z", Err("cadence grid")),
        (
            "9999-12-31T23:59:60Z",
            Err("timestamp must be whole-second UTC"),
        ),
        (
            "10000-01-01T00:00:00Z",
            Err("timestamp must be whole-second UTC"),
        ),
        ("9999-02-29T00:00:00Z", Err("WIST3-E03")),
    ] {
        let f = Fixture::new();
        f.append_at(at, vec![]);
        let mut history = f.history();
        match expected {
            Ok(seconds) => {
                let verified = history.next_block().unwrap().unwrap();
                assert_eq!(verified.sealed_at_s(), seconds, "{at}");
                assert!(history.next_block().unwrap().is_none());
            }
            Err(message) => {
                let error = history.next_block().unwrap_err().to_string();
                assert!(error.contains(message), "{at}: {error}");
                assert!(history.schedule().is_none());
                assert!(history.next_block().is_err());
            }
        }
    }
}

#[test]
fn missing_middle_block_cannot_be_skipped_or_resumed() {
    let f = Fixture::new();
    for h in 0..3 {
        f.append(START + h * 3600, vec![]);
    }
    std::fs::remove_file(f.path(1)).unwrap();
    let mut history = f.history();
    history.next_block().unwrap().unwrap();
    assert!(history.next_block().is_err());
    assert!(history
        .next_block()
        .unwrap_err()
        .to_string()
        .contains("cannot continue"));
}

#[test]
fn forged_block_header_and_entry_bytes_are_rejected() {
    for header in [false, true] {
        let f = Fixture::new();
        let mut doc = f.append(START, vec![]);
        if header {
            doc["sig"]["value"] =
                json!(SigningKey::from_seed(&[9; 32])
                    .sign(&jcs::canonicalize(&doc["header"]).unwrap()));
        } else {
            doc["entries"] = json!([{"type":"audit_record", "body":{}}]);
        }
        f.write(0, &doc);
        assert!(f.history().next_block().is_err());
    }
}

#[test]
fn authenticated_noncanonical_order_and_unknown_types_are_rejected() {
    for entries in [
        vec![json!({"type":"unknown", "body":{}})],
        vec![
            json!({"type":"audit_record", "body":{}}),
            json!({"type":"publisher_declaration", "body":{}}),
        ],
        {
            let mut entries = sorted(vec![
                json!({"type":"audit_record", "body":{"a":1}}),
                json!({"type":"audit_record", "body":{"a":2}}),
            ]);
            entries.reverse();
            entries
        },
    ] {
        let f = Fixture::new();
        f.append(START, entries);
        assert!(f.history().next_block().is_err());
    }
}

#[test]
fn whitespace_and_duplicate_json_members_do_not_authenticate_as_file_bytes() {
    for duplicate in [false, true] {
        let f = Fixture::new();
        let doc = f.append(START, vec![]);
        let mut bytes = jcs::canonicalize(&doc).unwrap();
        if duplicate {
            bytes.splice(1..1, b"\"entries\":[],".iter().copied());
        } else {
            bytes.push(b'\n');
        }
        std::fs::write(f.path(0), zstd::bulk::compress(&bytes, 3).unwrap()).unwrap();
        assert!(f.history().next_block().is_err());
    }
}

#[test]
fn verified_prefix_bounds_reject_a_frame_before_decompression() {
    let f = Fixture::new();
    f.append(
        START,
        vec![f.parameter("block_decompressed_cap_bytes", 4096, START + 7 * DAY)],
    );
    f.append(START + 7 * DAY, vec![]);
    f.append(START + 7 * DAY + 3600, vec![]);
    let mut history = f.history();
    history.next_block().unwrap().unwrap();
    history.next_block().unwrap().unwrap();
    assert_eq!(
        history
            .schedule()
            .unwrap()
            .block_size_bounds(START + 7 * DAY)
            .1,
        4096
    );
    let raw = zstd::bulk::compress(&vec![b'x'; 4097], 3).unwrap();
    std::fs::write(f.path(2), &raw[..18.min(raw.len())]).unwrap();
    assert!(history
        .next_block()
        .unwrap_err()
        .to_string()
        .contains("excessive Block frame size"));
}

#[test]
fn missing_frame_size_and_corrupt_compression_are_rejected() {
    use std::io::Write;
    for missing_size in [false, true] {
        let f = Fixture::new();
        let doc = f.append(START, vec![]);
        let mut raw = if missing_size {
            let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
            encoder.include_contentsize(false).unwrap();
            encoder
                .write_all(&jcs::canonicalize(&doc).unwrap())
                .unwrap();
            encoder.finish().unwrap()
        } else {
            std::fs::read(f.path(0)).unwrap()
        };
        if !missing_size {
            raw.truncate(raw.len() - 1);
        }
        std::fs::write(f.path(0), raw).unwrap();
        assert!(f.history().next_block().is_err());
    }
}

#[test]
fn head_is_pinned_and_later_seals_are_excluded() {
    let f = Fixture::new();
    f.append(START, vec![]);
    let mut history = f.history();
    f.append(START + 3600, vec![]);
    history.next_block().unwrap().unwrap();
    assert!(history.next_block().unwrap().is_none());
    let mut head = f.db.last_block().unwrap().unwrap();
    head.block_hash = format!("sha256:{}", "0".repeat(64));
    let mut history = History::open(f.data.path(), Some(head)).unwrap();
    history.next_block().unwrap().unwrap();
    assert!(history.next_block().is_err());
}

#[test]
fn substituted_chain_and_nonmonotonic_timestamps_are_rejected() {
    for broken_chain in [false, true] {
        let f = Fixture::new();
        f.append(START, vec![]);
        let mut doc = f.append(if broken_chain { START + 3600 } else { START }, vec![]);
        let head = if broken_chain {
            doc["header"]["prev_block_hash"] = json!(format!("sha256:{}", "0".repeat(64)));
            doc["sig"]["value"] = json!(f.sk.sign(&jcs::canonicalize(&doc["header"]).unwrap()));
            f.write(1, &doc);
            Some(BlockRow {
                block_number: 1,
                block_hash: block::block_hash(&doc["header"]).unwrap(),
                sealed_at: ts(START + 3600),
            })
        } else {
            f.db.last_block().unwrap()
        };
        let mut history = History::open(f.data.path(), head).unwrap();
        history.next_block().unwrap().unwrap();
        assert!(history.next_block().is_err());
    }
}

#[test]
fn unsupported_log_key_transitions_stop_before_exposing_entries() {
    let f = Fixture::new();
    f.append(
        START,
        vec![
            json!({"type":"registry_update", "body":{"update":{"action":"aggregator_key_remove"}}}),
        ],
    );
    let mut history = f.history();
    assert!(history
        .next_block()
        .unwrap_err()
        .to_string()
        .contains("key transitions"));
    assert!(history.schedule().is_none());
}

#[test]
fn anchor_signature_key_identity_is_checked_without_the_private_key() {
    let f = Fixture::new();
    f.append(START, vec![]);
    std::fs::remove_file(f.data.path().join("keys/seed")).unwrap();
    f.history().next_block().unwrap().unwrap();
    let path = f.data.path().join("anchor.json");
    let mut doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    doc["sig"]["key_id"] = json!("wrong");
    std::fs::write(path, serde_json::to_vec(&doc).unwrap()).unwrap();
    assert!(History::open(f.data.path(), f.db.last_block().unwrap()).is_err());
}

#[test]
fn correctly_signed_malformed_parameter_envelopes_are_ignored() {
    for mutation in 0..8 {
        let f = Fixture::new();
        let mut entry = f.parameter("confirm_auditors", 3, START + 7 * DAY);
        let mut update = entry["body"]["update"].clone();
        match mutation {
            0 => {
                update.as_object_mut().unwrap().remove("subject");
            }
            1 => {
                update.as_object_mut().unwrap().remove("wist_version");
            }
            2 => {
                update["wist_version"] = json!("2.0.0");
            }
            3 => {
                update["extra"] = json!(true);
            }
            4 => {
                update["subject"] = json!("x".repeat(257));
            }
            5 => {
                update["evidence"] = json!(["x".repeat(257)]);
            }
            6 => {
                update["details"]["value"] = Value::Null;
            }
            _ => {}
        }
        entry["body"] = envelope::sign_envelope(&update, "update", "log1", &f.sk).unwrap();
        if mutation == 7 {
            entry["body"]["extra"] = json!(true);
        }
        f.append(START, vec![entry]);
        let mut history = f.history();
        assert_eq!(
            history.next_block().unwrap().unwrap().rejected_parameters(),
            [0]
        );
        assert!(history.schedule().unwrap().accepted().is_empty());
    }
}

#[test]
fn foreign_parameter_signer_does_not_gain_authority_from_block_inclusion() {
    let f = Fixture::new();
    let mut entry = f.parameter("confirm_auditors", 3, START + 7 * DAY);
    entry["body"] = envelope::sign_envelope(
        &entry["body"]["update"],
        "update",
        "log1",
        &SigningKey::from_seed(&[11; 32]),
    )
    .unwrap();
    f.append(START, vec![entry]);
    let mut history = f.history();
    assert_eq!(
        history.next_block().unwrap().unwrap().rejected_parameters(),
        [0]
    );
    assert!(history.schedule().unwrap().accepted().is_empty());
}

#[test]
fn canonical_positions_determine_equal_effective_parameter_precedence() {
    let f = Fixture::new();
    let entries = sorted(vec![
        f.parameter("confirm_auditors", 3, START + 7 * DAY),
        f.parameter("confirm_auditors", 4, START + 7 * DAY),
    ]);
    let expected = entries[1]["body"]["update"]["details"]["value"]
        .as_i64()
        .unwrap();
    f.append(START, entries);
    let mut history = f.history();
    assert!(history
        .next_block()
        .unwrap()
        .unwrap()
        .rejected_parameters()
        .is_empty());
    assert_eq!(
        history
            .schedule()
            .unwrap()
            .value_at("confirm_auditors", START + 7 * DAY),
        Some(expected)
    );
}

#[test]
fn pending_reduction_constrains_blocks_before_it_becomes_current() {
    let f = Fixture::new();
    f.append(
        START,
        vec![f.parameter("block_decompressed_cap_bytes", 4096, START + 7 * DAY)],
    );
    f.append(
        START + 3600,
        vec![json!({"type":"audit_record", "body":{"data":"x".repeat(4096)}})],
    );
    let mut history = f.history();
    history.next_block().unwrap().unwrap();
    let before = history.schedule().unwrap().accepted().to_vec();
    assert!(history
        .next_block()
        .unwrap_err()
        .to_string()
        .contains("accepted size schedule"));
    assert_eq!(history.schedule().unwrap().accepted(), before);
}

#[test]
fn accepted_future_increase_raises_transport_bound_but_waits_for_activation() {
    for at in [START + 8 * DAY, START + 14 * DAY] {
        let f = Fixture::new();
        f.append(
            START,
            vec![f.parameter("block_decompressed_cap_bytes", 4096, START + 7 * DAY)],
        );
        f.append(
            START + 7 * DAY,
            vec![f.parameter("block_decompressed_cap_bytes", 8192, START + 14 * DAY)],
        );
        f.append(
            at,
            vec![json!({"type":"audit_record", "body":{"data":"x".repeat(4096)}})],
        );
        let mut history = f.history();
        history.next_block().unwrap().unwrap();
        history.next_block().unwrap().unwrap();
        assert_eq!(
            history
                .schedule()
                .unwrap()
                .block_size_bounds(START + 7 * DAY),
            (4096, 8192)
        );
        let result = history.next_block();
        if at == START + 14 * DAY {
            assert!(result.unwrap().unwrap().decompressed_bytes() > 4096);
        } else {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("accepted size schedule"));
        }
    }
}

#[test]
fn cli_authenticates_history_without_requiring_a_signing_key() {
    let f = Fixture::new();
    f.append(START, vec![]);
    std::fs::remove_file(f.data.path().join("keys/seed")).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clave"))
        .arg("verify-history")
        .arg("--data")
        .arg(f.data.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("authenticated 1 Blocks"));
    std::fs::remove_file(f.path(0)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_clave"))
        .arg("verify-history")
        .arg("--data")
        .arg(f.data.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn duplicate_decoded_members_in_signed_headers_and_entries_reject_before_replay() {
    for (name, escaped) in [
        ("sealed_at", "sealed_\\u0061t"),
        ("key_id", "key_id"),
        ("action", "\\u0061ction"),
    ] {
        let f = Fixture::new();
        let doc = f.append(
            START,
            vec![f.parameter("block_decompressed_cap_bytes", 4096, START + 7 * DAY)],
        );
        let raw = String::from_utf8(jcs::canonicalize(&doc).unwrap()).unwrap();
        let changed = raw.replacen(
            &format!("\"{name}\":"),
            &format!("\"{name}\":null,\"{escaped}\":"),
            1,
        );
        assert_ne!(changed, raw);
        assert_eq!(serde_json::from_str::<Value>(&changed).unwrap(), doc);
        std::fs::write(
            f.path(0),
            zstd::bulk::compress(changed.as_bytes(), 3).unwrap(),
        )
        .unwrap();
        let mut history = f.history();
        assert!(history
            .next_block()
            .unwrap_err()
            .to_string()
            .contains("duplicate JSON member name"));
        assert!(history.schedule().is_none());
        assert!(history.next_block().is_err());
    }
}

#[test]
fn duplicate_anchor_members_cannot_supply_history_authority() {
    let f = Fixture::new();
    let path = f.data.path().join("anchor.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let doc: Value = serde_json::from_str(&raw).unwrap();
    let compact = serde_json::to_string(&doc).unwrap();
    let changed = compact.replacen(
        "\"public_key\":",
        "\"public_key\":null,\"public_\\u006bey\":",
        1,
    );
    assert_ne!(changed, compact);
    assert_eq!(serde_json::from_str::<Value>(&changed).unwrap(), doc);
    std::fs::write(path, changed).unwrap();
    let err = History::open(f.data.path(), None).err().unwrap();
    assert!(err.to_string().contains("duplicate JSON member name"));
}
