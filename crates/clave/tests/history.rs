use clave::db::{BlockRow, Db};
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
        let body = envelope::sign_envelope(
            &json!({inner:{"preserved":"complete signed content"}}),
            inner,
            "log1",
            &f.sk,
        )
        .unwrap();
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
