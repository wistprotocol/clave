mod common;

use clave::db::{Db, ParamChangeRow};
use serde_json::{json, Value};
use wist_core::crypto::SigningKey;

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

fn ts(at: i64) -> String {
    jiff::Timestamp::from_second(at).unwrap().to_string()
}

fn setup() -> (tempfile::TempDir, Db, SigningKey) {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example.test", data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    (data, db, sk)
}

fn envelope(sk: &SigningKey, name: &str, value: i64, effective: i64) -> Value {
    wist_core::envelope::sign_envelope(
        &json!({
            "wist_version":"1.0.0", "action":"parameter_change", "subject":name,
            "details":{"parameter":name,"value":value}, "effective_at":ts(effective),
        }),
        "update",
        "log1",
        sk,
    )
    .unwrap()
}

fn queue(db: &Db, body: &Value) {
    db.insert_pending_entry("registry_update", "", body, 0)
        .unwrap();
}

fn block(data: &std::path::Path, height: u64) -> (Vec<u8>, Value) {
    let raw = std::fs::read(data.join(format!("log/blocks/{height:09}.json.zst"))).unwrap();
    let bytes = zstd::decode_all(&raw[..]).unwrap();
    let doc = serde_json::from_slice(&bytes).unwrap();
    (bytes, doc)
}

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist4/parameter-combinations.json"))
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn historical_size_vectors_replay_identically_after_reopening() {
    for case in fixture()["block_size_cases"].as_array().unwrap() {
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("clave.sqlite");
        let mut db = Db::open(&path).unwrap();
        for (height, b) in case["blocks"].as_array().unwrap().iter().enumerate() {
            let expected = &case["expected"][height];
            let at = b["sealed_at_s"].as_i64().unwrap();
            let effective: Vec<_> = b["amendments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| ts(c["effective_at_s"].as_i64().unwrap()))
                .collect();
            let amendments = b["amendments"].as_array().unwrap();
            let changes: Vec<_> = amendments
                .iter()
                .enumerate()
                .filter_map(|(i, c)| {
                    Some(ParamChangeRow {
                        entry_index: i as u64,
                        parameter: "block_decompressed_cap_bytes",
                        value: c["value"].as_i64()?,
                        effective_at: &effective[i],
                    })
                })
                .collect();
            db.commit_seal(
                &[],
                height as u64,
                "sha256:fixture",
                &ts(at),
                &[],
                &changes,
                &[],
                &[],
                &[],
                &[],
                &[],
                b["jcs_bytes"].as_u64().unwrap(),
            )
            .unwrap();
            let replay = db.parameter_schedule(0);
            if !expected["block_valid"].as_bool().unwrap() {
                assert!(
                    replay.err().unwrap().to_string().contains("WIST3-E03"),
                    "{}",
                    case["label"]
                );
                drop(db);
                assert!(Db::open(&path).is_err(), "{}", case["label"]);
                break;
            }
            let replay = replay.unwrap();
            let rejected: Vec<_> = (0..amendments.len())
                .filter(|&i| {
                    !replay
                        .accepted()
                        .iter()
                        .any(|a| a.block_number == height as u64 && a.entry_index == i as u64)
                })
                .collect();
            assert_eq!(
                json!(rejected),
                expected["rejected_indices"],
                "{}",
                case["label"]
            );
            assert_eq!(
                replay.block_size_bounds(at).0,
                expected["sealing_cap"].as_u64().unwrap(),
                "{}",
                case["label"]
            );
            let before = replay.accepted().to_vec();
            drop(db);
            db = Db::open(&path).unwrap();
            assert_eq!(
                db.parameter_schedule(0).unwrap().accepted(),
                before,
                "{}",
                case["label"]
            );
            assert_eq!(
                db.largest_block_bytes().unwrap(),
                expected["largest_bytes"].as_u64().unwrap()
            );
        }
    }
}

#[test]
fn prospective_vectors_filter_rejected_history_and_preserve_every_future_map() {
    for case in fixture()["prospective_cases"].as_array().unwrap() {
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let changes = case["changes"].as_array().unwrap();
        let mut blocks = std::collections::BTreeMap::new();
        for c in changes {
            blocks
                .entry(c["block_height"].as_u64().unwrap())
                .or_insert_with(Vec::new)
                .push(c);
        }
        for (height, group) in blocks {
            let effective: Vec<_> = group
                .iter()
                .map(|c| ts(c["effective_at_s"].as_i64().unwrap()))
                .collect();
            let rows: Vec<_> = group
                .iter()
                .enumerate()
                .map(|(i, c)| ParamChangeRow {
                    entry_index: c["entry_index"].as_u64().unwrap(),
                    parameter: c["parameter"].as_str().unwrap(),
                    value: c["value"].as_i64().unwrap(),
                    effective_at: &effective[i],
                })
                .collect();
            db.commit_seal(
                &[],
                height,
                "sha256:fixture",
                &ts(group[0]["sealed_at_s"].as_i64().unwrap()),
                &[],
                &rows,
                &[],
                &[],
                &[],
                &[],
                &[],
                0,
            )
            .unwrap();
        }
        drop(db);
        let db = Db::open(&path).unwrap();
        let accepted = db.parameter_schedule(0).unwrap();
        let rejected: Vec<_> = changes
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                !accepted.accepted().iter().any(|a| {
                    a.block_number == c["block_height"].as_u64().unwrap()
                        && a.entry_index == c["entry_index"].as_u64().unwrap()
                })
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            json!(rejected),
            case["rejected_indices"],
            "{}",
            case["label"]
        );
        for probe in case["maps"].as_array().unwrap() {
            for (name, value) in probe["values"].as_object().unwrap() {
                assert_eq!(
                    clave::registry::effective(&db, name, &ts(probe["at_s"].as_i64().unwrap()))
                        .unwrap(),
                    value.as_i64().unwrap(),
                    "{}",
                    case["label"]
                );
            }
        }
    }
}

#[test]
fn queued_conflicts_use_canonical_entry_order_for_admission_and_sealing() {
    let (data, db, sk) = setup();
    let mut candidates = [
        envelope(&sk, "link_url_cap_bytes", 4000, NOW + 10 * DAY),
        envelope(&sk, "links_cap_bytes", 4000, NOW + 10 * DAY),
    ];
    candidates.sort_by_key(|body| {
        wist_core::merkle::leaf_hash(
            &wist_core::jcs::canonicalize(&json!({"type":"registry_update","body":body})).unwrap(),
        )
    });
    let first = &candidates[0]["update"]["details"];
    clave::param_change::run(
        &db,
        &sk,
        first["parameter"].as_str().unwrap(),
        first["value"].as_i64().unwrap(),
        Some(&ts(NOW + 10 * DAY)),
        NOW,
    )
    .unwrap();
    let second = &candidates[1]["update"]["details"];
    assert!(clave::param_change::run(
        &db,
        &sk,
        second["parameter"].as_str().unwrap(),
        second["value"].as_i64().unwrap(),
        Some(&ts(NOW + 10 * DAY)),
        NOW
    )
    .err()
    .unwrap()
    .to_string()
    .contains("WIST4-E03"));
    queue(&db, &candidates[1]);
    let report = clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    assert_eq!(report.entry_count, 1);
    assert_eq!(report.dropped.len(), 1);
    assert!(report.dropped[0].contains("WIST4-E03"));
    let (_, doc) = block(data.path(), 0);
    assert_eq!(doc["entries"][0]["body"], candidates[0]);
}

#[test]
fn grace_changes_are_read_from_the_accepted_sealing_prefix() {
    let (data, db, sk) = setup();
    queue(&db, &envelope(&sk, "param_grace_days", 1, NOW + 7 * DAY));
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    queue(&db, &envelope(&sk, "feed_window", 500, NOW + 2 * DAY));
    let rejected = clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();
    assert_eq!(rejected.entry_count, 0);
    assert!(rejected.dropped[0].contains("grace"));
    clave::param_change::run(
        &db,
        &sk,
        "feed_window",
        600,
        Some(&ts(NOW + 8 * DAY)),
        NOW + 7 * DAY,
    )
    .unwrap();
    assert_eq!(
        clave::seal::run(&db, data.path(), &sk, NOW + 7 * DAY)
            .unwrap()
            .entry_count,
        1
    );
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &ts(NOW + 8 * DAY)).unwrap(),
        600
    );
}

#[test]
fn accepted_pending_reduction_bounds_actual_jcs_blocks_after_restart() {
    let (data, db, sk) = setup();
    clave::param_change::run(
        &db,
        &sk,
        "block_decompressed_cap_bytes",
        4096,
        Some(&ts(NOW + 10 * DAY)),
        NOW,
    )
    .unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    drop(db);
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    assert_eq!(
        clave::registry::effective(&db, "block_decompressed_cap_bytes", &ts(NOW + DAY)).unwrap(),
        268_435_456
    );
    for value in 0..30 {
        queue(
            &db,
            &envelope(&sk, "clock_skew_seconds", value, NOW + 30 * DAY),
        );
    }
    let mut count = 0;
    for i in 1..=10 {
        let report = clave::seal::run(&db, data.path(), &sk, NOW + DAY + i * 3600).unwrap();
        let (bytes, doc) = block(data.path(), report.block_number);
        assert_eq!(bytes, wist_core::jcs::canonicalize(&doc).unwrap());
        assert!(bytes.len() <= 4096);
        wist_core::block::verify_block(&doc, &sk.public()).unwrap();
        count += report.entry_count;
        if db.peek_pending_entries().unwrap().0.is_empty() {
            break;
        }
    }
    assert_eq!(count, 30);
    assert!(db.last_block().unwrap().unwrap().block_number > 1);
    assert!(db.largest_block_bytes().unwrap() <= 4096);
}

#[test]
fn historical_block_size_rejects_a_reduction_at_admission_and_sealing() {
    let (data, db, sk) = setup();
    for value in 0..20 {
        queue(
            &db,
            &envelope(&sk, "clock_skew_seconds", value, NOW + 30 * DAY),
        );
    }
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    assert!(db.largest_block_bytes().unwrap() > 4096);
    assert!(clave::param_change::run(
        &db,
        &sk,
        "block_decompressed_cap_bytes",
        4096,
        Some(&ts(NOW + 10 * DAY)),
        NOW + DAY
    )
    .err()
    .unwrap()
    .to_string()
    .contains("Block cap"));
    queue(
        &db,
        &envelope(&sk, "block_decompressed_cap_bytes", 4096, NOW + 10 * DAY),
    );
    let report = clave::seal::run(&db, data.path(), &sk, NOW + DAY).unwrap();
    assert_eq!(report.entry_count, 0);
    assert!(report.dropped[0].contains("Block cap"));
}

#[test]
fn snapshot_parameters_include_pending_amendments_and_only_the_winning_ties() {
    let (data, db, sk) = setup();
    for (value, days) in [(500, 7), (600, 10), (700, 10)] {
        queue(&db, &envelope(&sk, "feed_window", value, NOW + days * DAY));
    }
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    let (_, doc) = block(data.path(), 0);
    let last = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .rfind(|e| e["body"]["update"]["effective_at"] == ts(NOW + 10 * DAY))
        .unwrap();
    let winning = last["body"]["update"]["details"]["value"].as_i64().unwrap();
    let date = &ts(NOW)[..10];
    let state: Value = serde_json::from_slice(
        &std::fs::read(data.path().join(format!("snapshots/{date}/state.json"))).unwrap(),
    )
    .unwrap();
    let params: Vec<_> = state["state"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e[0] == "parameter")
        .cloned()
        .collect();
    assert_eq!(params.len(), 2);
    let typed: wist_core::objects::SnapshotState =
        serde_json::from_value(state["state"].clone()).unwrap();
    let tuples: Vec<_> = typed
        .entries
        .iter()
        .filter_map(|e| match e {
            wist_core::objects::StateEntry::Parameter(p) => Some((p.effective_at.clone(), p.value)),
            _ => None,
        })
        .collect();
    assert!(tuples.contains(&(ts(NOW + 7 * DAY), 500)));
    assert!(tuples.contains(&(ts(NOW + 10 * DAY), winning)));
}

#[test]
fn legacy_migration_recovers_sizes_and_canonical_positions_from_blocks() {
    let (data, db, sk) = setup();
    for value in [500, 600] {
        queue(&db, &envelope(&sk, "feed_window", value, NOW + 10 * DAY));
    }
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    let before = db.parameter_schedule(NOW).unwrap().accepted().to_vec();
    let (bytes, doc) = block(data.path(), 0);
    let typed: wist_core::objects::Block = serde_json::from_value(doc.clone()).unwrap();
    let legacy = serde_json::to_vec(&typed).unwrap();
    assert_ne!(legacy, bytes);
    std::fs::write(
        data.path().join("log/blocks/000000000.json.zst"),
        zstd::bulk::compress(&legacy, 0).unwrap(),
    )
    .unwrap();
    drop(db);
    let path = data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("ALTER TABLE blocks DROP COLUMN decompressed_bytes", [])
        .unwrap();
    conn.execute("ALTER TABLE param_changes DROP COLUMN entry_index", [])
        .unwrap();
    conn.execute("UPDATE param_changes SET value = -1", [])
        .unwrap();
    drop(conn);
    std::fs::remove_file(data.path().join("keys/seed")).unwrap();
    let db = Db::open(&path).unwrap();
    assert_eq!(db.largest_block_bytes().unwrap(), bytes.len() as u64);
    assert_eq!(db.parameter_schedule(NOW).unwrap().accepted(), before);
    assert_eq!(block(data.path(), 0), (bytes, doc));
}

#[test]
fn incomplete_legacy_block_history_fails_without_guessing_sizes() {
    let (data, db, sk) = setup();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    drop(db);
    let path = data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE blocks SET decompressed_bytes = NULL", [])
        .unwrap();
    drop(conn);
    std::fs::remove_file(data.path().join("log/blocks/000000000.json.zst")).unwrap();
    assert!(Db::open(&path).is_err());
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("SELECT decompressed_bytes FROM blocks", [], |r| r
            .get::<_, Option<u64>>(0))
            .unwrap(),
        None
    );
}

#[test]
fn false_frame_sizes_fail_migration_with_the_protocol_error() {
    for difference in [-1i64, 1] {
        let (data, db, sk) = setup();
        clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
        drop(db);
        let path = data.path().join("clave.sqlite");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE blocks SET decompressed_bytes = NULL", [])
            .unwrap();
        drop(conn);
        let file = data.path().join("log/blocks/000000000.json.zst");
        let raw = std::fs::read(&file).unwrap();
        let declared = zstd::zstd_safe::get_frame_content_size(&raw)
            .unwrap()
            .unwrap();
        let target = (declared as i64 + difference) as u64;
        let mut changed = None;
        'search: for index in 4..raw.len().min(18) {
            for byte in 0..=255 {
                let mut candidate = raw.clone();
                candidate[index] = byte;
                if zstd::zstd_safe::get_frame_content_size(&candidate)
                    .ok()
                    .flatten()
                    == Some(target)
                {
                    changed = Some(candidate);
                    break 'search;
                }
            }
        }
        std::fs::write(file, changed.expect("frame-size mutation")).unwrap();
        assert!(Db::open(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("WIST3-E03"));
    }
}
