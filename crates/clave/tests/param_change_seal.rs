mod common;
use std::path::Path;

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86400;

fn ts(epoch: i64) -> String {
    jiff::Timestamp::from_second(epoch).unwrap().to_string()
}

fn setup() -> (
    tempfile::TempDir,
    clave::db::Db,
    wist_core::crypto::SigningKey,
) {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("example-log.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    db.set_param("canary_reveal_min_blocks", 259272).unwrap();
    db.set_param("canary_lifetime_blocks", 300000).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    (data, db, sk)
}

fn read_block(data: &Path, number: u64) -> serde_json::Value {
    let raw = std::fs::read(data.join(format!("log/blocks/{number:09}.json.zst"))).unwrap();
    serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap()
}

#[test]
fn seal_includes_valid_parameter_change_and_applies_it_at_effective_at() {
    let (data, db, sk) = setup();
    let report = clave::param_change::run(&db, &sk, "feed_window", 500, None, NOW).unwrap();

    let seal = clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());

    let block = read_block(data.path(), 0);
    let entry = &block["entries"][0];
    assert_eq!(entry["type"], "registry_update");
    wist_core::envelope::verify_envelope(&entry["body"], "update", &sk.public()).unwrap();
    assert_eq!(
        entry["body"]["update"]["details"]["parameter"],
        "feed_window"
    );

    let before = ts(NOW + DAY);
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &before).unwrap(),
        1000
    );
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &report.effective_at).unwrap(),
        500
    );
}

#[test]
fn seal_drops_and_reports_parameter_change_gone_stale_in_queue() {
    let (data, db, sk) = setup();
    let effective_at = ts(NOW + 7 * DAY);
    clave::param_change::run(&db, &sk, "feed_window", 500, Some(&effective_at), NOW).unwrap();

    let seal = clave::seal::run(&db, data.path(), &sk, NOW + 3600).unwrap();
    assert_eq!(seal.entry_count, 0);
    assert_eq!(seal.dropped.len(), 1);
    assert!(seal.dropped[0].contains("feed_window"));

    let block = read_block(data.path(), 0);
    assert_eq!(block["header"]["entry_count"], 0);
    let (pending, _) = db.peek_pending_entries().unwrap();
    assert!(pending.is_empty());
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &effective_at).unwrap(),
        1000
    );
}

#[test]
fn seal_reads_cadence_in_force_at_previous_block_sealed_at() {
    let (data, db, sk) = setup();
    let effective_at = ts(NOW + 7 * DAY);
    clave::param_change::run(
        &db,
        &sk,
        "block_cadence_seconds",
        60,
        Some(&effective_at),
        NOW,
    )
    .unwrap();

    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    let b1 = clave::seal::run(&db, data.path(), &sk, NOW + 7 * DAY).unwrap();
    assert_eq!(b1.block_number, 1);
    assert_eq!(
        db.last_block().unwrap().unwrap().sealed_at,
        ts(NOW + 7 * DAY),
        "previous block sealed before effective_at keeps the old one-second grid"
    );

    let b2 = clave::seal::run(&db, data.path(), &sk, NOW + 7 * DAY + 90).unwrap();
    assert_eq!(b2.block_number, 2);
    assert_eq!(
        db.last_block().unwrap().unwrap().sealed_at,
        ts(NOW + 7 * DAY + 60),
        "previous block sealed at effective_at puts this block on the new 60-second grid"
    );
}

#[test]
fn snapshot_state_carries_amended_parameters_with_their_effective_instant() {
    let (data, db, sk) = setup();
    let effective_at = ts(NOW + 7 * DAY);
    clave::param_change::run(&db, &sk, "feed_window", 500, Some(&effective_at), NOW).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + 7 * DAY).unwrap();

    let snapdir = std::fs::read_dir(data.path().join("snapshots"))
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_dir())
        .expect("a snapshot directory")
        .path();
    let state_bytes = std::fs::read(snapdir.join("state.json")).unwrap();
    let state_env: serde_json::Value = serde_json::from_slice(&state_bytes).unwrap();
    let state: wist_core::objects::SnapshotState =
        serde_json::from_value(state_env["state"].clone()).unwrap();

    let params: Vec<_> = state
        .entries
        .iter()
        .filter_map(|e| match e {
            wist_core::objects::StateEntry::Parameter(p) => Some(p),
            _ => None,
        })
        .collect();
    assert_eq!(
        params.len(),
        1,
        "only the amended parameter gets a tuple (WIST-3 §7)"
    );
    assert_eq!(params[0].name, "feed_window");
    assert_eq!(params[0].value, 500);
    assert_eq!(
        params[0].effective_at, effective_at,
        "the tuple restates the Registry Update's instant, not a height"
    );
}

#[test]
fn spec_coverage_countability_vectors_respect_extension_window() {
    let path = common::spec_dir().join("vectors/wist4/parameter-combinations.json");
    let vector: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let cases = vector["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let at = |name: &str| case[name].as_i64().unwrap();
        let lookup = |name: &str| match name {
            "block_cadence_seconds" | "coverage_deadline_hours" | "record_seal_blocks" => at(name),
            other => clave::registry::spec(other).unwrap().default.unwrap(),
        };
        let changed = case["changed"].as_str().unwrap();
        let got = clave::registry::validate(changed, at(changed), lookup);
        if label == "the last seal deadline the rule admits" {
            assert!(case["rule_holds"].as_bool().unwrap());
            assert!(got
                .unwrap_err()
                .to_string()
                .contains("extension publication and sealing must fit the confirmation window"));
            continue;
        }
        assert_eq!(
            got.is_ok(),
            case["rule_holds"].as_bool().unwrap(),
            "{label}: {got:?}"
        );
    }
}

#[test]
fn spec_extension_window_vectors() {
    let path = common::spec_dir().join("vectors/wist4/parameter-combinations.json");
    let vector: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let cases = vector["extension_window_cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let lookup = |name: &str| {
            case[name]
                .as_i64()
                .unwrap_or_else(|| clave::registry::spec(name).unwrap().default.unwrap())
        };
        let changed = case["changed"].as_str().unwrap();
        let got = clave::registry::validate(changed, lookup(changed), lookup);
        assert_eq!(
            got.is_ok(),
            case["rule_holds"].as_bool().unwrap(),
            "{}: {got:?}",
            case["label"]
        );
    }
}

#[test]
fn observer_and_canary_amendments_survive_sealing_and_reopening() {
    for (name, value) in [
        ("epoch_blocks", 12),
        ("observer_checkpoint_budget", 512),
        ("canary_lead_blocks", 12),
        ("canary_leaves_max", 512),
        ("canary_commitments_max", 4),
        ("canary_reveal_min_blocks", 259273),
        ("canary_lifetime_blocks", 300001),
    ] {
        let (data, db, sk) = setup();
        let report = clave::param_change::run(&db, &sk, name, value, None, NOW).unwrap();
        let sealed = clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
        assert_eq!(sealed.entry_count, 1, "{name}: {:?}", sealed.dropped);
        assert!(sealed.dropped.is_empty(), "{name}");
        let block = read_block(data.path(), 0);
        let details = &block["entries"][0]["body"]["update"]["details"];
        assert_eq!(details["parameter"], name);
        assert_eq!(details["value"], value);
        drop(db);
        let reopened = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        assert_eq!(
            clave::registry::effective(&reopened, name, &report.effective_at).unwrap(),
            value,
            "{name}"
        );
    }
}

#[test]
fn admission_rejects_invalid_canary_combination_without_queueing() {
    let (_data, db, sk) = setup();
    for (name, value) in [
        ("epoch_blocks", 25),
        ("canary_reveal_min_blocks", 259271),
        ("canary_lifetime_blocks", 259296),
        ("contradictions_max", 2),
    ] {
        assert!(
            matches!(
                clave::param_change::run(&db, &sk, name, value, None, NOW),
                Err(clave::error::Error::ParamChange(_))
            ),
            "{name}"
        );
        assert!(db.peek_pending_entries().unwrap().0.is_empty(), "{name}");
    }
}
