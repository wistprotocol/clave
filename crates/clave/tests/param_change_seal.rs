mod common;

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86400;

fn ts(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).unwrap().to_string()
}

fn setup() -> (
    tempfile::TempDir,
    clave::db::Db,
    wist_core::crypto::SigningKey,
) {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("example-log.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    (data, db, sk)
}

fn read_entries(db: &clave::db::Db, number: u64) -> Vec<serde_json::Value> {
    db.epoch_entries(number).unwrap()
}

#[test]
fn seal_includes_valid_parameter_change_and_applies_it_at_effective_at() {
    let (data, db, sk) = setup();
    let report = clave::param_change::run(&db, &sk, "feed_window", 500, None, NOW).unwrap();

    let seal = clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());

    let entries = read_entries(&db, 0);
    let entry = &entries[0];
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

    assert!(read_entries(&db, 0).is_empty());
    let (pending, _) = db.peek_pending_entries().unwrap();
    assert!(pending.is_empty());
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &effective_at).unwrap(),
        1000
    );
}

#[test]
fn seal_reads_cadence_in_force_at_previous_epoch_sealed_at() {
    let (data, db, sk) = setup();
    let effective_at = ts(NOW + 7 * DAY);
    clave::param_change::run(
        &db,
        &sk,
        "epoch_cadence_seconds",
        3500,
        Some(&effective_at),
        NOW,
    )
    .unwrap();

    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    let b1 = clave::seal::run(&db, data.path(), &sk, NOW + 7 * DAY).unwrap();
    assert_eq!(b1.epoch_number, 1);
    assert_eq!(
        db.last_epoch().unwrap().unwrap().sealed_at,
        ts(NOW + 7 * DAY),
        "the activation Epoch still uses the prior hourly grid"
    );

    let b2 = clave::seal::run(&db, data.path(), &sk, NOW + 7 * DAY + 3600).unwrap();
    assert_eq!(b2.epoch_number, 2);
    assert_eq!(
        db.last_epoch().unwrap().unwrap().sealed_at,
        ts((NOW + 7 * DAY + 3600).div_euclid(3500) * 3500),
        "the following Epoch uses the new 3500-second grid"
    );
}

#[test]
fn snapshot_state_carries_amended_parameters_with_their_effective_instant() {
    let (data, db, sk) = setup();
    let effective_at = ts(NOW + 7 * DAY);
    clave::param_change::run(&db, &sk, "feed_window", 500, Some(&effective_at), NOW).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + 7 * DAY).unwrap();
    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();

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
fn admission_rejects_invalid_combinations_without_queueing() {
    let (_data, db, sk) = setup();
    for (name, value) in [
        ("links_cap_bytes", 2000),
        ("payload_window_days", 541),
        ("mirror_retention_days", 29),
        ("sampling_floor", 2),
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
