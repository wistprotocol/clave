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

fn queued(report: clave::param_change::ParamChangeReport) -> String {
    match report {
        clave::param_change::ParamChangeReport::Queued { effective_at, .. } => effective_at,
        clave::param_change::ParamChangeReport::Genesis { .. } => {
            panic!("recorded as a genesis amendment")
        }
    }
}

#[test]
fn seal_includes_valid_parameter_change_and_applies_it_at_effective_at() {
    let (data, db, sk) = setup();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    let effective_at =
        queued(clave::param_change::run(&db, &sk, "feed_window", 500, None, NOW + 60).unwrap());

    let seal = clave::seal::run(&db, data.path(), &sk, NOW + 3600).unwrap();
    assert_eq!(seal.epoch_number, 1);
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());

    let entries = read_entries(&db, 1);
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
        clave::registry::effective(&db, "feed_window", &effective_at).unwrap(),
        500
    );
}

#[test]
fn seal_drops_and_reports_parameter_change_gone_stale_in_queue() {
    let (data, db, sk) = setup();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    let queued_at = NOW + 3600;
    let effective_at = ts(queued_at + 7 * DAY);
    clave::param_change::run(&db, &sk, "feed_window", 500, Some(&effective_at), queued_at).unwrap();

    let seal = clave::seal::run(&db, data.path(), &sk, queued_at + 3600).unwrap();
    assert_eq!(seal.epoch_number, 1);
    assert_eq!(seal.entry_count, 0);
    assert_eq!(seal.dropped.len(), 1);
    assert!(seal.dropped[0].contains("feed_window"));

    assert!(read_entries(&db, 1).is_empty());
    let (pending, _) = db.peek_pending_entries().unwrap();
    assert!(pending.is_empty());
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &effective_at).unwrap(),
        1000
    );
}

#[test]
fn an_epoch_0_parameter_change_sealed_late_is_valid_under_the_genesis_exemption() {
    let (data, db, sk) = setup();
    let effective_at = ts(NOW + 7 * DAY);
    clave::param_change::run(&db, &sk, "feed_window", 500, Some(&effective_at), NOW).unwrap();

    let seal = clave::seal::run(&db, data.path(), &sk, NOW + 3600).unwrap();
    assert_eq!(seal.epoch_number, 0);
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &effective_at).unwrap(),
        500
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
    common::assert_resumes_as_replayed(&db, data.path());
}

#[test]
fn snapshot_state_carries_amended_parameters_with_their_effective_instant() {
    let (data, db, sk) = setup();
    let effective_at = ts(NOW + 7 * DAY);
    clave::param_change::run(&db, &sk, "feed_window", 500, Some(&effective_at), NOW).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    clave::seal::run(&db, data.path(), &sk, NOW + 7 * DAY).unwrap();
    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();

    let snapdir = common::newest_served_snapshot(data.path());
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

fn corrupt_queued_signature(data: &std::path::Path, parameter: &str) {
    let conn = rusqlite::Connection::open(data.join("clave.sqlite")).unwrap();
    let rows: Vec<(i64, Vec<u8>)> = conn
        .prepare(
            "SELECT rowid, entry_json FROM pending_entries WHERE entry_type = 'registry_update'",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut corrupted = 0;
    for (rowid, json) in rows {
        let mut body: serde_json::Value = serde_json::from_slice(&json).unwrap();
        if body["update"]["details"]["parameter"] != parameter {
            continue;
        }
        body["sig"]["value"] = wist_core::crypto::b64u_encode(&[0u8; 64]).into();
        conn.execute(
            "UPDATE pending_entries SET entry_json = ?2 WHERE rowid = ?1",
            rusqlite::params![rowid, serde_json::to_vec(&body).unwrap()],
        )
        .unwrap();
        corrupted += 1;
    }
    assert_eq!(corrupted, 1);
}

const REDUCED_CAP: u64 = 65_537;

fn publish_items_over_the_reduced_cap(r: &common::Rig) {
    let items: Vec<_> = (0..40)
        .map(|n| {
            let (item, payload) = r.page(&format!("{n:04}/{}", "p".repeat(1900)), "body");
            (item, Some(payload))
        })
        .collect();
    r.publish(&items, "2026-08-09T12:00:00Z", None);
    r.pull("2026-08-09T12:00:05Z");
}

fn carries_cap_change(entries: &[serde_json::Value]) -> bool {
    entries
        .iter()
        .any(|entry| entry["body"]["update"]["details"]["parameter"] == "epoch_cap_bytes")
}

fn seal_beside_a_queued_cap_reduction(
    corrupt: bool,
) -> (common::Rig, clave::seal::SealReport, Vec<serde_json::Value>) {
    let r = common::Rig::new();
    let genesis = r.seal("2026-08-09T11:00:00Z");
    assert_eq!(genesis.epoch_number, 0);
    assert!(r.db.largest_epoch_bytes().unwrap() <= REDUCED_CAP);
    let queued_at = wist_core::timestamp::log_seconds("2026-08-09T11:00:10Z").unwrap();
    clave::param_change::run(
        &r.db,
        &r.sk,
        "epoch_cap_bytes",
        REDUCED_CAP as i64,
        Some(&ts(queued_at + 10 * DAY)),
        queued_at,
    )
    .unwrap();
    if corrupt {
        corrupt_queued_signature(r.data.path(), "epoch_cap_bytes");
    }
    publish_items_over_the_reduced_cap(&r);
    let seal = r.seal("2026-08-09T13:00:00Z");
    assert_eq!(seal.epoch_number, 1);
    let entries = r.entries(1);
    (r, seal, entries)
}

#[test]
fn a_queued_cap_reduction_whose_signature_fails_at_sealing_does_not_tighten_that_epochs_cap() {
    let (r, seal, entries) = seal_beside_a_queued_cap_reduction(true);
    assert_eq!(seal.dropped.len(), 1, "{:?}", seal.dropped);
    assert!(
        seal.dropped[0].contains("epoch_cap_bytes"),
        "{:?}",
        seal.dropped
    );
    assert!(!carries_cap_change(&entries));
    assert!(wist_core::epoch::epoch_octets(&entries).unwrap() > REDUCED_CAP);
    assert!(r.state().urls.is_empty(), "every queued Item seals");
    assert!(r.db.peek_pending_entries().unwrap().0.is_empty());
}

#[test]
fn a_valid_queued_cap_reduction_bounds_the_epoch_that_seals_it() {
    let (r, seal, entries) = seal_beside_a_queued_cap_reduction(false);
    assert!(seal.dropped.is_empty(), "{:?}", seal.dropped);
    assert!(carries_cap_change(&entries));
    assert!(wist_core::epoch::epoch_octets(&entries).unwrap() <= REDUCED_CAP);
    assert!(
        !r.state().urls.is_empty(),
        "the reduced cap keeps Items out"
    );
}

#[test]
fn a_genesis_cap_reduction_bounds_the_contents_of_epoch_0() {
    let r = common::Rig::new();
    clave::param_change::record_genesis(
        &r.db,
        &clave::db::GenesisAmendment::at_genesis("epoch_cap_bytes", REDUCED_CAP as i64),
    )
    .unwrap();
    publish_items_over_the_reduced_cap(&r);
    let seal = r.seal("2026-08-09T13:00:00Z");
    assert_eq!(seal.epoch_number, 0);
    assert!(seal.dropped.is_empty(), "{:?}", seal.dropped);
    let entries = r.entries(0);
    assert!(carries_cap_change(&entries));
    assert!(wist_core::epoch::epoch_octets(&entries).unwrap() <= REDUCED_CAP);
    assert!(
        !r.state().urls.is_empty(),
        "the reduced cap keeps Items out"
    );
}
