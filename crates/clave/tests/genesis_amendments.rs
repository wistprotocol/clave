use clave::scheduler::{next_seal, Decision};
use std::path::Path;
use std::process::{Command, Output};

const T: i64 = 1_800_000_000;

fn ts(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).unwrap().to_string()
}

fn clave(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_clave"))
        .args(args)
        .output()
        .unwrap()
}

fn init(data: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "init",
        "--log-id",
        "genesis-log.test",
        "--data",
        data.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    clave(&args)
}

fn open(data: &Path) -> (clave::db::Db, wist_core::crypto::SigningKey) {
    (
        clave::db::Db::open(&data.join("clave.sqlite")).unwrap(),
        clave::keys::load(&data.join("keys/seed")).unwrap(),
    )
}

fn parameter_change(entry: &serde_json::Value) -> (&str, i64, &str) {
    assert_eq!(entry["type"], "registry_update");
    let update = &entry["body"]["update"];
    assert_eq!(update["action"], "parameter_change");
    (
        update["details"]["parameter"].as_str().unwrap(),
        update["details"]["value"].as_i64().unwrap(),
        update["effective_at"].as_str().unwrap(),
    )
}

#[test]
fn a_log_initialized_with_a_900_second_cadence_seals_epoch_0_hourly_and_epoch_1_on_its_grid() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("log");
    let out = init(&data, &["--cadence", "900"]);
    assert!(out.status.success(), "{out:?}");
    let (db, sk) = open(&data);

    let (last, cadence) = clave::registry::sealing_grid(&db).unwrap();
    assert_eq!(
        next_seal(last, cadence, T + 1000),
        Decision::SleepUntil(T + 3600)
    );

    let epoch_0 = clave::seal::run(&db, &data, &sk, T + 3600 + 1000).unwrap();
    assert_eq!(epoch_0.epoch_number, 0);
    assert!(epoch_0.dropped.is_empty(), "{:?}", epoch_0.dropped);
    let sealed_at = db.last_epoch().unwrap().unwrap().sealed_at;
    assert_eq!(sealed_at, ts(T + 3600));
    let entries = db.epoch_entries(0).unwrap();
    assert_eq!(
        parameter_change(&entries[0]),
        ("epoch_cadence_seconds", 900, sealed_at.as_str())
    );
    wist_core::envelope::verify_envelope(&entries[0]["body"], "update", &sk.public()).unwrap();
    assert!(db.genesis_amendments().unwrap().is_empty());

    let (last, cadence) = clave::registry::sealing_grid(&db).unwrap();
    assert_eq!((last, cadence), (Some(T + 3600), 900));
    assert_eq!(
        next_seal(last, cadence, T + 3600 + 10),
        Decision::SleepUntil(T + 3600 + 900)
    );

    let epoch_1 = clave::seal::run(&db, &data, &sk, T + 3600 + 900).unwrap();
    assert_eq!(epoch_1.epoch_number, 1);
    assert_eq!(
        db.last_epoch().unwrap().unwrap().sealed_at,
        ts(T + 3600 + 900)
    );

    let mut history = clave::history::History::open(&db, &data, db.last_epoch().unwrap()).unwrap();
    let mut heights = Vec::new();
    while let Some(epoch) = history.next_epoch().unwrap() {
        assert!(epoch.rejected_parameters().is_empty());
        heights.push(epoch.epoch_number());
    }
    assert_eq!(heights, [0, 1]);

    let out = clave(&["verify-history", "--data", data.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("authenticated 2 Checkpoints"));
}

#[test]
fn a_log_initialized_at_the_default_cadence_seals_no_genesis_amendment() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("log");
    assert!(init(&data, &["--cadence", "3600"]).status.success());
    let (db, sk) = open(&data);
    assert!(db.genesis_amendments().unwrap().is_empty());
    let epoch_0 = clave::seal::run(&db, &data, &sk, T).unwrap();
    assert_eq!(epoch_0.entry_count, 0);
}

fn param_change(data: &Path, parameter: &str, value: &str, effective_at: Option<&str>) -> Output {
    let mut args = vec![
        "param-change",
        "--data",
        data.to_str().unwrap(),
        "--parameter",
        parameter,
        "--value",
        value,
    ];
    if let Some(at) = effective_at {
        args.extend(["--effective-at", at]);
    }
    clave(&args)
}

#[test]
fn param_change_before_epoch_0_records_a_genesis_amendment_epoch_0_carries() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("log");
    assert!(init(&data, &["--parameter", "quota_base=50"])
        .status
        .success());
    let out = param_change(&data, "feed_window", "500", None);
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("seals in Epoch 0, effective at that Epoch's sealed_at"),
        "{out:?}"
    );
    let later = ts(T + 7 * 86_400 + 7200);
    let out = param_change(&data, "clock_skew_seconds", "300", Some(&later));
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains(&format!("seals in Epoch 0, effective {later}")),
        "{out:?}"
    );
    let (db, sk) = open(&data);
    assert!(db.peek_pending_entries().unwrap().0.is_empty());
    assert_eq!(db.genesis_amendments().unwrap().len(), 3);

    let epoch_0 = clave::seal::run(&db, &data, &sk, T).unwrap();
    assert!(epoch_0.dropped.is_empty(), "{:?}", epoch_0.dropped);
    assert_eq!(epoch_0.entry_count, 3);
    let sealed_at = ts(T);
    let mut sealed: Vec<_> = db
        .epoch_entries(0)
        .unwrap()
        .iter()
        .map(|entry| {
            let (name, value, effective_at) = parameter_change(entry);
            (name.to_owned(), value, effective_at.to_owned())
        })
        .collect();
    sealed.sort();
    assert_eq!(
        sealed,
        [
            ("clock_skew_seconds".to_owned(), 300, later.clone()),
            ("feed_window".to_owned(), 500, sealed_at.clone()),
            ("quota_base".to_owned(), 50, sealed_at.clone()),
        ]
    );
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &sealed_at).unwrap(),
        500
    );
    assert_eq!(clave::quota::quota_q(&db, &sealed_at).unwrap(), 50);
    assert_eq!(
        clave::registry::effective(&db, "clock_skew_seconds", &sealed_at).unwrap(),
        600
    );
    assert_eq!(
        clave::registry::effective(&db, "clock_skew_seconds", &later).unwrap(),
        300
    );
    assert!(db.genesis_amendments().unwrap().is_empty());
}

#[test]
fn a_genesis_amendment_whose_instant_precedes_epoch_0_is_dropped_at_sealing() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("log");
    assert!(init(&data, &[]).status.success());
    let early = ts(T - 3600);
    assert!(param_change(&data, "feed_window", "500", Some(&early))
        .status
        .success());
    let (db, sk) = open(&data);
    let epoch_0 = clave::seal::run(&db, &data, &sk, T).unwrap();
    assert_eq!(epoch_0.entry_count, 0);
    assert_eq!(epoch_0.dropped.len(), 1);
    assert!(
        epoch_0.dropped[0].contains("WIST4-E03"),
        "{:?}",
        epoch_0.dropped
    );
    assert!(db.peek_pending_entries().unwrap().0.is_empty());
    assert!(db.genesis_amendments().unwrap().is_empty());
    assert_eq!(
        clave::registry::effective(&db, "feed_window", &ts(T)).unwrap(),
        1000
    );
}

#[test]
fn param_change_after_epoch_0_queues_an_amendment_under_the_grace_period() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("log");
    assert!(init(&data, &[]).status.success());
    let (db, sk) = open(&data);
    clave::seal::run(&db, &data, &sk, T).unwrap();
    let report = clave::param_change::run(&db, &sk, "feed_window", 500, None, T + 60).unwrap();
    assert!(matches!(
        report,
        clave::param_change::ParamChangeReport::Queued { .. }
    ));
    assert!(db.genesis_amendments().unwrap().is_empty());
    assert_eq!(db.peek_pending_entries().unwrap().0.len(), 1);
}

#[test]
fn init_refuses_a_genesis_parameter_out_of_bounds_or_unknown() {
    for extra in [
        &["--parameter", "epoch_cadence_seconds=0"][..],
        &["--parameter", "epoch_cadence_seconds=86401"],
        &["--cadence", "0"],
        &["--parameter", "links_cap_bytes=2000"],
        &["--parameter", "no_such_parameter=1"],
        &["--parameter", "feed_window"],
        &[
            "--parameter",
            "feed_window=500",
            "--parameter",
            "feed_window=600",
        ],
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("log");
        let out = init(&data, extra);
        assert!(!out.status.success(), "{extra:?}");
        assert!(!data.join("anchor.json").exists(), "{extra:?}");
    }
}

#[test]
fn a_failed_epoch_0_seal_keeps_the_genesis_amendments_for_the_next_attempt() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("log");
    assert!(init(&data, &["--cadence", "900"]).status.success());
    let (db, sk) = open(&data);
    let foreign = wist_core::crypto::SigningKey::from_seed(&[5u8; 32]);
    assert!(clave::seal::run(&db, &data, &foreign, T).is_err());
    assert!(db.last_epoch().unwrap().is_none());
    assert!(db.peek_pending_entries().unwrap().0.is_empty());
    assert_eq!(db.genesis_amendments().unwrap().len(), 1);

    let epoch_0 = clave::seal::run(&db, &data, &sk, T).unwrap();
    assert_eq!(epoch_0.entry_count, 1);
    assert_eq!(
        parameter_change(&db.epoch_entries(0).unwrap()[0]),
        ("epoch_cadence_seconds", 900, ts(T).as_str())
    );
}
