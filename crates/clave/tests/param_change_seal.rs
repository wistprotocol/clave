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
