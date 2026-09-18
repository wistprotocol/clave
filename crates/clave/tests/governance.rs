mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86400;

fn ts(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).unwrap().to_string()
}

struct Rig {
    host: String,
    data: tempfile::TempDir,
    db: clave::db::Db,
    sk: wist_core::crypto::SigningKey,
    ids: Vec<String>,
}

fn rig(urls: &[&str]) -> Rig {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = urls
        .iter()
        .map(|url| add_delta(&p, url, "withdrawable body", None))
        .collect();
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, &ts(NOW)).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    Rig {
        host,
        data,
        db,
        sk,
        ids,
    }
}

fn read_entries(db: &clave::db::Db, number: u64) -> Vec<serde_json::Value> {
    db.epoch_entries(number).unwrap()
}

#[test]
fn payload_withdrawal_removes_payload_record_and_stale_snapshots() {
    let r = rig(&["https://example.com/a"]);
    let id = &r.ids[0];
    clave::seal::run(&r.db, r.data.path(), &r.sk, NOW).unwrap();

    let hex = id.strip_prefix("sha256:").unwrap();
    let payload_path = r.data.path().join("payloads").join(format!("{hex}.json"));
    assert!(payload_path.exists());
    let first_snapshot_dir = r.data.path().join("snapshots").join(&ts(NOW)[..10]);
    assert!(first_snapshot_dir.exists());
    assert!(r
        .db
        .get_record("https://example.com/a", &r.host)
        .unwrap()
        .is_some());

    clave::governance::withdraw(
        &r.db,
        &r.sk,
        &r.host,
        id,
        "court order",
        "DE",
        NOW + 2 * DAY,
    )
    .unwrap();
    let seal = clave::seal::run(&r.db, r.data.path(), &r.sk, NOW + 2 * DAY).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());

    assert!(!payload_path.exists());
    assert!(r
        .db
        .get_record("https://example.com/a", &r.host)
        .unwrap()
        .is_none());
    assert!(r.db.is_withdrawn(id).unwrap());
    assert!(
        !first_snapshot_dir.exists(),
        "snapshot containing withdrawn content must stop being served"
    );
    let new_snapshot_dir = r
        .data
        .path()
        .join("snapshots")
        .join(&ts(NOW + 2 * DAY)[..10]);
    assert!(new_snapshot_dir.exists());
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(r.data.path().join("snapshots/index.json")).unwrap())
            .unwrap();
    let dates: Vec<&str> = index["index"]["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["snapshot_date"].as_str().unwrap())
        .collect();
    assert_eq!(dates, vec![&ts(NOW + 2 * DAY)[..10]]);
}

#[test]
fn a_repeated_withdrawal_seals_and_keeps_the_first_height() {
    let r = rig(&["https://example.com/a"]);
    let id = &r.ids[0];
    clave::seal::run(&r.db, r.data.path(), &r.sk, NOW).unwrap();
    clave::governance::withdraw(&r.db, &r.sk, &r.host, id, "court order", "DE", NOW + 3600)
        .unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, NOW + 3600).unwrap();
    clave::governance::withdraw(&r.db, &r.sk, &r.host, id, "later order", "DE", NOW + 7200)
        .unwrap();
    let seal = clave::seal::run(&r.db, r.data.path(), &r.sk, NOW + 7200).unwrap();
    assert_eq!(seal.entry_count, 1);
    assert!(seal.dropped.is_empty());
    assert_eq!(
        r.db.withdrawal_state().unwrap(),
        vec![(id.clone(), r.host.clone(), 1)]
    );
}

#[test]
fn a_withdrawal_may_seal_beside_its_delta_but_not_before_it() {
    let r = rig(&["https://example.com/a", "https://example.com/b"]);
    let (first, second) = (&r.ids[0], &r.ids[1]);
    r.db.set_param("domain_epoch_entries_max", 1).unwrap();
    clave::governance::withdraw(&r.db, &r.sk, &r.host, first, "court order", "DE", NOW).unwrap();
    clave::governance::withdraw(&r.db, &r.sk, &r.host, second, "court order", "DE", NOW).unwrap();
    let seal = clave::seal::run(&r.db, r.data.path(), &r.sk, NOW).unwrap();
    let entries = read_entries(&r.db, 0);
    let sealed_delta = entries
        .iter()
        .find(|e| e["type"] == "publisher_delta")
        .map(|e| wist_core::delta::delta_id(&e["body"]["delta"]).unwrap())
        .expect("one Delta seals under the capacity");
    let held = if &sealed_delta == first {
        second
    } else {
        first
    };
    assert_eq!(seal.entry_count, 3, "{:?}", seal.dropped);
    assert_eq!(seal.dropped.len(), 1);
    assert!(seal.dropped[0].contains("WIST4-E04"));
    assert!(seal.dropped[0].contains(held.as_str()));
    assert!(r.db.is_withdrawn(&sealed_delta).unwrap());
    assert!(!r.db.is_withdrawn(held).unwrap());
    assert!(r
        .db
        .get_record(
            if &sealed_delta == first {
                "https://example.com/a"
            } else {
                "https://example.com/b"
            },
            &r.host
        )
        .unwrap()
        .is_none());
}

#[test]
fn withdraw_refuses_a_delta_the_log_never_accepted() {
    let r = rig(&["https://example.com/a"]);
    let unknown = format!("sha256:{}", "f".repeat(64));
    assert!(matches!(
        clave::governance::withdraw(&r.db, &r.sk, &r.host, &unknown, "court order", "DE", NOW),
        Err(clave::Error::Governance(_))
    ));
    assert!(matches!(
        clave::governance::withdraw(&r.db, &r.sk, "other.example", &r.ids[0], "order", "DE", NOW),
        Err(clave::Error::Governance(_))
    ));
    assert!(r
        .db
        .peek_pending_entries()
        .unwrap()
        .0
        .iter()
        .all(|e| e.entry_type != "registry_update"));
}
