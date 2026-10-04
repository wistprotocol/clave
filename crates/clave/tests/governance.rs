mod common;

use common::{add_label, make_publisher_with_scope, reserve_addr, serve_static, write_label_feed};

const NOW: i64 = 1_800_000_000;

fn ts(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).unwrap().to_string()
}

struct Rig {
    host: String,
    _data: tempfile::TempDir,
    db: clave::db::Db,
    sk: wist_core::crypto::SigningKey,
    ids: Vec<String>,
}

fn rig(urls: &[&str]) -> Rig {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = urls
        .iter()
        .map(|url| {
            add_label(
                &p,
                &url.replace("example.com", "other.example"),
                "2026-08-09T11:00:00Z",
            )
        })
        .collect();
    write_label_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, &ts(NOW)).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    Rig {
        host,
        _data: data,
        db,
        sk,
        ids,
    }
}

#[test]
fn withdraw_refuses_an_id_that_names_no_item_sealed_for_the_subject() {
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
    assert!(matches!(
        clave::governance::withdraw(&r.db, &r.sk, &r.host, &r.ids[0], "order", "DE", NOW),
        Err(clave::Error::Governance(_))
    ));
    assert!(matches!(
        clave::governance::withdraw(&r.db, &r.sk, &r.host, "sha256:F00", "order", "DE", NOW),
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

fn sealed_log() -> (common::Rig, serde_json::Value, common::Published, String) {
    let log = common::Rig::new();
    let (item, payload) = log.page("a", "withdrawable body");
    let published = log.publish(
        &[(item.clone(), Some(payload))],
        "2026-08-09T12:00:00Z",
        None,
    );
    log.pull("2026-08-09T12:00:05Z");
    log.seal("2026-08-09T13:00:00Z");
    let id = common::item_id(&item);
    (log, item, published, id)
}

fn withdraw(log: &common::Rig, id: &str, at: &str) -> clave::error::Result<String> {
    clave::governance::withdraw(
        &log.db,
        &log.sk,
        &log.host,
        id,
        "court order",
        "DE",
        wist_core::timestamp::log_seconds(at).unwrap(),
    )
    .map(|report| report.update_id)
}

fn withdrawn_at(log: &common::Rig, id: &str) -> Option<u64> {
    log.db
        .withdrawal_state()
        .unwrap()
        .into_iter()
        .find(|(item_id, _, _)| item_id == id)
        .map(|(_, _, height)| height)
}

#[test]
fn a_payload_withdrawal_destroys_the_payload_and_stale_snapshots_and_leaves_the_record() {
    let (log, _, _, id) = sealed_log();
    let served = clave::db::served_payload_path(log.data.path(), &id).unwrap();
    assert!(served.exists());
    clave::snapshot::produce(&log.data.path().join("clave.sqlite"), log.data.path()).unwrap();
    assert!(!common::listed_snapshots(log.data.path()).is_empty());
    withdraw(&log, &id, "2026-08-09T13:30:00Z").unwrap();
    let report = log.seal("2026-08-09T14:00:00Z");
    assert_eq!(report.entry_count, 1);
    let entries = log.entries(1);
    assert_eq!(entries[0]["body"]["update"]["action"], "payload_withdrawal");
    assert_eq!(
        entries[0]["body"]["update"]["details"]["delta_id"],
        id.as_str()
    );
    assert_eq!(withdrawn_at(&log, &id), Some(1));
    assert!(!served.exists());
    assert!(!clave::db::held_payload_path(log.data.path(), &id)
        .unwrap()
        .exists());
    assert!(common::listed_snapshots(log.data.path()).is_empty());
    assert!(log.db.payload_duties().unwrap().is_empty());
    let state = log.state();
    assert_eq!(state.record(&log.host, &log.url("a")).unwrap().item_id, id);
    assert!(state.withdrawals.is_withdrawn(&id));
}

#[test]
fn a_repeated_withdrawal_seals_and_keeps_the_first_height() {
    let (log, _, _, id) = sealed_log();
    withdraw(&log, &id, "2026-08-09T13:30:00Z").unwrap();
    log.seal("2026-08-09T14:00:00Z");
    withdraw(&log, &id, "2026-08-09T14:30:00Z").unwrap();
    let report = log.seal("2026-08-09T15:00:00Z");
    assert_eq!(report.entry_count, 1, "{:?}", report.dropped);
    assert!(report.dropped.is_empty());
    assert_eq!(withdrawn_at(&log, &id), Some(1));
}

#[test]
fn a_withdrawal_queued_again_under_an_accepted_id_is_dropped_and_keeps_the_first_height() {
    let (log, _, _, id) = sealed_log();
    let update_id = withdraw(&log, &id, "2026-08-09T13:30:00Z").unwrap();
    let (pending, _) = log.db.peek_pending_entries().unwrap();
    let act = pending[0].entry_json.clone();
    assert_eq!(log.seal("2026-08-09T14:00:00Z").entry_count, 1);

    log.db
        .insert_pending_entry("registry_update", "", &act, 0)
        .unwrap();
    let report = log.seal("2026-08-09T15:00:00Z");
    assert_eq!(report.entry_count, 0);
    assert_eq!(
        report.dropped,
        [format!(
            "payload_withdrawal {} is not sealed: its Registry Update ID {update_id} was accepted at height 1",
            log.host
        )]
    );
    assert!(log.db.peek_pending_entries().unwrap().0.is_empty());
    assert_eq!(withdrawn_at(&log, &id), Some(1));
}

#[test]
fn a_withdrawal_names_an_item_sealed_below_it_and_never_one_waiting() {
    let log = common::Rig::new();
    let (item, payload) = log.page("a", "waiting body");
    log.publish(
        &[(item.clone(), Some(payload))],
        "2026-08-09T12:00:00Z",
        None,
    );
    log.pull("2026-08-09T12:00:05Z");
    let id = common::item_id(&item);
    assert!(matches!(
        withdraw(&log, &id, "2026-08-09T12:30:00Z"),
        Err(clave::Error::Governance(_))
    ));
    let report = log.seal("2026-08-09T13:00:00Z");
    assert_eq!(
        common::sealed_item_ids(&log.entries(0)),
        std::slice::from_ref(&id)
    );
    assert!(report.dropped.is_empty());
    withdraw(&log, &id, "2026-08-09T13:30:00Z").unwrap();
    log.seal("2026-08-09T14:00:00Z");
    assert_eq!(withdrawn_at(&log, &id), Some(1));
}

#[test]
fn a_withdrawn_item_is_not_admitted_at_a_later_pull() {
    let (log, item, published, id) = sealed_log();
    withdraw(&log, &id, "2026-08-09T13:30:00Z").unwrap();
    log.seal("2026-08-09T14:00:00Z");
    let replacement = log.page("a", "a new body under a fresh salt");
    let two = log.publish(
        &[(replacement.0.clone(), Some(replacement.1.clone()))],
        "2026-08-09T14:30:00Z",
        Some(&published),
    );
    log.pull("2026-08-09T14:30:05Z");
    log.seal("2026-08-09T15:00:00Z");
    let payload = wist_core::item::payload_name(&item).unwrap();
    std::fs::write(
        common::collection_dir(&log.p, "default").join(format!("payloads/{payload}.json")),
        b"{}",
    )
    .unwrap();
    log.publish(&[(item.clone(), None)], "2026-08-09T15:30:00Z", Some(&two));
    let report = log.pull("2026-08-09T15:30:05Z");
    assert!(
        report
            .rejected
            .iter()
            .any(|(object, code)| object.ends_with(&id) && code == "WIST2-E03"),
        "{report:?}"
    );
    assert!(!report.items.iter().any(|object| object.ends_with(&id)));
    let sealed = log.seal("2026-08-09T16:00:00Z");
    assert!(common::sealed_item_ids(&log.entries(sealed.epoch_number)).is_empty());
}
