mod common;

fn sealed_withdrawal() -> common::Rig {
    let log = common::Rig::new();
    let (item, payload) = log.page("a", "withdrawable body");
    log.publish(
        &[(item.clone(), Some(payload))],
        "2026-08-09T12:00:00Z",
        None,
    );
    log.pull("2026-08-09T12:00:05Z");
    log.seal("2026-08-09T13:00:00Z");
    clave::governance::withdraw(
        &log.db,
        &log.sk,
        &log.host,
        &common::item_id(&item),
        "court order",
        "DE",
        wist_core::timestamp::log_seconds("2026-08-09T13:30:00Z").unwrap(),
    )
    .unwrap();
    assert_eq!(log.seal("2026-08-09T14:00:00Z").entry_count, 1);
    log
}

#[test]
fn a_seal_leaves_the_derived_state_of_its_epoch_and_a_resumed_history_equals_the_replay() {
    let log = sealed_withdrawal();
    let head = log.db.last_epoch().unwrap().unwrap();
    assert!(log.db.derived_declarations(&head).unwrap().is_some());
    assert_eq!(log.db.accepted_updates().unwrap().len(), 1);
    common::assert_resumes_as_replayed(&log.db, log.data.path());
}

#[test]
fn a_store_without_derived_state_fills_it_at_its_first_resume_and_then_resumes_as_replayed() {
    let log = sealed_withdrawal();
    let path = log.data.path().join("clave.sqlite");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DELETE FROM derived_state; DELETE FROM accepted_updates;")
        .unwrap();
    let db = clave::db::Db::open(&path).unwrap();
    let head = db.last_epoch().unwrap().unwrap();
    assert!(db.derived_declarations(&head).unwrap().is_none());
    let resumed = clave::history::History::resume(&db, log.data.path()).unwrap();
    assert_eq!(resumed.height(), Some(head.epoch_number));
    assert!(db.derived_declarations(&head).unwrap().is_some());
    assert_eq!(db.accepted_updates().unwrap().len(), 1);
    common::assert_resumes_as_replayed(&db, log.data.path());
}

#[test]
fn derived_state_naming_another_root_is_not_resumed_from() {
    let log = sealed_withdrawal();
    let path = log.data.path().join("clave.sqlite");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "UPDATE derived_state SET root = 'sha256:other'; DELETE FROM accepted_updates;",
        )
        .unwrap();
    let head = log.db.last_epoch().unwrap().unwrap();
    assert!(log.db.derived_declarations(&head).unwrap().is_none());
    clave::history::History::resume(&log.db, log.data.path()).unwrap();
    assert!(log.db.derived_declarations(&head).unwrap().is_some());
    assert_eq!(log.db.accepted_updates().unwrap().len(), 1);
    common::assert_resumes_as_replayed(&log.db, log.data.path());
}
