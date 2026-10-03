mod common;

use common::*;

#[test]
fn acceptance_counter_exhaustion_rolls_back_the_pull_and_the_seal() {
    let r = Rig::new();
    let (item, payload) = r.page("a", "alpha");
    r.publish(&[(item, Some(payload))], "2026-08-09T12:00:00Z", None);
    rusqlite::Connection::open(r.data.path().join("clave.sqlite"))
        .unwrap()
        .execute("UPDATE acceptance_clock SET position = ?1", [i64::MAX])
        .unwrap();
    assert!(clave::ingest::run(
        &r.db,
        &r.client,
        r.data.path(),
        &r.host,
        "2026-08-09T12:00:05Z"
    )
    .is_err());
    let state = r.state();
    assert!(state.collections.is_empty());
    assert!(state.discovered.is_empty());
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 0);
    assert_eq!(payload_files(r.data.path()), 0);

    rusqlite::Connection::open(r.data.path().join("clave.sqlite"))
        .unwrap()
        .execute("UPDATE acceptance_clock SET position = 0", [])
        .unwrap();
    r.pull("2026-08-09T12:00:05Z");
    rusqlite::Connection::open(r.data.path().join("clave.sqlite"))
        .unwrap()
        .execute("UPDATE acceptance_clock SET position = ?1", [i64::MAX])
        .unwrap();
    let before = r.state();
    assert!(clave::seal::run(
        &r.db,
        r.data.path(),
        &r.sk,
        wist_core::timestamp::log_seconds("2026-08-09T13:00:00Z").unwrap()
    )
    .is_err());
    assert!(r.db.last_epoch().unwrap().is_none());
    let after = r.state();
    assert_eq!(after.collections, before.collections);
    assert_eq!(after.urls, before.urls);
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 1);
}
