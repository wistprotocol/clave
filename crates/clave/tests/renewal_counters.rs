use std::time::Duration;

fn renew_while_the_write_lock_is_held(path: &std::path::Path, uncounted: bool) {
    let holder = rusqlite::Connection::open(path).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    let renewing = path.to_path_buf();
    let renewal = std::thread::spawn(move || {
        if uncounted {
            clave::db::exclude_thread_from_counters();
        }
        let db = clave::db::Db::connect(&renewing).unwrap();
        db.renew_sealer_lease("sealer", 1, 0, 60).unwrap();
    });
    std::thread::sleep(Duration::from_millis(300));
    holder.execute_batch("COMMIT").unwrap();
    renewal.join().unwrap();
}

#[test]
fn a_renewal_on_an_excluded_thread_moves_neither_the_engine_time_nor_the_write_wait() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("clave.sqlite");
    drop(clave::db::Db::open(&path).unwrap());

    let (nanos, waited) = (
        clave::db::sqlite_nanos(),
        clave::db::longest_write_wait_ms(),
    );
    renew_while_the_write_lock_is_held(&path, true);
    assert_eq!(clave::db::sqlite_nanos(), nanos);
    assert_eq!(clave::db::longest_write_wait_ms(), waited);

    renew_while_the_write_lock_is_held(&path, false);
    assert!(clave::db::sqlite_nanos() - nanos >= 200_000_000);
    assert!(clave::db::longest_write_wait_ms() >= 200);
}
