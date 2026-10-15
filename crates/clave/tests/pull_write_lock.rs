mod common;

use common::{
    make_publisher_with_scope, page_item, publish_collection, reserve_addr, serve_static,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ITEMS: usize = 500;

fn longest_write_lock_hold(path: std::path::PathBuf, stop: Arc<AtomicBool>) -> Duration {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.busy_timeout(Duration::ZERO).unwrap();
    let mut acquired = Instant::now();
    let mut longest = Duration::ZERO;
    while !stop.load(Ordering::Relaxed) {
        if conn.execute_batch("BEGIN IMMEDIATE").is_ok() {
            conn.execute_batch("COMMIT").unwrap();
            let now = Instant::now();
            longest = longest.max(now - acquired);
            acquired = now;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    longest
}

#[test]
fn a_pull_of_500_payloads_holds_the_write_lock_for_less_than_the_busy_timeout() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let items: Vec<_> = (0..ITEMS)
        .map(|n| {
            let (item, payload) = page_item(
                &p,
                &format!("https://example.com/{n}"),
                &format!("body {n}"),
            );
            (item, Some(payload))
        })
        .collect();
    publish_collection(&p, "default", &items, "2026-08-09T12:00:00Z", None);
    serve_static(listener, p.dir.path().to_path_buf());
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let started_at = jiff::Timestamp::now().as_second();
    db.schedule_ping(&host, started_at, 4).unwrap();
    let task = db
        .claim_pulls(
            started_at,
            1,
            "me",
            clave::db::PARTITIONS as usize,
            &[],
            &mut true,
            true,
        )
        .unwrap()
        .remove(0);

    let stop = Arc::new(AtomicBool::new(false));
    let watcher = {
        let path = tmp.path().join("clave.sqlite");
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || longest_write_lock_hold(path, stop))
    };
    let run = clave::ingest::open_pull(
        &db,
        &client,
        tmp.path(),
        &host,
        &clave::registry::instant(started_at).unwrap(),
        jiff::Timestamp::now,
        clave::ingest::PullLimits::default(),
    )
    .unwrap();
    let report = clave::ingest::finish_pull(&db, &task, "me", started_at, run, started_at).unwrap();
    stop.store(true, Ordering::Relaxed);
    let longest = watcher.join().unwrap();

    assert_eq!(report.items.len(), ITEMS);
    let held = std::fs::read_dir(tmp.path().join("held/payloads"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".json")
        })
        .count();
    assert_eq!(held, ITEMS);
    eprintln!("longest write-lock hold during the pull: {longest:?}");
    assert!(longest < Duration::from_secs(5), "{longest:?}");
}
