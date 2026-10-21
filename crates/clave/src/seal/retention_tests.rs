use super::hook::{self, BETWEEN_RETENTION_SCAN_AND_WRITE};
use crate::db::Db;
use crate::ingest::stage_tests::{Log, Site};
use std::collections::BTreeSet;
use std::rc::Rc;

const AT: &str = "2026-08-09T12:00:05Z";

struct Hooked;

impl Hooked {
    fn with(hook: impl FnMut() + 'static) -> Hooked {
        hook::set(&BETWEEN_RETENTION_SCAN_AND_WRITE, hook);
        Hooked
    }
}

impl Drop for Hooked {
    fn drop(&mut self) {
        hook::clear(&BETWEEN_RETENTION_SCAN_AND_WRITE);
    }
}

fn retain(log: &Log) {
    super::retain(&log.db, log.data.path(), AT).unwrap();
}

fn racing_pull_once(log: &Log, site: &Rc<Site>, publish: impl FnOnce(&Site) + 'static) -> Hooked {
    let (path, data) = (log.path(), log.data.path().to_path_buf());
    let racing = site.clone();
    let mut publish = Some(publish);
    Hooked::with(move || {
        if let Some(publish) = publish.take() {
            publish(&racing);
            racing
                .pull_into(&Db::connect(&path).unwrap(), &data)
                .unwrap();
        }
    })
}

fn tree_files(log: &Log) -> BTreeSet<String> {
    rusqlite::Connection::open(log.path())
        .unwrap()
        .prepare("SELECT sha256 FROM tree_files")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn duty_held(log: &Log, item_id: &str) -> bool {
    log.db.holds_payload_duty(item_id).unwrap()
}

fn served_file(log: &Log, item_id: &str) -> std::path::PathBuf {
    let path = crate::db::served_payload_path(log.data.path(), item_id).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"{}").unwrap();
    path
}

fn item_id(n: u8) -> String {
    format!("sha256:{}", wist_core::crypto::hex_encode(&[n; 32]))
}

#[test]
fn a_held_payload_a_pull_names_again_between_the_scan_and_the_write_survives_retention() {
    let site = Rc::new(Site::new());
    let log = Log::onboard(&site);
    let first = site.page_item("https://localhost/a", "first page");
    let second = site.page_item("https://localhost/b", "second page");
    site.collection(
        "default",
        std::slice::from_ref(&first),
        "2026-08-09T11:00:00Z",
    );
    log.pull(&site).unwrap();
    let held = crate::db::held_payload_path(
        log.data.path(),
        &wist_core::item::item_id(&first.0).unwrap(),
    )
    .unwrap();
    assert!(held.exists());
    site.collection(
        "default",
        std::slice::from_ref(&second),
        "2026-08-09T11:10:00Z",
    );
    log.pull(&site).unwrap();
    assert!(!log
        .db
        .payload_item_needed(&wist_core::item::item_id(&first.0).unwrap())
        .unwrap());

    let hooked = racing_pull_once(&log, &site, move |site| {
        site.collection("default", &[first], "2026-08-09T11:20:00Z");
    });
    retain(&log);
    drop(hooked);

    assert!(held.exists());
}

#[test]
fn a_tree_file_a_pull_names_again_between_the_scan_and_the_write_survives_retention() {
    let site = Rc::new(Site::new());
    let log = Log::onboard(&site);
    let first = site.page_item("https://localhost/a", "first page");
    let second = site.page_item("https://localhost/b", "second page");
    site.collection(
        "default",
        std::slice::from_ref(&first),
        "2026-08-09T11:00:00Z",
    );
    log.pull(&site).unwrap();
    let first_tree = tree_files(&log);
    assert!(!first_tree.is_empty());
    site.collection(
        "default",
        std::slice::from_ref(&second),
        "2026-08-09T11:10:00Z",
    );
    log.pull(&site).unwrap();
    assert!(tree_files(&log).len() > first_tree.len());

    let hooked = racing_pull_once(&log, &site, move |site| {
        site.collection("default", &[first], "2026-08-09T11:20:00Z");
    });
    retain(&log);
    drop(hooked);

    let held = tree_files(&log);
    assert!(first_tree.is_subset(&held), "{first_tree:?} in {held:?}");
    retain(&log);
    assert_eq!(tree_files(&log), first_tree);
}

#[test]
fn a_duty_that_lapses_between_the_scan_and_the_write_ends_at_the_next_retention() {
    let log = Log::new();
    let (lapsing, extended) = (item_id(1), item_id(2));
    log.db
        .add_payload_duty(
            &extended,
            "a.example",
            "https://a.example/2",
            "2026-08-09T12:00:00Z",
        )
        .unwrap();
    let lapsing_file = served_file(&log, &lapsing);
    let extended_file = served_file(&log, &extended);
    let path = log.path();
    let racing = (lapsing.clone(), extended.clone());
    let hooked = Hooked::with(move || {
        let db = Db::connect(&path).unwrap();
        db.add_payload_duty(
            &racing.0,
            "a.example",
            "https://a.example/1",
            "2026-08-09T12:00:00Z",
        )
        .unwrap();
        db.add_payload_duty(
            &racing.1,
            "a.example",
            "https://a.example/2",
            "2026-08-10T00:00:00Z",
        )
        .unwrap();
    });
    retain(&log);
    drop(hooked);

    assert!(duty_held(&log, &lapsing));
    assert!(lapsing_file.exists());
    assert!(duty_held(&log, &extended));
    assert!(extended_file.exists());

    retain(&log);

    assert!(!duty_held(&log, &lapsing));
    assert!(!lapsing_file.exists());
    assert!(duty_held(&log, &extended));
    assert!(extended_file.exists());
}
