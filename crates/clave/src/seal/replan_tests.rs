use super::between_plan_and_write;
use crate::collection::state::{LabelKind, Place, State, WaitingLabel, WaitingUrl};
use crate::db::Db;
use crate::ingest::stage_tests::{Log, Site};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

struct Hooked;

impl Hooked {
    fn with(hook: impl FnMut() + 'static) -> Hooked {
        between_plan_and_write::set(hook);
        Hooked
    }
}

impl Drop for Hooked {
    fn drop(&mut self) {
        between_plan_and_write::clear();
    }
}

fn seal(log: &Log, at: &str) -> super::SealReport {
    let signing = crate::keys::load(&log.data.path().join("keys/seed")).unwrap();
    super::run(
        &log.db,
        log.data.path(),
        &signing,
        crate::registry::unix(at).unwrap(),
    )
    .unwrap()
}

fn sealed_entries(log: &Log, report: &super::SealReport) -> Vec<serde_json::Value> {
    log.db.epoch_entries(report.epoch_number).unwrap()
}

fn sealed_declarations(entries: &[serde_json::Value]) -> Vec<serde_json::Value> {
    entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_declaration")
        .map(|entry| entry["body"].clone())
        .collect()
}

#[test]
fn a_scoped_write_between_the_plan_and_the_write_transaction_makes_the_seal_seal_a_fresh_plan() {
    let site = Rc::new(Site::new());
    let raced = Log::onboard(&site);
    let serial = Log::onboard(&site);
    let first = site.page_item("https://localhost/a", "first page");
    site.collection(
        "default",
        std::slice::from_ref(&first),
        "2026-08-09T11:00:00Z",
    );
    raced.pull(&site).unwrap();
    serial.pull(&site).unwrap();
    let second = site.page_item("https://localhost/b", "second page");
    site.collection("default", &[first, second], "2026-08-09T12:00:00Z");
    serial.pull(&site).unwrap();

    let (path, data) = (raced.path(), raced.data.path().to_path_buf());
    let racing = site.clone();
    let mut pulls = 0;
    let hooked = Hooked::with(move || {
        if pulls == 0 {
            racing
                .pull_into(&Db::connect(&path).unwrap(), &data)
                .unwrap();
        }
        pulls += 1;
    });
    let raced_report = seal(&raced, "2026-08-09T13:00:00Z");
    drop(hooked);
    let serial_report = seal(&serial, "2026-08-09T13:00:00Z");

    assert_eq!(raced_report.replanned, 1);
    assert_eq!(serial_report.replanned, 0);
    assert_eq!(raced_report.epoch_number, serial_report.epoch_number);
    let entries = sealed_entries(&raced, &raced_report);
    assert_eq!(entries, sealed_entries(&serial, &serial_report));
    assert!(entries.iter().any(|entry| entry["type"] == "publisher_item"
        && entry["body"]["item"]["url"] == "https://localhost/b"));
    assert_eq!(raced_report.dropped, serial_report.dropped);
    assert_eq!(raced_report.late, serial_report.late);
}

#[test]
fn a_write_outside_the_scope_neither_replans_the_seal_nor_loses_its_waiting_work() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let page = site.page_item("https://localhost/a", "a page");
    site.collection("default", &[page], "2026-08-09T11:00:00Z");
    log.pull(&site).unwrap();
    let other = Site::at("other.localhost");
    let declaration = other.read("publisher.json");
    assert!(!log.db.waiting_publishers().unwrap().contains(&other.host));

    let (path, host, written) = (log.path(), other.host.clone(), declaration.clone());
    let hooked = Hooked::with(move || {
        Db::connect(&path)
            .unwrap()
            .hold_discovered_declaration(&host, &written)
            .unwrap();
    });
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    assert_eq!(report.replanned, 0);
    let entries = sealed_entries(&log, &report);
    assert!(entries.iter().any(|entry| entry["type"] == "publisher_item"
        && entry["body"]["item"]["url"] == "https://localhost/a"));
    assert!(!sealed_declarations(&entries).contains(&declaration));
    assert!(log.db.waiting_publishers().unwrap().contains(&other.host));
    assert_eq!(
        log.db.discovered_declarations(&other.host).unwrap(),
        vec![declaration.clone()]
    );

    let next = seal(&log, "2026-08-09T14:00:00Z");
    assert_eq!(next.replanned, 0);
    assert!(sealed_declarations(&sealed_entries(&log, &next)).contains(&declaration));
}

#[test]
fn three_conflicting_plans_fall_back_to_planning_under_the_write_lock_and_the_seal_completes() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let page = site.page_item("https://localhost/a", "a page");
    site.collection("default", &[page], "2026-08-09T11:00:00Z");
    log.pull(&site).unwrap();
    let declaration = site.read("publisher.json");
    let head = log.db.last_epoch().unwrap().unwrap().epoch_number;

    let calls = Rc::new(std::cell::Cell::new(0));
    let (path, host, counted) = (log.path(), site.host.clone(), calls.clone());
    let hooked = Hooked::with(move || {
        counted.set(counted.get() + 1);
        Db::connect(&path)
            .unwrap()
            .hold_discovered_declaration(&host, &declaration)
            .unwrap();
    });
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    assert_eq!(calls.get(), super::PLAN_ATTEMPTS);
    assert_eq!(report.replanned, super::PLAN_ATTEMPTS);
    assert_eq!(report.epoch_number, head + 1);
    assert_eq!(
        log.db.last_epoch().unwrap().unwrap().epoch_number,
        report.epoch_number
    );
    assert!(sealed_entries(&log, &report)
        .iter()
        .any(|entry| entry["type"] == "publisher_item"
            && entry["body"]["item"]["url"] == "https://localhost/a"));
}

#[test]
fn a_seal_over_a_store_missing_its_derived_state_records_it_before_its_read_only_plan() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let page = site.page_item("https://localhost/a", "a page");
    site.collection("default", &[page], "2026-08-09T11:00:00Z");
    log.pull(&site).unwrap();
    let head = log.db.last_epoch().unwrap().unwrap();
    rusqlite::Connection::open(log.path())
        .unwrap()
        .execute("DELETE FROM derived_state", [])
        .unwrap();
    assert!(log.db.derived_declarations(&head).unwrap().is_none());

    let report = seal(&log, "2026-08-09T13:00:00Z");

    assert_eq!(report.epoch_number, head.epoch_number + 1);
    assert_eq!(report.replanned, 0);
    let sealed = log.db.last_epoch().unwrap().unwrap();
    assert!(log.db.derived_declarations(&sealed).unwrap().is_some());
}

#[test]
fn store_changes_bumps_the_version_only_of_publishers_it_writes() {
    let data = tempfile::tempdir().unwrap();
    crate::init::run("127.0.0.1:0", data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    let publishers: BTreeSet<String> = ["a.example", "b.example", "c.example", "d.example"]
        .map(String::from)
        .into();
    let versions = |db: &Db| db.waiting_versions(&publishers).unwrap();
    let expect = |a: i64, b: i64, c: i64| -> BTreeMap<String, i64> {
        [
            ("a.example", a),
            ("b.example", b),
            ("c.example", c),
            ("d.example", 0),
        ]
        .map(|(publisher, version)| (publisher.to_owned(), version))
        .into()
    };
    assert_eq!(versions(&db), expect(0, 0, 0));

    let before = State::default();
    let mut after = before.clone();
    after.urls.insert(
        ("a.example".into(), "https://a.example/x".into()),
        WaitingUrl {
            collection: "default".into(),
            item_id: format!("sha256:{}", "0".repeat(64)),
            place: Place::url(1, 0, 0),
            eligibility: 1,
        },
    );
    after.labels.insert(
        format!("sha256:{}", "1".repeat(64)),
        WaitingLabel {
            kind: LabelKind::Label,
            publisher: "c.example".into(),
            envelope: serde_json::json!({}),
            place: Place::url(1, 0, 1),
            eligibility: 1,
        },
    );
    db.store_state(&before, &after, &publishers, "2026-08-09T12:00:00Z")
        .unwrap();
    assert_eq!(versions(&db), expect(1, 0, 1));

    db.store_state(&after, &after, &publishers, "2026-08-09T12:00:00Z")
        .unwrap();
    assert_eq!(versions(&db), expect(1, 0, 1));

    let mut floor = after.clone();
    floor.floors.insert("b.example".into(), 3);
    db.store_state(&after, &floor, &publishers, "2026-08-09T12:00:00Z")
        .unwrap();
    assert_eq!(versions(&db), expect(1, 1, 1));

    let outside: BTreeSet<String> = ["a.example".to_owned()].into();
    let mut moved = floor.clone();
    moved.floors.insert("b.example".into(), 4);
    db.store_state(&floor, &moved, &outside, "2026-08-09T12:00:00Z")
        .unwrap();
    assert_eq!(versions(&db), expect(1, 1, 1));
}

fn log_with_items_left_waiting_by_the_cap(site: &Site) -> Log {
    let log = Log::onboard(site);
    let items = ["x", "y"].map(|name| site.page_item(&format!("https://localhost/{name}"), "page"));
    site.collection("default", &items, "2026-08-09T11:00:00Z");
    log.pull(site).unwrap();
    log.db.set_param("domain_epoch_entries_max", 1).unwrap();
    log
}

fn first_contact_pull_between_plan_and_write(log: &Log) -> (Hooked, Rc<std::cell::Cell<i64>>) {
    let other = Site::at("other.localhost");
    let (path, data) = (log.path(), log.data.path().to_path_buf());
    let moved = Rc::new(std::cell::Cell::new(0));
    let counted = moved.clone();
    let hooked = Hooked::with(move || {
        if counted.get() == 0 {
            let db = Db::connect(&path).unwrap();
            let before = db.acceptance_clock().unwrap();
            other.pull_into(&db, &data).unwrap();
            counted.set(db.acceptance_clock().unwrap() - before);
        }
    });
    (hooked, moved)
}

#[test]
fn an_unscoped_pull_moving_the_clock_does_not_replan_a_seal_that_placed_nothing_with_its_event() {
    let site = Site::new();
    let log = log_with_items_left_waiting_by_the_cap(&site);
    let (hooked, moved) = first_contact_pull_between_plan_and_write(&log);
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    assert!(moved.get() > 0, "the racing pull moved the clock");
    assert_eq!(report.replanned, 0);
    assert!(log
        .db
        .waiting_publishers()
        .unwrap()
        .contains("other.localhost"));
}

#[test]
fn an_unscoped_pull_moving_the_clock_replans_a_seal_that_placed_a_waiting_url_with_its_event() {
    let site = Site::new();
    let log = log_with_items_left_waiting_by_the_cap(&site);
    let scope = BTreeSet::from([site.host.clone()]);
    let left = (site.host.clone(), "https://localhost/y".to_owned());
    let before = log
        .db
        .load_state(log.db.sealed_state(log.data.path()).unwrap(), &scope)
        .unwrap();
    let mut after = before.clone();
    after.urls.remove(&left);
    log.db
        .store_state(&before, &after, &scope, "2026-08-09T12:00:05Z")
        .unwrap();

    let (hooked, moved) = first_contact_pull_between_plan_and_write(&log);
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    assert!(moved.get() > 0, "the racing pull moved the clock");
    assert_eq!(report.replanned, 1);
    let sealed = log
        .db
        .load_state(log.db.sealed_state(log.data.path()).unwrap(), &scope)
        .unwrap();
    assert_eq!(
        sealed.urls[&left].place.event,
        log.db.acceptance_clock().unwrap() as u64,
        "the refresh placed the URL with the event of the plan that sealed"
    );
}
