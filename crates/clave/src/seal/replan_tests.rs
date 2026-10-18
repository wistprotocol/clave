use super::hook::{self, Point, BETWEEN_PLAN_AND_WRITE};
use crate::collection::plan::{defer_eligibility, Deferral, Deferred, Publication};
use crate::collection::state::{
    AcceptedCatalog, Admission, CollectionState, ItemKind, LabelKind, ListItem, Place, Record,
    SealedCatalog, State, WaitingLabel, WaitingUrl,
};
use crate::db::Db;
use crate::ingest::stage_tests::{Log, Site};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

struct Hooked(Point);

impl Hooked {
    fn with(hook: impl FnMut() + 'static) -> Hooked {
        hook::set(&BETWEEN_PLAN_AND_WRITE, hook);
        Hooked(&BETWEEN_PLAN_AND_WRITE)
    }
}

impl Drop for Hooked {
    fn drop(&mut self) {
        hook::clear(self.0);
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

fn scoped_state(log: &Log, host: &str) -> State {
    log.db
        .load_state(
            log.db.sealed_state(log.data.path()).unwrap(),
            &BTreeSet::from([host.to_owned()]),
        )
        .unwrap()
}

fn sealed_items(entries: &[serde_json::Value]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_item")
        .map(|entry| entry["body"]["item"]["url"].as_str().unwrap().to_owned())
        .collect()
}

fn sealed_label_ids(entries: &[serde_json::Value]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| entry["type"] == "label")
        .map(|entry| wist_core::label::label_id(&entry["body"]["label"]).unwrap())
        .collect()
}

type Reserved = Rc<std::cell::Cell<Option<(u64, u64)>>>;

fn racing_pull_once(log: &Log, site: &Rc<Site>) -> (Hooked, Reserved) {
    let (path, data) = (log.path(), log.data.path().to_path_buf());
    let racing = site.clone();
    let reserved = Reserved::default();
    let seen = reserved.clone();
    let mut pulls = 0;
    let hooked = Hooked::with(move || {
        if pulls == 0 {
            let db = Db::connect(&path).unwrap();
            seen.set(db.sealing_reservation().unwrap());
            racing.pull_into(&db, &data).unwrap();
        }
        pulls += 1;
    });
    (hooked, reserved)
}

fn epoch_event(reserved: &Reserved, report: &super::SealReport) -> u64 {
    let (epoch_number, event) = reserved.get().expect("the seal reserved its event");
    assert_eq!(epoch_number, report.epoch_number);
    event
}

#[test]
fn a_catalog_a_pull_accepts_during_the_plan_follows_the_epoch_that_seals_the_one_it_replaces() {
    let site = Rc::new(Site::new());
    let log = Log::onboard(&site);
    let first = site.page_item("https://localhost/a", "first page");
    site.collection(
        "default",
        std::slice::from_ref(&first),
        "2026-08-09T11:00:00Z",
    );
    log.pull(&site).unwrap();
    let sealed_catalog = scoped_state(&log, &site.host).collections
        [&(site.host.clone(), "default".to_owned())]
        .accepted
        .as_ref()
        .unwrap()
        .catalog_id
        .clone();
    let second = site.page_item("https://localhost/b", "second page");
    site.collection("default", &[first.clone(), second], "2026-08-09T12:00:00Z");

    let (hooked, reserved) = racing_pull_once(&log, &site);
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);
    let event = epoch_event(&reserved, &report);

    assert_eq!(report.replanned, 0);
    assert!(report.conflicts.is_empty());
    assert_eq!(report.merged, vec![site.host.clone()]);
    assert!(report.late.is_empty());
    let entries = sealed_entries(&log, &report);
    assert_eq!(
        sealed_items(&entries),
        vec!["https://localhost/a".to_owned()]
    );
    let catalogs: Vec<String> = entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_catalog")
        .map(|entry| wist_core::catalog::catalog_id(&entry["body"]["catalog"]).unwrap())
        .collect();
    assert_eq!(catalogs, vec![sealed_catalog.clone()]);
    let after = scoped_state(&log, &site.host);
    let collection = &after.collections[&(site.host.clone(), "default".to_owned())];
    assert_eq!(
        collection.latest.as_ref().unwrap().catalog_id,
        sealed_catalog
    );
    let replacement = collection.waiting().unwrap();
    assert_ne!(replacement.catalog_id, sealed_catalog);
    assert!(
        replacement.place.event > event,
        "the replacement's place {} follows the Epoch's event {event}",
        replacement.place.event
    );
    assert_eq!(replacement.eligibility, report.epoch_number + 1);
    let waiting = &after.urls[&(site.host.clone(), "https://localhost/b".to_owned())];
    assert!(waiting.place.event > event);
    assert_eq!(waiting.eligibility, report.epoch_number + 1);
    assert!(!after
        .urls
        .contains_key(&(site.host.clone(), "https://localhost/a".to_owned())));
    assert_eq!(
        after
            .record(&site.host, "https://localhost/a")
            .unwrap()
            .item_id,
        wist_core::item::item_id(&first.0).unwrap()
    );
    assert!(log.db.sealing_reservation().unwrap().is_none());

    let next = seal(&log, "2026-08-09T14:00:00Z");
    assert_eq!(next.replanned, 0);
    assert!(next.late.is_empty());
    let entries = sealed_entries(&log, &next);
    assert_eq!(
        sealed_items(&entries),
        vec!["https://localhost/b".to_owned()]
    );
    assert!(entries
        .iter()
        .any(|entry| entry["type"] == "publisher_catalog"
            && wist_core::catalog::catalog_id(&entry["body"]["catalog"]).unwrap()
                == replacement.catalog_id));
    assert!(scoped_state(&log, &site.host).urls.is_empty());
}

#[test]
fn labels_a_pull_accepts_during_the_plan_are_eligible_for_the_next_epoch_beside_the_labels_the_plan_seals(
) {
    let site = Rc::new(Site::new());
    let earlier = site.label("https://other.example/a", "2026-08-09T10:00:00Z");
    site.label_feed(std::slice::from_ref(&earlier), "2026-08-09T10:00:00Z", None);
    let log = Log::onboard(&site);
    log.pull(&site).unwrap();
    assert!(scoped_state(&log, &site.host).labels.contains_key(&earlier));
    let later = site.label("https://other.example/b", "2026-08-09T11:00:00Z");
    site.label_feed(
        &[later.clone(), earlier.clone()],
        "2026-08-09T11:00:00Z",
        None,
    );

    let (hooked, reserved) = racing_pull_once(&log, &site);
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);
    let event = epoch_event(&reserved, &report);

    assert_eq!(report.replanned, 0);
    assert_eq!(
        sealed_label_ids(&sealed_entries(&log, &report)),
        vec![earlier.clone()]
    );
    let waiting = scoped_state(&log, &site.host).labels;
    assert_eq!(
        waiting.keys().cloned().collect::<Vec<_>>(),
        vec![later.clone()]
    );
    assert_eq!(waiting[&later].eligibility, report.epoch_number + 1);
    assert!(waiting[&later].place.event > event);

    let next = seal(&log, "2026-08-09T14:00:00Z");
    assert_eq!(next.replanned, 0);
    assert!(next.late.is_empty());
    assert_eq!(sealed_label_ids(&sealed_entries(&log, &next)), vec![later]);
    assert!(scoped_state(&log, &site.host).labels.is_empty());
}

#[test]
fn a_racing_write_of_an_in_scope_publisher_s_discovered_declaration_replans_instead_of_merging() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let page = site.page_item("https://localhost/a", "a page");
    site.collection("default", &[page], "2026-08-09T11:00:00Z");
    log.pull(&site).unwrap();
    let declaration = site.read("publisher.json");

    let (path, host) = (log.path(), site.host.clone());
    let mut writes = 0;
    let hooked = Hooked::with(move || {
        if writes == 0 {
            Db::connect(&path)
                .unwrap()
                .hold_discovered_declaration(&host, &declaration)
                .unwrap();
        }
        writes += 1;
    });
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    assert_eq!(report.replanned, 1);
    assert_eq!(report.conflicts, vec![vec![site.host.clone()]]);
    assert!(report.merged.is_empty());
    assert_eq!(
        sealed_items(&sealed_entries(&log, &report)),
        vec!["https://localhost/a".to_owned()]
    );
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
    assert!(report.conflicts.is_empty());
    assert!(report.merged.is_empty());
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
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE discovered_declarations SET event = event + 1 WHERE domain = ?1",
                [&host],
            )
            .unwrap();
    });
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    assert_eq!(calls.get(), super::PLAN_ATTEMPTS);
    assert_eq!(report.replanned, super::PLAN_ATTEMPTS);
    assert_eq!(report.conflicts.len(), super::PLAN_ATTEMPTS);
    assert!(report.merged.is_empty());
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

type ClockMove = Rc<std::cell::Cell<Option<(i64, i64)>>>;

fn first_contact_pull_between_plan_and_write(log: &Log) -> (Hooked, ClockMove) {
    let other = Site::at("other.localhost");
    let (path, data) = (log.path(), log.data.path().to_path_buf());
    let moved = Rc::new(std::cell::Cell::new(None));
    let counted = moved.clone();
    let hooked = Hooked::with(move || {
        if counted.get().is_none() {
            let db = Db::connect(&path).unwrap();
            let before = db.acceptance_clock().unwrap();
            other.pull_into(&db, &data).unwrap();
            counted.set(Some((before, db.acceptance_clock().unwrap())));
        }
    });
    (hooked, moved)
}

fn clock_moved(moved: &std::cell::Cell<Option<(i64, i64)>>) -> (i64, i64) {
    let (before, after) = moved.get().expect("the racing pull ran");
    assert!(after > before, "the racing pull moved the clock");
    (before, after)
}

#[test]
fn an_unscoped_pull_moving_the_clock_does_not_replan_a_seal_that_placed_nothing_with_its_event() {
    let site = Site::new();
    let log = log_with_items_left_waiting_by_the_cap(&site);
    let (hooked, moved) = first_contact_pull_between_plan_and_write(&log);
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    clock_moved(&moved);
    assert_eq!(report.replanned, 0);
    assert!(log
        .db
        .waiting_publishers()
        .unwrap()
        .contains("other.localhost"));
}

#[test]
fn a_url_the_seal_places_with_its_event_precedes_an_unscoped_pull_without_replanning() {
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

    let (reserved, pulled) = clock_moved(&moved);
    assert_eq!(report.replanned, 0);
    let sealed = log
        .db
        .load_state(log.db.sealed_state(log.data.path()).unwrap(), &scope)
        .unwrap();
    let place = sealed.urls[&left].place.event;
    assert_eq!(place, reserved as u64, "the URL holds the Epoch's event");
    assert!(
        place < pulled as u64,
        "the Epoch's place {place} precedes the racing pull's event {pulled}"
    );
}

#[test]
fn a_first_contact_pull_during_the_plan_waits_for_the_next_epoch_above_the_epoch_s_event() {
    let site = Site::new();
    let log = log_with_items_left_waiting_by_the_cap(&site);
    let (hooked, moved) = first_contact_pull_between_plan_and_write(&log);
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    let (reserved, _) = clock_moved(&moved);
    assert_eq!(report.replanned, 0);
    assert!(log.db.sealing_reservation().unwrap().is_none());
    let other = scoped_state(&log, "other.localhost");
    let first = other
        .collections
        .iter()
        .filter(|((publisher, _), _)| publisher == "other.localhost")
        .filter_map(|(_, collection)| collection.waiting())
        .collect::<Vec<_>>();
    assert!(
        !first.is_empty(),
        "the first-contact pull left a Catalog waiting"
    );
    for waiting in first {
        assert!(waiting.place.event > reserved as u64);
        assert_eq!(waiting.eligibility, report.epoch_number + 1);
    }
    for waiting in other.discovered.values().flatten() {
        assert!(waiting.event > reserved as u64);
    }
}

#[test]
fn a_reservation_at_or_below_the_sealed_head_defers_no_eligibility() {
    let site = Site::new();
    let log = log_with_items_left_waiting_by_the_cap(&site);
    let head = log.db.last_epoch().unwrap().unwrap().epoch_number;
    let mutation = log.db.mutation().unwrap();
    log.db.reserve_epoch_event(head).unwrap();
    mutation.commit().unwrap();
    let state = scoped_state(&log, &site.host);
    assert_eq!(state.sealing, None);
    assert_eq!(state.first_epoch_after(), head + 1);
    assert_eq!(log.db.next_eligible_epoch().unwrap(), head + 1);

    let mutation = log.db.mutation().unwrap();
    log.db.reserve_epoch_event(head + 1).unwrap();
    mutation.commit().unwrap();
    let state = scoped_state(&log, &site.host);
    assert_eq!(state.sealing, Some(head + 1));
    assert_eq!(state.first_epoch_after(), head + 2);
    assert_eq!(log.db.next_eligible_epoch().unwrap(), head + 2);
}

fn reserve_next(log: &Log) -> (u64, u64) {
    let next = super::prepare::next_epoch_number(&log.db).unwrap();
    (next, log.db.reserve_epoch_event(next).unwrap())
}

fn sealed_catalog_ids(entries: &[serde_json::Value]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_catalog")
        .map(|entry| wist_core::catalog::catalog_id(&entry["body"]["catalog"]).unwrap())
        .collect()
}

fn accepted_id(log: &Log, host: &str) -> String {
    scoped_state(log, host).collections[&(host.to_owned(), "default".to_owned())]
        .accepted
        .as_ref()
        .unwrap()
        .catalog_id
        .clone()
}

#[test]
fn a_catalog_a_pull_accepts_between_the_reservation_and_the_plan_is_sealed_in_the_waiting_one_s_stead(
) {
    let site = Site::new();
    let log = Log::onboard(&site);
    let first = site.page_item("https://localhost/a", "first page");
    site.collection(
        "default",
        std::slice::from_ref(&first),
        "2026-08-09T11:00:00Z",
    );
    log.pull(&site).unwrap();
    let replaced = accepted_id(&log, &site.host);
    let (next, event) = reserve_next(&log);
    let second = site.page_item("https://localhost/b", "second page");
    site.collection("default", &[first.clone(), second], "2026-08-09T12:00:00Z");
    log.pull(&site).unwrap();
    let replacement = accepted_id(&log, &site.host);
    assert_ne!(replacement, replaced);

    let report = seal(&log, "2026-08-09T13:00:00Z");

    assert_eq!(report.epoch_number, next);
    assert_eq!(report.replanned, 0);
    assert!(report.late.is_empty());
    let entries = sealed_entries(&log, &report);
    assert_eq!(sealed_catalog_ids(&entries), vec![replacement]);
    assert_eq!(
        sealed_items(&entries),
        vec!["https://localhost/a".to_owned()]
    );
    let after = scoped_state(&log, &site.host);
    let waiting = &after.urls[&(site.host.clone(), "https://localhost/b".to_owned())];
    assert!(
        waiting.place.event > event,
        "the pull's place {} follows the Epoch's event {event}",
        waiting.place.event
    );
    assert_eq!(waiting.eligibility, next + 1);
}

#[test]
fn a_reservation_left_behind_is_the_epoch_s_event_and_what_follows_it_seals_at_the_next_epoch() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let (next, event) = reserve_next(&log);
    assert_eq!(log.db.reserve_epoch_event(next).unwrap(), event);
    let page = site.page_item("https://localhost/a", "a page");
    site.collection("default", &[page], "2026-08-09T11:00:00Z");
    log.pull(&site).unwrap();
    let pulled = scoped_state(&log, &site.host);
    let catalog = pulled
        .collection(&site.host, "default")
        .and_then(CollectionState::waiting)
        .unwrap();
    assert!(catalog.place.event > event);
    assert_eq!(catalog.eligibility, next + 1);
    let url = &pulled.urls[&(site.host.clone(), "https://localhost/a".to_owned())];
    assert!(url.place.event > event);
    assert_eq!(url.eligibility, next + 1);

    let seen = Rc::new(std::cell::Cell::new(None));
    let (path, reserved) = (log.path(), seen.clone());
    let hooked = Hooked::with(move || {
        reserved.set(Db::connect(&path).unwrap().sealing_reservation().unwrap());
    });
    let report = seal(&log, "2026-08-09T13:00:00Z");
    drop(hooked);

    assert_eq!(seen.get(), Some((next, event)));
    assert_eq!(report.epoch_number, next);
    assert_eq!(report.replanned, 0);
    let entries = sealed_entries(&log, &report);
    assert!(sealed_catalog_ids(&entries).is_empty());
    assert!(sealed_items(&entries).is_empty());
    assert!(log.db.sealing_reservation().unwrap().is_none());

    let following = seal(&log, "2026-08-09T14:00:00Z");
    assert!(following.late.is_empty());
    let entries = sealed_entries(&log, &following);
    assert_eq!(sealed_catalog_ids(&entries).len(), 1);
    assert_eq!(
        sealed_items(&entries),
        vec!["https://localhost/a".to_owned()]
    );
}

fn accepted(catalog_id: &str, eligibility: u64) -> CollectionState {
    CollectionState {
        accepted: Some(AcceptedCatalog {
            envelope: serde_json::json!({"catalog": {"generated_at": "2026-08-09T11:00:00Z"}}),
            catalog_id: catalog_id.into(),
            key: "key".into(),
            base_against_floor: false,
            failed_c1: false,
            failed_c4: false,
            place: Place::catalog(3, 0),
            eligibility,
            read: Vec::new(),
        }),
        ..CollectionState::default()
    }
}

fn waiting_label(publisher: &str) -> WaitingLabel {
    WaitingLabel {
        kind: LabelKind::Label,
        publisher: publisher.into(),
        envelope: serde_json::json!({}),
        place: Place::url(3, 0, 0),
        eligibility: 4,
    }
}

#[test]
fn a_merge_keeps_the_plan_s_deferral_for_the_catalog_a_pull_put_in_the_deferred_one_s_place() {
    let (publisher, height) = ("p.example", 4);
    let key = (publisher.to_owned(), "default".to_owned());
    let x = format!("sha256:{}", "a".repeat(64));
    let y = format!("sha256:{}", "b".repeat(64));
    let mut before = State::default();
    before.collections.insert(key.clone(), accepted(&x, height));
    let mut planned = before.clone();
    planned
        .collections
        .insert(key.clone(), accepted(&x, height + 1));
    let mut current = before.clone();
    current
        .collections
        .insert(key.clone(), accepted(&y, height));

    let mut base = before.clone();
    let fresh = super::merge::Fresh::new(5, 9, height + 1);
    super::merge::splice(&mut base, &current, &mut planned, publisher, &fresh).unwrap();
    let deferred = [Deferred {
        publication: Publication::Catalog {
            publisher: publisher.into(),
            collection: "default".into(),
            catalog: x,
        },
        place: Place::catalog(3, 0),
        reasons: vec![Deferral::Capacity],
    }];
    defer_eligibility(&mut planned, &deferred, height, Some(publisher));

    let waiting = planned.collections[&key].waiting().unwrap();
    assert_eq!(waiting.catalog_id, y);
    assert_eq!(waiting.eligibility, height + 1);
    assert_eq!(base.collections[&key], current.collections[&key]);
}

#[test]
fn a_merge_drops_the_labels_the_plan_sealed_and_keeps_those_the_pull_accepted() {
    let publisher = "p.example";
    let (sealed, accepted_later) = (
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
    );
    let mut before = State::default();
    before
        .labels
        .insert(sealed.clone(), waiting_label(publisher));
    let mut planned = before.clone();
    planned.labels.remove(&sealed);
    let mut current = before.clone();
    current
        .labels
        .insert(accepted_later.clone(), waiting_label(publisher));

    let mut base = before.clone();
    let fresh = super::merge::Fresh::new(2, 9, 5);
    super::merge::splice(&mut base, &current, &mut planned, publisher, &fresh).unwrap();

    assert_eq!(
        planned.labels.keys().cloned().collect::<Vec<_>>(),
        vec![accepted_later]
    );
    assert_eq!(base.labels, current.labels);
}

#[test]
fn a_merge_refuses_a_collection_the_plan_and_the_pull_both_rewrote() {
    let publisher = "p.example";
    let key = (publisher.to_owned(), "default".to_owned());
    let x = format!("sha256:{}", "a".repeat(64));
    let y = format!("sha256:{}", "b".repeat(64));
    let mut before = State::default();
    before.collections.insert(key.clone(), accepted(&x, 4));
    let mut planned = before.clone();
    if let Some(accepted) = planned
        .collections
        .get_mut(&key)
        .and_then(|collection| collection.accepted.as_mut())
    {
        accepted.failed_c4 = true;
    }
    let mut current = before.clone();
    current.collections.insert(key, accepted(&y, 4));

    let mut base = before.clone();
    let fresh = super::merge::Fresh::new(5, 9, 5);
    assert!(super::merge::splice(&mut base, &current, &mut planned, publisher, &fresh).is_err());
}

#[test]
fn a_deferral_report_follows_the_place_to_the_catalog_and_item_a_pull_put_there() {
    let mut state = State::default();
    state.collections.insert(
        ("p.example".into(), "default".into()),
        accepted("sha256:y", 7),
    );
    state.urls.insert(
        ("p.example".into(), "https://p.example/a".into()),
        WaitingUrl {
            collection: "default".into(),
            item_id: "sha256:new".into(),
            place: Place::url(1, 0, 0),
            eligibility: 7,
        },
    );
    let mut catalog = super::merge::Publication::Catalog {
        publisher: "p.example".into(),
        collection: "default".into(),
        catalog: "sha256:x".into(),
    };
    assert!(super::merge::follows_place(&state, &mut catalog));
    assert!(
        matches!(catalog, super::merge::Publication::Catalog { catalog, .. } if catalog == "sha256:y")
    );
    let mut item = super::merge::Publication::Item {
        publisher: "p.example".into(),
        collection: "default".into(),
        url: "https://p.example/a".into(),
        item: "sha256:old".into(),
    };
    assert!(super::merge::follows_place(&state, &mut item));
    assert!(matches!(item, super::merge::Publication::Item { item, .. } if item == "sha256:new"));
    let mut gone = super::merge::Publication::Item {
        publisher: "p.example".into(),
        collection: "default".into(),
        url: "https://p.example/b".into(),
        item: "sha256:old".into(),
    };
    assert!(!super::merge::follows_place(&state, &mut gone));
}

fn sealed_as_latest(collection: &mut CollectionState, catalog_id: &str) {
    collection.latest = Some(SealedCatalog {
        envelope: serde_json::json!({"catalog": {"generated_at": "2026-08-09T10:00:00Z"}}),
        catalog_id: catalog_id.into(),
        sealing_height: 4,
        base: false,
    });
}

fn replaced_in_place(height: u64) -> (String, State, State, String) {
    let publisher = "p.example".to_owned();
    let key = (publisher.clone(), "default".to_owned());
    let x = format!("sha256:{}", "a".repeat(64));
    let y = format!("sha256:{}", "b".repeat(64));
    let mut before = State::default();
    before.collections.insert(key.clone(), accepted(&x, height));
    let mut current = before.clone();
    current.collections.insert(key, accepted(&y, height));
    (publisher, before, current, y)
}

#[test]
fn a_replacement_of_a_catalog_the_epoch_sealed_takes_a_fresh_place_eligible_for_the_next_epoch() {
    let height = 4;
    let (publisher, before, current, y) = replaced_in_place(height);
    let key = (publisher.clone(), "default".to_owned());
    let mut planned = before.clone();
    let x = before.collections[&key]
        .accepted
        .as_ref()
        .unwrap()
        .catalog_id
        .clone();
    sealed_as_latest(planned.collections.get_mut(&key).unwrap(), &x);
    assert!(planned.collections[&key].waiting().is_none());

    let mut base = before.clone();
    let fresh = super::merge::Fresh::new(5, 9, height + 1);
    super::merge::splice(&mut base, &current, &mut planned, &publisher, &fresh).unwrap();

    let waiting = planned.collections[&key].waiting().unwrap();
    assert_eq!(waiting.catalog_id, y);
    assert_eq!(waiting.place, Place::catalog(9, 0));
    assert_eq!(waiting.eligibility, height + 1);
}

#[test]
fn a_replacement_of_a_catalog_the_epoch_deferred_keeps_its_place_and_the_plan_s_eligibility() {
    let height = 4;
    let (publisher, before, current, y) = replaced_in_place(height);
    let key = (publisher.clone(), "default".to_owned());
    let mut planned = before.clone();
    let x = before.collections[&key]
        .accepted
        .as_ref()
        .unwrap()
        .catalog_id
        .clone();
    planned
        .collections
        .insert(key.clone(), accepted(&x, height + 1));

    let mut base = before.clone();
    let fresh = super::merge::Fresh::new(5, 9, height + 1);
    super::merge::splice(&mut base, &current, &mut planned, &publisher, &fresh).unwrap();

    let waiting = planned.collections[&key].waiting().unwrap();
    assert_eq!(waiting.catalog_id, y);
    assert_eq!(waiting.place, Place::catalog(3, 0));
    assert_eq!(waiting.eligibility, height + 1);
}

#[test]
fn a_merge_refuses_a_replacement_catalog_that_omits_a_record_the_epoch_seals_under_the_old_latest()
{
    let (publisher, mut before, mut current, y) = replaced_in_place(4);
    let key = (publisher.clone(), "default".to_owned());
    let x = before.collections[&key]
        .accepted
        .as_ref()
        .unwrap()
        .catalog_id
        .clone();
    for state in [&mut before, &mut current] {
        sealed_as_latest(state.collections.get_mut(&key).unwrap(), &x);
    }
    current
        .lists
        .insert((publisher.clone(), "default".into(), y.clone()), Vec::new());
    let mut planned = before.clone();
    planned.records.insert(
        (publisher.clone(), "https://p.example/a".into()),
        Record {
            item: serde_json::json!({}),
            item_id: "sha256:a".into(),
            collection: "default".into(),
            catalog_id: x,
            generated_at: "2026-08-09T10:00:00Z".into(),
            sealing_height: 4,
        },
    );

    let mut base = before.clone();
    let fresh = super::merge::Fresh::new(5, 9, 5);
    let refused =
        super::merge::splice(&mut base, &current, &mut planned, &publisher, &fresh).unwrap_err();
    assert!(
        refused.contains("does not list https://p.example/a"),
        "{refused}"
    );
}

#[test]
fn a_merge_refuses_a_replacement_of_a_catalog_whose_item_the_epoch_refused() {
    let (publisher, mut before, current, _) = replaced_in_place(4);
    let key = (publisher.clone(), "default".to_owned());
    let x = before.collections[&key]
        .accepted
        .as_ref()
        .unwrap()
        .catalog_id
        .clone();
    let list_key = (publisher.clone(), "default".to_owned(), x);
    let row = |admission| ListItem {
        url: "https://p.example/a".into(),
        item_id: "sha256:a".into(),
        kind: ItemKind::Page,
        admission,
        code: None,
        read: Vec::new(),
    };
    before
        .lists
        .insert(list_key.clone(), vec![row(Admission::Admitted)]);
    let mut current = current;
    current.lists = before.lists.clone();
    let mut planned = before.clone();
    planned
        .lists
        .insert(list_key, vec![row(Admission::Refused)]);

    let mut base = before.clone();
    let fresh = super::merge::Fresh::new(5, 9, 5);
    let refused =
        super::merge::splice(&mut base, &current, &mut planned, &publisher, &fresh).unwrap_err();
    assert!(refused.contains("the Epoch refused an Item"), "{refused}");
}
