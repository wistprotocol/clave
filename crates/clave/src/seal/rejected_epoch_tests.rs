#[path = "../../tests/common/mod.rs"]
mod common;

use crate::ingest::stage_tests::{Log, Site};
use serde_json::{json, Value};
use wist_core::crypto::SigningKey;
use wist_core::objects::StateEntry;

const URL: &str = "https://localhost/a";
const COLLECTION: &str = "default";
const OTHER: &str = "other.example";

fn unix(at: &str) -> i64 {
    crate::registry::unix(at).unwrap()
}

fn first_contact(seed: &[u8; 32]) -> Value {
    let publisher = json!({
        "wist_version": "1.0.0",
        "domain": OTHER,
        "keys": [common::key_entry(seed, "2026-08-09T00:00:00Z")],
        "seq": 0,
    });
    let envelope = wist_core::envelope::sign_envelope(
        &publisher,
        "publisher",
        &common::kid(seed),
        &SigningKey::from_seed(seed),
    )
    .unwrap();
    json!({"type": "publisher_declaration", "body": envelope})
}

fn seal_with_conflicting_declarations(log: &Log, at: &str) -> u64 {
    let signing = crate::keys::load(&log.data.path().join("keys/seed")).unwrap();
    let mutation = log.db.mutation().unwrap();
    let next = super::prepare::next_epoch_number(&log.db).unwrap();
    let event = log.db.reserve_epoch_event(next).unwrap();
    let mut prepared =
        super::prepare::epoch(&log.db, log.data.path(), &signing, unix(at), event).unwrap();
    for kind in ["publisher_catalog", "publisher_item"] {
        assert!(
            prepared.entries.iter().any(|entry| entry["type"] == kind),
            "the planned Epoch carries a {kind}"
        );
    }
    prepared.entries.push(first_contact(&[7u8; 32]));
    prepared.entries.push(first_contact(&[8u8; 32]));
    wist_core::epoch::sort_entries(&mut prepared.entries).unwrap();
    prepared.octets = wist_core::epoch::epoch_octets(&prepared.entries).unwrap();
    prepared.planned.judged = None;
    let height = prepared.epoch_number;
    super::publish::epoch(
        &log.db,
        log.data.path(),
        &crate::fetch::Client::new(false),
        mutation,
        prepared,
    )
    .unwrap();
    height
}

fn read(log: &Log) -> rusqlite::Connection {
    rusqlite::Connection::open(log.path()).unwrap()
}

fn record_height(log: &Log, host: &str) -> Option<i64> {
    rusqlite::OptionalExtension::optional(read(log).query_row(
        "SELECT sealing_height FROM records WHERE publisher = ?1 AND url = ?2",
        (host, URL),
        |row| row.get(0),
    ))
    .unwrap()
}

fn latest_catalog(log: &Log, host: &str) -> Option<(Option<Vec<u8>>, Option<i64>)> {
    rusqlite::OptionalExtension::optional(read(log).query_row(
        "SELECT latest_envelope, latest_height FROM collections WHERE publisher = ?1 AND name = ?2",
        (host, COLLECTION),
        |row| Ok((row.get(0)?, row.get(1)?)),
    ))
    .unwrap()
}

fn sealed_item_heights(log: &Log, id: &str) -> Vec<u64> {
    log.db
        .sealed_items()
        .unwrap()
        .sealed()
        .filter(|item| item.item_id == id)
        .map(|item| item.height)
        .collect()
}

fn epoch_rejected(log: &Log, height: u64) -> bool {
    read(log)
        .query_row(
            "SELECT rejected FROM epochs WHERE epoch_number = ?1",
            [height as i64],
            |row| row.get(0),
        )
        .unwrap()
}

fn snapshot_entries(log: &Log) -> Vec<StateEntry> {
    let read = |path: &std::path::Path| -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    };
    crate::snapshot::produce(&log.path(), log.data.path()).unwrap();
    let index = read(&log.data.path().join("snapshots/index.json"));
    let manifest_path = log.data.path().join(
        index["index"]["snapshots"][0]["manifest_url"]
            .as_str()
            .unwrap()
            .trim_start_matches('/'),
    );
    let manifest = read(&manifest_path);
    let state = read(
        &manifest_path
            .parent()
            .unwrap()
            .join(manifest["manifest"]["state"]["path"].as_str().unwrap()),
    );
    serde_json::from_value(state["state"]["entries"].clone()).unwrap()
}

#[test]
fn a_rejected_epoch_persists_none_of_its_catalogs_and_items_and_the_next_seal_seals_them_again() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let (item, payload) = site.page_item(URL, "page body");
    let id = wist_core::item::item_id(&item).unwrap();
    site.collection(COLLECTION, &[(item, payload)], "2026-08-09T11:00:00Z");
    log.pull(&site).unwrap();
    let before = latest_catalog(&log, &site.host);
    assert!(before.as_ref().is_none_or(|(_, height)| *height == Some(0)));

    let rejected = seal_with_conflicting_declarations(&log, "2026-08-09T13:00:00Z");
    assert!(log.db.epoch_judged(rejected).unwrap());
    assert!(
        epoch_rejected(&log, rejected),
        "WIST1-E08 rejects the Epoch"
    );
    assert_eq!(record_height(&log, &site.host), None);
    assert_eq!(latest_catalog(&log, &site.host), before);
    assert!(sealed_item_heights(&log, &id).is_empty());
    common::assert_resumes_as_replayed(&log.db, log.data.path());
    let entries = snapshot_entries(&log);
    assert!(
        !entries.iter().any(|entry| match entry {
            StateEntry::Record(_) | StateEntry::Removal(_) => true,
            StateEntry::Collection(collection) => collection.sealing_height == rejected,
            _ => false,
        }),
        "the Snapshot carries a record of the rejected Epoch"
    );

    let signing = crate::keys::load(&log.data.path().join("keys/seed")).unwrap();
    let report = super::run(
        &log.db,
        log.data.path(),
        &signing,
        unix("2026-08-09T14:00:00Z"),
    )
    .unwrap();
    let accepted = report.epoch_number;
    assert!(accepted > rejected);
    assert!(!epoch_rejected(&log, accepted));
    assert_eq!(record_height(&log, &site.host), Some(accepted as i64));
    let (envelope, height) = latest_catalog(&log, &site.host).unwrap();
    assert!(envelope.is_some());
    assert_eq!(height, Some(accepted as i64));
    assert_eq!(sealed_item_heights(&log, &id), [accepted]);
    common::assert_resumes_as_replayed(&log.db, log.data.path());
}

#[test]
fn a_planned_epoch_whose_octets_exceed_the_size_bound_is_rejected_whole_despite_its_planned_judgment(
) {
    let site = Site::new();
    let log = Log::onboard(&site);
    let (item, payload) = site.page_item(URL, "page body");
    site.collection(COLLECTION, &[(item, payload)], "2026-08-09T11:00:00Z");
    log.pull(&site).unwrap();
    let before = latest_catalog(&log, &site.host);

    let signing = crate::keys::load(&log.data.path().join("keys/seed")).unwrap();
    let mutation = log.db.mutation().unwrap();
    let next = super::prepare::next_epoch_number(&log.db).unwrap();
    let event = log.db.reserve_epoch_event(next).unwrap();
    let mut prepared = super::prepare::epoch(
        &log.db,
        log.data.path(),
        &signing,
        unix("2026-08-09T13:00:00Z"),
        event,
    )
    .unwrap();
    assert!(prepared.planned.judged.is_some());
    prepared.octets = u64::from(u32::MAX);
    let height = prepared.epoch_number;
    super::publish::epoch(
        &log.db,
        log.data.path(),
        &crate::fetch::Client::new(false),
        mutation,
        prepared,
    )
    .unwrap();

    assert!(epoch_rejected(&log, height));
    assert_eq!(record_height(&log, &site.host), None);
    assert_eq!(latest_catalog(&log, &site.host), before);
}
