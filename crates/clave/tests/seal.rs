mod common;

use common::*;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use wist_core::sealing::{Epoch, Judgment, Outcome, Parameters, Replay};

const PULLED: &str = "2026-08-09T12:00:05Z";

fn hour(n: u32) -> String {
    format!("2026-08-09T{:02}:00:00Z", 13 + n)
}

fn long_path(index: usize) -> String {
    format!("{index:04}/{}", "p".repeat(1900))
}

fn with_payloads(items: &[(Value, Value)]) -> Vec<(Value, Option<Value>)> {
    items
        .iter()
        .map(|(item, payload)| (item.clone(), Some(payload.clone())))
        .collect()
}

fn leaf(entry: &Value) -> [u8; 32] {
    wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(entry).unwrap())
}

fn replay_served(r: &Rig) -> Replay {
    let head = head_checkpoint(r.data.path());
    let anchor = clave::history::anchor(r.data.path()).unwrap();
    let (key, key_id) = (anchor.key.clone(), anchor.key_id.clone());
    let log_key = move |kid: &str| (kid == key_id).then(|| key.clone());
    let parameters = Parameters::suite();
    let mut replay = Replay::new();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for height in 0..=head.epoch_number() {
        let note = std::fs::read_to_string(clave::publication::archive_path(r.data.path(), height))
            .unwrap();
        let checkpoint = wist_core::checkpoint::Checkpoint::parse(&note).unwrap();
        let previous = leaves.len() as u64;
        let entries = served_entries(r.data.path(), previous, checkpoint.tree_size());
        wist_core::epoch::verify_epoch(
            previous,
            &checkpoint,
            &entries,
            &wist_core::merkle::LeafHashes(&leaves),
            u64::MAX,
        )
        .unwrap();
        leaves.extend(entries.iter().map(leaf));
        let outcome = replay
            .epoch(&Epoch {
                height,
                root: &checkpoint.root_token(),
                sealed_at: checkpoint.sealed_at(),
                parameters: &parameters,
                suffix_list: None,
                log_key: &log_key,
                entries: &entries,
            })
            .unwrap();
        let Outcome::Accepted {
            entries: judged, ..
        } = outcome
        else {
            panic!("Epoch {height} is rejected: {outcome:?}");
        };
        for (index, judgment) in judged.iter().enumerate() {
            assert!(
                matches!(judgment, None | Some(Judgment::Valid)),
                "Entry {index} of Epoch {height}: {judgment:?}"
            );
        }
    }
    replay
}

fn records_agree(r: &Rig, replay: &Replay) {
    let state = r.state();
    let replayed: Vec<(String, String, String)> = replay
        .records()
        .records()
        .map(|(publisher, url, record)| {
            (publisher.to_owned(), url.to_owned(), record.item_id.clone())
        })
        .collect();
    let stored: Vec<(String, String, String)> = state
        .records
        .iter()
        .map(|((publisher, url), record)| (publisher.clone(), url.clone(), record.item_id.clone()))
        .collect();
    assert_eq!(stored, replayed);
    for (publisher, collection, latest) in replay.latest_catalogs() {
        let stored = state.collection(publisher, collection).unwrap();
        assert_eq!(
            stored.latest.as_ref().map(|latest| &latest.catalog_id),
            Some(&latest.catalog_id)
        );
    }
}

#[test]
fn seal_produces_a_verifiable_tree_and_checkpoints() {
    let r = Rig::new();
    let (item, payload) = r.page("a", "alpha body");
    let published = r.publish(
        &[(item.clone(), Some(payload))],
        "2026-08-09T12:00:00Z",
        None,
    );
    r.pull(PULLED);

    let r0 = r.seal(&hour(0));
    assert_eq!(r0.epoch_number, 0);
    assert_eq!(r0.entry_count, 3);
    let anchor = clave::history::anchor(r.data.path()).unwrap();
    let key = wist_core::checkpoint::AggregatorKey {
        key_id: anchor.key_id.clone(),
        public_key: r.sk.public(),
    };
    let epoch0 = head_checkpoint(r.data.path());
    wist_core::checkpoint::verify(&epoch0, &r.host, std::slice::from_ref(&key), &[]).unwrap();
    assert_eq!((epoch0.epoch_number(), epoch0.tree_size()), (0, 3));
    let entries = served_entries(r.data.path(), 0, epoch0.tree_size());
    assert_eq!(
        types(&entries),
        [
            "publisher_declaration",
            "publisher_catalog",
            "publisher_item"
        ]
    );
    assert_eq!(entries[1]["body"], published.envelope);
    assert_eq!(entries[2]["body"]["catalog"], published.catalog_id.as_str());
    assert_eq!(entries[2]["body"]["collection"], "default");
    let catalog: wist_core::objects::Catalog =
        serde_json::from_value(published.envelope["catalog"].clone()).unwrap();
    wist_core::publisher_item::verify(&entries[2]["body"], &catalog).unwrap();

    let state = r.state();
    let record = state.record(&r.host, &r.url("a")).unwrap();
    assert_eq!(record.item_id, item_id(&item));
    assert_eq!(record.catalog_id, published.catalog_id);
    assert_eq!(record.sealing_height, 0);
    let latest = state.collection(&r.host, "default").unwrap();
    assert_eq!(
        latest.latest.as_ref().unwrap().catalog_id,
        published.catalog_id
    );
    assert!(latest.waiting().is_none());
    assert!(state.urls.is_empty());

    assert!(clave::seal::run(
        &r.db,
        r.data.path(),
        &r.sk,
        wist_core::timestamp::log_seconds(&hour(0)).unwrap()
    )
    .is_err());
    let r1 = r.seal(&hour(1));
    assert_eq!((r1.epoch_number, r1.entry_count), (1, 0));
    let epoch1 = head_checkpoint(r.data.path());
    wist_core::checkpoint::verify(&epoch1, &r.host, std::slice::from_ref(&key), &[]).unwrap();
    assert_eq!(
        (epoch1.tree_size(), epoch1.root()),
        (epoch0.tree_size(), epoch0.root()),
        "an empty Epoch restates the tree the Epoch before it states"
    );
    let archived =
        std::fs::read_to_string(r.data.path().join("log/checkpoints/000000000")).unwrap();
    assert_eq!(
        wist_core::checkpoint::Checkpoint::parse(&archived)
            .unwrap()
            .note_text(),
        epoch0.note_text()
    );
}

#[test]
fn seal_orders_same_type_entries_by_ascending_leaf_hash() {
    let r = Rig::new();
    let items: Vec<(Value, Value)> = (0..6)
        .map(|n| r.page(&format!("page-{n}"), &format!("body {n}")))
        .collect();
    r.publish(&with_payloads(&items), "2026-08-09T12:00:00Z", None);
    r.pull(PULLED);
    let report = r.seal(&hour(0));
    assert_eq!(report.entry_count, 8);
    let entries = r.entries(0);
    let item_entries: Vec<&Value> = entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_item")
        .collect();
    assert_eq!(item_entries.len(), 6);
    let hashes: Vec<[u8; 32]> = item_entries.iter().map(|entry| leaf(entry)).collect();
    let mut sorted = hashes.clone();
    sorted.sort();
    assert_eq!(hashes, sorted);
    let listed: Vec<String> = items.iter().map(|(item, _)| item_id(item)).collect();
    assert_ne!(
        sealed_item_ids(&entries),
        listed,
        "the fixture lists its Items in an order their leaf hashes do not share"
    );
}

#[test]
fn a_replacing_item_seals_against_the_latest_catalog_and_becomes_the_record() {
    let r = Rig::new();
    let first = r.page("a", "first content");
    let one = r.publish(
        &with_payloads(std::slice::from_ref(&first)),
        "2026-08-09T12:00:00Z",
        None,
    );
    r.pull(PULLED);
    r.seal(&hour(0));
    let second = r.page("a", "second content");
    let two = r.publish(
        &with_payloads(std::slice::from_ref(&second)),
        "2026-08-09T13:30:00Z",
        Some(&one),
    );
    r.pull("2026-08-09T13:30:05Z");
    let report = r.seal(&hour(1));
    assert_eq!(report.entry_count, 2);
    let entries = r.entries(1);
    assert_eq!(types(&entries), ["publisher_catalog", "publisher_item"]);
    assert_eq!(entries[1]["body"]["catalog"], two.catalog_id.as_str());
    let state = r.state();
    let record = state.record(&r.host, &r.url("a")).unwrap();
    assert_eq!(record.item_id, item_id(&second.0));
    assert_eq!(record.sealing_height, 1);
    records_agree(&r, &replay_served(&r));
}

#[test]
fn an_empty_first_epoch_states_the_empty_tree_and_serves_no_tile() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("example-log.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, 1_800_000_000).unwrap();
    let head = head_checkpoint(data.path());
    assert_eq!(head.tree_size(), 0);
    assert_eq!(head.root(), &wist_core::merkle::EMPTY_ROOT);
    assert!(wist_core::tiles::required_tiles(0).is_empty());
    assert!(!data.path().join("tile/0/000").exists());
    assert!(data.path().join("log/checkpoints/000000000").exists());
}

#[test]
fn an_epoch_over_the_entry_bundle_cap_leaves_entries_unsealed_for_a_later_seal() {
    let r = Rig::new();
    let items: Vec<(Value, Value)> = (0..40).map(|n| r.page(&long_path(n), "body")).collect();
    r.publish(&with_payloads(&items), "2026-08-09T12:00:00Z", None);
    r.pull(PULLED);
    let cap = 65_537;
    r.db.set_param("epoch_cap_bytes", cap).unwrap();
    let mut sealed = Vec::new();
    let mut height = 0;
    while sealed.len() < items.len() {
        assert!(height < 6, "the Items never all sealed");
        let report = r.seal(&hour(height));
        let entries = r.entries(report.epoch_number);
        assert!(wist_core::epoch::epoch_octets(&entries).unwrap() <= cap as u64);
        if height == 0 {
            assert!(entries.len() < items.len() + 2, "the cap keeps Items out");
            assert_eq!(
                types(&entries)[..2],
                ["publisher_declaration", "publisher_catalog"]
            );
        }
        let reports = r.db.waiting_reports(&r.host).unwrap();
        assert!(
            reports.is_empty(),
            "an Item the cap keeps out is reported: {reports:?}"
        );
        sealed.extend(sealed_item_ids(&entries));
        height += 1;
    }
    assert!(height > 1);
    let mut listed: Vec<String> = items.iter().map(|(item, _)| item_id(item)).collect();
    listed.sort();
    sealed.sort();
    assert_eq!(sealed, listed);
    records_agree(&r, &replay_served(&r));
}

#[test]
fn the_per_domain_epoch_cap_defers_the_surplus_in_place_order() {
    let r = Rig::new();
    let items: Vec<(Value, Value)> = (0..5).map(|n| r.page(&format!("p{n}"), "body")).collect();
    let published = r.publish(&with_payloads(&items), "2026-08-09T12:00:00Z", None);
    r.db.set_param("domain_epoch_entries_max", 2).unwrap();
    r.pull(PULLED);
    let mut listed = published.list.clone();
    listed.sort_by_key(|item| wist_core::item::key(item["url"].as_str().unwrap()));
    let in_place: Vec<String> = listed.iter().map(item_id).collect();
    let expected: [&[String]; 3] = [&in_place[..1], &in_place[1..3], &in_place[3..]];
    for (height, expected) in expected.into_iter().enumerate() {
        let report = r.seal(&hour(height as u32));
        let mut sealed = sealed_item_ids(&r.entries(report.epoch_number));
        sealed.sort();
        let mut expected = expected.to_vec();
        expected.sort();
        assert_eq!(
            sealed, expected,
            "Epoch {height} seals in the order of places"
        );
        let deferred: Vec<_> =
            r.db.waiting_reports(&r.host)
                .unwrap()
                .into_iter()
                .filter(|report| report.deferrals.as_deref() == Some(&["capacity".to_owned()][..]))
                .collect();
        assert_eq!(deferred.len(), [4, 2, 0][height], "Epoch {height}");
    }
    assert!(r.state().urls.is_empty());
}

#[test]
fn an_entry_left_unsealed_past_its_inclusion_ceiling_is_reported() {
    let r = Rig::new();
    let items: Vec<(Value, Value)> = (0..60).map(|n| r.page(&long_path(n), "body")).collect();
    r.publish(&with_payloads(&items), "2026-08-09T12:00:00Z", None);
    r.db.set_param("max_inclusion_epochs", 1).unwrap();
    r.db.set_param("epoch_cap_bytes", 65_537).unwrap();
    r.pull(PULLED);
    let mut late = Vec::new();
    for height in 0..6 {
        late.extend(r.seal(&hour(height)).late);
    }
    assert!(!late.is_empty());
    assert!(late
        .iter()
        .any(|line| line.contains("past its inclusion ceiling")));
    assert!(r.state().urls.is_empty(), "every Item seals in the end");
}

#[test]
fn an_epoch_the_replay_rejects_is_not_committed() {
    let r = Rig::new();
    let (item, payload) = r.page("a", "alpha");
    r.publish(&[(item, Some(payload))], "2026-08-09T12:00:00Z", None);
    r.pull(PULLED);
    let fresh = |contact: &str| {
        let signer = wist_core::crypto::SigningKey::from_seed(&K2_SEED);
        wist_core::envelope::sign_envelope(
            &json!({"wist_version": "1.0.0", "domain": "fresh.example", "contact": contact,
                "keys": [key_entry(&K2_SEED, "2026-08-09T00:00:00Z")], "seq": 0}),
            "publisher",
            &kid(&K2_SEED),
            &signer,
        )
        .unwrap()
    };
    r.db.hold_discovered_declaration("fresh.example", &fresh("mailto:a@fresh.example"))
        .unwrap();
    r.db.hold_discovered_declaration("fresh.example", &fresh("mailto:b@fresh.example"))
        .unwrap();
    let before = r.state();
    let refused = clave::seal::run(
        &r.db,
        r.data.path(),
        &r.sk,
        wist_core::timestamp::log_seconds(&hour(0)).unwrap(),
    );
    let error = refused
        .err()
        .expect("the planned Epoch is rejected")
        .to_string();
    assert!(error.contains("WIST1-E08"), "{error}");
    assert!(r.db.last_epoch().unwrap().is_none());
    assert!(!r.data.path().join("checkpoint").exists());
    assert_eq!(
        r.db.count_discovered_declarations("fresh.example").unwrap(),
        2
    );
    let after = r.state();
    assert_eq!(after.collections, before.collections);
    assert_eq!(after.urls, before.urls);
    assert!(r.db.payload_duties().unwrap().is_empty());
    assert_eq!(common::payload_files(r.data.path()), 1);
    assert!(!r
        .data
        .path()
        .join("payloads")
        .read_dir()
        .unwrap()
        .any(|_| true));
}

#[test]
fn a_payload_is_served_from_the_sealing_of_its_item_and_an_unsealed_one_never() {
    let r = Rig::new();
    let served = |id: &str| clave::db::served_payload_path(r.data.path(), id).unwrap();
    let held = |id: &str| clave::db::held_payload_path(r.data.path(), id).unwrap();
    let a = r.page("a", "first");
    let one = r.publish(
        &with_payloads(std::slice::from_ref(&a)),
        "2026-08-09T12:00:00Z",
        None,
    );
    r.pull(PULLED);
    let a_id = item_id(&a.0);
    assert!(held(&a_id).exists());
    assert!(
        !served(&a_id).exists(),
        "a Payload whose Item is not sealed is served"
    );
    r.seal(&hour(0));
    assert_eq!(
        std::fs::read(served(&a_id)).unwrap(),
        wist_core::jcs::canonicalize(&a.1).unwrap()
    );
    let duties = r.db.payload_duties().unwrap();
    assert_eq!(duties.len(), 1);
    assert_eq!(
        (duties[0].item_id.as_str(), duties[0].until.as_str()),
        (a_id.as_str(), "2027-02-05T13:00:00Z")
    );

    let replaced = r.page("a", "second");
    let replaced_id = item_id(&replaced.0);
    let two = r.publish(
        &with_payloads(std::slice::from_ref(&replaced)),
        "2026-08-09T13:10:00Z",
        Some(&one),
    );
    r.pull("2026-08-09T13:10:05Z");
    assert!(held(&replaced_id).exists());
    assert!(!served(&replaced_id).exists());

    let b = r.page("b", "other");
    r.publish(
        &with_payloads(&[a.clone(), b.clone()]),
        "2026-08-09T13:20:00Z",
        Some(&two),
    );
    r.pull("2026-08-09T13:20:05Z");
    r.seal(&hour(1));
    let b_id = item_id(&b.0);
    assert!(served(&b_id).exists());
    assert!(
        !held(&replaced_id).exists() && !served(&replaced_id).exists(),
        "a Payload no list names and no record carries is discarded"
    );
    assert!(served(&a_id).exists(), "a record's Payload is served");
}

#[test]
fn a_payload_whose_window_ended_and_whose_item_is_no_record_is_no_longer_served() {
    let r = Rig::new();
    let a = r.page("a", "first");
    let one = r.publish(
        &with_payloads(std::slice::from_ref(&a)),
        "2026-08-09T12:00:00Z",
        None,
    );
    r.pull(PULLED);
    r.seal(&hour(0));
    let a_id = item_id(&a.0);
    let replaced = r.page("a", "second");
    r.publish(
        &with_payloads(std::slice::from_ref(&replaced)),
        "2026-08-09T13:10:00Z",
        Some(&one),
    );
    r.pull("2026-08-09T13:10:05Z");
    r.seal(&hour(1));
    let served = clave::db::served_payload_path(r.data.path(), &a_id).unwrap();
    assert!(
        served.exists(),
        "the window still binds a superseded Payload"
    );
    r.seal("2027-02-05T13:00:00Z");
    assert!(!served.exists());
    assert!(
        clave::db::served_payload_path(r.data.path(), &item_id(&replaced.0))
            .unwrap()
            .exists()
    );
}

struct Holding {
    hold: Arc<Mutex<Option<String>>>,
    held: mpsc::Receiver<()>,
    release: Arc<AtomicBool>,
}

fn serve_holding(listener: std::net::TcpListener, dir: std::path::PathBuf) -> Holding {
    let hold = Arc::new(Mutex::new(None::<String>));
    let release = Arc::new(AtomicBool::new(false));
    let (tx, held) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let (holding, released) = (hold.clone(), release.clone());
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                    let path = uri.path().to_owned();
                    let blocks = holding
                        .lock()
                        .unwrap()
                        .as_deref()
                        .is_some_and(|suffix| path.ends_with(suffix));
                    let (dir, released, tx) = (dir.clone(), released.clone(), tx.clone());
                    async move {
                        if blocks {
                            let _ = tx.lock().unwrap().send(());
                            while !released.load(Ordering::SeqCst) {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                        match std::fs::read(dir.join(path.trim_start_matches('/'))) {
                            Ok(bytes) => (axum::http::StatusCode::OK, bytes),
                            Err(_) => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                        }
                    }
                });
                axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                    .await
                    .unwrap();
            });
    });
    Holding {
        hold,
        held,
        release,
    }
}

#[test]
fn a_pull_and_a_seal_racing_on_one_collection_keep_the_sealed_catalog() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let holding = serve_holding(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let a = page_item(&p, &format!("https://{host}/a"), "alpha");
    let one = publish_collection(
        &p,
        "default",
        &with_payloads(std::slice::from_ref(&a)),
        "2026-08-09T12:00:00Z",
        None,
    );
    pull_at(&db, &client, data.path(), &host, PULLED);

    let b = page_item(&p, &format!("https://{host}/b"), "beta");
    let two = publish_collection(
        &p,
        "default",
        &with_payloads(&[a.clone(), b.clone()]),
        "2026-08-09T12:30:00Z",
        Some(&one),
    );
    *holding.hold.lock().unwrap() = Some(format!(
        "/payloads/{}.json",
        wist_core::item::payload_name(&b.0).unwrap()
    ));
    let pulling = {
        let (path, data, host, client) = (
            path.clone(),
            data.path().to_path_buf(),
            host.clone(),
            client.clone(),
        );
        std::thread::spawn(move || {
            let db = clave::db::Db::connect(&path).unwrap();
            clave::ingest::run(&db, &client, &data, &host, "2026-08-09T12:30:05Z")
        })
    };
    holding
        .held
        .recv_timeout(Duration::from_secs(20))
        .expect("the pull requests the held Payload");
    let sealer = clave::db::Db::connect(&path).unwrap();
    let sealed = clave::seal::run(
        &sealer,
        data.path(),
        &sk,
        wist_core::timestamp::log_seconds(&hour(0)).unwrap(),
    )
    .unwrap();
    assert!(sealed.dropped.is_empty(), "{:?}", sealed.dropped);
    holding.release.store(true, Ordering::SeqCst);
    let report = pulling.join().unwrap().unwrap();
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);

    let scope = std::collections::BTreeSet::from([host.clone()]);
    let state = db
        .load_state(db.sealed_state(data.path()).unwrap(), &scope)
        .unwrap();
    let collection = state.collection(&host, "default").unwrap();
    assert_eq!(
        collection
            .latest
            .as_ref()
            .map(|latest| latest.catalog_id.as_str()),
        Some(one.catalog_id.as_str()),
        "the pull kept the Catalog the seal made latest"
    );
    assert_eq!(
        collection
            .waiting()
            .map(|waiting| waiting.catalog_id.as_str()),
        Some(two.catalog_id.as_str())
    );
    assert!(state.record(&host, &format!("https://{host}/a")).is_some());

    clave::seal::run(
        &db,
        data.path(),
        &sk,
        wist_core::timestamp::log_seconds(&hour(1)).unwrap(),
    )
    .unwrap();
    let state = db
        .load_state(db.sealed_state(data.path()).unwrap(), &scope)
        .unwrap();
    assert_eq!(
        state
            .collection(&host, "default")
            .unwrap()
            .latest
            .as_ref()
            .map(|latest| latest.catalog_id.as_str()),
        Some(two.catalog_id.as_str())
    );
    assert!(state.record(&host, &format!("https://{host}/b")).is_some());
    assert!(state.urls.is_empty());
}

#[test]
fn a_sealed_log_replays_through_core_with_every_entry_valid_and_the_records_of_the_store() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let r = Rig {
        p,
        host,
        client,
        data,
        db,
        sk,
    };
    let a = r.page("a", "alpha");
    let b = r.page("b", "beta");
    let c = r.page("c", "gamma");
    let d = r.page("keep/d", "delta");
    let e = r.page("keep/e", "epsilon");
    let one = r.publish(
        &with_payloads(&[a.clone(), b.clone(), c.clone(), d.clone()]),
        "2026-08-09T12:00:00Z",
        None,
    );
    r.pull(PULLED);
    r.seal("2026-08-09T13:00:00Z");

    let a_id = item_id(&a.0);
    clave::governance::withdraw(
        &r.db,
        &r.sk,
        &r.host,
        &a_id,
        "court order",
        "DE",
        wist_core::timestamp::log_seconds("2026-08-09T13:30:00Z").unwrap(),
    )
    .unwrap();
    r.seal("2026-08-09T14:00:00Z");
    assert_eq!(types(&r.entries(1)), ["registry_update"]);
    assert!(!clave::db::served_payload_path(r.data.path(), &a_id)
        .unwrap()
        .exists());

    let removed = removed_item(&r.p, &r.url("c"));
    let two = r.publish(
        &[
            (a.0.clone(), Some(a.1.clone())),
            (b.0.clone(), Some(b.1.clone())),
            (removed.clone(), None),
            (d.0.clone(), Some(d.1.clone())),
        ],
        "2026-08-09T14:30:00Z",
        Some(&one),
    );
    r.pull("2026-08-09T14:30:05Z");
    r.seal("2026-08-09T15:00:00Z");
    assert!(r
        .state()
        .removals
        .contains_key(&(r.host.clone(), r.url("c"))));

    let initial = current_declaration(&r.p);
    let mut narrowed = initial["publisher"].clone();
    narrowed["seq"] = 1.into();
    narrowed["prev_declaration"] = declaration_hash(&initial).into();
    narrowed["collections"] = json!([{"name": "default",
        "scope": [{"url": r.url("keep/"), "match": "prefix"}]}]);
    write_declaration(&r.p, &narrowed, &K1_SEED);
    r.pull("2026-08-09T15:30:05Z");
    r.seal("2026-08-09T16:00:00Z");
    let state = r.state();
    assert!(state.record(&r.host, &r.url("a")).is_none());
    assert!(state.record(&r.host, &r.url("keep/d")).is_some());

    let base = r.publish(
        &with_payloads(std::slice::from_ref(&e)),
        "2027-02-10T00:00:00Z",
        Some(&two),
    );
    r.pull("2027-02-10T00:00:05Z");
    r.seal("2027-02-10T01:00:00Z");
    let state = r.state();
    assert!(
        state.record(&r.host, &r.url("keep/d")).is_none(),
        "a base removes a record it does not list"
    );
    assert!(state.record(&r.host, &r.url("keep/e")).is_some());
    assert!(
        state
            .collection(&r.host, "default")
            .unwrap()
            .latest
            .as_ref()
            .unwrap()
            .catalog_id
            == base.catalog_id
    );

    let narrowed_envelope = current_declaration(&r.p);
    let mut recovered = narrowed.clone();
    recovered["seq"] = 2.into();
    recovered["prev_declaration"] = declaration_hash(&narrowed_envelope).into();
    recovered["keys"] = json!([key_entry(&K2_SEED, "2027-02-10T00:00:00Z")]);
    write_declaration(&r.p, &recovered, &R1_SEED);
    r.pull("2027-02-10T02:00:05Z");
    r.seal("2027-02-10T03:00:00Z");
    let sealed = r.db.sealed_state(r.data.path()).unwrap();
    assert!(sealed.declarations.domains()[&r.host].window().is_some());
    r.seal("2027-02-18T00:00:00Z");
    let sealed = r.db.sealed_state(r.data.path()).unwrap();
    assert!(
        sealed.declarations.domains()[&r.host].window().is_none(),
        "the window settled"
    );

    let replay = replay_served(&r);
    records_agree(&r, &replay);
    let state = r.state();
    let replayed_removals: Vec<(String, String)> = replay
        .records()
        .removals()
        .map(|(publisher, url, removal)| (url.to_owned(), removal.item_id.clone() + publisher))
        .collect();
    let stored_removals: Vec<(String, String)> = state
        .removals
        .iter()
        .map(|((publisher, url), removal)| (url.clone(), removal.item_id.clone() + publisher))
        .collect();
    assert_eq!(stored_removals, replayed_removals);
    assert!(replay.withdrawals().is_withdrawn(&a_id));
    assert_eq!(sealed.withdrawals.entries(), replay.withdrawals().entries());
    let mut duties: Vec<(String, Option<String>)> = replay
        .payload_duties("2027-02-18T00:00:00Z")
        .unwrap()
        .into_iter()
        .map(|duty| (duty.item_id, duty.until))
        .collect();
    duties.sort();
    let mut stored: Vec<(String, Option<String>)> =
        r.db.payload_duties()
            .unwrap()
            .into_iter()
            .filter(|duty| {
                r.db.payload_under_duty(&duty.item_id, "2027-02-18T00:00:00Z")
                    .unwrap()
            })
            .map(|duty| {
                let record = state
                    .records
                    .values()
                    .any(|record| record.item_id == duty.item_id);
                (duty.item_id, (!record).then_some(duty.until))
            })
            .collect();
    stored.sort();
    assert_eq!(stored, duties);
}
