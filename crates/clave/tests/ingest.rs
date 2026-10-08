mod common;

use clave::history::declarations::DeclarationsReplay;
use common::{make_publisher, make_publisher_with_scope, reserve_addr, serve_static};

#[test]
fn ingest_onboard_failure_is_e04_noise() {
    let (listener, host, client) = reserve_addr();
    let empty = tempfile::tempdir().unwrap();
    serve_static(listener, empty.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(report.noise, Some("WIST2-E04"));
}

#[test]
fn a_redirect_chain_that_revisits_a_url_stops_at_the_repeat() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);

    let server = std::thread::spawn(move || {
        listener
            .set_nonblocking(false)
            .expect("blocking accept loop");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            counter.fetch_add(1, Ordering::SeqCst);
            let body = format!("HTTP/1.1 302 Found\r\nLocation: http://{addr}/loop.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });

    let client = clave::fetch::Client::new(true);
    let err = client
        .get_json(&format!("http://{addr}/loop.json"))
        .unwrap_err();
    assert!(
        err.to_string().contains("already fetched"),
        "unexpected error {err}"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the chain must stop at the repeat, not run to the hop bound"
    );
    drop(server);
}

/// WIST-2 §4: only a Ping's own pull can cost its Registrable Domain
/// noise, counted under the unit and UTC day in force at the Ping.
#[test]
fn only_a_pulls_own_ping_is_charged_noise_and_at_the_instant_it_was_received() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let all = clave::db::PARTITIONS as usize;
    let now = jiff::Timestamp::now().as_second();
    let day = |unix: i64| jiff::Timestamp::from_second(unix).unwrap().to_string()[..10].to_string();

    let onboarded = jiff::Timestamp::from_second(now - 2 * 86_400)
        .unwrap()
        .to_string();
    clave::ingest::run(&db, &client, tmp.path(), &host, &onboarded).unwrap();
    let pinged_at = now - 86_400;
    db.schedule_ping(&host, pinged_at, 4).unwrap();
    let task = db
        .claim_pulls(now, 1, "me", all, &[], &mut true, true)
        .unwrap()
        .remove(0);
    assert_eq!(task.pinged_at, Some(pinged_at));
    let pull = |task: &clave::db::PullTask, at: i64| {
        let now = jiff::Timestamp::from_second(at).unwrap().to_string();
        let run = clave::ingest::open_pull(
            &db,
            &client,
            tmp.path(),
            &host,
            &now,
            jiff::Timestamp::now,
            clave::ingest::PullLimits::default(),
        )
        .unwrap();
        clave::ingest::finish_pull(&db, task, "me", at, run, at).unwrap()
    };

    let report = pull(&task, now);
    assert_eq!(report.noise, Some("WIST2-E02"));
    assert_eq!(
        db.noise_ping_count(&host, &day(pinged_at)).unwrap(),
        1,
        "the noise is counted on the day of the Ping it answered"
    );
    assert_eq!(db.noise_ping_count(&host, &day(now)).unwrap(), 0);

    let baseline = db.scheduled_pull(&host).unwrap().unwrap();
    assert_eq!(baseline.reason, clave::db::Reason::Baseline);
    assert_eq!(baseline.pinged_at, None);
    let later = baseline.due_at;
    let task = db
        .claim_pulls(later, 1, "me", all, &[], &mut false, true)
        .unwrap()
        .remove(0);
    assert_eq!(task.pinged_at, None);
    assert_eq!(pull(&task, later).noise, Some("WIST2-E02"));
    for at in [pinged_at, now, later] {
        assert_eq!(
            db.noise_ping_count(&host, &day(at)).unwrap(),
            i64::from(at == pinged_at),
            "a baseline poll no Ping asked for counts against no quota"
        );
    }
}

#[test]
fn a_label_feed_regressed_at_wist2_e05_keeps_the_baseline_schedule() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let started_at = jiff::Timestamp::now().as_second();
    let at = |unix: i64| jiff::Timestamp::from_second(unix).unwrap().to_string();
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let all = clave::db::PARTITIONS as usize;
    let baseline = 3600;
    db.set_param("baseline_poll_seconds", baseline).unwrap();
    let pull = |started_at: i64| {
        db.schedule_ping(&host, started_at, 4).unwrap();
        let task = db
            .claim_pulls(started_at, 1, "me", all, &[], &mut true, true)
            .unwrap()
            .remove(0);
        let run = clave::ingest::open_pull(
            &db,
            &client,
            tmp.path(),
            &host,
            &at(started_at),
            jiff::Timestamp::now,
            clave::ingest::PullLimits::default(),
        )
        .unwrap();
        clave::ingest::finish_pull(&db, &task, "me", started_at, run, started_at + 5).unwrap()
    };
    common::write_label_feed(&p, &host, &[], &at(started_at - 60));
    assert_eq!(pull(started_at).ended, None);

    common::write_label_feed(&p, &host, &[], &at(started_at - 600));
    let regressed_at = started_at + baseline;
    assert_eq!(pull(regressed_at).ended, None);
    assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST2-E05");
    let next = db.scheduled_pull(&host).unwrap().unwrap();
    assert_eq!(next.reason, clave::db::Reason::Baseline);
    assert_eq!(next.attempts, 0);
    assert_eq!(next.due_at, regressed_at + baseline);
}

#[test]
fn a_declaration_fetch_that_fails_after_first_contact_stops_the_pull_at_wist2_e01() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let requests = common::serve_recording(listener, p.dir.path().to_path_buf());
    common::write_label_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    std::fs::remove_file(p.dir.path().join(".well-known/wist/publisher.json")).unwrap();
    requests.lock().unwrap().clear();
    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:10:00Z").unwrap();
    assert_eq!(report.ended.as_deref(), Some("WIST2-E01"));
    assert_eq!(report.noise, None);
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        ["/.well-known/wist/publisher.json"],
        "no Label Feed is read in a pull stopped at its Declaration"
    );
    assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST2-E01");
}

#[test]
fn a_refused_declaration_stops_the_pull_at_wist2_e01_after_recording_its_code() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    common::publish_collection(&p, "default", &[], "2026-08-09T11:00:00Z", None);
    let requests = common::serve_recording(listener, p.dir.path().to_path_buf());
    common::write_label_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let mut same_seq = common::current_declaration(&p)["publisher"].clone();
    same_seq["contact"] = "mailto:other@example.com".into();
    common::write_declaration(&p, &same_seq, &common::K1_SEED);
    requests.lock().unwrap().clear();
    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:10:00Z").unwrap();
    assert_eq!(report.ended.as_deref(), Some("WIST2-E01"));
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|rejection| rejection.code)
        .collect();
    assert_eq!(codes, ["WIST2-E01", "WIST1-E08"]);
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        ["/.well-known/wist/publisher.json"]
    );
}

fn open_store(host: &str) -> (tempfile::TempDir, clave::db::Db) {
    let data = tempfile::tempdir().unwrap();
    clave::init::run(host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    (data, db)
}

fn with_payloads(
    items: &[(serde_json::Value, serde_json::Value)],
) -> Vec<(serde_json::Value, Option<serde_json::Value>)> {
    items
        .iter()
        .map(|(item, payload)| (item.clone(), Some(payload.clone())))
        .collect()
}

fn admitted_ids(report: &clave::ingest::IngestReport) -> Vec<String> {
    let mut ids: Vec<String> = report
        .items
        .iter()
        .map(|id| id.rsplit_once('/').unwrap().1.to_owned())
        .collect();
    ids.sort();
    ids
}

fn sorted_ids(items: &[(serde_json::Value, Option<serde_json::Value>)]) -> Vec<String> {
    let mut ids: Vec<String> = items
        .iter()
        .map(|(item, _)| common::item_id(item))
        .collect();
    ids.sort();
    ids
}

#[test]
fn a_pull_admits_the_items_whose_payloads_verify_and_not_one_whose_payload_breaks_its_commitment() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let good = common::page_item(&p, &format!("https://{host}/good"), "good");
    let (bad, mut tampered) = common::page_item(&p, &format!("https://{host}/bad"), "bad");
    tampered["content"]["extract"] = "altered".into();
    let removed = common::removed_item(&p, &format!("https://{host}/gone"));
    common::publish_collection(
        &p,
        "default",
        &[
            (good.0.clone(), Some(good.1)),
            (bad.clone(), Some(tampered)),
            (removed.clone(), None),
        ],
        "2026-08-09T12:00:00Z",
        None,
    );
    serve_static(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");
    let mut admitted = vec![common::item_id(&good.0), common::item_id(&removed)];
    admitted.sort();
    assert_eq!(admitted_ids(&report), admitted);
    assert_eq!(report.accepted.len(), 1);
    assert_eq!(
        report.rejected,
        [(
            format!("default/{}", common::item_id(&bad)),
            "WIST2-E03".into()
        )]
    );
    let rejection = db.list_rejections(&host).unwrap().remove(0);
    assert_eq!(rejection.code, "WIST2-E03");
    assert_eq!(rejection.collection.as_deref(), Some("default"));
    assert_eq!(rejection.detail.as_deref(), Some("WIST1-E10"));
    assert_eq!(rejection.urls, Some(vec![format!("https://{host}/bad")]));
    assert_eq!(
        common::payload_files(data.path()),
        1,
        "only the verified Payload is held"
    );
    assert_eq!(report.noise, None);
}

#[test]
fn an_item_outside_the_publishers_scope_is_refused_alone_and_one_in_its_subdomain_scope_is_admitted(
) {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let inside = common::page_item(&p, "https://example.com/a", "inside");
    let outside = common::page_item(&p, "https://other.example/a", "outside");
    common::publish_collection(
        &p,
        "default",
        &with_payloads(&[inside.clone(), outside.clone()]),
        "2026-08-09T12:00:00Z",
        None,
    );
    serve_static(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");
    assert_eq!(admitted_ids(&report), [common::item_id(&inside.0)]);
    assert_eq!(
        report.rejected,
        [(
            format!("default/{}", common::item_id(&outside.0)),
            "WIST1-E03".into()
        )]
    );
}

#[test]
fn a_tree_of_several_files_is_walked_whole_and_an_unchanged_catalog_fetches_nothing_again() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let items: Vec<_> = (0..40)
        .map(|n| common::page_item(&p, &format!("https://{host}/{n}"), "content"))
        .collect();
    let items = with_payloads(&items);
    let published = common::publish_collection(&p, "default", &items, "2026-08-09T12:00:00Z", None);
    assert!(published.tree.len() > 2);
    let requests = common::serve_recording(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");
    assert_eq!(admitted_ids(&report), sorted_ids(&items));
    let fetched = |part: &str| {
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.contains(part))
            .count()
    };
    assert_eq!(fetched("/tree/"), published.tree.len());
    assert_eq!(fetched("/payloads/"), items.len());

    requests.lock().unwrap().clear();
    let again = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:10:05Z");
    assert!(again.accepted.is_empty() && again.items.is_empty());
    assert_eq!(
        (
            fetched("/tree/"),
            fetched("/payloads/"),
            fetched("/changes/")
        ),
        (0, 0, 0),
        "an idempotent re-serve fetches no tree file, no change list and no Payload"
    );
    assert_eq!(again.noise, Some("WIST2-E02"));
}

#[test]
fn a_changed_catalog_is_obtained_by_its_change_list_without_walking_the_tree() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let items = with_payloads(
        &(0..20)
            .map(|n| common::page_item(&p, &format!("https://{host}/{n}"), "content"))
            .collect::<Vec<_>>(),
    );
    let first = common::publish_collection(&p, "default", &items, "2026-08-09T12:00:00Z", None);
    let requests = common::serve_recording(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");

    let mut changed = items.clone();
    let added = common::page_item(&p, &format!("https://{host}/added"), "added");
    changed.push((added.0.clone(), Some(added.1)));
    let second = common::publish_collection(
        &p,
        "default",
        &changed,
        "2026-08-09T12:05:00Z",
        Some(&first),
    );
    assert!(second.change_list.is_some());
    requests.lock().unwrap().clear();
    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:10:05Z");
    assert_eq!(report.accepted, [format!("default/{}", second.catalog_id)]);
    let requests = requests.lock().unwrap().clone();
    assert!(
        !requests.iter().any(|path| path.contains("/tree/")),
        "{requests:?}"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.contains("/changes/"))
            .count(),
        1
    );
    assert!(admitted_ids(&report).contains(&common::item_id(&added.0)));
}

#[test]
fn a_discarded_chain_is_recorded_as_wist2_e08_and_the_walk_accepts_the_catalog() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let items = with_payloads(&[common::page_item(&p, &format!("https://{host}/a"), "a")]);
    common::publish_collection(&p, "default", &items, "2026-08-09T12:00:00Z", None);
    serve_static(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");
    let mut changed = items.clone();
    let added = common::page_item(&p, &format!("https://{host}/b"), "b");
    changed.push((added.0, Some(added.1)));
    let second = common::publish_collection(&p, "default", &changed, "2026-08-09T12:05:00Z", None);
    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:10:05Z");
    assert_eq!(report.accepted, [format!("default/{}", second.catalog_id)]);
    let discarded = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .find(|rejection| rejection.code == "WIST2-E08")
        .unwrap();
    assert_eq!(discarded.id.as_deref(), Some(second.catalog_id.as_str()));
    assert_eq!(discarded.collection.as_deref(), Some("default"));
    assert_eq!(
        discarded.condition,
        Some(wist_core::objects::status::RejectionCondition::Fetch)
    );
    assert_eq!(
        discarded.change_list.as_deref(),
        Some(second.catalog_id.as_str())
    );
    assert_eq!(
        report.noise, None,
        "the accepted Catalog makes the pull productive"
    );
}

#[test]
fn a_refused_catalog_is_recorded_with_its_collection_and_a_pull_accepting_nothing_is_noise() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let items = with_payloads(&[common::page_item(&p, &format!("https://{host}/a"), "a")]);
    let published = common::publish_collection(&p, "default", &items, "2026-08-10T12:00:00Z", None);
    serve_static(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");
    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:10:05Z");
    let rejection = db.list_rejections(&host).unwrap().remove(0);
    assert_eq!(rejection.id.as_deref(), Some(published.catalog_id.as_str()));
    assert_eq!(rejection.collection.as_deref(), Some("default"));
    assert!(report.accepted.is_empty() && report.items.is_empty());
    assert_eq!(
        report.noise,
        Some("WIST2-E02"),
        "WIST-2 §5.4: a refused Catalog accepts nothing"
    );
}

#[test]
fn the_budget_suspends_a_tree_walk_and_a_later_day_resumes_it_from_the_held_files() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let items = with_payloads(
        &(0..40)
            .map(|n| common::page_item(&p, &format!("https://{host}/{n}"), "content"))
            .collect::<Vec<_>>(),
    );
    let published = common::publish_collection(&p, "default", &items, "2026-08-09T12:00:00Z", None);
    let requests = common::serve_recording(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    let catalog = std::fs::metadata(common::collection_dir(&p, "default").join("catalog.json"))
        .unwrap()
        .len() as i64;
    let root = &published.tree[&published.envelope["catalog"]["tree"].as_str().unwrap()[7..]];
    db.set_param("ingest_budget_bytes_day", catalog + root.len() as i64 + 10)
        .unwrap();
    let first = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");
    assert!(first.suspended && first.items.is_empty() && first.accepted.is_empty());
    assert_eq!(first.noise, None, "a suspended pull is not noise");
    let walked: Vec<String> = requests
        .lock()
        .unwrap()
        .iter()
        .filter(|path| path.contains("/tree/"))
        .cloned()
        .collect();
    assert_eq!(
        walked.len(),
        2,
        "the root file is read whole and the next one interrupted"
    );

    db.set_param("ingest_budget_bytes_day", 1 << 30).unwrap();
    requests.lock().unwrap().clear();
    let second = common::pull_at(&db, &client, data.path(), &host, "2026-08-10T00:00:05Z");
    assert!(!second.suspended);
    assert_eq!(admitted_ids(&second), sorted_ids(&items));
    let resumed = requests.lock().unwrap().clone();
    assert!(
        !resumed.contains(&walked[0]),
        "the root tree file held whole is not fetched again"
    );
    assert!(
        resumed.contains(&walked[1]),
        "the interrupted file is fetched again"
    );
}

#[test]
fn held_lists_tree_files_waiting_places_the_queue_and_a_discarded_chain_survive_reopening_the_store(
) {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let items = with_payloads(
        &(0..20)
            .map(|n| common::page_item(&p, &format!("https://{host}/{n}"), "content"))
            .collect::<Vec<_>>(),
    );
    common::publish_collection(&p, "default", &items[..10], "2026-08-09T12:00:00Z", None);
    serve_static(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");
    let second = common::publish_collection(&p, "default", &items, "2026-08-09T12:05:00Z", None);
    common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:10:05Z");

    let scope = std::collections::BTreeSet::from([host.clone()]);
    let sealed = || db.sealed_state(data.path()).unwrap();
    let before = db.load_state(sealed(), &scope).unwrap();
    let mut queued = before.clone();
    let mut queue = clave::collection::state::RecoveryQueue {
        owner: "sha256:owner".into(),
        end_s: Some(1_786_881_600),
        ..Default::default()
    };
    queue.queued.insert(
        ("default".into(), "key".into()),
        clave::collection::state::QueuedCatalog {
            envelope: second.envelope.clone(),
            catalog_id: second.catalog_id.clone(),
            place: clave::collection::state::Place::catalog(7, 0),
            sources: vec!["sha256:source".into()],
        },
    );
    queue.first.insert(
        "default".into(),
        clave::collection::state::Place::catalog(5, 0),
    );
    queued.queues.insert(host.clone(), queue);
    db.store_state(&before, &queued, &scope, "2026-08-09T12:20:00Z")
        .unwrap();
    let stored = db.load_state(sealed(), &scope).unwrap();
    assert!(
        !stored.urls.is_empty(),
        "the admitted URLs wait with their places"
    );
    assert!(stored.collections[&(host.clone(), "default".into())]
        .discarded_chain
        .is_some());
    let tree: Vec<String> = second.tree.keys().cloned().collect();
    let list = |db: &clave::db::Db| {
        use clave::collection::Held;
        let held = clave::db::StoreHeld::new(db, data.path(), "2026-08-09T12:30:00Z");
        (
            held.list(&host, "default", &second.catalog_id).unwrap(),
            tree.iter()
                .map(|hex| held.tree_file(hex).unwrap())
                .collect::<Vec<_>>(),
        )
    };
    let held = list(&db);
    assert!(held.0.is_some() && held.1.iter().all(Option::is_some));
    drop(db);

    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let reopened = db
        .load_state(db.sealed_state(data.path()).unwrap(), &scope)
        .unwrap();
    assert_eq!(reopened.collections, stored.collections);
    assert_eq!(reopened.lists, stored.lists);
    assert_eq!(reopened.urls, stored.urls);
    assert_eq!(reopened.queues, queued.queues);
    assert_eq!(reopened.discovered, stored.discovered);
    assert_eq!(reopened.events, stored.events);
    assert_eq!(db.waiting_publishers().unwrap(), scope);
    let waiting = db
        .load_waiting_state(db.sealed_state(data.path()).unwrap())
        .unwrap();
    assert_eq!(waiting.urls, stored.urls);
    assert_eq!(waiting.queues, queued.queues);
    assert_eq!(list(&db), held);
    assert_eq!(
        db.list_rejections(&host)
            .unwrap()
            .iter()
            .filter(|rejection| rejection.code == "WIST2-E08")
            .count(),
        1
    );
}

#[test]
fn a_pull_stopped_at_its_declaration_is_scheduled_on_the_backoff() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    let now = jiff::Timestamp::now().as_second();
    let at = |unix: i64| jiff::Timestamp::from_second(unix).unwrap().to_string();
    common::pull_at(&db, &client, data.path(), &host, &at(now - 60));
    std::fs::remove_file(p.dir.path().join(".well-known/wist/publisher.json")).unwrap();
    db.schedule_ping(&host, now, 4).unwrap();
    let task = db
        .claim_pulls(
            now,
            1,
            "me",
            clave::db::PARTITIONS as usize,
            &[],
            &mut true,
            true,
        )
        .unwrap()
        .remove(0);
    let run = clave::ingest::open_pull(
        &db,
        &client,
        data.path(),
        &host,
        &at(now),
        jiff::Timestamp::now,
        clave::ingest::PullLimits::default(),
    )
    .unwrap();
    let report = clave::ingest::finish_pull(&db, &task, "me", now, run, now).unwrap();
    assert_eq!(report.ended.as_deref(), Some("WIST2-E01"));
    let next = db.scheduled_pull(&host).unwrap().unwrap();
    assert_eq!(next.reason, clave::db::Reason::Retry);
    assert_eq!(next.attempts, 1);
}

#[test]
fn a_store_of_the_layout_before_collections_is_refused_at_open() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE publishers(domain TEXT PRIMARY KEY); PRAGMA user_version = 2;",
    )
    .unwrap();
    drop(conn);
    let error = clave::db::Db::open(&path).err().unwrap().to_string();
    assert!(error.contains("superseded layout 2"), "{error}");
}

#[test]
fn a_declaration_that_fails_verification_is_e01_and_an_unknown_key_is_e02() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    let path = p.dir.path().join(".well-known/wist/publisher.json");
    let stored: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut tampered = stored.clone();
    tampered["publisher"]["seq"] = 1.into();
    tampered["publisher"]["prev_declaration"] = common::declaration_hash(&stored).as_str().into();
    std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T13:00:05Z").unwrap();
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|r| r.code)
        .collect();
    assert!(codes.contains(&"WIST1-E01".to_string()), "codes {codes:?}");
    let mut unknown = tampered.clone();
    unknown["sig"]["key_id"] = "kX".into();
    std::fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T14:00:05Z").unwrap();
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|r| r.code)
        .collect();
    assert!(codes.contains(&"WIST1-E02".to_string()), "codes {codes:?}");
    assert_eq!(db.count_discovered_declarations(&host).unwrap(), 1);
}

#[test]
fn ingest_rejects_publisher_domain_mismatch() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher("not-the-host.example");
    serve_static(listener, p.dir.path().to_path_buf());
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert!(report.accepted.is_empty());
    assert_eq!(report.noise, Some("WIST2-E04"));
    assert!(db.get_publisher(&host).unwrap().is_none());
    let rejections = db.list_rejections(&host).unwrap();
    assert_eq!(rejections.len(), 1);
    assert_eq!(rejections[0].code, "WIST2-E04");
}

#[test]
fn invalid_first_declarations_remain_e04_noise_without_persistence() {
    for (mutation, reason) in [
        ("duplicate", "WIST1-E08"),
        ("unknown", "WIST1-E02"),
        ("signature", "WIST1-E01"),
        ("shape", "WIST1-E14"),
        ("encoding", "WIST1-E14"),
        ("excluded", "WIST1-E02"),
        ("host", "WIST1-E14"),
        ("scope", "WIST1-E14"),
        ("timestamp", "WIST1-E14"),
        ("optional-null", "WIST1-E14"),
    ] {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher(&host);
        let path = publisher.dir.path().join(".well-known/wist/publisher.json");
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let resign = |doc: &serde_json::Value, key: &wist_core::crypto::SigningKey| {
            wist_core::envelope::sign_envelope(&doc["publisher"], "publisher", &publisher.kid, key)
                .unwrap()
        };
        match mutation {
            "duplicate" => {
                let key = doc["publisher"]["keys"][0].clone();
                doc["publisher"]["keys"].as_array_mut().unwrap().push(key);
                doc = resign(&doc, &publisher.sk);
            }
            "unknown" => doc["sig"]["key_id"] = "unknown".into(),
            "signature" => {
                doc = resign(&doc, &wist_core::crypto::SigningKey::from_seed(&[22; 32]));
            }
            "encoding" => {
                let mut encoded = doc["sig"]["value"].as_str().unwrap().to_string();
                let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let last = encoded.pop().unwrap() as u8;
                let index = alphabet.iter().position(|byte| *byte == last).unwrap();
                encoded.push(alphabet[index + 1] as char);
                doc["sig"]["value"] = encoded.into();
            }
            "excluded" => {
                common::rekey(
                    &mut doc["publisher"]["keys"][0],
                    &wist_core::crypto::b64u_encode(&[0; 32]),
                );
                doc = resign(&doc, &publisher.sk);
            }
            "host" => doc["publisher"]["domain"] = format!("{host}:8080").into(),
            "scope" => doc["publisher"]["subdomain_scope"] = serde_json::json!(["EXAMPLE.com"]),
            "timestamp" => doc["publisher"]["keys"][0]["nbf"] = (-1).into(),
            "optional-null" => doc["publisher"]["contact"] = serde_json::Value::Null,
            _ => doc["extra"] = true.into(),
        }
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        serve_static(listener, publisher.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example", data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let report =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z").unwrap();
        assert!(report.accepted.is_empty(), "{mutation}");
        assert_eq!(report.noise, Some("WIST2-E04"), "{mutation}");
        assert!(db.get_publisher(&host).unwrap().is_none(), "{mutation}");
        assert_eq!(db.count_discovered_declarations(&host).unwrap(), 0);
        let rejected = db.list_rejections(&host).unwrap();
        let stopped = rejected
            .iter()
            .find(|rejection| rejection.code == "WIST2-E04")
            .unwrap_or_else(|| panic!("{mutation}: {rejected:?}"));
        assert!(
            stopped.detail.as_deref().unwrap().contains(reason),
            "{mutation}: {rejected:?}"
        );
        assert!(
            rejected
                .iter()
                .all(|rejection| [reason, "WIST2-E04"].contains(&rejection.code.as_str())),
            "{mutation}: {rejected:?}"
        );
    }
}

#[test]
fn declaration_field_rejections_preserve_signed_state_through_reopen_and_sealing() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher_with_scope(
        &host,
        &["example.com", "xn--bcher-kva.example", "-foo.example"],
    );
    let path = publisher.dir.path().join(".well-known/wist/publisher.json");
    let mut initial = common::current_declaration(&publisher)["publisher"].clone();
    initial["contact"] = "😀".repeat(256).into();
    initial["keys"][0]["nbf"] = 0.into();
    let signed =
        wist_core::envelope::sign_envelope(&initial, "publisher", &publisher.kid, &publisher.sk)
            .unwrap();
    std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
    serve_static(listener, publisher.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example", data.path()).unwrap();
    let database = data.path().join("clave.sqlite");
    let mut db = clave::db::Db::open(&database).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(report.noise, None);
    assert_eq!(db.count_discovered_declarations(&host).unwrap(), 1);
    for field in [
        "signature",
        "timestamp",
        "hostname",
        "optional-null",
        "length",
    ] {
        let mut incoming = signed.clone();
        match field {
            "signature" => incoming["sig"]["alg"] = "other".into(),
            "timestamp" => incoming["publisher"]["keys"][0]["nbf"] = 253_402_300_800u64.into(),
            "hostname" => incoming["publisher"]["domain"] = "LOCALHOST".into(),
            "optional-null" => incoming["publisher"]["recovery_keys"] = serde_json::Value::Null,
            _ => incoming["publisher"]["contact"] = "😀".repeat(257).into(),
        }
        std::fs::write(&path, serde_json::to_vec(&incoming).unwrap()).unwrap();
        let before = db.list_rejections(&host).unwrap().len();
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:01:00Z").unwrap();
        let rejections = db.list_rejections(&host).unwrap();
        let codes: Vec<&str> = rejections[..rejections.len() - before]
            .iter()
            .map(|rejection| rejection.code.as_str())
            .collect();
        assert_eq!(codes, ["WIST2-E01", "WIST1-E14"], "{field}");
        drop(db);
        db = clave::db::Db::open(&database).unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&db.get_publisher_declaration(&host).unwrap().unwrap()).unwrap();
        assert_eq!(stored, signed, "{field}");
        assert_eq!(db.count_discovered_declarations(&host).unwrap(), 1);
    }
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let at = wist_core::timestamp::log_seconds("2026-08-09T13:00:00Z").unwrap();
    clave::seal::run(&db, data.path(), &sk, at).unwrap();
    let state = clave::history::declarations::Declarations::reconstruct(
        &db,
        data.path(),
        db.last_epoch().unwrap(),
    )
    .unwrap();
    assert_eq!(*state.domains()[&host].current().envelope(), signed);
}

#[test]
fn unused_excluded_keys_survive_ingest_reopen_and_sealing_without_blocking_usable_keys() {
    let (listener, host, client) = reserve_addr();
    let publisher = make_publisher(&host);
    let path = publisher.dir.path().join(".well-known/wist/publisher.json");
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut excluded = doc["publisher"]["keys"][0].clone();
    common::rekey(&mut excluded, &wist_core::crypto::b64u_encode(&[0; 32]));
    doc["publisher"]["keys"]
        .as_array_mut()
        .unwrap()
        .insert(0, excluded);
    let signed = wist_core::envelope::sign_envelope(
        &doc["publisher"],
        "publisher",
        &publisher.kid,
        &publisher.sk,
    )
    .unwrap();
    std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
    let (item, payload) =
        common::page_item(&publisher, &format!("https://{host}/a"), "eligible content");
    common::publish_collection(
        &publisher,
        "default",
        &[(item.clone(), Some(payload))],
        "2026-08-09T12:00:00Z",
        None,
    );
    serve_static(listener, publisher.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example", data.path()).unwrap();
    let database = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&database).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(
        report.items,
        [format!("default/{}", common::item_id(&item))]
    );
    assert!(report.rejected.is_empty(), "{report:?}");
    drop(db);
    let db = clave::db::Db::open(&database).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let at = wist_core::timestamp::log_seconds("2026-08-09T13:00:00Z").unwrap();
    let sealed = clave::seal::run(&db, data.path(), &sk, at).unwrap();
    let entries = db.epoch_entries(sealed.epoch_number).unwrap();
    assert_eq!(entries[0]["body"], signed);
    assert_eq!(common::sealed_item_ids(&entries), [common::item_id(&item)]);
}

#[test]
fn an_established_publisher_is_admitted_at_first_contact_and_its_seq_becomes_the_floor() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let seed = common::current_declaration(&p)["publisher"].clone();
    let mut unseen = seed.clone();
    unseen["seq"] = 1.into();
    unseen["prev_declaration"] = common::declaration_hash(&common::current_declaration(&p)).into();
    unseen["contact"] = "mailto:unseen@example.com".into();
    common::write_declaration(&p, &unseen, &common::K1_SEED);
    let unseen = common::current_declaration(&p);
    let mut established = seed.clone();
    established["seq"] = 2.into();
    established["prev_declaration"] = common::declaration_hash(&unseen).into();
    common::write_declaration(&p, &established, &common::K1_SEED);
    let established = common::current_declaration(&p);
    let page = common::page_item(&p, &format!("https://{host}/a"), "first contact");
    let catalog = common::publish_collection(
        &p,
        "default",
        &with_payloads(std::slice::from_ref(&page)),
        "2026-08-09T12:00:00Z",
        None,
    );
    serve_static(listener, p.dir.path().to_path_buf());
    let (data, db) = open_store(&host);
    let stored = |db: &clave::db::Db| -> serde_json::Value {
        serde_json::from_slice(&db.get_publisher_declaration(&host).unwrap().unwrap()).unwrap()
    };

    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:05Z");
    assert_eq!(report.ended, None);
    assert_eq!(report.noise, None);
    assert_eq!(report.accepted, [format!("default/{}", catalog.catalog_id)]);
    assert_eq!(admitted_ids(&report), [common::item_id(&page.0)]);
    assert_eq!(stored(&db), established);
    assert_eq!(db.highest_accepted_declaration_seq(&host).unwrap(), Some(2));
    assert!(db.get_pending_identity(&host).unwrap().is_none());
    assert!(db.get_recovery_window(&host).unwrap().is_none());

    let mut forged = seed.clone();
    forged["seq"] = 1.into();
    forged["prev_declaration"] = common::declaration_hash(&established).into();
    common::write_declaration(&p, &forged, &common::K1_SEED);
    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T12:10:00Z");
    assert_eq!(report.ended.as_deref(), Some("WIST2-E01"));
    assert_eq!(report.noise, None);
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|rejection| rejection.code)
        .collect();
    assert_eq!(codes, ["WIST2-E01", "WIST1-E08"]);
    assert_eq!(stored(&db), established);

    let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let sealed_at = wist_core::timestamp::log_seconds("2026-08-09T13:00:00Z").unwrap();
    let height = clave::seal::run(&db, data.path(), &key, sealed_at)
        .unwrap()
        .epoch_number;
    let history = clave::history::declarations::Declarations::reconstruct(
        &db,
        data.path(),
        db.last_epoch().unwrap(),
    )
    .unwrap();
    let domain = &history.domains()[&host];
    assert_eq!(domain.current().envelope(), &established);
    assert_eq!(domain.highest_accepted_seq(), 2);
    assert_eq!(domain.first().epoch_number, height);
    assert!(domain.window().is_none() && domain.pending().is_none());

    let mut rotated = seed;
    rotated["seq"] = 3.into();
    rotated["prev_declaration"] = common::declaration_hash(&established).into();
    rotated["keys"] = serde_json::json!([
        common::key_entry(&common::K1_SEED, "2026-08-09T00:00:00Z"),
        common::key_entry(&common::K2_SEED, "2026-08-09T00:00:00Z"),
    ]);
    common::write_declaration(&p, &rotated, &common::K1_SEED);
    let rotated = common::current_declaration(&p);
    let report = common::pull_at(&db, &client, data.path(), &host, "2026-08-09T14:00:00Z");
    assert_eq!(report.ended, None);
    assert_eq!(report.noise, None);
    assert_eq!(stored(&db), rotated);
    assert_eq!(db.highest_accepted_declaration_seq(&host).unwrap(), Some(3));
    assert!(db.get_pending_identity(&host).unwrap().is_none());
    assert!(db.get_recovery_window(&host).unwrap().is_none());
}
