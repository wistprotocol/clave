mod common;

use common::{make_publisher_with_scope, page_item, publish_collection, reserve_addr, TestPub};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const ALL: usize = clave::db::PARTITIONS as usize;
const T0: i64 = 1_786_276_800;
const LAPSED: i64 = 700;
const HOLD_LIMIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_secs(20);

struct Origin {
    requests: Arc<Mutex<Vec<String>>>,
    held: mpsc::Receiver<()>,
    release: Arc<AtomicBool>,
}

impl Origin {
    fn wait_held(&self) {
        self.held
            .recv_timeout(Duration::from_secs(10))
            .expect("the pull requested the Payload");
    }

    fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn served(&self, suffix: &str) -> usize {
        self.requests()
            .iter()
            .filter(|path| path.ends_with(suffix))
            .count()
    }
}

fn serve_origin(listener: std::net::TcpListener, dir: std::path::PathBuf, hold: bool) -> Origin {
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let release = Arc::new(AtomicBool::new(false));
    let (tx, held) = mpsc::channel();
    let tx = Arc::new(Mutex::new(hold.then_some(tx)));
    let (recorded, released) = (requests.clone(), release.clone());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                let path = uri.path().to_string();
                recorded.lock().unwrap().push(path.clone());
                let first = if path.contains("/payloads/") {
                    tx.lock().unwrap().take()
                } else {
                    None
                };
                let (dir, released) = (dir.clone(), released.clone());
                async move {
                    if let Some(tx) = first {
                        let _ = tx.send(());
                        let until = tokio::time::Instant::now() + HOLD_LIMIT;
                        while !released.load(Ordering::SeqCst)
                            && tokio::time::Instant::now() < until
                        {
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
    Origin {
        requests,
        held,
        release,
    }
}

fn client_for(origin: std::net::SocketAddr) -> clave::fetch::Client {
    clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve("localhost", origin),
    )
}

fn spawn_server(
    data_dir: &Path,
    transport: clave::fetch::Client,
    options: clave::serve::ServeOptions,
) -> String {
    let bind = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let data_dir = data_dir.to_path_buf();
    let db_path = data_dir.join("clave.sqlite");
    std::thread::spawn(move || {
        clave::serve::run_with_options(data_dir, db_path, bind, transport, options).unwrap();
    });
    let addr = format!("http://{bind}");
    let client = reqwest::blocking::Client::new();
    poll_until("the server answers", Duration::from_secs(5), || {
        client
            .get(format!("{addr}/status/readiness-probe"))
            .send()
            .is_ok()
    });
    addr
}

fn serving(instance: &str) -> clave::serve::ServeOptions {
    clave::serve::ServeOptions {
        instance: instance.into(),
        seal: false,
        ..clave::serve::ServeOptions::default()
    }
}

fn ping(addr: &str, host: &str) -> u16 {
    reqwest::blocking::Client::new()
        .post(format!("{addr}/ingest"))
        .json(&serde_json::json!({"host": host}))
        .send()
        .unwrap()
        .status()
        .as_u16()
}

fn poll_until(what: &str, timeout: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !ready() {
        assert!(Instant::now() < deadline, "{what} within {timeout:?}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn store(data_dir: &Path) -> clave::db::Db {
    clave::db::Db::connect(&data_dir.join("clave.sqlite")).unwrap()
}

fn unix_now() -> i64 {
    jiff::Timestamp::now().as_second()
}

fn utc(second: i64) -> String {
    jiff::Timestamp::from_second(second).unwrap().to_string()
}

fn payload_files(data_dir: &Path) -> usize {
    std::fs::read_dir(data_dir.join("held/payloads")).map_or(0, |dir| dir.count())
}

fn open_runs(data_dir: &Path) -> i64 {
    rusqlite::Connection::open(data_dir.join("clave.sqlite"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pull_runs", [], |row| row.get(0))
        .unwrap()
}

fn payload_path(item: &serde_json::Value) -> String {
    format!(
        "/.well-known/wist/collections/default/payloads/{}.json",
        wist_core::item::payload_name(item).unwrap()
    )
}

fn admitted(data_dir: &Path, item_id: &str) -> i64 {
    rusqlite::Connection::open(data_dir.join("clave.sqlite"))
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM list_items WHERE item_id = ?1 AND admission = 'admitted'",
            [item_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn partition_lease(db: &clave::db::Db, host: &str) -> clave::db::Lease {
    let partition = db.partition_of(host).unwrap();
    db.partition_leases()
        .unwrap()
        .into_iter()
        .find(|(number, _)| *number == partition)
        .unwrap()
        .1
}

struct Fixture {
    host: String,
    _publisher: TestPub,
    item: serde_json::Value,
    id: String,
    origin: Origin,
    address: std::net::SocketAddr,
    client: clave::fetch::Client,
    data: tempfile::TempDir,
}

fn fixture(hold: bool) -> Fixture {
    let (listener, host, client) = reserve_addr();
    let address = listener.local_addr().unwrap();
    let publisher = make_publisher_with_scope(&host, &["example.com"]);
    let (item, payload) = page_item(&publisher, "https://example.com/a", "first content");
    let id = common::item_id(&item);
    publish_collection(
        &publisher,
        "default",
        &[(item.clone(), Some(payload))],
        "2026-08-09T12:00:00Z",
        None,
    );
    let origin = serve_origin(listener, publisher.dir.path().to_path_buf(), hold);
    let data = tempfile::tempdir().unwrap();
    clave::init::run("127.0.0.1:0", data.path()).unwrap();
    Fixture {
        host,
        _publisher: publisher,
        item,
        id,
        origin,
        address,
        client,
        data,
    }
}

#[test]
fn a_lapsed_task_of_a_running_dispatchers_own_partition_is_returned_and_pulled_exactly_once() {
    let f = fixture(false);
    let db = clave::db::Db::open(&f.data.path().join("clave.sqlite")).unwrap();
    let sk = clave::keys::load(&f.data.path().join("keys/seed")).unwrap();
    clave::param_change::run(&db, &sk, "feed_window", 500, None, unix_now()).unwrap();
    spawn_server(
        f.data.path(),
        client_for(f.address),
        clave::serve::ServeOptions {
            backlog_entries: 1,
            ..serving("worker")
        },
    );
    poll_until(
        "the dispatcher holds every partition",
        Duration::from_secs(5),
        || {
            store(f.data.path())
                .partition_leases()
                .unwrap()
                .iter()
                .all(|(_, lease)| lease.owner.as_deref() == Some("worker"))
        },
    );
    let token = partition_lease(&db, &f.host).token;

    let lapsed_at = unix_now() - LAPSED;
    db.schedule_ping(&f.host, lapsed_at, 4).unwrap();
    let lost = db
        .claim_pulls(lapsed_at, 1, "worker", ALL, &[], &mut true, true)
        .unwrap();
    assert_eq!(lost.len(), 1, "the lost worker's task is claimed");
    assert_eq!(lost[0].token, token);

    poll_until(
        "the dispatcher returns the lapsed task to the schedule",
        POLL,
        || {
            let db = store(f.data.path());
            db.pull_lease(&f.host).unwrap().is_none()
                && db
                    .scheduled_pull(&f.host)
                    .unwrap()
                    .is_some_and(|row| row.reason == clave::db::Reason::Retry)
        },
    );
    assert_eq!(
        partition_lease(&db, &f.host),
        clave::db::Lease {
            owner: Some("worker".into()),
            lease_until: partition_lease(&db, &f.host).lease_until,
            token,
        },
        "the dispatcher kept its partition at its token: the task was returned as a lapsed task of a held partition, not by a takeover"
    );
    assert_eq!(
        f.origin.served("/catalog.json"),
        0,
        "the returned Ping waits while the sealing backlog is full"
    );

    clave::seal::run(&db, f.data.path(), &sk, unix_now().div_euclid(3600) * 3600).unwrap();
    poll_until("the returned task is pulled", POLL, || {
        admitted(f.data.path(), &f.id) == 1
            && store(f.data.path()).pull_lease(&f.host).unwrap().is_none()
    });
    std::thread::sleep(Duration::from_millis(2500));

    assert_eq!(
        f.origin.served("/catalog.json"),
        1,
        "the domain is pulled exactly once"
    );
    assert_eq!(f.origin.served(&payload_path(&f.item)), 1);
    assert_eq!(admitted(f.data.path(), &f.id), 1);
    assert_eq!(payload_files(f.data.path()), 1);
    assert_eq!(db.pull_lease(&f.host).unwrap(), None);
    assert!(db.scheduled_pull(&f.host).unwrap().is_some());
    assert_eq!(partition_lease(&db, &f.host).token, token);
}

#[test]
fn a_running_dispatcher_takes_over_a_lost_workers_partition_and_pulls_while_the_lost_pull_is_still_in_flight(
) {
    let f = fixture(true);
    let path = f.data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let now = unix_now();
    let lapsed_at = now - LAPSED;
    db.schedule_ping(&f.host, lapsed_at, 4).unwrap();
    let old = db
        .claim_pulls(lapsed_at, 1, "old", ALL, &[], &mut true, true)
        .unwrap()
        .remove(0);
    let at = utc(now);
    let lost = {
        let (path, data, host, at, fence, client) = (
            path.clone(),
            f.data.path().to_path_buf(),
            f.host.clone(),
            at.clone(),
            old.fence(),
            f.client,
        );
        std::thread::spawn(move || {
            let db = clave::db::Db::connect(&path).unwrap().fenced(fence);
            clave::ingest::run(&db, &client, &data, &host, &at)
        })
    };
    f.origin.wait_held();

    spawn_server(f.data.path(), client_for(f.address), serving("successor"));
    poll_until("the successor pulls the domain", POLL, || {
        let db = store(f.data.path());
        admitted(f.data.path(), &f.id) == 1
            && db.pull_lease(&f.host).unwrap().is_none()
            && db.scheduled_pull(&f.host).unwrap().is_some()
    });
    let lease = partition_lease(&db, &f.host);
    assert_eq!(lease.owner.as_deref(), Some("successor"));
    assert_eq!(
        lease.token,
        old.token + 1,
        "the takeover increments the token"
    );
    assert_eq!(payload_files(f.data.path()), 1);
    assert_eq!(
        f.origin.served("/catalog.json"),
        2,
        "the successor fetches the Catalog again"
    );
    assert_eq!(
        f.origin.served(&payload_path(&f.item)),
        2,
        "the successor requests the Payload the lost pull still waits for"
    );

    f.origin.release();
    let outcome = lost.join().unwrap();
    assert!(
        matches!(outcome, Err(clave::Error::Fenced)),
        "{:?}",
        outcome.map(|report| report.items)
    );
    assert!(matches!(
        db.complete_pull(
            &old,
            "old",
            lapsed_at,
            clave::db::PullOutcome::Failed,
            0.0,
            unix_now()
        ),
        Err(clave::Error::Fenced)
    ));
    assert_eq!(admitted(f.data.path(), &f.id), 1);
    assert_eq!(payload_files(f.data.path()), 1);
    let lease = db.pull_lease(&f.host).unwrap();
    assert!(
        lease
            .as_ref()
            .is_none_or(|lease| lease.owner == "successor"),
        "{lease:?}"
    );
    assert!(lease.is_some() || db.scheduled_pull(&f.host).unwrap().is_some());
}

#[test]
fn a_ping_during_a_pull_in_flight_queues_one_follow_up_pull_that_starts_after_the_first_ends() {
    let f = fixture(true);
    let addr = spawn_server(f.data.path(), client_for(f.address), serving("primary"));
    assert_eq!(ping(&addr, &f.host), 202);
    f.origin.wait_held();
    assert_eq!(ping(&addr, &f.host), 202);
    let db = store(f.data.path());
    assert!(db.pull_lease(&f.host).unwrap().is_some());
    assert_eq!(
        db.scheduled_pull(&f.host).unwrap().map(|row| row.reason),
        Some(clave::db::Reason::Ping),
        "the Ping waits beside the pull in flight"
    );
    f.origin.release();

    poll_until("the follow-up pull completes", POLL, || {
        let db = store(f.data.path());
        f.origin.served("/catalog.json") == 2
            && db.pull_lease(&f.host).unwrap().is_none()
            && db
                .scheduled_pull(&f.host)
                .unwrap()
                .is_some_and(|row| row.reason == clave::db::Reason::Baseline)
    });
    let requests = f.origin.requests();
    let payload = payload_path(&f.item);
    let first_pull_end = requests.iter().position(|path| *path == payload).unwrap();
    let second_pull_start = requests
        .iter()
        .enumerate()
        .filter(|(_, path)| path.ends_with("/catalog.json"))
        .nth(1)
        .unwrap()
        .0;
    assert!(
        second_pull_start > first_pull_end,
        "the second pull began before the first ended: {requests:?}"
    );
    assert_eq!(
        f.origin.served(&payload),
        1,
        "the follow-up pull judges the held Payload"
    );
    assert_eq!(admitted(f.data.path(), &f.id), 1);
    assert_eq!(payload_files(f.data.path()), 1);
}

#[test]
fn an_item_judged_after_an_epoch_sealed_during_its_payload_fetch_is_admitted() {
    let f = fixture(true);
    let path = f.data.path().join("clave.sqlite");
    let sk = clave::keys::load(&f.data.path().join("keys/seed")).unwrap();
    let pull = {
        let (path, data, host, client) = (
            path.clone(),
            f.data.path().to_path_buf(),
            f.host.clone(),
            f.client,
        );
        std::thread::spawn(move || {
            let db = clave::db::Db::connect(&path).unwrap();
            clave::ingest::run(&db, &client, &data, &host, "2026-08-09T12:30:00Z")
        })
    };
    f.origin.wait_held();
    let sealer = clave::db::Db::connect(&path).unwrap();
    let sealed = clave::seal::run(&sealer, f.data.path(), &sk, T0 + 3600).unwrap();
    assert!(sealed.dropped.is_empty(), "{:?}", sealed.dropped);
    f.origin.release();
    let report = pull.join().unwrap().unwrap();
    assert_eq!(report.items, vec![format!("default/{}", f.id)]);
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    assert_eq!(admitted(f.data.path(), &f.id), 1);
    assert_eq!(payload_files(f.data.path()), 1);
}

#[test]
fn a_domain_reassigned_after_its_walk_suspended_resumes_from_the_held_tree_files_and_admits_each_item_once(
) {
    for old_completes in [false, true] {
        let (listener, host, client) = reserve_addr();
        let address = listener.local_addr().unwrap();
        let p = make_publisher_with_scope(&host, &["example.com"]);
        let items: Vec<(serde_json::Value, Option<serde_json::Value>)> = (0..40)
            .map(|n| {
                let (item, payload) = page_item(&p, &format!("https://example.com/{n}"), "content");
                (item, Some(payload))
            })
            .collect();
        publish_collection(&p, "default", &[], "2026-08-09T09:00:00Z", None);
        let origin = serve_origin(listener, p.dir.path().to_path_buf(), false);
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = clave::db::Db::open(&path).unwrap();
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T09:00:00Z").unwrap();
        let published = publish_collection(&p, "default", &items, "2026-08-09T13:00:00Z", None);
        assert!(published.tree.len() > 3, "the tree spans several files");
        let before = origin.requests().len();

        let now = unix_now();
        let old = db
            .claim_pulls(now - LAPSED, 1, "old", ALL, &[], &mut true, true)
            .unwrap()
            .remove(0);
        let at = "2026-08-09T14:00:05Z";
        let clock = || at.parse::<jiff::Timestamp>().unwrap();
        let pull = clave::db::Db::connect(&path).unwrap().fenced(old.fence());
        let run = clave::ingest::open_pull(
            &pull,
            &client,
            data.path(),
            &host,
            at,
            clock,
            clave::ingest::PullLimits {
                work_bytes: u64::MAX,
                work_objects: 3,
                ..Default::default()
            },
        )
        .unwrap();
        if old_completes {
            let report =
                clave::ingest::finish_pull(&pull, &old, "old", now - LAPSED, run, now).unwrap();
            assert!(report.suspended, "the first pull suspends its walk");
            assert!(report.items.is_empty());
        }
        let walked: Vec<String> = origin.requests()[before..]
            .iter()
            .filter(|path| path.contains("/tree/"))
            .cloned()
            .collect();
        assert_eq!(
            walked.len(),
            1,
            "after the missing change list the first pull reads the root tree file and suspends"
        );

        let new = db
            .claim_pulls(now, 1, "new", ALL, &[], &mut true, true)
            .unwrap()
            .remove(0);
        assert_eq!(new.domain, host);
        assert_eq!(new.token, old.token + 1);
        if !old_completes {
            assert!(matches!(
                clave::ingest::finish_pull(&pull, &old, "old", now - LAPSED, run, now),
                Err(clave::Error::Fenced)
            ));
            assert_eq!(
                open_runs(data.path()),
                1,
                "the lost pull leaves its run behind"
            );
        }
        let resumed_from = origin.requests().len();
        let pull = clave::db::Db::connect(&path).unwrap().fenced(new.fence());
        let run = clave::ingest::open_pull(
            &pull,
            &client_for(address),
            data.path(),
            &host,
            "2026-08-09T14:10:05Z",
            || "2026-08-09T14:10:05Z".parse::<jiff::Timestamp>().unwrap(),
            clave::ingest::PullLimits::default(),
        )
        .unwrap();
        let second = clave::ingest::finish_pull(&pull, &new, "new", now, run, now).unwrap();
        assert!(!second.suspended);

        let resumed = origin.requests()[resumed_from..].to_vec();
        for file in &walked {
            assert!(
                !resumed.contains(file),
                "old completes: {old_completes}: the new holder fetched the held {file} again: {resumed:?}"
            );
        }
        assert_eq!(
            resumed
                .iter()
                .filter(|path| path.contains("/tree/"))
                .count(),
            published.tree.len() - walked.len()
        );
        assert_eq!(
            second.items.len(),
            items.len(),
            "old completes: {old_completes}"
        );
        for (item, _) in &items {
            assert_eq!(admitted(data.path(), &common::item_id(item)), 1);
        }
        assert_eq!(payload_files(data.path()), items.len());
        assert_eq!(open_runs(data.path()), 0);
        assert_eq!(db.pull_lease(&host).unwrap(), None);
        assert!(db.scheduled_pull(&host).unwrap().is_some());
    }
}
