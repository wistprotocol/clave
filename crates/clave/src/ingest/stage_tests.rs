use super::*;

const SEED: [u8; 32] = [1; 32];
const NOW: &str = "2026-08-09T12:00:05Z";

fn signing_key() -> wist_core::crypto::SigningKey {
    wist_core::crypto::SigningKey::from_seed(&SEED)
}

fn kid() -> String {
    wist_core::objects::publisher::thumbprint(&signing_key().public().to_b64u())
}

fn sign(body: &Value, kind: &str) -> Value {
    wist_core::envelope::sign_envelope(body, kind, &kid(), &signing_key()).unwrap()
}

#[derive(Default)]
struct Origin {
    delay_ms: std::sync::atomic::AtomicU64,
    served: std::sync::Mutex<Vec<String>>,
}

impl Origin {
    fn delay(&self, ms: u64) {
        self.delay_ms.store(ms, std::sync::atomic::Ordering::SeqCst);
    }

    fn take_served(&self) -> Vec<String> {
        std::mem::take(&mut self.served.lock().unwrap())
    }

    async fn serve(&self, root: &std::path::Path, path: &str) -> Option<Vec<u8>> {
        use std::sync::atomic::Ordering::SeqCst;
        self.served.lock().unwrap().push(path.to_string());
        let delay = self.delay_ms.load(SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        std::fs::read(root.join(path.trim_start_matches('/'))).ok()
    }
}

pub(crate) struct Site {
    dir: tempfile::TempDir,
    pub(crate) host: String,
    client: Client,
    origin: std::sync::Arc<Origin>,
}

impl Site {
    pub(crate) fn new() -> Site {
        Site::at("localhost")
    }

    fn at(host: &str) -> Site {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = Client::with_builder(
            true,
            reqwest::blocking::Client::builder()
                .no_proxy()
                .resolve(host, listener.local_addr().unwrap()),
        );
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let origin = std::sync::Arc::new(Origin::default());
        let served = origin.clone();
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                        let (origin, root) = (served.clone(), root.clone());
                        async move {
                            match origin.serve(&root, uri.path()).await {
                                Some(bytes) => (axum::http::StatusCode::OK, bytes),
                                None => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                            }
                        }
                    });
                    axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                        .await
                        .unwrap();
                });
        });
        let site = Site {
            dir,
            host: host.into(),
            client,
            origin,
        };
        let key = wist_core::objects::PublisherKey::new(
            &signing_key().public().to_b64u(),
            registry::unix("2026-08-09T00:00:00Z").unwrap() as u64,
            None,
        );
        site.write(
            "publisher.json",
            &sign(
                &serde_json::json!({
                    "wist_version": "1.0.0", "domain": site.host,
                    "keys": [key], "seq": 0
                }),
                "publisher",
            ),
        );
        site.collection("default", &[], "2026-08-09T08:00:00Z");
        site
    }

    fn write(&self, path: &str, doc: &Value) {
        let path = self.dir.path().join(".well-known/wist").join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec(doc).unwrap()).unwrap();
    }

    pub(crate) fn page_item(&self, url: &str, extract: &str) -> (Value, Value) {
        let salt = wist_core::crypto::b64u_encode(&[5u8; 16]);
        let content = serde_json::json!({
            "extract": extract,
            "links": {"total": 0, "urls": []},
            "summary": {"title": url}
        });
        let item = serde_json::json!({
            "publisher": self.host, "url": url, "observed_at": "2026-08-09T07:00:00Z",
            "payload": {
                "commitment": wist_core::item::commitment(&salt, &content).unwrap(),
                "alg": "HMAC-SHA256",
                "bytes": wist_core::jcs::canonicalize(&content).unwrap().len()
            },
            "meta": {"lang": "en"}
        });
        let payload =
            serde_json::json!({"wist_version": "1.0.0", "salt": salt, "content": content});
        (item, payload)
    }

    pub(crate) fn collection(&self, name: &str, items: &[(Value, Value)], generated_at: &str) {
        let list: Vec<Value> = items.iter().map(|(item, _)| item.clone()).collect();
        let bounds = wist_core::tree::TreeBounds::new(65_536, 16).unwrap();
        let built = wist_core::tree::build(&list, &bounds).unwrap();
        let root = wist_core::item::root(&list).unwrap();
        let base = self
            .dir
            .path()
            .join(format!(".well-known/wist/collections/{name}"));
        std::fs::create_dir_all(base.join("tree")).unwrap();
        std::fs::create_dir_all(base.join("payloads")).unwrap();
        for (hex, octets) in &built.files {
            std::fs::write(base.join("tree").join(hex), octets).unwrap();
        }
        for (item, payload) in items {
            std::fs::write(
                base.join(format!(
                    "payloads/{}.json",
                    wist_core::item::payload_name(item).unwrap()
                )),
                wist_core::jcs::canonicalize(payload).unwrap(),
            )
            .unwrap();
        }
        let catalog = sign(
            &serde_json::json!({
                "wist_version": "1.0.0", "publisher": self.host, "collection": name,
                "generated_at": generated_at, "size": list.len(),
                "root": format!("sha256:{}", wist_core::crypto::hex_encode(&root)),
                "tree": built.tree,
            }),
            "catalog",
        );
        std::fs::write(
            base.join("catalog.json"),
            wist_core::jcs::canonicalize(&catalog).unwrap(),
        )
        .unwrap();
    }

    fn read(&self, path: &str) -> Value {
        serde_json::from_slice(
            &std::fs::read(self.dir.path().join(".well-known/wist").join(path)).unwrap(),
        )
        .unwrap()
    }

    pub(crate) fn label(&self, subject: &str, asserted_at: &str) -> String {
        let label = serde_json::json!({
            "wist_version": "1.0.0", "labeler": self.host, "subject": subject,
            "name": "wist:spam", "asserted_at": asserted_at
        });
        let id = wist_core::label::label_id(&label).unwrap();
        self.write(&format!("labels/{}.json", &id[7..]), &sign(&label, "label"));
        id
    }

    fn unreadable_label(&self, seed: u8) -> String {
        let id = format!("sha256:{}", wist_core::crypto::hex_encode(&[seed; 32]));
        self.write(
            &format!("labels/{}.json", &id[7..]),
            &serde_json::json!({"wist_version": "1.0.0"}),
        );
        id
    }

    fn feed_doc(&self, ids: &[String], generated_at: &str, next: Option<u64>) -> Value {
        let next =
            next.map(|n| format!("https://{}/.well-known/wist/label-feed/{n}.json", self.host));
        sign(
            &serde_json::json!({
                "wist_version": "1.0.0", "domain": self.host,
                "generated_at": generated_at, "deltas": ids, "next": next
            }),
            "feed",
        )
    }

    pub(crate) fn label_feed(&self, ids: &[String], generated_at: &str, next: Option<u64>) {
        self.write("label-feed.json", &self.feed_doc(ids, generated_at, next));
    }

    fn page(&self, number: u64, ids: &[String], generated_at: &str) {
        let doc = self.feed_doc(ids, generated_at, number.checked_sub(1));
        self.write(&format!("label-feed/{number}.json"), &doc);
    }
}

pub(crate) struct Log {
    pub(crate) data: tempfile::TempDir,
    pub(crate) db: Db,
}

impl Log {
    fn new() -> Log {
        let data = tempfile::tempdir().unwrap();
        crate::init::run("127.0.0.1:0", data.path()).unwrap();
        let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
        Log { data, db }
    }

    pub(crate) fn onboard(site: &Site) -> Log {
        Log::new().onboarded(site)
    }

    fn with_suffix_list() -> Log {
        let log = Log::new();
        let file = log.data.path().join("suffixes.dat");
        std::fs::write(
            &file,
            "// ===BEGIN ICANN DOMAINS===\ncom\nnet\nlocalhost\n// ===END ICANN DOMAINS===\n",
        )
        .unwrap();
        let signing = crate::keys::load(&log.data.path().join("keys/seed")).unwrap();
        let seal = instant("2026-08-09T08:00:00Z").as_second();
        crate::suffix_list::pin(&log.db, log.data.path(), &signing, &file, seal - 1).unwrap();
        crate::seal::run(&log.db, log.data.path(), &signing, seal).unwrap();
        log
    }

    fn onboarded(self, site: &Site) -> Log {
        let Log { data, db } = self;
        let live = site.dir.path().join(".well-known/wist/label-feed.json");
        let feed = std::fs::read(&live).ok();
        let _ = std::fs::remove_file(&live);
        run(
            &db,
            &site.client,
            data.path(),
            &site.host,
            "2026-08-09T09:00:00Z",
        )
        .unwrap();
        let signing = crate::keys::load(&data.path().join("keys/seed")).unwrap();
        crate::seal::run(
            &db,
            data.path(),
            &signing,
            instant("2026-08-09T09:00:00Z").as_second(),
        )
        .unwrap();
        if let Some(feed) = feed {
            std::fs::write(&live, feed).unwrap();
        }
        Log { data, db }
    }

    pub(crate) fn path(&self) -> std::path::PathBuf {
        self.data.path().join("clave.sqlite")
    }

    pub(crate) fn pull(&self, site: &Site) -> Result<IngestReport> {
        run(&self.db, &site.client, self.data.path(), &site.host, NOW)
    }

    fn pull_with(&self, site: &Site, limits: PullLimits) -> Result<IngestReport> {
        run_bounded(
            &self.db,
            &site.client,
            self.data.path(),
            &site.host,
            NOW,
            || instant(NOW),
            limits,
        )
    }

    fn open_pull(&self, site: &Site, limits: PullLimits) -> i64 {
        open_pull(
            &self.db,
            &site.client,
            self.data.path(),
            &site.host,
            NOW,
            || instant(NOW),
            limits,
        )
        .unwrap()
        .unwrap()
    }

    fn count(&self, query: &str, run_id: i64) -> i64 {
        rusqlite::Connection::open(self.path())
            .unwrap()
            .query_row(query, [run_id], |row| row.get(0))
            .unwrap()
    }
}

fn instant(at: &str) -> jiff::Timestamp {
    at.parse().unwrap()
}

fn start_run(db: &Db, host: &str, now: &str) -> PullRun {
    db.start_pull_run(&NewRun {
        domain: host,
        now,
        day: &now[..10],
        unit: host,
        work_bytes: 1 << 20,
        work_objects: 64,
        pages_epoch: None,
    })
    .unwrap()
}

fn admitted_state(log: &Log) -> Vec<String> {
    let conn = rusqlite::Connection::open(log.path()).unwrap();
    let mut dump = Vec::new();
    for query in [
        "SELECT entry_type, domain, CAST(entry_json AS TEXT) FROM pending_entries ORDER BY rowid",
        "SELECT id, domain FROM seen_labels ORDER BY id",
        "SELECT publisher, name, accepted_id, left_chain FROM collections ORDER BY publisher, name",
        "SELECT publisher, name, catalog_id, idx, item_id, admission, code FROM list_items ORDER BY publisher, name, catalog_id, idx",
        "SELECT publisher, url, collection, item_id FROM waiting_urls ORDER BY publisher, url",
        "SELECT publisher, name, catalog_id, size FROM held_lists ORDER BY publisher, name, catalog_id",
        "SELECT sha256 FROM tree_files ORDER BY sha256",
    ] {
        let mut statement = conn.prepare(query).unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                let mut fields = Vec::new();
                for column in 0..columns {
                    fields.push(format!(
                        "{:?}",
                        row.get::<_, rusqlite::types::Value>(column)?
                    ));
                }
                Ok(fields.join("|"))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        dump.push(format!("{query}: {}", rows.join(" / ")));
    }
    dump
}

fn open_runs(log: &Log) -> i64 {
    rusqlite::Connection::open(log.path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pull_runs", [], |row| row.get(0))
        .unwrap()
}

/// SQLite fires `UPDATE OF` on the statement's SET list, so this counts
/// writes of the queue column, changed value or not.
fn count_queue_writes(log: &Log) {
    rusqlite::Connection::open(log.path())
        .unwrap()
        .execute_batch(
            "CREATE TABLE queue_writes(writes INTEGER NOT NULL);
            INSERT INTO queue_writes VALUES (0);
            CREATE TRIGGER count_queue_writes AFTER UPDATE OF queue_json ON pull_runs BEGIN
                UPDATE queue_writes SET writes = writes + 1;
            END;",
        )
        .unwrap();
}

fn queue_writes(log: &Log) -> i64 {
    rusqlite::Connection::open(log.path())
        .unwrap()
        .query_row("SELECT writes FROM queue_writes", [], |row| row.get(0))
        .unwrap()
}

fn walked_site() -> (Site, [String; 3]) {
    let site = Site::new();
    let pages = [
        site.page_item("https://localhost/a", "first page"),
        site.page_item("https://localhost/b", "second page"),
    ];
    site.collection("default", &pages, "2026-08-09T11:45:00Z");
    let paged = site.label("https://other.example/paged", "2026-08-09T10:00:00Z");
    let broken = site.unreadable_label(9);
    let live = site.label("https://other.example/live", "2026-08-09T11:30:00Z");
    site.page(0, std::slice::from_ref(&paged), "2026-08-09T10:30:00Z");
    site.label_feed(&[broken.clone(), live.clone()], NOW, Some(0));
    (site, [paged, broken, live])
}

#[test]
fn delivering_the_same_fetched_or_verified_result_twice_changes_nothing() {
    let site = Site::new();
    let id = site.label("https://other.example/a", "2026-08-09T11:00:00Z");
    let log = Log::onboard(&site);
    let db = &log.db;
    let host = site.host.clone();
    let mut run = start_run(db, &host, NOW);
    let slot = format!("{id}#0");
    let raw = serde_json::to_vec(&site.read(&format!("labels/{}.json", &id[7..]))).unwrap();

    let spent = db.ingest_bytes(&host, &NOW[..10]).unwrap();
    db.reserve_pull_object(
        run.run_id,
        "label",
        &slot,
        "https://localhost/l",
        &host,
        &NOW[..10],
        100,
    )
    .unwrap();
    assert!(db
        .settle_pull_object(&run, "label", &slot, Settled::Body(&raw))
        .unwrap());
    let debited = db.ingest_bytes(&host, &NOW[..10]).unwrap();
    assert_eq!(debited, spent + raw.len() as i64);
    assert!(
        !db.settle_pull_object(&run, "label", &slot, Settled::Body(&raw))
            .unwrap(),
        "a second delivery of the same response is not persisted again"
    );
    assert_eq!(db.ingest_bytes(&host, &NOW[..10]).unwrap(), debited);

    assert!(db
        .advance_pull_object(
            run.run_id,
            "label",
            &slot,
            &[Status::Fetched],
            Status::Verified,
            None
        )
        .unwrap());
    assert!(!db
        .advance_pull_object(
            run.run_id,
            "label",
            &slot,
            &[Status::Fetched],
            Status::Verified,
            None
        )
        .unwrap());

    let refused = site.unreadable_label(3);
    let slot = format!("{refused}#0");
    let refusal = admit::Refusal {
        index: 1,
        id: &refused,
        kind: "label",
        slot: &slot,
    };
    for _ in 0..2 {
        admit::reject_item(db, &mut run, &host, &refusal, "WIST2-E06", "unavailable").unwrap();
    }
    assert_eq!(
        db.list_rejections(&host)
            .unwrap()
            .iter()
            .filter(|rejection| rejection.id.as_deref() == Some(refused.as_str()))
            .count(),
        1
    );
    assert_eq!(db.pull_report(run.run_id).unwrap().len(), 1);
}

#[test]
fn the_reservation_a_crashed_pull_left_is_released_with_its_run_and_settles_once() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let (db, host, day) = (&log.db, site.host.clone(), &NOW[..10]);
    let spent = db.ingest_bytes(&host, day).unwrap();
    let run = start_run(db, &host, NOW);
    let slot = "sha256:abc#0";
    db.reserve_pull_object(
        run.run_id,
        "label",
        slot,
        "https://localhost/l",
        &host,
        day,
        4096,
    )
    .unwrap();
    assert_eq!(
        db.ingest_bytes(&host, day).unwrap(),
        spent + 4096,
        "an issued request reserves its whole bound against the budget"
    );

    let next = start_run(db, &host, NOW);
    assert_ne!(next.run_id, run.run_id, "the open run is not continued");
    assert_eq!(
        db.ingest_bytes(&host, day).unwrap(),
        spent,
        "the reservation of the request that never settled returns to the budget"
    );
    db.reserve_pull_object(
        next.run_id,
        "label",
        slot,
        "https://localhost/l",
        &host,
        day,
        4096,
    )
    .unwrap();
    assert_eq!(db.ingest_bytes(&host, day).unwrap(), spent + 4096);
    db.settle_pull_object(&next, "label", slot, Settled::Body(b"12345"))
        .unwrap();
    assert_eq!(db.ingest_bytes(&host, day).unwrap(), spent + 5);
}

#[test]
fn a_reservation_settles_and_releases_on_the_row_its_request_was_issued_against() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let (db, host, day) = (&log.db, site.host.clone(), &NOW[..10]);
    let (crossed_unit, crossed_day) = ("sub.localhost", "2026-08-10");
    let spent = db.ingest_bytes(&host, day).unwrap();
    let run = start_run(db, &host, NOW);
    let slot = "sha256:abc#0";
    db.reserve_pull_object(
        run.run_id,
        "label",
        slot,
        "https://localhost/l",
        crossed_unit,
        crossed_day,
        4096,
    )
    .unwrap();
    assert_eq!(db.ingest_bytes(crossed_unit, crossed_day).unwrap(), 4096);
    assert_eq!(
        db.ingest_bytes(&host, day).unwrap(),
        spent,
        "a request issued against another row does not reserve on the run's"
    );

    assert!(db
        .settle_pull_object(&run, "label", slot, Settled::Body(b"12345"))
        .unwrap());
    assert_eq!(
        db.ingest_bytes(crossed_unit, crossed_day).unwrap(),
        5,
        "the response settles on the row its bound was reserved against"
    );
    assert_eq!(db.ingest_bytes(&host, day).unwrap(), spent);

    db.reserve_pull_object(
        run.run_id,
        "page",
        "label:0",
        "https://localhost/f",
        crossed_unit,
        crossed_day,
        2048,
    )
    .unwrap();
    assert_eq!(
        db.ingest_bytes(crossed_unit, crossed_day).unwrap(),
        5 + 2048
    );
    db.delete_pull_run(run.run_id).unwrap();
    assert_eq!(
        db.ingest_bytes(crossed_unit, crossed_day).unwrap(),
        5,
        "the reservation that never settled returns to the row it debited"
    );
    assert_eq!(db.ingest_bytes(&host, day).unwrap(), spent);
}

#[test]
fn a_fresh_pull_after_an_interruption_at_any_commit_admits_what_one_pull_admits() {
    let (site, ids) = walked_site();
    let expected = {
        let log = Log::onboard(&site);
        let report = log.pull(&site).unwrap();
        assert_eq!(report.labels, [ids[0].clone(), ids[2].clone()]);
        assert_eq!(report.rejected, [(ids[1].clone(), "WIST2-E06".to_string())]);
        assert_eq!(report.accepted.len(), 1, "the default Catalog is accepted");
        assert_eq!(report.items.len(), 2, "both Items are admitted");
        assert!(!report.suspended && report.noise.is_none());
        admitted_state(&log)
    };
    for commits in 0.. {
        let log = Log::onboard(&site);
        crate::db::interrupt::after(commits);
        let interrupted =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| log.pull(&site)));
        if crate::db::interrupt::disarm() {
            assert!(interrupted.is_ok(), "the pull ran to its end");
            assert!(commits > 0, "the pull commits at least once");
            break;
        }
        assert!(
            interrupted.is_err(),
            "the {commits}th commit interrupts the pull"
        );
        let fresh = log.pull(&site).unwrap();
        assert!(
            !fresh.suspended,
            "the pull after the {commits}th commit runs to its end"
        );
        assert_eq!(
            admitted_state(&log),
            expected,
            "a fresh pull after the {commits}th commit"
        );
        assert_eq!(open_runs(&log), 0, "the fresh pull closed its own run");
    }
}

#[test]
fn a_pull_never_continues_the_run_an_interrupted_pull_left_open() {
    let site = Site::new();
    let log = Log::onboard(&site);
    let db = &log.db;
    let run = start_run(db, &site.host, NOW);
    db.record_pull_object(
        run.run_id,
        "label",
        "sha256:abc#0",
        "https://localhost/l",
        Status::Fetched,
        Some(b"{}"),
        None,
    )
    .unwrap();

    let next = start_run(db, &site.host, NOW);
    assert_ne!(next.run_id, run.run_id, "the pull begins a fresh run");
    assert_eq!(open_runs(&log), 1, "one run per domain");
    assert!(
        db.pull_object(run.run_id, "label", "sha256:abc#0")
            .unwrap()
            .is_none(),
        "the objects of the run left open are dropped with it"
    );
    assert_eq!(
        next.phase,
        Phase::Walk,
        "a fresh run starts at Declaration discovery"
    );
    assert_eq!(next.now, NOW, "a fresh run takes the new pull's clock");
}

#[test]
fn settling_a_fetch_or_admitting_an_item_does_not_write_the_run_s_queue() {
    let mut writes = Vec::new();
    for items in [2u32, 8] {
        let site = Site::new();
        let ids: Vec<String> = (0..items)
            .map(|n| {
                site.label(
                    &format!("https://other.example/{n}"),
                    "2026-08-09T11:00:00Z",
                )
            })
            .collect();
        site.label_feed(&ids, NOW, None);
        let log = Log::onboard(&site);
        count_queue_writes(&log);
        let report = log.pull(&site).unwrap();
        assert_eq!(report.labels, ids, "every listed Label is admitted");
        writes.push(queue_writes(&log));
    }
    assert_eq!(
        writes[0], writes[1],
        "the queue is written where it changes, not once per item decided"
    );
    assert_eq!(writes[0], 1, "the Label Feed walk ends once");
}

#[test]
fn a_decided_label_holds_no_fetched_bytes_while_its_run_is_open() {
    let (site, _) = walked_site();
    let log = Log::onboard(&site);
    let run_id = log.open_pull(&site, PullLimits::default());
    let decided = "FROM pull_objects WHERE run_id = ?1 AND kind = 'label' AND status IN ('admitted', 'rejected')";
    assert_eq!(
        log.count(
            &format!("SELECT COUNT(*) {decided} AND byte_len > 0 AND debited > 0"),
            run_id
        ),
        3,
        "the decided objects keep their size and debit"
    );
    assert_eq!(
        log.count(
            &format!("SELECT COUNT(*) {decided} AND raw IS NOT NULL"),
            run_id
        ),
        0
    );
    assert!(
        log.count(
            "SELECT COUNT(*) FROM pull_objects WHERE run_id = ?1 AND kind IN ('page', 'declaration') AND raw IS NOT NULL",
            run_id
        ) >= 3,
        "pages and Declarations keep their octets"
    );
}

fn track_cursor_peak(log: &Log) {
    rusqlite::Connection::open(log.path())
        .unwrap()
        .execute_batch(
            "CREATE TABLE cursor_peak(pages INTEGER NOT NULL, bytes INTEGER NOT NULL);
            INSERT INTO cursor_peak VALUES (0, 0);
            CREATE TRIGGER track_cursor_peak AFTER INSERT ON pull_walk BEGIN
                UPDATE cursor_peak SET
                    pages = MAX(pages, (SELECT COUNT(*) FROM pull_walk WHERE domain = NEW.domain AND feed = NEW.feed)),
                    bytes = MAX(bytes, (SELECT COALESCE(SUM(LENGTH(raw)), 0) FROM pull_walk WHERE domain = NEW.domain AND feed = NEW.feed));
            END;",
        )
        .unwrap();
}

fn cursor_peak(log: &Log) -> (u64, u64) {
    rusqlite::Connection::open(log.path())
        .unwrap()
        .query_row("SELECT pages, bytes FROM cursor_peak", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap()
}

fn paged_site() -> (Site, Vec<String>) {
    let site = Site::new();
    let ids: Vec<String> = (0..5)
        .map(|n| {
            site.label(
                &format!("https://other.example/{n}"),
                &format!("2026-08-09T10:0{n}:00Z"),
            )
        })
        .collect();
    for (page, id) in ids[..4].iter().enumerate() {
        site.page(
            page as u64,
            std::slice::from_ref(id),
            &format!("2026-08-09T10:3{page}:00Z"),
        );
    }
    site.label_feed(std::slice::from_ref(&ids[4]), NOW, Some(3));
    (site, ids.into_iter().rev().collect())
}

fn served_pages(site: &Site) -> Vec<String> {
    site.origin
        .take_served()
        .into_iter()
        .filter(|path| path.contains("/label-feed"))
        .collect()
}

#[test]
fn the_walk_cursor_page_bound_ends_the_walk_as_an_absent_next_does() {
    let (site, ids) = paged_site();
    let log = Log::onboard(&site);
    track_cursor_peak(&log);
    let rejections = log.db.list_rejections(&site.host).unwrap().len();
    site.origin.take_served();
    let limits = PullLimits {
        walk_pages: 3,
        ..PullLimits::default()
    };
    let report = log.pull_with(&site, limits).unwrap();
    assert_eq!(
        report.labels,
        [ids[2].clone(), ids[1].clone(), ids[0].clone()]
    );
    assert!(!report.suspended && report.ended.is_none() && report.rejected.is_empty());
    assert_eq!(
        log.db.list_rejections(&site.host).unwrap().len(),
        rejections
    );
    assert_eq!(
        served_pages(&site),
        [
            "/.well-known/wist/label-feed.json",
            "/.well-known/wist/label-feed/3.json",
            "/.well-known/wist/label-feed/2.json"
        ]
    );
    let (pages, bytes) = cursor_peak(&log);
    assert_eq!(pages, 3);
    assert!(bytes <= limits.walk_bytes);

    let report = log.pull_with(&site, limits).unwrap();
    assert!(report.labels.is_empty() && !report.suspended);
    assert_eq!(
        served_pages(&site),
        ["/.well-known/wist/label-feed.json"],
        "a later walk stops at the first page listing no unseen ID"
    );
}

#[test]
fn the_walk_cursor_byte_bound_counts_a_page_it_does_not_hold_at_the_page_cap() {
    let (site, ids) = paged_site();
    let size = |path: &str| {
        std::fs::metadata(site.dir.path().join(".well-known/wist").join(path))
            .unwrap()
            .len()
    };
    let log = Log::onboard(&site);
    track_cursor_peak(&log);
    let limits = PullLimits {
        walk_bytes: crate::fetch::OBJECT_CAP_BYTES
            + size("label-feed.json")
            + size("label-feed/3.json")
            - 1,
        ..PullLimits::default()
    };
    let report = log.pull_with(&site, limits).unwrap();
    assert_eq!(report.labels, [ids[1].clone(), ids[0].clone()]);
    assert!(!report.suspended && report.ended.is_none());
    assert_eq!(
        cursor_peak(&log),
        (2, size("label-feed.json") + size("label-feed/3.json"))
    );
}

#[test]
fn a_pull_past_its_work_seconds_suspends_and_a_later_pull_resumes_it() {
    let site = Site::new();
    let ids: Vec<String> = (0..6)
        .map(|n| {
            site.label(
                &format!("https://other.example/{n}"),
                "2026-08-09T11:00:00Z",
            )
        })
        .collect();
    site.label_feed(&ids, NOW, None);
    let log = Log::onboard(&site);
    site.origin.delay(400);
    let first = log
        .pull_with(
            &site,
            PullLimits {
                work_seconds: 1,
                ..PullLimits::default()
            },
        )
        .unwrap();
    assert!(first.suspended);
    assert!(first.labels.len() < ids.len());
    site.origin.delay(0);
    let later = log.pull(&site).unwrap();
    assert!(!later.suspended);
    assert_eq!([first.labels, later.labels].concat(), ids);
}

const WAKE_NOW: i64 = 1_786_276_805;

fn claim_all(db: &Db) -> Vec<crate::db::PullTask> {
    let mut tasks = Vec::new();
    loop {
        let claimed = db
            .claim_pulls(
                WAKE_NOW,
                usize::MAX,
                "me",
                crate::db::PARTITIONS as usize,
                &[],
                &mut false,
                true,
            )
            .unwrap();
        if claimed.is_empty() {
            return tasks;
        }
        tasks.extend(claimed);
    }
}

fn defer_resume(db: &Db, task: &crate::db::PullTask, unit: &str) {
    let (day, domain) = (&NOW[..10], task.domain.as_str());
    let budget = registry::effective(db, "ingest_budget_bytes_day", NOW).unwrap();
    let spent = (budget - db.ingest_bytes(unit, day).unwrap()).max(0);
    db.add_ingest_bytes(unit, day, spent).unwrap();
    db.complete_pull(
        task,
        "me",
        WAKE_NOW,
        crate::db::PullOutcome::Pulled { suspended: true },
        0.0,
        WAKE_NOW,
    )
    .unwrap();
    db.add_ingest_bytes(unit, day, -spent).unwrap();
    assert_eq!(
        db.scheduled_pull(domain).unwrap().map(|due| due.due_at),
        Some(WAKE_NOW - WAKE_NOW % 86_400 + 86_400),
        "the resumption of a walk suspended on a spent budget waits for the next day"
    );
}

fn due_at(db: &Db, domain: &str) -> i64 {
    db.scheduled_pull(domain).unwrap().unwrap().due_at
}

#[test]
fn a_credit_to_a_meter_row_wakes_the_resumptions_of_its_registrable_domain_that_day() {
    assert_eq!(registry::instant(WAKE_NOW).unwrap(), NOW);
    let log = Log::with_suffix_list();
    let db = &log.db;
    let (a, b, other) = ("a.example.com", "b.example.com", "c.example.net");
    for domain in [a, b, other] {
        db.insert_publisher(domain, b"{}", "k", "p").unwrap();
    }
    let tasks = claim_all(db);
    let task = |domain: &str| tasks.iter().find(|task| task.domain == domain).unwrap();
    let unit = crate::suffix_list::unit_at(db, a, NOW).unwrap();
    assert_eq!(unit, crate::suffix_list::unit_at(db, b, NOW).unwrap());
    let other_unit = crate::suffix_list::unit_at(db, other, NOW).unwrap();
    assert_ne!(unit, other_unit);

    let (day, budget) = (
        &NOW[..10],
        registry::effective(db, "ingest_budget_bytes_day", NOW).unwrap(),
    );
    let run = start_run(db, a, NOW);
    let remainder = budget - db.ingest_bytes(&unit, day).unwrap();
    db.reserve_pull_object(
        run.run_id,
        "label",
        "sha256:a#0",
        "https://a.example.com/l",
        &unit,
        day,
        remainder as u64,
    )
    .unwrap();
    defer_resume(db, task(other), &other_unit);
    defer_resume(db, task(b), &unit);
    let deferred = due_at(db, b);

    wake_credited(
        db,
        [Credit {
            unit: unit.clone(),
            day: day.into(),
            bytes: 10,
        }],
        WAKE_NOW,
    )
    .unwrap();
    assert_eq!(
        due_at(db, b),
        deferred,
        "a credit that leaves less than a page's cap of budget wakes nothing"
    );

    wake_credited(
        db,
        [Credit {
            unit: unit.clone(),
            day: "2026-08-08".into(),
            bytes: 10,
        }],
        WAKE_NOW,
    )
    .unwrap();
    wake_credited(
        db,
        [Credit {
            unit: other_unit.clone(),
            day: "2026-08-10".into(),
            bytes: 10,
        }],
        WAKE_NOW,
    )
    .unwrap();
    wake_credited(
        db,
        [Credit {
            unit: "example.org".into(),
            day: day.into(),
            bytes: 10,
        }],
        WAKE_NOW,
    )
    .unwrap();
    assert_eq!(
        due_at(db, b),
        deferred,
        "a credit on another day or unit wakes nothing"
    );

    let credit = db
        .settle_pull_object_crediting(&run, "label", "sha256:a#0", Settled::Body(b"12345"))
        .unwrap();
    assert_eq!(
        credit,
        Some(Credit {
            unit: unit.clone(),
            day: day.into(),
            bytes: remainder as u64 - 5
        })
    );
    wake_credited(db, credit, WAKE_NOW).unwrap();
    assert_eq!(
        due_at(db, b),
        WAKE_NOW,
        "the sibling's resumption is due at once"
    );
    assert!(
        due_at(db, other) > WAKE_NOW,
        "another Registrable Domain still waits"
    );
}

#[test]
fn a_pull_s_settlement_wakes_a_sibling_resumption_deferred_to_the_next_day() {
    let site = Site::at("a.wake.localhost");
    let id = site.label("https://other.example/a", "2026-08-09T11:00:00Z");
    site.label_feed(std::slice::from_ref(&id), NOW, None);
    let log = Log::with_suffix_list().onboarded(&site);
    let db = &log.db;
    let sibling = "b.wake.localhost";
    let unit = crate::suffix_list::unit_at(db, &site.host, NOW).unwrap();
    assert_eq!(unit, crate::suffix_list::unit_at(db, sibling, NOW).unwrap());
    db.insert_publisher(sibling, b"{}", "k", "p").unwrap();
    let tasks = claim_all(db);
    defer_resume(
        db,
        tasks.iter().find(|task| task.domain == sibling).unwrap(),
        &unit,
    );

    let report = log.pull(&site).unwrap();
    assert_eq!(report.labels, [id]);
    assert_eq!(due_at(db, sibling), WAKE_NOW);
}

#[test]
fn opening_a_pull_releases_a_crashed_run_s_reservation_and_wakes_a_sibling_resumption() {
    let site = Site::at("a.wake.localhost");
    std::fs::remove_file(site.dir.path().join(".well-known/wist/publisher.json")).unwrap();
    let log = Log::with_suffix_list();
    let db = &log.db;
    let sibling = "b.wake.localhost";
    let unit = crate::suffix_list::unit_at(db, &site.host, NOW).unwrap();
    assert_eq!(unit, crate::suffix_list::unit_at(db, sibling, NOW).unwrap());
    db.insert_publisher(sibling, b"{}", "k", "p").unwrap();
    let crashed = start_run(db, &site.host, NOW);
    db.reserve_pull_object(
        crashed.run_id,
        "label",
        "sha256:a#0",
        "https://a.wake.localhost/l",
        &unit,
        &NOW[..10],
        4096,
    )
    .unwrap();
    let tasks = claim_all(db);
    defer_resume(
        db,
        tasks.iter().find(|task| task.domain == sibling).unwrap(),
        &unit,
    );

    site.origin.take_served();
    let report = log.pull(&site).unwrap();
    assert_eq!(report.ended.as_deref(), Some("WIST2-E04"));
    assert_eq!(
        site.origin.take_served(),
        ["/.well-known/wist/publisher.json"],
        "the pull makes no metered request whose settlement could credit the row"
    );
    assert_eq!(due_at(db, sibling), WAKE_NOW);
}
