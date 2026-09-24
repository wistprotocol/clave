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
    slow_ms: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    in_flight: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
    served: std::sync::Mutex<Vec<String>>,
}

impl Origin {
    fn delay(&self, ms: u64) {
        self.delay_ms.store(ms, std::sync::atomic::Ordering::SeqCst);
    }

    fn slow(&self, path: &str, ms: u64) {
        self.slow_ms
            .lock()
            .unwrap()
            .insert(format!("/.well-known/wist/{path}"), ms);
    }

    fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn take_peak(&self) -> usize {
        self.peak.swap(0, std::sync::atomic::Ordering::SeqCst)
    }

    fn take_served(&self) -> Vec<String> {
        std::mem::take(&mut self.served.lock().unwrap())
    }

    async fn serve(&self, root: &std::path::Path, path: &str) -> Option<Vec<u8>> {
        use std::sync::atomic::Ordering::SeqCst;
        self.served.lock().unwrap().push(path.to_string());
        let running = self.in_flight.fetch_add(1, SeqCst) + 1;
        self.peak.fetch_max(running, SeqCst);
        let delay = self.slow_ms.lock().unwrap().get(path).copied();
        let delay = delay.unwrap_or_else(|| self.delay_ms.load(SeqCst));
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        let body = std::fs::read(root.join(path.trim_start_matches('/'))).ok();
        self.in_flight.fetch_sub(1, SeqCst);
        body
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
        site
    }

    fn write(&self, path: &str, doc: &Value) {
        let path = self.dir.path().join(".well-known/wist").join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec(doc).unwrap()).unwrap();
    }

    fn read(&self, path: &str) -> Value {
        serde_json::from_slice(
            &std::fs::read(self.dir.path().join(".well-known/wist").join(path)).unwrap(),
        )
        .unwrap()
    }

    pub(crate) fn delta(
        &self,
        url: &str,
        extract: &str,
        prev: Option<&str>,
        observed_at: &str,
    ) -> String {
        let salt = wist_core::crypto::b64u_encode(&[5u8; 16]);
        let content = serde_json::json!({
            "extract": extract, "links": {"total": 0, "urls": []},
            "summary": {"title": url}
        });
        let mut delta = serde_json::json!({
            "wist_version": "1.0.0", "publisher": self.host, "url": url,
            "change_type": if prev.is_some() { "update" } else { "new" },
            "observed_at": observed_at,
            "payload": {
                "commitment": wist_core::delta::make_commitment(&salt, &content).unwrap(),
                "alg": "HMAC-SHA256",
                "bytes": wist_core::delta::content_bytes(&content).unwrap()
            },
            "meta": {"lang": "en"}
        });
        if let Some(prev) = prev {
            delta["prev"] = prev.into();
        }
        let id = wist_core::delta::delta_id(&delta).unwrap();
        let hex = &id[7..];
        self.write(&format!("deltas/{hex}.json"), &sign(&delta, "delta"));
        self.write(
            &format!("payloads/{hex}.json"),
            &serde_json::json!({"wist_version": "1.0.0", "salt": salt, "content": content}),
        );
        id
    }

    fn feed_doc(&self, ids: &[String], generated_at: &str, next: Option<u64>) -> Value {
        let next = next.map(|n| format!("https://{}/.well-known/wist/feed/{n}.json", self.host));
        sign(
            &serde_json::json!({
                "wist_version": "1.0.0", "domain": self.host,
                "generated_at": generated_at, "deltas": ids, "next": next
            }),
            "feed",
        )
    }

    pub(crate) fn feed(&self, ids: &[String], generated_at: &str, next: Option<u64>) {
        self.write("feed.json", &self.feed_doc(ids, generated_at, next));
    }

    fn page(&self, number: u64, ids: &[String], generated_at: &str) {
        let doc = self.feed_doc(ids, generated_at, number.checked_sub(1));
        self.write(&format!("feed/{number}.json"), &doc);
    }

    fn label_feed(&self, ids: &[String], generated_at: &str) {
        let doc = self.feed_doc(ids, generated_at, None);
        self.write("label-feed.json", &doc);
        for id in ids {
            self.write(
                &format!("labels/{}.json", &id[7..]),
                &serde_json::json!({"wist_version": "1.0.0"}),
            );
        }
    }

    fn tamper_payload(&self, id: &str) {
        let path = format!("payloads/{}.json", &id[7..]);
        let mut payload = self.read(&path);
        payload["content"]["extract"] = "tampered".into();
        self.write(&path, &payload);
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
        let feed = site.read("feed.json");
        site.feed(&[], "2026-08-09T09:00:00Z", None);
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
        site.write("feed.json", &feed);
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
        "SELECT delta_id, domain FROM seen_deltas ORDER BY delta_id",
        "SELECT entry_type, domain, json_extract(CAST(entry_json AS TEXT), '$.delta.url'), json_extract(CAST(entry_json AS TEXT), '$.delta.observed_at') FROM pending_entries ORDER BY rowid",
        "SELECT domain, delta_id FROM queued_deltas ORDER BY rowid",
        "SELECT url, domain, tip FROM url_tips ORDER BY domain, url",
        "SELECT id, domain FROM seen_labels ORDER BY id",
    ] {
        let mut statement = conn.prepare(query).unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                let mut fields = Vec::new();
                for column in 0..columns {
                    fields.push(format!("{:?}", row.get::<_, rusqlite::types::Value>(column)?));
                }
                Ok(fields.join("|"))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        dump.push(format!("{query}: {}", rows.join(" / ")));
    }
    let mut payloads: Vec<String> = std::fs::read_dir(log.data.path().join("payloads"))
        .map(|dir| {
            dir.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    payloads.sort();
    dump.push(format!("payloads: {}", payloads.join(" / ")));
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

fn walked_site() -> (Site, [String; 4]) {
    let site = Site::new();
    let paged = site.delta("https://localhost/a", "paged", None, "2026-08-09T10:00:00Z");
    let broken = site.delta(
        "https://localhost/b",
        "broken",
        None,
        "2026-08-09T11:00:00Z",
    );
    site.tamper_payload(&broken);
    let root = site.delta("https://localhost/c", "root", None, "2026-08-09T11:30:00Z");
    let update = site.delta(
        "https://localhost/c",
        "update",
        Some(&root),
        "2026-08-09T11:40:00Z",
    );
    site.page(0, std::slice::from_ref(&paged), "2026-08-09T10:30:00Z");
    site.feed(&[broken.clone(), update.clone()], NOW, Some(0));
    site.label_feed(std::slice::from_ref(&paged), NOW);
    (site, [paged, broken, root, update])
}

#[test]
fn a_delta_admits_only_under_the_references_it_was_verified_under() {
    let site = Site::new();
    let first = site.delta("https://localhost/a", "one", None, "2026-08-09T12:00:00Z");
    site.feed(&[], NOW, None);
    let log = Log::onboard(&site);
    let (db, data) = (&log.db, log.data.path());
    let doc = site.read(&format!("deltas/{}.json", &first[7..]));
    let payload = std::fs::read(
        site.dir
            .path()
            .join(format!(".well-known/wist/payloads/{}.json", &first[7..])),
    )
    .unwrap();
    let mut run = start_run(db, &site.host, NOW);
    let slot = format!("{first}#0");
    db.record_pull_object(
        run.run_id,
        "delta",
        &slot,
        "https://localhost/",
        Status::Verified,
        None,
        None,
    )
    .unwrap();
    let refs = issue_refs(db, data, &site.host, instant(NOW)).unwrap();
    let Ok(verified) =
        verify::delta(&doc, &site.host, &first, &refs.sizes, refs.clock, 600).decoded
    else {
        panic!("the Delta decodes");
    };
    let envelope = verified.envelope;
    let item = admit::DeltaItem {
        index: 0,
        id: &first,
        slot: &slot,
        payload_slot: None,
    };
    let unwritten = || {
        assert!(!db.is_delta_seen_for(&first, &site.host).unwrap());
        assert_eq!(db.url_tip(&site.host, "https://localhost/a").unwrap(), None);
        assert!(!data.join(format!("payloads/{}.json", &first[7..])).exists());
    };

    let mut stale = issue_refs(db, data, &site.host, instant(NOW)).unwrap();
    stale.decl.hash = Some("another Declaration".into());
    assert!(matches!(
        admit::admit_delta(
            db,
            data,
            &mut run,
            &site.host,
            &item,
            &doc,
            &envelope,
            Some(&payload),
            &stale
        )
        .unwrap(),
        admit::Admission::Stale(admit::Staleness::Declaration)
    ));
    unwritten();

    let mut stale = issue_refs(db, data, &site.host, instant(NOW)).unwrap();
    stale.schedule_at = Some(u64::MAX);
    stale.sizes.url_cap_bytes += 1;
    assert!(matches!(
        admit::admit_delta(
            db,
            data,
            &mut run,
            &site.host,
            &item,
            &doc,
            &envelope,
            Some(&payload),
            &stale
        )
        .unwrap(),
        admit::Admission::Stale(admit::Staleness::Schedule)
    ));
    unwritten();

    let mut extended = issue_refs(db, data, &site.host, instant(NOW)).unwrap();
    extended.schedule_at = Some(u64::MAX);
    assert!(matches!(
        admit::admit_delta(
            db,
            data,
            &mut run,
            &site.host,
            &item,
            &doc,
            &envelope,
            Some(&payload),
            &extended
        )
        .unwrap(),
        admit::Admission::Accepted
    ));
    assert!(db.is_delta_seen_for(&first, &site.host).unwrap());
    assert!(data.join(format!("payloads/{}.json", &first[7..])).exists());

    let second = site.delta(
        "https://localhost/a",
        "two",
        Some(&first),
        "2026-08-09T12:00:01Z",
    );
    let doc = site.read(&format!("deltas/{}.json", &second[7..]));
    let Ok(verified) =
        verify::delta(&doc, &site.host, &second, &refs.sizes, refs.clock, 600).decoded
    else {
        panic!("the Delta decodes");
    };
    let slot = format!("{second}#0");
    db.record_pull_object(
        run.run_id,
        "delta",
        &slot,
        "https://localhost/",
        Status::Verified,
        None,
        None,
    )
    .unwrap();
    db.set_url_tip("https://localhost/a", &site.host, "sha256:elsewhere")
        .unwrap();
    let item = admit::DeltaItem {
        index: 1,
        id: &second,
        slot: &slot,
        payload_slot: None,
    };
    assert!(matches!(
        admit::admit_delta(
            db,
            data,
            &mut run,
            &site.host,
            &item,
            &doc,
            &verified.envelope,
            None,
            &refs
        )
        .unwrap(),
        admit::Admission::Stale(admit::Staleness::ChainTip)
    ));
    assert!(!db.is_delta_seen_for(&second, &site.host).unwrap());
}

#[test]
fn delivering_the_same_fetched_or_verified_result_twice_changes_nothing() {
    let site = Site::new();
    let id = site.delta("https://localhost/a", "one", None, "2026-08-09T12:00:00Z");
    site.feed(&[], NOW, None);
    let log = Log::onboard(&site);
    let (db, data) = (&log.db, log.data.path());
    let host = site.host.clone();
    let mut run = start_run(db, &host, NOW);
    let slot = format!("{id}#0");
    let doc = site.read(&format!("deltas/{}.json", &id[7..]));
    let raw = serde_json::to_vec(&doc).unwrap();

    let spent = db.ingest_bytes(&host, &NOW[..10]).unwrap();
    db.reserve_pull_object(
        run.run_id,
        "delta",
        &slot,
        "https://localhost/d",
        &host,
        &NOW[..10],
        100,
    )
    .unwrap();
    assert!(db
        .settle_pull_object(&run, "delta", &slot, Settled::Body(&raw))
        .unwrap());
    let debited = db.ingest_bytes(&host, &NOW[..10]).unwrap();
    assert_eq!(debited, spent + raw.len() as i64);
    assert!(
        !db.settle_pull_object(&run, "delta", &slot, Settled::Body(&raw))
            .unwrap(),
        "a second delivery of the same response is not persisted again"
    );
    assert_eq!(db.ingest_bytes(&host, &NOW[..10]).unwrap(), debited);

    assert!(db
        .advance_pull_object(
            run.run_id,
            "delta",
            &slot,
            &[Status::Fetched],
            Status::Verified,
            None
        )
        .unwrap());
    assert!(!db
        .advance_pull_object(
            run.run_id,
            "delta",
            &slot,
            &[Status::Fetched],
            Status::Verified,
            None
        )
        .unwrap());

    let refs = issue_refs(db, data, &host, instant(NOW)).unwrap();
    let Ok(verified) = verify::delta(&doc, &host, &id, &refs.sizes, refs.clock, 600).decoded else {
        panic!("the Delta decodes");
    };
    let item = admit::DeltaItem {
        index: 0,
        id: &id,
        slot: &slot,
        payload_slot: None,
    };
    for expected_duplicate in [false, true] {
        let admission = admit::admit_delta(
            db,
            data,
            &mut run,
            &host,
            &item,
            &doc,
            &verified.envelope,
            None,
            &refs,
        )
        .unwrap();
        assert_eq!(
            matches!(admission, admit::Admission::Duplicate),
            expected_duplicate
        );
    }
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
    assert_eq!(run.chain_pos, 1);

    let refused = site.delta("https://localhost/b", "two", None, "2026-08-09T12:00:00Z");
    let slot = format!("{refused}#0");
    let refusal = admit::Refusal {
        index: 1,
        id: &refused,
        kind: "delta",
        slot: &slot,
        consumed: None,
        resolved_prev: false,
    };
    for _ in 0..2 {
        admit::reject_item(db, &mut run, &host, &refusal, "WIST2-E03", "unavailable").unwrap();
    }
    assert_eq!(
        db.list_rejections(&host)
            .unwrap()
            .iter()
            .filter(|rejection| rejection.delta_id.as_deref() == Some(refused.as_str()))
            .count(),
        1
    );
    assert_eq!(db.pull_report(run.run_id).unwrap().len(), 2);
}

#[test]
fn the_reservation_a_crashed_pull_left_is_released_with_its_run_and_settles_once() {
    let site = Site::new();
    site.feed(&[], NOW, None);
    let log = Log::onboard(&site);
    let (db, host, day) = (&log.db, site.host.clone(), &NOW[..10]);
    let spent = db.ingest_bytes(&host, day).unwrap();
    let run = start_run(db, &host, NOW);
    let slot = "sha256:abc#0";
    db.reserve_pull_object(
        run.run_id,
        "delta",
        slot,
        "https://localhost/d",
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
        "delta",
        slot,
        "https://localhost/d",
        &host,
        day,
        4096,
    )
    .unwrap();
    assert_eq!(db.ingest_bytes(&host, day).unwrap(), spent + 4096);
    db.settle_pull_object(&next, "delta", slot, Settled::Body(b"12345"))
        .unwrap();
    assert_eq!(db.ingest_bytes(&host, day).unwrap(), spent + 5);
}

#[test]
fn a_reservation_settles_and_releases_on_the_row_its_request_was_issued_against() {
    let site = Site::new();
    site.feed(&[], NOW, None);
    let log = Log::onboard(&site);
    let (db, host, day) = (&log.db, site.host.clone(), &NOW[..10]);
    let (crossed_unit, crossed_day) = ("sub.localhost", "2026-08-10");
    let spent = db.ingest_bytes(&host, day).unwrap();
    let run = start_run(db, &host, NOW);
    let slot = "sha256:abc#0";
    db.reserve_pull_object(
        run.run_id,
        "delta",
        slot,
        "https://localhost/d",
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
        .settle_pull_object(&run, "delta", slot, Settled::Body(b"12345"))
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
        "feed:0",
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
    interrupted_pulls_admit_what_one_pull_admits(PullLimits::default());
}

#[test]
fn a_fresh_pull_after_an_interruption_at_any_commit_with_prefetches_admits_what_one_pull_admits() {
    interrupted_pulls_admit_what_one_pull_admits(PullLimits {
        prefetch_objects: 4,
        ..PullLimits::default()
    });
}

fn interrupted_pulls_admit_what_one_pull_admits(limits: PullLimits) {
    let (site, ids) = walked_site();
    let expected = {
        let log = Log::onboard(&site);
        let report = log.pull_with(&site, limits).unwrap();
        assert_eq!(
            report.accepted,
            [ids[0].clone(), ids[2].clone(), ids[3].clone()]
        );
        assert_eq!(
            report.rejected,
            [
                (ids[1].clone(), "WIST2-E03".to_string()),
                (ids[0].clone(), "WIST2-E06".to_string())
            ]
        );
        assert!(!report.suspended && report.noise.is_none());
        admitted_state(&log)
    };
    for commits in 0.. {
        let log = Log::onboard(&site);
        crate::db::interrupt::after(commits);
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            log.pull_with(&site, limits)
        }));
        if crate::db::interrupt::disarm() {
            assert!(interrupted.is_ok(), "the pull ran to its end");
            assert!(commits > 0, "the pull commits at least once");
            break;
        }
        assert!(
            interrupted.is_err(),
            "the {commits}th commit interrupts the pull"
        );
        let fresh = log.pull_with(&site, limits).unwrap();
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
    site.feed(&[], NOW, None);
    let log = Log::onboard(&site);
    let db = &log.db;
    let run = start_run(db, &site.host, NOW);
    db.record_pull_object(
        run.run_id,
        "delta",
        "sha256:abc#0",
        "https://localhost/d",
        Status::Fetched,
        Some(b"{}"),
        None,
    )
    .unwrap();

    let next = start_run(db, &site.host, NOW);
    assert_ne!(next.run_id, run.run_id, "the pull begins a fresh run");
    assert_eq!(open_runs(&log), 1, "one run per domain");
    assert!(
        db.pull_object(run.run_id, "delta", "sha256:abc#0")
            .unwrap()
            .is_none(),
        "the objects of the run left open are dropped with it"
    );
    assert_eq!(
        next.phase,
        Phase::Walk,
        "a fresh run starts at Declaration discovery and the Feed walk"
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
                site.delta(
                    &format!("https://localhost/{n}"),
                    "listed",
                    None,
                    "2026-08-09T11:00:00Z",
                )
            })
            .collect();
        site.feed(&ids, NOW, None);
        let log = Log::onboard(&site);
        count_queue_writes(&log);
        let report = log.pull(&site).unwrap();
        assert_eq!(report.accepted, ids, "every listed Delta is admitted");
        writes.push(queue_writes(&log));
    }
    assert_eq!(
        writes[0], writes[1],
        "the queue is written where it changes, not once per item decided"
    );
    assert_eq!(
        writes[0], 3,
        "the Feed walk, the Delta queue and the Label Feed walk each end once"
    );
}

#[test]
fn a_page_that_cannot_be_fetched_leaves_the_cursor_holding_the_feed_it_read() {
    let site = Site::new();
    let first = site.delta("https://localhost/a", "first", None, "2026-08-09T11:00:00Z");
    let second = site.delta(
        "https://localhost/b",
        "second",
        None,
        "2026-08-09T11:10:00Z",
    );
    let listed = [first.clone(), second.clone()];
    site.feed(&listed, NOW, Some(0));
    let log = Log::onboard(&site);

    let report = run_bounded(
        &log.db,
        &site.client,
        log.data.path(),
        &site.host,
        NOW,
        || instant(NOW),
        PullLimits {
            work_bytes: u64::MAX,
            work_objects: 3,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(report.accepted, [first]);
    assert!(report.suspended);
    assert_eq!(report.ended, None);
    let held = log.db.walk_pages(&site.host, "feed").unwrap();
    assert_eq!(
        held.iter().map(|page| page.ids.clone()).collect::<Vec<_>>(),
        [listed],
        "the Feed the walk read stays held and the Page it could not fetch does not"
    );
}

#[test]
fn a_decided_delta_payload_or_label_holds_no_fetched_bytes_while_its_run_is_open() {
    let (site, _) = walked_site();
    let log = Log::onboard(&site);
    let run_id = log.open_pull(&site, PullLimits::default());
    let decided = "FROM pull_objects WHERE run_id = ?1 AND kind IN ('delta', 'payload', 'label') AND status IN ('admitted', 'rejected')";
    assert!(
        log.count(
            &format!("SELECT COUNT(*) {decided} AND byte_len > 0 AND debited > 0"),
            run_id
        ) >= 5,
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
            site.delta(
                &format!("https://localhost/{n}"),
                "paged",
                None,
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
    site.feed(std::slice::from_ref(&ids[4]), NOW, Some(3));
    (site, ids.into_iter().rev().collect())
}

fn served_pages(site: &Site) -> Vec<String> {
    site.origin
        .take_served()
        .into_iter()
        .filter(|path| path.contains("/feed"))
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
        report.accepted,
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
            "/.well-known/wist/feed.json",
            "/.well-known/wist/feed/3.json",
            "/.well-known/wist/feed/2.json"
        ]
    );
    let (pages, bytes) = cursor_peak(&log);
    assert_eq!(pages, 3);
    assert!(bytes <= limits.walk_bytes);

    let report = log.pull_with(&site, limits).unwrap();
    assert!(report.accepted.is_empty() && !report.suspended);
    assert_eq!(
        served_pages(&site),
        ["/.well-known/wist/feed.json"],
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
        walk_bytes: crate::fetch::OBJECT_CAP_BYTES + size("feed.json") + size("feed/3.json") - 1,
        ..PullLimits::default()
    };
    let report = log.pull_with(&site, limits).unwrap();
    assert_eq!(report.accepted, [ids[1].clone(), ids[0].clone()]);
    assert!(!report.suspended && report.ended.is_none());
    assert_eq!(
        cursor_peak(&log),
        (2, size("feed.json") + size("feed/3.json"))
    );
}

#[test]
fn a_pull_past_its_work_seconds_suspends_and_a_later_pull_resumes_it() {
    let site = Site::new();
    let ids: Vec<String> = (0..6)
        .map(|n| {
            site.delta(
                &format!("https://localhost/{n}"),
                "timed",
                None,
                "2026-08-09T11:00:00Z",
            )
        })
        .collect();
    site.feed(&ids, NOW, None);
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
    assert!(first.accepted.len() < ids.len());
    site.origin.delay(0);
    let later = log.pull(&site).unwrap();
    assert!(!later.suspended);
    assert_eq!([first.accepted, later.accepted].concat(), ids);
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
        "delta",
        "sha256:a#0",
        "https://a.example.com/d",
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
        .settle_pull_object_crediting(&run, "delta", "sha256:a#0", Settled::Body(b"12345"))
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
    let id = site.delta(
        "https://a.wake.localhost/a",
        "one",
        None,
        "2026-08-09T11:00:00Z",
    );
    site.feed(std::slice::from_ref(&id), NOW, None);
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
    assert_eq!(report.accepted, [id]);
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
        "delta",
        "sha256:a#0",
        "https://a.wake.localhost/d",
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

fn listed_site() -> (Site, Vec<String>) {
    let site = Site::new();
    let ids: Vec<String> = (0..12)
        .map(|n| {
            site.delta(
                &format!("https://localhost/{n}"),
                "listed",
                None,
                "2026-08-09T11:00:00Z",
            )
        })
        .collect();
    site.feed(&ids, NOW, None);
    (site, ids)
}

const PREFETCHING: PullLimits = PullLimits {
    work_bytes: 64 << 20,
    work_objects: 4096,
    work_seconds: 300,
    walk_pages: 1024,
    walk_bytes: 64 << 20,
    prefetch_objects: 4,
    prefetch_bytes: 8 << 20,
};

#[test]
fn prefetched_delta_files_are_fetched_concurrently_and_admit_what_a_sequential_pull_admits() {
    let (site, ids) = listed_site();
    let mut states = Vec::new();
    let mut peaks = Vec::new();
    for limits in [PullLimits::default(), PREFETCHING] {
        let log = Log::onboard(&site);
        site.origin.delay(50);
        site.origin.take_peak();
        let report = log.pull_with(&site, limits).unwrap();
        site.origin.delay(0);
        assert_eq!(report.accepted, ids);
        peaks.push(site.origin.take_peak());
        states.push(admitted_state(&log));
    }
    assert_eq!(peaks[0], 1, "the default pull is sequential");
    assert!(peaks[1] >= 2, "prefetches overlap: {}", peaks[1]);
    assert_eq!(states[0], states[1]);
}

#[test]
fn prefetching_under_a_budget_below_its_margin_stays_sequential_and_crosses_where_a_sequential_pull_does(
) {
    let (site, _) = listed_site();
    let mut pulls = Vec::new();
    for limits in [PullLimits::default(), PREFETCHING] {
        let log = Log::onboard(&site);
        let unit = crate::suffix_list::unit_at(&log.db, &site.host, NOW).unwrap();
        let spent = log.db.ingest_bytes(&unit, &NOW[..10]).unwrap();
        log.db
            .set_param("ingest_budget_bytes_day", spent + 6_000)
            .unwrap();
        site.origin.take_peak();
        site.origin.take_served();
        let report = log.pull_with(&site, limits).unwrap();
        assert!(report.suspended, "the budget is crossed");
        pulls.push((
            report.accepted,
            log.db.ingest_bytes(&unit, &NOW[..10]).unwrap(),
            site.origin.take_served(),
            site.origin.take_peak(),
        ));
    }
    assert_eq!(pulls[1].3, 1, "no request overlaps another");
    assert_eq!(pulls[0], pulls[1]);
}

#[test]
fn a_pull_suspended_with_prefetches_in_flight_joins_and_settles_them_before_it_returns() {
    let site = Site::new();
    let mut chain = None;
    for n in 0..11 {
        chain = Some(site.delta(
            "https://localhost/chain",
            "chained",
            chain.as_deref(),
            &format!("2026-08-09T10:{n:02}:00Z"),
        ));
    }
    let mut ids = vec![chain.unwrap()];
    for n in 0..8 {
        let id = site.delta(
            &format!("https://localhost/{n}"),
            "listed",
            None,
            "2026-08-09T11:00:00Z",
        );
        site.origin
            .slow(&format!("deltas/{}.json", &id[7..]), 1_500);
        ids.push(id);
    }
    site.feed(&ids, NOW, None);
    let log = Log::onboard(&site);

    let run_id = log.open_pull(
        &site,
        PullLimits {
            work_objects: 16,
            ..PREFETCHING
        },
    );
    assert_eq!(site.origin.in_flight(), 0, "no prefetch outlives the pull");
    assert_eq!(
        log.count(
            "SELECT COUNT(*) FROM pull_objects WHERE run_id = ?1 AND status = 'issued'",
            run_id
        ),
        0
    );
    let prefetched = ids[1..5]
        .iter()
        .map(|id| {
            log.db
                .pull_object(run_id, "delta", &format!("{id}#0"))
                .unwrap()
                .map(|object| object.status)
        })
        .collect::<Vec<_>>();
    assert_eq!(prefetched, [Some(Status::Fetched); 4]);
    assert!(log.db.pull_run(run_id).unwrap().unwrap().suspended);
    admit::close_run(&log.db, run_id).unwrap();

    let later = log.pull(&site).unwrap();
    assert!(!later.suspended);
    for id in &ids {
        assert!(log.db.is_delta_seen_for(id, &site.host).unwrap());
    }
}

#[test]
fn a_pull_after_a_suspension_requests_and_debits_again_the_prefetched_delta_files_it_never_reached()
{
    let site = Site::new();
    let mut chain = None;
    for n in 0..11 {
        chain = Some(site.delta(
            "https://localhost/chain",
            "chained",
            chain.as_deref(),
            &format!("2026-08-09T10:{n:02}:00Z"),
        ));
    }
    let mut ids = vec![chain.unwrap()];
    for n in 0..8 {
        ids.push(site.delta(
            &format!("https://localhost/{n}"),
            "listed",
            None,
            "2026-08-09T11:00:00Z",
        ));
    }
    site.feed(&ids, NOW, None);
    let metered = |served: Vec<String>| {
        served
            .into_iter()
            .filter(|path| !path.ends_with("/publisher.json"))
            .collect::<Vec<_>>()
    };
    let octets = |paths: &[String]| -> i64 {
        paths
            .iter()
            .map(|path| {
                std::fs::metadata(site.dir.path().join(path.trim_start_matches('/')))
                    .unwrap()
                    .len() as i64
            })
            .sum()
    };

    let control = Log::onboard(&site);
    let unit = crate::suffix_list::unit_at(&control.db, &site.host, NOW).unwrap();
    let spent = |log: &Log| log.db.ingest_bytes(&unit, &NOW[..10]).unwrap();
    let before = spent(&control);
    let report = control.pull_with(&site, PREFETCHING).unwrap();
    assert!(!report.suspended);
    let uninterrupted = spent(&control) - before;

    let log = Log::onboard(&site);
    let before = spent(&log);
    site.origin.take_served();
    let run_id = log.open_pull(
        &site,
        PullLimits {
            work_objects: 16,
            ..PREFETCHING
        },
    );
    assert!(log.db.pull_run(run_id).unwrap().unwrap().suspended);
    let prefetched = ids[1..5]
        .iter()
        .map(|id| {
            log.db
                .pull_object(run_id, "delta", &format!("{id}#0"))
                .unwrap()
                .map(|object| object.status)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        prefetched,
        [Some(Status::Fetched); 4],
        "the prefetched Delta files landed and the walk never reached them"
    );
    admit::close_run(&log.db, run_id).unwrap();
    let suspended = metered(site.origin.take_served());
    let resumed = log.pull_with(&site, PREFETCHING).unwrap();
    assert!(!resumed.suspended);
    let later = metered(site.origin.take_served());
    let interrupted = spent(&log) - before;

    let prefetched: Vec<String> = ids[1..5]
        .iter()
        .map(|id| format!("/.well-known/wist/deltas/{}.json", &id[7..]))
        .collect();
    for path in &prefetched {
        assert_eq!(
            suspended
                .iter()
                .chain(&later)
                .filter(|p| *p == path)
                .count(),
            2,
            "{path} is requested by both pulls"
        );
    }
    let refetched: Vec<String> = suspended
        .iter()
        .filter(|path| later.contains(path))
        .cloned()
        .collect();
    assert_eq!(
        interrupted - uninterrupted,
        octets(&refetched),
        "the two pulls are debited the octets of every file the second one requested again beyond one uninterrupted pull"
    );
    assert!(prefetched.iter().all(|path| refetched.contains(path)));
    assert!(octets(&prefetched) <= PREFETCHING.prefetch_bytes as i64);
    assert_eq!(admitted_state(&log), admitted_state(&control));
}
