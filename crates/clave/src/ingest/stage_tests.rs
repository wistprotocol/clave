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

/// A Publisher's well-known directory served on loopback.
struct Site {
    dir: tempfile::TempDir,
    host: String,
    client: Client,
}

impl Site {
    fn new() -> Site {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = Client::with_builder(
            true,
            reqwest::blocking::Client::builder()
                .no_proxy()
                .resolve("localhost", listener.local_addr().unwrap()),
        );
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                        let body = std::fs::read(root.join(uri.path().trim_start_matches('/')));
                        async move {
                            match body {
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
        let site = Site {
            dir,
            host: "localhost".into(),
            client,
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

    /// Publishes a Delta for `url` with its Payload and returns its ID.
    fn delta(&self, url: &str, extract: &str, prev: Option<&str>, observed_at: &str) -> String {
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

    fn feed(&self, ids: &[String], generated_at: &str, next: Option<u64>) {
        self.write("feed.json", &self.feed_doc(ids, generated_at, next));
    }

    /// Publishes sealed Page `number`, whose `next` names the Page below
    /// it.
    fn page(&self, number: u64, ids: &[String], generated_at: &str) {
        let doc = self.feed_doc(ids, generated_at, number.checked_sub(1));
        self.write(&format!("feed/{number}.json"), &doc);
    }

    /// Publishes a Label Feed listing `ids` and, for each, a file that is
    /// neither a Label nor a dispute.
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

    /// Replaces a Delta's Payload with one its commitment does not cover.
    fn tamper_payload(&self, id: &str) {
        let path = format!("payloads/{}.json", &id[7..]);
        let mut payload = self.read(&path);
        payload["content"]["extract"] = "tampered".into();
        self.write(&path, &payload);
    }
}

/// An initialized Log whose store already holds the Site's Declaration,
/// sealed so that sealed Pages resolve a Key Set.
struct Log {
    data: tempfile::TempDir,
    db: Db,
}

impl Log {
    fn onboard(site: &Site) -> Log {
        let data = tempfile::tempdir().unwrap();
        crate::init::run("127.0.0.1:0", data.path()).unwrap();
        let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
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

    fn path(&self) -> std::path::PathBuf {
        self.data.path().join("clave.sqlite")
    }

    fn pull(&self, site: &Site) -> Result<IngestReport> {
        run(&self.db, &site.client, self.data.path(), &site.host, NOW)
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

/// A pull run again after an interruption re-reads what it had not
/// admitted, so this leaves out the rejection log and the bytes read.
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

/// A Site whose pull walks a sealed Page and the live Feed, admits a
/// Delta whose predecessor it must retrieve, rejects one whose Payload
/// does not match its commitment, and walks a Label Feed listing a file
/// that is neither a Label nor a dispute.
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
fn a_fresh_pull_after_an_interruption_at_any_commit_admits_what_one_pull_admits() {
    let (site, ids) = walked_site();
    let expected = {
        let log = Log::onboard(&site);
        let report = log.pull(&site).unwrap();
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
