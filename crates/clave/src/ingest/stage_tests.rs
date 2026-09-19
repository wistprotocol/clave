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
}

/// An initialized Log whose store already holds the Site's Declaration.
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
        site.write("feed.json", &feed);
        Log { data, db }
    }
}

fn instant(at: &str) -> jiff::Timestamp {
    at.parse().unwrap()
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
    let refs = issue_refs(db, data, &site.host, instant(NOW)).unwrap();
    let Ok(verified) =
        verify::delta(&doc, &site.host, &first, &refs.sizes, refs.clock, 600).decoded
    else {
        panic!("the Delta decodes");
    };
    let envelope = verified.envelope;
    let admit = |refs: &verify::IssuedRefs| {
        admit::admit_delta(
            db,
            data,
            &site.host,
            &first,
            &doc,
            &envelope,
            Some(&payload),
            0,
            refs,
        )
        .unwrap()
    };
    let unwritten = || {
        assert!(!db.is_delta_seen_for(&first, &site.host).unwrap());
        assert_eq!(db.url_tip(&site.host, "https://localhost/a").unwrap(), None);
        assert!(!data.join(format!("payloads/{}.json", &first[7..])).exists());
    };

    let mut other = issue_refs(db, data, &site.host, instant(NOW)).unwrap();
    other.decl.hash = Some("another Declaration".into());
    assert!(matches!(
        admit(&other),
        admit::Admission::Stale(admit::Staleness::Declaration)
    ));
    unwritten();

    let mut other = issue_refs(db, data, &site.host, instant(NOW)).unwrap();
    other.schedule_at = Some(u64::MAX);
    other.sizes.url_cap_bytes += 1;
    assert!(matches!(
        admit(&other),
        admit::Admission::Stale(admit::Staleness::Schedule)
    ));
    unwritten();

    let mut other = issue_refs(db, data, &site.host, instant(NOW)).unwrap();
    other.schedule_at = Some(u64::MAX);
    assert!(matches!(admit(&other), admit::Admission::Accepted));
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
    db.set_url_tip("https://localhost/a", &site.host, "sha256:elsewhere")
        .unwrap();
    assert!(matches!(
        admit::admit_delta(
            db,
            data,
            &site.host,
            &second,
            &doc,
            &verified.envelope,
            None,
            1,
            &refs
        )
        .unwrap(),
        admit::Admission::Stale(admit::Staleness::ChainTip)
    ));
    assert!(!db.is_delta_seen_for(&second, &site.host).unwrap());
}
