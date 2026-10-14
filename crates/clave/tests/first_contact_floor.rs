mod common;

use clave::history::declarations::DeclarationsReplay;
use common::*;
use serde_json::{json, Value};

const EPOCH_0: &str = "2026-08-10T00:00:00Z";
const ADMITTED_AT: &str = "2026-08-10T01:00:00Z";
const REDUCED_AT: &str = "2026-08-17T00:00:00Z";
const SEALED_AT: &str = "2026-08-17T01:00:00Z";

fn unix(at: &str) -> i64 {
    wist_core::timestamp::log_seconds(at).unwrap()
}

fn declaration(domain: &str, seed: &[u8; 32], seq: u64, collections: usize) -> Value {
    let mut publisher = json!({
        "wist_version": "1.0.0",
        "domain": domain,
        "keys": [key_entry(seed, "2026-08-09T00:00:00Z")],
        "seq": seq,
        "collections": (0..collections)
            .map(|index| json!({
                "name": format!("c{index:02}"),
                "scope": [{"url": format!("https://{domain}/c{index:02}/"), "match": "prefix"}],
            }))
            .collect::<Vec<_>>(),
    });
    if seq > 0 {
        publisher["prev_declaration"] = format!("sha256:{}", "0".repeat(64)).into();
    }
    publisher
}

struct Site {
    publisher: TestPub,
    client: clave::fetch::Client,
}

fn site(domain: &str) -> Site {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .resolve(domain, listener.local_addr().unwrap());
    let publisher = make_publisher(domain);
    serve_static(listener, publisher.dir.path().to_path_buf());
    Site {
        publisher,
        client: clave::fetch::Client::with_builder(true, builder),
    }
}

struct Store {
    data: tempfile::TempDir,
    db: clave::db::Db,
    key: wist_core::crypto::SigningKey,
}

impl Store {
    fn genesis_with_collections_max_32_then_16() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example.com", data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        clave::param_change::run(&db, &key, "collections_max", 32, None, unix(EPOCH_0)).unwrap();
        clave::param_change::run(
            &db,
            &key,
            "collections_max",
            16,
            Some(REDUCED_AT),
            unix(EPOCH_0),
        )
        .unwrap();
        let store = Self { data, db, key };
        assert_eq!(store.seal(EPOCH_0), 0);
        assert_eq!(
            clave::registry::effective(&store.db, "collections_max", ADMITTED_AT).unwrap(),
            32
        );
        assert_eq!(
            clave::registry::effective(&store.db, "collections_max", SEALED_AT).unwrap(),
            16
        );
        store
    }

    fn seal(&self, at: &str) -> u64 {
        clave::seal::run(&self.db, self.data.path(), &self.key, unix(at))
            .unwrap()
            .epoch_number
    }

    fn pull(&self, site: &Site, at: &str) -> clave::ingest::IngestReport {
        pull_at(
            &self.db,
            &site.client,
            self.data.path(),
            &site.publisher.domain,
            at,
        )
    }

    fn reopen(&mut self) {
        self.db = clave::db::Db::open(&self.data.path().join("clave.sqlite")).unwrap();
    }

    fn floor(&self, domain: &str) -> Option<u64> {
        self.db.highest_accepted_declaration_seq(domain).unwrap()
    }

    fn status_collections(&self, domain: &str) -> Vec<String> {
        let status = clave::serve::load_status(&self.db, domain)
            .unwrap()
            .unwrap();
        let status = serde_json::to_value(status).unwrap();
        assert_eq!(status["state"], "active");
        status["collections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|collection| collection["name"].as_str().unwrap().to_owned())
            .collect()
    }

    fn sealed_domains(&self) -> Vec<String> {
        clave::history::declarations::Declarations::reconstruct(
            &self.db,
            self.data.path(),
            self.db.last_epoch().unwrap(),
        )
        .unwrap()
        .domains()
        .keys()
        .cloned()
        .collect()
    }
}

#[test]
fn a_domain_returning_to_first_contact_at_sealing_holds_no_floor_and_no_declaration() {
    let departing = site("a.localhost");
    let keeping = site("b.localhost");
    let mut store = Store::genesis_with_collections_max_32_then_16();

    write_declaration(
        &departing.publisher,
        &declaration("a.localhost", &K1_SEED, 5, 20),
        &K1_SEED,
    );
    store.pull(&departing, ADMITTED_AT);
    assert_eq!(store.floor("a.localhost"), Some(5));
    assert_eq!(
        store.status_collections("a.localhost"),
        (0..20)
            .map(|index| format!("c{index:02}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        store
            .db
            .count_discovered_declarations("a.localhost")
            .unwrap(),
        1
    );
    write_declaration(
        &keeping.publisher,
        &declaration("b.localhost", &K1_SEED, 3, 1),
        &K1_SEED,
    );
    store.pull(&keeping, ADMITTED_AT);
    assert_eq!(store.floor("b.localhost"), Some(3));

    assert_eq!(store.seal(SEALED_AT), 1);
    assert_eq!(
        store
            .db
            .count_discovered_declarations("a.localhost")
            .unwrap(),
        0
    );
    assert_eq!(store.sealed_domains(), ["b.localhost"]);
    assert_eq!(store.floor("a.localhost"), None);
    assert_eq!(store.floor("b.localhost"), Some(3));
    assert_eq!(
        store.db.get_publisher_declaration("a.localhost").unwrap(),
        None
    );
    assert!(store.db.get_publisher("a.localhost").unwrap().is_none());
    assert!(store.db.publisher_known("a.localhost").unwrap());
    assert!(store.status_collections("a.localhost").is_empty());
    assert_eq!(store.status_collections("b.localhost"), ["c00"]);

    store.reopen();
    assert_eq!(store.floor("a.localhost"), None);
    assert_eq!(store.floor("b.localhost"), Some(3));
    assert_eq!(
        store.db.get_publisher_declaration("a.localhost").unwrap(),
        None
    );
    assert!(store.status_collections("a.localhost").is_empty());

    write_declaration(
        &departing.publisher,
        &declaration("a.localhost", &K2_SEED, 0, 16),
        &K2_SEED,
    );
    let fresh = current_declaration(&departing.publisher);
    let report = store.pull(&departing, "2026-08-17T02:00:00Z");
    assert_eq!(report.ended, None);
    assert_eq!(
        store.db.get_publisher_declaration("a.localhost").unwrap(),
        Some(serde_json::to_vec(&fresh).unwrap())
    );
    assert_eq!(store.floor("a.localhost"), Some(0));
    assert_eq!(
        store.status_collections("a.localhost"),
        (0..16)
            .map(|index| format!("c{index:02}"))
            .collect::<Vec<_>>()
    );

    store.reopen();
    assert_eq!(store.floor("a.localhost"), Some(0));
    assert_eq!(store.floor("b.localhost"), Some(3));

    let mut next = declaration("a.localhost", &K2_SEED, 1, 16);
    next["prev_declaration"] = declaration_hash(&fresh).into();
    write_declaration(&departing.publisher, &next, &K2_SEED);
    let next = current_declaration(&departing.publisher);
    let report = store.pull(&departing, "2026-08-17T03:00:00Z");
    assert_eq!(report.ended, None);
    assert_eq!(
        store.db.get_publisher_declaration("a.localhost").unwrap(),
        Some(serde_json::to_vec(&next).unwrap())
    );
    assert_eq!(store.floor("a.localhost"), Some(1));
}
