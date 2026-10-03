mod common;

use common::*;
use std::sync::{Arc, Mutex};

type Action = Box<dyn FnOnce() + Send>;

type Hook = (String, Option<Action>);

#[derive(Clone, Default)]
struct Hooks(Arc<Mutex<Vec<Hook>>>);

impl Hooks {
    fn on(&self, suffix: &str, action: impl FnOnce() + Send + 'static) {
        self.0
            .lock()
            .unwrap()
            .push((suffix.into(), Some(Box::new(action))));
    }

    fn fired(&self, path: &str) -> Option<Action> {
        self.0
            .lock()
            .unwrap()
            .iter_mut()
            .find(|(suffix, action)| action.is_some() && path.ends_with(suffix.as_str()))?
            .1
            .take()
    }
}

fn serve_hooked(listener: std::net::TcpListener, dir: std::path::PathBuf, hooks: Hooks) {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                let hooks = hooks.clone();
                let dir = dir.clone();
                async move {
                    let path = uri.path().to_owned();
                    if let Some(action) = hooks.fired(&path) {
                        tokio::task::spawn_blocking(action).await.unwrap();
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
}

fn ts(at: &str) -> i64 {
    wist_core::timestamp::log_seconds(at).unwrap()
}

struct Store {
    data: tempfile::TempDir,
    path: std::path::PathBuf,
    db: clave::db::Db,
    sk: wist_core::crypto::SigningKey,
}

fn store(host: &str) -> Store {
    let data = tempfile::tempdir().unwrap();
    clave::init::run(host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    Store { data, path, db, sk }
}

impl Store {
    fn seal_at(&self, at: &str) -> impl FnOnce() + Send + 'static {
        let (path, dir, at) = (
            self.path.clone(),
            self.data.path().to_path_buf(),
            at.to_owned(),
        );
        move || {
            let db = clave::db::Db::open(&path).unwrap();
            let sk = clave::keys::load(&dir.join("keys/seed")).unwrap();
            clave::seal::run(&db, &dir, &sk, ts(&at)).unwrap();
        }
    }

    fn query<T: rusqlite::types::FromSql>(&self, sql: &str) -> Vec<T> {
        rusqlite::Connection::open(&self.path)
            .unwrap()
            .prepare(sql)
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
}

fn two_collections(p: &TestPub, host: &str) -> ((serde_json::Value, serde_json::Value), String) {
    let url = |path: &str| format!("https://{host}/{path}");
    let mut declaration = current_declaration(p)["publisher"].clone();
    declaration["collections"] = serde_json::json!([
        {"name": "journal", "scope": [{"url": url("journal/"), "match": "prefix"}]},
        {"name": "shop", "scope": [{"url": url("shop/"), "match": "prefix"}]},
    ]);
    write_declaration(p, &declaration, &K1_SEED);
    let a = page_item(p, &url("journal/a"), "a");
    let x = page_item(p, &url("shop/x"), "x");
    publish_collection(
        p,
        "journal",
        &[(a.0.clone(), Some(a.1.clone()))],
        "2026-08-09T11:59:00Z",
        None,
    );
    publish_collection(
        p,
        "shop",
        &[(x.0.clone(), Some(x.1.clone()))],
        "2026-08-09T11:59:00Z",
        None,
    );
    (a, url("shop/x"))
}

#[test]
fn a_pull_retried_after_a_settlement_reads_the_current_declaration_alone() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    let hooks = Hooks::default();
    serve_hooked(listener, p.dir.path().to_path_buf(), hooks.clone());
    let s = store(&host);
    let ingest = |now: &str| clave::ingest::run(&s.db, &client, s.data.path(), &host, now).unwrap();
    ingest("2026-08-09T12:00:00Z");
    clave::seal::run(&s.db, s.data.path(), &s.sk, ts("2026-08-09T12:00:00Z")).unwrap();
    let prior = current_declaration(&p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry(&K2_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&p, &owner, &R1_SEED);
    ingest("2026-08-09T13:00:00Z");
    clave::seal::run(&s.db, s.data.path(), &s.sk, ts("2026-08-09T13:00:00Z")).unwrap();
    let legit_item = page_item(&p, "https://example.com/legit", "legit");
    let legit = publish_collection_signed(
        &p,
        "default",
        &[(legit_item.0.clone(), Some(legit_item.1.clone()))],
        "2026-08-10T00:00:00Z",
        None,
        &K2_SEED,
    );
    assert_eq!(
        ingest("2026-08-10T00:00:05Z").queued,
        [format!("default/{}", legit.catalog_id)]
    );
    let thief_item = page_item(&p, "https://example.com/thief", "thief");
    let thief = publish_collection_signed(
        &p,
        "default",
        &[
            (legit_item.0.clone(), Some(legit_item.1.clone())),
            (thief_item.0.clone(), Some(thief_item.1.clone())),
        ],
        "2026-08-16T12:00:00Z",
        None,
        &K1_SEED,
    );
    hooks.on(
        "collections/default/catalog.json",
        s.seal_at("2026-08-16T13:00:00Z"),
    );
    let pulled = ingest("2026-08-16T12:59:59Z");
    let thief_slot = format!("default/{}", thief.catalog_id);
    assert!(!pulled.accepted.contains(&thief_slot), "{pulled:?}");
    assert!(!pulled.queued.contains(&thief_slot), "{pulled:?}");
    assert!(
        pulled.rejected.iter().any(|(slot, _)| *slot == thief_slot),
        "{pulled:?}"
    );
    let status = clave::serve::load_status(&s.db, &host).unwrap().unwrap();
    assert_eq!(
        status.collections[0].accepted.as_deref(),
        Some(legit.catalog_id.as_str())
    );
    let next = clave::seal::run(&s.db, s.data.path(), &s.sk, ts("2026-08-16T13:00:01Z")).unwrap();
    assert!(next.dropped.is_empty(), "{:?}", next.dropped);
}

#[test]
fn a_withdrawn_payload_is_not_written_back_by_a_retried_pull() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let hooks = Hooks::default();
    serve_hooked(listener, p.dir.path().to_path_buf(), hooks.clone());
    let s = store(&host);
    let u = format!("https://{host}/u");
    let x = page_item(&p, &u, "x");
    let y = page_item(&p, &u, "y");
    let x_id = item_id(&x.0);
    let v1 = publish_collection(
        &p,
        "default",
        &[(x.0.clone(), Some(x.1.clone()))],
        "2026-08-09T11:00:00Z",
        None,
    );
    clave::ingest::run(&s.db, &client, s.data.path(), &host, "2026-08-09T11:30:00Z").unwrap();
    clave::seal::run(&s.db, s.data.path(), &s.sk, ts("2026-08-09T12:00:00Z")).unwrap();
    let v2 = publish_collection(
        &p,
        "default",
        &[(y.0.clone(), Some(y.1.clone()))],
        "2026-08-09T12:10:00Z",
        Some(&v1),
    );
    clave::ingest::run(&s.db, &client, s.data.path(), &host, "2026-08-09T12:30:00Z").unwrap();
    clave::seal::run(&s.db, s.data.path(), &s.sk, ts("2026-08-09T13:00:00Z")).unwrap();
    let held = clave::db::held_payload_path(s.data.path(), &x_id).unwrap();
    let served = clave::db::served_payload_path(s.data.path(), &x_id).unwrap();
    let _ = std::fs::remove_file(&held);
    let _ = std::fs::remove_file(&served);
    clave::governance::withdraw(
        &s.db,
        &s.sk,
        &host,
        &x_id,
        "gdpr-17",
        "EU",
        ts("2026-08-09T13:10:00Z"),
    )
    .unwrap();
    publish_collection(
        &p,
        "default",
        &[(x.0.clone(), Some(x.1.clone()))],
        "2026-08-09T13:20:00Z",
        Some(&v2),
    );
    hooks.on(
        &format!(
            "payloads/{}.json",
            wist_core::item::payload_name(&x.0).unwrap()
        ),
        s.seal_at("2026-08-09T14:00:00Z"),
    );
    let pulled =
        clave::ingest::run(&s.db, &client, s.data.path(), &host, "2026-08-09T13:30:00Z").unwrap();
    assert!(s.db.is_withdrawn(&x_id).unwrap());
    assert!(
        pulled
            .rejected
            .iter()
            .any(|(slot, code)| slot.ends_with(&x_id) && code == "WIST2-E03"),
        "{pulled:?}"
    );
    assert!(
        !held.exists(),
        "the retried pull wrote the withdrawn Payload"
    );
    clave::seal::run(&s.db, s.data.path(), &s.sk, ts("2026-08-09T15:00:00Z")).unwrap();
    assert!(!held.exists());
    assert!(!served.exists());
}

#[test]
fn a_url_takes_its_place_in_its_collections_transaction_when_a_seal_lands_mid_pull() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let hooks = Hooks::default();
    serve_hooked(listener, p.dir.path().to_path_buf(), hooks.clone());
    let s = store(&host);
    let (a, shop_url) = two_collections(&p, &host);
    hooks.on(
        "collections/shop/catalog.json",
        s.seal_at("2026-08-09T12:00:00Z"),
    );
    clave::ingest::run(&s.db, &client, s.data.path(), &host, "2026-08-09T11:59:30Z").unwrap();
    let first = s.db.epoch_entries(0).unwrap();
    assert_eq!(
        types(&first),
        [
            "publisher_declaration",
            "publisher_catalog",
            "publisher_item"
        ]
    );
    assert_eq!(sealed_item_ids(&first), [item_id(&a.0)]);
    assert_eq!(
        s.query::<String>("SELECT url FROM waiting_urls"),
        [shop_url]
    );
    assert_eq!(s.query::<i64>("SELECT eligibility FROM waiting_urls"), [1]);
}

#[test]
fn labels_take_the_last_event_of_a_retried_pull() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let hooks = Hooks::default();
    serve_hooked(listener, p.dir.path().to_path_buf(), hooks.clone());
    let s = store(&host);
    two_collections(&p, &host);
    let label = add_label(&p, "https://subject.example/page", "2026-08-09T11:59:30Z");
    write_label_feed(
        &p,
        &host,
        std::slice::from_ref(&label),
        "2026-08-09T11:59:30Z",
    );
    hooks.on(
        "collections/shop/catalog.json",
        s.seal_at("2026-08-09T12:00:00Z"),
    );
    let pulled =
        clave::ingest::run(&s.db, &client, s.data.path(), &host, "2026-08-09T11:59:30Z").unwrap();
    assert_eq!(pulled.labels, [label]);
    let shop: Vec<(i64, i64)> = rusqlite::Connection::open(&s.path)
        .unwrap()
        .prepare("SELECT place_event, place_position FROM waiting_urls")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let labeled: Vec<(i64, i64)> = rusqlite::Connection::open(&s.path)
        .unwrap()
        .prepare(
            "SELECT place_event, place_position FROM pending_entries WHERE label_id IS NOT NULL",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(shop.len(), 1);
    assert_eq!(labeled, [(shop[0].0, 2)]);
}

#[test]
fn a_retried_pull_takes_an_event_no_concurrent_pull_shares() {
    let a_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    a_listener.set_nonblocking(true).unwrap();
    let b_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    b_listener.set_nonblocking(true).unwrap();
    let (a_host, b_host) = ("a.localhost".to_owned(), "b.localhost".to_owned());
    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve(&a_host, a_listener.local_addr().unwrap())
            .resolve(&b_host, b_listener.local_addr().unwrap()),
    );
    let a = make_publisher(&a_host);
    let b = make_publisher(&b_host);
    let hooks = Hooks::default();
    serve_hooked(a_listener, a.dir.path().to_path_buf(), hooks.clone());
    serve_static(b_listener, b.dir.path().to_path_buf());
    let s = store(&a_host);
    let (_, shop_url) = two_collections(&a, &a_host);
    let b_url = format!("https://{b_host}/b");
    let item = page_item(&b, &b_url, "b");
    publish_collection(
        &b,
        "default",
        &[(item.0.clone(), Some(item.1.clone()))],
        "2026-08-09T11:59:00Z",
        None,
    );
    hooks.on(
        "collections/shop/catalog.json",
        s.seal_at("2026-08-09T12:00:00Z"),
    );
    {
        let (path, dir, client, b_host) = (
            s.path.clone(),
            s.data.path().to_path_buf(),
            client.clone(),
            b_host.clone(),
        );
        hooks.on("collections/shop/catalog.json", move || {
            let db = clave::db::Db::open(&path).unwrap();
            clave::ingest::run(&db, &client, &dir, &b_host, "2026-08-09T12:00:10Z").unwrap();
        });
    }
    clave::ingest::run(
        &s.db,
        &client,
        s.data.path(),
        &a_host,
        "2026-08-09T11:59:30Z",
    )
    .unwrap();
    let event_of = |url: &str| {
        rusqlite::Connection::open(&s.path)
            .unwrap()
            .query_row(
                "SELECT place_event FROM waiting_urls WHERE url = ?1",
                [url],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    assert_ne!(event_of(&shop_url), event_of(&b_url));
}
