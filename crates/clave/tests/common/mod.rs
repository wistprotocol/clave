#![allow(dead_code)]

use std::fs;

pub fn seal_fixture_epoch(
    db: &clave::db::Db,
    data_dir: &std::path::Path,
    epoch_number: u64,
    sealed_at: &str,
    entries: &[serde_json::Value],
) -> clave::db::EpochRow {
    let sk = clave::keys::load(&data_dir.join("keys/seed")).unwrap();
    let anchor = clave::history::anchor(data_dir).unwrap();
    let mut ordered = entries.to_vec();
    wist_core::epoch::sort_entries(&mut ordered).unwrap();
    let octets = wist_core::epoch::epoch_octets(&ordered).unwrap();
    let row = db
        .commit_seal(
            &sk,
            &anchor.log_id,
            &[],
            epoch_number,
            sealed_at,
            &ordered,
            octets,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
    clave::publication::recover(db, data_dir).unwrap();
    row
}

pub fn seal_vector_epochs(
    db: &clave::db::Db,
    data_dir: &std::path::Path,
    sk: &wist_core::crypto::SigningKey,
    epochs: &[serde_json::Value],
) -> clave::db::EpochRow {
    let anchor = clave::history::anchor(data_dir).unwrap();
    rusqlite::Connection::open(data_dir.join("clave.sqlite"))
        .unwrap()
        .execute_batch("DELETE FROM epochs; DELETE FROM log_entries; DELETE FROM log_tiles;")
        .unwrap();
    let mut head = None;
    for epoch in epochs {
        let checkpoint =
            wist_core::checkpoint::Checkpoint::parse(epoch["checkpoint"].as_str().unwrap())
                .unwrap();
        let mut entries: Vec<serde_json::Value> =
            serde_json::from_value(epoch["entries"].clone()).unwrap();
        wist_core::epoch::sort_entries(&mut entries).unwrap();
        head = Some(
            db.commit_seal(
                sk,
                &anchor.log_id,
                &[],
                checkpoint.epoch_number(),
                checkpoint.sealed_at(),
                &entries,
                wist_core::epoch::epoch_octets(&entries).unwrap(),
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap(),
        );
    }
    head.expect("a vector carries at least one Epoch")
}

pub fn head_checkpoint(data_dir: &std::path::Path) -> wist_core::checkpoint::Checkpoint {
    let note = fs::read_to_string(data_dir.join("checkpoint")).unwrap();
    wist_core::checkpoint::Checkpoint::parse(&note).unwrap()
}

pub fn served_entries(data_dir: &std::path::Path, from: u64, to: u64) -> Vec<serde_json::Value> {
    let serving = fs::read_to_string(data_dir.join("checkpoint"))
        .ok()
        .and_then(|note| wist_core::checkpoint::Checkpoint::parse(&note).ok())
        .map_or(to, |head| head.tree_size())
        .max(to);
    let mut leaves = Vec::new();
    for bundle in wist_core::tiles::entry_bundles_for_range(from, to, serving) {
        let bytes = fs::read(data_dir.join(bundle.path().trim_start_matches('/'))).unwrap();
        let (start, _) = bundle.leaf_range();
        for (offset, entry) in wist_core::tiles::decode_entry_bundle(&bytes)
            .unwrap()
            .into_iter()
            .enumerate()
        {
            let index = start + offset as u64;
            if (from..to).contains(&index) {
                leaves.push(entry);
            }
        }
    }
    wist_core::epoch::parse_entries(&leaves).unwrap()
}

pub fn listed_snapshots(data_dir: &std::path::Path) -> Vec<serde_json::Value> {
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(data_dir.join("snapshots/index.json")).unwrap()).unwrap();
    document["index"]["snapshots"].as_array().unwrap().clone()
}

pub fn listed_snapshot_directory(
    data_dir: &std::path::Path,
    entry: &serde_json::Value,
) -> std::path::PathBuf {
    let url = entry["manifest_url"].as_str().unwrap();
    data_dir.join(
        url.trim_start_matches('/')
            .strip_suffix("/manifest.json")
            .unwrap(),
    )
}

pub fn served_snapshot(data_dir: &std::path::Path, date: &str) -> std::path::PathBuf {
    let entry = listed_snapshots(data_dir)
        .into_iter()
        .find(|entry| entry["snapshot_date"] == date)
        .unwrap_or_else(|| panic!("no Snapshot of {date} is listed"));
    listed_snapshot_directory(data_dir, &entry)
}

pub fn newest_served_snapshot(data_dir: &std::path::Path) -> std::path::PathBuf {
    let entry = listed_snapshots(data_dir)
        .into_iter()
        .next()
        .expect("a Snapshot is listed");
    listed_snapshot_directory(data_dir, &entry)
}

pub fn tree_bytes(
    root: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let bytes = fs::read(&path).unwrap();
                files.insert(path.strip_prefix(root).unwrap().to_path_buf(), bytes);
            }
        }
    }
    files
}

pub fn spec_dir() -> std::path::PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
}

pub struct TestPub {
    pub domain: String,
    pub sk: wist_core::crypto::SigningKey,
    pub kid: String,
    pub dir: tempfile::TempDir,
}

/// The RFC 7638 thumbprint that names the key a seed derives.
pub fn kid(seed: &[u8; 32]) -> String {
    wist_core::objects::publisher::thumbprint(&seed_public_b64u(seed))
}

/// A whole-second UTC instant as the NumericDate a key window carries.
pub fn nbf(at: &str) -> u64 {
    u64::try_from(wist_core::timestamp::log_seconds(at).unwrap()).unwrap()
}

pub fn key_entry_public(public_b64u: &str, valid_from: &str) -> serde_json::Value {
    serde_json::to_value(wist_core::objects::PublisherKey::new(
        public_b64u,
        nbf(valid_from),
        None,
    ))
    .unwrap()
}

pub fn rekey(entry: &mut serde_json::Value, public_b64u: &str) {
    entry["x"] = public_b64u.into();
    entry["kid"] = wist_core::objects::publisher::thumbprint(public_b64u).into();
}

fn build_publisher(domain: &str, subdomain_scope: Option<&[&str]>) -> TestPub {
    let sk = wist_core::crypto::SigningKey::from_seed(&K1_SEED);
    let dir = tempfile::tempdir().unwrap();
    let wk = dir.path().join(".well-known/wist");
    fs::create_dir_all(&wk).unwrap();
    let mut publisher = serde_json::json!({
        "wist_version": "1.0.0", "domain": domain,
        "keys": [key_entry(&K1_SEED, "2026-08-09T00:00:00Z")],
        "seq": 0
    });
    if let Some(scope) = subdomain_scope {
        publisher["subdomain_scope"] = serde_json::json!(scope);
    }
    let env =
        wist_core::envelope::sign_envelope(&publisher, "publisher", &kid(&K1_SEED), &sk).unwrap();
    fs::write(wk.join("publisher.json"), serde_json::to_vec(&env).unwrap()).unwrap();
    let p = TestPub {
        domain: domain.into(),
        sk,
        kid: kid(&K1_SEED),
        dir,
    };
    publish_collection(&p, "default", &[], "2026-08-09T00:00:01Z", None);
    p
}

pub fn make_publisher(domain: &str) -> TestPub {
    build_publisher(domain, None)
}

pub fn make_publisher_with_scope(domain: &str, subdomain_scope: &[&str]) -> TestPub {
    build_publisher(domain, Some(subdomain_scope))
}

pub fn label(labeler: &str, subject: &str, asserted_at: &str) -> serde_json::Value {
    serde_json::json!({"wist_version": "1.0.0", "labeler": labeler, "subject": subject, "name": "wist:spam", "asserted_at": asserted_at})
}

pub fn add_label(p: &TestPub, subject: &str, asserted_at: &str) -> String {
    let inner = label(&p.domain, subject, asserted_at);
    let id = wist_core::label::label_id(&inner).unwrap();
    let envelope = wist_core::envelope::sign_envelope(&inner, "label", &p.kid, &p.sk).unwrap();
    let dir = p.dir.path().join(".well-known/wist/labels");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format!("{}.json", &id[7..])),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    id
}

pub fn write_label_feed(p: &TestPub, domain: &str, ids: &[String], generated_at: &str) {
    write_label_feed_with_next(p, domain, ids, generated_at, None);
}

pub fn write_label_feed_with_next(
    p: &TestPub,
    domain: &str,
    ids: &[String],
    generated_at: &str,
    next: Option<&str>,
) {
    let feed = serde_json::json!({"wist_version": "1.0.0", "domain": domain, "generated_at": generated_at, "deltas": ids, "next": next});
    let env = wist_core::envelope::sign_envelope(&feed, "feed", &p.kid, &p.sk).unwrap();
    fs::write(
        p.dir.path().join(".well-known/wist/label-feed.json"),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
}

pub fn write_label_feed_page(
    p: &TestPub,
    domain: &str,
    number: u64,
    ids: &[String],
    generated_at: &str,
    next: Option<&str>,
) {
    write_label_feed_page_signed(p, domain, number, ids, generated_at, next, &K1_SEED);
}

#[allow(clippy::too_many_arguments)]
pub fn write_label_feed_page_signed(
    p: &TestPub,
    domain: &str,
    number: u64,
    ids: &[String],
    generated_at: &str,
    next: Option<&str>,
    signer_seed: &[u8; 32],
) {
    let feed = serde_json::json!({"wist_version": "1.0.0", "domain": domain, "generated_at": generated_at, "deltas": ids, "next": next});
    let sk = wist_core::crypto::SigningKey::from_seed(signer_seed);
    let env = wist_core::envelope::sign_envelope(&feed, "feed", &kid(signer_seed), &sk).unwrap();
    let dir = p.dir.path().join(".well-known/wist/label-feed");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format!("{number}.json")),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
}

pub fn write_label_feed_signed(
    p: &TestPub,
    domain: &str,
    ids: &[String],
    generated_at: &str,
    signer_seed: &[u8; 32],
) {
    let feed = serde_json::json!({"wist_version": "1.0.0", "domain": domain, "generated_at": generated_at, "deltas": ids, "next": null});
    let sk = wist_core::crypto::SigningKey::from_seed(signer_seed);
    let env = wist_core::envelope::sign_envelope(&feed, "feed", &kid(signer_seed), &sk).unwrap();
    fs::write(
        p.dir.path().join(".well-known/wist/label-feed.json"),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
}

pub fn label_page_url(domain: &str, number: u64) -> String {
    format!("https://{domain}/.well-known/wist/label-feed/{number}.json")
}

pub fn reserve_addr() -> (std::net::TcpListener, String, clave::fetch::Client) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .resolve("localhost", listener.local_addr().unwrap());
    let client = clave::fetch::Client::with_builder(true, builder);
    (listener, "localhost".into(), client)
}

pub fn serve_recording(
    listener: std::net::TcpListener,
    dir: std::path::PathBuf,
) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let recorded = requests.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                recorded.lock().unwrap().push(uri.to_string());
                let body = fs::read(dir.join(uri.path().trim_start_matches('/')));
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
    requests
}

pub fn serve_static(listener: std::net::TcpListener, dir: std::path::PathBuf) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app =
                axum::Router::new().fallback_service(tower_http::services::ServeDir::new(dir));
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                .await
                .unwrap();
        });
    });
}

pub const K1_SEED: [u8; 32] = [1u8; 32];
pub const K2_SEED: [u8; 32] = [7u8; 32];
pub const R1_SEED: [u8; 32] = [9u8; 32];
pub const X1_SEED: [u8; 32] = [11u8; 32];

pub fn seed_public_b64u(seed: &[u8; 32]) -> String {
    wist_core::crypto::b64u_encode(
        &ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    )
}

pub fn key_entry(seed: &[u8; 32], valid_from: &str) -> serde_json::Value {
    key_entry_public(&seed_public_b64u(seed), valid_from)
}

pub fn make_publisher_with_recovery(domain: &str) -> TestPub {
    let sk = wist_core::crypto::SigningKey::from_seed(&K1_SEED);
    let dir = tempfile::tempdir().unwrap();
    let wk = dir.path().join(".well-known/wist");
    fs::create_dir_all(&wk).unwrap();
    let publisher = serde_json::json!({
        "wist_version": "1.0.0", "domain": domain,
        "subdomain_scope": ["example.com"],
        "keys": [key_entry(&K1_SEED, "2026-08-01T00:00:00Z")],
        "recovery_keys": [key_entry(&R1_SEED, "2026-08-01T00:00:00Z")],
        "seq": 0
    });
    let env =
        wist_core::envelope::sign_envelope(&publisher, "publisher", &kid(&K1_SEED), &sk).unwrap();
    fs::write(wk.join("publisher.json"), serde_json::to_vec(&env).unwrap()).unwrap();
    let p = TestPub {
        domain: domain.into(),
        sk,
        kid: kid(&K1_SEED),
        dir,
    };
    publish_collection(&p, "default", &[], "2026-08-01T00:00:01Z", None);
    p
}

pub fn current_declaration(p: &TestPub) -> serde_json::Value {
    serde_json::from_slice(&fs::read(p.dir.path().join(".well-known/wist/publisher.json")).unwrap())
        .unwrap()
}

pub fn declaration_hash(doc: &serde_json::Value) -> String {
    use sha2::Digest;
    let canonical = wist_core::jcs::canonicalize(&doc["publisher"]).unwrap();
    format!(
        "sha256:{}",
        wist_core::crypto::hex_encode(&sha2::Sha256::digest(&canonical))
    )
}

pub fn write_declaration(p: &TestPub, publisher: &serde_json::Value, signer_seed: &[u8; 32]) {
    let sk = wist_core::crypto::SigningKey::from_seed(signer_seed);
    let env =
        wist_core::envelope::sign_envelope(publisher, "publisher", &kid(signer_seed), &sk).unwrap();
    fs::write(
        p.dir.path().join(".well-known/wist/publisher.json"),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
}

pub fn serve_crossing(
    listener: std::net::TcpListener,
    directory: std::path::PathBuf,
    suffix: String,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let crossed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = crossed.clone();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                    let path = directory.join(uri.path().trim_start_matches('/'));
                    if uri.path().ends_with(&suffix) {
                        flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    async move {
                        match std::fs::read(path) {
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
    crossed
}

pub fn loopback_client() -> clave::fetch::Client {
    clave::fetch::Client::with_builder(true, reqwest::blocking::Client::builder().no_proxy())
}

pub fn list_signed_mirrors(
    data_dir: &std::path::Path,
    key_id: &str,
    sk: &wist_core::crypto::SigningKey,
    urls: &[String],
    now_unix: i64,
) {
    let inner = serde_json::json!({
        "wist_version": clave::WIST_VERSION,
        "updated_at": jiff::Timestamp::from_second(now_unix).unwrap().to_string(),
        "mirror_urls": urls,
    });
    let envelope = wist_core::envelope::sign_envelope(&inner, "mirrors", key_id, sk).unwrap();
    fs::create_dir_all(data_dir.join("log")).unwrap();
    fs::write(
        data_dir.join("log/mirrors.json"),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
}

pub fn serve_not_found() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new()
                .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, Vec::<u8>::new()) });
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                .await
                .unwrap();
        });
    });
    url
}

pub fn page_item_with_links(
    p: &TestPub,
    url: &str,
    extract: &str,
    links: &[&str],
) -> (serde_json::Value, serde_json::Value) {
    let salt = wist_core::crypto::b64u_encode(&[5u8; 16]);
    let content = serde_json::json!({
        "extract": extract,
        "links": {"total": links.len(), "urls": links},
        "summary": {"title": url.chars().take(256).collect::<String>()}
    });
    page_item_with_content(p, url, &salt, &content)
}

pub fn page_item_with_content(
    p: &TestPub,
    url: &str,
    salt: &str,
    content: &serde_json::Value,
) -> (serde_json::Value, serde_json::Value) {
    let bytes = wist_core::jcs::canonicalize(content)
        .map(|octets| octets.len())
        .unwrap_or_default();
    let commitment = wist_core::item::commitment(salt, content)
        .unwrap_or_else(|_| format!("hmac-sha256:{}", "0".repeat(64)));
    let item = serde_json::json!({
        "publisher": p.domain, "url": url, "observed_at": "2026-08-09T07:00:00Z",
        "payload": {"commitment": commitment, "alg": "HMAC-SHA256", "bytes": bytes},
        "meta": {"lang": "en"}
    });
    let payload = serde_json::json!({"wist_version": "1.0.0", "salt": salt, "content": content});
    (item, payload)
}

pub fn page_item(p: &TestPub, url: &str, extract: &str) -> (serde_json::Value, serde_json::Value) {
    page_item_with_links(p, url, extract, &[])
}

pub fn removed_item(p: &TestPub, url: &str) -> serde_json::Value {
    serde_json::json!({
        "publisher": p.domain, "url": url, "observed_at": "2026-08-09T07:00:00Z", "removed": true
    })
}

pub fn item_id(item: &serde_json::Value) -> String {
    wist_core::item::item_id(item).unwrap()
}

#[derive(Debug, Clone)]
pub struct Published {
    pub envelope: serde_json::Value,
    pub catalog_id: String,
    pub list: Vec<serde_json::Value>,
    pub tree: std::collections::BTreeMap<String, Vec<u8>>,
    pub change_list: Option<String>,
}

pub fn collection_dir(p: &TestPub, name: &str) -> std::path::PathBuf {
    p.dir
        .path()
        .join(format!(".well-known/wist/collections/{name}"))
}

pub fn publish_collection(
    p: &TestPub,
    name: &str,
    items: &[(serde_json::Value, Option<serde_json::Value>)],
    generated_at: &str,
    previous: Option<&Published>,
) -> Published {
    publish_collection_signed(p, name, items, generated_at, previous, &K1_SEED)
}

pub fn publish_collection_signed(
    p: &TestPub,
    name: &str,
    items: &[(serde_json::Value, Option<serde_json::Value>)],
    generated_at: &str,
    previous: Option<&Published>,
    signer: &[u8; 32],
) -> Published {
    let list: Vec<serde_json::Value> = items.iter().map(|(item, _)| item.clone()).collect();
    let bounds = wist_core::tree::TreeBounds::new(65_536, 16).unwrap();
    let built = wist_core::tree::build(&list, &bounds).unwrap();
    let root = wist_core::item::root(&list).unwrap();
    let base = collection_dir(p, name);
    for directory in ["tree", "payloads", "changes"] {
        fs::create_dir_all(base.join(directory)).unwrap();
    }
    for (hex, octets) in &built.files {
        fs::write(base.join("tree").join(hex), octets).unwrap();
    }
    for (item, payload) in items {
        if let Some(payload) = payload {
            fs::write(
                base.join(format!(
                    "payloads/{}.json",
                    wist_core::item::payload_name(item).unwrap()
                )),
                wist_core::jcs::canonicalize(payload).unwrap(),
            )
            .unwrap();
        }
    }
    let inner = serde_json::json!({
        "wist_version": "1.0.0", "publisher": p.domain, "collection": name,
        "generated_at": generated_at, "size": list.len(),
        "root": format!("sha256:{}", wist_core::crypto::hex_encode(&root)),
        "tree": built.tree,
    });
    let envelope = wist_core::envelope::sign_envelope(
        &inner,
        "catalog",
        &kid(signer),
        &wist_core::crypto::SigningKey::from_seed(signer),
    )
    .unwrap();
    fs::write(
        base.join("catalog.json"),
        wist_core::jcs::canonicalize(&envelope).unwrap(),
    )
    .unwrap();
    let catalog: wist_core::objects::Catalog = serde_json::from_value(inner.clone()).unwrap();
    let mut change_list = None;
    if let Some(previous) = previous {
        let served: wist_core::objects::Catalog =
            serde_json::from_value(previous.envelope["catalog"].clone()).unwrap();
        if let Some(written) = wist_core::change_list::write(
            Some(wist_core::change_list::Listed {
                catalog: &served,
                list: &previous.list,
            }),
            wist_core::change_list::Listed {
                catalog: &catalog,
                list: &list,
            },
        )
        .unwrap()
        {
            fs::write(
                base.join(format!("changes/{}.json", written.name)),
                &written.octets,
            )
            .unwrap();
            change_list = Some(written.name);
        }
    }
    Published {
        catalog_id: wist_core::catalog::catalog_id(&inner).unwrap(),
        envelope,
        list,
        tree: built.files,
        change_list,
    }
}

pub fn pull_at(
    db: &clave::db::Db,
    client: &clave::fetch::Client,
    data_dir: &std::path::Path,
    host: &str,
    now: &str,
) -> clave::ingest::IngestReport {
    clave::ingest::run(db, client, data_dir, host, now).unwrap()
}

pub const VECTOR_HOST: &str = "example.localhost";

pub fn vector_site() -> (std::net::TcpListener, clave::fetch::Client, TestPub) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve(VECTOR_HOST, listener.local_addr().unwrap()),
    );
    (listener, client, make_publisher(VECTOR_HOST))
}

pub fn to_vector_host(value: &serde_json::Value) -> serde_json::Value {
    serde_json::from_str(
        &serde_json::to_string(value)
            .unwrap()
            .replace("example.com", VECTOR_HOST),
    )
    .unwrap()
}

pub fn effective_code(
    db: &clave::db::Db,
    host: &str,
    item: &serde_json::Value,
    report: &clave::ingest::IngestReport,
) -> Option<String> {
    let id = item_id(item);
    if report.items.iter().any(|admitted| admitted.ends_with(&id)) {
        return None;
    }
    let rejection = db
        .list_rejections(host)
        .unwrap()
        .into_iter()
        .find(|rejection| rejection.id.as_deref() == Some(id.as_str()))
        .unwrap_or_else(|| panic!("{id} is neither admitted nor rejected"));
    Some(match (rejection.code.as_str(), rejection.detail) {
        ("WIST2-E03", Some(detail)) => detail,
        (code, _) => code.to_owned(),
    })
}

pub fn payload_files(data_dir: &std::path::Path) -> usize {
    fs::read_dir(data_dir.join("held/payloads")).map_or(0, |dir| dir.count())
}

pub struct Rig {
    pub p: TestPub,
    pub host: String,
    pub client: clave::fetch::Client,
    pub data: tempfile::TempDir,
    pub db: clave::db::Db,
    pub sk: wist_core::crypto::SigningKey,
}

impl Rig {
    pub fn new() -> Rig {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        db.set_param("epoch_cadence_seconds", 1).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        Rig {
            p,
            host,
            client,
            data,
            db,
            sk,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://{}/{path}", self.host)
    }

    pub fn page(&self, path: &str, extract: &str) -> (serde_json::Value, serde_json::Value) {
        page_item(&self.p, &self.url(path), extract)
    }

    pub fn publish(
        &self,
        items: &[(serde_json::Value, Option<serde_json::Value>)],
        generated_at: &str,
        previous: Option<&Published>,
    ) -> Published {
        publish_collection(&self.p, "default", items, generated_at, previous)
    }

    pub fn pull(&self, at: &str) -> clave::ingest::IngestReport {
        pull_at(&self.db, &self.client, self.data.path(), &self.host, at)
    }

    pub fn seal(&self, at: &str) -> clave::seal::SealReport {
        clave::seal::run(
            &self.db,
            self.data.path(),
            &self.sk,
            wist_core::timestamp::log_seconds(at).unwrap(),
        )
        .unwrap()
    }

    pub fn state(&self) -> clave::collection::State {
        let scope = std::collections::BTreeSet::from([self.host.clone()]);
        self.db
            .load_state(self.db.sealed_state(self.data.path()).unwrap(), &scope)
            .unwrap()
    }

    pub fn entries(&self, height: u64) -> Vec<serde_json::Value> {
        self.db.epoch_entries(height).unwrap()
    }
}

pub fn types(entries: &[serde_json::Value]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| entry["type"].as_str().unwrap().to_owned())
        .collect()
}

pub fn sealed_item_ids(entries: &[serde_json::Value]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_item")
        .map(|entry| item_id(&entry["body"]["item"]))
        .collect()
}
