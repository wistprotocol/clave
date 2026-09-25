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
    fs::create_dir_all(wk.join("deltas")).unwrap();
    fs::create_dir_all(wk.join("payloads")).unwrap();
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
    TestPub {
        domain: domain.into(),
        sk,
        kid: kid(&K1_SEED),
        dir,
    }
}

pub fn make_publisher(domain: &str) -> TestPub {
    build_publisher(domain, None)
}

pub fn make_publisher_with_scope(domain: &str, subdomain_scope: &[&str]) -> TestPub {
    build_publisher(domain, Some(subdomain_scope))
}

pub fn add_delta(p: &TestPub, url: &str, extract: &str, prev: Option<&str>) -> String {
    add_delta_with_links(p, url, extract, prev, &[])
}

pub fn add_delta_with_links(
    p: &TestPub,
    url: &str,
    extract: &str,
    prev: Option<&str>,
    links: &[&str],
) -> String {
    let salt = wist_core::crypto::b64u_encode(&[5u8; 16]);
    let content = serde_json::json!({"extract": extract, "links": {"total": links.len(), "urls": links}, "summary": {"title": url.chars().take(256).collect::<String>()}});
    let payload = serde_json::json!({"wist_version": "1.0.0", "salt": salt, "content": content});
    let mut delta = serde_json::json!({
        "wist_version": "1.0.0", "publisher": p.domain, "url": url,
        "change_type": if prev.is_some() { "update" } else { "new" },
        "observed_at": "2026-08-09T12:00:00Z",
        "payload": {"commitment": wist_core::delta::make_commitment(&salt, &content).unwrap(), "alg": "HMAC-SHA256", "bytes": wist_core::delta::content_bytes(&content).unwrap()},
        "meta": {"lang": "en"}
    });
    if let Some(pv) = prev {
        delta["prev"] = pv.into();
        if let Some(at) = successor_observed_at(p, pv) {
            delta["observed_at"] = at.into();
        }
    }
    let id = store_delta(p, &delta);
    fs::write(
        p.dir
            .path()
            .join(format!(".well-known/wist/payloads/{}.json", &id[7..])),
        serde_json::to_vec(&payload).unwrap(),
    )
    .unwrap();
    id
}

/// An `attest` Delta continuing `prev`, observed one second after it.
pub fn add_attest(p: &TestPub, url: &str, prev: &str) -> String {
    add_content_free_delta(p, url, "attest", prev)
}

/// A `delete` Delta continuing `prev`, observed one second after it.
pub fn add_delete(p: &TestPub, url: &str, prev: &str) -> String {
    add_content_free_delta(p, url, "delete", prev)
}

fn add_content_free_delta(p: &TestPub, url: &str, change_type: &str, prev: &str) -> String {
    let delta = serde_json::json!({
        "wist_version": "1.0.0", "publisher": p.domain, "url": url,
        "change_type": change_type,
        "observed_at": successor_observed_at(p, prev).expect("the predecessor Delta is on the site"),
        "prev": prev,
        "meta": {"lang": "en"}
    });
    store_delta(p, &delta)
}

fn successor_observed_at(p: &TestPub, prev: &str) -> Option<String> {
    let raw = fs::read(
        p.dir
            .path()
            .join(format!(".well-known/wist/deltas/{}.json", &prev[7..])),
    )
    .ok()?;
    let predecessor: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let at = predecessor["delta"]["observed_at"]
        .as_str()
        .unwrap()
        .parse::<jiff::Timestamp>()
        .unwrap();
    Some(
        at.checked_add(jiff::SignedDuration::from_secs(1))
            .unwrap()
            .to_string(),
    )
}

fn store_delta(p: &TestPub, delta: &serde_json::Value) -> String {
    let id = wist_core::delta::delta_id(delta).unwrap();
    let env = wist_core::envelope::sign_envelope(delta, "delta", &p.kid, &p.sk).unwrap();
    fs::write(
        p.dir
            .path()
            .join(format!(".well-known/wist/deltas/{}.json", &id[7..])),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
    id
}

pub fn write_feed(p: &TestPub, domain: &str, ids: &[String], generated_at: &str) {
    write_feed_with_next(p, domain, ids, generated_at, None);
}

pub fn write_feed_with_next(
    p: &TestPub,
    domain: &str,
    ids: &[String],
    generated_at: &str,
    next: Option<&str>,
) {
    let feed = serde_json::json!({"wist_version": "1.0.0", "domain": domain, "generated_at": generated_at, "deltas": ids, "next": next});
    let env = wist_core::envelope::sign_envelope(&feed, "feed", &p.kid, &p.sk).unwrap();
    fs::write(
        p.dir.path().join(".well-known/wist/feed.json"),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
}

pub fn write_feed_page(
    p: &TestPub,
    domain: &str,
    number: u64,
    ids: &[String],
    generated_at: &str,
    next: Option<&str>,
) {
    let feed = serde_json::json!({"wist_version": "1.0.0", "domain": domain, "generated_at": generated_at, "deltas": ids, "next": next});
    let env = wist_core::envelope::sign_envelope(&feed, "feed", &p.kid, &p.sk).unwrap();
    let dir = p.dir.path().join(".well-known/wist/feed");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format!("{number}.json")),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
pub fn write_feed_page_signed(
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
    let dir = p.dir.path().join(".well-known/wist/feed");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format!("{number}.json")),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
}

pub fn page_url(domain: &str, number: u64) -> String {
    format!("https://{domain}/.well-known/wist/feed/{number}.json")
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
    fs::create_dir_all(wk.join("deltas")).unwrap();
    fs::create_dir_all(wk.join("payloads")).unwrap();
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
    TestPub {
        domain: domain.into(),
        sk,
        kid: kid(&K1_SEED),
        dir,
    }
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

pub fn add_delta_signed(
    p: &TestPub,
    url: &str,
    extract: &str,
    prev: Option<&str>,
    observed_at: &str,
    signer_seed: &[u8; 32],
) -> String {
    add_delta_signed_as(p, url, extract, prev, observed_at, signer_seed, signer_seed)
}

/// A Delta whose signature names `named_seed`'s entry but was produced by
/// `signer_seed`: the shape WIST-1 §5.1 rejects with `WIST1-E01` when the
/// named entry is authorized and `WIST1-E02` when it is not.
#[allow(clippy::too_many_arguments)]
pub fn add_delta_signed_as(
    p: &TestPub,
    url: &str,
    extract: &str,
    prev: Option<&str>,
    observed_at: &str,
    signer_seed: &[u8; 32],
    named_seed: &[u8; 32],
) -> String {
    let salt = wist_core::crypto::b64u_encode(&[5u8; 16]);
    let content = serde_json::json!({"extract": extract, "links": {"total": 0, "urls": []}, "summary": {"title": url.chars().take(256).collect::<String>()}});
    let payload = serde_json::json!({"wist_version": "1.0.0", "salt": salt, "content": content});
    let mut delta = serde_json::json!({
        "wist_version": "1.0.0", "publisher": p.domain, "url": url,
        "change_type": if prev.is_some() { "update" } else { "new" },
        "observed_at": observed_at,
        "payload": {"commitment": wist_core::delta::make_commitment(&salt, &content).unwrap(), "alg": "HMAC-SHA256", "bytes": wist_core::delta::content_bytes(&content).unwrap()},
        "meta": {"lang": "en"}
    });
    if let Some(pv) = prev {
        delta["prev"] = pv.into();
    }
    let id = wist_core::delta::delta_id(&delta).unwrap();
    let sk = wist_core::crypto::SigningKey::from_seed(signer_seed);
    let env = wist_core::envelope::sign_envelope(&delta, "delta", &kid(named_seed), &sk).unwrap();
    let hex = id.strip_prefix("sha256:").unwrap();
    let wk = p.dir.path().join(".well-known/wist");
    fs::write(
        wk.join(format!("deltas/{hex}.json")),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
    fs::write(
        wk.join(format!("payloads/{hex}.json")),
        serde_json::to_vec(&payload).unwrap(),
    )
    .unwrap();
    id
}

pub fn write_feed_signed(
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
        p.dir.path().join(".well-known/wist/feed.json"),
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
