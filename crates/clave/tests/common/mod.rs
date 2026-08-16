#![allow(dead_code)]

use std::fs;

pub struct TestPub {
    pub sk: wist_core::crypto::SigningKey,
    pub dir: tempfile::TempDir,
}

fn build_publisher(domain: &str, subdomain_scope: Option<&[&str]>) -> TestPub {
    let sk = wist_core::crypto::SigningKey::from_seed(&[1u8; 32]);
    let dir = tempfile::tempdir().unwrap();
    let wk = dir.path().join(".well-known/wist");
    fs::create_dir_all(wk.join("deltas")).unwrap();
    fs::create_dir_all(wk.join("payloads")).unwrap();
    let public_key = wist_core::crypto::b64u_encode(
        &ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let mut publisher = serde_json::json!({
        "wist_version": "1.0.0", "domain": domain,
        "keys": [{"key_id": "k1", "alg": "Ed25519", "public_key": public_key, "valid_from": "2026-08-09T00:00:00Z"}],
        "seq": 0
    });
    if let Some(scope) = subdomain_scope {
        publisher["subdomain_scope"] = serde_json::json!(scope);
    }
    let env = wist_core::envelope::sign_envelope(&publisher, "publisher", "k1", &sk).unwrap();
    fs::write(wk.join("publisher.json"), serde_json::to_vec(&env).unwrap()).unwrap();
    TestPub { sk, dir }
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
    let content = serde_json::json!({"extract": extract, "links": {"total": links.len(), "urls": links}, "summary": {"title": url}});
    let payload = serde_json::json!({"wist_version": "1.0.0", "salt": salt, "content": content});
    let mut delta = serde_json::json!({
        "wist_version": "1.0.0", "url": url,
        "change_type": if prev.is_some() { "update" } else { "new" },
        "observed_at": "2026-08-09T12:00:00Z",
        "payload": {"commitment": wist_core::delta::make_commitment(&salt, &content).unwrap(), "alg": "HMAC-SHA256", "bytes": wist_core::delta::content_bytes(&content).unwrap()},
        "meta": {"lang": "en"}
    });
    if let Some(pv) = prev {
        delta["prev"] = pv.into();
    }
    let id = wist_core::delta::delta_id(&delta).unwrap();
    let env = wist_core::envelope::sign_envelope(&delta, "delta", "k1", &p.sk).unwrap();
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
    let env = wist_core::envelope::sign_envelope(&feed, "feed", "k1", &p.sk).unwrap();
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
    let env = wist_core::envelope::sign_envelope(&feed, "feed", "k1", &p.sk).unwrap();
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

/// Binds an ephemeral loopback port synchronously so its host:port is known
/// before any fixture file (which must embed that same host:port as its
/// `domain`) is written. Pass the listener to `serve_static` once the
/// fixture directory is fully populated.
pub fn reserve_addr() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    (listener, addr)
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

pub fn key_entry(key_id: &str, seed: &[u8; 32], valid_from: &str) -> serde_json::Value {
    serde_json::json!({"key_id": key_id, "alg": "Ed25519", "public_key": seed_public_b64u(seed), "valid_from": valid_from})
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
        "keys": [key_entry("k1", &K1_SEED, "2026-08-01T00:00:00Z")],
        "recovery_keys": [key_entry("r1", &R1_SEED, "2026-08-01T00:00:00Z")],
        "seq": 0
    });
    let env = wist_core::envelope::sign_envelope(&publisher, "publisher", "k1", &sk).unwrap();
    fs::write(wk.join("publisher.json"), serde_json::to_vec(&env).unwrap()).unwrap();
    TestPub { sk, dir }
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

pub fn write_declaration(
    p: &TestPub,
    publisher: &serde_json::Value,
    signer_key_id: &str,
    signer_seed: &[u8; 32],
) {
    let sk = wist_core::crypto::SigningKey::from_seed(signer_seed);
    let env =
        wist_core::envelope::sign_envelope(publisher, "publisher", signer_key_id, &sk).unwrap();
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
    key_id: &str,
    signer_seed: &[u8; 32],
) -> String {
    let salt = wist_core::crypto::b64u_encode(&[5u8; 16]);
    let content = serde_json::json!({"extract": extract, "links": {"total": 0, "urls": []}, "summary": {"title": url}});
    let payload = serde_json::json!({"wist_version": "1.0.0", "salt": salt, "content": content});
    let mut delta = serde_json::json!({
        "wist_version": "1.0.0", "url": url,
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
    let env = wist_core::envelope::sign_envelope(&delta, "delta", key_id, &sk).unwrap();
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
    key_id: &str,
    signer_seed: &[u8; 32],
) {
    let feed = serde_json::json!({"wist_version": "1.0.0", "domain": domain, "generated_at": generated_at, "deltas": ids, "next": null});
    let sk = wist_core::crypto::SigningKey::from_seed(signer_seed);
    let env = wist_core::envelope::sign_envelope(&feed, "feed", key_id, &sk).unwrap();
    fs::write(
        p.dir.path().join(".well-known/wist/feed.json"),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
}
