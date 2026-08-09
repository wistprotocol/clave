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
    let salt = wist_core::crypto::b64u_encode(&[5u8; 16]);
    let content = serde_json::json!({"extract": extract, "links": {"total": 0, "urls": []}, "summary": {"title": url}});
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
    let feed = serde_json::json!({"wist_version": "1.0.0", "domain": domain, "generated_at": generated_at, "deltas": ids, "next": null});
    let env = wist_core::envelope::sign_envelope(&feed, "feed", "k1", &p.sk).unwrap();
    fs::write(
        p.dir.path().join(".well-known/wist/feed.json"),
        serde_json::to_vec(&env).unwrap(),
    )
    .unwrap();
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
