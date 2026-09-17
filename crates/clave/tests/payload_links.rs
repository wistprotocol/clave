mod common;

use clave::db::Db;
use common::*;
use serde_json::{json, Value};
use wist_core::{crypto::PublicKey, delta, envelope};

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/payload-links.json")).unwrap(),
    )
    .unwrap()
}

#[test]
fn signed_payload_link_vectors_preserve_committed_content() {
    let vector = fixture();
    let key = PublicKey::from_b64u(vector["public_key"].as_str().unwrap()).unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let original = case.clone();
        let body = &case["envelope"]["delta"];
        envelope::verify_envelope(&case["envelope"], "delta", &key).unwrap();
        delta::verify_commitment(
            case["payload"]["salt"].as_str().unwrap(),
            &case["payload"]["content"],
            body["payload"]["commitment"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            delta::content_bytes(&case["payload"]["content"]).unwrap(),
            body["payload"]["bytes"].as_u64().unwrap()
        );
        let links = serde_json::from_value(case["payload"]["content"]["links"].clone()).unwrap();
        assert_eq!(
            json!(
                clave::payload::validate_links(&links, body["publisher"].as_str().unwrap()).err()
            ),
            case["expected"],
            "{}",
            case["name"]
        );
        assert_eq!(*case, original);
    }
}

fn publish(p: &TestPub, url: &str, links: Value, prev: Option<&str>) -> String {
    let salt = wist_core::crypto::b64u_encode(&[5; 16]);
    let content = json!({"extract":"Content", "links":links, "summary":{"title":"Title"}});
    let payload = json!({"wist_version":"1.0.0", "salt":salt, "content":content});
    let mut body = json!({
        "wist_version":"1.0.0", "publisher":p.domain, "url":url,
        "change_type":if prev.is_some() { "update" } else { "new" },
        "observed_at":if prev.is_some() { "2026-08-09T12:00:01Z" } else { "2026-08-09T12:00:00Z" },
        "meta":{"lang":"en"},
        "payload":{"commitment":delta::make_commitment(&salt, &content).unwrap(), "alg":"HMAC-SHA256", "bytes":delta::content_bytes(&content).unwrap()}
    });
    if let Some(prev) = prev {
        body["prev"] = prev.into();
    }
    let id = delta::delta_id(&body).unwrap();
    let signed = envelope::sign_envelope(&body, "delta", &p.kid, &p.sk).unwrap();
    let base = p.dir.path().join(".well-known/wist");
    std::fs::write(
        base.join(format!("deltas/{}.json", &id[7..])),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
    std::fs::write(
        base.join(format!("payloads/{}.json", &id[7..])),
        serde_json::to_vec(&payload).unwrap(),
    )
    .unwrap();
    id
}

#[test]
fn invalid_links_reject_before_storage_and_stay_retryable_after_restart() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let vector = fixture();
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut all = Vec::new();
    for (i, case) in vector["cases"].as_array().unwrap().iter().enumerate() {
        let mut links = case["payload"]["content"]["links"].clone();
        for url in links["urls"].as_array_mut().unwrap() {
            *url = url
                .as_str()
                .unwrap()
                .replace("example.com", "localhost")
                .into();
        }
        let url = format!("https://localhost/link-case-{i}");
        let id = publish(&p, &url, links, None);
        all.push(id.clone());
        if case["expected"].is_null() {
            accepted.push(id);
        } else {
            rejected.push((id, url));
        }
    }
    write_feed(&p, &host, &all, "2026-08-09T12:00:00Z");
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
    assert_eq!(report.accepted, accepted);
    assert_eq!(report.noise, None);
    assert!(!report.suspended);
    assert_eq!(
        report.rejected,
        rejected
            .iter()
            .map(|(id, _)| (id.clone(), "WIST2-E03".into()))
            .collect::<Vec<_>>()
    );
    for (id, url) in &rejected {
        assert!(!db.is_delta_seen(id).unwrap());
        assert_eq!(db.url_tip(&host, url).unwrap(), None);
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &id[7..]))
            .exists());
    }
    assert_eq!(
        db.count_pending_entries("publisher_delta").unwrap(),
        accepted.len() as i64
    );
    drop(db);
    let db = Db::open(&path).unwrap();
    let repeated =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:03Z").unwrap();
    assert_eq!(repeated.rejected, report.rejected);
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let seal = clave::seal::run(
        &db,
        data.path(),
        &sk,
        "2026-08-09T12:00:03Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second(),
    )
    .unwrap();
    assert!(seal.dropped.is_empty());
    for id in accepted {
        let source = p
            .dir
            .path()
            .join(format!(".well-known/wist/payloads/{}.json", &id[7..]));
        let retained = data.path().join(format!("payloads/{}.json", &id[7..]));
        assert_eq!(
            std::fs::read(source).unwrap(),
            std::fs::read(retained).unwrap()
        );
    }
}

#[test]
fn scoped_subject_uses_signed_publisher_for_internal_links_and_predecessor_retrieval() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["subject.example.org"]);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let url = "https://subject.example.org/item";
    let first = publish(
        &p,
        url,
        json!({"total":1, "urls":["https://localhost/internal"]}),
        None,
    );
    let child = publish(
        &p,
        url,
        json!({"total":1, "urls":["https://subject.example.org/external"]}),
        Some(&first),
    );
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&child),
        "2026-08-09T12:00:00Z",
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
    assert!(report.accepted.is_empty());
    assert!(report
        .rejected
        .contains(&(first.clone(), "WIST2-E03".into())));
    assert!(report
        .rejected
        .contains(&(child.clone(), "WIST1-E07".into())));
    assert_eq!(db.url_tip(&host, url).unwrap(), None);
    for id in [&first, &child] {
        assert!(!db.is_delta_seen(id).unwrap());
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &id[7..]))
            .exists());
    }
    drop(db);
    let db = Db::open(&path).unwrap();
    let valid = publish(
        &p,
        url,
        json!({"total":1, "urls":["https://subject.example.org/external"]}),
        None,
    );
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&valid),
        "2026-08-09T12:00:01Z",
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:03Z").unwrap();
    assert_eq!(report.accepted.as_slice(), std::slice::from_ref(&valid));
    assert!(report.rejected.is_empty());
    let invalid = publish(
        &p,
        url,
        json!({"total":1, "urls":["https://child.localhost/internal"]}),
        Some(&valid),
    );
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&invalid),
        "2026-08-09T12:00:02Z",
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:04Z").unwrap();
    assert_eq!(report.rejected, [(invalid.clone(), "WIST2-E03".into())]);
    assert!(report.accepted.is_empty());
    assert!(report.queued.is_empty());
    drop(db);
    let db = Db::open(&path).unwrap();
    assert_eq!(
        db.url_tip(&host, url).unwrap().as_deref(),
        Some(valid.as_str())
    );
    assert!(!db.is_delta_seen(&invalid).unwrap());
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
    assert!(!data
        .path()
        .join(format!("payloads/{}.json", &invalid[7..]))
        .exists());
}
