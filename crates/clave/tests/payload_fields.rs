mod common;

use clave::db::Db;
use clave::declaration::delta::SizeCaps;
use common::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use wist_core::{crypto::PublicKey, delta, envelope, objects::Payload};

fn caps(case: &Value) -> SizeCaps {
    SizeCaps {
        url_cap_bytes: 2048,
        extract_cap_bytes: case["caps"]["extract_cap_bytes"].as_i64().unwrap_or(32768),
        links_cap_bytes: case["caps"]["links_cap_bytes"].as_i64().unwrap_or(4096),
        link_url_cap_bytes: case["caps"]["link_url_cap_bytes"].as_i64().unwrap_or(2048),
        summary_cap_bytes: case["caps"]["summary_cap_bytes"].as_i64().unwrap_or(2048),
    }
}

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/payload-fields.json")).unwrap(),
    )
    .unwrap()
}

#[test]
fn signed_payload_fields_and_semantic_diagnostics_match_vectors() {
    let vector = fixture();
    let key = PublicKey::from_b64u(vector["public_key"].as_str().unwrap()).unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let original = case.clone();
        let payload = &case["payload"];
        let body = &case["envelope"]["delta"];
        envelope::verify_envelope(&case["envelope"], "delta", &key).unwrap();
        delta::verify_commitment(
            case["preimage"]["salt"].as_str().unwrap(),
            &case["preimage"]["content"],
            body["payload"]["commitment"].as_str().unwrap(),
        )
        .unwrap();
        let mut errors = BTreeSet::new();
        let raw = case["payload_json"]
            .as_str()
            .map(|raw| raw.as_bytes().to_vec())
            .unwrap_or_else(|| serde_json::to_vec(payload).unwrap());
        if let Err(code) = clave::payload::validate_json(&raw)
            .and_then(|()| clave::payload::validate_fields(payload))
        {
            errors.insert(code);
        } else {
            if let Err(code) = clave::payload::validate_version(payload) {
                errors.insert(code);
            }
            let typed: Payload =
                serde_json::from_slice(&wist_core::jcs::canonicalize(payload).unwrap()).unwrap();
            if let Err(code) = clave::payload::validate_links(&typed.content.links, "example.com") {
                errors.insert(code);
            }
            if delta::verify_commitment(
                &typed.salt,
                &payload["content"],
                body["payload"]["commitment"].as_str().unwrap(),
            )
            .is_err()
            {
                errors.insert("WIST1-E10");
            }
            if delta::content_bytes(&payload["content"]).unwrap()
                != body["payload"]["bytes"].as_u64().unwrap()
            {
                errors.insert("WIST1-E10");
            }
            let caps = caps(case);
            if let Err(code) = caps.validate_payload_sizes(payload) {
                errors.insert(code);
            }
        }
        assert_eq!(json!(errors), case["allowed"], "{}", case["name"]);
        let commitment =
            serde_json::from_slice(&wist_core::jcs::canonicalize(&body["payload"]).unwrap())
                .unwrap();
        let result = clave::payload::validate_json(&raw).and_then(|()| {
            clave::payload::validate(payload, &commitment, "example.com", &caps(case))
        });
        match result {
            Ok(_) => assert!(errors.is_empty(), "{}", case["name"]),
            Err(code) => assert!(errors.contains(code), "{}: {code}", case["name"]),
        }
        assert_eq!(*case, original);
    }
}

fn publish(p: &TestPub, case: &Value, suffix: &str, prev: Option<&str>) -> String {
    let transform = |v: &Value| -> Value {
        serde_json::from_str(
            &serde_json::to_string(v)
                .unwrap()
                .replace("https://example.com/", "https://localhost/"),
        )
        .unwrap()
    };
    let payload = transform(&case["payload"]);
    let preimage = transform(&case["preimage"]);
    let mut body = case["envelope"]["delta"].clone();
    body["publisher"] = p.domain.clone().into();
    body["url"] = format!("https://localhost/{suffix}").into();
    body["payload"]["commitment"] =
        delta::make_commitment(preimage["salt"].as_str().unwrap(), &preimage["content"])
            .unwrap()
            .into();
    body["payload"]["bytes"] = (body["payload"]["bytes"].as_u64().unwrap() as i64
        + delta::content_bytes(&preimage["content"]).unwrap() as i64
        - delta::content_bytes(&case["preimage"]["content"]).unwrap() as i64)
        .into();
    if let Some(prev) = prev {
        body["prev"] = prev.into();
        body["change_type"] = "update".into();
        body["observed_at"] = "2026-08-09T12:00:01Z".into();
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
        case["payload_json"]
            .as_str()
            .map(|raw| raw.as_bytes().to_vec())
            .unwrap_or_else(|| serde_json::to_vec(&payload).unwrap()),
    )
    .unwrap();
    id
}

#[test]
fn payload_field_rejections_precede_storage_and_survive_restart() {
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
        if case.get("caps").is_some() {
            continue;
        }
        let suffix = format!("field-case-{i}");
        let id = publish(&p, case, &suffix, None);
        all.push(id.clone());
        if case["allowed"].as_array().unwrap().is_empty() {
            accepted.push(id);
        } else {
            rejected.push((id, format!("https://localhost/{suffix}")));
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
    assert!(repeated.accepted.is_empty());
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
    assert_eq!(db.list_records().unwrap().len(), accepted.len());
    for id in accepted {
        let signed: Value = serde_json::from_slice(
            &std::fs::read(
                p.dir
                    .path()
                    .join(format!(".well-known/wist/deltas/{}.json", &id[7..])),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            db.get_record(signed["delta"]["url"].as_str().unwrap(), &host)
                .unwrap()
                .unwrap()
                .delta_id,
            id
        );
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
fn fetched_predecessor_payload_version_rejects_and_retries_without_changing_delta_id() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let vector = fixture();
    let mut case = vector["cases"][0].clone();
    case["payload"]["wist_version"] = "2.0.0".into();
    let first = publish(&p, &case, "chain", None);
    let child = publish(&p, &vector["cases"][0], "chain", Some(&first));
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
    for id in [&first, &child] {
        assert!(!db.is_delta_seen(id).unwrap());
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &id[7..]))
            .exists());
    }
    assert_eq!(db.url_tip(&host, "https://localhost/chain").unwrap(), None);
    drop(db);
    let db = Db::open(&path).unwrap();
    case["payload"]["wist_version"] = "1.123456789012345678901234567890.42".into();
    assert_eq!(publish(&p, &case, "chain", None), first);
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:03Z").unwrap();
    assert_eq!(report.accepted, [first, child.clone()]);
    assert!(report.rejected.is_empty());
    assert_eq!(
        db.url_tip(&host, "https://localhost/chain").unwrap(),
        Some(child)
    );
}

#[test]
fn invalid_retained_payload_vectors_stop_sealing_without_rejecting_deltas() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let vector = fixture();
    let now = "2026-08-09T12:00:03Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    for (i, case) in vector["cases"].as_array().unwrap().iter().enumerate() {
        if case.get("caps").is_some() || case["allowed"].as_array().unwrap().is_empty() {
            continue;
        }
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
        let id = publish(&p, case, &format!("retained-{i}"), None);
        let base = p.dir.path().join(".well-known/wist");
        let signed: Value = serde_json::from_slice(
            &std::fs::read(base.join(format!("deltas/{}.json", &id[7..]))).unwrap(),
        )
        .unwrap();
        let url = signed["delta"]["url"].as_str().unwrap();
        db.record_accepted_delta(&host, &id, &signed, 0, url, &id)
            .unwrap();
        let payload = data.path().join(format!("payloads/{}.json", &id[7..]));
        std::fs::copy(base.join(format!("payloads/{}.json", &id[7..])), &payload).unwrap();
        let original = std::fs::read(&payload).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        drop(db);
        for _ in 0..2 {
            let db = Db::open(&path).unwrap();
            let error = clave::seal::run(&db, data.path(), &sk, now)
                .err()
                .unwrap_or_else(|| panic!("{} sealed", case["name"]));
            if !case["allowed"]
                .as_array()
                .unwrap()
                .contains(&json!("WIST1-E05"))
            {
                assert!(
                    case["allowed"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|code| { error.to_string().contains(code.as_str().unwrap()) }),
                    "{}: {error}",
                    case["name"]
                );
            }
            assert!(db.last_block().unwrap().is_none(), "{}", case["name"]);
            assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
            assert_eq!(
                db.url_tip(&host, url).unwrap().as_deref(),
                Some(id.as_str())
            );
            assert!(db.is_delta_seen(&id).unwrap());
            assert!(db.list_rejections(&host).unwrap().is_empty());
            assert!(db.list_records().unwrap().is_empty());
            assert!(db.block_at(0).unwrap().is_none());
            assert!(!data.path().join("checkpoint").exists());
            assert_eq!(std::fs::read(&payload).unwrap(), original);
            assert_eq!(
                db.peek_pending_entries()
                    .unwrap()
                    .0
                    .iter()
                    .find(|entry| entry.entry_type == "publisher_delta")
                    .unwrap()
                    .entry_json,
                signed
            );
        }
    }
}

#[test]
fn altered_retained_payload_preserves_chains_until_repaired_after_restart() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let first = add_delta(&p, "https://localhost/chain", "first", None);
    let child = add_delta(&p, "https://localhost/chain", "child", Some(&first));
    let other = add_delta(&p, "https://localhost/other", "other", None);
    let ids = [first.clone(), child.clone(), other.clone()];
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
    assert_eq!(report.accepted, ids);
    let payload = data.path().join(format!("payloads/{}.json", &first[7..]));
    let original = std::fs::read(&payload).unwrap();
    let mut altered: Value = serde_json::from_slice(&original).unwrap();
    altered["content"]["extract"] = "wrong".into();
    std::fs::write(&payload, serde_json::to_vec(&altered).unwrap()).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let now = "2026-08-09T12:00:03Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let error = clave::seal::run(&db, data.path(), &sk, now).err().unwrap();
    assert!(error.to_string().contains("WIST1-E10"), "{error}");
    assert!(db.last_block().unwrap().is_none());
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 3);
    assert_eq!(
        db.url_tip(&host, "https://localhost/chain").unwrap(),
        Some(child.clone())
    );
    for id in &ids {
        assert!(db.is_delta_seen(id).unwrap());
    }
    assert!(db.list_rejections(&host).unwrap().is_empty());
    drop(db);
    let db = Db::open(&path).unwrap();
    assert!(clave::seal::run(&db, data.path(), &sk, now).is_err());
    std::fs::write(&payload, &original).unwrap();
    let report = clave::seal::run(&db, data.path(), &sk, now).unwrap();
    assert!(report.dropped.is_empty());
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 0);
    assert_eq!(
        db.get_record("https://localhost/chain", &host)
            .unwrap()
            .unwrap()
            .delta_id,
        child
    );
    assert_eq!(
        db.get_record("https://localhost/other", &host)
            .unwrap()
            .unwrap()
            .delta_id,
        other
    );
    assert_eq!(std::fs::read(&payload).unwrap(), original);
}
