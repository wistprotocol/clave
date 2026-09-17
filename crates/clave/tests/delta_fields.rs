mod common;

use clave::declaration::{
    self,
    delta::{validate_fields, validate_static, validate_version},
};
use common::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[test]
fn signed_field_vectors_preserve_diagnostics_and_source_bytes() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/delta-fields.json")).unwrap(),
    )
    .unwrap();
    let source: wist_core::objects::Publisher = serde_json::from_value(json!({
        "wist_version":"1.0.0", "domain":"example.com", "seq":0,
        "keys":[key_entry_public(vector["author_key"].as_str().unwrap(), "2026-08-01T00:00:00Z")]
    }))
    .unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let doc = &case["envelope"];
        let before = doc.clone();
        let allowed: BTreeSet<_> = case["allowed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let field = validate_fields(doc);
        if allowed.contains("WIST1-E14") {
            assert_eq!(field, Err("WIST1-E14"), "{}", case["name"]);
        } else {
            field.unwrap();
        }
        let version = validate_version(doc);
        assert_eq!(
            version,
            if allowed.contains("WIST1-E14") {
                Err("WIST1-E14")
            } else if allowed.contains("WIST1-E15") {
                Err("WIST1-E15")
            } else {
                Ok(())
            },
            "{}",
            case["name"]
        );
        let errors: BTreeSet<_> = [
            validate_static(
                doc,
                case["url_cap_bytes"].as_i64().unwrap_or(2048),
                i128::from(case["commitment_cap_bytes"].as_i64().unwrap_or(38944)),
            ),
            declaration::verify_delta_authority(&[&source], doc),
        ]
        .into_iter()
        .filter_map(Result::err)
        .collect();
        assert_eq!(
            errors.is_empty(),
            allowed.is_empty(),
            "{}: {errors:?}",
            case["name"]
        );
        assert!(
            errors.is_subset(&allowed),
            "{}: {errors:?} outside {allowed:?}",
            case["name"]
        );
        assert_eq!(
            wist_core::delta::delta_id(&doc["delta"]).unwrap(),
            case["id"]
        );
        assert_eq!(*doc, before);
    }
    for case in vector["transport_cases"].as_array().unwrap() {
        let doc = &case["envelope"];
        let outcome = (|| {
            let domain = declaration::delta_publisher(doc)?;
            if domain != case["feed_domain"].as_str().unwrap()
                || wist_core::delta::delta_id(&doc["delta"]).unwrap() != case["requested_id"]
            {
                return Err("WIST2-E03");
            }
            Ok(())
        })();
        assert_eq!(
            outcome.err().unwrap_or("association_satisfied"),
            case["expected"]
        );
    }
}

fn store(p: &TestPub, doc: &Value) -> String {
    let id = wist_core::delta::delta_id(&doc["delta"]).unwrap();
    std::fs::write(
        p.dir
            .path()
            .join(format!(".well-known/wist/deltas/{}.json", &id[7..])),
        serde_json::to_vec(doc).unwrap(),
    )
    .unwrap();
    id
}

#[test]
fn field_and_static_rejections_leave_no_admission_state_across_restart() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let mut probes = Vec::new();
    for (index, expected) in [
        "WIST1-E14",
        "WIST1-E14",
        "WIST1-E09",
        "WIST1-E07",
        "WIST1-E04",
        "WIST1-E11",
        "WIST1-E15",
        "WIST1-E14",
    ]
    .iter()
    .enumerate()
    {
        let mut inner = json!({"wist_version":"1.0.0", "publisher":host, "url":format!("https://localhost/{index}"),
            "change_type":"new", "observed_at":"2026-08-09T12:00:00Z", "meta":{"lang":"en"}});
        match index {
            0 => {
                inner["change_type"] = json!("replace");
            }
            1 => {
                inner["meta"]["topics"] = Value::Null;
            }
            2 => {}
            3 => {
                inner["change_type"] = json!("attest");
            }
            4 => {
                inner["payload"] = json!({"commitment":format!("hmac-sha256:{}", "0".repeat(64)),"alg":"HMAC-SHA256","bytes":38945});
            }
            5 => {
                inner["url"] = json!(format!("https://localhost/{}", "a".repeat(2048)));
                inner["change_type"] = json!("attest");
                inner["prev"] = json!(format!("sha256:{}", "0".repeat(64)));
            }
            6 | 7 => {
                inner["wist_version"] = json!("2.0.0");
                inner["payload"] = json!({"commitment":format!("hmac-sha256:{}", "0".repeat(64)),"alg":"HMAC-SHA256","bytes":0});
                if index == 7 {
                    inner["meta"]["lang"] = json!("EN");
                }
            }
            _ => unreachable!(),
        }
        let mut doc = wist_core::envelope::sign_envelope(&inner, "delta", &p.kid, &p.sk).unwrap();
        if index == 1 {
            doc["sig"]["value"] = json!(wist_core::crypto::b64u_encode(&[0; 64]));
        }
        probes.push((
            store(&p, &doc),
            inner["url"].as_str().unwrap().to_owned(),
            *expected,
        ));
    }
    let ids: Vec<_> = probes.iter().map(|(id, _, _)| id.clone()).collect();
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert!(report.accepted.is_empty() && report.queued.is_empty());
    assert_eq!(report.rejected.len(), probes.len());
    assert!(report.noise.is_none());
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    for (id, url, code) in probes {
        assert!(
            report.rejected.contains(&(id.clone(), code.into())),
            "{report:?}"
        );
        assert!(!db.is_delta_seen(&id).unwrap());
        assert!(db.url_tip(&host, &url).unwrap().is_none());
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &id[7..]))
            .exists());
        assert!(db
            .list_rejections(&host)
            .unwrap()
            .iter()
            .any(|entry| entry.delta_id.as_deref() == Some(&id) && entry.code == code));
    }
}

#[test]
fn decimal_byte_counts_and_active_url_caps_use_canonical_values() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let url = format!("https://localhost/{}", "a".repeat(2048));
    let id = add_delta(&p, &url, "body", None);
    let file = p
        .dir
        .path()
        .join(format!(".well-known/wist/deltas/{}.json", &id[7..]));
    let mut doc: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let bytes = doc["delta"]["payload"]["bytes"].as_u64().unwrap();
    doc["delta"]["payload"]["bytes"] = json!(bytes as f64);
    assert_eq!(store(&p, &doc), id);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    let rejected =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(rejected.rejected, [(id.clone(), "WIST1-E11".into())]);
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let now = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    clave::param_change::run(
        &db,
        &sk,
        "url_cap_bytes",
        4096,
        Some("2026-08-16T12:00:00Z"),
        now,
    )
    .unwrap();
    clave::seal::run(&db, data.path(), &sk, now).unwrap();
    let accepted =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-16T12:00:00Z").unwrap();
    assert_eq!(accepted.accepted, std::slice::from_ref(&id));
    assert!(accepted.rejected.is_empty());
    assert_eq!(db.url_tip(&host, &url).unwrap(), Some(id));
    let public = wist_core::crypto::PublicKey::from_b64u(&seed_public_b64u(&K1_SEED)).unwrap();
    wist_core::envelope::verify_envelope(&doc, "delta", &public).unwrap();
}

fn retained_delta(db: &clave::db::Db, id: &str) -> Value {
    db.peek_pending_entries()
        .unwrap()
        .0
        .into_iter()
        .find(|row| {
            row.entry_type == "publisher_delta"
                && wist_core::delta::delta_id(&row.entry_json["delta"]).unwrap() == id
        })
        .unwrap()
        .entry_json
}

fn versioned_delta(p: &TestPub, url: &str, version: &str) -> (String, Value) {
    let original = add_delta(p, url, "body", None);
    let source = p.dir.path().join(".well-known/wist");
    let doc: Value = serde_json::from_slice(
        &std::fs::read(source.join(format!("deltas/{}.json", &original[7..]))).unwrap(),
    )
    .unwrap();
    let mut inner = doc["delta"].clone();
    inner["wist_version"] = json!(version);
    let updated = wist_core::envelope::sign_envelope(&inner, "delta", &p.kid, &p.sk).unwrap();
    let id = store(p, &updated);
    std::fs::copy(
        source.join(format!("payloads/{}.json", &original[7..])),
        source.join(format!("payloads/{}.json", &id[7..])),
    )
    .unwrap();
    (id, updated)
}

#[test]
fn same_major_versions_preserve_signed_values_through_admission_and_restart() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let mut db = clave::db::Db::open(&path).unwrap();
    for (index, version) in [
        "1.0.1".into(),
        "1.1.0".into(),
        format!("1.{}.{}", "9".repeat(80), "9".repeat(80)),
    ]
    .iter()
    .enumerate()
    {
        let url = format!("https://localhost/{index}");
        let (id, doc) = versioned_delta(&p, &url, version);
        write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
        let report =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
        assert_eq!(report.accepted, std::slice::from_ref(&id));
        assert!(report.rejected.is_empty());
        drop(db);
        db = clave::db::Db::open(&path).unwrap();
        let retained = retained_delta(&db, &id);
        assert_eq!(retained, doc);
        assert_eq!(db.url_tip(&host, &url).unwrap(), Some(id.clone()));
        let duplicate =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
        assert!(duplicate.rejected.is_empty());
        assert_eq!(retained_delta(&db, &id), doc);
    }
}

#[test]
fn fetched_unsupported_predecessor_cannot_advance_a_supported_chain() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let url = "https://localhost/page";
    let (prior, _) = versioned_delta(&p, url, "2.0.0");
    let next = add_delta(&p, url, "changed", Some(&prior));
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&next),
        "2026-08-09T12:00:00Z",
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert!(report.accepted.is_empty() && report.queued.is_empty());
    assert!(report
        .rejected
        .contains(&(prior.clone(), "WIST1-E15".into())));
    assert!(report
        .rejected
        .contains(&(next.clone(), "WIST1-E07".into())));
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    assert!(db.url_tip(&host, url).unwrap().is_none());
    for id in [prior, next] {
        assert!(!db.is_delta_seen(&id).unwrap());
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &id[7..]))
            .exists());
    }
}

#[test]
fn sealing_preserves_version_diagnostics_and_supported_signed_values() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let bad_url = "https://localhost/unsupported";
    let (bad_id, bad) = versioned_delta(&p, bad_url, "2.0.0");
    let good_url = "https://localhost/supported";
    let (good_id, good) = versioned_delta(&p, good_url, "1.2.3");
    for (id, doc, url) in [(&bad_id, &bad, bad_url), (&good_id, &good, good_url)] {
        db.record_accepted_delta(&host, id, doc, 0, url, id)
            .unwrap();
        std::fs::create_dir_all(data.path().join("payloads")).unwrap();
        std::fs::copy(
            p.dir
                .path()
                .join(format!(".well-known/wist/payloads/{}.json", &id[7..])),
            data.path().join(format!("payloads/{}.json", &id[7..])),
        )
        .unwrap();
    }
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let at = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let report = clave::seal::run(&db, data.path(), &sk, at).unwrap();
    assert_eq!(report.entry_count, 2);
    assert_eq!(report.dropped.len(), 1);
    assert!(report.dropped[0].contains("WIST1-E15"));
    let bytes = std::fs::read(data.path().join("log/blocks/000000000.json.zst")).unwrap();
    let block: Value = serde_json::from_slice(&zstd::decode_all(&bytes[..]).unwrap()).unwrap();
    assert_eq!(
        block["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["type"] == "publisher_delta")
            .unwrap()["body"],
        good
    );
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    assert!(!db.is_delta_seen(&bad_id).unwrap());
    assert!(db.url_tip(&host, bad_url).unwrap().is_none());
    assert_eq!(db.url_tip(&host, good_url).unwrap(), Some(good_id));
    assert!(db
        .list_rejections(&host)
        .unwrap()
        .iter()
        .any(|entry| entry.delta_id.as_deref() == Some(&bad_id) && entry.code == "WIST1-E15"));
}

#[test]
fn integral_byte_spellings_materialize_fetched_chains_through_restart_and_sealing() {
    for suffix in [".0", "e0"] {
        for restart in [false, true] {
            let (listener, host, client) = reserve_addr();
            let p = make_publisher(&host);
            serve_static(listener, p.dir.path().to_path_buf());
            let data = tempfile::tempdir().unwrap();
            clave::init::run(&host, data.path()).unwrap();
            let path = data.path().join("clave.sqlite");
            let mut db = clave::db::Db::open(&path).unwrap();
            let url = "https://localhost/article";
            let first = add_delta(&p, url, "initial body", None);
            let second = add_delta(&p, url, "updated body", Some(&first));
            let mut originals = Vec::new();
            for id in [&first, &second] {
                let source = p
                    .dir
                    .path()
                    .join(format!(".well-known/wist/deltas/{}.json", &id[7..]));
                let raw = std::fs::read_to_string(&source).unwrap();
                let doc: Value = serde_json::from_str(&raw).unwrap();
                let count = doc["delta"]["payload"]["bytes"].as_u64().unwrap();
                let raw = raw.replace(
                    &format!("\"bytes\":{count}"),
                    &format!("\"bytes\":{count}{suffix}"),
                );
                let changed: Value = serde_json::from_str(&raw).unwrap();
                assert!(changed["delta"]["payload"]["bytes"].as_u64().is_none());
                assert_eq!(wist_core::delta::delta_id(&changed["delta"]).unwrap(), *id);
                assert_eq!(
                    wist_core::jcs::canonicalize(&changed).unwrap(),
                    wist_core::jcs::canonicalize(&doc).unwrap(),
                );
                std::fs::write(&source, &raw).unwrap();
                originals.push((source, raw, changed));
            }
            write_feed(
                &p,
                &host,
                std::slice::from_ref(&second),
                "2026-08-09T12:00:01Z",
            );
            let report =
                clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z")
                    .unwrap();
            assert_eq!(report.accepted, [first.clone(), second.clone()]);
            assert!(report.rejected.is_empty());
            if restart {
                drop(db);
                db = clave::db::Db::open(&path).unwrap();
            }
            for (id, (_, _, original)) in [&first, &second].into_iter().zip(&originals) {
                assert_eq!(retained_delta(&db, id), *original);
            }
            let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
            let now = "2026-08-09T13:00:00Z"
                .parse::<jiff::Timestamp>()
                .unwrap()
                .as_second();
            let sealed = clave::seal::run(&db, data.path(), &key, now).unwrap();
            assert_eq!(sealed.entry_count, 3);
            assert!(sealed.dropped.is_empty());
            let record = db.get_record(url, &host).unwrap().unwrap();
            assert_eq!(record.delta_id, second);
            assert_eq!(record.observed_at, "2026-08-09T12:00:01Z");
            assert_eq!(record.title, url);
            let mut history =
                clave::history::History::open(data.path(), db.last_block().unwrap()).unwrap();
            let block = history.next_block().unwrap().unwrap();
            for (id, (source, raw, original)) in [&first, &second].into_iter().zip(&originals) {
                let sealed = block
                    .block()
                    .entries
                    .iter()
                    .find(|entry| {
                        entry["type"] == "publisher_delta"
                            && wist_core::delta::delta_id(&entry["body"]["delta"]).unwrap() == *id
                    })
                    .unwrap();
                assert_eq!(
                    wist_core::jcs::canonicalize(&sealed["body"]).unwrap(),
                    wist_core::jcs::canonicalize(original).unwrap(),
                );
                assert_eq!(std::fs::read_to_string(source).unwrap(), *raw);
                assert_eq!(
                    std::fs::read(data.path().join(format!("payloads/{}.json", &id[7..]))).unwrap(),
                    std::fs::read(
                        p.dir
                            .path()
                            .join(format!(".well-known/wist/payloads/{}.json", &id[7..]))
                    )
                    .unwrap(),
                );
            }
            assert!(history.next_block().unwrap().is_none());
            drop(db);
            rusqlite::Connection::open(&path).unwrap().execute_batch(
                "DROP TABLE delta_index_reconciliation; DELETE FROM seen_deltas; DELETE FROM url_tips;",
            ).unwrap();
            let db = clave::db::Db::open(&path).unwrap();
            assert_eq!(db.url_tip(&host, url).unwrap(), Some(second.clone()));
            assert!(db.is_delta_seen(&first).unwrap());
            assert_eq!(db.get_record(url, &host).unwrap().unwrap().delta_id, second);
        }
    }
}
