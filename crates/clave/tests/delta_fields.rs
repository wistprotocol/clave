mod common;

use clave::declaration::{
    self,
    delta::{validate_fields, validate_static},
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
        "keys":[{"key_id":"test-k1", "alg":"Ed25519", "public_key":vector["author_key"],
        "valid_from":"2026-08-01T00:00:00Z"}]
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
            _ => unreachable!(),
        }
        let mut doc = wist_core::envelope::sign_envelope(&inner, "delta", "k1", &p.sk).unwrap();
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
    db.set_param("url_cap_bytes", 4096).unwrap();
    let accepted =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(accepted.accepted, std::slice::from_ref(&id));
    assert!(accepted.rejected.is_empty());
    assert_eq!(db.url_tip(&host, &url).unwrap(), Some(id));
    let public = wist_core::crypto::PublicKey::from_b64u(&seed_public_b64u(&K1_SEED)).unwrap();
    wist_core::envelope::verify_envelope(&doc, "delta", &public).unwrap();
}
