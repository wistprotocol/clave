mod common;

use clave::{db::Db, declaration::verify_delta_predecessor};
use common::*;
use serde_json::{json, Value};

const NOW: &str = "2026-08-09T14:00:00Z";
const URL: &str = "https://localhost/a";

#[test]
fn signed_predecessor_vectors_preserve_exact_ordering() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/declaration-fields.json")).unwrap(),
    )
    .unwrap();
    let key =
        wist_core::crypto::PublicKey::from_b64u(vector["author_key"].as_str().unwrap()).unwrap();
    let mut count = 0;
    for case in vector["relation_cases"].as_array().unwrap() {
        if case["kind"] != "predecessor" {
            continue;
        }
        for doc in [&case["predecessor"], &case["envelope"]] {
            wist_core::envelope::verify_envelope(doc, "delta", &key).unwrap();
        }
        assert_eq!(
            verify_delta_predecessor(&case["envelope"], &case["predecessor"])
                .err()
                .unwrap_or("relation_satisfied"),
            case["expected"],
            "{}",
            case["name"]
        );
        count += 1;
    }
    assert_eq!(count, 3);
}

#[test]
fn predecessor_ownership_and_current_field_checks_precede_time_comparison() {
    let key = wist_core::crypto::SigningKey::from_seed(&K1_SEED);
    let public = wist_core::crypto::PublicKey::from_b64u(&seed_public_b64u(&K1_SEED)).unwrap();
    let prior = json!({
        "wist_version": "1.0.0", "publisher": "localhost", "url": URL,
        "observed_at": "2026-08-09T12:00:00Z", "change_type": "delete",
        "prev": format!("sha256:{}", "0".repeat(64)), "meta": {"lang": "en"}
    });
    for (publisher, url) in [
        ("foreign.example", URL),
        ("localhost", "https://localhost/b"),
    ] {
        let mut predecessor = prior.clone();
        predecessor["publisher"] = json!(publisher);
        predecessor["url"] = json!(url);
        let mut candidate = prior.clone();
        candidate["observed_at"] = json!("2026-08-09T12:00:01Z");
        candidate["prev"] = json!(wist_core::delta::delta_id(&predecessor).unwrap());
        let predecessor =
            wist_core::envelope::sign_envelope(&predecessor, "delta", "k1", &key).unwrap();
        let candidate =
            wist_core::envelope::sign_envelope(&candidate, "delta", "k1", &key).unwrap();
        for doc in [&predecessor, &candidate] {
            wist_core::envelope::verify_envelope(doc, "delta", &public).unwrap();
        }
        assert_eq!(
            verify_delta_predecessor(&candidate, &predecessor),
            Err("WIST1-E07")
        );
        for invalid in [Value::Null, json!(0), json!("2026-08-09T12:00:60Z")] {
            let mut malformed = candidate["delta"].clone();
            malformed["observed_at"] = invalid;
            let malformed =
                wist_core::envelope::sign_envelope(&malformed, "delta", "k1", &key).unwrap();
            assert_eq!(
                verify_delta_predecessor(&malformed, &predecessor),
                Err("WIST1-E14")
            );
        }
    }
}

fn add(p: &TestPub, prev: Option<&str>, at: &str) -> String {
    add_delta_signed(p, URL, at, prev, at, "k1", &K1_SEED)
}

fn assert_rejected(db: &Db, data: &std::path::Path, id: &str, tip: &str) {
    assert!(!db.is_delta_seen(id).unwrap());
    assert_eq!(db.url_tip("localhost", URL).unwrap().as_deref(), Some(tip));
    assert!(!data.join(format!("payloads/{}.json", &id[7..])).exists());
    assert!(db
        .list_rejections("localhost")
        .unwrap()
        .iter()
        .any(
            |rejection| rejection.delta_id.as_deref() == Some(id) && rejection.code == "WIST1-E07"
        ));
}

#[test]
fn pending_sealed_and_recovery_predecessors_survive_restart() {
    for state in ["pending", "sealed", "recovery"] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher_with_recovery(&host);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        if state == "recovery" {
            write_feed(&p, &host, &[], "2026-08-09T11:00:00Z");
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T11:00:00Z").unwrap();
            let previous = current_declaration(&p);
            let mut owner = previous["publisher"].clone();
            owner["seq"] = json!(1);
            owner["prev_declaration"] = json!(declaration_hash(&previous));
            write_declaration(&p, &owner, "r1", &R1_SEED);
        }
        let first = add(&p, None, "2026-08-09T12:00:00.00000000000000000002Z");
        write_feed(&p, &host, std::slice::from_ref(&first), NOW);
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert!(report.rejected.is_empty(), "{state}: {report:?}");
        if state == "recovery" {
            assert_eq!(report.queued, std::slice::from_ref(&first));
        } else {
            assert_eq!(report.accepted, std::slice::from_ref(&first));
        }
        if state == "sealed" {
            clave::seal::run(
                &db,
                data.path(),
                &key,
                NOW.parse::<jiff::Timestamp>().unwrap().as_second(),
            )
            .unwrap();
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute(
                    "UPDATE records SET observed_at = '1900-01-01T00:00:00Z'",
                    [],
                )
                .unwrap();
        }
        drop(db);
        let db = Db::open(&path).unwrap();
        let invalid: Vec<_> = [
            "2026-08-09t09:00:00.000000000000000000020-03:00",
            "2026-08-09T12:00:00.00000000000000000001Z",
            "2026-08-09T11:59:59.999999999999999999999Z",
        ]
        .iter()
        .map(|at| add(&p, Some(&first), at))
        .collect();
        let valid = add(
            &p,
            Some(&first),
            "2026-08-09T12:00:00.00000000000000000003Z",
        );
        write_feed(&p, &host, &invalid, NOW);
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert_eq!(
            report.rejected,
            invalid
                .iter()
                .map(|id| (id.clone(), "WIST1-E07".into()))
                .collect::<Vec<_>>(),
            "{state}"
        );
        assert!(report.accepted.is_empty());
        assert!(report.queued.is_empty());
        for id in &invalid {
            assert_rejected(&db, data.path(), id, &first);
        }
        write_feed(&p, &host, std::slice::from_ref(&valid), NOW);
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert!(report.rejected.is_empty(), "{state}: {report:?}");
        assert_eq!(
            db.url_tip(&host, URL).unwrap().as_deref(),
            Some(valid.as_str())
        );
        if state == "recovery" {
            assert_eq!(report.queued, [valid]);
        } else {
            assert_eq!(report.accepted, [valid]);
        }
    }
}

#[test]
fn retrieved_predecessors_are_checked_before_their_descendants() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let first = add(&p, None, "2026-08-09T12:00:00Z");
    let invalid = add(&p, Some(&first), "2026-08-09T12:00:00.000Z");
    let descendant = add(&p, Some(&invalid), "2026-08-09T12:00:01Z");
    write_feed(&p, &host, std::slice::from_ref(&descendant), NOW);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&first));
    assert_eq!(
        report.rejected,
        [
            (invalid.clone(), "WIST1-E07".into()),
            (descendant.clone(), "WIST1-E07".into())
        ]
    );
    for id in [&invalid, &descendant] {
        assert_rejected(&db, data.path(), id, &first);
    }
}

#[test]
fn corrupt_history_after_the_predecessor_stops_admission() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let first = add(&p, None, "2026-08-09T12:00:00Z");
    write_feed(&p, &host, std::slice::from_ref(&first), NOW);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let at = NOW.parse::<jiff::Timestamp>().unwrap().as_second();
    clave::seal::run(&db, data.path(), &key, at).unwrap();
    clave::seal::run(&db, data.path(), &key, at + 3600).unwrap();
    let next = add(&p, Some(&first), "2026-08-09T12:00:01Z");
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&next),
        "2026-08-09T16:00:00Z",
    );
    let calls = std::cell::Cell::new(0);
    let result = clave::ingest::run_with_clock(
        &db,
        &client,
        data.path(),
        &host,
        "2026-08-09T16:00:00Z",
        || {
            calls.set(calls.get() + 1);
            std::fs::write(
                data.path().join("log/blocks/000000001.json.zst"),
                b"corrupt",
            )
            .unwrap();
            "2026-08-09T16:00:00Z".parse().unwrap()
        },
    );
    assert_eq!(calls.get(), 1);
    assert!(result.is_err());
    assert!(!db.is_delta_seen(&next).unwrap());
    assert_eq!(
        db.url_tip(&host, URL).unwrap().as_deref(),
        Some(first.as_str())
    );
    assert!(!data
        .path()
        .join(format!("payloads/{}.json", &next[7..]))
        .exists());
}

#[test]
fn an_accepted_tip_without_its_envelope_stops_the_pull() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let first = add(&p, None, "2026-08-09T12:00:00Z");
    write_feed(&p, &host, std::slice::from_ref(&first), NOW);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "DELETE FROM pending_entries WHERE entry_type = 'publisher_delta'",
            [],
        )
        .unwrap();
    let next = add(&p, Some(&first), "2026-08-09T12:00:01Z");
    write_feed(&p, &host, std::slice::from_ref(&next), NOW);
    let error = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap_err();
    assert!(error
        .to_string()
        .contains("predecessor Envelope is missing"));
    assert!(!db.is_delta_seen(&next).unwrap());
    assert!(db.is_delta_seen(&first).unwrap());
    assert_eq!(
        db.url_tip(&host, URL).unwrap().as_deref(),
        Some(first.as_str())
    );
    assert!(!data
        .path()
        .join(format!("payloads/{}.json", &next[7..]))
        .exists());
    assert!(db.list_rejections(&host).unwrap().is_empty());
}
