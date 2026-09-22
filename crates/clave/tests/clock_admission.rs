mod common;

use clave::declaration::verify_delta_clock;
use common::*;
use serde_json::{json, Value};

#[test]
fn signed_clock_vectors_preserve_the_exact_boundary() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/declaration-fields.json")).unwrap(),
    )
    .unwrap();
    let key =
        wist_core::crypto::PublicKey::from_b64u(vector["author_key"].as_str().unwrap()).unwrap();
    let mut count = 0;
    for case in vector["relation_cases"].as_array().unwrap() {
        if case["kind"] != "clock" {
            continue;
        }
        let doc = &case["envelope"];
        wist_core::envelope::verify_envelope(doc, "delta", &key).unwrap();
        let clock = case["reference"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            verify_delta_clock(doc, clock, 600)
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
fn excess_skew_cannot_enter_a_recovery_queue() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    write_feed(&p, &host, &[], "2026-08-09T11:00:00Z");
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T11:00:00Z").unwrap();
    let opening = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    clave::seal::run(&db, data.path(), &sk, opening - 3600).unwrap();
    let previous = current_declaration(&p);
    let mut recovery = previous["publisher"].clone();
    recovery["seq"] = json!(1);
    recovery["prev_declaration"] = json!(declaration_hash(&previous));
    recovery["keys"] = json!([key_entry(&K2_SEED, "2026-08-09T12:00:00Z")]);
    write_declaration(&p, &recovery, &R1_SEED);
    let accepted = add_delta_signed(
        &p,
        "https://localhost/a",
        "first",
        None,
        "2026-08-09T12:10:00Z",
        &K2_SEED,
    );
    let rejected = add_delta_signed(
        &p,
        "https://localhost/b",
        "later",
        None,
        "2026-08-09T12:10:00.000000000001Z",
        &K2_SEED,
    );
    write_feed_signed(
        &p,
        &host,
        &[accepted.clone(), rejected.clone()],
        "2026-08-09T12:00:00Z",
        &K2_SEED,
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(report.queued, std::slice::from_ref(&accepted));
    assert!(report.accepted.is_empty());
    assert_eq!(report.rejected, [(rejected.clone(), "WIST1-E06".into())]);
    assert!(!db.is_delta_seen(&rejected).unwrap());
    assert!(db
        .url_tip("localhost", "https://localhost/b")
        .unwrap()
        .is_none());
    assert!(!data
        .path()
        .join(format!("payloads/{}.json", &rejected[7..]))
        .exists());
    clave::seal::run(&db, data.path(), &sk, opening).unwrap();
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:01Z").unwrap();
    assert_eq!(report.queued, std::slice::from_ref(&rejected));
    assert!(report.rejected.is_empty());
    clave::seal::run(&db, data.path(), &sk, opening + 7 * 86_400).unwrap();
    assert_eq!(
        db.get_record("https://localhost/a", &host)
            .unwrap()
            .unwrap()
            .delta_id,
        accepted
    );
    assert_eq!(
        db.get_record("https://localhost/b", &host)
            .unwrap()
            .unwrap()
            .delta_id,
        rejected
    );
}

#[test]
fn clock_bounds_preserve_fractional_offsets_and_calendar_extremes() {
    for (clock, observed, allowance, expected) in [
        (
            "1969-12-31T23:59:59.5Z",
            "1970-01-01T00:09:59.5Z",
            600,
            Ok(()),
        ),
        (
            "1969-12-31T23:59:59.5Z",
            "1970-01-01T00:09:59.50000000000000000001Z",
            600,
            Err("WIST1-E06"),
        ),
        (
            "2026-08-09T12:00:00.123456789Z",
            "2026-08-09t09:10:00.123456789000-03:00",
            600,
            Ok(()),
        ),
        (
            "2026-08-09T12:00:00.123456789Z",
            "2026-08-09T12:10:00.123456789000000001Z",
            600,
            Err("WIST1-E06"),
        ),
        (
            "2026-08-09T12:00:00Z",
            "2026-08-09T12:00:00.00000000001Z",
            0,
            Err("WIST1-E06"),
        ),
        (
            "2026-08-09T12:00:00Z",
            "2026-08-09T12:00:00-00:00",
            0,
            Ok(()),
        ),
        (
            "2026-08-09T12:00:00.5Z",
            "2026-08-09T11:59:00.5Z",
            -60,
            Ok(()),
        ),
        (
            "2026-08-09T12:00:00.5Z",
            "2026-08-09T11:59:00.50000000001Z",
            -60,
            Err("WIST1-E06"),
        ),
        (
            "0000-01-01T00:00:00Z",
            "0000-01-01T00:00:00+23:59",
            -9_007_199_254_740_991,
            Err("WIST1-E06"),
        ),
        (
            "0000-01-01T00:00:00Z",
            "0000-01-01T00:00:00+23:59",
            0,
            Ok(()),
        ),
        (
            "9999-12-30T00:00:00Z",
            "9999-12-31T23:59:59-00:10",
            173_399,
            Ok(()),
        ),
        (
            "9999-12-30T00:00:00Z",
            "9999-12-31T23:59:59.00001-00:10",
            173_399,
            Err("WIST1-E06"),
        ),
        (
            "0000-01-01T00:00:00Z",
            "9999-12-31T23:59:59-23:59",
            9_007_199_254_740_991,
            Ok(()),
        ),
        (
            "2026-08-09T12:00:00Z",
            "2016-12-31T23:59:60Z",
            600,
            Err("WIST1-E14"),
        ),
    ] {
        let doc = json!({"delta": {"observed_at": observed}});
        assert_eq!(
            verify_delta_clock(&doc, clock.parse().unwrap(), allowance),
            expected,
            "{clock}: {observed}"
        );
    }
    let clock = "2026-08-09T12:00:00Z".parse().unwrap();
    for value in [Value::Null, json!(123), json!("not a timestamp")] {
        assert_eq!(
            verify_delta_clock(&json!({"delta": {"observed_at": value}}), clock, 600),
            Err("WIST1-E14")
        );
    }
    assert_eq!(
        verify_delta_clock(&json!({"delta": {}}), clock, 600),
        Err("WIST1-E14")
    );
    let observed = format!("2026-08-09T12:10:00.{}1Z", "0".repeat(10_000));
    assert_eq!(
        verify_delta_clock(&json!({"delta": {"observed_at": observed}}), clock, 600),
        Err("WIST1-E06")
    );
}

#[test]
fn ingest_rechecks_rejected_ids_after_restart_without_advancing_the_chain() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let url = "https://localhost/a";
    let first = add_delta_signed(&p, url, "first", None, "2026-08-09T12:10:00Z", &K1_SEED);
    let later = add_delta_signed(
        &p,
        url,
        "later",
        Some(&first),
        "2026-08-09T12:10:00.00000000000000000001Z",
        &K1_SEED,
    );
    write_feed(
        &p,
        &host,
        &[first.clone(), later.clone()],
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&first));
    assert_eq!(report.rejected, [(later.clone(), "WIST1-E06".into())]);
    assert_eq!(report.noise, None);
    assert_eq!(
        db.url_tip("localhost", url).unwrap().as_deref(),
        Some(first.as_str())
    );
    assert!(!db.is_delta_seen(&later).unwrap());
    assert!(!data
        .path()
        .join(format!("payloads/{}.json", &later[7..]))
        .exists());
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
    assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST1-E06");
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let report = clave::ingest::run_with_clock(
        &db,
        &client,
        data.path(),
        &host,
        "2026-08-09T12:00:00Z",
        || "2026-08-09T12:00:00.000000001Z".parse().unwrap(),
    )
    .unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&later));
    assert!(report.rejected.is_empty());
    assert_eq!(
        db.url_tip("localhost", url).unwrap().as_deref(),
        Some(later.as_str())
    );
    assert!(data
        .path()
        .join(format!("payloads/{}.json", &later[7..]))
        .exists());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let sealed = clave::seal::run(
        &db,
        data.path(),
        &sk,
        "2026-08-09T13:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second(),
    )
    .unwrap();
    assert_eq!(sealed.entry_count, 3);
    assert!(sealed.dropped.is_empty());
}

#[test]
fn ingest_samples_each_delta_clock_and_uses_the_parameter_effective_then() {
    for allowance in [0, -60] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        let ids: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|path| {
                add_delta_signed(
                    &p,
                    &format!("https://localhost/{path}"),
                    path,
                    None,
                    "2026-08-16T12:00:00.5Z",
                    &K1_SEED,
                )
            })
            .collect();
        write_feed(&p, &host, &ids, "2026-08-16T11:59:59Z");
        let requests = serve_recording(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        let at = "2026-08-09T12:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second();
        clave::param_change::run(
            &db,
            &sk,
            "clock_skew_seconds",
            allowance,
            Some("2026-08-16T12:00:00Z"),
            at,
        )
        .unwrap();
        assert!(clave::seal::run(&db, data.path(), &sk, at)
            .unwrap()
            .dropped
            .is_empty());
        let clocks = if allowance == 0 {
            [
                "2026-08-16T11:59:59.999999999Z",
                "2026-08-16T12:00:00.499999999Z",
                "2026-08-16T12:00:00.5Z",
            ]
        } else {
            [
                "2026-08-16T11:59:59.999999999Z",
                "2026-08-16T12:01:00.499999999Z",
                "2026-08-16T12:01:00.5Z",
            ]
        };
        let served = std::cell::RefCell::new(Vec::<String>::new());
        let report = clave::ingest::run_with_clock(
            &db,
            &client,
            data.path(),
            &host,
            "2026-08-16T11:59:59Z",
            || {
                let fetched = requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request.contains("/deltas/"))
                    .count();
                let at = clocks[fetched.saturating_sub(1).min(clocks.len() - 1)];
                let mut served = served.borrow_mut();
                if served.last().map(String::as_str) != Some(at) {
                    served.push(at.to_string());
                }
                at.parse().unwrap()
            },
        )
        .unwrap();
        assert_eq!(
            *served.borrow(),
            clocks,
            "the pull reads one clock sample per Delta, in the order the Feed lists them"
        );
        assert_eq!(report.accepted, [ids[0].clone(), ids[2].clone()]);
        assert_eq!(report.rejected, [(ids[1].clone(), "WIST1-E06".into())]);
        assert!(!db.is_delta_seen(&ids[1]).unwrap());
    }
}
