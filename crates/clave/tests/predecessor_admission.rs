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
            wist_core::envelope::sign_envelope(&predecessor, "delta", &kid(&K1_SEED), &key)
                .unwrap();
        let candidate =
            wist_core::envelope::sign_envelope(&candidate, "delta", &kid(&K1_SEED), &key).unwrap();
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
                wist_core::envelope::sign_envelope(&malformed, "delta", &kid(&K1_SEED), &key)
                    .unwrap();
            assert_eq!(
                verify_delta_predecessor(&malformed, &predecessor),
                Err("WIST1-E14")
            );
        }
    }
}

fn add(p: &TestPub, prev: Option<&str>, at: &str) -> String {
    add_delta_signed(p, URL, at, prev, at, &K1_SEED)
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
            write_declaration(&p, &owner, &R1_SEED);
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
    let requests = serve_recording(listener, p.dir.path().to_path_buf());
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
    let corruptions = std::cell::Cell::new(0);
    let result = clave::ingest::run_with_clock(
        &db,
        &client,
        data.path(),
        &host,
        "2026-08-09T16:00:00Z",
        || {
            let fetched = requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.contains("/deltas/"));
            if fetched && corruptions.get() == 0 {
                corruptions.set(1);
                rusqlite::Connection::open(data.path().join("clave.sqlite"))
                    .unwrap()
                    .execute(
                        "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = 0",
                        [br#"{"type":"label","body":{}}"#.as_slice()],
                    )
                    .unwrap();
            }
            "2026-08-09T16:00:00Z".parse().unwrap()
        },
    );
    assert_eq!(
        corruptions.get(),
        1,
        "the history is corrupted once, at the clock sample of the Delta's attempt"
    );
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
        .contains("requested Delta is absent from the pinned history"));
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

fn write_envelope(p: &TestPub, body: &Value) -> String {
    let id = wist_core::delta::delta_id(body).unwrap();
    let envelope = wist_core::envelope::sign_envelope(body, "delta", &p.kid, &p.sk).unwrap();
    std::fs::write(
        p.dir
            .path()
            .join(format!(".well-known/wist/deltas/{}.json", &id[7..])),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    id
}

#[test]
fn malformed_retrieved_predecessors_keep_field_diagnostics_despite_older_missing_links() {
    for malformed in ["timestamp", "prev", "root"] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        let first = add(&p, None, "2026-08-09T12:00:00Z");
        write_feed(&p, &host, std::slice::from_ref(&first), NOW);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert_eq!(report.accepted, std::slice::from_ref(&first));
        let mut body = json!({
            "wist_version": "1.0.0", "publisher": host, "url": URL,
            "change_type": "attest", "observed_at": "2026-08-09T12:00:01Z",
            "prev": format!("sha256:{}", "a".repeat(64)), "meta": {"lang": "en"}
        });
        match malformed {
            "timestamp" => body["observed_at"] = json!("invalid"),
            "prev" => body["prev"] = json!("sha256:invalid"),
            "root" => {
                body.as_object_mut().unwrap().remove("prev");
                body["meta"] = json!({"lang": "INVALID"});
            }
            _ => unreachable!(),
        }
        let invalid = write_envelope(&p, &body);
        let descendant = add(&p, Some(&invalid), "2026-08-09T12:00:02Z");
        write_feed(&p, &host, std::slice::from_ref(&descendant), NOW);
        for _ in 0..2 {
            let db = Db::open(&path).unwrap();
            let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
            assert_eq!(
                report.rejected,
                [
                    (invalid.clone(), "WIST1-E14".into()),
                    (descendant.clone(), "WIST1-E07".into()),
                ],
                "{malformed}"
            );
            assert!(report.accepted.is_empty() && report.queued.is_empty());
            assert!(!report.suspended);
            assert_rejected(&db, data.path(), &descendant, &first);
            assert!(!db.is_delta_seen(&invalid).unwrap());
            assert!(!data
                .path()
                .join(format!("payloads/{}.json", &invalid[7..]))
                .exists());
        }
    }
}

#[test]
fn unavailable_older_predecessor_rejects_each_fetched_descendant_and_remains_retryable() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let first = add(&p, None, "2026-08-09T12:00:00Z");
    let middle = add(&p, Some(&first), "2026-08-09T12:00:01Z");
    let last = add(&p, Some(&middle), "2026-08-09T12:00:02Z");
    let first_path = p
        .dir
        .path()
        .join(format!(".well-known/wist/deltas/{}.json", &first[7..]));
    let first_bytes = std::fs::read(&first_path).unwrap();
    std::fs::remove_file(&first_path).unwrap();
    write_feed(&p, &host, std::slice::from_ref(&last), NOW);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(
        report.rejected,
        [
            (middle.clone(), "WIST1-E07".into()),
            (last.clone(), "WIST1-E07".into()),
        ]
    );
    assert!(report.accepted.is_empty() && report.queued.is_empty());
    assert!(!report.suspended);
    assert!(db.url_tip(&host, URL).unwrap().is_none());
    for id in [&first, &middle, &last] {
        assert!(!db.is_delta_seen(id).unwrap());
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &id[7..]))
            .exists());
    }
    drop(db);
    std::fs::write(first_path, first_bytes).unwrap();
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, [first, middle, last.clone()]);
    assert!(report.rejected.is_empty());
    assert_eq!(db.url_tip(&host, URL).unwrap(), Some(last));
}

#[test]
fn retrieved_delta_keeps_its_own_url_chain_when_the_requested_relationship_is_invalid() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let first = add(&p, None, "2026-08-09T12:00:00Z");
    write_feed(&p, &host, std::slice::from_ref(&first), NOW);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&first));
    let other_url = "https://localhost/b";
    let other = add_delta_signed(
        &p,
        other_url,
        "other",
        None,
        "2026-08-09T12:00:01Z",
        &K1_SEED,
    );
    let invalid = add(&p, Some(&other), "2026-08-09T12:00:02Z");
    write_feed(&p, &host, std::slice::from_ref(&invalid), NOW);
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&other));
    assert_eq!(report.rejected, [(invalid.clone(), "WIST1-E07".into())]);
    assert_rejected(&db, data.path(), &invalid, &first);
    drop(db);
    let db = Db::open(&path).unwrap();
    assert_eq!(db.url_tip(&host, other_url).unwrap(), Some(other.clone()));
    assert!(db.is_delta_seen_for(&other, &host).unwrap());
    assert_rejected(&db, data.path(), &invalid, &first);
}

#[test]
fn predecessor_retrieval_suspends_without_rejection_and_resumes_after_restart() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let first = add(&p, None, "2026-08-09T12:00:00Z");
    let middle = add(&p, Some(&first), "2026-08-09T12:00:01Z");
    let last = add(&p, Some(&middle), "2026-08-09T12:00:02Z");
    write_feed(&p, &host, std::slice::from_ref(&last), NOW);
    let wk = p.dir.path().join(".well-known/wist");
    let budget: u64 = [
        "feed.json".into(),
        format!("deltas/{}.json", &last[7..]),
        format!("deltas/{}.json", &middle[7..]),
    ]
    .iter()
    .map(|path| std::fs::metadata(wk.join(path)).unwrap().len())
    .sum();
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    db.set_param("ingest_budget_bytes_day", budget as i64)
        .unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert!(report.suspended);
    assert!(report.rejected.is_empty() && report.accepted.is_empty() && report.queued.is_empty());
    assert!(db.url_tip(&host, URL).unwrap().is_none());
    for id in [&first, &middle, &last] {
        assert!(!db.is_delta_seen(id).unwrap());
    }
    drop(db);
    let db = Db::open(&path).unwrap();
    assert!(db.walk_suspended(&host).unwrap());
    db.set_param("ingest_budget_bytes_day", 1_000_000).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert_eq!(report.accepted, [first, middle, last.clone()]);
    assert!(report.rejected.is_empty());
    assert!(!report.suspended);
    assert!(!db.walk_suspended(&host).unwrap());
    assert_eq!(db.url_tip(&host, URL).unwrap(), Some(last));
}

fn replace_epochs(data: &std::path::Path, epochs: &[(String, Vec<Value>)]) {
    use wist_core::epoch;
    let key = clave::keys::load(&data.join("keys/seed")).unwrap();
    let anchor = clave::history::anchor(data).unwrap();
    let database = data.join("clave.sqlite");
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute_batch("DELETE FROM epochs; DELETE FROM log_entries; DELETE FROM log_tiles;")
        .unwrap();
    let head = data.join("checkpoint");
    if head.exists() {
        std::fs::remove_file(head).unwrap();
    }
    for directory in [data.join("log/checkpoints"), data.join("tile")] {
        if directory.exists() {
            std::fs::remove_dir_all(directory).unwrap();
        }
    }
    let db = Db::connect(&database).unwrap();
    for (height, (sealed_at, entries)) in epochs.iter().enumerate() {
        let mut ordered = entries.clone();
        epoch::sort_entries(&mut ordered).unwrap();
        db.commit_seal(
            &key,
            &anchor.log_id,
            &[],
            height as u64,
            sealed_at,
            &ordered,
            epoch::epoch_octets(&ordered).unwrap(),
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
    }
    clave::publication::recover(&db, data).unwrap();
}

#[test]
fn sealed_predecessors_require_authored_connected_history_before_admission() {
    use wist_core::{crypto, delta, envelope};
    for fault in [
        "ancestor_signature",
        "target_signature",
        "missing_ancestor",
        "late_signature",
        "late_fields",
        "late_version",
        "late_scope",
        "late_missing",
        "late_duplicate",
    ] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        let root = add(&p, None, "2026-08-09T12:00:00Z");
        let tip = add(&p, Some(&root), "2026-08-09T12:00:01Z");
        write_feed(&p, &host, std::slice::from_ref(&tip), NOW);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
        assert_eq!(report.accepted, [root.clone(), tip.clone()]);
        let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        let at = NOW.parse::<jiff::Timestamp>().unwrap().as_second();
        clave::seal::run(&db, data.path(), &key, at).unwrap();
        clave::seal::run(&db, data.path(), &key, at + 3600).unwrap();
        let originals: Vec<(String, Vec<Value>)> = (0..2)
            .map(|height| {
                (
                    db.epoch_at(height).unwrap().unwrap().sealed_at,
                    db.epoch_entries(height).unwrap(),
                )
            })
            .collect();
        let mut altered = originals.clone();
        let entries = &mut altered[0].1;
        let index = entries
            .iter()
            .position(|entry| {
                entry["type"] == "publisher_delta"
                    && &delta::delta_id(&entry["body"]["delta"]).unwrap()
                        == if fault == "ancestor_signature" || fault == "missing_ancestor" {
                            &root
                        } else {
                            &tip
                        }
            })
            .unwrap();
        if fault == "missing_ancestor" {
            entries.remove(index);
        } else if fault.ends_with("signature") && !fault.starts_with("late_") {
            entries[index]["body"]["sig"]["value"] = json!(crypto::b64u_encode(&[0; 64]));
        } else {
            let mut body = entries[index]["body"]["delta"].clone();
            if fault != "late_duplicate" {
                body["change_type"] = json!("new");
                body["url"] = json!("https://localhost/other");
                body["observed_at"] = json!("2026-08-09T12:00:02Z");
                body.as_object_mut().unwrap().remove("prev");
            }
            match fault {
                "late_fields" => body["meta"]["unknown"] = json!(true),
                "late_version" => body["wist_version"] = json!("2.0.0"),
                "late_scope" => body["url"] = json!("https://outside.example/page"),
                "late_missing" => {
                    body["change_type"] = json!("update");
                    body["prev"] = json!(format!("sha256:{}", "a".repeat(64)));
                }
                _ => (),
            }
            let mut doc = envelope::sign_envelope(&body, "delta", &p.kid, &p.sk).unwrap();
            if fault == "late_signature" {
                doc["sig"]["value"] = json!(crypto::b64u_encode(&[0; 64]));
            }
            altered[1].1 = vec![json!({"type":"publisher_delta", "body":doc})];
        }
        replace_epochs(data.path(), &altered);
        let mut history =
            clave::history::History::open(&db, data.path(), db.last_epoch().unwrap()).unwrap();
        while history.next_epoch().unwrap().is_some() {}
        drop(db);
        let next = add(&p, Some(&tip), "2026-08-09T12:00:03Z");
        write_feed(
            &p,
            &host,
            std::slice::from_ref(&next),
            "2026-08-09T16:00:00Z",
        );
        for _ in 0..2 {
            let db = Db::open(&path).unwrap();
            let error =
                clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T16:00:00Z")
                    .unwrap_err();
            assert!(
                error.to_string().contains("Delta history:"),
                "{fault}: {error}"
            );
            assert!(!db.is_delta_seen(&next).unwrap(), "{fault}");
            assert!(db.is_delta_seen_for(&root, &host).unwrap());
            assert!(db.is_delta_seen_for(&tip, &host).unwrap());
            assert_eq!(db.url_tip(&host, URL).unwrap(), Some(tip.clone()));
            assert!(!data
                .path()
                .join(format!("payloads/{}.json", &next[7..]))
                .exists());
            assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 0);
            assert!(db.list_rejections(&host).unwrap().is_empty());
        }
        replace_epochs(data.path(), &originals);
        let db = Db::open(&path).unwrap();
        let report =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T16:00:00Z").unwrap();
        assert_eq!(report.accepted, std::slice::from_ref(&next), "{fault}");
        assert!(report.rejected.is_empty());
        assert_eq!(db.url_tip(&host, URL).unwrap(), Some(next));
    }
}

#[test]
fn sealed_predecessor_keeps_its_historical_authority_after_rotation_and_restart() {
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
    let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let at = NOW.parse::<jiff::Timestamp>().unwrap().as_second();
    clave::seal::run(&db, data.path(), &key, at).unwrap();
    let original = current_declaration(&p);
    let mut replacement = original["publisher"].clone();
    replacement["seq"] = json!(1);
    replacement["prev_declaration"] = json!(declaration_hash(&original));
    replacement["keys"] = json!([key_entry(&K2_SEED, "2026-08-09T00:00:00Z")]);
    // Signed by the key it replaces, so the rotation preserves the identity
    // and the new key has authority at once (WIST-1 §5.2).
    write_declaration(&p, &replacement, &K1_SEED);
    write_feed_signed(&p, &host, &[], "2026-08-09T15:00:00Z", &K2_SEED);
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T15:00:00Z").unwrap();
    assert!(report.rejected.is_empty());
    clave::seal::run(&db, data.path(), &key, at + 3600).unwrap();
    drop(db);
    let next = add_delta_signed(
        &p,
        URL,
        "new key",
        Some(&first),
        "2026-08-09T15:00:01Z",
        &K2_SEED,
    );
    write_feed_signed(
        &p,
        &host,
        std::slice::from_ref(&next),
        "2026-08-09T16:00:00Z",
        &K2_SEED,
    );
    let db = Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T16:00:00Z").unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&next));
    assert!(report.rejected.is_empty());
    assert_eq!(db.url_tip(&host, URL).unwrap(), Some(next));
    let source = clave::history::deltas::DeltaSource::reconstruct(
        &db,
        data.path(),
        db.last_epoch().unwrap(),
        &first,
    )
    .unwrap();
    assert_eq!(source.declaration().envelope(), &original);
}
