mod common;

use clave::db::BlockRow;
use clave::history::{deltas::DeltaSource, History};
use common::*;
use serde_json::{json, Value};
use wist_core::{crypto, envelope};

fn vector() -> Value {
    serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/delta-clock-time.json")).unwrap(),
    )
    .unwrap()
}

fn append(
    db: &clave::db::Db,
    data: &std::path::Path,
    head: Option<&BlockRow>,
    at: &str,
    entries: Vec<Value>,
) -> BlockRow {
    let height = head.map_or(0, |h| h.block_number + 1);
    seal_fixture_block(db, data, height, at, &entries)
}

fn genesis(db: &clave::db::Db, data: &std::path::Path, vector: &Value) -> BlockRow {
    let key = crypto::SigningKey::from_seed(&std::array::from_fn(|i| i as u8));
    let entry = wist_core::objects::PublisherKey::new(&key.public().to_b64u(), 0, None);
    let declaration = envelope::sign_envelope(
        &json!({"wist_version":"1.0.0", "domain":"example.com", "seq":0, "keys":[entry]}),
        "publisher",
        &entry.kid,
        &key,
    )
    .unwrap();
    let mut entries = vec![json!({"type":"publisher_declaration", "body":declaration})];
    let log_key = clave::keys::load(&data.join("keys/seed")).unwrap();
    for amendment in vector["amendments"].as_array().unwrap() {
        let mut doc =
            envelope::sign_envelope(&amendment["envelope"]["update"], "update", "log1", &log_key)
                .unwrap();
        if amendment["envelope"]["sig"]["value"] == crypto::b64u_encode(&[0; 64]) {
            doc["sig"]["value"] = json!(crypto::b64u_encode(&[0; 64]));
        }
        entries.push(json!({"type":"registry_update", "body":doc}));
    }
    append(
        db,
        data,
        None,
        vector["amendments"][0]["sealed_at"].as_str().unwrap(),
        entries,
    )
}

fn store(data: &std::path::Path) -> clave::db::Db {
    clave::init::run("log.example.net", data).unwrap();
    clave::db::Db::open(&data.join("clave.sqlite")).unwrap()
}

#[test]
fn signed_clock_vectors_select_authenticated_profiles_and_exact_endpoints() {
    let vector = vector();
    let data = tempfile::tempdir().unwrap();
    let db = store(data.path());
    let head = genesis(&db, data.path(), &vector);
    let mut history = History::open(&db, data.path(), Some(head)).unwrap();
    let block = history.next_block().unwrap().unwrap();
    assert_eq!(block.rejected_parameters().len(), 2);
    assert_eq!(block.clock_skew_seconds(), 600);
    assert!(history.next_block().unwrap().is_none());
    let schedule = history.schedule().unwrap();
    let key = crypto::PublicKey::from_b64u(vector["public_key"].as_str().unwrap()).unwrap();
    for probe in vector["probes"].as_array().unwrap() {
        let clock_field = match probe["stage"].as_str().unwrap() {
            "admission" => "started_at",
            "sealing" => "candidate_sealed_at",
            "historical" => "sealed_at",
            _ => unreachable!(),
        };
        let clock: jiff::Timestamp = probe[clock_field].as_str().unwrap().parse().unwrap();
        let allowance = schedule
            .value_at("clock_skew_seconds", clock.as_second())
            .unwrap();
        assert_eq!(json!(allowance), probe["expected_allowance"]);
        envelope::verify_envelope(&probe["envelope"], "delta", &key).unwrap();
        assert_eq!(
            json!(
                clave::declaration::verify_delta_clock(&probe["envelope"], clock, allowance).err()
            ),
            probe["expected"],
            "{}",
            probe["name"],
        );
    }
}

#[test]
fn historical_clock_rejections_survive_later_blocks_restart_and_repair() {
    let vector = vector();
    for probe in vector["probes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["stage"] == "historical")
    {
        let data = tempfile::tempdir().unwrap();
        let db = store(data.path());
        let first = genesis(&db, data.path(), &vector);
        let delta = &probe["envelope"];
        let id = wist_core::delta::delta_id(&delta["delta"]).unwrap();
        let head = append(
            &db,
            data.path(),
            Some(&first),
            probe["sealed_at"].as_str().unwrap(),
            vec![json!({"type":"publisher_delta", "body":delta})],
        );
        let later = append(
            &db,
            data.path(),
            Some(&head),
            probe["checked_at"].as_str().unwrap(),
            vec![],
        );
        // A key entry's `nbf` is a NumericDate, so no binding reaches an
        // instant before the epoch: such a Delta fails the WIST-1 §5.1 key
        // check whatever the clock rule makes of it.
        let before_epoch = wist_core::publisher_time::at_or_after(
            delta["delta"]["observed_at"].as_str().unwrap(),
            0,
        ) == Some(false);
        for pinned in [&head, &later, &later] {
            let result = DeltaSource::reconstruct(&db, data.path(), Some(pinned.clone()), &id);
            if before_epoch {
                let error = result.err().unwrap().to_string();
                let clock = probe["expected"].as_str().unwrap_or("WIST1-E02");
                assert!(
                    error.contains("WIST1-E02") || error.contains(clock),
                    "{}: {error}",
                    probe["name"]
                );
            } else if probe["expected"].is_null() {
                let source = result.unwrap_or_else(|e| panic!("{}: {e}", probe["name"]));
                assert_eq!(source.envelope(), delta);
                assert_eq!(
                    json!(source.clock_skew_seconds()),
                    probe["expected_allowance"]
                );
                assert_eq!(
                    source.sealed_at_s(),
                    head.sealed_at
                        .parse::<jiff::Timestamp>()
                        .unwrap()
                        .as_second()
                );
            } else {
                let error = result.err().unwrap().to_string();
                assert!(error.contains("WIST1-E06"), "{}: {error}", probe["name"]);
            }
        }
        if probe["expected"].is_null() && !before_epoch {
            let connection = rusqlite::Connection::open(data.path().join("clave.sqlite")).unwrap();
            let original: Vec<u8> = connection
                .query_row(
                    "SELECT entry_json FROM log_entries WHERE leaf_index = 0",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .execute(
                    "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = 0",
                    [br#"{"type":"label","body":{}}"#.as_slice()],
                )
                .unwrap();
            assert!(DeltaSource::reconstruct(&db, data.path(), Some(later.clone()), &id).is_err());
            connection
                .execute(
                    "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = 0",
                    [original],
                )
                .unwrap();
            DeltaSource::reconstruct(&db, data.path(), Some(later), &id).unwrap();
        }
    }
}

fn instant(at: &str) -> i64 {
    at.parse::<jiff::Timestamp>().unwrap().as_second()
}

fn reduce_allowance(db: &clave::db::Db, data: &std::path::Path) {
    let key = clave::keys::load(&data.join("keys/seed")).unwrap();
    clave::param_change::run(
        db,
        &key,
        "clock_skew_seconds",
        60,
        Some("2026-08-16T12:00:00Z"),
        instant("2026-08-09T12:00:00Z"),
    )
    .unwrap();
    clave::seal::run(db, data, &key, instant("2026-08-09T12:00:00Z")).unwrap();
}

#[test]
fn sealing_rechecks_clock_reductions_and_releases_rejected_chains_for_retry() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    reduce_allowance(&db, data.path());
    let root = add_delta_signed(
        &p,
        "https://localhost/chain",
        "root",
        None,
        "2026-08-16T12:05:00Z",
        &[1; 32],
    );
    let child = add_delta_signed(
        &p,
        "https://localhost/chain",
        "child",
        Some(&root),
        "2026-08-16T12:05:01Z",
        &[1; 32],
    );
    let boundary = add_delta_signed(
        &p,
        "https://localhost/boundary",
        "boundary",
        None,
        "2026-08-16T12:01:00Z",
        &[1; 32],
    );
    write_feed(
        &p,
        &host,
        &[root.clone(), child.clone(), boundary.clone()],
        "2026-08-16T11:59:59Z",
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-16T11:59:59Z").unwrap();
    assert_eq!(
        report.accepted,
        [root.clone(), child.clone(), boundary.clone()]
    );
    assert!(report.rejected.is_empty());
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let report = clave::seal::run(&db, data.path(), &key, instant("2026-08-16T12:00:00Z")).unwrap();
    assert!(
        report
            .dropped
            .iter()
            .any(|reason| reason.contains("WIST1-E06")),
        "{:?}",
        report.dropped
    );
    assert!(!db.is_delta_seen(&root).unwrap());
    assert!(!db.is_delta_seen(&child).unwrap());
    assert!(db
        .url_tip(&host, "https://localhost/chain")
        .unwrap()
        .is_none());
    let source =
        DeltaSource::reconstruct(&db, data.path(), db.last_block().unwrap(), &boundary).unwrap();
    assert_eq!(source.clock_skew_seconds(), 60);
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-16T12:05:00Z").unwrap();
    assert_eq!(report.accepted, [root.clone(), child.clone()]);
    assert!(report.rejected.is_empty());
    clave::seal::run(&db, data.path(), &key, instant("2026-08-16T13:00:00Z")).unwrap();
    for id in [&root, &child, &boundary] {
        DeltaSource::reconstruct(&db, data.path(), db.last_block().unwrap(), id).unwrap();
    }
}

#[test]
fn waiting_successors_keep_their_clock_while_predecessors_start_new_attempts() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let root = add_delta_signed(
        &p,
        "https://localhost/chain",
        "root",
        None,
        "2026-08-16T12:00:30Z",
        &[1; 32],
    );
    let child = add_delta_signed(
        &p,
        "https://localhost/chain",
        "child",
        Some(&root),
        "2026-08-16T12:05:00Z",
        &[1; 32],
    );
    let crossed = serve_crossing(
        listener,
        p.dir.path().into(),
        format!("deltas/{}.json", &root[7..]),
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    reduce_allowance(&db, data.path());
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&child),
        "2026-08-16T11:59:59Z",
    );
    let report = clave::ingest::run_with_clock(
        &db,
        &client,
        data.path(),
        &host,
        "2026-08-16T11:59:59Z",
        || {
            if crossed.load(std::sync::atomic::Ordering::SeqCst) {
                "2026-08-16T12:00:00Z"
            } else {
                "2026-08-16T11:59:59Z"
            }
            .parse()
            .unwrap()
        },
    )
    .unwrap();
    assert!(crossed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(report.accepted, [root, child]);
    assert!(report.rejected.is_empty());
}
