mod common;

use clave::db::BlockRow;
use clave::history::{deltas::DeltaSource, History};
use common::*;
use serde_json::{json, Value};
use wist_core::{block, crypto, envelope, jcs, merkle};

fn vector() -> Value {
    serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/delta-clock-time.json")).unwrap(),
    )
    .unwrap()
}

fn append(
    data: &std::path::Path,
    head: Option<&BlockRow>,
    at: &str,
    mut entries: Vec<Value>,
) -> BlockRow {
    entries.sort_by_key(|entry| {
        (
            match entry["type"].as_str().unwrap() {
                "publisher_declaration" => 0,
                "registry_update" => 1,
                "publisher_delta" => 2,
                _ => 3,
            },
            merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()),
        )
    });
    let hashes: Vec<_> = entries
        .iter()
        .map(|entry| merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()))
        .collect();
    let root = if hashes.is_empty() {
        merkle::leaf_hash(&[])
    } else {
        merkle::merkle_root(&hashes).unwrap()
    };
    let height = head.map_or(0, |h| h.block_number + 1);
    let header = json!({"wist_version":"1.0.0", "block_number":height,
        "prev_block_hash":head.map_or("sha256:genesis", |h| h.block_hash.as_str()),
        "sealed_at":at, "entry_count":entries.len(),
        "merkle_root":format!("sha256:{}", crypto::hex_encode(&root))});
    let key = clave::keys::load(&data.join("keys/seed")).unwrap();
    let mut doc = envelope::sign_envelope(&header, "header", "log1", &key).unwrap();
    doc["entries"] = json!(entries);
    std::fs::write(
        data.join(format!("log/blocks/{height:09}.json.zst")),
        zstd::bulk::compress(&jcs::canonicalize(&doc).unwrap(), 1).unwrap(),
    )
    .unwrap();
    BlockRow {
        block_number: height,
        block_hash: block::block_hash(&header).unwrap(),
        sealed_at: at.into(),
    }
}

fn genesis(data: &std::path::Path, vector: &Value) -> BlockRow {
    clave::init::run("log.example.net", data).unwrap();
    let key = crypto::SigningKey::from_seed(&std::array::from_fn(|i| i as u8));
    let declaration = envelope::sign_envelope(
        &json!({"wist_version":"1.0.0", "domain":"example.com", "seq":0,
            "keys":[{"key_id":"test-k1", "alg":"Ed25519", "public_key":key.public().to_b64u(),
                "valid_from":"0000-01-01T00:00:00+23:59"}]}),
        "publisher",
        "test-k1",
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
        data,
        None,
        vector["amendments"][0]["sealed_at"].as_str().unwrap(),
        entries,
    )
}

#[test]
fn signed_clock_vectors_select_authenticated_profiles_and_exact_endpoints() {
    let vector = vector();
    let data = tempfile::tempdir().unwrap();
    let head = genesis(data.path(), &vector);
    let mut history = History::open(data.path(), Some(head)).unwrap();
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
        let first = genesis(data.path(), &vector);
        let delta = &probe["envelope"];
        let id = wist_core::delta::delta_id(&delta["delta"]).unwrap();
        let head = append(
            data.path(),
            Some(&first),
            probe["sealed_at"].as_str().unwrap(),
            vec![json!({"type":"publisher_delta", "body":delta})],
        );
        let later = append(
            data.path(),
            Some(&head),
            probe["checked_at"].as_str().unwrap(),
            vec![],
        );
        for pinned in [&head, &later, &later] {
            let result = DeltaSource::reconstruct(data.path(), Some(pinned.clone()), &id);
            if probe["expected"].is_null() {
                let source = result.unwrap();
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
        if probe["expected"].is_null() {
            let path = data.path().join("log/blocks/000000001.json.zst");
            let original = std::fs::read(&path).unwrap();
            std::fs::write(&path, b"corrupt").unwrap();
            assert!(DeltaSource::reconstruct(data.path(), Some(later.clone()), &id).is_err());
            std::fs::write(&path, original).unwrap();
            DeltaSource::reconstruct(data.path(), Some(later), &id).unwrap();
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
        "k1",
        &[1; 32],
    );
    let child = add_delta_signed(
        &p,
        "https://localhost/chain",
        "child",
        Some(&root),
        "2026-08-16T12:05:01Z",
        "k1",
        &[1; 32],
    );
    let boundary = add_delta_signed(
        &p,
        "https://localhost/boundary",
        "boundary",
        None,
        "2026-08-16T12:01:00Z",
        "k1",
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
        DeltaSource::reconstruct(data.path(), db.last_block().unwrap(), &boundary).unwrap();
    assert_eq!(source.clock_skew_seconds(), 60);
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-16T12:05:00Z").unwrap();
    assert_eq!(report.accepted, [root.clone(), child.clone()]);
    assert!(report.rejected.is_empty());
    clave::seal::run(&db, data.path(), &key, instant("2026-08-16T13:00:00Z")).unwrap();
    for id in [&root, &child, &boundary] {
        DeltaSource::reconstruct(data.path(), db.last_block().unwrap(), id).unwrap();
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
        "k1",
        &[1; 32],
    );
    let child = add_delta_signed(
        &p,
        "https://localhost/chain",
        "child",
        Some(&root),
        "2026-08-16T12:05:00Z",
        "k1",
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
