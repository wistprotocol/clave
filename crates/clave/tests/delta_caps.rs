mod common;

use clave::db::{BlockRow, Db};
use clave::declaration::delta::SizeCaps;
use clave::history::History;
use common::*;
use serde_json::{json, Value};
use wist_core::{block, crypto::SigningKey, envelope, jcs};

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/delta-cap-time.json")).unwrap(),
    )
    .unwrap()
}

fn timestamp(at: &str) -> i64 {
    at.parse::<jiff::Timestamp>().unwrap().as_second()
}

fn write_blocks(data: &std::path::Path, blocks: &[Value]) -> BlockRow {
    std::fs::create_dir_all(data.join("log/blocks")).unwrap();
    for doc in blocks {
        let height = doc["header"]["block_number"].as_u64().unwrap();
        std::fs::write(
            data.join(format!("log/blocks/{height:09}.json.zst")),
            zstd::bulk::compress(&jcs::canonicalize(doc).unwrap(), 1).unwrap(),
        )
        .unwrap();
    }
    let last = blocks.last().unwrap();
    BlockRow {
        block_number: last["header"]["block_number"].as_u64().unwrap(),
        block_hash: block::block_hash(&last["header"]).unwrap(),
        sealed_at: last["header"]["sealed_at"].as_str().unwrap().into(),
    }
}

fn anchor(data: &std::path::Path) {
    let key = SigningKey::from_seed(&std::array::from_fn(|i| i as u8));
    let body = json!({"wist_version":"1.0.0", "log_id":"log.example.net", "genesis_key":{"key_id":"test-log-k1", "alg":"Ed25519", "public_key":key.public().to_b64u()}, "created_at":"2026-08-02T00:00:00Z"});
    let doc = envelope::sign_envelope(&body, "anchor", "test-log-k1", &key).unwrap();
    std::fs::write(data.join("anchor.json"), jcs::canonicalize(&doc).unwrap()).unwrap();
}

#[test]
fn signed_cap_profiles_follow_authenticated_prefixes_and_survive_later_amendments() {
    let vector = fixture();
    let data = tempfile::tempdir().unwrap();
    anchor(data.path());
    let blocks = vector["blocks"].as_array().unwrap();
    let head = write_blocks(data.path(), blocks);
    assert_eq!(head.block_hash, vector["pinned_head"]);
    let mut history = History::open(data.path(), Some(head)).unwrap();
    let mut schedules = Vec::new();
    let mut profiles = Vec::new();
    while let Some(block) = history.next_block().unwrap() {
        assert!(block.rejected_parameters().is_empty());
        profiles.push(block.delta_size_caps().clone());
        schedules.push(history.schedule().unwrap().clone());
    }
    for probe in vector["probes"].as_array().unwrap() {
        let object = &vector["objects"][probe["object"].as_str().unwrap()];
        let caps = match probe["stage"].as_str().unwrap() {
            "admission" => SizeCaps::from_schedule(
                &schedules[probe["prefix_height"].as_u64().unwrap() as usize],
                timestamp(probe["started_at"].as_str().unwrap()),
            ),
            "sealing" => {
                let height = probe["candidate_height"].as_u64().unwrap() as usize;
                SizeCaps::from_schedule(
                    &schedules[height - 1],
                    timestamp(blocks[height]["header"]["sealed_at"].as_str().unwrap()),
                )
            }
            "historical" => profiles[object["sealed_height"].as_u64().unwrap() as usize].clone(),
            stage => panic!("unknown stage {stage}"),
        };
        assert_eq!(json!(caps), probe["expected_profile"], "{}", probe["name"]);
        let delta = caps.validate_delta(&object["envelope"]);
        assert_eq!(
            json!(delta.err()),
            probe["expected_delta"],
            "{}",
            probe["name"]
        );
        let result = delta.and_then(|()| caps.validate_payload_sizes(&object["payload"]));
        assert_eq!(json!(result.err()), probe["expected"], "{}", probe["name"]);
    }
    for case in vector["invalid_blocks"].as_array().unwrap() {
        let doc = &case["block"];
        let height = doc["header"]["block_number"].as_u64().unwrap() as usize;
        let head = write_blocks(data.path(), std::slice::from_ref(doc));
        let mut history = History::open(data.path(), Some(head)).unwrap();
        let candidate = loop {
            let block = history.next_block().unwrap().unwrap();
            if block.block().header.block_number == height as u64 {
                break block;
            }
        };
        let caps = candidate.delta_size_caps();
        let result = caps
            .validate_delta(&doc["entries"][0]["body"])
            .and_then(|()| caps.validate_payload_sizes(&case["payload"]));
        assert_eq!(json!(result.err()), case["expected"], "{}", case["name"]);
        write_blocks(data.path(), std::slice::from_ref(&blocks[height]));
    }
}

#[test]
fn historical_payload_sources_keep_the_committing_profile_after_restart() {
    use clave::history::payloads::PayloadSource;

    let vector = fixture();
    let data = tempfile::tempdir().unwrap();
    anchor(data.path());
    let head = write_blocks(data.path(), vector["blocks"].as_array().unwrap());
    std::fs::create_dir_all(data.path().join("payloads")).unwrap();
    let (listener, host, client) = reserve_addr();
    serve_static(listener, data.path().to_owned());
    std::fs::write(
        data.path().join("log/mirrors.json"),
        serde_json::to_vec(&json!({"mirrors":{"mirror_urls":[format!("http://{host}/")]}}))
            .unwrap(),
    )
    .unwrap();
    for probe in vector["probes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|probe| probe["stage"] == "historical" && probe["expected_delta"].is_null())
    {
        let object = &vector["objects"][probe["object"].as_str().unwrap()];
        let id = wist_core::delta::delta_id(&object["envelope"]["delta"]).unwrap();
        let raw = serde_json::to_vec(&object["payload"]).unwrap();
        let name = format!("payloads/{}.json", &id[7..]);
        std::fs::write(data.path().join(&name), &raw).unwrap();
        for _ in 0..2 {
            let source = PayloadSource::reconstruct(data.path(), Some(head.clone()), &id).unwrap();
            assert_eq!(source.envelope(), &object["envelope"]);
            assert_eq!(json!(source.block_number()), object["sealed_height"]);
            assert_eq!(json!(source.size_caps()), probe["expected_profile"]);
            assert_eq!(json!(source.validate(&raw).err()), probe["expected"]);
            let discovered = source.discover(
                &client,
                &data.path().join("missing"),
                &[format!("http://{host}/")],
            );
            assert!(discovered.discovery_failures().is_empty());
            let remote = source.discover_with_remote_mirrors(
                &client,
                &data.path().join("missing"),
                &[],
                &[format!("http://{host}/")],
            );
            assert!(remote.discovery_failures().is_empty());
            assert_eq!(remote.locations(), discovered.locations());
            for result in [
                source.read(data.path()),
                source.fetch(&client, &format!("http://{host}/{name}")),
                source
                    .retrieve(&client, discovered.locations().iter().take(2).cloned())
                    .map_err(|failure| {
                        assert_eq!(failure.attempts.len(), 2);
                        assert!(matches!(failure.attempts[0].error, clave::Error::Io(_)));
                        failure.attempts.into_iter().last().unwrap().error
                    }),
                source
                    .retrieve(&client, remote.locations().iter().take(2).cloned())
                    .map_err(|failure| {
                        assert_eq!(failure.attempts.len(), 2);
                        assert!(matches!(failure.attempts[0].error, clave::Error::Io(_)));
                        failure.attempts.into_iter().last().unwrap().error
                    }),
            ] {
                let code = match result {
                    Ok(copy) => {
                        assert_eq!(copy.raw(), raw);
                        assert_eq!(json!(copy.source().size_caps()), probe["expected_profile"]);
                        None
                    }
                    Err(clave::Error::Payload(code)) => Some(code),
                    Err(error) => panic!("{error}"),
                };
                assert_eq!(json!(code), probe["expected"]);
            }
        }
    }
    for case in vector["invalid_blocks"].as_array().unwrap() {
        let doc = &case["block"];
        let height = doc["header"]["block_number"].as_u64().unwrap() as usize;
        let head = write_blocks(data.path(), std::slice::from_ref(doc));
        let id = wist_core::delta::delta_id(&doc["entries"][0]["body"]["delta"]).unwrap();
        let error = match PayloadSource::reconstruct(data.path(), Some(head), &id) {
            Ok(source) => source
                .validate(&serde_json::to_vec(&case["payload"]).unwrap())
                .err()
                .unwrap()
                .to_string(),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(case["expected"].as_str().unwrap()),
            "{}: {error}",
            case["name"]
        );
        write_blocks(data.path(), std::slice::from_ref(&vector["blocks"][height]));
    }
}

fn amend(db: &Db, data: &std::path::Path, parameter: &str, value: i64) {
    let sk = clave::keys::load(&data.join("keys/seed")).unwrap();
    clave::param_change::run(
        db,
        &sk,
        parameter,
        value,
        Some("2026-08-16T12:00:00Z"),
        timestamp("2026-08-09T12:00:00Z"),
    )
    .unwrap();
    clave::seal::run(db, data, &sk, timestamp("2026-08-09T12:00:00Z")).unwrap();
}

#[test]
fn payload_cap_rechecks_reject_successors_atomically_and_allow_a_new_attempt() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    amend(&db, data.path(), "extract_cap_bytes", 32);
    let url = "https://localhost/large";
    let first = add_delta(&p, url, &"x".repeat(31), None);
    let successor = add_delta(&p, url, "small", Some(&first));
    let boundary = add_delta(&p, "https://localhost/boundary", &"x".repeat(30), None);
    write_feed(
        &p,
        &host,
        &[first.clone(), successor.clone(), boundary.clone()],
        "2026-08-16T11:59:59Z",
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-16T11:59:59Z").unwrap();
    assert_eq!(
        report.accepted,
        [first.clone(), successor.clone(), boundary.clone()]
    );
    drop(db);
    let db = Db::open(&path).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE param_changes SET value = 65536 WHERE parameter = 'extract_cap_bytes'",
            [],
        )
        .unwrap();
    db.set_param("extract_cap_bytes", 65536).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let report =
        clave::seal::run(&db, data.path(), &sk, timestamp("2026-08-16T12:00:00Z")).unwrap();
    assert!(report
        .dropped
        .iter()
        .any(|s| s.contains(&first) && s.contains("WIST1-E04")));
    assert!(report
        .dropped
        .iter()
        .any(|s| s.contains(&successor) && s.contains("WIST1-E07")));
    assert_eq!(db.url_tip(&host, url).unwrap(), None);
    assert!(!db.is_delta_seen(&first).unwrap());
    assert!(!db.is_delta_seen(&successor).unwrap());
    assert!(db.is_delta_seen(&boundary).unwrap());
    drop(db);
    let db = Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-16T12:00:00Z").unwrap();
    assert!(report.rejected.contains(&(first, "WIST2-E03".into())));
    assert!(report.rejected.contains(&(successor, "WIST1-E07".into())));
}

#[test]
fn predecessor_attempts_get_new_caps_while_waiting_successors_retain_theirs() {
    for oversized_predecessor in [false, true] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        let url = "https://localhost/chain";
        let parent = add_delta(
            &p,
            url,
            if oversized_predecessor {
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            } else {
                "small"
            },
            None,
        );
        let child = add_delta(&p, url, &"x".repeat(31), Some(&parent));
        let crossed = serve_crossing(
            listener,
            p.dir.path().to_path_buf(),
            format!("deltas/{}.json", &parent[7..]),
        );
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
        amend(&db, data.path(), "extract_cap_bytes", 32);
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
        if oversized_predecessor {
            assert!(report.accepted.is_empty());
            assert_eq!(
                report.rejected,
                [(parent, "WIST2-E03".into()), (child, "WIST1-E07".into())]
            );
        } else {
            assert_eq!(report.accepted, [parent, child]);
            assert!(report.rejected.is_empty());
        }
    }
}

#[test]
fn rejected_payload_attempts_do_not_freeze_caps_for_repeated_page_ids() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let id = add_delta(&p, "https://localhost/large", &"x".repeat(32767), None);
    let crossed = serve_crossing(
        listener,
        p.dir.path().to_path_buf(),
        format!("payloads/{}.json", &id[7..]),
    );
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    amend(&db, data.path(), "extract_cap_bytes", 65536);
    write_feed_page(
        &p,
        &host,
        0,
        std::slice::from_ref(&id),
        "2026-08-09T12:00:00Z",
        None,
    );
    write_feed_with_next(
        &p,
        &host,
        std::slice::from_ref(&id),
        "2026-08-16T11:59:59Z",
        Some("https://localhost/.well-known/wist/feed/0.json"),
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
    assert_eq!(report.rejected, [(id.clone(), "WIST2-E03".into())]);
    assert_eq!(report.accepted, [id]);
}

#[test]
fn missing_or_corrupt_retained_payload_rolls_back_sealing() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    let id = add_delta(&p, "https://localhost/a", "body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let payload = data.path().join(format!("payloads/{}.json", &id[7..]));
    let bytes = std::fs::read(&payload).unwrap();
    std::fs::remove_file(&payload).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    for corrupt in [false, true] {
        if corrupt {
            std::fs::write(&payload, b"corrupt").unwrap();
        }
        assert!(
            clave::seal::run(&db, data.path(), &sk, timestamp("2026-08-09T12:00:00Z")).is_err()
        );
        assert!(db.last_block().unwrap().is_none());
        assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);
        assert!(db.is_delta_seen(&id).unwrap());
        assert!(db.list_rejections(&host).unwrap().is_empty());
    }
    drop(db);
    let db = Db::open(&path).unwrap();
    std::fs::write(payload, bytes).unwrap();
    clave::seal::run(&db, data.path(), &sk, timestamp("2026-08-09T12:00:00Z")).unwrap();
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 0);
}

#[test]
fn index_restoration_uses_signed_block_caps_and_rejects_oversized_history_atomically() {
    let vector = fixture();
    for invalid in [false, true] {
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example.net", data.path()).unwrap();
        anchor(data.path());
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let mut blocks = vector["blocks"].as_array().unwrap().clone();
        if invalid {
            let candidate = &vector["invalid_blocks"][0]["block"];
            blocks.truncate(candidate["header"]["block_number"].as_u64().unwrap() as usize);
            blocks.push(candidate.clone());
        }
        write_blocks(data.path(), &blocks);
        for doc in &blocks {
            db.commit_seal(
                &[],
                doc["header"]["block_number"].as_u64().unwrap(),
                &block::block_hash(&doc["header"]).unwrap(),
                doc["header"]["sealed_at"].as_str().unwrap(),
                &[],
                &[],
                &[],
                &[],
                jcs::canonicalize(doc).unwrap().len() as u64,
            )
            .unwrap();
        }
        db.set_param("url_cap_bytes", 9000).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("DELETE FROM delta_index_reconciliation;")
            .unwrap();
        drop(db);
        let restored = Db::open(&path);
        if invalid {
            assert!(restored.err().unwrap().to_string().contains("WIST1-E11"));
            assert_eq!(
                connection
                    .query_row("SELECT count(*) FROM delta_index_reconciliation", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                connection
                    .query_row("SELECT count(*) FROM seen_deltas", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        } else {
            let restored = restored.unwrap();
            for object in vector["objects"].as_object().unwrap().values() {
                assert!(restored
                    .is_delta_seen(object["id"].as_str().unwrap())
                    .unwrap());
            }
        }
    }
}
