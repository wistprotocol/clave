mod common;

const SEAL_START: i64 = 1_786_276_800;

use common::{
    add_attest, add_delete, add_delta, make_publisher_with_scope, reserve_addr, serve_static,
    write_feed,
};
use sha2::{Digest, Sha256};
use wist_core::objects::StateEntry;

fn sha256_hex(bytes: &[u8]) -> String {
    wist_core::crypto::hex_encode(&Sha256::digest(bytes))
}

fn record_projection(r: &clave::db::RecordRow) -> serde_json::Value {
    serde_json::json!({
        "url": r.url,
        "publisher": r.publisher,
        "delta_id": r.delta_id,
        "observed_at": r.observed_at,
    })
}

#[test]
fn snapshot_build_produces_verifiable_tier0_state_and_signed_artifacts() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/alpha", "alpha body", None);
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let report = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    assert_eq!(report.epoch_number, 0);
    assert_eq!(
        std::fs::read_dir(data.path().join("snapshots"))
            .map(|entries| entries.count())
            .unwrap_or(0),
        0,
        "sealing publishes the Checkpoint only"
    );
    let clave::snapshot::Outcome::Built {
        epoch_number,
        tree_size,
        snapshot_date,
        shards_rebuilt,
        shard_count,
        ..
    } = clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap()
    else {
        panic!("no Snapshot built");
    };
    assert_eq!(
        (
            epoch_number,
            tree_size,
            snapshot_date,
            shards_rebuilt,
            shard_count
        ),
        (
            0,
            db.last_epoch().unwrap().unwrap().tree_size,
            "2026-08-09".to_string(),
            1,
            1
        )
    );

    let head = db.last_epoch().unwrap().unwrap();
    let epoch_root = head.root.clone();

    let snapdir = data.path().join("snapshots");
    let idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(snapdir.join("index.json")).unwrap()).unwrap();
    wist_core::envelope::verify_envelope(&idx, "index", &sk.public()).unwrap();
    let snapshots = idx["index"]["snapshots"].as_array().unwrap();
    assert_eq!(snapshots.len(), 1);
    let entry = &snapshots[0];
    assert_eq!(entry["snapshot_date"], "2026-08-09");
    assert_eq!(entry["tree_size"], head.tree_size);
    assert_eq!(
        entry["manifest_url"],
        "/snapshots/2026-08-09/000000000/manifest.json"
    );

    let man_path = data.path().join(
        entry["manifest_url"]
            .as_str()
            .unwrap()
            .trim_start_matches('/'),
    );
    let man: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&man_path).unwrap()).unwrap();
    wist_core::envelope::verify_envelope(&man, "manifest", &sk.public()).unwrap();

    assert_eq!(man["manifest"]["wist_version"], "1.0.0");
    assert_eq!(man["manifest"]["snapshot_date"], "2026-08-09");
    assert_eq!(man["manifest"]["epoch_number"], 0);
    assert_eq!(man["manifest"]["tree_size"], head.tree_size);
    assert_eq!(man["manifest"]["root_hash"], epoch_root);
    assert_eq!(man["manifest"]["content_digest"], entry["content_digest"]);

    let snapshot_dir = man_path.parent().unwrap();

    let files = man["manifest"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 6, "tier 0 and the five tier-1 tables");
    for f in files {
        let path = f["path"].as_str().unwrap();
        let bytes = std::fs::read(snapshot_dir.join(path)).unwrap();
        assert_eq!(bytes.len() as u64, f["bytes"].as_u64().unwrap());
        assert_eq!(sha256_hex(&bytes), f["sha256"].as_str().unwrap());
    }
    assert_eq!(files[0]["path"], "tier0/index.sqlite");
    assert_eq!(files[0]["tier"], 0);

    let sqlite_path = snapshot_dir.join("tier0/index.sqlite");
    let conn = rusqlite::Connection::open_with_flags(
        &sqlite_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let matched_url: String = conn
        .query_row(
            "SELECT r.url FROM records_fts f JOIN records r ON f.rowid = r.rowid WHERE records_fts MATCH 'alpha'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(matched_url, "https://example.com/alpha");

    let records = db.list_records().unwrap();
    assert_eq!(records.len(), 1);
    let record_values: Vec<serde_json::Value> = records.iter().map(record_projection).collect();
    let recomputed_content_digest = wist_core::snapshot::content_digest(&record_values).unwrap();
    assert_eq!(man["manifest"]["content_digest"], recomputed_content_digest);

    let state_bytes = std::fs::read(snapshot_dir.join("state.json")).unwrap();
    assert_eq!(
        man["manifest"]["state"]["path"],
        serde_json::json!("state.json")
    );
    assert_eq!(man["manifest"]["state"]["sha256"], sha256_hex(&state_bytes));
    assert_eq!(
        man["manifest"]["state"]["bytes"].as_u64().unwrap(),
        state_bytes.len() as u64
    );

    let state_env: serde_json::Value = serde_json::from_slice(&state_bytes).unwrap();
    wist_core::envelope::verify_envelope(&state_env, "state", &sk.public()).unwrap();
    let state: wist_core::objects::SnapshotState =
        serde_json::from_value(state_env["state"].clone()).unwrap();
    assert_eq!(state.wist_version, "1.0.0");
    assert_eq!(state.tree_size, head.tree_size);

    let entry_values: Vec<serde_json::Value> = state
        .entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    let recomputed_state_digest = wist_core::snapshot::state_digest(&entry_values).unwrap();
    assert_eq!(
        man["manifest"]["state"]["state_digest"],
        recomputed_state_digest
    );

    let seed_bytes: [u8; 32] = std::fs::read(data.path().join("keys/seed"))
        .unwrap()
        .try_into()
        .unwrap();
    let expected_pubkey = clave::keys::public_b64u(&seed_bytes);

    let mut saw_key = false;
    let mut saw_declaration = false;
    let mut saw_record = false;
    for e in &state.entries {
        match e {
            StateEntry::AggregatorKey(k) => {
                saw_key = true;
                assert_eq!(k.key_id, "log1");
                assert_eq!(k.public_key, expected_pubkey);
                assert_eq!(k.added_height, 0);
                assert_eq!(k.removed_height, None);
            }
            StateEntry::Declaration(d) => {
                saw_declaration = true;
                assert_eq!(d.domain, host);
                assert!(d.declaration.get("publisher").is_some());
                assert!(d.declaration.get("sig").is_some());
                assert_eq!(d.sealing_height, 0);
            }
            StateEntry::Record(r) => {
                saw_record = true;
                assert_eq!(r.publisher, host);
                assert_eq!(r.url, "https://example.com/alpha");
                assert_eq!(r.delta_id, id1);
            }
            other => panic!("unexpected state entry in this slice: {other:?}"),
        }
    }
    assert!(saw_key && saw_declaration && saw_record);
    assert_eq!(
        state.entries.len(),
        3,
        "no parameter is amended here, and WIST-3 §7 does not restate Registry defaults"
    );
}

fn tier0_records(snapshot_dir: &std::path::Path) -> Vec<(String, String, String)> {
    let conn = rusqlite::Connection::open_with_flags(
        snapshot_dir.join("tier0/index.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut statement = conn
        .prepare("SELECT url, delta_id, observed_at FROM records ORDER BY url")
        .unwrap();
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap();
    rows.map(Result::unwrap).collect()
}

/// WIST-3 §7: an `attest` moves a record's `observed_at` and keeps its
/// anchor, a `delete` excludes the URL from every later Snapshot, and a
/// `new` naming the `delete` as `prev` brings the URL back under the new anchor.
#[test]
fn attest_and_delete_deltas_reach_the_snapshot_records() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let alpha = add_delta(&p, "https://example.com/alpha", "alpha body", None);
    let beta = add_delta(&p, "https://example.com/beta", "beta body", None);
    let mut ids = vec![alpha.clone(), beta.clone()];
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let snapshot_dir = || common::served_snapshot(data.path(), "2026-08-09");
    let manifest = || -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(snapshot_dir().join("manifest.json")).unwrap())
            .unwrap()
    };
    let digest_of = |records: &[clave::db::RecordRow]| {
        let values: Vec<serde_json::Value> = records.iter().map(record_projection).collect();
        wist_core::snapshot::content_digest(&values).unwrap()
    };

    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(report.accepted.len(), 2);
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();
    let first = manifest();
    assert_eq!(
        tier0_records(&snapshot_dir()),
        [
            (
                "https://example.com/alpha".to_string(),
                alpha.clone(),
                "2026-08-09T12:00:00Z".to_string()
            ),
            (
                "https://example.com/beta".to_string(),
                beta.clone(),
                "2026-08-09T12:00:00Z".to_string()
            ),
        ]
    );

    let attest = add_attest(&p, "https://example.com/alpha", &alpha);
    let delete = add_delete(&p, "https://example.com/beta", &beta);
    ids.extend([attest.clone(), delete.clone()]);
    write_feed(&p, &host, &ids, "2026-08-09T12:30:00Z");
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:30:00Z").unwrap();
    assert_eq!(report.accepted, [attest.clone(), delete.clone()]);
    clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();
    let second = manifest();
    assert_eq!(second["manifest"]["epoch_number"], 1);
    assert_eq!(
        tier0_records(&snapshot_dir()),
        [(
            "https://example.com/alpha".to_string(),
            alpha.clone(),
            "2026-08-09T12:00:01Z".to_string()
        )],
        "the attest keeps alpha's anchor and moves its freshness; the delete excludes beta"
    );
    let records = db.list_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(second["manifest"]["content_digest"], digest_of(&records));
    assert_ne!(
        second["manifest"]["content_digest"],
        first["manifest"]["content_digest"]
    );
    assert!(
        db.list_sealed_url_tips().unwrap().contains(&(
            host.clone(),
            "https://example.com/beta".to_string(),
            delete.clone()
        )),
        "the chain tip survives the delete"
    );

    let beta_again = add_delta(
        &p,
        "https://example.com/beta",
        "beta body again",
        Some(&delete),
    );
    ids.push(beta_again.clone());
    write_feed(&p, &host, &ids, "2026-08-09T13:30:00Z");
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T13:30:00Z").unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&beta_again));
    clave::seal::run(&db, data.path(), &sk, SEAL_START + 7200).unwrap();
    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();
    let third = manifest();
    assert_eq!(
        tier0_records(&snapshot_dir()),
        [
            (
                "https://example.com/alpha".to_string(),
                alpha,
                "2026-08-09T12:00:01Z".to_string()
            ),
            (
                "https://example.com/beta".to_string(),
                beta_again,
                "2026-08-09T12:00:02Z".to_string()
            ),
        ]
    );
    assert_eq!(
        third["manifest"]["content_digest"],
        digest_of(&db.list_records().unwrap())
    );
}

#[test]
fn an_empty_same_day_epoch_gets_its_own_directory_and_leaves_the_first_byte_identical() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/alpha", "alpha body", None);
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let db_path = data.path().join("clave.sqlite");
    let first_dir = data.path().join("snapshots/2026-08-09/000000000");
    let second_dir = data.path().join("snapshots/2026-08-09/000000001");
    let manifest = |dir: &std::path::Path| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap()
    };
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    clave::snapshot::produce(&db_path, data.path()).unwrap();
    let first_files = common::tree_bytes(&first_dir);
    let first = manifest(&first_dir);
    let r1 = clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    assert_eq!(r1.epoch_number, 1);
    assert_eq!(r1.entry_count, 0);
    assert!(matches!(
        clave::snapshot::produce(&db_path, data.path()).unwrap(),
        clave::snapshot::Outcome::Built {
            epoch_number: 1,
            ..
        }
    ));
    let second = manifest(&second_dir);
    assert_eq!(common::tree_bytes(&first_dir), first_files);
    assert_eq!(second["manifest"]["epoch_number"], 1);
    assert_eq!(first["manifest"]["epoch_number"], 0);
    assert_eq!(
        second["manifest"]["content_digest"],
        first["manifest"]["content_digest"]
    );

    let idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data.path().join("snapshots/index.json")).unwrap())
            .unwrap();
    wist_core::envelope::verify_envelope(&idx, "index", &sk.public()).unwrap();
    let snapshots = idx["index"]["snapshots"].as_array().unwrap();
    let urls: Vec<&str> = snapshots
        .iter()
        .map(|entry| entry["manifest_url"].as_str().unwrap())
        .collect();
    assert_eq!(
        urls,
        vec![
            "/snapshots/2026-08-09/000000001/manifest.json",
            "/snapshots/2026-08-09/000000000/manifest.json",
        ]
    );
    assert_eq!(
        snapshots[0]["tree_size"],
        db.last_epoch().unwrap().unwrap().tree_size
    );
}

fn tier1_fixture(shards: Option<i64>) -> (common::TestPub, tempfile::TempDir, String, String) {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = common::add_delta_with_links(
        &p,
        "https://example.com/linked",
        "extract text here",
        None,
        &["https://other.example/x", "https://another.example/y"],
    );
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    if let Some(n) = shards {
        db.set_param("snapshot_shard_count", n).unwrap();
    }
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();
    (p, data, host, id)
}

fn read_parquet_rows(path: &std::path::Path) -> Vec<Vec<String>> {
    use parquet::file::reader::{FileReader, SerializedFileReader};
    let file = std::fs::File::open(path).unwrap();
    let reader = SerializedFileReader::new(file).unwrap();
    reader
        .get_row_iter(None)
        .unwrap()
        .map(|row| {
            row.unwrap()
                .get_column_iter()
                .map(|(_, v)| match v {
                    parquet::record::Field::Str(s) => s.clone(),
                    other => format!("{other}"),
                })
                .collect()
        })
        .collect()
}

#[test]
fn snapshot_includes_tier1_extracts_and_link_graph() {
    let (_p, data, host, id) = tier1_fixture(None);
    let dir = common::served_snapshot(data.path(), "2026-08-09");

    let extracts = read_parquet_rows(&dir.join("tier1/extracts.parquet"));
    assert_eq!(
        extracts,
        vec![vec![
            "https://example.com/linked".to_string(),
            host.clone(),
            id.clone(),
            "extract text here".to_string(),
        ]]
    );

    let links = read_parquet_rows(&dir.join("tier1/links.parquet"));
    assert_eq!(
        links,
        vec![
            vec![
                "https://example.com/linked".to_string(),
                "https://other.example/x".to_string(),
                "0".to_string(),
            ],
            vec![
                "https://example.com/linked".to_string(),
                "https://another.example/y".to_string(),
                "1".to_string(),
            ],
        ]
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let files = manifest["manifest"]["files"].as_array().unwrap();
    for path in ["tier1/extracts.parquet", "tier1/links.parquet"] {
        let entry = files.iter().find(|f| f["path"] == path).unwrap();
        assert_eq!(entry["tier"], 1);
        let bytes = std::fs::read(dir.join(path)).unwrap();
        assert_eq!(entry["bytes"].as_u64().unwrap(), bytes.len() as u64);
        assert_eq!(entry["sha256"].as_str().unwrap(), sha256_hex(&bytes));
    }
    assert!(manifest["manifest"]["shards"].is_null());
}

#[test]
fn sharded_snapshot_declares_count_digests_and_shard_labels() {
    let (_p, data, host, _id) = tier1_fixture(Some(2));
    let dir = common::served_snapshot(data.path(), "2026-08-09");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let m = &manifest["manifest"];
    assert_eq!(m["shards"]["count"], 2);
    assert_eq!(m["shards"]["digests"].as_array().unwrap().len(), 2);

    let digest_bytes = Sha256::digest(host.as_bytes());
    let expected_shard = u64::from_be_bytes(digest_bytes[..8].try_into().unwrap()) % 2;
    let files = m["files"].as_array().unwrap();
    assert_eq!(files.len(), 12, "six files per shard, both shards emitted");
    for f in files {
        let shard = f["shard"].as_u64().unwrap();
        assert!(shard < 2);
        assert!(f["path"]
            .as_str()
            .unwrap()
            .starts_with(&format!("shard-{shard}/")));
    }
    let count_rows = |shard: u64| -> i64 {
        let conn =
            rusqlite::Connection::open(dir.join(format!("shard-{shard}/tier0/index.sqlite")))
                .unwrap();
        conn.query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(count_rows(expected_shard), 1);
    assert_eq!(count_rows(1 - expected_shard), 0);
    let extracts =
        read_parquet_rows(&dir.join(format!("shard-{expected_shard}/tier1/extracts.parquet")));
    assert_eq!(extracts.len(), 1);
}

#[test]
fn the_state_artifact_carries_every_kind_with_live_instances() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let live = add_delta(&p, "https://example.com/live", "alpha body", None);
    let doomed = add_delta(&p, "https://example.com/gone", "beta body", None);
    write_feed(
        &p,
        &host,
        &[live.clone(), doomed.clone()],
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();

    clave::governance::withdraw(
        &db,
        &sk,
        &host,
        &doomed,
        "court order",
        "DE",
        SEAL_START + 1,
    )
    .unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();

    clave::seal::run(&db, data.path(), &sk, SEAL_START + 7200).unwrap();
    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();
    let date = &jiff::Timestamp::from_second(SEAL_START + 7200)
        .unwrap()
        .to_string()[..10];
    let state_env: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::served_snapshot(data.path(), date).join("state.json")).unwrap(),
    )
    .unwrap();
    let state: wist_core::objects::SnapshotState =
        serde_json::from_value(state_env["state"].clone()).unwrap();

    assert!(
        state.entries.iter().any(
            |e| matches!(e, StateEntry::Withdrawal(w) if w.delta_id == doomed && w.publisher == host && w.sealing_height == 1)
        ),
        "no withdrawal tuple"
    );
    assert!(
        state.entries.iter().any(
            |e| matches!(e, StateEntry::Declaration(d) if d.domain == host && d.sealing_height > 0
                || matches!(e, StateEntry::Declaration(d) if d.domain == host))
        ),
        "no declaration tuple"
    );
    let tips: Vec<&str> = state
        .entries
        .iter()
        .filter_map(|e| match e {
            StateEntry::Record(r) => Some(r.url.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        tips.contains(&"https://example.com/gone"),
        "a withdrawn URL keeps its chain tip; tips {tips:?}"
    );
    assert!(db
        .get_record("https://example.com/gone", &host)
        .unwrap()
        .is_none());
}

fn record_tips(data: &std::path::Path, at: i64) -> Vec<(String, String)> {
    let date = &jiff::Timestamp::from_second(at).unwrap().to_string()[..10];
    let state_env: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::served_snapshot(data, date).join("state.json")).unwrap(),
    )
    .unwrap();
    let state: wist_core::objects::SnapshotState =
        serde_json::from_value(state_env["state"].clone()).unwrap();
    state
        .entries
        .iter()
        .filter_map(|e| match e {
            StateEntry::Record(r) => Some((r.url.clone(), r.delta_id.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn a_snapshot_names_the_sealed_chain_tip_not_the_admitted_one() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let url = "https://example.com/page";
    let unsealed_url = "https://example.com/unsealed";
    let first = add_delta(&p, url, "first body", None);
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&first),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();

    let second = add_delta(&p, url, "second body", Some(&first));
    let orphan = add_delta(&p, unsealed_url, "unsealed body", None);
    write_feed(
        &p,
        &host,
        &[first.clone(), second.clone(), orphan.clone()],
        "2026-08-09T13:00:00Z",
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T13:00:00Z").unwrap();
    assert!(report.accepted.contains(&second), "{report:?}");
    assert!(report.accepted.contains(&orphan), "{report:?}");
    assert_eq!(db.url_tip(&host, url).unwrap(), Some(second.clone()));
    assert_eq!(
        db.url_tip(&host, unsealed_url).unwrap(),
        Some(orphan.clone())
    );

    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();
    let tips = record_tips(data.path(), SEAL_START);
    assert_eq!(tips, vec![(url.to_string(), first.clone())]);

    clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    clave::snapshot::produce(&data.path().join("clave.sqlite"), data.path()).unwrap();
    let tips = record_tips(data.path(), SEAL_START + 3600);
    assert!(tips.contains(&(url.to_string(), second)), "{tips:?}");
    assert!(
        tips.contains(&(unsealed_url.to_string(), orphan)),
        "{tips:?}"
    );
    assert_eq!(tips.len(), 2, "{tips:?}");
}
