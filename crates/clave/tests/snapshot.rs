mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};
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
        "weight": r.weight,
    })
}

#[test]
fn snapshot_build_produces_verifiable_tier0_state_and_signed_artifacts() {
    let (listener, host) = reserve_addr();
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
    db.set_param("block_cadence_seconds", 1).unwrap();
    let client = clave::fetch::Client::new(true);
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let report = clave::seal::run(&db, data.path(), &sk, 1_754_740_800).unwrap();
    assert_eq!(report.block_number, 0);

    let raw = std::fs::read(data.path().join("log/blocks/000000000.json.zst")).unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
    let block_hash = wist_core::block::block_hash(&block["header"]).unwrap();

    let snapdir = data.path().join("snapshots");
    let idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(snapdir.join("index.json")).unwrap()).unwrap();
    wist_core::envelope::verify_envelope(&idx, "index", &sk.public()).unwrap();
    let snapshots = idx["index"]["snapshots"].as_array().unwrap();
    assert_eq!(snapshots.len(), 1);
    let entry = &snapshots[0];
    assert_eq!(entry["snapshot_date"], "2025-08-09");
    assert_eq!(entry["log_position"], 0);
    assert_eq!(entry["manifest_url"], "/snapshots/2025-08-09/manifest.json");

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
    assert_eq!(man["manifest"]["snapshot_date"], "2025-08-09");
    assert_eq!(man["manifest"]["log_position"], 0);
    assert_eq!(man["manifest"]["anchor_block_hash"], block_hash);
    assert_eq!(man["manifest"]["content_digest"], entry["content_digest"]);

    let snapshot_dir = man_path.parent().unwrap();

    let files = man["manifest"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
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
    assert_eq!(state.log_position, 0);

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
    let mut saw_param = false;
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
            StateEntry::Parameter(pa) => {
                saw_param = true;
                assert_eq!(pa.name, "block_cadence_seconds");
                assert_eq!(pa.value, 1);
                assert_eq!(pa.effective_height, 0);
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
    assert!(saw_key && saw_param && saw_declaration && saw_record);
    assert_eq!(state.entries.len(), 4);
}

#[test]
fn snapshot_index_replaces_same_date_entry_on_reseal() {
    let (listener, host) = reserve_addr();
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
    db.set_param("block_cadence_seconds", 1).unwrap();
    let client = clave::fetch::Client::new(true);
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, 1_754_740_800).unwrap();
    let r1 = clave::seal::run(&db, data.path(), &sk, 1_754_740_801).unwrap();
    assert_eq!(r1.block_number, 1);

    let idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data.path().join("snapshots/index.json")).unwrap())
            .unwrap();
    wist_core::envelope::verify_envelope(&idx, "index", &sk.public()).unwrap();
    let snapshots = idx["index"]["snapshots"].as_array().unwrap();
    assert_eq!(
        snapshots.len(),
        1,
        "same-day reseal must replace, not duplicate, the index entry"
    );
    assert_eq!(snapshots[0]["snapshot_date"], "2025-08-09");
    assert_eq!(snapshots[0]["log_position"], 1);
}

fn tier1_fixture(shards: Option<i64>) -> (common::TestPub, tempfile::TempDir, String, String) {
    let (listener, host) = reserve_addr();
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
    db.set_param("block_cadence_seconds", 1).unwrap();
    if let Some(n) = shards {
        db.set_param("snapshot_shard_count", n).unwrap();
    }
    let client = clave::fetch::Client::new(true);
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, 1_754_740_800).unwrap();
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
    let dir = data.path().join("snapshots/2025-08-09");

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
    let dir = data.path().join("snapshots/2025-08-09");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let m = &manifest["manifest"];
    assert_eq!(m["shards"]["count"], 2);
    assert_eq!(m["shards"]["digests"].as_array().unwrap().len(), 2);

    let digest_bytes = Sha256::digest(host.as_bytes());
    let expected_shard = u64::from_be_bytes(digest_bytes[..8].try_into().unwrap()) % 2;
    let files = m["files"].as_array().unwrap();
    assert_eq!(files.len(), 6, "three files per shard, both shards emitted");
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
