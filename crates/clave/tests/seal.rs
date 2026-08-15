mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};

#[test]
fn seal_produces_verifiable_chain() {
    let (listener, host) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a", "alpha body", None);
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
    let r0 = clave::seal::run(&db, data.path(), &sk, 1_754_740_800).unwrap();
    assert_eq!(r0.block_number, 0);
    assert_eq!(r0.entry_count, 2);
    let raw = std::fs::read(data.path().join("log/blocks/000000000.json.zst")).unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
    wist_core::block::verify_block(&block, &sk.public()).unwrap();
    wist_core::block::verify_chain_link(&block["header"], "sha256:genesis").unwrap();
    let cp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data.path().join("log/checkpoint.json")).unwrap())
            .unwrap();
    wist_core::envelope::verify_envelope(&cp, "checkpoint", &sk.public()).unwrap();
    wist_core::block::verify_checkpoint_binding(&cp, &block).unwrap();

    let record = db
        .get_record("https://example.com/a", &host)
        .unwrap()
        .unwrap();
    assert_eq!(record.delta_id, id1);
    assert_eq!(record.weight, "full");
    assert_eq!(record.title, "https://example.com/a");
    assert_eq!(record.lang, "en");

    assert!(clave::seal::run(&db, data.path(), &sk, 1_754_740_800).is_err());
    let r1 = clave::seal::run(&db, data.path(), &sk, 1_754_740_801).unwrap();
    assert_eq!(r1.block_number, 1);
    assert_eq!(r1.entry_count, 0);
    let b1: serde_json::Value = serde_json::from_slice(
        &zstd::decode_all(
            &std::fs::read(data.path().join("log/blocks/000000001.json.zst")).unwrap()[..],
        )
        .unwrap(),
    )
    .unwrap();
    wist_core::block::verify_chain_link(
        &b1["header"],
        wist_core::block::block_hash(&block["header"])
            .unwrap()
            .as_str(),
    )
    .unwrap();
    wist_core::block::verify_block(&b1, &sk.public()).unwrap();
}

#[test]
fn seal_orders_same_type_entries_by_ascending_leaf_hash() {
    let (listener, host) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a0", "alpha body", None);
    let id2 = add_delta(&p, "https://example.com/b0", "beta body", None);
    write_feed(
        &p,
        &host,
        &[id1.clone(), id2.clone()],
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
    assert_eq!(report.entry_count, 3);

    let raw = std::fs::read(data.path().join("log/blocks/000000000.json.zst")).unwrap();
    let block: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
    wist_core::block::verify_block(&block, &sk.public()).unwrap();

    let entries = block["entries"].as_array().unwrap();
    assert_eq!(entries[0]["type"], "publisher_declaration");
    let delta_entries: Vec<&serde_json::Value> = entries[1..].iter().collect();
    assert_eq!(delta_entries.len(), 2);
    assert!(delta_entries.iter().all(|e| e["type"] == "publisher_delta"));

    let observed_hashes: Vec<[u8; 32]> = delta_entries
        .iter()
        .map(|e| wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(e).unwrap()))
        .collect();
    let mut expected = observed_hashes.clone();
    expected.sort();
    assert_ne!(observed_hashes[0], observed_hashes[1]);
    assert_eq!(
        observed_hashes, expected,
        "entries must appear in ascending leaf-hash order within their type group"
    );

    let observed_delta_ids: Vec<String> = delta_entries
        .iter()
        .map(|e| wist_core::delta::delta_id(&e["body"]["delta"]).unwrap())
        .collect();
    assert_eq!(
        observed_delta_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        2
    );
    assert!(observed_delta_ids.contains(&id1));
    assert!(observed_delta_ids.contains(&id2));

    let ingestion_order = vec![id1.clone(), id2.clone()];
    assert_ne!(
        observed_delta_ids, ingestion_order,
        "fixture must invert ingestion order so this test cannot pass without a real leaf-hash sort"
    );
    assert_eq!(
        observed_delta_ids,
        vec![id2, id1],
        "id2 (ingested second) must sort before id1 (ingested first): its entry's leaf hash is smaller"
    );
}

#[test]
fn seal_applies_chained_deltas_in_chain_order_regardless_of_storage_order() {
    let (listener, host) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a0", "first content", None);
    let id2 = add_delta(&p, "https://example.com/a0", "second content", Some(&id1));
    write_feed(
        &p,
        &host,
        &[id1.clone(), id2.clone()],
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
    assert_eq!(report.entry_count, 3);

    let record = db
        .get_record("https://example.com/a0", &host)
        .unwrap()
        .unwrap();
    assert_eq!(
        record.delta_id, id2,
        "the later (update) delta must win over the earlier (new) delta it chains from"
    );
}

#[test]
fn block_frame_declares_decompressed_size() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("example-log.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, 1_800_000_000).unwrap();
    let raw = std::fs::read(data.path().join("log/blocks/000000000.json.zst")).unwrap();
    let decompressed = zstd::decode_all(&raw[..]).unwrap();
    let declared = zstd::zstd_safe::get_frame_content_size(&raw)
        .expect("frame header must parse")
        .expect("Frame_Content_Size must be declared (WIST-3 §6)");
    assert_eq!(declared, decompressed.len() as u64);
}

#[test]
fn oversize_block_defers_entries_to_the_next_seal() {
    let (listener, host) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_delta(&p, "https://example.com/a", "alpha body", None);
    let id2 = add_delta(&p, "https://example.com/b", "beta body", None);
    write_feed(
        &p,
        &host,
        &[id1.clone(), id2.clone()],
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    let client = clave::fetch::Client::new(true);
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let cap = 1024;
    db.set_param("block_decompressed_cap_bytes", cap).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let mut total = 0u64;
    let mut sealed_blocks = 0u64;
    for i in 0..5 {
        let report = clave::seal::run(&db, data.path(), &sk, 1_800_000_000 + i).unwrap();
        total += report.entry_count;
        let raw = std::fs::read(
            data.path()
                .join(format!("log/blocks/{:09}.json.zst", report.block_number)),
        )
        .unwrap();
        assert!(
            zstd::decode_all(&raw[..]).unwrap().len() as i64 <= cap,
            "every emitted Block must respect the decompressed cap"
        );
        if i == 0 {
            assert!(report.entry_count < 3, "cap must defer some entries");
        }
        sealed_blocks += 1;
        let (pending, _) = db.peek_pending_entries().unwrap();
        if pending.is_empty() {
            break;
        }
    }
    assert_eq!(total, 3, "deferred entries must seal in later Blocks");
    assert!(sealed_blocks > 1);
    assert!(db
        .get_record("https://example.com/a", &host)
        .unwrap()
        .is_some());
    assert!(db
        .get_record("https://example.com/b", &host)
        .unwrap()
        .is_some());
}
