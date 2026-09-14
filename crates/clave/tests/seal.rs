mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};

const SEAL_START: i64 = 1_786_276_800;

#[test]
fn seal_produces_verifiable_chain() {
    let (listener, host, client) = reserve_addr();
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
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let r0 = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
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

    assert!(clave::seal::run(&db, data.path(), &sk, SEAL_START).is_err());
    let r1 = clave::seal::run(&db, data.path(), &sk, SEAL_START + 1).unwrap();
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
    let (listener, host, client) = reserve_addr();
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
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let report = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
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
    let (listener, host, client) = reserve_addr();
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
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let report = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
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
    let (listener, host, client) = reserve_addr();
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
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let cap = 1024;
    db.set_param("block_decompressed_cap_bytes", cap).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let mut total = 0u64;
    let mut sealed_blocks = 0u64;
    for i in 0..5 {
        let report = clave::seal::run(&db, data.path(), &sk, 1_800_000_000 + i * 3600).unwrap();
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

#[test]
fn the_per_domain_block_cap_defers_the_surplus_in_acceptance_order() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = (0..5)
        .map(|i| add_delta(&p, &format!("https://example.com/p{i}"), "body", None))
        .collect();
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    db.set_param("domain_block_entries_max", 2).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    let mut sealed: Vec<String> = Vec::new();
    for (i, at) in [SEAL_START, SEAL_START + 3600, SEAL_START + 7200]
        .into_iter()
        .enumerate()
    {
        let report = clave::seal::run(&db, data.path(), &sk, at).unwrap();
        let raw = std::fs::read(
            data.path()
                .join(format!("log/blocks/{:09}.json.zst", report.block_number)),
        )
        .unwrap();
        let block: serde_json::Value =
            serde_json::from_slice(&zstd::decode_all(&raw[..]).unwrap()).unwrap();
        let deltas: Vec<String> = block["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["type"] == "publisher_delta")
            .map(|e| wist_core::delta::delta_id(&e["body"]["delta"]).unwrap())
            .collect();
        assert!(
            deltas.len() <= 2,
            "block {i} carried {} deltas",
            deltas.len()
        );
        let mut expected = ids[i * 2..ids.len().min(i * 2 + 2)].to_vec();
        let mut actual = deltas.clone();
        expected.sort();
        actual.sort();
        assert_eq!(
            actual, expected,
            "Block {i} must select by acceptance order"
        );
        sealed.extend(deltas);
    }
    assert_eq!(sealed.len(), ids.len());
}

#[test]
fn a_delta_held_past_the_inclusion_ceiling_is_reported() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = (0..3)
        .map(|i| add_delta(&p, &format!("https://example.com/p{i}"), "body", None))
        .collect();
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    db.set_param("max_inclusion_blocks", 1).unwrap();
    db.set_param("block_decompressed_cap_bytes", 1100).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    let mut late = Vec::new();
    for at in (SEAL_START..SEAL_START + 21600).step_by(3600) {
        let report = clave::seal::run(&db, data.path(), &sk, at).unwrap();
        late.extend(report.late);
    }
    assert!(!late.is_empty(), "no late inclusion reported");
}

fn roster_update(action: &str, auditor_id: &str, key_id: &str, seed: u8) -> serde_json::Value {
    let public_key = wist_core::crypto::SigningKey::from_seed(&[seed; 32])
        .public()
        .to_b64u();
    serde_json::json!({
        "wist_version": "1.0.0",
        "action": action,
        "subject": auditor_id,
        "details": {"key_id": key_id, "alg": "Ed25519", "public_key": public_key},
        "effective_at": "2026-08-09T12:00:00Z",
    })
}

#[test]
fn a_roster_act_the_e07_rules_reject_is_not_sealed() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example.org", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    let admit = roster_update("auditor_admit", "audit.example.net", "a1", 21);
    let envelope = wist_core::envelope::sign_envelope(&admit, "update", "log1", &sk).unwrap();
    db.insert_pending_entry("registry_update", "", &envelope, 0)
        .unwrap();
    let first = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    assert_eq!(first.entry_count, 1, "dropped {:?}", first.dropped);

    let again = roster_update("auditor_admit", "audit.example.net", "a2", 22);
    let envelope = wist_core::envelope::sign_envelope(&again, "update", "log1", &sk).unwrap();
    db.insert_pending_entry("registry_update", "", &envelope, 0)
        .unwrap();
    let second = clave::seal::run(&db, data.path(), &sk, SEAL_START + 1).unwrap();
    assert_eq!(second.entry_count, 0, "dropped {:?}", second.dropped);
    assert!(
        second.dropped.iter().any(|d| d.contains("WIST4-E07")),
        "dropped {:?}",
        second.dropped
    );
}

#[test]
fn live_roster_acts_follow_authenticated_history_and_batch_rules() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example.org", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let observer = wist_core::crypto::SigningKey::from_seed(&[41; 32]);
    let queue = |envelope: &serde_json::Value| {
        db.insert_pending_entry("registry_update", "", envelope, 0)
            .unwrap();
    };

    let register = serde_json::json!({
        "wist_version": "1.0.0", "action": "observer_register", "subject": "watch.sample.net",
        "details": {"key_id": "w1", "alg": "Ed25519", "public_key": observer.public().to_b64u()},
        "effective_at": "2026-08-09T12:00:00Z",
    });
    queue(&wist_core::envelope::sign_envelope(&register, "update", "w1", &observer).unwrap());
    let mut malformed = roster_update("auditor_admit", "audit.example.net", "a1", 21);
    malformed["details"]["public_key"] = serde_json::json!("not-a-key");
    queue(&wist_core::envelope::sign_envelope(&malformed, "update", "log1", &sk).unwrap());
    let forged = roster_update("auditor_admit", "checker.example.info", "c1", 23);
    queue(
        &wist_core::envelope::sign_envelope(
            &forged,
            "update",
            "log1",
            &wist_core::crypto::SigningKey::from_seed(&[42; 32]),
        )
        .unwrap(),
    );
    let first = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    assert_eq!(first.entry_count, 1, "dropped {:?}", first.dropped);
    assert!(
        first.dropped.iter().any(|d| d.contains("WIST4-E04"))
            && first.dropped.iter().any(|d| d.contains("Log key")),
        "dropped {:?}",
        first.dropped
    );

    let checkpoint = serde_json::json!({
        "wist_version": "1.0.0", "action": "observer_checkpoint", "subject": "watch.sample.net",
        "details": {"head": format!("sha256:{}", "7".repeat(64))},
        "effective_at": "2026-08-09T12:00:01Z",
    });
    let checkpoint_envelope =
        wist_core::envelope::sign_envelope(&checkpoint, "update", "w1", &observer).unwrap();
    queue(&checkpoint_envelope);
    let stranger = serde_json::json!({
        "wist_version": "1.0.0", "action": "observer_checkpoint", "subject": "watch.sample.org",
        "details": {"head": format!("sha256:{}", "8".repeat(64))},
        "effective_at": "2026-08-09T12:00:01Z",
    });
    queue(&wist_core::envelope::sign_envelope(&stranger, "update", "w1", &observer).unwrap());
    let second = clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    assert_eq!(second.entry_count, 1, "dropped {:?}", second.dropped);
    assert!(
        second.dropped.iter().any(|d| d.contains("WIST4-E07")),
        "dropped {:?}",
        second.dropped
    );

    let mut promote = roster_update("auditor_admit", "watch.sample.net", "w1", 41);
    queue(&wist_core::envelope::sign_envelope(&promote, "update", "log1", &sk).unwrap());
    let third = clave::seal::run(&db, data.path(), &sk, SEAL_START + 2 * 3600).unwrap();
    assert_eq!(third.entry_count, 0, "dropped {:?}", third.dropped);
    assert!(
        third.dropped.iter().any(|d| d.contains("WIST4-E04")),
        "dropped {:?}",
        third.dropped
    );
    promote["details"]["track_record"] = serde_json::json!({
        "checkpoint": wist_core::delta::delta_id(&checkpoint_envelope["update"]).unwrap(),
        "scoreboard": {"provisional": [0, 0, 0], "standing": [0, 0, 0], "mature": [0, 0, 0]},
    });
    queue(&wist_core::envelope::sign_envelope(&promote, "update", "log1", &sk).unwrap());
    let fourth = clave::seal::run(&db, data.path(), &sk, SEAL_START + 3 * 3600).unwrap();
    assert_eq!(fourth.entry_count, 1, "dropped {:?}", fourth.dropped);

    let roster =
        clave::history::roster::RosterHistory::reconstruct(data.path(), db.last_block().unwrap())
            .unwrap();
    assert!(roster.rejected().is_empty(), "{:?}", roster.rejected());
    assert_eq!(
        roster
            .admitted_key_at("watch.sample.net", SEAL_START + 3 * 3600)
            .map(|b| b.key_id),
        Some("w1")
    );
    assert!(roster
        .registered_key_at("watch.sample.net", SEAL_START + 3 * 3600)
        .is_none());
    assert_eq!(roster.checkpoints().len(), 1);
    assert_eq!(
        db.roster_state()
            .unwrap()
            .iter()
            .map(|(auditor, key, ..)| (auditor.as_str(), key.as_str()))
            .collect::<Vec<_>>(),
        vec![("watch.sample.net", "w1")]
    );
}
