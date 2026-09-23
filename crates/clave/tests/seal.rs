mod common;

use common::{
    add_delta, head_checkpoint, make_publisher_with_scope, reserve_addr, serve_static,
    served_entries, write_feed,
};

const SEAL_START: i64 = 1_786_276_800;

fn long_url(index: usize) -> String {
    format!("https://example.com/{index:04}/{}", "p".repeat(2000))
}

#[test]
fn seal_produces_a_verifiable_tree_and_checkpoints() {
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
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let r0 = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    assert_eq!(r0.epoch_number, 0);
    assert_eq!(r0.entry_count, 2);
    let key = wist_core::checkpoint::AggregatorKey {
        key_id: "log1".into(),
        public_key: sk.public(),
    };
    let epoch0 = head_checkpoint(data.path());
    wist_core::checkpoint::verify(&epoch0, &host, std::slice::from_ref(&key), &[]).unwrap();
    assert_eq!(epoch0.epoch_number(), 0);
    assert_eq!(epoch0.tree_size(), 2);
    let entries = served_entries(data.path(), 0, epoch0.tree_size());
    wist_core::epoch::verify_epoch(
        0,
        &epoch0,
        &entries,
        &wist_core::merkle::LeafHashes(&[]),
        u64::MAX,
    )
    .unwrap();

    let record = db
        .get_record("https://example.com/a", &host)
        .unwrap()
        .unwrap();
    assert_eq!(record.delta_id, id1);
    assert_eq!(record.title, "https://example.com/a");
    assert_eq!(record.lang, "en");

    assert!(clave::seal::run(&db, data.path(), &sk, SEAL_START).is_err());
    let r1 = clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    assert_eq!(r1.epoch_number, 1);
    assert_eq!(r1.entry_count, 0);
    let epoch1 = head_checkpoint(data.path());
    wist_core::checkpoint::verify(&epoch1, &host, std::slice::from_ref(&key), &[]).unwrap();
    assert_eq!(epoch1.epoch_number(), 1);
    assert_eq!(
        (epoch1.tree_size(), epoch1.root()),
        (epoch0.tree_size(), epoch0.root()),
        "an empty Epoch restates the tree the Epoch before it states"
    );
    let archived = std::fs::read_to_string(data.path().join("log/checkpoints/000000000")).unwrap();
    assert_eq!(
        wist_core::checkpoint::Checkpoint::parse(&archived)
            .unwrap()
            .note_text(),
        epoch0.note_text()
    );
}

#[test]
fn seal_orders_same_type_entries_by_ascending_leaf_hash() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    // Ingested in the order below, whose leaf hashes invert it, so the test
    // cannot pass without a real sort.
    let id1 = add_delta(&p, "https://example.com/b0", "beta body", None);
    let id2 = add_delta(&p, "https://example.com/a0", "alpha body", None);
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
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let report = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    assert_eq!(report.entry_count, 3);

    let head = head_checkpoint(data.path());
    let entries = served_entries(data.path(), 0, head.tree_size());
    wist_core::epoch::verify_epoch(
        0,
        &head,
        &entries,
        &wist_core::merkle::LeafHashes(&[]),
        u64::MAX,
    )
    .unwrap();
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
    db.set_param("epoch_cadence_seconds", 1).unwrap();
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
fn an_empty_first_epoch_states_the_empty_tree_and_serves_no_tile() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("example-log.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, 1_800_000_000).unwrap();
    let head = head_checkpoint(data.path());
    assert_eq!(head.tree_size(), 0);
    assert_eq!(head.root(), &wist_core::merkle::EMPTY_ROOT);
    assert!(wist_core::tiles::required_tiles(0).is_empty());
    assert!(!data.path().join("tile/0/000").exists());
    assert!(data.path().join("log/checkpoints/000000000").exists());
}

#[test]
fn a_epoch_over_the_entry_bundle_cap_defers_entries_to_the_next_seal() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = (0..40)
        .map(|i| add_delta(&p, &long_url(i), "body", None))
        .collect();
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let cap = 65_537;
    db.set_param("epoch_cap_bytes", cap).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let mut total = 0u64;
    let mut sealed_epochs = 0u64;
    for i in 0..5 {
        let report = clave::seal::run(&db, data.path(), &sk, 1_800_000_000 + i * 3600).unwrap();
        total += report.entry_count;
        let entries = db.epoch_entries(report.epoch_number).unwrap();
        assert!(
            wist_core::epoch::epoch_octets(&entries).unwrap() <= cap as u64,
            "every emitted Epoch must respect the entry-bundle cap"
        );
        if i == 0 {
            assert!(report.entry_count < 41, "cap must defer some entries");
        }
        sealed_epochs += 1;
        let (pending, _) = db.peek_pending_entries().unwrap();
        if pending.is_empty() {
            break;
        }
    }
    assert_eq!(total, 41, "deferred entries must seal in later Epochs");
    assert!(sealed_epochs > 1);
    for id in &ids {
        assert!(db.is_delta_seen(id).unwrap());
    }
}

#[test]
fn the_per_domain_epoch_cap_defers_the_surplus_in_acceptance_order() {
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
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    db.set_param("domain_epoch_entries_max", 2).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    let mut sealed: Vec<String> = Vec::new();
    for (i, at) in [SEAL_START, SEAL_START + 3600, SEAL_START + 7200]
        .into_iter()
        .enumerate()
    {
        let report = clave::seal::run(&db, data.path(), &sk, at).unwrap();
        let deltas: Vec<String> = db
            .epoch_entries(report.epoch_number)
            .unwrap()
            .iter()
            .filter(|e| e["type"] == "publisher_delta")
            .map(|e| wist_core::delta::delta_id(&e["body"]["delta"]).unwrap())
            .collect();
        assert!(
            deltas.len() <= 2,
            "epoch {i} carried {} deltas",
            deltas.len()
        );
        let mut expected = ids[i * 2..ids.len().min(i * 2 + 2)].to_vec();
        let mut actual = deltas.clone();
        expected.sort();
        actual.sort();
        assert_eq!(
            actual, expected,
            "Epoch {i} must select by acceptance order"
        );
        sealed.extend(deltas);
    }
    assert_eq!(sealed.len(), ids.len());
}

#[test]
fn a_delta_held_past_the_inclusion_ceiling_is_reported() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = (0..60)
        .map(|i| add_delta(&p, &long_url(i), "body", None))
        .collect();
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    db.set_param("max_inclusion_epochs", 1).unwrap();
    db.set_param("epoch_cap_bytes", 65_537).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    let mut late = Vec::new();
    for at in (SEAL_START..SEAL_START + 21600).step_by(3600) {
        let report = clave::seal::run(&db, data.path(), &sk, at).unwrap();
        late.extend(report.late);
    }
    assert!(!late.is_empty(), "no late inclusion reported");
}
