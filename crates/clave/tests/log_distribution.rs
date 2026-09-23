mod common;

use common::{
    add_delta, head_checkpoint, make_publisher_with_scope, reserve_addr, seal_fixture_epoch,
    serve_static, served_entries, spec_dir, write_feed,
};
use serde_json::Value;
use std::path::Path;
use wist_core::checkpoint::{self, AggregatorKey, Checkpoint};
use wist_core::merkle::{self, HashReader, LeafHashes};
use wist_core::tiles::{self, TILE_WIDTH};

const SEAL_START: i64 = 1_786_276_800;

fn read(data: &Path, path: &str) -> Vec<u8> {
    std::fs::read(data.join(path.trim_start_matches('/'))).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn served_tiles(data: &Path, tree_size: u64) -> tiles::TileSet {
    let mut set = tiles::TileSet::new();
    for tile in tiles::required_tiles(tree_size) {
        set.insert_bytes(tile.level, tile.index, &read(data, &tile.path()))
            .unwrap();
    }
    set
}

/// WIST-3 §4, §5, §6: verified as a Consumer holding the Log Anchor does.
fn verify_static_log(data: &Path, log_id: &str, key: &AggregatorKey) -> Vec<Checkpoint> {
    let head = Checkpoint::parse(&String::from_utf8(read(data, "/checkpoint")).unwrap()).unwrap();
    let tree = served_tiles(data, head.tree_size());
    tiles::check_tree(&tree, head.tree_size(), head.root()).unwrap();

    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    for number in 0..=head.epoch_number() {
        let note = String::from_utf8(read(data, &checkpoint::archive_path(number))).unwrap();
        let archived = Checkpoint::parse(&note).unwrap();
        checkpoint::check_archive_path(&archived, &checkpoint::archive_path(number)).unwrap();
        checkpoint::verify(&archived, log_id, std::slice::from_ref(key), &[]).unwrap();
        checkpoint::check_sequence(checkpoints.last(), &archived, 3600).unwrap();

        let previous_size = checkpoints.last().map_or(0, Checkpoint::tree_size);
        let proof =
            merkle::consistency_proof_from(&tree, previous_size, archived.tree_size()).unwrap();
        if let Some(previous) = checkpoints.last() {
            checkpoint::check_consistency(previous, &archived, &proof).unwrap();
        }

        let entries = served_entries(data, previous_size, archived.tree_size());
        let summary = wist_core::epoch::verify_epoch(
            previous_size,
            &archived,
            &entries,
            &LeafHashes(&leaves),
            u64::MAX,
        )
        .unwrap();
        for (offset, leaf) in summary.leaf_hashes.iter().enumerate() {
            assert_eq!(
                tree.node(0, previous_size + offset as u64).unwrap(),
                *leaf,
                "an entry bundle's leaf is not the level-0 tile's hash"
            );
        }
        leaves.extend(summary.leaf_hashes);
        checkpoints.push(archived);
    }
    assert_eq!(checkpoints.last().unwrap().note_text(), head.note_text());
    assert_eq!(merkle::merkle_root(&leaves), *head.root());
    checkpoints
}

fn sealed_log(host: &str, client: &clave::fetch::Client, data: &Path) -> clave::db::Db {
    clave::init::run(host, data).unwrap();
    let db = clave::db::Db::open(&data.join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, client, data, host, "2026-08-09T12:00:00Z").unwrap();
    db
}

#[test]
fn a_sealed_log_verifies_end_to_end_from_its_static_files_alone() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let first = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&first),
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_log(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    let second = add_delta(&p, "https://example.com/b", "beta body", None);
    write_feed(
        &p,
        &host,
        std::slice::from_ref(&second),
        "2026-08-09T13:00:00Z",
    );
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T13:00:00Z").unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START + 7200).unwrap();

    let key = AggregatorKey {
        key_id: "log1".into(),
        public_key: sk.public(),
    };
    let checkpoints = verify_static_log(data.path(), &host, &key);
    assert_eq!(checkpoints.len(), 3);
    assert_eq!(
        checkpoints[1].tree_size(),
        checkpoints[0].tree_size(),
        "the empty Epoch restates the tree size"
    );
    assert_eq!(checkpoints[1].root(), checkpoints[0].root());
    assert!(checkpoints[2].tree_size() > checkpoints[1].tree_size());
}

#[test]
fn crossing_a_tile_boundary_publishes_a_full_tile_and_removes_its_partials() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let entries = |from: usize, to: usize| -> Vec<Value> {
        (from..to)
            .map(|i| serde_json::json!({"type": "label", "body": {"n": i}}))
            .collect()
    };

    seal_fixture_epoch(
        &db,
        data.path(),
        0,
        "2026-08-09T12:00:00Z",
        &entries(0, 200),
    );
    let partial = data.path().join("tile/0/000.p/200");
    assert!(partial.exists(), "a head size requires its partial tile");
    assert!(!data.path().join("tile/0/000").exists());
    assert!(data.path().join("tile/entries/000.p/200").exists());

    seal_fixture_epoch(
        &db,
        data.path(),
        1,
        "2026-08-09T13:00:00Z",
        &entries(200, 300),
    );
    let head = head_checkpoint(data.path());
    assert_eq!(head.tree_size(), 300);
    assert_eq!(
        tiles::required_tiles(300)
            .iter()
            .map(tiles::Tile::path)
            .collect::<Vec<_>>(),
        ["/tile/0/000", "/tile/0/001.p/44", "/tile/1/000.p/1"]
    );
    assert!(data.path().join("tile/0/000").is_file());
    assert_eq!(
        read(data.path(), "/tile/0/000").len(),
        TILE_WIDTH as usize * 32
    );
    assert!(
        !data.path().join("tile/0/000.p").exists(),
        "a partial tile is removed once its full tile exists"
    );
    assert!(
        !data.path().join("tile/entries/000.p").exists(),
        "a partial entry bundle is removed once its full bundle exists"
    );
    assert!(data.path().join("tile/0/001.p/44").is_file());
    assert!(data.path().join("tile/1/000.p/1").is_file());
    assert!(data.path().join("tile/entries/001.p/44").is_file());

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    verify_static_log(
        data.path(),
        "log.example.test",
        &AggregatorKey {
            key_id: "log1".into(),
            public_key: sk.public(),
        },
    );
}

#[test]
fn tiles_and_entry_bundles_take_the_paths_and_encodings_the_vector_fixes() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist3/epoch.json")).unwrap(),
    )
    .unwrap();
    let entries: Vec<Value> = serde_json::from_value(vector["entries"].clone()).unwrap();
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|entry| merkle::leaf_hash(&wist_core::jcs::canonicalize(entry).unwrap()))
        .collect();
    let leaf_data: Vec<Vec<u8>> = entries
        .iter()
        .map(|entry| wist_core::jcs::canonicalize(entry).unwrap())
        .collect();

    let tile = &tiles::required_tiles(vector["tree_size"].as_u64().unwrap())[0];
    assert_eq!(tile.path(), vector["tile_0_000_p_4_path"].as_str().unwrap());
    assert_eq!(
        wist_core::crypto::hex_encode(&tiles::encode_tile(&leaves)),
        vector["tile_0_000_p_4"].as_str().unwrap()
    );
    let bundle = &tiles::required_entry_bundles(vector["tree_size"].as_u64().unwrap())[0];
    assert_eq!(
        bundle.path(),
        vector["entry_bundle_000_p_4_path"].as_str().unwrap()
    );
    assert_eq!(
        wist_core::crypto::hex_encode(&tiles::encode_entry_bundle(&leaf_data).unwrap()),
        vector["entry_bundle_000_p_4"].as_str().unwrap()
    );

    let data = tempfile::tempdir().unwrap();
    let log_id = vector["log_id"].as_str().unwrap();
    clave::init::run(log_id, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let sealed = seal_fixture_epoch(&db, data.path(), 0, "2026-08-02T13:00:00Z", &entries);
    assert_eq!(sealed.tree_size, vector["tree_size"].as_u64().unwrap());
    assert_eq!(sealed.root, vector["root"].as_str().unwrap());
    assert_eq!(
        read(data.path(), vector["tile_0_000_p_4_path"].as_str().unwrap()),
        wist_core::crypto::hex_decode(vector["tile_0_000_p_4"].as_str().unwrap()).unwrap()
    );
    assert_eq!(
        read(
            data.path(),
            vector["entry_bundle_000_p_4_path"].as_str().unwrap()
        ),
        wist_core::crypto::hex_decode(vector["entry_bundle_000_p_4"].as_str().unwrap()).unwrap()
    );
    let head = head_checkpoint(data.path());
    assert_eq!(head.origin(), log_id);
    assert_eq!(head.tree_size(), vector["tree_size"].as_u64().unwrap());
    assert_eq!(head.root_token(), vector["root"].as_str().unwrap());
    assert_eq!(head.sealed_at(), "2026-08-02T13:00:00Z");
    assert!(
        merkle::consistency_proof_from(&served_tiles(data.path(), head.tree_size()), 0, 4)
            .unwrap()
            .is_empty(),
        "the empty tree is a prefix of every tree"
    );
}
