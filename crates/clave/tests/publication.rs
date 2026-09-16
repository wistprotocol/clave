mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};
use std::path::Path;

const SEAL_START: i64 = 1_786_276_800;

fn sealed_store(host: &str, client: &clave::fetch::Client, data: &Path) -> clave::db::Db {
    clave::init::run(host, data).unwrap();
    let db = clave::db::Db::open(&data.join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, client, data, host, "2026-08-09T12:00:00Z").unwrap();
    db
}

fn decoded_block(data: &Path, number: u64) -> Vec<u8> {
    zstd::decode_all(
        std::fs::read(data.join(format!("log/blocks/{number:09}.json.zst")))
            .unwrap()
            .as_slice(),
    )
    .unwrap()
}

fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".tmp"))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_seal_records_its_bytes_before_publishing_them_durably() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_store(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();

    let (number, block_json, checkpoint_json) = db.head_publication().unwrap().unwrap();
    assert_eq!(number, 0);
    assert_eq!(decoded_block(data.path(), 0), block_json);
    assert_eq!(
        std::fs::read(data.path().join("log/checkpoints/000000000.json")).unwrap(),
        checkpoint_json
    );
    assert_eq!(
        std::fs::read(data.path().join("log/checkpoint.json")).unwrap(),
        checkpoint_json
    );
    assert!(db.unpublished_publications().unwrap().is_empty());
    for dir in ["log", "log/blocks", "log/checkpoints"] {
        assert!(leftovers(&data.path().join(dir)).is_empty(), "{dir}");
    }
    assert!(clave::publication::recover(&db, data.path())
        .unwrap()
        .is_empty());
}

#[cfg(unix)]
#[test]
fn a_publication_interrupted_after_its_commit_is_finished_with_the_recorded_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_store(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    let checkpoints = data.path().join("log/checkpoints");
    std::fs::create_dir_all(&checkpoints).unwrap();
    std::fs::set_permissions(&checkpoints, std::fs::Permissions::from_mode(0o500)).unwrap();
    let failed = clave::seal::run(&db, data.path(), &sk, SEAL_START);
    std::fs::set_permissions(&checkpoints, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(failed.is_err(), "publication could not complete");

    let (number, block_json, checkpoint_json) = db.head_publication().unwrap().unwrap();
    assert_eq!(number, 0);
    assert_eq!(db.unpublished_publications().unwrap().len(), 1);
    assert_eq!(
        decoded_block(data.path(), 0),
        block_json,
        "the Block file is published before its Checkpoint"
    );
    assert!(
        !data.path().join("log/checkpoint.json").exists(),
        "no Checkpoint is published before its Block and numbered copy are durable"
    );
    assert_eq!(db.last_block().unwrap().unwrap().block_number, 0);

    let report = clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    assert_eq!(report.block_number, 1);
    assert_eq!(decoded_block(data.path(), 0), block_json);
    assert_eq!(
        std::fs::read(checkpoints.join("000000000.json")).unwrap(),
        checkpoint_json
    );
    assert!(db.unpublished_publications().unwrap().is_empty());
    let head: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data.path().join("log/checkpoint.json")).unwrap())
            .unwrap();
    assert_eq!(head["checkpoint"]["block_number"], 1);
    let block1: serde_json::Value = serde_json::from_slice(&decoded_block(data.path(), 1)).unwrap();
    let block0: serde_json::Value = serde_json::from_slice(&block_json).unwrap();
    wist_core::block::verify_chain_link(
        &block1["header"],
        &wist_core::block::block_hash(&block0["header"]).unwrap(),
    )
    .unwrap();
}

#[test]
fn a_head_whose_files_went_missing_is_republished_from_the_record() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_store(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    let before = std::fs::read(data.path().join("log/checkpoint.json")).unwrap();
    let block_before = std::fs::read(data.path().join("log/blocks/000000000.json.zst")).unwrap();

    std::fs::remove_file(data.path().join("log/blocks/000000000.json.zst")).unwrap();
    std::fs::write(data.path().join("log/checkpoint.json"), b"{}").unwrap();

    assert_eq!(
        clave::publication::recover(&db, data.path()).unwrap(),
        vec![0]
    );
    assert_eq!(
        std::fs::read(data.path().join("log/blocks/000000000.json.zst")).unwrap(),
        block_before
    );
    assert_eq!(
        std::fs::read(data.path().join("log/checkpoint.json")).unwrap(),
        before
    );
}

#[test]
fn a_torn_head_block_file_is_repaired_but_a_different_block_is_refused() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_store(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    let head = data.path().join("log/blocks/000000001.json.zst");
    let recorded = std::fs::read(&head).unwrap();

    std::fs::write(&head, &recorded[..recorded.len() / 2]).unwrap();
    assert_eq!(
        clave::publication::recover(&db, data.path()).unwrap(),
        vec![1]
    );
    assert_eq!(std::fs::read(&head).unwrap(), recorded);

    let mut other: serde_json::Value =
        serde_json::from_slice(&decoded_block(data.path(), 1)).unwrap();
    other["header"]["sealed_at"] = serde_json::json!("2026-08-09T13:00:01Z");
    let encoded = zstd::bulk::compress(
        &wist_core::jcs::canonicalize(&other).unwrap(),
        zstd::DEFAULT_COMPRESSION_LEVEL,
    )
    .unwrap();
    std::fs::write(&head, encoded).unwrap();
    let err = clave::publication::recover(&db, data.path()).unwrap_err();
    assert!(err.to_string().contains("on disk hashes to"), "{err}");
    assert!(clave::seal::run(&db, data.path(), &sk, SEAL_START + 7200).is_err());
    std::fs::write(&head, &recorded).unwrap();
    assert!(clave::publication::recover(&db, data.path())
        .unwrap()
        .is_empty());
}
