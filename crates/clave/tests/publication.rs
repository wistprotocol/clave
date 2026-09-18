mod common;

use common::{
    add_delta, head_checkpoint, make_publisher_with_scope, reserve_addr, serve_static,
    served_entries, write_feed,
};
use std::path::Path;

const SEAL_START: i64 = 1_786_276_800;

fn sealed_store(host: &str, client: &clave::fetch::Client, data: &Path) -> clave::db::Db {
    clave::init::run(host, data).unwrap();
    let db = clave::db::Db::open(&data.join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, client, data, host, "2026-08-09T12:00:00Z").unwrap();
    db
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
fn a_seal_records_its_checkpoint_before_publishing_the_tree_it_states() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_store(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();

    let (number, note) = db.head_publication().unwrap().unwrap();
    assert_eq!(number, 0);
    assert_eq!(
        std::fs::read_to_string(data.path().join("checkpoint")).unwrap(),
        note
    );
    assert_eq!(
        std::fs::read_to_string(data.path().join("log/checkpoints/000000000")).unwrap(),
        note
    );
    let head = head_checkpoint(data.path());
    assert_eq!(
        served_entries(data.path(), 0, head.tree_size()),
        db.epoch_entries(0).unwrap()
    );
    assert!(db.unpublished_publications().unwrap().is_empty());
    for dir in ["log", "log/checkpoints", "tile/0", "tile/entries"] {
        assert!(leftovers(&data.path().join(dir)).is_empty(), "{dir}");
    }
    assert!(clave::publication::recover(&db, data.path())
        .unwrap()
        .is_empty());
}

#[cfg(unix)]
#[test]
fn a_publication_interrupted_after_its_commit_is_finished_from_the_stored_checkpoint() {
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

    let (number, note) = db.head_publication().unwrap().unwrap();
    assert_eq!(number, 0);
    assert_eq!(db.unpublished_publications().unwrap().len(), 1);
    let head = wist_core::checkpoint::Checkpoint::parse(&note).unwrap();
    assert_eq!(
        served_entries(data.path(), 0, head.tree_size()),
        db.epoch_entries(0).unwrap(),
        "the Entries reach their bundles before the Checkpoint is archived"
    );
    assert!(
        !data.path().join("checkpoint").exists(),
        "no Checkpoint is published before its archive copy is durable"
    );
    assert_eq!(db.last_epoch().unwrap().unwrap().epoch_number, 0);

    let report = clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    assert_eq!(report.epoch_number, 1);
    assert_eq!(
        std::fs::read_to_string(checkpoints.join("000000000")).unwrap(),
        note
    );
    assert!(db.unpublished_publications().unwrap().is_empty());
    assert_eq!(head_checkpoint(data.path()).epoch_number(), 1);
}

#[test]
fn a_head_whose_files_went_missing_is_republished_from_the_store() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_store(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    let head = head_checkpoint(data.path());
    let note = std::fs::read(data.path().join("checkpoint")).unwrap();
    let bundle = data
        .path()
        .join(format!("tile/entries/000.p/{}", head.tree_size()));
    let bundle_before = std::fs::read(&bundle).unwrap();

    std::fs::remove_file(&bundle).unwrap();
    std::fs::write(data.path().join("checkpoint"), b"broken").unwrap();

    assert_eq!(
        clave::publication::recover(&db, data.path()).unwrap(),
        vec![0]
    );
    assert_eq!(std::fs::read(&bundle).unwrap(), bundle_before);
    assert_eq!(std::fs::read(data.path().join("checkpoint")).unwrap(), note);
    assert!(clave::publication::recover(&db, data.path())
        .unwrap()
        .is_empty());
}

#[test]
fn a_torn_head_tile_is_repaired_from_the_stored_tree() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_store(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    let head = head_checkpoint(data.path());
    let tile = data
        .path()
        .join(format!("tile/0/000.p/{}", head.tree_size()));
    let recorded = std::fs::read(&tile).unwrap();

    std::fs::write(&tile, &recorded[..recorded.len() / 2]).unwrap();
    assert_eq!(
        clave::publication::recover(&db, data.path()).unwrap(),
        vec![0]
    );
    assert_eq!(std::fs::read(&tile).unwrap(), recorded);
    assert!(clave::publication::recover(&db, data.path())
        .unwrap()
        .is_empty());
}

#[test]
fn the_head_checkpoint_never_names_entries_the_log_does_not_serve() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = (0..3)
        .map(|i| add_delta(&p, &format!("https://example.com/p{i}"), "body", None))
        .collect();
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    let db = sealed_store(&host, &client, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();

    for (index, at) in [SEAL_START, SEAL_START + 3600, SEAL_START + 7200]
        .into_iter()
        .enumerate()
    {
        clave::seal::run(&db, data.path(), &sk, at).unwrap();
        let head = head_checkpoint(data.path());
        assert_eq!(head.epoch_number(), index as u64);
        let entries = served_entries(data.path(), 0, head.tree_size());
        assert_eq!(entries.len() as u64, head.tree_size());
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|entry| {
                wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(entry).unwrap())
            })
            .collect();
        assert_eq!(
            wist_core::merkle::merkle_root(&leaves),
            *head.root(),
            "the served Entries reproduce the root the head Checkpoint states"
        );
    }
}
