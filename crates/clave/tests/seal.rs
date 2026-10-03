mod common;

use common::head_checkpoint;

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
