mod common;

const SEAL_START: i64 = 1_786_276_800;

use common::{add_label, make_publisher_with_scope, reserve_addr, serve_static, write_label_feed};

#[test]
fn an_empty_same_day_epoch_gets_its_own_directory_and_leaves_the_first_byte_identical() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id1 = add_label(&p, "https://other.example/alpha", "2026-08-09T11:00:00Z");
    write_label_feed(
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
