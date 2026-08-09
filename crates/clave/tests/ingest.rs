mod common;

use common::{add_delta, make_publisher, serve_static, write_feed};
use std::fs;

#[test]
fn ingest_accepts_valid_and_rejects_bad_commitment() {
    let p = make_publisher("127.0.0.1");
    let id1 = add_delta(&p, "https://example.com/a", "alpha body", None);
    let id2 = add_delta(&p, "https://example.com/b", "beta body", None);
    let hex2 = id2.strip_prefix("sha256:").unwrap().to_string();
    let bad = p
        .dir
        .path()
        .join(format!(".well-known/wist/payloads/{hex2}.json"));
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&bad).unwrap()).unwrap();
    v["content"]["extract"] = "tampered".into();
    fs::write(&bad, serde_json::to_vec(&v).unwrap()).unwrap();
    write_feed(
        &p,
        "127.0.0.1",
        &[id1.clone(), id2.clone()],
        "2026-08-09T12:00:00Z",
    );
    let host = serve_static(p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let client = clave::fetch::Client::new(true);

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();

    assert_eq!(report.accepted, vec![id1.clone()]);
    assert_eq!(
        report.rejected,
        vec![(id2.clone(), "WIST2-E03".to_string())]
    );

    let hex1 = id1.strip_prefix("sha256:").unwrap();
    let src = fs::read(
        p.dir
            .path()
            .join(format!(".well-known/wist/payloads/{hex1}.json")),
    )
    .unwrap();
    let dst = fs::read(tmp.path().join(format!("payloads/{hex1}.json"))).unwrap();
    assert_eq!(src, dst);
    assert!(!tmp.path().join(format!("payloads/{hex2}.json")).exists());

    assert_eq!(
        db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
    assert_eq!(db.count_pending_entries("publisher_delta").unwrap(), 1);

    let report2 =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:10Z").unwrap();
    assert!(report2.accepted.is_empty());
    assert_eq!(report2.rejected, vec![(id2, "WIST2-E03".to_string())]);
}

#[test]
fn drain_pending_entries_orders_declaration_then_deltas_across_passes() {
    let p = make_publisher("127.0.0.1");
    let id1 = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(
        &p,
        "127.0.0.1",
        std::slice::from_ref(&id1),
        "2026-08-09T12:00:00Z",
    );
    let host = serve_static(p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let client = clave::fetch::Client::new(true);

    let report1 =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(report1.accepted, vec![id1.clone()]);

    let id2 = add_delta(&p, "https://example.com/a", "alpha body v2", Some(&id1));
    write_feed(
        &p,
        "127.0.0.1",
        &[id1.clone(), id2.clone()],
        "2026-08-09T12:00:10Z",
    );
    let report2 =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:10Z").unwrap();
    assert_eq!(report2.accepted, vec![id2.clone()]);

    let entries = db.drain_pending_entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].entry_type, "publisher_declaration");
    assert_eq!(entries[1].entry_type, "publisher_delta");
    assert_eq!(
        wist_core::delta::delta_id(&entries[1].entry_json["delta"]).unwrap(),
        id1
    );
    assert_eq!(entries[2].entry_type, "publisher_delta");
    assert_eq!(
        wist_core::delta::delta_id(&entries[2].entry_json["delta"]).unwrap(),
        id2
    );

    assert!(db.drain_pending_entries().unwrap().is_empty());
}
