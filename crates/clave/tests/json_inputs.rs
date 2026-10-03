mod common;

use clave::db::Db;
use common::*;
use rusqlite::Connection;
use serde_json::Value;

fn duplicate(raw: &[u8], name: &str, escaped: &str) -> Vec<u8> {
    let text = std::str::from_utf8(raw).unwrap();
    let changed = text.replacen(
        &format!("\"{name}\":"),
        &format!("\"{name}\":null,\"{escaped}\":"),
        1,
    );
    assert_ne!(changed, text);
    assert_eq!(
        serde_json::from_str::<Value>(&changed).unwrap(),
        serde_json::from_slice::<Value>(raw).unwrap()
    );
    changed.into_bytes()
}

#[test]
fn retained_declaration_duplicates_cannot_authorize_a_pull() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
    let original = db.get_publisher_declaration(&host).unwrap().unwrap();
    let raw = duplicate(&original, "x", "\\u0078");
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE publishers SET declaration_json = ?1 WHERE domain = ?2",
            (&raw, &host),
        )
        .unwrap();
    drop(db);
    let db = Db::open(&path).unwrap();
    let err =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:03Z").unwrap_err();
    assert!(err.to_string().contains("duplicate JSON member name"));
    assert_eq!(db.get_publisher_declaration(&host).unwrap().unwrap(), raw);
}
