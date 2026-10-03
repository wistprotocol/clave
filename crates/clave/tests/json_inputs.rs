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

fn admitted(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM list_items WHERE admission = 'admitted'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn duplicate_members_in_collection_files_admit_nothing_and_retry_after_restart() {
    for (object, name, escaped, code) in [
        ("catalog", "catalog", "catalog", "WIST1-E05"),
        ("catalog", "publisher", "publishe\\u0072", "WIST1-E05"),
        ("catalog", "generated_at", "generated_at", "WIST1-E05"),
        ("catalog", "key_id", "key_id", "WIST1-E05"),
        ("tree", "items", "items", "WIST2-E07"),
        ("tree", "url", "\\u0075rl", "WIST2-E07"),
        ("payload", "salt", "salt", "WIST2-E03"),
        ("payload", "extract", "e\\u0078tract", "WIST2-E03"),
    ] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let (item, payload) = page_item(&p, "https://localhost/article", "body");
        let published = publish_collection(
            &p,
            "default",
            &[(item.clone(), Some(payload))],
            "2026-08-09T12:00:00Z",
            None,
        );
        let relative = match object {
            "catalog" => "catalog.json".to_owned(),
            "tree" => format!("tree/{}", published.tree.keys().next().unwrap()),
            _ => format!(
                "payloads/{}.json",
                wist_core::item::payload_name(&item).unwrap()
            ),
        };
        let source = collection_dir(&p, "default").join(relative);
        let original = std::fs::read(&source).unwrap();
        std::fs::write(&source, duplicate(&original, name, escaped)).unwrap();
        let report =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
        assert!(report.items.is_empty(), "{object}/{name}: {report:?}");
        assert_eq!(admitted(&path), 0);
        assert!(!data
            .path()
            .join(format!(
                "payloads/{}.json",
                wist_core::item::payload_name(&item).unwrap()
            ))
            .exists());
        let codes: Vec<String> = db
            .list_rejections(&host)
            .unwrap()
            .into_iter()
            .map(|rejection| rejection.code)
            .collect();
        assert!(
            codes.iter().any(|got| got == code),
            "{object}/{name}: {codes:?}"
        );
        std::fs::write(&source, &original).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let report =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:03Z").unwrap();
        assert_eq!(
            report.items,
            [format!("default/{}", item_id(&item))],
            "{object}/{name}"
        );
        assert!(report.rejected.is_empty(), "{object}/{name}: {report:?}");
    }
}

#[test]
fn retained_duplicates_in_held_state_fail_a_pull_without_changing_it() {
    for (table, column) in [
        ("held_lists", "items"),
        ("collections", "accepted_envelope"),
    ] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let (item, payload) = page_item(&p, "https://localhost/article", "body");
        let first = publish_collection(
            &p,
            "default",
            &[(item, Some(payload))],
            "2026-08-09T12:00:00Z",
            None,
        );
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
        let conn = Connection::open(&path).unwrap();
        let held: Vec<u8> = conn
            .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        let name = if table == "held_lists" { "url" } else { "root" };
        let raw = duplicate(&held, name, name);
        conn.execute(&format!("UPDATE {table} SET {column} = ?1"), [&raw])
            .unwrap();
        let (item, payload) = page_item(&p, "https://localhost/other", "other");
        publish_collection(
            &p,
            "default",
            &[(item, Some(payload))],
            "2026-08-09T12:00:01Z",
            Some(&first),
        );
        drop(db);
        let db = Db::open(&path).unwrap();
        let err = clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:03Z")
            .unwrap_err();
        assert!(
            err.to_string().contains("duplicate JSON member name"),
            "{table}: {err}"
        );
        let retained: Vec<u8> = conn
            .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(retained, raw, "{table}");
    }
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
