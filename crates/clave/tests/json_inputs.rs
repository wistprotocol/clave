mod common;

use clave::db::Db;
use common::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::fs;

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
fn signed_last_value_duplicates_reject_before_live_admission_and_retry_after_restart() {
    for (object, name, escaped) in [
        ("publisher", "publisher", "publishe\\u0072"),
        ("publisher", "domain", "\\u0064omain"),
        ("publisher", "public_key", "public_key"),
        ("publisher", "key_id", "key_id"),
        ("feed", "feed", "feed"),
        ("feed", "domain", "\\u0064omain"),
        ("feed", "generated_at", "generated_at"),
        ("page", "feed", "feed"),
        ("page", "domain", "\\u0064omain"),
        ("delta", "delta", "delta"),
        ("delta", "publisher", "publishe\\u0072"),
        ("delta", "bytes", "b\\u0079tes"),
        ("delta", "lang", "lang"),
        ("delta", "key_id", "key_id"),
    ] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let id = add_delta(&p, "https://localhost/article", "body", None);
        if object == "page" {
            write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:01Z").unwrap();
            let key = clave::keys::load(&data.path().join("keys/seed")).unwrap();
            clave::seal::run(&db, data.path(), &key, 1_786_276_800).unwrap();
            write_feed_page(
                &p,
                &host,
                1,
                std::slice::from_ref(&id),
                "2026-08-09T12:00:00Z",
                None,
            );
            write_feed_with_next(
                &p,
                &host,
                std::slice::from_ref(&id),
                "2026-08-09T12:00:00Z",
                Some(&page_url(&host, 1)),
            );
        } else {
            write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
        }
        let relative = match object {
            "delta" => format!("deltas/{}.json", &id[7..]),
            "page" => "feed/1.json".into(),
            _ => format!("{object}.json"),
        };
        let source = p.dir.path().join(".well-known/wist").join(relative);
        let original = fs::read(&source).unwrap();
        fs::write(&source, duplicate(&original, name, escaped)).unwrap();
        let report =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
        assert!(report.accepted.is_empty(), "{object}/{name}");
        assert!(!db.is_delta_seen(&id).unwrap());
        assert_eq!(
            db.url_tip(&host, "https://localhost/article").unwrap(),
            None
        );
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &id[7..]))
            .exists());
        let rejected = db.list_rejections(&host).unwrap();
        let last = rejected.last().unwrap();
        assert_eq!(
            last.code,
            match object {
                "publisher" => "WIST2-E04",
                "delta" => "WIST2-E03",
                _ => "WIST2-E01",
            }
        );
        assert!(last
            .detail
            .as_deref()
            .unwrap()
            .contains("duplicate JSON member name"));
        if object == "publisher" {
            assert!(db.get_publisher(&host).unwrap().is_none());
        }
        fs::write(&source, &original).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let report =
            clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:03Z").unwrap();
        assert_eq!(report.accepted, [id], "{object}/{name}");
        assert!(report.rejected.is_empty());
        assert_eq!(fs::read(source).unwrap(), original);
    }
}

#[test]
fn duplicate_rejection_precedes_invalid_fields_and_signatures() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let source = p.dir.path().join(".well-known/wist/feed.json");
    let mut doc: Value = serde_json::from_slice(&fs::read(&source).unwrap()).unwrap();
    doc["feed"].as_object_mut().unwrap().remove("generated_at");
    doc["sig"]["value"] = "invalid".into();
    let bytes = duplicate(&serde_json::to_vec(&doc).unwrap(), "domain", "\\u0064omain");
    fs::write(source, bytes).unwrap();
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
    let rejected = db.list_rejections(&host).unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].code, "WIST2-E01");
    assert!(rejected[0]
        .detail
        .as_deref()
        .unwrap()
        .contains("duplicate JSON member name"));
}

#[test]
fn retained_duplicates_reject_without_draining_pending_or_recovery_entries() {
    for entry_type in [
        "publisher_declaration",
        "publisher_delta",
        "registry_update",
        "queued",
    ] {
        let data = tempfile::tempdir().unwrap();
        clave::init::run("localhost", data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let p = make_publisher("localhost");
        let id = add_delta(&p, "https://localhost/article", "body", None);
        let (doc, name) = match entry_type {
            "publisher_declaration" => (current_declaration(&p), "domain"),
            "registry_update" => (
                wist_core::envelope::sign_envelope(
                    &json!({"action":"parameter_change", "subject":"quota_base"}),
                    "update",
                    "k1",
                    &p.sk,
                )
                .unwrap(),
                "action",
            ),
            _ => (
                serde_json::from_slice(
                    &fs::read(
                        p.dir
                            .path()
                            .join(format!(".well-known/wist/deltas/{}.json", &id[7..])),
                    )
                    .unwrap(),
                )
                .unwrap(),
                "bytes",
            ),
        };
        let raw = duplicate(&serde_json::to_vec(&doc).unwrap(), name, name);
        let conn = Connection::open(&path).unwrap();
        if entry_type == "queued" {
            conn.execute(
                "INSERT INTO queued_deltas(domain, delta_id, entry_json, url, chain_pos) VALUES ('localhost', ?1, ?2, 'https://localhost/article', 0)",
                (&id, &raw),
            ).unwrap();
        } else {
            conn.execute(
                "INSERT INTO pending_entries(entry_type, domain, entry_json, chain_pos) VALUES (?1, 'localhost', ?2, 0)",
                (entry_type, &raw),
            ).unwrap();
        }
        drop(db);
        let db = Db::open(&path).unwrap();
        let err = if entry_type == "queued" {
            db.drain_queued_deltas("localhost").err().unwrap()
        } else {
            assert!(db.peek_pending_entries().is_err());
            db.drain_pending_entries().err().unwrap()
        };
        assert!(err.to_string().contains("duplicate JSON member name"));
        let table = if entry_type == "queued" {
            "queued_deltas"
        } else {
            "pending_entries"
        };
        let retained: Vec<u8> = conn
            .query_row(&format!("SELECT entry_json FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(retained, raw);
        if matches!(entry_type, "publisher_delta" | "queued") {
            conn.execute_batch("DROP TABLE delta_index_reconciliation")
                .unwrap();
            assert!(Db::open(&path)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate JSON member name"));
        }
    }
}

#[test]
fn retained_declaration_duplicates_cannot_authorize_a_pull() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z").unwrap();
    let original = db.get_publisher_declaration(&host).unwrap().unwrap();
    let raw = duplicate(&original, "public_key", "public_\\u006bey");
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
