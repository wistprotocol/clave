mod common;

use common::*;
use serde_json::{json, Value};
use std::fs;

fn write_delta(p: &TestPub, delta: &Value) -> String {
    let id = wist_core::delta::delta_id(delta).unwrap();
    let envelope = wist_core::envelope::sign_envelope(delta, "delta", "k1", &p.sk).unwrap();
    fs::write(
        p.dir
            .path()
            .join(format!(".well-known/wist/deltas/{}.json", &id[7..])),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    id
}

#[test]
fn feed_rejects_foreign_authors_before_seen_ids_and_fetched_predecessors() {
    for seen in [false, true] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher_with_scope(&host, &["example.com"]);
        let local_id = add_delta(&p, "https://example.com/a", "body", None);
        let local: Value = serde_json::from_slice(
            &fs::read(
                p.dir
                    .path()
                    .join(format!(".well-known/wist/deltas/{}.json", &local_id[7..])),
            )
            .unwrap(),
        )
        .unwrap();
        let mut foreign = local["delta"].clone();
        foreign["publisher"] = json!("example.com");
        foreign["prev"] = json!(format!("sha256:{}", "0".repeat(64)));
        let foreign_id = write_delta(&p, &foreign);
        let mut child = foreign.clone();
        child["publisher"] = json!(host);
        child["prev"] = json!(foreign_id);
        child["observed_at"] = json!("2026-08-09T12:00:01Z");
        let child_id = write_delta(&p, &child);
        serve_static(listener, p.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = clave::db::Db::open(&path).unwrap();
        if seen {
            db.insert_seen_delta(&foreign_id, "example.com").unwrap();
        }
        drop(db);
        let db = clave::db::Db::open(&path).unwrap();
        for candidate in [&foreign_id, &child_id] {
            write_feed(
                &p,
                &host,
                std::slice::from_ref(candidate),
                "2026-08-09T12:00:02Z",
            );
            let report =
                clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:02Z")
                    .unwrap();
            assert!(report.accepted.is_empty() && report.queued.is_empty());
            assert!(
                report
                    .rejected
                    .contains(&(foreign_id.clone(), "WIST2-E03".into())),
                "{seen} {candidate}: {report:?}"
            );
            if candidate == &child_id {
                assert!(
                    report
                        .rejected
                        .contains(&(child_id.clone(), "WIST1-E07".into())),
                    "{report:?}"
                );
            }
            assert!(!db.is_delta_seen_for(candidate, &host).unwrap());
            assert!(db
                .url_tip(&host, "https://example.com/a")
                .unwrap()
                .is_none());
        }
    }
}

#[test]
fn malformed_signed_publisher_rejects_before_binding_and_feed_association() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let mut ids = Vec::new();
    for publisher in [
        Value::Null,
        json!(7),
        json!("LOCALHOST"),
        json!("localhost."),
        json!("localhost:80"),
        json!(""),
    ] {
        let inner = json!({"wist_version":"1.0.0", "publisher":publisher, "url":"https://localhost/a", "change_type":"delete", "prev":format!("sha256:{}", "0".repeat(64)), "observed_at":"2026-08-09T12:00:00Z", "meta":{"lang":"en"}});
        ids.push(write_delta(&p, &inner));
    }
    let missing = json!({"wist_version":"1.0.0", "url":"https://localhost/a", "change_type":"delete", "observed_at":"2026-08-09T12:00:00Z", "meta":{"lang":"en"}});
    ids.push(write_delta(&p, &missing));
    write_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert!(report.accepted.is_empty() && report.queued.is_empty());
    assert_eq!(
        report.rejected,
        ids.iter()
            .map(|id| (id.clone(), "WIST1-E14".into()))
            .collect::<Vec<_>>()
    );
    for id in ids {
        assert!(!db.is_delta_seen(&id).unwrap());
    }
}

#[test]
fn orphaned_legacy_tips_are_cleared_before_publisher_scoped_updates() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("clave.sqlite");
    let url = "https://shared.example/a";
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE url_tips(url TEXT PRIMARY KEY, domain TEXT NOT NULL, tip TEXT NOT NULL);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO url_tips VALUES (?1, ?2, ?3)",
            (url, "first.example", "sha256:first"),
        )
        .unwrap();
    }
    let db = clave::db::Db::open(&path).unwrap();
    assert!(db.url_tip("first.example", url).unwrap().is_none());
    assert!(db.url_tip("second.example", url).unwrap().is_none());
    db.set_url_tip(url, "second.example", "sha256:second")
        .unwrap();
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    db.set_url_tip(url, "first.example", "sha256:first-update")
        .unwrap();
    assert_eq!(
        db.url_tip("first.example", url).unwrap().as_deref(),
        Some("sha256:first-update")
    );
    assert_eq!(
        db.url_tip("second.example", url).unwrap().as_deref(),
        Some("sha256:second")
    );
    assert_eq!(db.list_url_tips().unwrap().len(), 2);
}

#[test]
fn sealing_rejects_a_shared_key_delta_assigned_to_another_domain() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "body", None);
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let original: Value = serde_json::from_slice(
        &fs::read(
            p.dir
                .path()
                .join(format!(".well-known/wist/deltas/{}.json", &id[7..])),
        )
        .unwrap(),
    )
    .unwrap();
    let mut inner = original["delta"].clone();
    inner["publisher"] = json!("example.com");
    let foreign = wist_core::envelope::sign_envelope(&inner, "delta", "k1", &p.sk).unwrap();
    db.insert_pending_entry("publisher_delta", &host, &foreign, 0)
        .unwrap();
    let mut malformed_inner = inner.clone();
    malformed_inner["publisher"] = Value::Null;
    let malformed =
        wist_core::envelope::sign_envelope(&malformed_inner, "delta", "k1", &p.sk).unwrap();
    db.insert_pending_entry("publisher_delta", &host, &malformed, 0)
        .unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let at = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let sealed = clave::seal::run(&db, data.path(), &sk, at).unwrap();
    assert_eq!(sealed.entry_count, 1);
    assert_eq!(sealed.dropped.len(), 2);
    assert!(sealed
        .dropped
        .iter()
        .any(|error| error.contains("WIST1-E14")));
    assert!(sealed
        .dropped
        .iter()
        .any(|error| error.contains("WIST1-E02")));
    let bytes = fs::read(data.path().join("log/blocks/000000000.json.zst")).unwrap();
    let block: Value = serde_json::from_slice(&zstd::decode_all(&bytes[..]).unwrap()).unwrap();
    assert!(block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["type"] != "publisher_delta"));
}

#[test]
fn recovery_settlement_preserves_publisher_field_errors_in_corrupted_queues() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    write_feed(&p, &host, &[], "2026-08-09T11:00:00Z");
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T11:00:00Z").unwrap();
    let at = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    clave::seal::run(&db, data.path(), &sk, at - 3600).unwrap();
    let previous = current_declaration(&p);
    let mut recovery = previous["publisher"].clone();
    recovery["seq"] = json!(1);
    recovery["prev_declaration"] = json!(declaration_hash(&previous));
    recovery["keys"] = json!([key_entry("k2", &K2_SEED, "2026-08-09T12:00:00Z")]);
    write_declaration(&p, &recovery, "r1", &R1_SEED);
    write_feed_signed(&p, &host, &[], "2026-08-09T12:00:00Z", "k2", &K2_SEED);
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    clave::seal::run(&db, data.path(), &sk, at).unwrap();
    let signer = wist_core::crypto::SigningKey::from_seed(&K2_SEED);
    let mut expected = Vec::new();
    for (publisher, code) in [
        (json!("example.com"), "WIST1-E13"),
        (Value::Null, "WIST1-E14"),
    ] {
        let inner = json!({"wist_version":"1.0.0", "publisher":publisher, "url":"https://example.com/a", "change_type":"delete", "observed_at":"2026-08-09T12:00:00Z", "prev":format!("sha256:{}", "0".repeat(64)), "meta":{"lang":"en"}});
        let id = wist_core::delta::delta_id(&inner).unwrap();
        let envelope = wist_core::envelope::sign_envelope(&inner, "delta", "k2", &signer).unwrap();
        db.queue_delta(&host, &id, &envelope, "https://example.com/a", &id, 0)
            .unwrap();
        expected.push((id, code));
    }
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    clave::seal::run(&db, data.path(), &sk, at + 7 * 86400).unwrap();
    let rejected = db.list_rejections(&host).unwrap();
    for (id, code) in expected {
        assert!(rejected
            .iter()
            .any(|row| row.delta_id.as_deref() == Some(&id) && row.code == code));
    }
    assert!(db
        .get_record("https://example.com/a", &host)
        .unwrap()
        .is_none());
}
