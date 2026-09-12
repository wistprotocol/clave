use clave::db::Db;
use rusqlite::Connection;
use serde_json::json;

fn remove_order(connection: &Connection) {
    connection
        .execute_batch(
            "DROP TRIGGER pending_entries_assign_order;
         DROP TRIGGER queued_deltas_assign_order;
         DROP INDEX pending_entries_acceptance_order;
         DROP INDEX queued_deltas_acceptance_order;
         ALTER TABLE pending_entries DROP COLUMN acceptance_order;
         ALTER TABLE queued_deltas DROP COLUMN acceptance_order;
         DROP TABLE acceptance_clock;",
        )
        .unwrap();
}

#[test]
fn legacy_multiple_delta_copies_require_independent_order_evidence() {
    for placement in ["pending", "queued", "mixed"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        for (position, id) in ["b", "a"].into_iter().enumerate() {
            let url = format!("https://example.com/{id}");
            let body = json!({"delta": {"publisher": "example.com", "url": url}});
            if placement == "queued" || placement == "mixed" && position == 0 {
                db.queue_delta("example.com", id, &body, &url, id, 0)
                    .unwrap();
            } else {
                db.record_accepted_delta("example.com", id, &body, 0, &url, id)
                    .unwrap();
            }
        }
        drop(db);
        let connection = Connection::open(&path).unwrap();
        remove_order(&connection);
        for _ in 0..2 {
            let error = Db::open(&path).err().expect("unrecoverable legacy order");
            assert!(
                error.to_string().contains("provable acceptance order"),
                "{placement}: {error}"
            );
            let missing: i64 = connection.query_row(
                "SELECT (SELECT COUNT(*) FROM pending_entries WHERE acceptance_order IS NULL) + (SELECT COUNT(*) FROM queued_deltas WHERE acceptance_order IS NULL)", [], |row| row.get(0),
            ).unwrap();
            assert_eq!(missing, 2);
            let seen: i64 = connection
                .query_row("SELECT COUNT(*) FROM seen_deltas", [], |row| row.get(0))
                .unwrap();
            assert_eq!(seen, 2);
        }
    }
}

#[test]
fn legacy_single_copy_per_domain_restores_without_inventing_relative_order() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("clave.sqlite");
    let db = Db::open(&path).unwrap();
    db.record_accepted_delta(
        "a.example",
        "a",
        &json!({"delta": {"url": "https://a.example/"}}),
        0,
        "https://a.example/",
        "a",
    )
    .unwrap();
    db.queue_delta(
        "b.example",
        "b",
        &json!({"delta": {"url": "https://b.example/"}}),
        "https://b.example/",
        "b",
        0,
    )
    .unwrap();
    drop(db);
    let connection = Connection::open(&path).unwrap();
    remove_order(&connection);
    for _ in 0..2 {
        let db = Db::open(&path).unwrap();
        assert!(db.is_delta_seen_for("a", "a.example").unwrap());
        assert!(db.is_delta_seen_for("b", "b.example").unwrap());
        assert_eq!(db.peek_pending_entries().unwrap().0.len(), 1);
        let positions: (i64, i64) = connection.query_row(
            "SELECT (SELECT acceptance_order FROM pending_entries), (SELECT acceptance_order FROM queued_deltas)", [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(positions, (1, 2));
    }
}

#[test]
fn acceptance_counter_exhaustion_rolls_back_seen_tip_and_queue_changes() {
    for queued in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute("UPDATE acceptance_clock SET position = ?1", [i64::MAX])
            .unwrap();
        let body = json!({"delta": {"publisher": "example.com", "url": "https://example.com/"}});
        let result = if queued {
            db.queue_delta("example.com", "id", &body, "https://example.com/", "id", 0)
        } else {
            db.record_accepted_delta("example.com", "id", &body, 0, "https://example.com/", "id")
        };
        assert!(result.is_err());
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(!db.is_delta_seen("id").unwrap());
        assert!(db
            .url_tip("example.com", "https://example.com/")
            .unwrap()
            .is_none());
        assert!(db.peek_pending_entries().unwrap().0.is_empty());
        assert!(db.drain_queued_deltas("example.com").unwrap().is_empty());
    }
}
