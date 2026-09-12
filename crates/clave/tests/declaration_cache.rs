mod common;

use clave::db::Db;
use common::*;
use serde_json::json;

const INITIAL: &str = "2026-08-09T14:00:00Z";
const WITHIN_TTL: &str = "2026-08-09T15:00:00Z";
const EXPIRED: &str = "2026-08-10T14:00:01Z";

#[test]
fn rejected_declarations_cannot_extend_cached_key_authority() {
    for failure in ["fields", "sequence", "signature", "unavailable"] {
        let (listener, host, client) = reserve_addr();
        let p = make_publisher(&host);
        write_feed(&p, &host, &[], INITIAL);
        serve_static(listener, p.dir.path().into());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let path = data.path().join("clave.sqlite");
        let db = Db::open(&path).unwrap();
        clave::ingest::run(&db, &client, data.path(), &host, INITIAL).unwrap();
        let previous = current_declaration(&p);
        let mut rejected = previous.clone();
        rejected["publisher"]["seq"] = json!(1);
        rejected["publisher"]["prev_declaration"] = json!(declaration_hash(&previous));
        match failure {
            "fields" => rejected["publisher"]["unknown"] = json!(true),
            "sequence" => rejected["publisher"]["seq"] = json!(0),
            "signature" => {
                rejected["sig"]["value"] = json!(wist_core::crypto::b64u_encode(&[0; 64]))
            }
            "unavailable" => {}
            _ => unreachable!(),
        }
        let declaration_path = p.dir.path().join(".well-known/wist/publisher.json");
        if failure == "unavailable" {
            std::fs::remove_file(&declaration_path).unwrap();
        } else {
            std::fs::write(&declaration_path, serde_json::to_vec(&rejected).unwrap()).unwrap();
        }
        let first = add_delta(&p, "https://localhost/a", "within TTL", None);
        write_feed(&p, &host, std::slice::from_ref(&first), WITHIN_TTL);
        let report = clave::ingest::run(&db, &client, data.path(), &host, WITHIN_TTL).unwrap();
        assert_eq!(report.accepted, [first], "{failure}: {report:?}");
        assert_eq!(
            db.declaration_fetched_at(&host).unwrap().as_deref(),
            Some(INITIAL)
        );
        drop(db);
        let db = Db::open(&path).unwrap();
        let second = add_delta(&p, "https://localhost/b", "expired TTL", None);
        write_feed(&p, &host, std::slice::from_ref(&second), EXPIRED);
        let report = clave::ingest::run(&db, &client, data.path(), &host, EXPIRED).unwrap();
        assert!(report.accepted.is_empty(), "{failure}: {report:?}");
        assert!(report.queued.is_empty());
        assert!(!db.is_delta_seen_for(&second, &host).unwrap());
        assert!(!data
            .path()
            .join(format!("payloads/{}.json", &second[7..]))
            .exists());
        assert_eq!(
            db.list_rejections(&host).unwrap().first().unwrap().code,
            "WIST1-E02"
        );
        assert_eq!(
            db.declaration_fetched_at(&host).unwrap().as_deref(),
            Some(INITIAL)
        );
        assert_eq!(
            db.get_publisher_declaration(&host).unwrap().unwrap(),
            serde_json::to_vec(&previous).unwrap()
        );
    }
}

#[test]
fn valid_unchanged_discovery_renews_the_cache_after_expiry() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], INITIAL);
    serve_static(listener, p.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, INITIAL).unwrap();
    let id = add_delta(&p, "https://localhost/a", "renewed", None);
    write_feed(&p, &host, std::slice::from_ref(&id), EXPIRED);
    let report = clave::ingest::run(&db, &client, data.path(), &host, EXPIRED).unwrap();
    assert_eq!(report.accepted, [id]);
    assert_eq!(
        db.declaration_fetched_at(&host).unwrap().as_deref(),
        Some(EXPIRED)
    );
    assert!(db.list_rejections(&host).unwrap().is_empty());
}

#[test]
fn exhausted_discovery_budget_preserves_suspension_even_when_the_cache_expired() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], INITIAL);
    serve_static(listener, p.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, INITIAL).unwrap();
    db.set_param("ingest_budget_bytes_day", 1).unwrap();
    db.add_ingest_bytes(&host, "2026-08-10", 1).unwrap();
    let report = clave::ingest::run(&db, &client, data.path(), &host, EXPIRED).unwrap();
    assert!(report.suspended);
    assert_eq!(report.noise, None);
    assert!(db.walk_suspended(&host).unwrap());
    assert!(db.list_rejections(&host).unwrap().is_empty());
    assert_eq!(
        db.declaration_fetched_at(&host).unwrap().as_deref(),
        Some(INITIAL)
    );
}
