mod common;

use common::{add_label, make_publisher_with_scope, reserve_addr, serve_static, write_label_feed};

const NOW: i64 = 1_800_000_000;

fn ts(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).unwrap().to_string()
}

struct Rig {
    host: String,
    _data: tempfile::TempDir,
    db: clave::db::Db,
    sk: wist_core::crypto::SigningKey,
    ids: Vec<String>,
}

fn rig(urls: &[&str]) -> Rig {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let ids: Vec<String> = urls
        .iter()
        .map(|url| {
            add_label(
                &p,
                &url.replace("example.com", "other.example"),
                "2026-08-09T11:00:00Z",
            )
        })
        .collect();
    write_label_feed(&p, &host, &ids, "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, &ts(NOW)).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    Rig {
        host,
        _data: data,
        db,
        sk,
        ids,
    }
}

#[test]
fn withdraw_refuses_an_id_that_names_no_item_sealed_for_the_subject() {
    let r = rig(&["https://example.com/a"]);
    let unknown = format!("sha256:{}", "f".repeat(64));
    assert!(matches!(
        clave::governance::withdraw(&r.db, &r.sk, &r.host, &unknown, "court order", "DE", NOW),
        Err(clave::Error::Governance(_))
    ));
    assert!(matches!(
        clave::governance::withdraw(&r.db, &r.sk, "other.example", &r.ids[0], "order", "DE", NOW),
        Err(clave::Error::Governance(_))
    ));
    assert!(matches!(
        clave::governance::withdraw(&r.db, &r.sk, &r.host, &r.ids[0], "order", "DE", NOW),
        Err(clave::Error::Governance(_))
    ));
    assert!(matches!(
        clave::governance::withdraw(&r.db, &r.sk, &r.host, "sha256:F00", "order", "DE", NOW),
        Err(clave::Error::Governance(_))
    ));
    assert!(r
        .db
        .peek_pending_entries()
        .unwrap()
        .0
        .iter()
        .all(|e| e.entry_type != "registry_update"));
}
