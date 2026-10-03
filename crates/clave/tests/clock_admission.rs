mod common;

use common::*;
use serde_json::json;

fn queued(report: &clave::ingest::IngestReport, catalog: &Published) -> bool {
    report
        .queued
        .contains(&format!("default/{}", catalog.catalog_id))
}

#[test]
fn excess_skew_cannot_enter_a_recovery_queue() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_recovery(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let seal = |db: &clave::db::Db, at: &str| {
        clave::seal::run(
            db,
            data.path(),
            &sk,
            wist_core::timestamp::log_seconds(at).unwrap(),
        )
        .unwrap()
    };
    pull_at(&db, &client, data.path(), &host, "2026-08-09T11:00:00Z");
    seal(&db, "2026-08-09T11:00:00Z");
    let previous = current_declaration(&p);
    let mut recovery = previous["publisher"].clone();
    recovery["seq"] = json!(1);
    recovery["prev_declaration"] = json!(declaration_hash(&previous));
    recovery["keys"] = json!([key_entry(&K2_SEED, "2026-08-09T12:00:00Z")]);
    write_declaration(&p, &recovery, &R1_SEED);
    let a = page_item(&p, &format!("https://{host}/a"), "first");
    let b = page_item(&p, &format!("https://{host}/b"), "later");
    let at_bound = publish_collection_signed(
        &p,
        "default",
        &[(a.0.clone(), Some(a.1.clone()))],
        "2026-08-09T12:10:00Z",
        None,
        &K2_SEED,
    );
    let report = pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z");
    assert!(queued(&report, &at_bound), "{report:?}");
    let beyond = publish_collection_signed(
        &p,
        "default",
        &[
            (a.0.clone(), Some(a.1.clone())),
            (b.0.clone(), Some(b.1.clone())),
        ],
        "2026-08-09T12:10:01Z",
        Some(&at_bound),
        &K2_SEED,
    );
    let report = pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z");
    assert!(!queued(&report, &beyond), "{report:?}");
    let [(object, code)] = &report.rejected[..] else {
        panic!("{report:?}");
    };
    assert_eq!(object, &format!("default/{}", beyond.catalog_id));
    assert!(
        ["WIST1-E06", "WIST1-E02"].contains(&code.as_str()),
        "the Catalog fails the clock under the owner and the binding under the source before the recovery: {code}"
    );
    assert!(!clave::db::held_payload_path(data.path(), &item_id(&b.0))
        .unwrap()
        .exists());
    seal(&db, "2026-08-09T12:00:00Z");
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let report = pull_at(&db, &client, data.path(), &host, "2026-08-09T12:00:01Z");
    assert!(queued(&report, &beyond), "{report:?}");
    assert!(report.rejected.is_empty(), "{report:?}");
    seal(&db, "2026-08-16T12:00:00Z");
    seal(&db, "2026-08-16T13:00:00Z");
    let scope = std::collections::BTreeSet::from([host.clone()]);
    let state = db
        .load_state(db.sealed_state(data.path()).unwrap(), &scope)
        .unwrap();
    for (url, item) in [("a", &a.0), ("b", &b.0)] {
        assert_eq!(
            state
                .record(&host, &format!("https://{host}/{url}"))
                .map(|record| record.item_id.clone()),
            Some(item_id(item)),
            "{url}"
        );
    }
}
