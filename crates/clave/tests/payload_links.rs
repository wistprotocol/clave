mod common;

use common::spec_dir;
use serde_json::{json, Value};
use wist_core::objects::PageItem;

#[test]
fn payload_link_vectors_are_judged_against_their_item() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/payload-links.json")).unwrap(),
    )
    .unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let item: PageItem = serde_json::from_value(case["item"].clone()).unwrap();
        let raw = serde_json::to_vec(&case["payload"]).unwrap();
        let judged = clave::payload::judge(&item, &raw, &Default::default());
        assert_eq!(json!(judged.err()), case["expected"], "{}", case["name"]);
    }
}

#[test]
fn payload_link_vectors_are_judged_at_a_pull_and_the_judgment_holds_after_restart() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/payload-links.json")).unwrap(),
    )
    .unwrap();
    let (listener, client, p) = common::vector_site();
    common::serve_static(listener, p.dir.path().to_path_buf());
    let mut items = Vec::new();
    let mut cases = Vec::new();
    for case in vector["cases"].as_array().unwrap() {
        let payload = common::to_vector_host(&case["payload"]);
        let mut item = common::to_vector_host(&case["item"]);
        item["payload"]["commitment"] =
            wist_core::item::commitment(payload["salt"].as_str().unwrap(), &payload["content"])
                .unwrap()
                .into();
        item["payload"]["bytes"] = wist_core::jcs::canonicalize(&payload["content"])
            .unwrap()
            .len()
            .into();
        items.push((item.clone(), Some(payload)));
        cases.push((item, case));
    }
    common::publish_collection(&p, "default", &items, "2026-08-09T12:00:00Z", None);
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&p.domain, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &p.domain, "2026-08-09T12:00:02Z").unwrap();
    let mut admitted = 0;
    for (item, case) in &cases {
        let code = common::effective_code(&db, &p.domain, item, &report);
        admitted += usize::from(code.is_none());
        assert_eq!(json!(code), case["expected"], "{}", case["name"]);
    }
    assert_eq!(common::payload_files(data.path()), admitted);
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let repeated =
        clave::ingest::run(&db, &client, data.path(), &p.domain, "2026-08-09T12:00:03Z").unwrap();
    assert!(repeated.items.is_empty());
    assert_eq!(repeated.rejected.len(), cases.len() - admitted);
}
