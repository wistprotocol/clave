mod common;

use common::spec_dir;
use serde_json::{json, Value};
use wist_core::item::SizeCaps;
use wist_core::objects::PageItem;

fn caps(case: &Value) -> SizeCaps {
    let cap = |name: &str, default: i64| case["caps"][name].as_i64().unwrap_or(default);
    SizeCaps::new(
        2048,
        cap("extract_cap_bytes", 32768),
        cap("links_cap_bytes", 4096),
        cap("link_url_cap_bytes", 2048),
        cap("summary_cap_bytes", 2048),
    )
    .unwrap()
}

#[test]
fn payload_field_vectors_are_judged_against_their_item_with_an_allowed_code() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/payload-fields.json")).unwrap(),
    )
    .unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let original = case.clone();
        let item: PageItem = serde_json::from_value(case["item"].clone()).unwrap();
        let raw = case["payload_json"]
            .as_str()
            .map(|raw| raw.as_bytes().to_vec())
            .unwrap_or_else(|| serde_json::to_vec(&case["payload"]).unwrap());
        let allowed = case["allowed"].as_array().unwrap();
        match clave::payload::judge(&item, &raw, &caps(case)) {
            Ok(_) => assert!(allowed.is_empty(), "{}", case["name"]),
            Err(code) => assert!(allowed.contains(&json!(code)), "{}: {code}", case["name"]),
        }
        assert_eq!(*case, original);
    }
}

#[test]
fn a_retained_payload_is_read_from_the_path_its_item_names_and_judged_against_it() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/payload-fields.json")).unwrap(),
    )
    .unwrap();
    let case = &vector["cases"][0];
    assert_eq!(case["name"], "valid");
    let source = clave::history::payloads::PayloadSource::from_item(
        case["item"].clone(),
        0,
        SizeCaps::suite(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(format!(
        "payloads/{}.json",
        wist_core::item::payload_name(&case["item"]).unwrap()
    ));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec(&case["payload"]).unwrap()).unwrap();
    let retrieved = source.read(directory.path()).unwrap();
    assert_eq!(
        retrieved.location(),
        &clave::history::payloads::PayloadLocation::File(path.clone())
    );
    let mut altered = case["payload"].clone();
    altered["content"]["extract"] = "Altered".into();
    std::fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(matches!(
        source.read(directory.path()),
        Err(clave::Error::Payload("WIST1-E10"))
    ));
}

fn vector_item(p: &common::TestPub, case: &Value, index: usize) -> (Value, Vec<u8>) {
    let preimage = common::to_vector_host(&case["preimage"]);
    let mut item = common::to_vector_host(&case["item"]);
    item["publisher"] = p.domain.clone().into();
    item["url"] = format!("https://{}/field-case-{index}", p.domain).into();
    item["payload"]["commitment"] =
        wist_core::item::commitment(preimage["salt"].as_str().unwrap(), &preimage["content"])
            .unwrap()
            .into();
    let octets = |content: &Value| wist_core::jcs::canonicalize(content).unwrap().len() as i64;
    item["payload"]["bytes"] = (item["payload"]["bytes"].as_i64().unwrap()
        + octets(&preimage["content"])
        - octets(&case["preimage"]["content"]))
    .into();
    let raw = match case["payload_json"].as_str() {
        Some(raw) => raw.replace("example.com", common::VECTOR_HOST).into_bytes(),
        None => serde_json::to_vec(&common::to_vector_host(&case["payload"])).unwrap(),
    };
    (item, raw)
}

#[test]
fn payload_field_vectors_are_judged_at_a_pull_and_the_judgment_holds_after_restart() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/payload-fields.json")).unwrap(),
    )
    .unwrap();
    let (listener, client, p) = common::vector_site();
    common::serve_static(listener, p.dir.path().to_path_buf());
    let mut items = Vec::new();
    let mut cases = Vec::new();
    for (index, case) in vector["cases"].as_array().unwrap().iter().enumerate() {
        if case.get("caps").is_some() {
            continue;
        }
        let (item, raw) = vector_item(&p, case, index);
        items.push((item.clone(), None));
        cases.push((item, raw, case));
    }
    common::publish_collection(&p, "default", &items, "2026-08-09T12:00:00Z", None);
    let payloads = common::collection_dir(&p, "default").join("payloads");
    for (item, raw, _) in &cases {
        std::fs::write(
            payloads.join(format!(
                "{}.json",
                wist_core::item::payload_name(item).unwrap()
            )),
            raw,
        )
        .unwrap();
    }
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&p.domain, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let db = clave::db::Db::open(&path).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &p.domain, "2026-08-09T12:00:02Z").unwrap();
    assert!(!report.suspended && report.noise.is_none());
    let mut admitted = 0;
    for (item, _, case) in &cases {
        let allowed = case["allowed"].as_array().unwrap();
        match common::effective_code(&db, &p.domain, item, &report) {
            None => {
                assert!(allowed.is_empty(), "{}", case["name"]);
                admitted += 1;
            }
            Some(code) => assert!(allowed.contains(&json!(code)), "{}: {code}", case["name"]),
        }
    }
    assert_eq!(report.items.len(), admitted);
    assert_eq!(common::payload_files(data.path()), admitted);
    drop(db);
    let db = clave::db::Db::open(&path).unwrap();
    let repeated =
        clave::ingest::run(&db, &client, data.path(), &p.domain, "2026-08-09T12:00:03Z").unwrap();
    assert!(
        repeated.items.is_empty(),
        "an admitted Item is not judged again"
    );
    assert_eq!(
        repeated.rejected.len(),
        cases.len() - admitted,
        "every Item not admitted is judged again and refused again"
    );
}
