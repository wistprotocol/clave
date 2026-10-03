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
