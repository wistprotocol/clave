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
