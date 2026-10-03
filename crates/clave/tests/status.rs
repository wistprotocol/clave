mod common;

use common::*;
use serde_json::Value;

fn status(r: &Rig) -> Value {
    let status = clave::serve::load_status(&r.db, &r.host).unwrap().unwrap();
    let value = serde_json::to_value(&status).unwrap();
    assert_valid("status.schema.json", &value);
    value
}

fn waiting(status: &Value) -> Vec<(Option<String>, Vec<String>, bool)> {
    status["collections"][0]["waiting"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["url"].as_str().map(str::to_owned),
                entry["deferrals"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|deferral| deferral.as_str().unwrap().to_owned())
                    .collect(),
                entry["held"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[test]
fn status_lists_the_waiting_catalog_and_items_with_the_deferrals_of_the_last_seal() {
    let r = Rig::new();
    let items: Vec<(Value, Option<Value>)> = (0..3)
        .map(|n| {
            let (item, payload) = r.page(&format!("p{n}"), "body");
            (item, Some(payload))
        })
        .collect();
    let published = r.publish(&items, "2026-08-09T12:00:00Z", None);
    r.db.set_param("domain_epoch_entries_max", 2).unwrap();
    r.pull("2026-08-09T12:00:05Z");
    let pulled = status(&r);
    let collection = &pulled["collections"][0];
    assert_eq!(collection["name"], "default");
    assert_eq!(collection["accepted"], published.catalog_id.as_str());
    assert_eq!(
        collection["waiting"][0]["id"],
        published.catalog_id.as_str()
    );
    assert!(waiting(&pulled)
        .iter()
        .all(|(_, deferrals, held)| deferrals.is_empty() && !held));
    assert_eq!(waiting(&pulled).len(), 4);

    r.seal("2026-08-09T13:00:00Z");
    let sealed = status(&r);
    assert_eq!(
        sealed["collections"][0]["latest"],
        published.catalog_id.as_str()
    );
    let rows = waiting(&sealed);
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|(url, deferrals, held)| url.is_some() && deferrals == &["capacity"] && !held));
}

#[test]
fn a_waiting_item_kept_out_by_an_authority_reducing_declaration_alone_is_held() {
    let r = Rig::new();
    let (item, payload) = r.page("p", "body");
    r.publish(
        &[(item.clone(), Some(payload))],
        "2026-08-09T12:00:00Z",
        None,
    );
    r.pull("2026-08-09T12:00:05Z");
    let connection = rusqlite::Connection::open(r.data.path().join("clave.sqlite")).unwrap();
    for (deferrals, held) in [
        (None, true),
        (Some(r#"["capacity","recovery_window"]"#), false),
    ] {
        connection
            .execute(
                "UPDATE waiting_urls SET deferrals = ?1, held = 'authority_reduction'",
                [deferrals],
            )
            .unwrap();
        let rows = waiting(&status(&r));
        let item_row = rows.iter().find(|(url, _, _)| url.is_some()).unwrap();
        assert_eq!(item_row.2, held);
        if deferrals.is_some() {
            assert_eq!(item_row.1, ["recovery_window", "capacity"]);
        }
    }
}

#[test]
fn a_status_lists_a_collection_the_declaration_names_before_any_catalog_is_accepted() {
    let r = Rig::new();
    std::fs::remove_file(collection_dir(&r.p, "default").join("catalog.json")).unwrap();
    r.pull("2026-08-09T12:00:05Z");
    let status = status(&r);
    assert_eq!(
        status["collections"],
        serde_json::json!([{"name": "default", "latest": null, "accepted": null, "waiting": []}])
    );
}

fn names(status: &Value) -> Vec<String> {
    status["collections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|collection| collection["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_status_names_the_collections_of_the_sealed_declaration_in_force_beside_a_discovered_one() {
    let r = Rig::new();
    let url = |path: &str| r.url(path);
    let mut first = current_declaration(&r.p)["publisher"].clone();
    first["collections"] = serde_json::json!([
        {"name": "journal", "scope": [{"url": url("journal/"), "match": "prefix"}]},
        {"name": "archive", "scope": [{"url": url("archive/"), "match": "prefix"}]},
    ]);
    write_declaration(&r.p, &first, &K1_SEED);
    r.pull("2026-08-09T12:00:05Z");
    r.seal("2026-08-09T13:00:00Z");
    let sealed = current_declaration(&r.p);
    let mut narrowed = sealed["publisher"].clone();
    narrowed["seq"] = 1.into();
    narrowed["prev_declaration"] = declaration_hash(&sealed).into();
    narrowed["collections"] = serde_json::json!([
        {"name": "journal", "scope": [{"url": url("journal/"), "match": "prefix"}]},
    ]);
    write_declaration(&r.p, &narrowed, &K1_SEED);
    r.pull("2026-08-09T13:30:00Z");
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 1);
    assert_eq!(names(&status(&r)), ["archive", "journal"]);
}

#[test]
fn a_status_with_a_long_host_failure_detail_and_a_refused_non_https_item_url_meets_its_schema() {
    let host = format!(
        "{}.{}.{}.{}.localhost",
        "a".repeat(50),
        "b".repeat(50),
        "c".repeat(50),
        "d".repeat(37)
    );
    assert_eq!(host.len(), 200);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve(&host, listener.local_addr().unwrap()),
    );
    let p = make_publisher(&host);
    let plain = page_item(&p, &format!("http://{host}/plain"), "plain");
    publish_collection(
        &p,
        "default",
        &[(plain.0.clone(), Some(plain.1.clone()))],
        "2026-08-09T11:00:00Z",
        None,
    );
    let missing = format!("sha256:{}", "0".repeat(64));
    write_label_feed(
        &p,
        &host,
        std::slice::from_ref(&missing),
        "2026-08-09T11:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let rejections = db.list_rejections(&host).unwrap();
    let label = rejections
        .iter()
        .find(|rejection| rejection.id.as_deref() == Some(missing.as_str()))
        .unwrap_or_else(|| panic!("{rejections:?}"));
    assert!(label.detail.as_ref().unwrap().contains(&host[..100]));
    assert_eq!(label.detail.as_ref().unwrap().chars().count(), 256);
    let refused = rejections
        .iter()
        .find(|rejection| rejection.id.as_deref() == Some(item_id(&plain.0).as_str()))
        .unwrap_or_else(|| panic!("{rejections:?}"));
    assert_eq!(refused.code, "WIST1-E03");
    assert_eq!(refused.urls, None);
    let status = clave::serve::load_status(&db, &host).unwrap().unwrap();
    assert_valid(
        "status.schema.json",
        &serde_json::to_value(&status).unwrap(),
    );
}
