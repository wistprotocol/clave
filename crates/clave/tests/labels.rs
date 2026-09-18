mod common;

use common::{make_publisher, make_publisher_with_scope, reserve_addr, serve_static, write_feed};
use serde_json::{json, Value};
use std::fs;

const SEAL_START: i64 = 1_786_276_800;

fn sign(p: &common::TestPub, inner_name: &str, inner: Value) -> (String, Value) {
    let id = wist_core::label::label_id(&inner).unwrap();
    let envelope = wist_core::envelope::sign_envelope(&inner, inner_name, &p.kid, &p.sk).unwrap();
    (id, envelope)
}

fn write_listed(p: &common::TestPub, host: &str, items: &[(String, Value)], generated_at: &str) {
    let dir = p.dir.path().join(".well-known/wist/labels");
    fs::create_dir_all(&dir).unwrap();
    for (id, envelope) in items {
        fs::write(
            dir.join(format!("{}.json", &id[7..])),
            serde_json::to_vec(envelope).unwrap(),
        )
        .unwrap();
    }
    let ids: Vec<&str> = items.iter().map(|(id, _)| id.as_str()).collect();
    let feed = json!({"wist_version": "1.0.0", "domain": host, "generated_at": generated_at, "deltas": ids, "next": null});
    let envelope = wist_core::envelope::sign_envelope(&feed, "feed", &p.kid, &p.sk).unwrap();
    fs::write(
        p.dir.path().join(".well-known/wist/label-feed.json"),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
}

fn state_entries(data: &std::path::Path) -> Vec<Value> {
    let read = |path: &std::path::Path| -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    };
    let index = read(&data.join("snapshots/index.json"));
    let manifest_url = index["index"]["snapshots"][0]["manifest_url"]
        .as_str()
        .unwrap()
        .trim_start_matches('/')
        .to_string();
    let manifest_path = data.join(&manifest_url);
    let manifest = read(&manifest_path);
    let files: Vec<&str> = manifest["manifest"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    for table in [
        "tier1/labels.parquet",
        "tier1/disputes.parquet",
        "tier1/labelers.parquet",
    ] {
        assert!(files.contains(&table), "{files:?}");
        assert!(manifest_path.parent().unwrap().join(table).exists());
    }
    let state_path = manifest_path
        .parent()
        .unwrap()
        .join(manifest["manifest"]["state"]["path"].as_str().unwrap());
    read(&state_path)["state"]["entries"]
        .as_array()
        .unwrap()
        .clone()
}

fn label(labeler: &str, subject: &str, name: &str, asserted_at: &str) -> Value {
    json!({"wist_version": "1.0.0", "labeler": labeler, "subject": subject, "name": name, "asserted_at": asserted_at})
}

#[test]
fn labels_and_disputes_are_pulled_sealed_and_carried() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let subject = "https://reduced.example.org/notice";
    let mut valid = label(&host, subject, "wist:spam", "2026-08-09T12:00:00Z");
    valid["value"] = 500_000.into();
    let (id, envelope) = sign(&p, "label", valid);
    let (self_id, self_envelope) = sign(
        &p,
        "label",
        label(
            &host,
            &format!("https://{host}/about"),
            "wist:spam",
            "2026-08-09T12:00:00Z",
        ),
    );
    let (bad_id, bad_envelope) = sign(
        &p,
        "label",
        label(&host, "example.com", "wist:unknown", "2026-08-09T12:00:00Z"),
    );
    write_listed(
        &p,
        &host,
        &[
            (id.clone(), envelope.clone()),
            (self_id.clone(), self_envelope),
            (bad_id.clone(), bad_envelope),
        ],
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(report.labels, vec![id.clone()]);
    assert_eq!(
        report.rejected,
        vec![
            (self_id.clone(), "WIST2-E06".to_string()),
            (bad_id.clone(), "WIST2-E06".to_string())
        ]
    );
    assert_eq!(report.noise, None);
    let rejections = db.list_rejections(&host).unwrap();
    assert!(rejections
        .iter()
        .any(|r| r.code == "WIST2-E06" && r.delta_id.as_deref() == Some(self_id.as_str())));

    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let r0 = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    assert_eq!((r0.epoch_number, r0.entry_count), (0, 2));
    assert_eq!(db.epoch_entries(0).unwrap()[1]["type"], "label");
    let sealed = db.sealed_labels().unwrap();
    assert_eq!(sealed.len(), 1);
    assert_eq!((sealed[0].height, sealed[0].entry_index), (0, 1));
    assert_eq!(
        db.sealed_label_subject(&id).unwrap().as_deref(),
        Some(subject)
    );
    let entries = state_entries(data.path());
    assert!(entries.contains(&json!([
        "label",
        host,
        subject,
        "wist:spam",
        500_000,
        "2026-08-09T12:00:00Z",
        null,
        null,
        id,
        0
    ])));

    let again =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:30:00Z").unwrap();
    assert!(again.labels.is_empty());
    assert_eq!(again.rejected.len(), 2, "rejected Labels are pulled again");
    assert_eq!(again.noise, None);

    let disputant_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    disputant_listener.set_nonblocking(true).unwrap();
    let disputant = "disputant.localhost".to_string();
    let disputant_client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve(&disputant, disputant_listener.local_addr().unwrap()),
    );
    let d = make_publisher_with_scope(&disputant, &["reduced.example.org"]);
    write_feed(&d, &disputant, &[], "2026-08-09T13:00:00Z");
    let (dispute_id, dispute_envelope) = sign(
        &d,
        "dispute",
        json!({"wist_version": "1.0.0", "disputant": disputant, "label": id, "log": "log.example", "height": 0, "reason": "https://reduced.example.org/why", "asserted_at": "2026-08-09T13:00:00Z"}),
    );
    let unknown = format!("sha256:{}", "f".repeat(64));
    let (unsealed_id, unsealed_envelope) = sign(
        &d,
        "dispute",
        json!({"wist_version": "1.0.0", "disputant": disputant, "label": unknown, "log": "log.example", "height": 0, "asserted_at": "2026-08-09T13:00:00Z"}),
    );
    write_listed(
        &d,
        &disputant,
        &[
            (dispute_id.clone(), dispute_envelope),
            (unsealed_id.clone(), unsealed_envelope),
        ],
        "2026-08-09T13:00:00Z",
    );
    serve_static(disputant_listener, d.dir.path().to_path_buf());
    let report = clave::ingest::run(
        &db,
        &disputant_client,
        data.path(),
        &disputant,
        "2026-08-09T13:00:00Z",
    )
    .unwrap();
    assert_eq!(
        report.labels,
        vec![dispute_id.clone()],
        "rejected {:?} noise {:?} rejections {:?}",
        report.rejected,
        report.noise,
        db.list_rejections(&disputant).unwrap()
    );
    assert_eq!(
        report.rejected,
        vec![(unsealed_id, "WIST2-E06".to_string())]
    );

    let retraction = {
        let mut inner = label(&host, subject, "wist:spam", "2026-08-09T14:00:00Z");
        inner["retracted"] = true.into();
        sign(&p, "label", inner)
    };
    write_listed(
        &p,
        &host,
        &[(id.clone(), envelope), retraction.clone()],
        "2026-08-09T14:00:00Z",
    );
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T14:00:00Z").unwrap();
    assert_eq!(report.labels, vec![retraction.0.clone()]);

    let r1 = clave::seal::run(&db, data.path(), &sk, SEAL_START + 3600).unwrap();
    assert_eq!((r1.epoch_number, r1.entry_count), (1, 3));
    let sealed_entries = db.epoch_entries(1).unwrap();
    let types: Vec<&str> = sealed_entries
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["publisher_declaration", "label", "dispute"]);
    let entries = state_entries(data.path());
    assert!(!entries.iter().any(|e| e[0] == "label"), "{entries:?}");
    assert!(entries.contains(&json!([
        "dispute",
        id,
        disputant,
        "https://reduced.example.org/why",
        "2026-08-09T13:00:00Z",
        1
    ])));
    assert_eq!(db.sealed_labels().unwrap().len(), 2);
    assert_eq!(db.sealed_disputes().unwrap().len(), 1);
}
