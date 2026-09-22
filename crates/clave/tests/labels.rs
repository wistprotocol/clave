mod common;

use common::{
    make_publisher, make_publisher_with_scope, reserve_addr, serve_recording, serve_static,
    write_feed,
};
use serde_json::{json, Value};
use std::fs;

const SEAL_START: i64 = 1_786_276_800;

fn sign(p: &common::TestPub, inner_name: &str, inner: Value) -> (String, Value) {
    let id = wist_core::label::label_id(&inner).unwrap();
    let envelope = wist_core::envelope::sign_envelope(&inner, inner_name, &p.kid, &p.sk).unwrap();
    (id, envelope)
}

fn write_listed(p: &common::TestPub, host: &str, items: &[(String, Value)], generated_at: &str) {
    write_listed_with_next(p, host, items, generated_at, None);
}

fn write_listed_with_next(
    p: &common::TestPub,
    host: &str,
    items: &[(String, Value)],
    generated_at: &str,
    next: Option<&str>,
) {
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
    let feed = json!({"wist_version": "1.0.0", "domain": host, "generated_at": generated_at, "deltas": ids, "next": next});
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
fn a_label_feed_next_failing_the_target_rule_records_e01_and_keeps_the_labels() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let (id, envelope) = sign(
        &p,
        "label",
        label(
            &host,
            "https://reduced.example.org/notice",
            "wist:spam",
            "2026-08-09T12:00:00Z",
        ),
    );
    write_listed_with_next(
        &p,
        &host,
        &[(id.clone(), envelope)],
        "2026-08-09T12:00:00Z",
        Some("https://localhost:443/.well-known/wist/labels/0.json"),
    );
    let requests = serve_recording(listener, p.dir.path().to_path_buf());

    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(report.labels, vec![id]);
    assert!(report.rejected.is_empty());
    assert_eq!(report.noise, None);
    assert_eq!(
        report.ended, None,
        "the Label walk's stop is not the Feed's WIST2-E01 backoff"
    );
    let e01: Vec<_> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .filter(|r| r.code == "WIST2-E01" && r.delta_id.is_none())
        .collect();
    assert_eq!(e01.len(), 1);
    assert!(e01[0]
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("label feed next"));
    assert!(!requests
        .lock()
        .unwrap()
        .iter()
        .any(|uri| uri.contains("/labels/0.json")));
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

    let r1 = clave::seal::run(&db, data.path(), &sk, SEAL_START + 7200).unwrap();
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

fn is_e06_for(db: &clave::db::Db, host: &str, id: &str) -> bool {
    db.list_rejections(host)
        .unwrap()
        .iter()
        .any(|r| r.code == "WIST2-E06" && r.delta_id.as_deref() == Some(id))
}

#[test]
fn a_label_asserted_beyond_the_attempt_clock_allowance_is_rejected_and_pulled_again() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let subject = "https://reduced.example.org/notice";
    let at_bound = sign(
        &p,
        "label",
        label(&host, subject, "wist:spam", "2026-08-09T12:10:00Z"),
    );
    let beyond = sign(
        &p,
        "label",
        label(&host, subject, "wist:spam", "2026-08-09T12:10:01Z"),
    );
    write_listed(
        &p,
        &host,
        &[at_bound.clone(), beyond.clone()],
        "2026-08-09T12:00:00Z",
    );
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    assert_eq!(report.labels, vec![at_bound.0.clone()]);
    assert_eq!(
        report.rejected,
        vec![(beyond.0.clone(), "WIST2-E06".to_string())]
    );
    assert!(is_e06_for(&db, &host, &beyond.0));
    assert_eq!(db.count_pending_entries("label").unwrap(), 1);
    assert!(db.is_label_seen_for(&at_bound.0, &host).unwrap());
    assert!(!db.is_label_seen_for(&beyond.0, &host).unwrap());

    let again =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:01Z").unwrap();
    assert_eq!(again.labels, vec![beyond.0.clone()]);
    assert!(again.rejected.is_empty());
    assert_eq!(db.count_pending_entries("label").unwrap(), 2);
}

#[test]
fn a_dispute_asserted_beyond_the_attempt_clock_allowance_is_rejected_and_pulled_again() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let subject = "https://reduced.example.org/notice";
    let (id, envelope) = sign(
        &p,
        "label",
        label(&host, subject, "wist:spam", "2026-08-09T12:00:00Z"),
    );
    write_listed(&p, &host, &[(id.clone(), envelope)], "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    assert!(db.sealed_label_subject(&id).unwrap().is_some());

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
    let dispute = |asserted_at: &str| {
        sign(
            &d,
            "dispute",
            json!({"wist_version": "1.0.0", "disputant": disputant, "label": id, "log": "log.example", "height": 0, "asserted_at": asserted_at}),
        )
    };
    let at_bound = dispute("2026-08-09T13:10:00Z");
    let beyond = dispute("2026-08-09T13:10:01Z");
    write_listed(
        &d,
        &disputant,
        &[at_bound.clone(), beyond.clone()],
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
    assert_eq!(report.labels, vec![at_bound.0.clone()]);
    assert_eq!(
        report.rejected,
        vec![(beyond.0.clone(), "WIST2-E06".to_string())]
    );
    assert!(is_e06_for(&db, &disputant, &beyond.0));
    assert_eq!(db.count_pending_entries("dispute").unwrap(), 1);
    assert!(!db.is_label_seen_for(&beyond.0, &disputant).unwrap());

    let again = clave::ingest::run(
        &db,
        &disputant_client,
        data.path(),
        &disputant,
        "2026-08-09T13:00:01Z",
    )
    .unwrap();
    assert_eq!(again.labels, vec![beyond.0.clone()]);
    assert!(again.rejected.is_empty());
    assert_eq!(db.count_pending_entries("dispute").unwrap(), 2);
}

#[test]
fn a_queued_label_beyond_the_allowance_at_sealed_at_is_dropped_reported_and_pulled_again() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], "2026-08-16T11:55:00Z");
    let (id, envelope) = sign(
        &p,
        "label",
        label(
            &host,
            "https://reduced.example.org/notice",
            "wist:spam",
            "2026-08-16T12:03:20Z",
        ),
    );
    write_listed(&p, &host, &[(id.clone(), envelope)], "2026-08-16T11:55:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let unix = |at: &str| at.parse::<jiff::Timestamp>().unwrap().as_second();
    let at = unix("2026-08-09T11:00:00Z");
    clave::param_change::run(
        &db,
        &sk,
        "clock_skew_seconds",
        60,
        Some("2026-08-16T11:59:00Z"),
        at,
    )
    .unwrap();
    assert!(clave::seal::run(&db, data.path(), &sk, at)
        .unwrap()
        .dropped
        .is_empty());

    let report =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-16T11:55:00Z").unwrap();
    assert_eq!(report.labels, vec![id.clone()]);
    assert!(db.is_label_seen_for(&id, &host).unwrap());

    let sealed = clave::seal::run(&db, data.path(), &sk, unix("2026-08-16T12:00:00Z")).unwrap();
    assert!(
        sealed.dropped.contains(&format!("{id}: WIST2-E06")),
        "{:?}",
        sealed.dropped
    );
    assert!(!db
        .epoch_entries(sealed.epoch_number)
        .unwrap()
        .iter()
        .any(|entry| entry["type"] == "label"));
    assert!(db.sealed_labels().unwrap().is_empty());
    assert!(is_e06_for(&db, &host, &id));
    assert_eq!(db.count_pending_entries("label").unwrap(), 0);
    assert!(!db.is_label_seen_for(&id, &host).unwrap());

    let again =
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-16T12:02:20Z").unwrap();
    assert_eq!(again.labels, vec![id.clone()]);
    let resealed = clave::seal::run(&db, data.path(), &sk, unix("2026-08-16T13:00:00Z")).unwrap();
    assert!(resealed.dropped.is_empty(), "{:?}", resealed.dropped);
    assert_eq!(db.sealed_labels().unwrap().len(), 1);
}
