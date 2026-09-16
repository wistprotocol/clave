mod common;

use clave::db::Db;
use common::*;
use serde_json::json;

const NOW: &str = "2026-08-09T14:00:00Z";

fn signed_act(
    p: &TestPub,
    action: &str,
    subject: &str,
    details: serde_json::Value,
) -> serde_json::Value {
    let update = json!({
        "wist_version": "1.0.0", "action": action, "subject": subject,
        "effective_at": NOW, "details": details,
    });
    wist_core::envelope::sign_envelope(&update, "update", "k1", &p.sk).unwrap()
}

fn write_registry(p: &TestPub, items: &[serde_json::Value]) {
    std::fs::write(
        p.dir.path().join(".well-known/wist/registry.json"),
        serde_json::to_vec(&items).unwrap(),
    )
    .unwrap();
}

fn pending_ids(db: &Db) -> Vec<String> {
    db.peek_pending_entries()
        .unwrap()
        .0
        .iter()
        .filter(|e| e.entry_type == "registry_update")
        .map(|e| clave::governance::update_id(&e.entry_json["update"]).unwrap())
        .collect()
}

#[test]
fn a_feed_pull_queues_each_verified_self_signed_act_once() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let id = add_delta(&p, "https://localhost/a", "content", None);
    write_feed(&p, &host, std::slice::from_ref(&id), NOW);
    let root = format!("sha256:{}", "0".repeat(64));
    let commitment = signed_act(
        &p,
        "canary_commitment",
        &host,
        json!({"root": root, "leaves": 4}),
    );
    let foreign = signed_act(
        &p,
        "canary_commitment",
        "other.example",
        json!({"root": root, "leaves": 4}),
    );
    let mut forged = commitment.clone();
    forged["sig"]["value"] = json!(wist_core::crypto::b64u_encode(&[7u8; 64]));
    let aggregator_act = signed_act(&p, "sanction_lift", &host, json!({"reason": "x"}));
    write_registry(
        &p,
        &[
            commitment.clone(),
            foreign,
            forged,
            aggregator_act,
            commitment.clone(),
        ],
    );
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();

    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    let commitment_id = clave::governance::update_id(&commitment["update"]).unwrap();
    assert_eq!(report.accepted, std::slice::from_ref(&id));
    assert_eq!(report.submissions, std::slice::from_ref(&commitment_id));
    assert_eq!(pending_ids(&db), std::slice::from_ref(&commitment_id));

    let again = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert!(again.submissions.is_empty());
    assert_eq!(pending_ids(&db).len(), 1);

    let pull = clave::submissions::pull(&db, &client, &host).unwrap();
    assert!(pull.served && pull.queued.is_empty());
    assert!(pull
        .skipped
        .iter()
        .any(|(_, reason)| *reason == "subject is not the serving domain"));
    assert!(pull
        .skipped
        .iter()
        .any(|(_, reason)| *reason == "signature does not verify"));
    assert!(pull
        .skipped
        .iter()
        .any(|(_, reason)| *reason == "not a self-signed act"));
}

#[test]
fn a_sealed_act_is_not_queued_again_and_an_absent_path_is_not_a_fault() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], NOW);
    let root = format!("sha256:{}", "1".repeat(64));
    let commitment = signed_act(
        &p,
        "canary_commitment",
        &host,
        json!({"root": root, "leaves": 2}),
    );
    let commitment_id = clave::governance::update_id(&commitment["update"]).unwrap();
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();

    let report = clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    assert!(report.submissions.is_empty() && report.noise == Some("WIST2-E02"));
    let pull = clave::submissions::pull(&db, &client, &host).unwrap();
    assert!(!pull.served && pull.queued.is_empty() && pull.skipped.is_empty());

    db.record_sealed_updates(3, std::slice::from_ref(&commitment_id))
        .unwrap();
    write_registry(&p, std::slice::from_ref(&commitment));
    let pull = clave::submissions::pull(&db, &client, &host).unwrap();
    assert!(pull.served && pull.queued.is_empty());
    assert_eq!(pull.skipped, [(commitment_id, "already queued or sealed")]);
    assert!(pending_ids(&db).is_empty());
}

#[test]
fn a_registration_is_queued_only_when_the_declaration_carries_its_key() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    write_feed(&p, &host, &[], NOW);
    let declared = p.sk.public().to_b64u();
    let stranger = wist_core::crypto::SigningKey::from_seed(&[9u8; 32])
        .public()
        .to_b64u();
    let registration = signed_act(
        &p,
        "observer_register",
        &host,
        json!({"key_id": "k1", "alg": "Ed25519", "public_key": declared}),
    );
    let undeclared = signed_act(
        &p,
        "observer_register",
        &host,
        json!({"key_id": "k1", "alg": "Ed25519", "public_key": stranger}),
    );
    write_registry(&p, &[registration.clone(), undeclared.clone()]);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = Db::open(&data.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, NOW).unwrap();
    let pull = clave::submissions::pull(&db, &client, &host).unwrap();
    assert!(
        pull.queued.is_empty(),
        "the ingest pull already queued the registration"
    );
    assert_eq!(
        pending_ids(&db),
        [clave::governance::update_id(&registration["update"]).unwrap()]
    );
    assert_eq!(
        pull.skipped,
        [
            (
                clave::governance::update_id(&registration["update"]).unwrap(),
                "already queued or sealed"
            ),
            (
                clave::governance::update_id(&undeclared["update"]).unwrap(),
                "registered key is not in the domain's Declaration"
            ),
        ]
    );
}
