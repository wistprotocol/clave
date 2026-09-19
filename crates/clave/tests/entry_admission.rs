mod common;

use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000;

fn store() -> (
    tempfile::TempDir,
    clave::db::Db,
    wist_core::crypto::SigningKey,
) {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example.test", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    (data, db, sk)
}

fn update(sk: &wist_core::crypto::SigningKey, inner: Value) -> Value {
    wist_core::envelope::sign_envelope(&inner, "update", "log1", sk).unwrap()
}

#[test]
fn an_entry_over_65_535_octets_is_never_sealed_and_is_reported() {
    let (data, db, sk) = store();
    let oversize = update(
        &sk,
        json!({"wist_version":"1.0.0","action":"parameter_change","subject":"clock_skew_seconds",
            "details":{"parameter":"clock_skew_seconds","value":1,"note":"p".repeat(70_000)},
            "effective_at":"2027-03-01T00:00:00Z"}),
    );
    let fitting = update(
        &sk,
        json!({"wist_version":"1.0.0","action":"parameter_change","subject":"clock_skew_seconds",
            "details":{"parameter":"clock_skew_seconds","value":2},
            "effective_at":"2027-03-01T00:00:00Z"}),
    );
    for body in [&oversize, &fitting] {
        db.insert_pending_entry("registry_update", "", body, 0)
            .unwrap();
    }

    let report = clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    assert_eq!(report.entry_count, 1);
    assert!(
        report
            .dropped
            .iter()
            .any(|reason| reason.contains("WIST3-E03") && reason.contains("65 535")),
        "{:?}",
        report.dropped
    );

    let sealed = db.epoch_entries(0).unwrap();
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0]["body"], fitting);
    for leaf in db.entry_range(0, db.tree_size().unwrap()).unwrap() {
        assert!(leaf.len() as u64 <= wist_core::tiles::ENTRY_MAX_BYTES);
    }
    assert!(db.peek_pending_entries().unwrap().0.is_empty());
}

#[test]
fn an_aggregator_key_add_that_collides_with_an_admitted_note_key_id_is_refused() {
    let (data, db, sk) = store();
    let anchor = clave::history::anchor(data.path()).unwrap();
    let colliding = update(
        &sk,
        json!({"wist_version":"1.0.0","action":"aggregator_key_add","subject":"log2",
            "details":{"key_id":"log2","alg":"Ed25519","public_key":anchor.key.to_b64u()},
            "effective_at":"2027-03-01T00:00:00Z"}),
    );
    db.insert_pending_entry("registry_update", "", &colliding, 0)
        .unwrap();

    let report = clave::seal::run(&db, data.path(), &sk, NOW).unwrap();
    assert_eq!(report.entry_count, 0);
    assert!(
        report
            .dropped
            .iter()
            .any(|reason| reason.contains("WIST4-E04") && reason.contains("note key ID")),
        "{:?}",
        report.dropped
    );
    assert!(db.epoch_entries(0).unwrap().is_empty());
    assert_eq!(
        db.admitted_note_key_ids().unwrap(),
        vec![wist_core::crypto::hex_encode(
            &wist_core::checkpoint::aggregator_key_id(&anchor.log_id, &anchor.key)
        )],
        "no key beyond the genesis key is admitted"
    );
}
