mod common;

use clave::history::History;
use serde_json::{json, Value};
use wist_core::crypto::SigningKey;
use wist_core::objects::StateEntry;
use wist_core::registry_updates::AcceptedUpdates;
use wist_core::timestamp::log_seconds;
use wist_core::{envelope, epoch, jcs};

const KEY_ID: &str = "test-agg-k1";

fn log_key() -> SigningKey {
    SigningKey::from_seed(&std::array::from_fn(|i| i as u8))
}

fn vector(relative: &str) -> Value {
    serde_json::from_slice(&std::fs::read(common::spec_dir().join(relative)).unwrap()).unwrap()
}

struct Store {
    data: tempfile::TempDir,
    db: clave::db::Db,
}

impl Store {
    fn sealing(epochs: &[(&str, Vec<Value>)]) -> Self {
        let data = tempfile::tempdir().unwrap();
        let anchor = json!({"wist_version": "1.0.0", "log_id": "log.example.org", "genesis_key": {"key_id": KEY_ID, "alg": "Ed25519", "public_key": log_key().public().to_b64u()}, "created_at": "2026-08-02T00:00:00Z"});
        let anchor = envelope::sign_envelope(&anchor, "anchor", KEY_ID, &log_key()).unwrap();
        std::fs::write(
            data.path().join("anchor.json"),
            jcs::canonicalize(&anchor).unwrap(),
        )
        .unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        for (height, (sealed_at, acts)) in epochs.iter().enumerate() {
            let mut entries: Vec<Value> = acts
                .iter()
                .map(|act| json!({"type": "registry_update", "body": act}))
                .collect();
            epoch::sort_entries(&mut entries).unwrap();
            db.commit_seal(
                &log_key(),
                "log.example.org",
                &[],
                height as u64,
                sealed_at,
                &entries,
                epoch::epoch_octets(&entries).unwrap(),
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        }
        Self { data, db }
    }

    fn reader(&self) -> History<'_> {
        History::open(&self.db, self.data.path(), self.db.last_epoch().unwrap()).unwrap()
    }
}

#[test]
fn the_history_reader_reads_an_amendment_sealed_again_after_a_later_one_as_idempotent() {
    let vector = vector("vectors/wist4/parameter-in-force.json");
    let cases = vector["resume_cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            case["log_key"]["public_key"].as_str(),
            Some(log_key().public().to_b64u().as_str()),
            "{label}"
        );
        let epochs: Vec<(&str, Vec<Value>)> = case["epochs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|epoch| {
                (
                    epoch["sealed_at"].as_str().unwrap(),
                    epoch["acts"].as_array().unwrap().clone(),
                )
            })
            .collect();
        let store = Store::sealing(&epochs);
        let mut reader = store.reader();
        let snapshot_epoch = case["snapshot_epoch"].as_u64().unwrap();
        let tuples: Vec<StateEntry> =
            serde_json::from_value(case["snapshot_tuples"].clone()).unwrap();
        while let Some(read) = reader.next_epoch().unwrap() {
            assert!(read.rejected_parameters().is_empty(), "{label}");
            if read.epoch_number() != snapshot_epoch {
                continue;
            }
            assert_eq!(
                reader.replay().registry_updates(),
                &AcceptedUpdates::from_state(&tuples).unwrap(),
                "{label}: the Snapshot's registry_update tuples"
            );
            let parameters: Vec<StateEntry> =
                clave::registry::parameter_state(reader.schedule().unwrap(), read.sealed_at_s())
                    .unwrap()
                    .into_iter()
                    .map(|(name, value, effective_at)| {
                        StateEntry::Parameter(wist_core::objects::ParameterEntry {
                            name,
                            effective_at,
                            value,
                        })
                    })
                    .collect();
            let stated: Vec<&StateEntry> = tuples
                .iter()
                .filter(|tuple| matches!(tuple, StateEntry::Parameter(_)))
                .collect();
            assert_eq!(
                serde_json::to_value(&parameters).unwrap(),
                serde_json::to_value(&stated).unwrap(),
                "{label}: the Snapshot's parameter tuples"
            );
        }
        let query_s = log_seconds(case["query_at"].as_str().unwrap()).unwrap();
        assert_eq!(
            reader
                .schedule()
                .unwrap()
                .value_at(case["parameter"].as_str().unwrap(), query_s),
            case["replayed_value"].as_i64(),
            "{label}"
        );
    }
}

#[test]
fn parameter_change_wire_cases_read_by_the_history_reader_change_the_schedule_as_the_vector_disposes(
) {
    let vector = vector("vectors/wist4/parameter-combinations.json");
    assert_eq!(
        vector["wire_public_key"].as_str(),
        Some(log_key().public().to_b64u().as_str())
    );
    let mut read = 0;
    for case in vector["wire_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        if !case["canonical_integer"].as_bool().unwrap() {
            continue;
        }
        let adopted = case["code"].is_null() && case["combinations_hold_at_defaults"] == true;
        let store = Store::sealing(&[("2026-08-04T00:00:00Z", vec![case["envelope"].clone()])]);
        let mut reader = store.reader();
        let epoch = reader.next_epoch().unwrap().unwrap();
        assert_eq!(
            epoch.rejected_parameters(),
            if adopted { &[][..] } else { &[0][..] },
            "{label}"
        );
        let accepted = reader.schedule().unwrap().accepted();
        assert_eq!(accepted.len(), usize::from(adopted), "{label}");
        if adopted {
            assert_eq!(
                accepted[0].parameter,
                case["envelope"]["update"]["details"]["parameter"]
                    .as_str()
                    .unwrap(),
                "{label}"
            );
        }
        read += 1;
    }
    assert_eq!(read, 43);
}

fn quota_base(wist_version: &str, subject: &str) -> Value {
    let update = json!({
        "wist_version": wist_version,
        "action": "parameter_change",
        "subject": subject,
        "effective_at": "2026-08-12T00:00:00Z",
        "details": {"parameter": "quota_base", "value": 2},
    });
    envelope::sign_envelope(&update, "update", KEY_ID, &log_key()).unwrap()
}

#[test]
fn the_history_reader_schedules_another_minor_version_and_ignores_a_subject_other_than_the_parameter(
) {
    for (label, act, scheduled) in [
        (
            "wist_version 1.1.0",
            quota_base("1.1.0", "quota_base"),
            true,
        ),
        (
            "wist_version 1.0.7",
            quota_base("1.0.7", "quota_base"),
            true,
        ),
        (
            "wist_version 2.0.0",
            quota_base("2.0.0", "quota_base"),
            false,
        ),
        (
            "a subject other than details.parameter",
            quota_base("1.0.0", "feed_window"),
            false,
        ),
    ] {
        let store = Store::sealing(&[("2026-08-04T00:00:00Z", vec![act])]);
        let mut reader = store.reader();
        let epoch = reader.next_epoch().unwrap().unwrap();
        assert_eq!(epoch.rejected_parameters().is_empty(), scheduled, "{label}");
        let at = log_seconds("2026-08-12T00:00:00Z").unwrap();
        assert_eq!(
            reader.schedule().unwrap().value_at("quota_base", at),
            Some(if scheduled { 2 } else { 1000 }),
            "{label}"
        );
    }
}
