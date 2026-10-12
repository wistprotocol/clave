mod common;

use clave::db::ParamChangeRow;
use clave::history::History;
use serde_json::{json, Value};
use wist_core::crypto::SigningKey;
use wist_core::objects::{ParameterEntry, StateEntry};

const T0: i64 = 1_786_276_800;
const DAY: i64 = 86_400;
const LOG_ID: &str = "log.example.test";

fn ts(at: i64) -> String {
    wist_core::timestamp::instant(at).unwrap()
}

fn signed_change(sk: &SigningKey, name: &str, value: i64, effective: i64) -> Value {
    let update = json!({
        "wist_version": "1.0.0",
        "action": "parameter_change",
        "subject": name,
        "details": {"parameter": name, "value": value},
        "effective_at": ts(effective),
    });
    json!({
        "type": "registry_update",
        "body": wist_core::envelope::sign_envelope(&update, "update", clave::keys::GENESIS_KEY_ID, sk).unwrap(),
    })
}

fn unauthenticated_padding(pad: &str) -> Value {
    json!({
        "type": "registry_update",
        "body": {"update": {
            "wist_version": "1.0.0",
            "action": "parameter_change",
            "subject": pad.repeat(40_000),
            "details": {"parameter": "feed_window", "value": 1},
            "effective_at": ts(T0 + 30 * DAY),
        }},
    })
}

fn seal(
    db: &clave::db::Db,
    sk: &SigningKey,
    height: u64,
    at: i64,
    mut entries: Vec<Value>,
    changes: &[ParamChangeRow],
) -> u64 {
    wist_core::epoch::sort_entries(&mut entries).unwrap();
    let octets = wist_core::epoch::epoch_octets(&entries).unwrap();
    db.commit_seal(
        sk,
        LOG_ID,
        &[],
        height,
        &ts(at),
        &entries,
        octets,
        changes,
        &[],
        &[],
        &[],
        &[],
        &[],
    )
    .unwrap();
    octets
}

fn read(path: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn a_store_holding_an_over_size_rejected_epoch_opens_and_snapshots_as_the_history_replays() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run(LOG_ID, data.path()).unwrap();
    let path = data.path().join("clave.sqlite");
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let db = clave::db::Db::open(&path).unwrap();

    let cap_effective = ts(T0);
    let octets0 = seal(
        &db,
        &sk,
        0,
        T0,
        vec![signed_change(&sk, "epoch_cap_bytes", 65_537, T0)],
        &[ParamChangeRow {
            entry_index: 0,
            parameter: "epoch_cap_bytes",
            value: 65_537,
            effective_at: &cap_effective,
        }],
    );
    let octets1 = seal(
        &db,
        &sk,
        1,
        T0 + 3600,
        vec![unauthenticated_padding("a"), unauthenticated_padding("b")],
        &[],
    );
    assert!(octets1 > 65_537);
    let window_effective = ts(T0 + 8 * DAY);
    let octets2 = seal(
        &db,
        &sk,
        2,
        T0 + 7200,
        vec![signed_change(&sk, "feed_window", 500, T0 + 8 * DAY)],
        &[ParamChangeRow {
            entry_index: 0,
            parameter: "feed_window",
            value: 500,
            effective_at: &window_effective,
        }],
    );
    drop(db);

    let db = clave::db::Db::open(&path).unwrap();
    let mut reader = History::open(&db, data.path(), db.last_epoch().unwrap()).unwrap();
    let mut epochs = Vec::new();
    while let Some(epoch) = reader.next_epoch().unwrap() {
        epochs.push((
            epoch.rejected().map(<[String]>::to_vec),
            epoch.rejected_parameters().to_vec(),
            epoch.sealed_at().to_owned(),
            epoch.sealed_at_s(),
        ));
    }
    assert_eq!(epochs.len(), 3);
    assert_eq!(epochs[1].0, Some(vec!["WIST3-E03".to_owned()]));
    assert_eq!(epochs[2].0, None);
    assert!(epochs[2].1.is_empty());
    let (sealed_at2, sealed_at2_s) = (epochs[2].2.clone(), epochs[2].3);

    let replayed =
        clave::registry::parameter_state(reader.schedule().unwrap(), sealed_at2_s).unwrap();
    let stored = db.parameter_state(&sealed_at2).unwrap();
    assert_eq!(stored, replayed);
    assert!(stored.contains(&("feed_window".to_owned(), 500, window_effective.clone())));
    assert_eq!(db.largest_epoch_bytes().unwrap(), octets0.max(octets2));

    clave::snapshot::produce(&path, data.path()).unwrap();
    let directory = common::served_snapshot(data.path(), &sealed_at2[..10]);
    let manifest = read(&directory.join("manifest.json"));
    let state = read(&directory.join(manifest["manifest"]["state"]["path"].as_str().unwrap()));
    let entries: Vec<StateEntry> =
        serde_json::from_value(state["state"]["entries"].clone()).unwrap();
    let served: Vec<&StateEntry> = entries
        .iter()
        .filter(|entry| matches!(entry, StateEntry::Parameter(_)))
        .collect();
    let expected: Vec<StateEntry> = replayed
        .into_iter()
        .map(|(name, value, effective_at)| {
            StateEntry::Parameter(ParameterEntry {
                name,
                effective_at,
                value,
            })
        })
        .collect();
    assert_eq!(
        serde_json::to_value(&served).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    let values = state["state"]["entries"].as_array().unwrap();
    assert_eq!(
        manifest["manifest"]["state"]["state_digest"],
        wist_core::snapshot::state_digest(values).unwrap()
    );
}
