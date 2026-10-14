mod common;

use clave::db::{ParamChangeRow, WithdrawalRow};
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
    entries: Vec<Value>,
    changes: &[ParamChangeRow],
) -> u64 {
    seal_with(db, sk, height, at, entries, changes, &[], &[])
}

#[allow(clippy::too_many_arguments)]
fn seal_with(
    db: &clave::db::Db,
    sk: &SigningKey,
    height: u64,
    at: i64,
    mut entries: Vec<Value>,
    changes: &[ParamChangeRow],
    withdrawals: &[WithdrawalRow],
    suffix_lists: &[String],
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
        withdrawals,
        suffix_lists,
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

const SUFFIX_LIST: &[u8] = b"test\n";
const ITEM_ID: &str = "sha256:7a1f0c5e3b9d2e4f6a8c0b1d3e5f7a9c2b4d6e8f0a1c3e5b7d9f1a3c5e7b9d0f";
const WITHDRAWN_DOMAIN: &str = "publisher.example.test";
const WITHDRAWAL_ID: &str =
    "sha256:0b1d3e5f7a9c2b4d6e8f0a1c3e5b7d9f1a3c5e7b9d0f7a1f0c5e3b9d2e4f6a8c";

fn suffix_list_act(sk: &SigningKey, identifier: &str, bytes: usize) -> Value {
    let update = json!({
        "wist_version": "1.0.0",
        "action": "suffix_list_update",
        "subject": identifier,
        "details": {"sha256": identifier, "bytes": bytes},
        "effective_at": ts(T0),
    });
    json!({
        "type": "registry_update",
        "body": wist_core::envelope::sign_envelope(&update, "update", clave::keys::GENESIS_KEY_ID, sk).unwrap(),
    })
}

fn withdrawal() -> WithdrawalRow<'static> {
    WithdrawalRow {
        update_id: WITHDRAWAL_ID,
        item_id: ITEM_ID,
        domain: WITHDRAWN_DOMAIN,
    }
}

struct RejectedStore {
    data: tempfile::TempDir,
    db: clave::db::Db,
    sk: SigningKey,
    identifier: String,
}

impl RejectedStore {
    fn build() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run(LOG_ID, data.path()).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let identifier = wist_core::suffix_list::identifier(SUFFIX_LIST);
        db.store_suffix_list(&identifier, SUFFIX_LIST).unwrap();
        let cap_effective = ts(T0);
        seal(
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
        let octets1 = seal_with(
            &db,
            &sk,
            1,
            T0 + 3600,
            vec![
                unauthenticated_padding("a"),
                unauthenticated_padding("b"),
                suffix_list_act(&sk, &identifier, SUFFIX_LIST.len()),
            ],
            &[],
            &[withdrawal()],
            std::slice::from_ref(&identifier),
        );
        assert!(octets1 > 65_537);
        let window_effective = ts(T0 + 8 * DAY);
        seal(
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
        Self {
            data,
            db,
            sk,
            identifier,
        }
    }

    fn read_all(&self) -> Vec<Option<Vec<String>>> {
        let mut reader =
            History::open(&self.db, self.data.path(), self.db.last_epoch().unwrap()).unwrap();
        let mut judgments = Vec::new();
        while let Some(epoch) = reader.next_epoch().unwrap() {
            judgments.push(epoch.rejected().map(<[String]>::to_vec));
        }
        judgments
    }

    fn markers(&self) -> Vec<(u64, i64)> {
        let conn = rusqlite::Connection::open(self.data.path().join("clave.sqlite")).unwrap();
        let mut stmt = conn
            .prepare("SELECT epoch_number, rejected FROM epochs ORDER BY epoch_number")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }
}

#[test]
fn a_suffix_list_update_of_a_rejected_epoch_never_comes_into_force_and_its_id_is_accepted_later() {
    let store = RejectedStore::build();
    let judgments = store.read_all();
    assert_eq!(judgments[1], Some(vec!["WIST3-E03".to_owned()]));
    assert_eq!(judgments[2], None);
    let db = &store.db;
    let sealed_at2 = db.epoch_at(2).unwrap().unwrap().sealed_at;
    assert!(clave::suffix_list::in_force_at_epoch(db, 2)
        .unwrap()
        .is_none());
    assert!(db.suffix_list_acts().unwrap().is_empty());
    assert_eq!(db.suffix_list_at_epoch(2).unwrap(), None);
    assert_eq!(
        clave::suffix_list::unit_at(db, "a.b.example.test", &sealed_at2).unwrap(),
        "a.b.example.test"
    );

    seal_with(
        db,
        &store.sk,
        3,
        T0 + 10_800,
        vec![suffix_list_act(
            &store.sk,
            &store.identifier,
            SUFFIX_LIST.len(),
        )],
        &[],
        &[],
        std::slice::from_ref(&store.identifier),
    );
    let judgments = store.read_all();
    assert_eq!(judgments[3], None);
    let sealed_at3 = db.epoch_at(3).unwrap().unwrap().sealed_at;
    assert_eq!(
        clave::suffix_list::in_force_at_epoch(db, 4)
            .unwrap()
            .map(|list| list.identifier().to_owned()),
        Some(store.identifier.clone())
    );
    assert_eq!(
        db.suffix_list_acts().unwrap(),
        vec![(3, store.identifier.clone())]
    );
    assert_eq!(
        clave::suffix_list::unit_at(db, "a.b.example.test", &sealed_at3).unwrap(),
        "example.test"
    );
}

#[test]
fn a_withdrawal_of_a_rejected_epoch_withdraws_nothing_until_an_accepted_epoch_seals_it() {
    let store = RejectedStore::build();
    store.read_all();
    let db = &store.db;
    assert!(db.withdrawal_state().unwrap().is_empty());
    assert!(!db.is_withdrawn(ITEM_ID).unwrap());

    db.clear_pending_removals(&[ITEM_ID.to_owned()]).unwrap();
    seal_with(
        db,
        &store.sk,
        3,
        T0 + 10_800,
        vec![],
        &[],
        &[withdrawal()],
        &[],
    );
    assert_eq!(
        db.withdrawal_state().unwrap(),
        vec![(ITEM_ID.to_owned(), WITHDRAWN_DOMAIN.to_owned(), 3)]
    );
    assert!(db.is_withdrawn(ITEM_ID).unwrap());
    assert_eq!(
        db.pending_removals().unwrap(),
        vec![(ITEM_ID.to_owned(), WITHDRAWN_DOMAIN.to_owned())]
    );
}

#[test]
fn a_withdrawal_sealed_again_after_an_accepted_one_keeps_the_earliest_height_and_queues_nothing() {
    let store = RejectedStore::build();
    store.read_all();
    let db = &store.db;
    seal_with(
        db,
        &store.sk,
        3,
        T0 + 10_800,
        vec![],
        &[],
        &[withdrawal()],
        &[],
    );
    db.clear_pending_removals(&[ITEM_ID.to_owned()]).unwrap();
    seal_with(
        db,
        &store.sk,
        4,
        T0 + 14_400,
        vec![],
        &[],
        &[withdrawal()],
        &[],
    );
    assert_eq!(
        db.withdrawal_state().unwrap(),
        vec![(ITEM_ID.to_owned(), WITHDRAWN_DOMAIN.to_owned(), 3)]
    );
    assert!(db.pending_removals().unwrap().is_empty());
}

#[test]
fn the_history_reader_marks_only_the_rejected_epoch_and_a_second_pass_leaves_the_marker_unchanged()
{
    let store = RejectedStore::build();
    assert_eq!(store.markers(), vec![(0, 0), (1, 0), (2, 0)]);
    store.read_all();
    assert_eq!(store.markers(), vec![(0, 0), (1, 1), (2, 0)]);
    store.read_all();
    assert_eq!(store.markers(), vec![(0, 0), (1, 1), (2, 0)]);
}

#[test]
fn parameter_state_applies_no_candidate_of_an_epoch_marked_rejected_and_counts_its_size() {
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
    let window_effective = ts(T0 + 8 * DAY);
    let octets1 = seal(
        &db,
        &sk,
        1,
        T0 + 3600,
        vec![
            signed_change(&sk, "feed_window", 500, T0 + 8 * DAY),
            unauthenticated_padding("a"),
        ],
        &[ParamChangeRow {
            entry_index: 0,
            parameter: "feed_window",
            value: 500,
            effective_at: &window_effective,
        }],
    );
    assert!(octets0 < octets1 && octets1 <= 65_537);
    let sealed_at1 = ts(T0 + 3600);
    assert!(db.parameter_state(&sealed_at1).unwrap().contains(&(
        "feed_window".to_owned(),
        500,
        window_effective.clone()
    )));

    db.record_epoch_judgment(1, true).unwrap();
    let state = db.parameter_state(&sealed_at1).unwrap();
    assert!(state
        .iter()
        .all(|(name, value, _)| name != "feed_window" || *value != 500));
    assert!(state.contains(&("epoch_cap_bytes".to_owned(), 65_537, cap_effective)));
    assert_eq!(db.largest_epoch_bytes().unwrap(), octets1);
}

#[test]
fn a_snapshot_that_is_the_first_pass_over_a_rejected_epoch_marks_it_and_builds() {
    let store = RejectedStore::build();
    assert_eq!(store.markers(), vec![(0, 0), (1, 0), (2, 0)]);
    let outcome =
        clave::snapshot::produce(&store.data.path().join("clave.sqlite"), store.data.path())
            .unwrap();
    assert!(matches!(outcome, clave::snapshot::Outcome::Built { .. }));
    assert_eq!(store.markers(), vec![(0, 0), (1, 1), (2, 0)]);
    assert!(clave::suffix_list::in_force_at_epoch(&store.db, 2)
        .unwrap()
        .is_none());
}
