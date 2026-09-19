//! WIST-3 §3.4 and §5, WIST-4 §5.1: the Aggregator's own key rotation —
//! the acts it seals, the ones it refuses, the Checkpoints and documents
//! the resulting key set signs, and the replay that reads them back.
mod common;

use common::spec_dir;
use serde_json::{json, Value};
use std::path::Path;
use wist_core::checkpoint::{self, AggregatorKey, Checkpoint};
use wist_core::crypto::{PublicKey, SigningKey};
use wist_core::objects::{AggregatorKeyEntry, StateEntry};

const SEAL_START: i64 = 1_786_276_800;
const LOG_ID: &str = "log.example.test";

struct Log {
    data: tempfile::TempDir,
    db: clave::db::Db,
}

impl Log {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run(LOG_ID, data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        db.set_param("epoch_cadence_seconds", 3600).unwrap();
        Log { data, db }
    }

    fn path(&self) -> &Path {
        self.data.path()
    }

    fn genesis(&self) -> SigningKey {
        clave::keys::load(&self.path().join("keys/seed")).unwrap()
    }

    fn seal(&self, height: u64) -> clave::seal::SealReport {
        let signer = clave::keys::Store::open(self.path(), &self.db)
            .unwrap()
            .signer_at(clave::keys::head_height(&self.db).unwrap())
            .unwrap()
            .signing()
            .unwrap();
        clave::seal::run(
            &self.db,
            self.path(),
            &signer,
            SEAL_START + height as i64 * 3600,
        )
        .unwrap()
    }

    fn reopen(&mut self) {
        self.db = clave::db::Db::open(&self.path().join("clave.sqlite")).unwrap();
    }

    fn checkpoint(&self, height: u64) -> Checkpoint {
        Checkpoint::parse(&self.db.checkpoint_note(height).unwrap().unwrap()).unwrap()
    }

    fn keys(&self) -> Vec<AggregatorKeyEntry> {
        self.db.aggregator_key_entries().unwrap()
    }

    fn public_key(&self, key_id: &str) -> PublicKey {
        let entry = self
            .keys()
            .into_iter()
            .find(|entry| entry.key_id == key_id)
            .unwrap_or_else(|| panic!("{key_id} is not an admitted key"));
        PublicKey::from_b64u(&entry.public_key).unwrap()
    }

    fn aggregator_keys(&self, key_ids: &[&str]) -> Vec<AggregatorKey> {
        key_ids
            .iter()
            .map(|key_id| AggregatorKey {
                key_id: (*key_id).to_string(),
                public_key: self.public_key(key_id),
            })
            .collect()
    }

    /// The signers `checkpoint_height`'s Checkpoint verifies under, judged
    /// against the keys named.
    fn signers(&self, checkpoint_height: u64, key_ids: &[&str]) -> Vec<String> {
        let note = self.checkpoint(checkpoint_height);
        let verification =
            checkpoint::verify(&note, LOG_ID, &self.aggregator_keys(key_ids), &[]).unwrap();
        verification.signers.into_iter().collect()
    }

    fn verify_history(&self) -> clave::error::Result<u64> {
        let mut history =
            clave::history::History::open(&self.db, self.path(), self.db.last_epoch()?)?;
        let mut epochs = 0;
        while history.next_epoch()?.is_some() {
            epochs += 1;
        }
        Ok(epochs)
    }

    fn queue(&self, envelope: &Value) {
        self.db
            .insert_pending_entry("registry_update", "", envelope, 0)
            .unwrap();
    }

    fn state(&self, snapshot_date: &str) -> Value {
        let bytes = std::fs::read(
            self.path()
                .join(format!("snapshots/{snapshot_date}/state.json")),
        )
        .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn signed(update: Value, key_id: &str, sk: &SigningKey) -> Value {
    wist_core::envelope::sign_envelope(&update, "update", key_id, sk).unwrap()
}

fn add_act(key_id: &str, public_key: &str) -> Value {
    json!({"wist_version": "1.0.0", "action": "aggregator_key_add", "subject": key_id,
        "details": {"key_id": key_id, "alg": "Ed25519", "public_key": public_key},
        "effective_at": "2026-12-01T00:00:00Z"})
}

fn remove_act(key_id: &str) -> Value {
    json!({"wist_version": "1.0.0", "action": "aggregator_key_remove", "subject": key_id,
        "details": {"key_id": key_id},
        "effective_at": "2026-12-01T00:00:00Z"})
}

#[test]
fn an_epoch_sealing_an_addition_signs_its_checkpoint_under_the_old_and_the_new_key() {
    let log = Log::new();
    log.seal(0);
    let report = clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    assert_eq!(report.key_id, "log2");
    assert!(report.verifier_key.starts_with(&format!("{LOG_ID}+")));

    let sealed = log.seal(1);
    assert_eq!(sealed.entry_count, 1, "{:?}", sealed.dropped);
    assert!(sealed.dropped.is_empty(), "{:?}", sealed.dropped);

    assert_eq!(
        log.keys()
            .iter()
            .map(|entry| (
                entry.key_id.clone(),
                entry.added_height,
                entry.removed_height
            ))
            .collect::<Vec<_>>(),
        vec![("log1".to_string(), 0, None), ("log2".to_string(), 1, None)]
    );
    assert_eq!(log.checkpoint(0).signatures().len(), 1);
    assert_eq!(log.checkpoint(1).signatures().len(), 2);
    assert_eq!(log.signers(1, &["log1", "log2"]), ["log1", "log2"]);
    assert_eq!(log.signers(0, &["log1"]), ["log1"]);
    assert!(
        checkpoint::verify(
            &log.checkpoint(0),
            LOG_ID,
            &log.aggregator_keys(&["log2"]),
            &[]
        )
        .is_err(),
        "a key admitted at Epoch 1 signs no Checkpoint below it"
    );
    assert_eq!(log.verify_history().unwrap(), 2);
}

#[test]
fn removing_the_genesis_key_leaves_every_later_document_verifiable_under_the_remaining_key() {
    let mut log = Log::new();
    log.seal(0);
    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.seal(1);

    clave::log_key::remove(&log.db, log.path(), "log1", SEAL_START + 3600).unwrap();
    let sealed = log.seal(2);
    assert!(sealed.dropped.is_empty(), "{:?}", sealed.dropped);
    assert_eq!(
        log.keys()
            .iter()
            .map(|entry| (entry.key_id.clone(), entry.removed_height))
            .collect::<Vec<_>>(),
        vec![("log1".to_string(), Some(2)), ("log2".to_string(), None)]
    );

    assert_eq!(log.checkpoint(2).signatures().len(), 1);
    assert_eq!(log.signers(2, &["log2"]), ["log2"]);
    assert!(
        checkpoint::verify(
            &log.checkpoint(2),
            LOG_ID,
            &log.aggregator_keys(&["log1"]),
            &[]
        )
        .is_err(),
        "a key removed at Epoch 2 signs no Checkpoint at or above it"
    );

    // WIST-3 §7: the state file carries a tuple per key ever admitted, the
    // removed genesis key included, and is signed under a key valid at the
    // head.
    let state = log.state("2026-08-09");
    let entries: Vec<StateEntry> =
        serde_json::from_value(state["state"]["entries"].clone()).unwrap();
    let key_tuples: Vec<(String, u64, Option<u64>)> = entries
        .iter()
        .filter_map(|entry| match entry {
            StateEntry::AggregatorKey(key) => {
                Some((key.key_id.clone(), key.added_height, key.removed_height))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        key_tuples,
        vec![
            ("log1".to_string(), 0, Some(2)),
            ("log2".to_string(), 1, None)
        ]
    );
    assert_eq!(state["sig"]["key_id"], "log2");
    let remaining = log.public_key("log2");
    wist_core::envelope::verify_envelope(&state, "state", &remaining).unwrap();
    for (path, inner) in [
        ("snapshots/2026-08-09/manifest.json", "manifest"),
        ("snapshots/index.json", "index"),
    ] {
        let doc: Value =
            serde_json::from_slice(&std::fs::read(log.path().join(path)).unwrap()).unwrap();
        assert_eq!(doc["sig"]["key_id"], "log2", "{path}");
        wist_core::envelope::verify_envelope(&doc, inner, &remaining).unwrap();
    }

    // A Registry Update queued after the removal names the remaining key
    // and seals (WIST-4 §5.1).
    let (key_id, signer) = {
        let store = clave::keys::Store::open(log.path(), &log.db).unwrap();
        let key = store.signer_at(2).unwrap();
        (key.key_id.clone(), key.signing().unwrap())
    };
    assert_eq!(key_id, "log2");
    clave::mirrors::add(
        log.path(),
        &key_id,
        &signer,
        "https://mirror.example/",
        SEAL_START + 7200,
    )
    .unwrap();
    let mirrors: Value =
        serde_json::from_slice(&std::fs::read(log.path().join("log/mirrors.json")).unwrap())
            .unwrap();
    assert_eq!(mirrors["sig"]["key_id"], "log2");
    wist_core::envelope::verify_envelope(&mirrors, "mirrors", &remaining).unwrap();

    clave::param_change::run(
        &log.db,
        &signer,
        "feed_window",
        500,
        None,
        SEAL_START + 3 * 3600,
    )
    .unwrap();
    log.reopen();
    let sealed = log.seal(3);
    assert!(sealed.dropped.is_empty(), "{:?}", sealed.dropped);
    assert_eq!(log.signers(3, &["log2"]), ["log2"]);
    assert_eq!(log.verify_history().unwrap(), 4);

    let mut history =
        clave::history::History::open(&log.db, log.path(), log.db.last_epoch().unwrap()).unwrap();
    let mut rejected = 0;
    while let Some(epoch) = history.next_epoch().unwrap() {
        rejected += epoch.rejected_parameters().len();
    }
    assert_eq!(
        rejected, 0,
        "the parameter change authenticates under the key valid at its Epoch"
    );
    assert_eq!(
        history
            .key_registry()
            .valid_at(3)
            .iter()
            .map(|key| key.key_id.clone())
            .collect::<Vec<_>>(),
        vec!["log2".to_string()]
    );
}

#[test]
fn an_addition_naming_an_admitted_key_id_or_note_key_id_is_never_sealed() {
    let log = Log::new();
    log.seal(0);
    let genesis = log.genesis();
    let fresh = SigningKey::from_seed(&[31u8; 32]);
    log.queue(&signed(
        add_act("log1", &fresh.public().to_b64u()),
        "log1",
        &genesis,
    ));
    log.queue(&signed(
        add_act("other", &genesis.public().to_b64u()),
        "log1",
        &genesis,
    ));

    let sealed = log.seal(1);
    assert_eq!(sealed.entry_count, 0);
    assert!(
        sealed
            .dropped
            .iter()
            .any(|reason| reason.contains("WIST4-E04")
                && reason.contains("aggregator_key_add log1")
                && reason.contains("key_id")),
        "{:?}",
        sealed.dropped
    );
    assert!(
        sealed
            .dropped
            .iter()
            .any(|reason| reason.contains("WIST4-E04")
                && reason.contains("aggregator_key_add other")
                && reason.contains("note key ID")),
        "{:?}",
        sealed.dropped
    );
    assert_eq!(log.keys().len(), 1);
    assert_eq!(log.verify_history().unwrap(), 2);
}

#[test]
fn a_removal_of_a_key_not_valid_below_the_epoch_is_refused_at_queueing_and_at_sealing() {
    let log = Log::new();
    log.seal(0);
    let refusal = clave::log_key::remove(&log.db, log.path(), "log7", SEAL_START)
        .unwrap_err()
        .to_string();
    assert!(
        refusal.contains("WIST4-E04") && refusal.contains("log7"),
        "{refusal}"
    );
    assert!(log.db.peek_pending_entries().unwrap().0.is_empty());

    log.queue(&signed(remove_act("log7"), "log1", &log.genesis()));
    let sealed = log.seal(1);
    assert_eq!(sealed.entry_count, 0);
    assert!(
        sealed
            .dropped
            .iter()
            .any(|reason| reason.contains("WIST4-E04")
                && reason.contains("aggregator_key_remove log7")),
        "{:?}",
        sealed.dropped
    );
    assert_eq!(log.signers(1, &["log1"]), ["log1"]);
}

#[test]
fn a_removal_leaving_no_key_valid_at_the_epoch_is_refused_at_queueing_and_at_sealing() {
    let log = Log::new();
    log.seal(0);
    let refusal = clave::log_key::remove(&log.db, log.path(), "log1", SEAL_START)
        .unwrap_err()
        .to_string();
    assert!(
        refusal.contains("no Aggregator key valid at height 1"),
        "{refusal}"
    );
    assert!(log.db.peek_pending_entries().unwrap().0.is_empty());

    log.queue(&signed(remove_act("log1"), "log1", &log.genesis()));
    let sealed = log.seal(1);
    assert_eq!(sealed.entry_count, 0);
    assert!(
        sealed
            .dropped
            .iter()
            .any(|reason| reason.contains("would leave no Aggregator key valid at height 1")),
        "{:?}",
        sealed.dropped
    );
    assert_eq!(log.keys()[0].removed_height, None);
    assert_eq!(log.signers(1, &["log1"]), ["log1"]);
    assert_eq!(log.verify_history().unwrap(), 2);
}

#[test]
fn a_second_removal_in_one_epoch_is_held_back_only_as_far_as_the_epoch_keeps_a_valid_key() {
    let log = Log::new();
    log.seal(0);
    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.seal(1);

    let genesis = log.genesis();
    let second = clave::keys::load(&log.path().join("keys/log2.seed")).unwrap();
    log.queue(&signed(remove_act("log1"), "log1", &genesis));
    log.queue(&signed(remove_act("log2"), "log2", &second));

    let sealed = log.seal(2);
    assert_eq!(
        sealed.entry_count, 1,
        "one removal seals and the other is held back: {:?}",
        sealed.dropped
    );
    assert!(
        sealed
            .dropped
            .iter()
            .any(|reason| reason.contains("would leave no Aggregator key valid at height 2")),
        "{:?}",
        sealed.dropped
    );
    let removed: Vec<String> = log
        .keys()
        .iter()
        .filter(|entry| entry.removed_height == Some(2))
        .map(|entry| entry.key_id.clone())
        .collect();
    let surviving: Vec<String> = log
        .keys()
        .iter()
        .filter(|entry| entry.removed_height.is_none())
        .map(|entry| entry.key_id.clone())
        .collect();
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert_eq!(surviving.len(), 1, "{surviving:?}");
    assert_eq!(
        log.signers(2, &[surviving[0].as_str()]),
        [surviving[0].clone()]
    );
    assert!(
        checkpoint::verify(
            &log.checkpoint(2),
            LOG_ID,
            &log.aggregator_keys(&[removed[0].as_str()]),
            &[]
        )
        .is_err(),
        "the removed key signs no Checkpoint at its removal height"
    );
    assert_eq!(log.verify_history().unwrap(), 3);
}

#[test]
fn a_queued_key_act_seals_after_a_restart_between_queueing_and_sealing() {
    let mut log = Log::new();
    log.seal(0);
    let report = clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.reopen();

    let listing = clave::log_key::list(&log.db, log.path()).unwrap();
    let pending = listing
        .iter()
        .find(|key| key.key_id == report.key_id)
        .unwrap();
    assert_eq!(pending.added_height, None);
    assert!(pending.held);

    let sealed = log.seal(1);
    assert_eq!(sealed.entry_count, 1, "{:?}", sealed.dropped);
    assert_eq!(log.signers(1, &["log1", "log2"]), ["log1", "log2"]);

    log.reopen();
    let listing = clave::log_key::list(&log.db, log.path()).unwrap();
    assert_eq!(
        listing
            .iter()
            .map(|key| (key.key_id.clone(), key.added_height, key.held))
            .collect::<Vec<_>>(),
        vec![
            ("log1".to_string(), Some(0), true),
            ("log2".to_string(), Some(1), true)
        ]
    );
    assert_eq!(log.verify_history().unwrap(), 2);
}

/// Builds a Log from one `aggregator-keys.json` history — its Anchor and
/// its Epochs with the exact Checkpoints the vector publishes — and reads
/// it back through the Aggregator's history reader.
fn replay_vector_history(history: &Value) -> (tempfile::TempDir, clave::db::Db, Vec<Value>) {
    let data = tempfile::tempdir().unwrap();
    let log_id = history["log_id"].as_str().unwrap();
    std::fs::write(
        data.path().join("anchor.json"),
        wist_core::jcs::canonicalize(&history["anchor"]).unwrap(),
    )
    .unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let local = SigningKey::from_seed(&[3u8; 32]);
    let epochs: Vec<Value> = history["epochs"].as_array().unwrap().clone();
    for epoch in &epochs {
        // An Epoch whose accepted removals leave no valid key has no
        // Checkpoint of its own (WIST-3 §3.4): the vector offers the
        // candidates a Consumer judges instead, and the reader must refuse
        // the one the Log would have to publish.
        let note = epoch["checkpoint"]
            .as_str()
            .unwrap_or_else(|| epoch["checkpoint_cases"][0]["checkpoint"].as_str().unwrap());
        let parsed = Checkpoint::parse(note).unwrap();
        let entries: Vec<Value> = serde_json::from_value(epoch["entries"].clone()).unwrap();
        let row = db
            .commit_seal(
                &local,
                log_id,
                &[],
                parsed.epoch_number(),
                parsed.sealed_at(),
                &entries,
                wist_core::epoch::epoch_octets(&entries).unwrap(),
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        assert_eq!(
            row.tree_size,
            epoch["tree_size"].as_u64().unwrap(),
            "{log_id} Epoch {}",
            parsed.epoch_number()
        );
        assert_eq!(row.root, parsed.root_token());
        db.replace_checkpoint_note(parsed.epoch_number(), note)
            .unwrap();
    }
    (data, db, epochs)
}

fn state_tuples(entries: &[AggregatorKeyEntry]) -> Vec<Value> {
    entries
        .iter()
        .map(|entry| {
            json!([
                "aggregator_key",
                entry.key_id,
                entry.public_key,
                entry.added_height,
                entry.removed_height
            ])
        })
        .collect()
}

#[test]
fn the_aggregator_key_vector_histories_replay_through_the_history_reader() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist3/aggregator-keys.json")).unwrap(),
    )
    .unwrap();
    for history in vector["histories"].as_array().unwrap() {
        let name = history["name"].as_str().unwrap();
        let (data, db, epochs) = replay_vector_history(history);
        let head = db.last_epoch().unwrap();
        let mut reader = clave::history::History::open(&db, data.path(), head).unwrap();
        let verified_head = history["verified_head"].as_u64().unwrap();
        for epoch in &epochs {
            let height = epoch["epoch_number"].as_u64().unwrap();
            let applied = epoch["applied"].as_bool().unwrap();
            let read = reader.next_epoch();
            if !applied {
                assert!(
                    read.is_err(),
                    "{name} Epoch {height} has no valid Checkpoint and is never applied"
                );
                break;
            }
            let read = read
                .unwrap_or_else(|error| panic!("{name} Epoch {height}: {error}"))
                .unwrap_or_else(|| panic!("{name} Epoch {height} is missing"));
            assert_eq!(read.epoch_number(), height, "{name}");
            let expected: Vec<Value> =
                serde_json::from_value(epoch["expected_state"].clone()).unwrap();
            assert_eq!(
                state_tuples(&reader.key_entries()),
                expected,
                "{name} Epoch {height} key registry"
            );
            let rejected: Vec<u64> = epoch["acts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|act| act["action"] == "parameter_change" && !act["code"].is_null())
                .map(|act| act["entry_index"].as_u64().unwrap())
                .collect();
            assert_eq!(
                read.rejected_parameters()
                    .iter()
                    .map(|index| *index as u64)
                    .collect::<Vec<_>>(),
                rejected,
                "{name} Epoch {height} parameter candidates"
            );
            assert!(
                height <= verified_head,
                "{name} read past its verified head"
            );
        }
        for stated in history["valid_at"].as_array().unwrap() {
            let height = stated["height"].as_i64().unwrap();
            if height < 0 || height as u64 > verified_head {
                continue;
            }
            let expected: Vec<String> = serde_json::from_value(stated["key_ids"].clone()).unwrap();
            let mut valid: Vec<String> = reader
                .key_registry()
                .valid_at(height as u64)
                .iter()
                .map(|key| key.key_id.clone())
                .collect();
            valid.sort();
            assert_eq!(valid, expected, "{name} keys valid at height {height}");
        }
        if let Some(state) = history.get("snapshot_state") {
            for case in state["cases"].as_array().unwrap() {
                let stated: Vec<Value> = case["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|tuple| tuple[0] == "aggregator_key")
                    .cloned()
                    .collect();
                let held = state_tuples(&reader.key_entries());
                let label = case["name"].as_str().unwrap();
                if case["verifies"].as_bool().unwrap() {
                    assert_eq!(held, stated, "{name}: {label}");
                } else {
                    assert_ne!(held, stated, "{name}: {label}");
                }
            }
        }
    }
}

#[test]
fn a_checkpoint_is_never_signed_by_more_than_sixteen_aggregator_keys() {
    let log = Log::new();
    let keys: Vec<SigningKey> = (0..=checkpoint::MAX_SIGNATURE_LINES as u8)
        .map(|seed| SigningKey::from_seed(&[seed; 32]))
        .collect();
    let refused = log
        .db
        .commit_seal_under(
            &keys.iter().collect::<Vec<_>>(),
            None,
            LOG_ID,
            &[],
            0,
            "2026-08-09T12:00:00Z",
            &[],
            0,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap_err()
        .to_string();
    assert!(refused.contains("at most 16 signature lines"), "{refused}");
    assert!(log.db.last_epoch().unwrap().is_none());
}

#[test]
fn a_checkpoint_verifies_only_under_the_keys_the_vector_makes_valid_at_its_height() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist3/aggregator-keys.json")).unwrap(),
    )
    .unwrap();
    let mut cases = 0;
    for history in vector["histories"].as_array().unwrap() {
        let name = history["name"].as_str().unwrap();
        for epoch in history["epochs"].as_array().unwrap() {
            let height = epoch["epoch_number"].as_u64().unwrap();
            for case in epoch["checkpoint_cases"].as_array().unwrap() {
                let label = case["name"].as_str().unwrap();
                let expected = case["expected"].as_str().unwrap();
                let (data, db, _) = replay_vector_history(history);
                db.replace_checkpoint_note(height, case["checkpoint"].as_str().unwrap())
                    .unwrap();
                let head = db.epoch_at(height).unwrap();
                let mut reader = clave::history::History::open(&db, data.path(), head).unwrap();
                let mut outcome = Ok(());
                for _ in 0..=height {
                    if let Err(error) = reader.next_epoch() {
                        outcome = Err(error.to_string());
                        break;
                    }
                }
                match expected {
                    "valid" => assert!(outcome.is_ok(), "{name}: {label}: {outcome:?}"),
                    code => {
                        let error = outcome.expect_err(label);
                        assert!(error.contains(code), "{name}: {label}: {error}");
                    }
                }
                cases += 1;
            }
        }
    }
    assert!(cases >= 6, "the vector offers {cases} Checkpoint cases");
}
