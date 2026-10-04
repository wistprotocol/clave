//! WIST-3 §3.4 and §5, WIST-4 §5.1: the Aggregator's own key rotation.
mod common;

use common::spec_dir;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use wist_core::checkpoint::{self, AggregatorKey, Checkpoint};
use wist_core::crypto::{PublicKey, SigningKey};
use wist_core::objects::{AggregatorKeyEntry, ParameterEntry, StateEntry};

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
        self.seal_at(SEAL_START + height as i64 * 3600)
    }

    fn seal_on_day(&self, day: i64) -> clave::seal::SealReport {
        self.seal_at(SEAL_START + day * 86_400)
    }

    fn seal_at(&self, now_unix: i64) -> clave::seal::SealReport {
        let (_, signer) = clave::keys::head_signer(self.path(), &self.db).unwrap();
        let report = clave::seal::run_with_client(
            &self.db,
            self.path(),
            &signer,
            &common::loopback_client(),
            now_unix,
        )
        .unwrap();
        clave::snapshot::produce(&self.path().join("clave.sqlite"), self.path()).unwrap();
        report
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
        self.document(&format!("{}/state.json", self.snapshot(snapshot_date)))
    }

    fn snapshot(&self, snapshot_date: &str) -> String {
        common::served_snapshot(self.path(), snapshot_date)
            .strip_prefix(self.path())
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn document(&self, path: &str) -> Value {
        serde_json::from_slice(&std::fs::read(self.path().join(path)).unwrap()).unwrap()
    }

    fn anchor(&self) -> wist_core::objects::Anchor {
        let doc: wist_core::objects::LogAnchorEnvelope =
            serde_json::from_value(self.document("anchor.json")).unwrap();
        doc.anchor
    }

    fn signing_key(&self, key_id: &str) -> SigningKey {
        clave::keys::Store::open(self.path(), &self.db)
            .unwrap()
            .keys()
            .iter()
            .find(|key| key.key_id == key_id)
            .and_then(|key| key.signing())
            .unwrap_or_else(|| panic!("{key_id} is not a held key"))
    }
}

fn state_key_entries(state: &Value) -> Vec<AggregatorKeyEntry> {
    let entries: Vec<StateEntry> =
        serde_json::from_value(state["state"]["entries"].clone()).unwrap();
    entries
        .into_iter()
        .filter_map(|entry| match entry {
            StateEntry::AggregatorKey(key) => Some(key),
            _ => None,
        })
        .collect()
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
        (
            format!("{}/manifest.json", log.snapshot("2026-08-09")),
            "manifest",
        ),
        ("snapshots/index.json".to_string(), "index"),
    ] {
        let doc: Value =
            serde_json::from_slice(&std::fs::read(log.path().join(&path)).unwrap()).unwrap();
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
    common::list_signed_mirrors(
        log.path(),
        &key_id,
        &signer,
        &[common::serve_not_found()],
        SEAL_START + 7200,
    );

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
fn the_state_file_key_tuples_authenticate_from_the_anchor_and_carry_the_accepted_acts() {
    let log = Log::new();
    log.seal(0);
    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.seal(1);
    clave::log_key::remove(&log.db, log.path(), "log1", SEAL_START + 3600).unwrap();
    log.seal(2);
    clave::log_key::add(&log.db, log.path(), SEAL_START + 2 * 3600).unwrap();
    log.seal(3);

    let second = log.signing_key("log2");
    let third = log.signing_key("log3");
    let mut later_removal = remove_act("log3");
    later_removal["effective_at"] = json!("2026-12-01T00:00:01Z");
    log.queue(&signed(remove_act("log3"), "log2", &second));
    log.queue(&signed(later_removal, "log3", &third));
    let sealed = log.seal(4);
    assert_eq!(
        sealed.entry_count, 2,
        "both removals of log3 are accepted in Epoch 4: {:?}",
        sealed.dropped
    );

    let entries = state_key_entries(&log.state("2026-08-09"));
    assert_eq!(
        entries
            .iter()
            .map(|entry| (
                entry.key_id.as_str(),
                entry.added_height,
                entry.removed_height
            ))
            .collect::<Vec<_>>(),
        vec![
            ("log1", 0, Some(2)),
            ("log2", 1, None),
            ("log3", 3, Some(4))
        ]
    );
    assert!(
        entries[0].adding_act.is_none(),
        "the genesis key adds itself"
    );
    assert_eq!(
        entries[0].removing_act.as_ref().unwrap()["update"]["details"]["key_id"],
        "log1"
    );
    assert_eq!(
        entries[1].adding_act.as_ref().unwrap()["update"]["details"]["key_id"],
        "log2"
    );
    assert!(
        entries[1].removing_act.is_none(),
        "log2 is valid at the head"
    );

    // WIST-3 §7: of two removals of one key accepted in one Epoch, the
    // tuple carries the one at the lower Entry index.
    let removals: Vec<Value> = log
        .db
        .epoch_entries(4)
        .unwrap()
        .iter()
        .filter(|entry| entry["body"]["update"]["action"] == "aggregator_key_remove")
        .map(|entry| entry["body"].clone())
        .collect();
    assert_eq!(removals.len(), 2);
    assert_ne!(removals[0], removals[1]);
    assert_eq!(entries[2].removing_act.as_ref().unwrap(), &removals[0]);

    let registry =
        wist_core::aggregator_keys::Registry::from_state_tuples(&log.anchor(), 4, &entries)
            .unwrap();
    assert_eq!(
        registry
            .valid_at(4)
            .iter()
            .map(|key| key.key_id.clone())
            .collect::<Vec<_>>(),
        vec!["log2".to_string()]
    );
    assert_eq!(
        registry
            .valid_at(1)
            .iter()
            .map(|key| key.key_id.clone())
            .collect::<Vec<_>>(),
        vec!["log1".to_string(), "log2".to_string()]
    );
}

#[test]
fn the_state_file_carries_one_registry_update_tuple_per_accepted_act_at_its_sealing_height() {
    let log = Log::new();
    log.seal(0);
    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.seal(1);
    clave::param_change::run(
        &log.db,
        &log.genesis(),
        "feed_window",
        500,
        None,
        SEAL_START + 3600,
    )
    .unwrap();
    log.seal(2);
    let list = log.path().join("list.dat");
    std::fs::write(&list, "com\n").unwrap();
    clave::suffix_list::pin(
        &log.db,
        log.path(),
        &log.genesis(),
        &list,
        SEAL_START + 2 * 3600,
    )
    .unwrap();
    let sealed = log.seal(3);
    assert_eq!(sealed.entry_count, 1, "{:?}", sealed.dropped);

    let mut expected = Vec::new();
    for height in 1..=3 {
        for entry in log.db.epoch_entries(height).unwrap() {
            expected.push((
                wist_core::registry_updates::update_id(&entry["body"]).unwrap(),
                height,
            ));
        }
    }
    assert_eq!(expected.len(), 3);
    let state = log.state("2026-08-09");
    let entries: Vec<StateEntry> =
        serde_json::from_value(state["state"]["entries"].clone()).unwrap();
    let mut carried: Vec<(String, u64)> = entries
        .iter()
        .filter_map(|entry| match entry {
            StateEntry::RegistryUpdate(entry) => {
                Some((entry.update_id.clone(), entry.sealing_height))
            }
            _ => None,
        })
        .collect();
    carried.sort_by_key(|(_, height)| *height);
    assert_eq!(carried, expected);
    let manifest = log.document(&format!("{}/manifest.json", log.snapshot("2026-08-09")));
    let values: Vec<Value> = state["state"]["entries"].as_array().unwrap().clone();
    assert_eq!(
        manifest["manifest"]["state"]["state_digest"],
        wist_core::snapshot::state_digest(&values).unwrap()
    );
}

fn forget_key_acts(log: &Log) {
    rusqlite::Connection::open(log.path().join("clave.sqlite"))
        .unwrap()
        .execute(
            "UPDATE aggregator_keys SET adding_act = NULL, removing_act = NULL",
            [],
        )
        .unwrap();
}

#[test]
fn a_store_without_the_key_acts_recovers_them_from_the_entries_it_has_sealed() {
    let mut log = Log::new();
    log.seal(0);
    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.seal(1);
    clave::log_key::remove(&log.db, log.path(), "log1", SEAL_START + 3600).unwrap();
    log.seal(2);
    let sealed = state_tuples(&log.keys());

    forget_key_acts(&log);
    log.reopen();
    assert_eq!(state_tuples(&log.keys()), sealed);
}

#[test]
fn a_store_whose_entries_do_not_reproduce_its_key_registry_is_refused() {
    let log = Log::new();
    log.seal(0);
    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.seal(1);

    forget_key_acts(&log);
    let connection = rusqlite::Connection::open(log.path().join("clave.sqlite")).unwrap();
    connection
        .execute("DELETE FROM log_entries WHERE epoch_number = 1", [])
        .unwrap();
    drop(connection);
    let refusal = match clave::db::Db::open(&log.path().join("clave.sqlite")) {
        Ok(_) => panic!("a store missing the Entries its key registry records reopened"),
        Err(error) => error.to_string(),
    };
    assert!(
        refusal.contains("do not reproduce the Aggregator key registry"),
        "{refusal}"
    );
}

fn unsealed_documents(data_dir: &Path) -> Vec<(String, &'static str)> {
    let mut documents = vec![
        ("snapshots/index.json".to_string(), "index"),
        ("log/mirrors.json".to_string(), "mirrors"),
    ];
    let mut directories: Vec<String> = common::listed_snapshots(data_dir)
        .iter()
        .map(|entry| {
            common::listed_snapshot_directory(data_dir, entry)
                .strip_prefix(data_dir)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    directories.sort();
    for directory in directories {
        documents.push((format!("{directory}/state.json"), "state"));
        documents.push((format!("{directory}/manifest.json"), "manifest"));
    }
    documents
}

#[test]
fn removing_a_key_re_signs_every_unsealed_document_it_signed_and_still_serves() {
    let log = Log::new();
    log.seal_on_day(0);
    let (genesis_key_id, genesis) = clave::keys::head_signer(log.path(), &log.db).unwrap();
    assert_eq!(genesis_key_id, "log1");
    common::list_signed_mirrors(
        log.path(),
        &genesis_key_id,
        &genesis,
        &[common::serve_not_found()],
        SEAL_START,
    );

    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.seal_on_day(1);
    for (path, _) in unsealed_documents(log.path()) {
        assert_eq!(
            log.document(&path)["sig"]["key_id"],
            "log1",
            "{path} is signed by the genesis key before its removal"
        );
    }
    let before =
        log.document(&format!("{}/manifest.json", log.snapshot("2026-08-09")))["manifest"].clone();
    let mirror_urls = log.document("log/mirrors.json")["mirrors"].clone();

    clave::log_key::remove(&log.db, log.path(), "log1", SEAL_START + 86_400).unwrap();
    log.seal_on_day(2);

    let remaining = log.public_key("log2");
    for (path, inner) in unsealed_documents(log.path()) {
        let document = log.document(&path);
        assert_eq!(document["sig"]["key_id"], "log2", "{path}");
        wist_core::envelope::verify_envelope(&document, inner, &remaining)
            .unwrap_or_else(|error| panic!("{path}: {error}"));
    }
    let after =
        log.document(&format!("{}/manifest.json", log.snapshot("2026-08-09")))["manifest"].clone();
    assert_eq!(after["content_digest"], before["content_digest"]);
    assert_eq!(
        after["state"]["state_digest"],
        before["state"]["state_digest"]
    );
    assert_eq!(after["epoch_number"], before["epoch_number"]);
    assert_eq!(
        log.document("log/mirrors.json")["mirrors"],
        mirror_urls,
        "re-signing states no new Mirror list"
    );
    for date in ["2026-08-09", "2026-08-10", "2026-08-11"] {
        let manifest = log.document(&format!("{}/manifest.json", log.snapshot(date)));
        let state = std::fs::read(
            log.path()
                .join(format!("{}/state.json", log.snapshot(date))),
        )
        .unwrap();
        assert_eq!(
            manifest["manifest"]["state"]["sha256"],
            wist_core::crypto::hex_encode(&Sha256::digest(&state)),
            "{date}"
        );
        assert_eq!(
            manifest["manifest"]["state"]["bytes"].as_u64().unwrap(),
            state.len() as u64,
            "{date}"
        );
    }

    let served: Vec<Vec<u8>> = unsealed_documents(log.path())
        .iter()
        .map(|(path, _)| std::fs::read(log.path().join(path)).unwrap())
        .collect();
    assert!(clave::publication::recover(&log.db, log.path())
        .unwrap()
        .is_empty());
    let again: Vec<Vec<u8>> = unsealed_documents(log.path())
        .iter()
        .map(|(path, _)| std::fs::read(log.path().join(path)).unwrap())
        .collect();
    assert_eq!(served, again, "a second pass rewrites nothing");
    assert_eq!(log.verify_history().unwrap(), 3);
}

#[test]
fn a_pass_interrupted_between_documents_is_finished_by_the_next_publication_repair() {
    let log = Log::new();
    log.seal_on_day(0);
    let (genesis_key_id, genesis) = clave::keys::head_signer(log.path(), &log.db).unwrap();
    common::list_signed_mirrors(
        log.path(),
        &genesis_key_id,
        &genesis,
        &[common::serve_not_found()],
        SEAL_START,
    );
    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    log.seal_on_day(1);
    let stale_state = std::fs::read(
        log.path()
            .join(format!("{}/state.json", log.snapshot("2026-08-09"))),
    )
    .unwrap();
    let stale_manifest = std::fs::read(
        log.path()
            .join(format!("{}/manifest.json", log.snapshot("2026-08-09"))),
    )
    .unwrap();
    let stale_index = std::fs::read(log.path().join("snapshots/index.json")).unwrap();

    clave::log_key::remove(&log.db, log.path(), "log1", SEAL_START + 86_400).unwrap();
    log.seal_on_day(2);
    let settled = std::fs::read(
        log.path()
            .join(format!("{}/state.json", log.snapshot("2026-08-09"))),
    )
    .unwrap();

    std::fs::write(
        log.path()
            .join(format!("{}/manifest.json", log.snapshot("2026-08-09"))),
        &stale_manifest,
    )
    .unwrap();
    std::fs::write(log.path().join("snapshots/index.json"), &stale_index).unwrap();
    clave::publication::recover(&log.db, log.path()).unwrap();
    let remaining = log.public_key("log2");
    for (path, inner) in [
        (
            format!("{}/manifest.json", log.snapshot("2026-08-09")),
            "manifest",
        ),
        ("snapshots/index.json".to_string(), "index"),
    ] {
        let document = log.document(&path);
        assert_eq!(document["sig"]["key_id"], "log2", "{path}");
        wist_core::envelope::verify_envelope(&document, inner, &remaining).unwrap();
    }
    assert_eq!(
        log.document(&format!("{}/manifest.json", log.snapshot("2026-08-09")))["manifest"]["state"]
            ["sha256"],
        wist_core::crypto::hex_encode(&Sha256::digest(&settled))
    );

    std::fs::write(
        log.path()
            .join(format!("{}/state.json", log.snapshot("2026-08-09"))),
        &stale_state,
    )
    .unwrap();
    let mut manifest = log.document(&format!("{}/manifest.json", log.snapshot("2026-08-09")));
    manifest["manifest"]["state"]["sha256"] = json!("0".repeat(64));
    let second = log.signing_key("log2");
    std::fs::write(
        log.path()
            .join(format!("{}/manifest.json", log.snapshot("2026-08-09"))),
        serde_json::to_vec(
            &wist_core::envelope::sign_envelope(&manifest["manifest"], "manifest", "log2", &second)
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    clave::publication::recover(&log.db, log.path()).unwrap();
    assert_eq!(
        std::fs::read(
            log.path()
                .join(format!("{}/state.json", log.snapshot("2026-08-09")))
        )
        .unwrap(),
        settled
    );
    assert_eq!(
        log.document(&format!("{}/manifest.json", log.snapshot("2026-08-09")))["manifest"]["state"]
            ["sha256"],
        wist_core::crypto::hex_encode(&Sha256::digest(&settled))
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
fn a_key_act_queued_again_under_an_accepted_id_is_dropped_as_repeated() {
    let log = Log::new();
    log.seal(0);
    clave::log_key::add(&log.db, log.path(), SEAL_START).unwrap();
    let (pending, _) = log.db.peek_pending_entries().unwrap();
    let addition = pending[0].entry_json.clone();
    assert_eq!(log.seal(1).entry_count, 1);

    log.queue(&addition);
    let sealed = log.seal(2);
    assert_eq!(sealed.entry_count, 0);
    let update_id = wist_core::registry_updates::update_id(&addition).unwrap();
    assert_eq!(
        sealed.dropped,
        [format!(
            "aggregator_key_add log2 is not sealed: its Registry Update ID {update_id} was accepted at height 1"
        )]
    );
    assert!(log.db.peek_pending_entries().unwrap().0.is_empty());
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

fn complete_state(reader: &clave::history::History<'_>, head_at: i64) -> BTreeSet<String> {
    let keys = reader
        .key_entries()
        .into_iter()
        .map(StateEntry::AggregatorKey);
    let parameters = clave::registry::parameter_state(reader.schedule().unwrap(), head_at)
        .unwrap()
        .into_iter()
        .map(|(name, value, effective_at)| {
            StateEntry::Parameter(ParameterEntry {
                name,
                effective_at,
                value,
            })
        });
    let updates = reader
        .replay()
        .registry_updates()
        .entries()
        .into_iter()
        .map(StateEntry::RegistryUpdate);
    keys.chain(parameters)
        .chain(updates)
        .map(|entry| serde_json::to_value(entry).unwrap().to_string())
        .collect()
}

fn registry_state(reader: &clave::history::History<'_>, at: i64, height: u64) -> BTreeSet<String> {
    let parameters = clave::registry::parameter_state(reader.schedule().unwrap(), at)
        .unwrap()
        .into_iter()
        .map(|(name, value, effective_at)| {
            StateEntry::Parameter(ParameterEntry {
                name,
                effective_at,
                value,
            })
        });
    let suffix_list = reader
        .suffix_lists()
        .entry_at(height)
        .map(StateEntry::SuffixList);
    let updates = reader
        .replay()
        .registry_updates()
        .entries()
        .into_iter()
        .map(StateEntry::RegistryUpdate);
    parameters
        .chain(suffix_list)
        .chain(updates)
        .map(|entry| serde_json::to_value(entry).unwrap().to_string())
        .collect()
}

fn state_tuples(entries: &[AggregatorKeyEntry]) -> Vec<Value> {
    entries
        .iter()
        .map(|entry| serde_json::to_value(StateEntry::AggregatorKey(entry.clone())).unwrap())
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
        let mut head_at = None;
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
            head_at = Some(read.sealed_at_s());
            let expected: Vec<Value> =
                serde_json::from_value(epoch["expected_state"].clone()).unwrap();
            assert_eq!(
                state_tuples(&reader.key_entries()),
                expected,
                "{name} Epoch {height} key registry"
            );
            assert_eq!(
                read.rejected().map(<[String]>::to_vec),
                epoch["rejection"]
                    .as_str()
                    .map(|code| vec![code.to_owned()]),
                "{name} Epoch {height}: {}",
                epoch["why"]
            );
            assert_eq!(
                registry_state(&reader, read.sealed_at_s(), height),
                epoch["expected_registry_state"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(Value::to_string)
                    .collect::<BTreeSet<_>>(),
                "{name} Epoch {height} registry state: {}",
                epoch["why"]
            );
            let rejected: Vec<u64> = epoch["acts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|act| {
                    epoch["rejection"].is_null()
                        && act["action"] == "parameter_change"
                        && !act["code"].is_null()
                })
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
            assert_eq!(state["epoch_number"].as_u64(), reader.height(), "{name}");
            let held = complete_state(&reader, head_at.unwrap());
            for case in state["cases"].as_array().unwrap() {
                let stated: BTreeSet<String> = case["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|tuple| tuple.to_string())
                    .collect();
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
fn the_snapshot_key_vector_states_a_replay_leaves_are_the_history_readers_state() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist3/snapshot-keys.json")).unwrap(),
    )
    .unwrap();
    let (data, db, _) = replay_vector_history(&vector["history"]);
    let tie = &vector["removal_tie_break"];
    let mut replayed = 0;
    for case in vector["cases"].as_array().unwrap() {
        let label = case["name"].as_str().unwrap();
        let head = db.epoch_at(case["epoch_number"].as_u64().unwrap()).unwrap();
        let mut reader = clave::history::History::open(&db, data.path(), head).unwrap();
        let mut head_at = None;
        while let Some(epoch) = reader.next_epoch().unwrap() {
            head_at = Some(epoch.sealed_at_s());
        }
        let held = complete_state(&reader, head_at.unwrap());
        let digest = wist_core::snapshot::state_digest(
            &held
                .iter()
                .map(|tuple| serde_json::from_str(tuple).unwrap())
                .collect::<Vec<Value>>(),
        )
        .unwrap();
        let stated: BTreeSet<String> = case["state"]["state"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tuple| tuple.to_string())
            .collect();
        if case["name"] == tie["alternate_case"] {
            assert_ne!(held, stated, "{label}");
            assert_eq!(digest, tie["accepted_state_digest"], "{label}");
            assert_eq!(
                case["state_digest"], tie["alternate_state_digest"],
                "{label}"
            );
        } else if case["expected"] == "accept" {
            assert_eq!(held, stated, "{label}");
            assert_eq!(digest, case["state_digest"], "{label}");
            replayed += 1;
        }
    }
    assert!(
        replayed >= 7,
        "the vector offers {replayed} accepted states"
    );
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

struct OwnLog {
    data: tempfile::TempDir,
    db: clave::db::Db,
    leaves: Vec<[u8; 32]>,
}

impl OwnLog {
    fn new(genesis: &SigningKey) -> Self {
        let data = tempfile::tempdir().unwrap();
        let anchor = json!({
            "wist_version": "1.0.0",
            "log_id": LOG_ID,
            "genesis_key": {"key_id": "genesis", "alg": "Ed25519", "public_key": genesis.public().to_b64u()},
            "created_at": "2026-08-01T00:00:00Z"
        });
        let envelope =
            wist_core::envelope::sign_envelope(&anchor, "anchor", "genesis", genesis).unwrap();
        std::fs::write(
            data.path().join("anchor.json"),
            wist_core::jcs::canonicalize(&envelope).unwrap(),
        )
        .unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        OwnLog {
            data,
            db,
            leaves: Vec::new(),
        }
    }

    fn seal(&mut self, height: u64, entries: &[Value], signers: &[&SigningKey]) {
        let sealed_at = wist_core::timestamp::instant(SEAL_START + height as i64 * 3600).unwrap();
        self.db
            .commit_seal(
                &SigningKey::from_seed(&[3u8; 32]),
                LOG_ID,
                &[],
                height,
                &sealed_at,
                entries,
                wist_core::epoch::epoch_octets(entries).unwrap(),
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        self.leaves.extend(entries.iter().map(|entry| {
            wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(entry).unwrap())
        }));
        let mut checkpoint = Checkpoint::new(
            LOG_ID,
            self.leaves.len() as u64,
            wist_core::merkle::merkle_root(&self.leaves),
            height,
            &sealed_at,
        )
        .unwrap();
        for signer in signers {
            checkpoint.sign(signer);
        }
        self.db
            .replace_checkpoint_note(height, &checkpoint.encode())
            .unwrap();
    }
}

fn registry_update(update: Value, key_id: &str, key: &SigningKey) -> Value {
    json!({
        "type": "registry_update",
        "body": wist_core::envelope::sign_envelope(&update, "update", key_id, key).unwrap(),
    })
}

#[test]
fn an_epoch_over_the_size_bound_is_rejected_and_applies_its_key_acts_alone() {
    let genesis = SigningKey::from_seed(&[21u8; 32]);
    let second = SigningKey::from_seed(&[22u8; 32]);
    let mut log = OwnLog::new(&genesis);
    let reduction = registry_update(
        json!({
            "wist_version": "1.0.0",
            "action": "parameter_change",
            "subject": "epoch_cap_bytes",
            "details": {"parameter": "epoch_cap_bytes", "value": 65_537},
            "effective_at": wist_core::timestamp::instant(SEAL_START + 8 * 86_400).unwrap()
        }),
        "genesis",
        &genesis,
    );
    log.seal(0, &[reduction], &[&genesis]);
    let addition = registry_update(
        json!({
            "wist_version": "1.0.0",
            "action": "aggregator_key_add",
            "subject": "second",
            "details": {"alg": "Ed25519", "key_id": "second", "public_key": second.public().to_b64u()},
            "effective_at": "2026-10-01T00:00:00Z"
        }),
        "genesis",
        &genesis,
    );
    let mut oversize = vec![addition.clone()];
    for pad in ["a", "b"] {
        oversize.push(json!({"type": "label", "body": {"pad": pad.repeat(40_000)}}));
    }
    wist_core::epoch::sort_entries(&mut oversize).unwrap();
    assert!(wist_core::epoch::epoch_octets(&oversize).unwrap() > 65_537);
    log.seal(1, &oversize, &[&second]);
    log.seal(2, &[], &[&second]);

    let head = log.db.last_epoch().unwrap();
    let mut reader = clave::history::History::open(&log.db, log.data.path(), head).unwrap();
    let first = reader.next_epoch().unwrap().unwrap();
    assert_eq!(first.rejected(), None);
    let rejected = reader.next_epoch().unwrap().unwrap();
    assert_eq!(rejected.rejected(), Some(&["WIST3-E03".to_string()][..]));
    let addition_id = wist_core::registry_updates::update_id(&addition["body"]).unwrap();
    assert_eq!(
        reader
            .replay()
            .registry_updates()
            .accepted_height(&addition_id),
        Some(1)
    );
    let after = reader.next_epoch().unwrap().unwrap();
    assert_eq!(after.epoch_number(), 2);
    assert_eq!(after.rejected(), None);
    assert!(reader.next_epoch().unwrap().is_none());
    let valid: Vec<String> = reader
        .key_registry()
        .valid_at(2)
        .into_iter()
        .map(|key| key.key_id)
        .collect();
    assert_eq!(valid, ["genesis", "second"]);
    assert!(reader.replay().labels().next().is_none());
}
