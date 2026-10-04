mod common;

use serde_json::{json, Value};
use wist_core::crypto::SigningKey;
use wist_core::objects::{DeclarationEntry, StateEntry};
use wist_core::sealing::{Epoch, Outcome, Parameters, Replay};

const SEAL_START: i64 = 1_786_276_800;
const LOG_ID: &str = "log.example.org";
const HOST: &str = "publisher.example";
const SIZE_REJECTED: &str = "WIST3-E03";

struct Store {
    data: tempfile::TempDir,
    db: clave::db::Db,
    sk: SigningKey,
}

impl Store {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run(LOG_ID, data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        Store { data, db, sk }
    }

    fn sealed_at(height: u64) -> String {
        wist_core::timestamp::instant(SEAL_START + height as i64 * 3600).unwrap()
    }

    fn seal(&self, height: u64, mut entries: Vec<Value>) -> Vec<Value> {
        wist_core::epoch::sort_entries(&mut entries).unwrap();
        self.db
            .commit_seal(
                &self.sk,
                LOG_ID,
                &[],
                height,
                &Self::sealed_at(height),
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
        entries
    }

    fn act(&self, update: Value) -> Value {
        json!({
            "type": "registry_update",
            "body": wist_core::envelope::sign_envelope(&update, "update", clave::keys::GENESIS_KEY_ID, &self.sk).unwrap(),
        })
    }

    fn snapshot(&self) -> (Vec<StateEntry>, Value) {
        let read = |path: &std::path::Path| -> Value {
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
        };
        clave::snapshot::produce(&self.data.path().join("clave.sqlite"), self.data.path()).unwrap();
        let index = read(&self.data.path().join("snapshots/index.json"));
        let manifest_url = index["index"]["snapshots"][0]["manifest_url"]
            .as_str()
            .unwrap()
            .trim_start_matches('/')
            .to_string();
        let manifest_path = self.data.path().join(&manifest_url);
        let manifest = read(&manifest_path);
        let state = read(
            &manifest_path
                .parent()
                .unwrap()
                .join(manifest["manifest"]["state"]["path"].as_str().unwrap()),
        );
        (
            serde_json::from_value(state["state"]["entries"].clone()).unwrap(),
            manifest["manifest"]["state"]["state_digest"].clone(),
        )
    }
}

fn first_install(seed: &[u8; 32]) -> Value {
    let publisher = json!({
        "wist_version": "1.0.0",
        "domain": HOST,
        "keys": [common::key_entry(seed, "2026-08-09T00:00:00Z")],
        "seq": 0,
    });
    let envelope = wist_core::envelope::sign_envelope(
        &publisher,
        "publisher",
        &common::kid(seed),
        &SigningKey::from_seed(seed),
    )
    .unwrap();
    json!({"type": "publisher_declaration", "body": envelope})
}

fn declaration_tuples(entries: &[StateEntry]) -> Vec<&StateEntry> {
    entries
        .iter()
        .filter(|entry| {
            matches!(
                entry,
                StateEntry::Declaration(_)
                    | StateEntry::PendingDeclaration(_)
                    | StateEntry::RecoveryWindow(_)
            )
        })
        .collect()
}

fn digest(entries: &[StateEntry]) -> String {
    let values: Vec<Value> = entries
        .iter()
        .map(|entry| serde_json::to_value(entry).unwrap())
        .collect();
    wist_core::snapshot::state_digest(&values).unwrap()
}

#[test]
fn an_over_size_rejected_epoch_installs_no_declaration_in_the_snapshot_state() {
    let store = Store::new();
    let reduction = store.act(json!({
        "wist_version": "1.0.0",
        "action": "parameter_change",
        "subject": "epoch_cap_bytes",
        "details": {"parameter": "epoch_cap_bytes", "value": 65_537},
        "effective_at": wist_core::timestamp::instant(SEAL_START + 8 * 86_400).unwrap(),
    }));
    let reduction_id = wist_core::registry_updates::update_id(&reduction["body"]).unwrap();
    let mut oversize = vec![first_install(&common::K1_SEED)];
    for pad in ["a", "b"] {
        oversize.push(json!({"type": "label", "body": {"pad": pad.repeat(40_000)}}));
    }
    let sealed = [
        store.seal(0, vec![reduction]),
        store.seal(1, oversize),
        store.seal(2, Vec::new()),
    ];
    assert!(wist_core::epoch::epoch_octets(&sealed[1]).unwrap() > 65_537);

    let mut replay = Replay::new();
    let parameters = Parameters::suite();
    let no_key = |_: &str| None;
    for (height, entries) in sealed.iter().enumerate() {
        let row = store.db.epoch_at(height as u64).unwrap().unwrap();
        let epoch = Epoch {
            height: height as u64,
            root: &row.root,
            sealed_at: &row.sealed_at,
            parameters: &parameters,
            suffix_list: None,
            log_key: &no_key,
            entries,
        };
        let outcome = if height == 1 {
            replay.reject_epoch(&epoch, vec![SIZE_REJECTED.to_owned()])
        } else {
            replay.epoch(&epoch)
        }
        .unwrap();
        assert_eq!(matches!(outcome, Outcome::Rejected { .. }), height == 1);
    }
    replay.accept_registry_update(&reduction_id, 0);
    assert!(replay.declarations().domains().is_empty());

    let (entries, served_digest) = store.snapshot();
    assert!(declaration_tuples(&entries).is_empty());
    let mut expected: Vec<StateEntry> = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry,
                StateEntry::AggregatorKey(_)
                    | StateEntry::Parameter(_)
                    | StateEntry::SuffixList(_)
                    | StateEntry::Label(_)
                    | StateEntry::Dispute(_)
            )
        })
        .cloned()
        .collect();
    expected.extend(replay.state_entries());
    expected.extend(
        replay
            .declarations()
            .domains()
            .iter()
            .map(|(domain, state)| {
                StateEntry::Declaration(DeclarationEntry {
                    domain: domain.clone(),
                    declaration: state.current().envelope().clone(),
                    sealing_height: state.current().position().epoch_number,
                    highest_accepted_seq: state.highest_accepted_seq(),
                })
            }),
    );
    assert_eq!(served_digest, digest(&expected));
    assert_eq!(served_digest, digest(&entries));
}

#[test]
fn an_epoch_rejected_for_conflicting_declarations_still_builds_its_snapshot() {
    let store = Store::new();
    store.seal(0, Vec::new());
    store.seal(
        1,
        vec![first_install(&common::K1_SEED), first_install(&[2u8; 32])],
    );
    store.seal(2, Vec::new());
    let head = store.db.last_epoch().unwrap();
    let mut reader = clave::history::History::open(&store.db, store.data.path(), head).unwrap();
    let mut rejected = Vec::new();
    while let Some(epoch) = reader.next_epoch().unwrap() {
        rejected.push(epoch.rejected().map(<[String]>::to_vec));
    }
    assert_eq!(
        rejected,
        [None, Some(vec!["WIST1-E08".to_owned()]), None],
        "the conflicting Declarations reject Epoch 1"
    );

    let (entries, _) = store.snapshot();
    assert!(declaration_tuples(&entries).is_empty());
}
