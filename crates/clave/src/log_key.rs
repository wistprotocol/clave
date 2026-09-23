//! WIST-3 §3.4: every key after the Anchor's genesis key is admitted by an
//! `aggregator_key_add` and retired by an `aggregator_key_remove`, each
//! signed under a key valid at the height below the Epoch that seals it.
use crate::db::Db;
use crate::error::{Error, Result};
use crate::keys::{self, Store};
use crate::WIST_VERSION;
use serde_json::Value;
use std::path::Path;
use wist_core::crypto::{PublicKey, SigningKey};

#[derive(Debug)]
pub struct AddReport {
    pub key_id: String,
    pub note_key_id: String,
    pub public_key: String,
    pub verifier_key: String,
    pub update_id: String,
}

#[derive(Debug)]
pub struct RemoveReport {
    pub key_id: String,
    pub update_id: String,
}

#[derive(Debug)]
pub struct Listing {
    pub key_id: String,
    pub note_key_id: String,
    pub added_height: Option<u64>,
    pub removed_height: Option<u64>,
    pub held: bool,
}

struct Queued {
    action: String,
    key_id: String,
    public_key: Option<PublicKey>,
}

fn queued_key_acts(db: &Db) -> Result<Vec<Queued>> {
    let (pending, _) = db.peek_pending_entries()?;
    let mut acts = Vec::new();
    for row in pending {
        if row.entry_type != "registry_update" {
            continue;
        }
        let update = &row.entry_json["update"];
        let action = match update["action"].as_str() {
            Some(action @ ("aggregator_key_add" | "aggregator_key_remove")) => action.to_owned(),
            _ => continue,
        };
        let Some(key_id) = update["details"]["key_id"].as_str() else {
            continue;
        };
        acts.push(Queued {
            action,
            key_id: key_id.to_owned(),
            public_key: update["details"]["public_key"]
                .as_str()
                .and_then(|encoded| PublicKey::from_b64u(encoded).ok()),
        });
    }
    Ok(acts)
}

/// WIST-3 §3.4's admitted set once the queued acts seal, removed keys
/// included.
fn admitted(store: &Store, queued: &[Queued]) -> Vec<String> {
    store
        .keys()
        .iter()
        .map(|key| key.key_id.clone())
        .chain(
            queued
                .iter()
                .filter(|act| act.action == "aggregator_key_add")
                .map(|act| act.key_id.clone()),
        )
        .collect()
}

fn admitted_note_key_ids(store: &Store, queued: &[Queued]) -> Vec<String> {
    let log_id = store.log_id().to_owned();
    store
        .keys()
        .iter()
        .map(|key| key.note_key_id(&log_id))
        .chain(queued.iter().filter_map(|act| {
            act.public_key.as_ref().map(|key| {
                wist_core::crypto::hex_encode(&wist_core::checkpoint::aggregator_key_id(
                    &log_id, key,
                ))
            })
        }))
        .collect()
}

/// WIST-3 §3.4, §5: the keys the next Epoch's Checkpoint would be signed
/// under.
fn valid_after_queue(store: &Store, queued: &[Queued], height: u64) -> Vec<String> {
    let mut valid: Vec<String> = store
        .valid_at(height)
        .iter()
        .map(|key| key.key_id.clone())
        .collect();
    for act in queued {
        if act.action == "aggregator_key_add" {
            if !valid.contains(&act.key_id) {
                valid.push(act.key_id.clone());
            }
        } else {
            valid.retain(|key_id| *key_id != act.key_id);
        }
    }
    valid
}

fn whole_second(unix: i64) -> Result<String> {
    Ok(jiff::Timestamp::from_second(unix)
        .map_err(|_| Error::Governance("timestamp out of range".into()))?
        .to_string())
}

fn next_key_id(store: &Store, queued: &[Queued]) -> String {
    let taken = |candidate: &str| {
        admitted(store, queued).iter().any(|key| key == candidate)
            || store
                .unadmitted()
                .iter()
                .any(|(key_id, _)| key_id == candidate)
    };
    (2u64..)
        .map(|n| format!("log{n}"))
        .find(|candidate| !taken(candidate))
        .expect("the key_id space is unbounded")
}

/// The seed reaches disk before the act is queued, so no sealed act ever
/// names a key this Aggregator cannot sign with.
pub fn add(db: &Db, data_dir: &Path, now_unix: i64) -> Result<AddReport> {
    let store = Store::open(data_dir, db)?;
    let height = keys::head_height(db)?;
    let signer = store.signer_at(height)?;
    let signing = signer
        .signing()
        .ok_or_else(|| Error::Key("the signing key is not held".into()))?;
    let signer_key_id = signer.key_id.clone();
    let queued = queued_key_acts(db)?;
    let key_id = next_key_id(&store, &queued);

    let (seed, generated) = keys::generate();
    let public_key = keys::public_b64u(&seed);
    let note_key_id = wist_core::crypto::hex_encode(&wist_core::checkpoint::aggregator_key_id(
        store.log_id(),
        &generated.public(),
    ));
    if admitted_note_key_ids(&store, &queued).contains(&note_key_id) {
        return Err(Error::Governance(format!(
            "WIST4-E04 aggregator_key_add {key_id} is not queued: its note key ID {note_key_id} is one an admitted key already derives (WIST-3 \u{a7}3.4)"
        )));
    }
    keys::save_seed(
        &keys::seed_path(data_dir, &key_id, store.genesis_key_id()),
        &seed,
    )?;

    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "aggregator_key_add",
        "subject": key_id,
        "details": {"key_id": key_id, "alg": "Ed25519", "public_key": public_key},
        "effective_at": whole_second(now_unix)?,
    });
    let update_id = enqueue(db, &signer_key_id, &signing, update)?;
    Ok(AddReport {
        key_id,
        note_key_id,
        public_key,
        verifier_key: wist_core::checkpoint::verifier_key(store.log_id(), &generated.public()),
        update_id,
    })
}

/// Refuses every removal WIST-3 §3.4 makes a key-act failure or that would
/// leave the next Epoch without a valid Checkpoint.
pub fn remove(db: &Db, data_dir: &Path, key_id: &str, now_unix: i64) -> Result<RemoveReport> {
    let store = Store::open(data_dir, db)?;
    let height = keys::head_height(db)?;
    let signer = store.signer_at(height)?;
    let signing = signer
        .signing()
        .ok_or_else(|| Error::Key("the signing key is not held".into()))?;
    let signer_key_id = signer.key_id.clone();
    if !store
        .valid_at(height)
        .iter()
        .any(|key| key.key_id == key_id)
    {
        return Err(Error::Governance(format!(
            "WIST4-E04 aggregator_key_remove {key_id} is not queued: no key of that key_id is valid at height {height}, the height the act authenticates at (WIST-3 \u{a7}3.4)"
        )));
    }
    let mut queued = queued_key_acts(db)?;
    queued.push(Queued {
        action: "aggregator_key_remove".into(),
        key_id: key_id.to_owned(),
        public_key: None,
    });
    let next = height.saturating_add(1);
    if valid_after_queue(&store, &queued, height).is_empty() {
        return Err(Error::Governance(format!(
            "aggregator_key_remove {key_id} is not queued: with the key acts already queued it would leave no Aggregator key valid at height {next}, which leaves that Epoch no valid Checkpoint (WIST-3 \u{a7}3.4)"
        )));
    }

    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "aggregator_key_remove",
        "subject": key_id,
        "details": {"key_id": key_id},
        "effective_at": whole_second(now_unix)?,
    });
    let update_id = enqueue(db, &signer_key_id, &signing, update)?;
    Ok(RemoveReport {
        key_id: key_id.to_owned(),
        update_id,
    })
}

fn enqueue(db: &Db, key_id: &str, signing: &SigningKey, update: Value) -> Result<String> {
    let update_id = crate::governance::update_id(&update)?;
    let envelope = wist_core::envelope::sign_envelope(&update, "update", key_id, signing)?;
    db.insert_pending_entry("registry_update", "", &envelope, 0)?;
    Ok(update_id)
}

pub fn list(db: &Db, data_dir: &Path) -> Result<Vec<Listing>> {
    let store = Store::open(data_dir, db)?;
    let log_id = store.log_id().to_owned();
    let mut listings: Vec<Listing> = store
        .keys()
        .iter()
        .map(|key| Listing {
            key_id: key.key_id.clone(),
            note_key_id: key.note_key_id(&log_id),
            added_height: Some(key.added_height),
            removed_height: key.removed_height,
            held: key.held(),
        })
        .collect();
    listings.extend(
        store
            .unadmitted()
            .iter()
            .map(|(key_id, public_key)| Listing {
                key_id: key_id.clone(),
                note_key_id: wist_core::crypto::hex_encode(
                    &wist_core::checkpoint::aggregator_key_id(&log_id, public_key),
                ),
                added_height: None,
                removed_height: None,
                held: true,
            }),
    );
    Ok(listings)
}
