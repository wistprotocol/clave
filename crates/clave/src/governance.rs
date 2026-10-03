use crate::db::Db;
use crate::error::{Error, Result};
use crate::WIST_VERSION;
use serde_json::Value;
use sha2::{Digest, Sha256};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::withdrawal::SealedItems;

pub struct GovernanceReport {
    pub update_id: String,
}

fn whole_second(unix: i64) -> Result<String> {
    Ok(jiff::Timestamp::from_second(unix)
        .map_err(|_| Error::ParamChange("timestamp out of range".into()))?
        .to_string())
}

pub fn update_id(update: &Value) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(wist_core::jcs::canonicalize(update)?))
    ))
}

pub(crate) fn enqueue(db: &Db, sk: &SigningKey, update: Value) -> Result<String> {
    let id = update_id(&update)?;
    let envelope = sign_envelope(&update, "update", &db.signing_key_id(&sk.public())?, sk)?;
    db.insert_pending_entry("registry_update", "", &envelope, 0)?;
    Ok(id)
}

fn is_item_id(id: &str) -> bool {
    id.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// WIST-4 §5.1: the Item must be sealed for the subject at or below the act's Epoch.
pub fn withdraw(
    db: &Db,
    sk: &SigningKey,
    domain: &str,
    item_id: &str,
    legal_basis: &str,
    jurisdiction: &str,
    now_unix: i64,
) -> Result<GovernanceReport> {
    if !is_item_id(item_id) {
        return Err(Error::Governance(format!("malformed Item ID {item_id:?}")));
    }
    if legal_basis.is_empty() || jurisdiction.is_empty() {
        return Err(Error::Governance(
            "payload_withdrawal requires legal_basis and jurisdiction (WIST-3 \u{a7}6.2)".into(),
        ));
    }
    let height = db.last_epoch()?.map_or(0, |epoch| epoch.epoch_number + 1);
    if sealed_items(db)?.meets_contract(item_id, domain, height) != Some(true) {
        return Err(Error::Governance(format!(
            "{item_id} is not an Item sealed for {domain} (WIST-4 \u{a7}5.1)"
        )));
    }
    let now = whole_second(now_unix)?;
    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "payload_withdrawal",
        "subject": domain,
        "details": {"delta_id": item_id, "legal_basis": legal_basis, "jurisdiction": jurisdiction},
        "effective_at": now,
    });
    let id = enqueue(db, sk, update)?;
    Ok(GovernanceReport { update_id: id })
}

pub(crate) fn sealed_items(db: &Db) -> Result<SealedItems> {
    db.sealed_items()
}
