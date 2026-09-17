use crate::db::Db;
use crate::error::{Error, Result};
use crate::WIST_VERSION;
use serde_json::Value;
use sha2::{Digest, Sha256};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;

const GENESIS_KEY_ID: &str = "log1";

pub struct GovernanceReport {
    pub update_id: String,
}

fn whole_second(epoch: i64) -> Result<String> {
    Ok(jiff::Timestamp::from_second(epoch)
        .map_err(|_| Error::ParamChange("timestamp out of range".into()))?
        .to_string())
}

pub fn update_id(update: &Value) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(wist_core::jcs::canonicalize(update)?))
    ))
}

fn enqueue(db: &Db, sk: &SigningKey, update: Value) -> Result<String> {
    let id = update_id(&update)?;
    let envelope = sign_envelope(&update, "update", GENESIS_KEY_ID, sk)?;
    db.insert_pending_entry("registry_update", "", &envelope, 0)?;
    Ok(id)
}

fn is_delta_id(id: &str) -> bool {
    id.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
}

/// WIST-4 §5.1 and WIST-3 §6.2: queues a `payload_withdrawal` naming a
/// Delta of `domain` the Log has accepted; the seal checks that the Delta
/// is sealed at or below the act's Block before the act is sealed.
pub fn withdraw(
    db: &Db,
    sk: &SigningKey,
    domain: &str,
    delta_id: &str,
    legal_basis: &str,
    jurisdiction: &str,
    now_epoch: i64,
) -> Result<GovernanceReport> {
    if !is_delta_id(delta_id) {
        return Err(Error::Governance(format!(
            "malformed delta id {delta_id:?}"
        )));
    }
    if legal_basis.is_empty() || jurisdiction.is_empty() {
        return Err(Error::Governance(
            "payload_withdrawal requires legal_basis and jurisdiction (WIST-3 \u{a7}6.2)".into(),
        ));
    }
    if !db.is_delta_seen_for(delta_id, domain)? {
        return Err(Error::Governance(format!(
            "{delta_id} is not a sealed or accepted Delta of {domain} (WIST-4 \u{a7}5.1)"
        )));
    }
    let now = whole_second(now_epoch)?;
    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "payload_withdrawal",
        "subject": domain,
        "details": {"delta_id": delta_id, "legal_basis": legal_basis, "jurisdiction": jurisdiction},
        "effective_at": now,
    });
    let id = enqueue(db, sk, update)?;
    Ok(GovernanceReport { update_id: id })
}
