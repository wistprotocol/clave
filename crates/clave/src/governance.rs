use crate::db::Db;
use crate::error::{Error, Result};
use crate::registry;
use crate::WIST_VERSION;
use serde_json::Value;
use sha2::{Digest, Sha256};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;

const GENESIS_KEY_ID: &str = "log1";
const DAY: i64 = 86400;

pub struct GovernanceReport {
    pub update_id: String,
    pub notice_id: Option<String>,
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

fn is_evidence_id(id: &str) -> bool {
    id.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
}

#[allow(clippy::too_many_arguments)]
pub fn sanction(
    db: &Db,
    sk: &SigningKey,
    domain: &str,
    level: i64,
    severity: i64,
    evidence: &[String],
    reason: Option<&str>,
    now_epoch: i64,
) -> Result<GovernanceReport> {
    if !(1..=4).contains(&level) {
        return Err(Error::Governance(format!("level must be 1-4, got {level}")));
    }
    if !(1..=3).contains(&severity) {
        return Err(Error::Governance(format!(
            "severity must be 1-3, got {severity}"
        )));
    }
    if evidence.len() < 2 || !evidence.iter().all(|e| is_evidence_id(e)) {
        return Err(Error::Governance(
            "evidence must name at least two Audit Record IDs (WIST-4 \u{a7}9.1)".into(),
        ));
    }
    let now = whole_second(now_epoch)?;

    let notice_id = if level >= 3 {
        let reason = reason.ok_or_else(|| {
            Error::Governance(
                "a level 3/4 sanction notice requires --reason (WIST-4 \u{a7}7)".into(),
            )
        })?;
        let window_days = registry::effective(db, "appeal_window_days", &now)?;
        let appeal_deadline = whole_second(now_epoch + window_days * DAY)?;
        let notice = serde_json::json!({
            "wist_version": WIST_VERSION,
            "action": "notice",
            "subject": domain,
            "details": {"kind": "sanction", "reason": reason, "appeal_deadline": appeal_deadline},
            "evidence": evidence,
            "effective_at": now,
        });
        Some(enqueue(db, sk, notice)?)
    } else {
        None
    };

    let sanction = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "sanction",
        "subject": domain,
        "details": {"level": level, "severity": severity},
        "evidence": evidence,
        "effective_at": now,
    });
    let id = enqueue(db, sk, sanction)?;
    Ok(GovernanceReport {
        update_id: id,
        notice_id,
    })
}

pub fn rule(
    db: &Db,
    sk: &SigningKey,
    domain: &str,
    notice_id: &str,
    outcome: &str,
    reasoning: &str,
    now_epoch: i64,
) -> Result<GovernanceReport> {
    if !["upheld", "overturned", "unappealed"].contains(&outcome) {
        return Err(Error::Governance(format!("invalid outcome {outcome:?}")));
    }
    let now = whole_second(now_epoch)?;
    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "appeal_ruling",
        "subject": domain,
        "details": {"notice": notice_id, "outcome": outcome, "reasoning": reasoning},
        "effective_at": now,
    });
    let id = enqueue(db, sk, update)?;
    Ok(GovernanceReport {
        update_id: id,
        notice_id: Some(notice_id.to_string()),
    })
}

pub fn lift(db: &Db, sk: &SigningKey, domain: &str, now_epoch: i64) -> Result<GovernanceReport> {
    let now = whole_second(now_epoch)?;
    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "sanction_lift",
        "subject": domain,
        "details": {},
        "effective_at": now,
    });
    let id = enqueue(db, sk, update)?;
    Ok(GovernanceReport {
        update_id: id,
        notice_id: None,
    })
}

pub fn withdraw(
    db: &Db,
    sk: &SigningKey,
    domain: &str,
    delta_id: &str,
    legal_basis: &str,
    jurisdiction: &str,
    now_epoch: i64,
) -> Result<GovernanceReport> {
    if !is_evidence_id(delta_id) {
        return Err(Error::Governance(format!(
            "malformed delta id {delta_id:?}"
        )));
    }
    if legal_basis.is_empty() || jurisdiction.is_empty() {
        return Err(Error::Governance(
            "payload_withdrawal requires legal_basis and jurisdiction (WIST-3 \u{a7}6.2)".into(),
        ));
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
    Ok(GovernanceReport {
        update_id: id,
        notice_id: None,
    })
}
