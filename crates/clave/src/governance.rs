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
    /// A level-3/4 sanction queues a notice alongside it. The notice has
    /// no Registry Update ID yet: WIST-4 §9.1 has its `appeal_deadline`
    /// restate the sealing Block's `sealed_at`, which the Block that
    /// seals it fixes, and the ID follows the bytes.
    pub notice_queued: bool,
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

/// WIST-4 §7/§9.1: a `sanction` records a ladder action the derived state
/// already shows; its primary finding is a first confirming Record of the
/// domain with the severity the closed confirming set fixes, and a level-3
/// or level-4 action seals a notice naming the activation that armed the
/// rung before the sanction can be enforced.
#[allow(clippy::too_many_arguments)]
pub fn sanction(
    db: &Db,
    data_dir: &std::path::Path,
    sk: &SigningKey,
    domain: &str,
    level: i64,
    severity: i64,
    finding: &str,
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
    if !is_evidence_id(finding) {
        return Err(Error::Governance(format!(
            "malformed finding id {finding:?}"
        )));
    }
    if evidence.len() < 2 || !evidence.iter().all(|e| is_evidence_id(e)) {
        return Err(Error::Governance(
            "evidence must name at least two Audit Record IDs (WIST-4 \u{a7}9.1)".into(),
        ));
    }
    if !evidence.iter().any(|id| id == finding) {
        return Err(Error::Governance(
            "evidence must include the primary finding's first confirming Record (WIST-4 \u{a7}9.1)".into(),
        ));
    }
    let head = db.last_block()?.ok_or_else(|| {
        Error::Governance("no sealed history: a sanction records a derived finding".into())
    })?;
    let history =
        crate::history::extension::ExtensionHistory::reconstruct(data_dir, Some(head.clone()))?;
    let derived = history
        .findings()
        .iter()
        .find(|f| f.publisher == domain && f.confirming_record_id == finding)
        .ok_or_else(|| {
            Error::Governance(format!(
                "{finding} is not a first confirming Record of a finding against {domain}"
            ))
        })?;
    if i64::from(derived.severity) != severity {
        return Err(Error::Governance(format!(
            "the finding's closed confirming set has severity {}, not {severity} (WIST-4 \u{a7}7)",
            derived.severity
        )));
    }
    let ladder = history.sanction_level(domain, head.block_number);
    if i64::from(ladder) < level {
        return Err(Error::Governance(format!(
            "the derived ladder for {domain} reaches level {ladder}, not {level} (WIST-4 \u{a7}7)"
        )));
    }
    let now = whole_second(now_epoch)?;

    let notice_queued = if level >= 3 {
        let reason = reason.ok_or_else(|| {
            Error::Governance(
                "a level 3/4 sanction notice requires --reason (WIST-4 \u{a7}7)".into(),
            )
        })?;
        let activation = history
            .processes(domain)
            .and_then(|processes| processes.activations.last())
            .and_then(|(_, activations)| activations[(level - 1) as usize].clone())
            .ok_or_else(|| {
                Error::Governance(format!(
                    "no active level-{level} activation for {domain} (WIST-4 \u{a7}7)"
                ))
            })?;
        let window_days = registry::effective(db, "appeal_window_days", &now)?;
        let appeal_deadline = whole_second(now_epoch + window_days * DAY)?;
        let notice = serde_json::json!({
            "wist_version": WIST_VERSION,
            "action": "notice",
            "subject": domain,
            "details": {"kind": "sanction", "level": level, "activation": activation,
                        "reason": reason, "appeal_deadline": appeal_deadline},
            "evidence": evidence,
            "effective_at": now,
        });
        enqueue(db, sk, notice)?;
        true
    } else {
        false
    };

    let sanction = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "sanction",
        "subject": domain,
        "details": {"level": level, "severity": severity, "finding": finding},
        "evidence": evidence,
        "effective_at": now,
    });
    let id = enqueue(db, sk, sanction)?;
    Ok(GovernanceReport {
        update_id: id,
        notice_queued,
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
        notice_queued: false,
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
        notice_queued: false,
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
    if !db.is_delta_seen_for(delta_id, domain)? {
        return Err(Error::Governance(format!(
            "{delta_id} is not a sealed or accepted Delta of {domain} (WIST-4 \u{a7}9.1)"
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
    Ok(GovernanceReport {
        update_id: id,
        notice_queued: false,
    })
}
