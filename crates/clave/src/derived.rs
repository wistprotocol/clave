use crate::db::{Db, DerivedAuditorRow, DerivedPublisherRow, DerivedPublisherState};
use crate::error::{Error, Result};
use crate::history::extension::ExtensionHistory;
use std::path::Path;
use wist_core::crypto::SigningKey;
use wist_core::objects::SanctionDeadlineLabel;
use wist_core::reputation::PROVISIONAL_CAP_U;

type OwnedPublisherState = (
    String,
    u64,
    u8,
    u8,
    u8,
    String,
    Vec<String>,
    Vec<(SanctionDeadlineLabel, String)>,
);

fn instant(epoch: i128) -> Result<String> {
    let epoch = i64::try_from(epoch).map_err(|_| Error::History("instant out of range".into()))?;
    crate::registry::instant(epoch).map_err(|_| Error::History("instant out of range".into()))
}

pub fn refresh(db: &Db, data_dir: &Path, sk: &SigningKey) -> Result<()> {
    let Some(head) = db.last_block()? else {
        return Ok(());
    };
    let history = ExtensionHistory::reconstruct(data_dir, Some(head.clone()))?;
    let height = head.block_number;
    let sealed_at_s = crate::registry::epoch(&head.sealed_at)?;
    let mut owned: Vec<OwnedPublisherState> = Vec::new();
    for publisher in history.publishers() {
        let reputation_u = history
            .reputation(&publisher, height)
            .map_or(PROVISIONAL_CAP_U, |state| state.reputation_u);
        let level = history.sanction_level(&publisher, height);
        let enforceable = history.enforceable_level(&publisher, height);
        let mut since = height;
        let mut evidence = Vec::new();
        let mut deadlines = Vec::new();
        let mut fallback = 0u8;
        if let Some(processes) = history.processes(&publisher) {
            if let Some((at, _)) = processes.levels.iter().rev().find(|(h, _)| *h <= height) {
                since = *at;
            }
            if let Some((_, activations)) = processes
                .activations
                .iter()
                .rev()
                .find(|(h, _)| *h <= height)
            {
                evidence = activations.iter().flatten().cloned().collect();
                evidence.sort();
                evidence.dedup();
                fallback = if activations[1].is_some() {
                    2
                } else if activations[0].is_some() {
                    1
                } else {
                    0
                };
            }
            for process in &processes.accepted {
                if process.notice.block_number > height {
                    continue;
                }
                if process
                    .void_at_s
                    .is_some_and(|void| void <= i128::from(sealed_at_s))
                {
                    continue;
                }
                let now = i128::from(sealed_at_s);
                if process.appeal.is_none() && process.appeal_window_close_s > now {
                    deadlines.push((SanctionDeadlineLabel::Appeal, process.appeal_window_close_s));
                }
                if process.appeal.is_none()
                    && process.unappealed.is_none()
                    && process.seal_deadline_s > now
                {
                    deadlines.push((
                        SanctionDeadlineLabel::AppealSealing,
                        process.seal_deadline_s,
                    ));
                }
                if let Some(due) = process.ruling_deadline_s {
                    if process.merits.is_none() && due > now {
                        deadlines.push((SanctionDeadlineLabel::Ruling, due));
                    }
                }
            }
        }
        let level_since =
            instant(i128::from(history.block_sealed_at_s(since).ok_or_else(
                || Error::History("derived level has no Block".into()),
            )?))?;
        let deadlines = deadlines
            .into_iter()
            .map(|(label, at)| instant(at).map(|at| (label, at)))
            .collect::<Result<Vec<_>>>()?;
        owned.push((
            publisher,
            reputation_u,
            level,
            enforceable,
            fallback,
            level_since,
            evidence,
            deadlines,
        ));
    }
    let rows: Vec<DerivedPublisherRow> = owned
        .iter()
        .map(
            |(domain, reputation_u, level, enforceable, fallback, since, evidence, deadlines)| {
                DerivedPublisherRow {
                    domain,
                    reputation_u: *reputation_u,
                    level: *level,
                    enforceable_level: *enforceable,
                    fallback_level: *fallback,
                    level_since: since,
                    evidence,
                    deadlines,
                }
            },
        )
        .collect();
    let auditors: Vec<(String, bool)> = history
        .roster()
        .admitted_at(sealed_at_s)
        .into_iter()
        .map(|(auditor, _)| {
            (
                auditor.to_owned(),
                history.in_coverage_failure(auditor, height),
            )
        })
        .collect();
    let auditor_rows: Vec<DerivedAuditorRow> = auditors
        .iter()
        .map(|(auditor_id, coverage_failure)| DerivedAuditorRow {
            auditor_id,
            coverage_failure: *coverage_failure,
        })
        .collect();
    db.record_derived_state(height, &head.sealed_at, &rows, &auditor_rows)?;
    let mut reputation_inputs = Vec::new();
    let mut escalations = Vec::new();
    for publisher in history.publishers() {
        if let Some(inputs) = history.reputation_inputs(&publisher, height) {
            let mut digests: Vec<String> = inputs
                .counted_urls
                .iter()
                .map(|url| counted_url_digest(&publisher, url))
                .collect::<Result<_>>()?;
            digests.sort();
            let penalties = inputs
                .penalties
                .iter()
                .map(|(at, severity)| instant(i128::from(*at)).map(|at| (at, u64::from(*severity))))
                .collect::<Result<Vec<_>>>()?;
            reputation_inputs.push((
                publisher.clone(),
                instant(i128::from(inputs.first_accepted_sealed_at_s))?,
                inputs.reset_height,
                inputs.counted_total,
                digests,
                penalties,
            ));
        }
        if let Some(establishing) = history.live_escalation(&publisher, height) {
            escalations.push((publisher.clone(), instant(i128::from(establishing))?));
        }
    }
    let reputation_rows: Vec<crate::db::DerivedReputationInputsRow> = reputation_inputs
        .iter()
        .map(|(domain, first, reset, total, digests, penalties)| {
            crate::db::DerivedReputationInputsRow {
                domain,
                first_accepted_at: first,
                reset_height: *reset,
                counted_total: *total,
                counted_url_digests: digests,
                penalties,
            }
        })
        .collect();
    let failures: Vec<(String, u64)> = auditors
        .iter()
        .flat_map(|(auditor_id, _)| {
            history
                .counting_failures(auditor_id, height)
                .into_iter()
                .map(move |duty| (auditor_id.clone(), duty))
        })
        .collect();
    db.record_derived_snapshot_inputs(height, &reputation_rows, &escalations, &failures)?;
    db.record_derived_exclusions(height, &history.exclusions(height))?;
    let commitments: Vec<crate::db::DerivedCanaryCommitment> = history
        .live_commitments(height)
        .into_iter()
        .map(|c| {
            (
                c.id.clone(),
                c.planter.clone(),
                c.root.clone(),
                c.leaves,
                c.height,
            )
        })
        .collect();
    db.record_derived_canary_commitments(height, &commitments)?;
    remove_failed_auditors(db, sk, &history, &head, &auditors)
}

/// WIST-3 §7: the first 16 octets of SHA-256(JCS(domain) ‖ JCS(URL)),
/// lowercase hex, standing in for a counted URL in the state artifact.
pub fn counted_url_digest(domain: &str, url: &str) -> Result<String> {
    use sha2::Digest;
    let mut preimage = wist_core::jcs::canonicalize(&serde_json::Value::String(domain.to_owned()))
        .map_err(|e| Error::History(e.to_string()))?;
    preimage.extend(
        wist_core::jcs::canonicalize(&serde_json::Value::String(url.to_owned()))
            .map_err(|e| Error::History(e.to_string()))?,
    );
    Ok(wist_core::crypto::hex_encode(
        &sha2::Sha256::digest(&preimage)[..16],
    ))
}

/// WIST-4 §4: an Auditor in coverage failure MUST be removed by an
/// `auditor_remove` whose `evidence` names the failed Blocks. The removal
/// records a consequence the Log already derives; it is queued once, for
/// the key the Auditor holds at the head, and the next seal records it.
fn remove_failed_auditors(
    db: &Db,
    sk: &SigningKey,
    history: &ExtensionHistory,
    head: &crate::db::BlockRow,
    auditors: &[(String, bool)],
) -> Result<()> {
    let (pending, _) = db.peek_pending_entries()?;
    let sealed_at_s = crate::registry::epoch(&head.sealed_at)?;
    for (auditor_id, failing) in auditors {
        if !failing {
            continue;
        }
        let already_queued = pending.iter().any(|entry| {
            entry.entry_type == "registry_update"
                && entry.entry_json["update"]["action"] == "auditor_remove"
                && entry.entry_json["update"]["subject"] == auditor_id.as_str()
        });
        if already_queued {
            continue;
        }
        let Some(key) = history.roster().admitted_key_at(auditor_id, sealed_at_s) else {
            continue;
        };
        let mut evidence: Vec<String> = history
            .counting_failures(auditor_id, head.block_number)
            .into_iter()
            .filter_map(|duty| history.block_hash(duty).map(str::to_owned))
            .collect();
        evidence.sort();
        if evidence.is_empty() {
            continue;
        }
        let update = serde_json::json!({
            "wist_version": crate::WIST_VERSION,
            "action": "auditor_remove",
            "subject": auditor_id,
            "details": {"key_id": key.key_id},
            "evidence": evidence,
            "effective_at": head.sealed_at,
        });
        let envelope = wist_core::envelope::sign_envelope(&update, "update", "log1", sk)?;
        db.insert_pending_entry("registry_update", "", &envelope, 0)?;
    }
    Ok(())
}

pub fn publisher_state(db: &Db, domain: &str, at: &str) -> Result<Option<DerivedPublisherState>> {
    db.derived_publisher_state_at(domain, at)
}

pub fn reputation_for_day(db: &Db, domain: &str, at: &str) -> Result<u64> {
    let day_start = format!("{}T00:00:00Z", at.get(..10).unwrap_or(at));
    Ok(db
        .derived_publisher_state_before(domain, &day_start)?
        .map_or(PROVISIONAL_CAP_U, |state| state.reputation_u))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counted_url_digests_match_the_state_example() {
        let root = std::env::var_os("WIST_SPEC_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
            });
        let state: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("examples/snapshot-state.json")).unwrap(),
        )
        .unwrap();
        let entries = state["state"]["entries"].as_array().unwrap();
        let inputs = entries
            .iter()
            .find(|e| e[0] == "reputation_inputs" && e[1] == "example.com")
            .unwrap();
        let digests: Vec<&str> = inputs[5]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap())
            .collect();
        assert!(!digests.is_empty());
        let matched = entries
            .iter()
            .filter(|e| e[0] == "record" && e[1] == "example.com")
            .map(|e| counted_url_digest("example.com", e[2].as_str().unwrap()).unwrap())
            .filter(|digest| digests.contains(&digest.as_str()))
            .count();
        assert_eq!(matched, digests.len());
        assert_ne!(
            counted_url_digest("example.com", "https://example.com/x").unwrap(),
            counted_url_digest("other.example", "https://example.com/x").unwrap()
        );
    }
}
