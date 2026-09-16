use crate::db::Db;
use crate::error::Result;
use crate::fetch::Client;
use serde_json::Value;
use wist_core::crypto::PublicKey;
use wist_core::envelope::verify_envelope;

const SELF_SIGNED_ACTIONS: [&str; 4] = [
    "observer_register",
    "observer_checkpoint",
    "canary_commitment",
    "canary_reveal",
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SubmissionsReport {
    pub queued: Vec<String>,
    pub skipped: Vec<(String, &'static str)>,
    pub served: bool,
}

/// WIST-4 §9.1: a domain serves the Registry Updates it signs for itself
/// at its submissions path; the Aggregator fetches it with every Feed pull
/// and queues each item that verifies and that no sealed Entry carries.
pub fn pull(db: &Db, client: &Client, domain: &str) -> Result<SubmissionsReport> {
    let scheme = crate::fetch::scheme_for_host(domain, client.allow_http());
    let url = format!("{scheme}://{domain}/.well-known/wist/registry.json");
    let served = client.get_json(&url).ok().map(|(_, value)| value);
    queue_served(db, domain, served.as_ref())
}

/// Queues the eligible items of a fetched submissions file; `None` is an
/// absent or unreadable path, which queues nothing and is no fault.
pub fn queue_served(db: &Db, domain: &str, served: Option<&Value>) -> Result<SubmissionsReport> {
    let mut report = SubmissionsReport::default();
    let Some(served) = served else {
        return Ok(report);
    };
    report.served = true;
    let Some(items) = served.as_array() else {
        report.skipped.push((domain.to_owned(), "not an array"));
        return Ok(report);
    };
    let (pending, _) = db.peek_pending_entries()?;
    let mut queued: Vec<String> = pending
        .iter()
        .filter(|entry| entry.entry_type == "registry_update")
        .filter_map(|entry| crate::governance::update_id(&entry.entry_json["update"]).ok())
        .collect();
    for item in items {
        let Ok(id) = crate::governance::update_id(&item["update"]) else {
            report
                .skipped
                .push((String::new(), "not a Registry Update"));
            continue;
        };
        if let Err(reason) = eligible(db, domain, item) {
            report.skipped.push((id, reason));
            continue;
        }
        if queued.contains(&id) || db.registry_update_sealed(&id)? {
            report.skipped.push((id, "already queued or sealed"));
            continue;
        }
        db.insert_pending_entry("registry_update", domain, item, 0)?;
        queued.push(id.clone());
        report.queued.push(id);
    }
    Ok(report)
}

/// WIST-4 §3.1: once the head Block closes a budgeting epoch, the Observers
/// that epoch budgets are due a submissions pull before the following
/// epoch's last Block seals. Returns the closed epoch and its Observers.
pub fn epoch_pull_targets(
    history: &crate::history::extension::ExtensionHistory,
) -> Option<(u64, Vec<String>)> {
    let head = history.through()?.block_number;
    let epoch = history.epoch_of(head)?;
    if u128::from(head) != epoch.last() {
        return None;
    }
    Some((epoch.number, history.budgeted_observers(&epoch)))
}

/// Pulls the submissions path of every Observer the just-closed epoch
/// budgets, once per epoch, queueing what verifies.
pub fn poll_epoch(db: &Db, client: &Client, data_dir: &std::path::Path) -> Result<Vec<String>> {
    let Some(head) = db.last_block()? else {
        return Ok(Vec::new());
    };
    let history =
        crate::history::extension::ExtensionHistory::reconstruct(data_dir, Some(head.clone()))?;
    let Some((epoch, observers)) = epoch_pull_targets(&history) else {
        return Ok(Vec::new());
    };
    if db.epoch_pulled(epoch)? {
        return Ok(Vec::new());
    }
    let mut queued = Vec::new();
    for observer in observers {
        queued.extend(pull(db, client, &observer)?.queued);
    }
    db.record_epoch_pull(epoch, head.block_number)?;
    Ok(queued)
}

fn eligible(db: &Db, domain: &str, item: &Value) -> std::result::Result<(), &'static str> {
    let update = &item["update"];
    let action = update["action"].as_str().ok_or("missing action")?;
    if !SELF_SIGNED_ACTIONS.contains(&action) {
        return Err("not a self-signed act");
    }
    if update["subject"] != domain {
        return Err("subject is not the serving domain");
    }
    let key_id = item["sig"]["key_id"]
        .as_str()
        .ok_or("missing signature key")?;
    let public_key = match action {
        "observer_register" => {
            if update["details"]["key_id"] != key_id {
                return Err("registration is not signed by the key it registers");
            }
            let registered = update["details"]["public_key"]
                .as_str()
                .ok_or("registered key is missing")?;
            let declared = db
                .get_publisher_declaration(domain)
                .map_err(|_| "declaration unavailable")?
                .and_then(|raw| crate::json::parse(&raw).ok())
                .and_then(|doc| crate::declaration::publisher_of(&doc).ok())
                .map(|publisher| publisher.keys)
                .unwrap_or_default();
            if !declared
                .iter()
                .any(|key| key.key_id == key_id && key.public_key == registered)
            {
                return Err("registered key is not in the domain's Declaration");
            }
            PublicKey::from_b64u(registered).map_err(|_| "registered key is unusable")?
        }
        "observer_checkpoint" => db
            .accepted_roster_acts()
            .map_err(|_| "roster unavailable")?
            .into_iter()
            .rfind(|act| act.auditor_id == domain)
            .filter(|act| act.action == "observer_register" && act.key_id == key_id)
            .and_then(|act| PublicKey::from_b64u(&act.public_key).ok())
            .ok_or("no registered key for the checkpoint")?,
        _ => {
            let declaration = db
                .get_publisher_declaration(domain)
                .map_err(|_| "declaration unavailable")?
                .and_then(|raw| crate::json::parse(&raw).ok())
                .ok_or("no Declaration for the domain")?;
            crate::declaration::publisher_of(&declaration)
                .map_err(|_| "unusable Declaration")?
                .keys
                .into_iter()
                .find(|key| key.key_id == key_id)
                .and_then(|key| PublicKey::from_b64u(&key.public_key).ok())
                .ok_or("signing key is not in the domain's Key Set")?
        }
    };
    verify_envelope(item, "update", &public_key).map_err(|_| "signature does not verify")
}
