//! Stage 4: stateful admission. Each function is one fenced write
//! transaction over the store.
use crate::db::Db;
use crate::declaration::{self, Decision};
use crate::error::Result;
use serde_json::Value;
use std::path::Path;
use wist_core::objects::{DeltaEnvelope, FeedEnvelope, Publisher, PublisherEnvelope};

use super::fetch_stage::Walk;
use super::verify::{self, LabelKind};

/// Records a rejection at the domain's status endpoint.
pub(super) fn reject(
    db: &Db,
    domain: &str,
    code: &str,
    now: &str,
    id: Option<&str>,
    detail: &str,
) -> Result<()> {
    db.insert_rejection(domain, code, now, id, Some(detail))
}

/// Debits `bytes` a metered fetch read against the Registrable Domain's
/// budget for `day`.
pub(super) fn debit(db: &Db, unit: &str, day: &str, bytes: u64) -> Result<()> {
    db.add_ingest_bytes(unit, day, bytes as i64)
}

/// WIST-1 §5.2: applies a recovery settlement that is due before an
/// admission decision under the domain's open window.
pub(super) fn settle_if_due(
    db: &Db,
    data_dir: &Path,
    host: &str,
    clock: &impl Fn() -> jiff::Timestamp,
) -> Result<()> {
    if db
        .get_recovery_window(host)?
        .is_some_and(|window| window.opened_epoch.is_some())
    {
        crate::recovery::settle(db, data_dir, &clock().to_string())?;
    }
    Ok(())
}

fn accepted_recovery_head(
    db: &Db,
    data_dir: &Path,
    host: &str,
    window: &crate::db::RecoveryWindowRow,
) -> Result<Value> {
    use crate::history::declarations::DeclarationsReplay;
    let mut head = if window.opened_epoch.is_some() {
        let state = crate::history::declarations::Declarations::reconstruct(
            db,
            data_dir,
            db.last_epoch()?,
        )?;
        state
            .domains()
            .get(host)
            .and_then(|domain| domain.window())
            .ok_or_else(|| {
                crate::error::Error::History(
                    "stored recovery window has no authenticated open window".into(),
                )
            })?
            .head()
            .envelope()
            .clone()
    } else {
        let owner: Value = crate::json::parse(&window.owner_declaration_json)?;
        let prior: Value = crate::json::parse(&window.prior_declaration_json)?;
        if declaration::evaluate(&prior, &owner) != Ok(Decision::Recovery) {
            return Err(crate::error::Error::History(
                "invalid pending recovery owner".into(),
            ));
        }
        owner
    };
    let mut pending: Vec<_> = db
        .peek_pending_entries()?
        .0
        .into_iter()
        .filter(|entry| entry.domain == host && entry.entry_type == "publisher_declaration")
        .map(|entry| {
            let publisher = declaration::publisher_of(&entry.entry_json)
                .map_err(crate::error::Error::History)?;
            Ok((publisher.seq, entry))
        })
        .collect::<Result<_>>()?;
    pending.sort_by_key(|(seq, _)| *seq);
    for (_, entry) in pending {
        if declaration::follows_chain_head(&head, &entry.entry_json) {
            head = entry.entry_json;
        }
    }
    Ok(head)
}

/// Records a first-contact Declaration that passed its checks as the
/// domain's accepted one.
pub(super) fn onboard(
    db: &Db,
    host: &str,
    now: &str,
    raw: &[u8],
    value: &Value,
    publisher: &Publisher,
) -> Result<()> {
    let mutation = db.mutation()?;
    let key = &publisher.keys[0];
    db.record_publisher_declaration(host, raw, &key.kid, &key.x, value)?;
    db.mark_declaration_fetched(host, now)?;
    mutation.commit()
}

/// WIST-1 §§5.1–5.2: evaluates a fetched Declaration against the domain's
/// chain and records what it establishes, after any recovery settlement
/// due first. Returns the Declaration the domain holds afterwards.
pub(super) fn admit_declaration(
    db: &Db,
    data_dir: &Path,
    host: &str,
    now: &str,
    clock: &impl Fn() -> jiff::Timestamp,
    raw: &[u8],
    value: Value,
) -> Result<Value> {
    settle_if_due(db, data_dir, host, clock)?;
    let mutation = db.mutation()?;
    let stored_raw = db.get_publisher_declaration(host)?.ok_or_else(|| {
        crate::error::Error::History("publisher row lost before Declaration admission".into())
    })?;
    let mut current_doc: Value = crate::json::parse(&stored_raw)?;
    let open_window = db.get_recovery_window(host)?;
    let recovery_head = open_window
        .as_ref()
        .map(|window| accepted_recovery_head(db, data_dir, host, window))
        .transpose()?;
    if let Some(head) = &recovery_head {
        db.update_recovery_chain_head(host, &serde_json::to_vec(head)?)?;
    }
    let floor = db.highest_accepted_declaration_seq(host)?.ok_or_else(|| {
        crate::error::Error::History("missing accepted Declaration sequence floor".into())
    })?;
    let pending_head = db
        .get_pending_identity(host)?
        .map(|raw| crate::json::parse(&raw))
        .transpose()?;
    match declaration::evaluate_with_heads(
        &current_doc,
        recovery_head.as_ref(),
        pending_head.as_ref(),
        floor,
        &value,
    ) {
        Ok(Decision::Unchanged) => {
            db.mark_declaration_fetched(host, now)?;
        }
        Ok(decision) => {
            let names_pending = pending_head.as_ref().is_some_and(|head| {
                declaration::inner_hash(head).ok().as_deref()
                    == value["publisher"]["prev_declaration"].as_str()
            });
            if names_pending {
                db.record_pending_identity(host, raw, &value)?;
                db.mark_declaration_fetched(host, now)?;
            } else if decision == Decision::FreshIdentity && open_window.is_none() {
                if pending_head.is_some() {
                    reject(
                        db,
                        host,
                        "WIST1-E08",
                        now,
                        None,
                        "fresh identity names the current Declaration beside a pending head",
                    )?;
                } else {
                    db.record_pending_identity(host, raw, &value)?;
                    db.mark_declaration_fetched(host, now)?;
                }
            } else {
                let (kid, x) = value
                    .pointer("/publisher/keys/0")
                    .map(|k| {
                        (
                            k["kid"].as_str().unwrap_or_default().to_string(),
                            k["x"].as_str().unwrap_or_default().to_string(),
                        )
                    })
                    .unwrap_or_default();
                db.update_publisher_declaration(host, raw, &kid, &x, &value)?;
                db.clear_pending_identity(host)?;
                match &open_window {
                    None => {
                        if decision == Decision::Recovery {
                            db.open_recovery_window(host, raw, &stored_raw)?;
                        }
                    }
                    Some(_) => {
                        if declaration::follows_chain_head(recovery_head.as_ref().unwrap(), &value)
                        {
                            db.update_recovery_chain_head(host, raw)?;
                        }
                    }
                }
                current_doc = value;
                db.mark_declaration_fetched(host, now)?;
            }
        }
        Err((code, detail)) => {
            reject(db, host, code, now, None, &detail)?;
        }
    }
    mutation.commit()?;
    Ok(current_doc)
}

/// Where a walk goes after an authenticated page.
pub(super) enum Step {
    /// Fetch the page at this URL next.
    Continue(String),
    /// The walk ends with this page.
    Stop,
    /// The page was refused and the rejection recorded; it joins no walk.
    Refused,
}

pub(super) struct PageAdmission {
    /// Whether the page lists an ID the domain has not seen.
    pub unseen: bool,
    pub step: Step,
}

/// Admits an authenticated page to its walk: a live page's `generated_at`
/// is compared and retained (WIST-2 §3.2, `WIST2-E05`), the page's IDs
/// are diffed against those seen and, where the walk continues, its
/// `next` target is read. `next` is the target rule's result for the
/// page's `next`, if it has one.
pub(super) fn admit_page(
    db: &Db,
    host: &str,
    now: &str,
    walk: Walk,
    live: bool,
    page: &FeedEnvelope,
    next: Option<Option<String>>,
) -> Result<PageAdmission> {
    let mutation = db.mutation()?;
    let observed = match walk {
        Walk::Feed => !live || db.observe_feed_generated_at(host, &page.feed.generated_at)?,
        Walk::Label => {
            !live || db.observe_label_feed_generated_at(host, &page.feed.generated_at)?
        }
    };
    if !observed {
        let detail = match walk {
            Walk::Feed => "live Feed generated_at precedes the retained authenticated observation",
            Walk::Label => {
                "live Label Feed generated_at precedes the retained authenticated observation"
            }
        };
        reject(db, host, "WIST2-E05", now, None, detail)?;
        mutation.commit()?;
        return Ok(PageAdmission {
            unseen: false,
            step: Step::Refused,
        });
    }
    let mut unseen = false;
    for id in &page.feed.deltas {
        let seen = match walk {
            Walk::Feed => db.is_delta_seen_for(id, host)?,
            Walk::Label => db.is_label_seen_for(id, host)?,
        };
        if !seen {
            unseen = true;
            break;
        }
    }
    let step = match (unseen, next) {
        (false, _) | (true, None) => Step::Stop,
        (true, Some(Some(url))) => Step::Continue(url),
        (true, Some(None)) => {
            if walk == Walk::Feed {
                reject(
                    db,
                    host,
                    "WIST2-E01",
                    now,
                    None,
                    "feed next fails the target rule: not its Normalized URL under the requested host's well-known prefix",
                )?;
            }
            Step::Stop
        }
    };
    mutation.commit()?;
    Ok(PageAdmission { unseen, step })
}

/// How a verified Delta's admission ended.
pub(super) enum Admission {
    Accepted,
    /// Accepted for sealing under an open recovery window.
    Queued,
    /// The admission sources or the URL's chain tip changed since the
    /// Delta was verified; nothing was written.
    Stale,
}

/// Accepts a verified Delta, with its Payload file, after re-reading the
/// admission sources and the URL's chain tip in the same transaction.
#[allow(clippy::too_many_arguments)]
pub(super) fn admit_delta(
    db: &Db,
    data_dir: &Path,
    host: &str,
    id: &str,
    doc: &Value,
    envelope: &DeltaEnvelope,
    payload_raw: Option<&[u8]>,
    chain_pos: i64,
) -> Result<Admission> {
    let admission = db.mutation()?;
    let (window_open, sources) = super::delta_admission_sources(db, host)?;
    if verify::delta_authority(&sources, doc).is_err()
        || envelope.delta.prev != db.url_tip(host, &envelope.delta.url)?
    {
        return Ok(Admission::Stale);
    }
    if let Some(raw) = payload_raw {
        let payloads_dir = data_dir.join("payloads");
        std::fs::create_dir_all(&payloads_dir)?;
        std::fs::write(payloads_dir.join(format!("{}.json", &id[7..])), raw)?;
    }
    let url = &envelope.delta.url;
    let outcome = if window_open {
        db.queue_delta(host, id, doc, url, id, chain_pos)?;
        Admission::Queued
    } else {
        db.record_accepted_delta(host, id, doc, chain_pos, url, id)?;
        Admission::Accepted
    };
    admission.commit()?;
    Ok(outcome)
}

/// Queues a Label or dispute that passed its checks for sealing, or
/// records its rejection; a dispute is validated here against the sealed
/// Labels. Returns the rejection, if any.
#[allow(clippy::too_many_arguments)]
pub(super) fn admit_label(
    db: &Db,
    host: &str,
    now: &str,
    id: &str,
    kind: LabelKind,
    doc: &Value,
    declaration: &PublisherEnvelope,
    label: Option<std::result::Result<(), wist_core::label::Rejection>>,
) -> Result<Option<wist_core::label::Rejection>> {
    use wist_core::label::{self, LabelLookup};
    let mutation = db.mutation()?;
    let outcome = match label {
        Some(outcome) => outcome,
        None => label::validate_dispute(doc, declaration, |label_id| {
            db.sealed_label_subject(label_id)
                .ok()
                .flatten()
                .map_or(LabelLookup::Absent, |subject| LabelLookup::Known {
                    subject,
                })
        })
        .map(|_| ()),
    };
    let rejection = match outcome {
        Ok(()) => {
            db.insert_pending_entry(kind.as_str(), host, doc, 0)?;
            db.insert_seen_label(id, host)?;
            None
        }
        Err(rejection) => {
            reject(
                db,
                host,
                rejection.code(),
                now,
                Some(id),
                &format!("{} rejected: {rejection:?}", kind.as_str()),
            )?;
            Some(rejection)
        }
    };
    mutation.commit()?;
    Ok(rejection)
}

/// Ends a pull that ran its walk: records whether the walk suspended and,
/// when it completed, the pull instant.
pub(super) fn close_run(db: &Db, host: &str, now: &str, suspended: bool) -> Result<()> {
    let mutation = db.mutation()?;
    db.set_walk_suspended(host, suspended)?;
    if !suspended {
        db.set_publisher_pulled(host, now)?;
    }
    mutation.commit()
}
