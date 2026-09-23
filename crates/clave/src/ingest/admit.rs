use crate::db::{Db, Phase, PullRun, Status, WalkPage};
use crate::declaration::{self, Decision};
use crate::error::Result;
use serde_json::Value;
use std::path::Path;
use wist_core::objects::{DeltaEnvelope, FeedEnvelope, Publisher, PublisherEnvelope};

use super::fetch_stage::{Attempt, ObjectKey, Walk};
use super::verify::{DeclarationRef, IssuedRefs, LabelKind};
use super::IngestReport;

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

pub(super) fn unseen(db: &Db, host: &str, walk: Walk, ids: &[String]) -> Result<bool> {
    for id in ids {
        let seen = match walk {
            Walk::Feed => db.is_delta_seen_for(id, host)?,
            Walk::Label => db.is_label_seen_for(id, host)?,
        };
        if !seen {
            return Ok(true);
        }
    }
    Ok(false)
}

/// WIST-1 §5.2: a settlement due is applied before an admission decision
/// under the open window.
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

fn consume(db: &Db, run: &mut PullRun, key: &ObjectKey) -> Result<()> {
    match key {
        ObjectKey::Declaration {
            attempt: Attempt::Feed,
        } => {
            run.feed_retry_used = true;
            db.update_pull_run(run)?;
        }
        ObjectKey::Declaration {
            attempt: Attempt::Delta(id),
        } => db.record_pull_attempt(run.run_id, "delta_refresh", id)?,
        _ => {}
    }
    db.advance_pull_object(
        run.run_id,
        key.kind(),
        &key.name(),
        &[Status::Fetched, Status::Failed],
        Status::Admitted,
        None,
    )?;
    Ok(())
}

pub(super) fn consume_attempt(db: &Db, run: &mut PullRun, key: &ObjectKey) -> Result<()> {
    let mutation = db.mutation()?;
    consume(db, run, key)?;
    mutation.commit()
}

pub(super) fn onboard(
    db: &Db,
    run: &mut PullRun,
    host: &str,
    key: &ObjectKey,
    raw: &[u8],
    value: &Value,
    publisher: &Publisher,
) -> Result<()> {
    let mutation = db.mutation()?;
    let entry = &publisher.keys[0];
    db.record_publisher_declaration(host, raw, &entry.kid, &entry.x, value)?;
    db.mark_declaration_fetched(host, &run.now)?;
    consume(db, run, key)?;
    mutation.commit()
}

/// WIST-1 §§5.1–5.2, after any recovery settlement due first.
#[allow(clippy::too_many_arguments)]
pub(super) fn admit_declaration(
    db: &Db,
    data_dir: &Path,
    run: &mut PullRun,
    host: &str,
    clock: &impl Fn() -> jiff::Timestamp,
    key: &ObjectKey,
    raw: &[u8],
    value: Value,
) -> Result<Value> {
    settle_if_due(db, data_dir, host, clock)?;
    let mutation = db.mutation()?;
    let now = run.now.clone();
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
            db.mark_declaration_fetched(host, &now)?;
        }
        Ok(decision) => {
            let names_pending = pending_head.as_ref().is_some_and(|head| {
                declaration::inner_hash(head).ok().as_deref()
                    == value["publisher"]["prev_declaration"].as_str()
            });
            if names_pending {
                db.record_pending_identity(host, raw, &value)?;
                db.mark_declaration_fetched(host, &now)?;
            } else if decision == Decision::FreshIdentity && open_window.is_none() {
                if pending_head.is_some() {
                    reject(
                        db,
                        host,
                        "WIST1-E08",
                        &now,
                        None,
                        "fresh identity names the current Declaration beside a pending head",
                    )?;
                } else {
                    db.record_pending_identity(host, raw, &value)?;
                    db.mark_declaration_fetched(host, &now)?;
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
                db.mark_declaration_fetched(host, &now)?;
            }
        }
        Err((code, detail)) => {
            reject(db, host, code, &now, None, &detail)?;
        }
    }
    consume(db, run, key)?;
    mutation.commit()?;
    Ok(current_doc)
}

pub(super) fn abort(
    db: &Db,
    run: &mut PullRun,
    host: &str,
    key: Option<&ObjectKey>,
    code: &str,
    detail: &str,
) -> Result<()> {
    let mutation = db.mutation()?;
    reject(db, host, code, &run.now, None, detail)?;
    if let Some(key) = key {
        db.advance_pull_object(
            run.run_id,
            key.kind(),
            &key.name(),
            &[Status::Fetched, Status::Failed],
            Status::Rejected,
            None,
        )?;
    }
    run.phase = Phase::Aborted;
    run.ended = Some(code.to_string());
    db.update_pull_run(run)?;
    mutation.commit()
}

fn refuse_page(
    db: &Db,
    run: &PullRun,
    host: &str,
    key: &ObjectKey,
    code: &str,
    detail: &str,
) -> Result<()> {
    reject(db, host, code, &run.now, None, detail)?;
    db.advance_pull_object(
        run.run_id,
        key.kind(),
        &key.name(),
        &[Status::Fetched, Status::Failed],
        Status::Rejected,
        None,
    )?;
    Ok(())
}

pub(super) fn reject_page(
    db: &Db,
    run: &PullRun,
    host: &str,
    key: &ObjectKey,
    code: &str,
    detail: &str,
) -> Result<()> {
    let mutation = db.mutation()?;
    refuse_page(db, run, host, key, code, detail)?;
    mutation.commit()
}

/// Refuses a sealed Page of the Feed walk: WIST-2 §3.2 stops the walk
/// there with the Pages before it, whose Deltas proceed under §5.
pub(super) fn stop_walk(
    db: &Db,
    run: &mut PullRun,
    host: &str,
    key: &ObjectKey,
    code: &str,
    detail: &str,
) -> Result<()> {
    let mutation = db.mutation()?;
    refuse_page(db, run, host, key, code, detail)?;
    run.ended = Some(code.to_string());
    db.update_pull_run(run)?;
    mutation.commit()
}

/// WIST-2 §3.2 (`WIST2-E05`): a live page's `generated_at` is compared and
/// retained.
#[allow(clippy::too_many_arguments)]
pub(super) fn admit_page(
    db: &Db,
    run: &mut PullRun,
    host: &str,
    key: &ObjectKey,
    walk: Walk,
    live: bool,
    index: u32,
    url: &str,
    page: &FeedEnvelope,
    raw: &[u8],
    next: Option<Option<String>>,
) -> Result<Option<(WalkPage, bool)>> {
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
        reject(db, host, "WIST2-E05", &run.now, None, detail)?;
        db.advance_pull_object(
            run.run_id,
            key.kind(),
            &key.name(),
            &[Status::Fetched],
            Status::Rejected,
            None,
        )?;
        if walk == Walk::Feed {
            run.phase = Phase::Aborted;
            run.ended = Some("WIST2-E05".to_string());
            db.update_pull_run(run)?;
        }
        mutation.commit()?;
        return Ok(None);
    }
    let unseen = unseen(db, host, walk, &page.feed.deltas)?;
    let stopped_at_next = unseen && next == Some(None);
    if stopped_at_next {
        let detail = match walk {
            Walk::Feed => "feed next fails the target rule: not its Normalized URL under the requested host's well-known prefix",
            Walk::Label => "label feed next fails the target rule: not its Normalized URL under the requested host's well-known prefix",
        };
        reject(db, host, "WIST2-E01", &run.now, None, detail)?;
    }
    let walked = WalkPage {
        url: url.to_string(),
        generated_at: page.feed.generated_at.clone(),
        ids: page.feed.deltas.clone(),
        next_url: next.flatten(),
        raw: Some(raw.to_vec()),
    };
    db.record_walk_page(host, walk.as_str(), index, &walked)?;
    if walk == Walk::Feed && unseen {
        run.unseen_any = true;
        if stopped_at_next {
            run.ended = Some("WIST2-E01".to_string());
        }
        db.update_pull_run(run)?;
    }
    db.advance_pull_object(
        run.run_id,
        key.kind(),
        &key.name(),
        &[Status::Fetched],
        Status::Admitted,
        None,
    )?;
    mutation.commit()?;
    Ok(Some((walked, unseen)))
}

fn past(db: &Db, run: &mut PullRun, index: usize, mutation: crate::db::Mutation<'_>) -> Result<()> {
    run.position = index + 1;
    db.update_pull_run(run)?;
    mutation.commit()
}

pub(super) struct Refusal<'a> {
    pub index: usize,
    pub id: &'a str,
    pub kind: &'static str,
    pub slot: &'a str,
    pub consumed: Option<(&'static str, String)>,
    pub resolved_prev: bool,
}

pub(super) fn reject_item(
    db: &Db,
    run: &mut PullRun,
    host: &str,
    refusal: &Refusal<'_>,
    code: &str,
    detail: &str,
) -> Result<()> {
    let mutation = db.mutation()?;
    if db
        .pull_object(run.run_id, refusal.kind, refusal.slot)?
        .is_some_and(|object| object.status.is_final())
    {
        return past(db, run, refusal.index, mutation);
    }
    reject(db, host, code, &run.now, Some(refusal.id), detail)?;
    db.report_pull_object(
        run.run_id,
        refusal.kind,
        refusal.slot,
        Status::Rejected,
        code,
    )?;
    if let Some((kind, slot)) = &refusal.consumed {
        db.advance_pull_object(
            run.run_id,
            kind,
            slot,
            &[
                Status::Issued,
                Status::Fetched,
                Status::Verified,
                Status::Failed,
            ],
            Status::Rejected,
            None,
        )?;
    }
    if refusal.resolved_prev {
        db.record_pull_attempt(run.run_id, "resolved_prev", refusal.id)?;
    }
    run.position = refusal.index + 1;
    db.update_pull_run(run)?;
    mutation.commit()
}

/// WIST-2 §5 step 3: a retrieved predecessor is admitted before the Delta
/// that named it.
pub(super) fn splice_predecessor(
    db: &Db,
    run: &mut PullRun,
    id: &str,
    prev: &str,
    index: usize,
) -> Result<()> {
    let mutation = db.mutation()?;
    db.record_pull_attempt(run.run_id, "resolved_prev", id)?;
    run.queue.insert(index, prev.to_string());
    run.position = index;
    db.set_pull_queue(run)?;
    db.update_pull_run(run)?;
    mutation.commit()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Staleness {
    Declaration,
    ChainTip,
    Schedule,
}

pub(super) enum Admission {
    Accepted,
    Queued,
    Stale(Staleness),
    Duplicate,
}

pub(super) struct DeltaItem<'a> {
    pub index: usize,
    pub id: &'a str,
    pub slot: &'a str,
    pub payload_slot: Option<&'a str>,
}

/// The references the Delta was verified under are revalidated in the
/// admitting transaction, the size caps and clock allowance only when an
/// Epoch was sealed since.
#[allow(clippy::too_many_arguments)]
pub(super) fn admit_delta(
    db: &Db,
    data_dir: &Path,
    run: &mut PullRun,
    host: &str,
    item: &DeltaItem<'_>,
    doc: &Value,
    envelope: &DeltaEnvelope,
    payload_raw: Option<&[u8]>,
    refs: &IssuedRefs,
) -> Result<Admission> {
    let admission = db.mutation()?;
    if db
        .pull_object(run.run_id, "delta", item.slot)?
        .is_none_or(|object| object.status != Status::Verified)
    {
        past(db, run, item.index, admission)?;
        return Ok(Admission::Duplicate);
    }
    let current = super::declaration_ref(db, host)?;
    if !current.same_version(&refs.decl) {
        return Ok(Admission::Stale(Staleness::Declaration));
    }
    if envelope.delta.prev != db.url_tip(host, &envelope.delta.url)? {
        return Ok(Admission::Stale(Staleness::ChainTip));
    }
    if db.last_epoch()?.map(|epoch| epoch.epoch_number) != refs.schedule_at {
        let profile = crate::declaration::delta::AdmissionProfile::start(db, data_dir, refs.clock)?;
        if profile.sizes != refs.sizes || profile.clock_skew_seconds != refs.clock_skew_seconds {
            return Ok(Admission::Stale(Staleness::Schedule));
        }
    }
    if let Some(raw) = payload_raw {
        let payloads_dir = data_dir.join("payloads");
        std::fs::create_dir_all(&payloads_dir)?;
        std::fs::write(payloads_dir.join(format!("{}.json", &item.id[7..])), raw)?;
    }
    let url = &envelope.delta.url;
    let (outcome, report) = if current.window.is_some() {
        db.queue_delta(host, item.id, doc, url, item.id, run.chain_pos)?;
        (Admission::Queued, "queued")
    } else {
        db.record_accepted_delta(host, item.id, doc, run.chain_pos, url, item.id)?;
        (Admission::Accepted, "accepted")
    };
    db.report_pull_object(run.run_id, "delta", item.slot, Status::Admitted, report)?;
    if let Some(slot) = item.payload_slot {
        db.advance_pull_object(
            run.run_id,
            "payload",
            slot,
            &[Status::Verified],
            Status::Admitted,
            None,
        )?;
    }
    run.chain_pos += 1;
    run.position = item.index + 1;
    db.update_pull_run(run)?;
    admission.commit()?;
    Ok(outcome)
}

pub(super) fn reissue(
    db: &Db,
    run: &PullRun,
    id: &str,
    slot: &str,
    refs: &IssuedRefs,
) -> Result<()> {
    let mutation = db.mutation()?;
    db.forget_pull_attempt(run.run_id, "resolved_prev", id)?;
    db.set_pull_object_refs(run.run_id, "delta", slot, &refs.to_json()?)?;
    mutation.commit()
}

pub(super) enum LabelAdmission {
    Admitted,
    Rejected,
    Stale,
    Duplicate,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn admit_label(
    db: &Db,
    run: &mut PullRun,
    host: &str,
    index: usize,
    id: &str,
    slot: &str,
    kind: LabelKind,
    doc: &Value,
    (declaration, decl): &(PublisherEnvelope, DeclarationRef),
    attempt: &IssuedRefs,
    label: Option<std::result::Result<(), wist_core::label::Rejection>>,
) -> Result<LabelAdmission> {
    use wist_core::label::{self, LabelLookup};
    let mutation = db.mutation()?;
    if db
        .pull_object(run.run_id, "label", slot)?
        .is_some_and(|object| object.status.is_final())
    {
        past(db, run, index, mutation)?;
        return Ok(LabelAdmission::Duplicate);
    }
    if !super::declaration_ref(db, host)?.same_version(decl) {
        return Ok(LabelAdmission::Stale);
    }
    let outcome = match label {
        Some(outcome) => outcome,
        None => label::validate_dispute(
            doc,
            declaration,
            |label_id| {
                db.sealed_label_subject(label_id)
                    .ok()
                    .flatten()
                    .map_or(LabelLookup::Absent, |subject| LabelLookup::Known {
                        subject,
                    })
            },
            attempt.clock_floor_s(),
            attempt.clock_skew_seconds,
        )
        .map(|_| ()),
    };
    let admission = match outcome {
        Ok(()) => {
            db.insert_pending_entry(kind.as_str(), host, doc, 0)?;
            db.insert_seen_label(id, host)?;
            db.report_pull_object(run.run_id, "label", slot, Status::Admitted, "label")?;
            LabelAdmission::Admitted
        }
        Err(rejection) => {
            reject(
                db,
                host,
                rejection.code(),
                &run.now,
                Some(id),
                &format!("{} rejected: {rejection:?}", kind.as_str()),
            )?;
            db.report_pull_object(
                run.run_id,
                "label",
                slot,
                Status::Rejected,
                rejection.code(),
            )?;
            LabelAdmission::Rejected
        }
    };
    run.position = index + 1;
    db.update_pull_run(run)?;
    mutation.commit()?;
    Ok(admission)
}

pub(super) fn end_walk(
    db: &Db,
    run: &mut PullRun,
    host: &str,
    walk: Walk,
    keep: Option<u32>,
    phase: Phase,
    queue: Vec<String>,
) -> Result<()> {
    let mutation = db.mutation()?;
    match keep {
        Some(pages) => db.trim_walk(host, walk.as_str(), pages)?,
        None => db.clear_walk(host, walk.as_str())?,
    }
    run.phase = phase;
    run.queue = queue;
    run.position = 0;
    db.set_pull_queue(run)?;
    db.update_pull_run(run)?;
    mutation.commit()
}

pub(super) fn close_run(db: &Db, run_id: i64) -> Result<IngestReport> {
    let mutation = db.mutation()?;
    let run = db
        .pull_run(run_id)?
        .ok_or_else(|| crate::error::Error::History("the pull run is already closed".into()))?;
    let mut report = IngestReport::default();
    for (object_id, entry) in db.pull_report(run_id)? {
        let id = object_id
            .rsplit_once('#')
            .map_or(object_id.as_str(), |(id, _)| id)
            .to_string();
        match entry.as_str() {
            "accepted" => report.accepted.push(id),
            "queued" => report.queued.push(id),
            "label" => report.labels.push(id),
            code => report.rejected.push((id, code.to_string())),
        }
    }
    report.noise = match run.ended.as_deref() {
        Some("WIST2-E04") => Some("WIST2-E04"),
        Some(_) | None => None,
    };
    match run.phase {
        Phase::Aborted => report.ended = run.ended.clone(),
        Phase::Closing => {
            report.suspended = run.suspended;
            db.set_walk_suspended(&run.domain, run.suspended)?;
            if !run.suspended {
                report.ended = run.ended.clone();
                if !run.unseen_any
                    && report.accepted.is_empty()
                    && report.queued.is_empty()
                    && report.rejected.is_empty()
                    && report.labels.is_empty()
                {
                    report.noise = Some("WIST2-E02");
                }
                db.set_publisher_pulled(&run.domain, &run.now)?;
            }
        }
        _ => {
            return Err(crate::error::Error::History(
                "a pull run is closed only once its walk has ended".into(),
            ))
        }
    }
    report.fetched_bytes = db.pull_run_fetched_bytes(run_id)?;
    db.delete_pull_run(run_id)?;
    mutation.commit()?;
    Ok(report)
}
