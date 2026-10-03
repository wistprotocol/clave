use crate::db::{Db, Phase, PullRun, Status, WalkPage};
use crate::error::Result;
use serde_json::Value;
use wist_core::objects::{FeedEnvelope, PublisherEnvelope};

use super::fetch_stage::{ObjectKey, Walk};
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
            Walk::Label => db.is_label_seen_for(id, host)?,
        };
        if !seen {
            return Ok(true);
        }
    }
    Ok(false)
}

fn consume(db: &Db, run: &mut PullRun, key: &ObjectKey) -> Result<()> {
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

pub(super) fn consume_declaration(db: &Db, run: &mut PullRun, key: &ObjectKey) -> Result<()> {
    consume(db, run, key)
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
        Walk::Label => {
            !live || db.observe_label_feed_generated_at(host, &page.feed.generated_at)?
        }
    };
    if !observed {
        let detail = "live Label Feed generated_at precedes the retained authenticated observation";
        reject(db, host, "WIST2-E05", &run.now, None, detail)?;
        db.advance_pull_object(
            run.run_id,
            key.kind(),
            &key.name(),
            &[Status::Fetched],
            Status::Rejected,
            None,
        )?;
        mutation.commit()?;
        return Ok(None);
    }
    let unseen = unseen(db, host, walk, &page.feed.deltas)?;
    let stopped_at_next = unseen && next == Some(None);
    if stopped_at_next {
        let detail = "label feed next fails the target rule: not its Normalized URL under the requested host's well-known prefix";
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
    run.position = refusal.index + 1;
    db.update_pull_run(run)?;
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
            let place = crate::collection::state::Place::url(
                run.event.unwrap_or_default(),
                run.positions,
                index as u64,
            );
            let eligibility = db.last_epoch()?.map_or(0, |epoch| epoch.epoch_number + 1);
            db.insert_waiting_label(
                id,
                &crate::collection::state::WaitingLabel {
                    kind: match kind {
                        LabelKind::Label => crate::collection::state::LabelKind::Label,
                        LabelKind::Dispute => crate::collection::state::LabelKind::Dispute,
                    },
                    publisher: host.to_owned(),
                    envelope: doc.clone(),
                    place,
                    eligibility,
                },
            )?;
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
            "item" => report.items.push(id),
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
                if !run.discovered
                    && report.accepted.is_empty()
                    && report.queued.is_empty()
                    && report.items.is_empty()
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
