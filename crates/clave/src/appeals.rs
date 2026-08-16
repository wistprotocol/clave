use crate::db::Db;
use crate::error::Result;
use crate::fetch::Client;
use crate::registry;
use wist_core::crypto::{PublicKey, SigningKey};
use wist_core::envelope::verify_envelope;

const DAY: i64 = 86400;

fn epoch(ts: &str) -> Option<i64> {
    ts.parse::<jiff::Timestamp>().ok().map(|t| t.as_second())
}

fn pending_touches_notice(db: &Db, notice_id: &str) -> Result<bool> {
    let (pending, _) = db.peek_pending_entries()?;
    Ok(pending.iter().any(|p| {
        p.entry_type == "registry_update"
            && p.entry_json["update"]["details"]["notice"] == notice_id
    }))
}

/// WIST-2 §3.3 / WIST-4 §7: for every sealed sanction notice, fetch the
/// domain's appeal path — during the window at the baseline interval and
/// at least once after it closes, independent of any Ping and despite the
/// 403 — sealing what is served, or an "unappealed" ruling once the
/// window closes empty.
pub fn poll(db: &Db, client: &Client, sk: &SigningKey, now_epoch: i64) -> Result<Vec<String>> {
    let mut actions = Vec::new();
    for notice in db.governance_by_action("notice")? {
        let entries = db.governance_for_domain(&notice.domain)?;
        let settled = entries.iter().any(|e| {
            (e.action == "appeal" || e.action == "appeal_ruling")
                && e.notice_id.as_deref() == Some(notice.update_id.as_str())
        });
        if settled || pending_touches_notice(db, &notice.update_id)? {
            continue;
        }
        let Some(notice_epoch) = epoch(&notice.sealed_at) else {
            continue;
        };
        let window_days = registry::effective(db, "appeal_window_days", &notice.sealed_at)?;
        let window_close = notice_epoch + window_days * DAY;

        let hex = notice
            .update_id
            .strip_prefix("sha256:")
            .unwrap_or(&notice.update_id);
        let scheme = crate::fetch::scheme_for_host(&notice.domain, client.allow_http());
        let url = format!(
            "{scheme}://{}/.well-known/wist/appeals/{hex}.json",
            notice.domain
        );
        let served = client.get_json(&url).ok().and_then(|(_, doc)| {
            let pk = db
                .get_publisher(&notice.domain)
                .ok()
                .flatten()
                .and_then(|row| PublicKey::from_b64u(&row.public_key).ok())?;
            let update = &doc["update"];
            let valid = verify_envelope(&doc, "update", &pk).is_ok()
                && update["action"] == "appeal"
                && update["subject"] == notice.domain.as_str()
                && update["details"]["notice"] == notice.update_id.as_str();
            valid.then_some(doc)
        });

        let late = now_epoch >= window_close;
        match served {
            Some(doc) => {
                db.insert_pending_entry("registry_update", "", &doc, 0)?;
                actions.push(format!("appeal enqueued for {}", notice.update_id));
                // WIST-4 §7: an appeal served after the window closed is
                // recorded, but it discharges no T — the window still closed
                // with nothing served in time, and that is what the ruling
                // reports.
                if late {
                    crate::governance::rule(
                        db,
                        sk,
                        &notice.domain,
                        &notice.update_id,
                        "unappealed",
                        "appeal window closed with no appeal served; a later appeal is recorded",
                        now_epoch,
                    )?;
                    actions.push(format!(
                        "unappealed ruling enqueued for {} alongside a late appeal",
                        notice.update_id
                    ));
                }
            }
            None if late => {
                crate::governance::rule(
                    db,
                    sk,
                    &notice.domain,
                    &notice.update_id,
                    "unappealed",
                    "appeal window closed with no appeal served",
                    now_epoch,
                )?;
                actions.push(format!(
                    "unappealed ruling enqueued for {}",
                    notice.update_id
                ));
            }
            None => {}
        }
    }
    Ok(actions)
}
