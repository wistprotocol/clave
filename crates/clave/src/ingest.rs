use crate::db::Db;
use crate::error::Result;
use crate::fetch::Client;
use serde_json::Value;
use std::path::Path;
use wist_core::crypto::PublicKey;
use wist_core::delta::{content_bytes, delta_id, verify_commitment};
use wist_core::envelope::verify_envelope;
use wist_core::objects::{DeltaEnvelope, FeedEnvelope, Payload, PublisherEnvelope};

#[derive(Debug, Default)]
pub struct IngestReport {
    pub accepted: Vec<String>,
    pub rejected: Vec<(String, String)>,
}

fn record_rejection(
    db: &Db,
    domain: &str,
    code: &str,
    now: &str,
    id: Option<&str>,
    detail: &str,
) -> Result<()> {
    db.insert_rejection(domain, code, now, id, Some(detail))
}

fn onboard_publisher(
    db: &Db,
    client: &Client,
    base: &str,
    host: &str,
    now: &str,
) -> Result<Option<(String, String)>> {
    let publisher_url = format!("{base}publisher.json");
    let (raw, value) = match client.get_json(&publisher_url) {
        Ok(v) => v,
        Err(e) => {
            record_rejection(db, host, "WIST2-E04", now, None, &e.to_string())?;
            return Ok(None);
        }
    };

    let embedded_key = value
        .pointer("/publisher/keys/0/public_key")
        .and_then(Value::as_str);
    let pk = match embedded_key.and_then(|s| PublicKey::from_b64u(s).ok()) {
        Some(pk) => pk,
        None => {
            record_rejection(
                db,
                host,
                "WIST2-E04",
                now,
                None,
                "missing or invalid embedded key",
            )?;
            return Ok(None);
        }
    };

    if verify_envelope(&value, "publisher", &pk).is_err() {
        record_rejection(
            db,
            host,
            "WIST2-E04",
            now,
            None,
            "signature verification failed",
        )?;
        return Ok(None);
    }

    let parsed: PublisherEnvelope = match serde_json::from_value(value.clone()) {
        Ok(p) => p,
        Err(e) => {
            record_rejection(db, host, "WIST2-E04", now, None, &e.to_string())?;
            return Ok(None);
        }
    };
    let key = match parsed.publisher.keys.first() {
        Some(k) => k,
        None => {
            record_rejection(db, host, "WIST2-E04", now, None, "publisher has no keys")?;
            return Ok(None);
        }
    };

    db.insert_publisher(host, &raw, &key.key_id, &key.public_key)?;
    db.insert_pending_entry("publisher_declaration", host, &value, 0)?;

    Ok(Some((key.key_id.clone(), key.public_key.clone())))
}

pub fn run(
    db: &Db,
    client: &Client,
    data_dir: &Path,
    host: &str,
    now: &str,
) -> Result<IngestReport> {
    let mut report = IngestReport::default();
    let scheme = if client.allow_http() { "http" } else { "https" };
    let base = format!("{scheme}://{host}/.well-known/wist/");

    let public_key_b64u = match db.get_publisher(host)? {
        Some(row) => row.public_key,
        None => match onboard_publisher(db, client, &base, host, now)? {
            Some((_, public_key)) => public_key,
            None => return Ok(report),
        },
    };
    let pubkey = match PublicKey::from_b64u(&public_key_b64u) {
        Ok(pk) => pk,
        Err(e) => {
            record_rejection(db, host, "WIST2-E04", now, None, &e.to_string())?;
            return Ok(report);
        }
    };

    let feed_url = format!("{base}feed.json");
    let (_, feed_value) = match client.get_json(&feed_url) {
        Ok(v) => v,
        Err(e) => {
            record_rejection(db, host, "WIST2-E01", now, None, &e.to_string())?;
            return Ok(report);
        }
    };
    if verify_envelope(&feed_value, "feed", &pubkey).is_err() {
        record_rejection(
            db,
            host,
            "WIST2-E01",
            now,
            None,
            "signature verification failed",
        )?;
        return Ok(report);
    }
    let feed_parsed: FeedEnvelope = match serde_json::from_value(feed_value) {
        Ok(f) => f,
        Err(e) => {
            record_rejection(db, host, "WIST2-E01", now, None, &e.to_string())?;
            return Ok(report);
        }
    };

    let mut chain_pos: i64 = 0;
    for id in &feed_parsed.feed.deltas {
        if db.is_delta_seen(id)? {
            continue;
        }

        let Some(hex) = id.strip_prefix("sha256:") else {
            record_rejection(
                db,
                host,
                "WIST2-E03",
                now,
                Some(id.as_str()),
                "malformed delta id",
            )?;
            report.rejected.push((id.clone(), "WIST2-E03".to_string()));
            continue;
        };

        let delta_url = format!("{base}deltas/{hex}.json");
        let (_, delta_value) = match client.get_json(&delta_url) {
            Ok(v) => v,
            Err(e) => {
                record_rejection(
                    db,
                    host,
                    "WIST2-E03",
                    now,
                    Some(id.as_str()),
                    &e.to_string(),
                )?;
                report.rejected.push((id.clone(), "WIST2-E03".to_string()));
                continue;
            }
        };
        if verify_envelope(&delta_value, "delta", &pubkey).is_err() {
            record_rejection(
                db,
                host,
                "WIST2-E03",
                now,
                Some(id.as_str()),
                "signature verification failed",
            )?;
            report.rejected.push((id.clone(), "WIST2-E03".to_string()));
            continue;
        }
        let delta_env: DeltaEnvelope = match serde_json::from_value(delta_value.clone()) {
            Ok(d) => d,
            Err(e) => {
                record_rejection(
                    db,
                    host,
                    "WIST2-E03",
                    now,
                    Some(id.as_str()),
                    &e.to_string(),
                )?;
                report.rejected.push((id.clone(), "WIST2-E03".to_string()));
                continue;
            }
        };
        let computed_id = match delta_id(&delta_value["delta"]) {
            Ok(v) => v,
            Err(e) => {
                record_rejection(
                    db,
                    host,
                    "WIST2-E03",
                    now,
                    Some(id.as_str()),
                    &e.to_string(),
                )?;
                report.rejected.push((id.clone(), "WIST2-E03".to_string()));
                continue;
            }
        };
        if computed_id != *id {
            record_rejection(
                db,
                host,
                "WIST2-E03",
                now,
                Some(id.as_str()),
                "delta id mismatch",
            )?;
            report.rejected.push((id.clone(), "WIST2-E03".to_string()));
            continue;
        }
        let expected_prev = db.url_tip(&delta_env.delta.url)?;
        if delta_env.delta.prev != expected_prev {
            record_rejection(
                db,
                host,
                "WIST2-E03",
                now,
                Some(id.as_str()),
                "prev does not match chain tip",
            )?;
            report.rejected.push((id.clone(), "WIST2-E03".to_string()));
            continue;
        }

        if let Some(commitment) = &delta_env.delta.payload {
            let payload_url = format!("{base}payloads/{hex}.json");
            let (payload_raw, payload_value) = match client.get_json(&payload_url) {
                Ok(v) => v,
                Err(e) => {
                    record_rejection(
                        db,
                        host,
                        "WIST2-E03",
                        now,
                        Some(id.as_str()),
                        &e.to_string(),
                    )?;
                    report.rejected.push((id.clone(), "WIST2-E03".to_string()));
                    continue;
                }
            };
            let payload_typed: Payload = match serde_json::from_value(payload_value.clone()) {
                Ok(p) => p,
                Err(e) => {
                    record_rejection(
                        db,
                        host,
                        "WIST2-E03",
                        now,
                        Some(id.as_str()),
                        &e.to_string(),
                    )?;
                    report.rejected.push((id.clone(), "WIST2-E03".to_string()));
                    continue;
                }
            };
            if verify_commitment(
                &payload_typed.salt,
                &payload_value["content"],
                &commitment.commitment,
            )
            .is_err()
            {
                record_rejection(
                    db,
                    host,
                    "WIST2-E03",
                    now,
                    Some(id.as_str()),
                    "commitment verification failed",
                )?;
                report.rejected.push((id.clone(), "WIST2-E03".to_string()));
                continue;
            }
            let bytes_ok =
                matches!(content_bytes(&payload_value["content"]), Ok(b) if b == commitment.bytes);
            if !bytes_ok {
                record_rejection(
                    db,
                    host,
                    "WIST2-E03",
                    now,
                    Some(id.as_str()),
                    "content bytes mismatch",
                )?;
                report.rejected.push((id.clone(), "WIST2-E03".to_string()));
                continue;
            }

            let payloads_dir = data_dir.join("payloads");
            std::fs::create_dir_all(&payloads_dir)?;
            std::fs::write(payloads_dir.join(format!("{hex}.json")), &payload_raw)?;
        }

        db.insert_seen_delta(id, host)?;
        db.insert_pending_entry("publisher_delta", host, &delta_value, chain_pos)?;
        db.set_url_tip(&delta_env.delta.url, host, id)?;
        report.accepted.push(id.clone());
        chain_pos += 1;
    }

    db.set_publisher_pulled(host, now)?;

    Ok(report)
}
