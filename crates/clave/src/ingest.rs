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
    pub noise: Option<&'static str>,
    pub suspended: bool,
}

/// WIST-2 §4: `host` MUST be a bare authority (`host[:port]`) — no scheme,
/// path, query, fragment or userinfo — before it is interpolated into a
/// fetch URL. This is narrower validation than WIST-1 §2's full Canonical
/// Host (which forbids a port and requires UTS #46 processing); this
/// codebase already treats `host` as `host[:port]` throughout (see the
/// aggregator's own `log_id`), so bare-authority syntax is what's enforced.
pub fn is_bare_authority(host: &str) -> bool {
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '@' | '\\'))
    {
        return false;
    }
    let Ok(parsed) = url::Url::parse(&format!("http://{host}/")) else {
        return false;
    };
    parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
}

/// WIST-1 §2 Canonical Host over a bare `host[:port]` authority: the
/// hostname is canonicalized (UTS #46, A-labels, lowercase), IP literals
/// pass through, and the port is preserved as this implementation's
/// loopback-deployment extension to §2's port-free Canonical Host.
pub fn canonical_authority(host: &str) -> Option<String> {
    if !is_bare_authority(host) {
        return None;
    }
    let parsed = url::Url::parse(&format!("http://{host}/")).ok()?;
    let canonical = match parsed.host()? {
        url::Host::Domain(d) => wist_core::host::canonical_host(d).ok()?,
        url::Host::Ipv4(a) => a.to_string(),
        url::Host::Ipv6(a) => format!("[{a}]"),
    };
    Some(match parsed.port() {
        Some(port) => format!("{canonical}:{port}"),
        None => canonical,
    })
}

fn url_authority(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// WIST-1 §3.2 scope rule, compared on Canonical Hosts (§2): a Delta's
/// `url` authority must equal the Publisher's `domain` or one of its
/// `subdomain_scope` hostnames.
fn url_in_scope(url: &str, domain: &str, subdomain_scope: &[String]) -> bool {
    let Some(authority) = url_authority(url).and_then(|a| canonical_authority(&a)) else {
        return false;
    };
    let matches = |declared: &str| canonical_authority(declared).as_deref() == Some(&authority);
    matches(domain) || subdomain_scope.iter().any(|s| matches(s))
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
) -> Result<Option<(String, String, Vec<String>)>> {
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
    if canonical_authority(&parsed.publisher.domain).as_deref() != Some(host) {
        record_rejection(
            db,
            host,
            "WIST2-E04",
            now,
            None,
            "publisher declaration domain does not match ping host",
        )?;
        return Ok(None);
    }

    let key = match parsed.publisher.keys.first() {
        Some(k) => k,
        None => {
            record_rejection(db, host, "WIST2-E04", now, None, "publisher has no keys")?;
            return Ok(None);
        }
    };

    db.record_publisher_declaration(host, &raw, &key.key_id, &key.public_key, &value)?;

    Ok(Some((
        key.key_id.clone(),
        key.public_key.clone(),
        parsed.publisher.subdomain_scope.clone().unwrap_or_default(),
    )))
}

struct Meter<'a> {
    db: &'a Db,
    domain: &'a str,
    day: &'a str,
    budget: i64,
}

impl Meter<'_> {
    fn get(&self, client: &Client, url: &str) -> Result<Option<(Vec<u8>, Value)>> {
        if self.db.ingest_bytes(self.domain, self.day)? >= self.budget {
            return Ok(None);
        }
        let (raw, value) = client.get_json(url)?;
        self.db
            .add_ingest_bytes(self.domain, self.day, raw.len() as i64)?;
        Ok(Some((raw, value)))
    }
}

/// WIST-2 §3.2: `next` MUST be an absolute URL whose authority is the
/// Publisher's own. The scheme is re-derived per host so a loopback
/// deployment can follow the https URLs a Publisher writes into sealed
/// pages.
fn next_page_url(next: &str, host: &str, allow_http: bool) -> Option<String> {
    let parsed = url::Url::parse(next).ok()?;
    let authority = match parsed.port() {
        Some(port) => format!("{}:{port}", parsed.host_str()?),
        None => parsed.host_str()?.to_string(),
    };
    if !authority.eq_ignore_ascii_case(host) {
        return None;
    }
    let scheme = crate::fetch::scheme_for_host(host, allow_http);
    Some(format!("{scheme}://{host}{}", parsed.path()))
}

pub fn run(
    db: &Db,
    client: &Client,
    data_dir: &Path,
    host: &str,
    now: &str,
) -> Result<IngestReport> {
    let mut report = IngestReport::default();
    let Some(host) = canonical_authority(host) else {
        return Ok(report);
    };
    let host = host.as_str();
    let scheme = crate::fetch::scheme_for_host(host, client.allow_http());
    let base = format!("{scheme}://{host}/.well-known/wist/");

    let (public_key_b64u, subdomain_scope) = match db.get_publisher(host)? {
        Some(row) => (
            row.public_key,
            db.get_publisher_scope(host)?.unwrap_or_default(),
        ),
        None => match onboard_publisher(db, client, &base, host, now)? {
            Some((_, public_key, scope)) => (public_key, scope),
            None => {
                report.noise = Some("WIST2-E04");
                return Ok(report);
            }
        },
    };
    let pubkey = match PublicKey::from_b64u(&public_key_b64u) {
        Ok(pk) => pk,
        Err(e) => {
            record_rejection(db, host, "WIST2-E04", now, None, &e.to_string())?;
            report.noise = Some("WIST2-E04");
            return Ok(report);
        }
    };

    let day = now.get(..10).unwrap_or(now);
    let budget = crate::registry::effective(db, "ingest_budget_bytes_day", now)?;
    let meter = Meter {
        db,
        domain: host,
        day,
        budget,
    };

    let mut pages: Vec<FeedEnvelope> = Vec::new();
    let mut page_url = format!("{base}feed.json");
    let mut unseen_any = false;
    let mut suspended = false;
    loop {
        let fetched = match meter.get(client, &page_url) {
            Ok(Some(v)) => v,
            Ok(None) => {
                suspended = true;
                break;
            }
            Err(e) => {
                record_rejection(db, host, "WIST2-E01", now, None, &e.to_string())?;
                return Ok(report);
            }
        };
        let (_, feed_value) = fetched;
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
        if feed_parsed.feed.domain != host {
            record_rejection(
                db,
                host,
                "WIST2-E01",
                now,
                None,
                "feed domain does not match ping host",
            )?;
            return Ok(report);
        }

        let mut page_has_unseen = false;
        for id in &feed_parsed.feed.deltas {
            if !db.is_delta_seen(id)? {
                page_has_unseen = true;
                break;
            }
        }
        unseen_any |= page_has_unseen;
        let next = feed_parsed.feed.next.clone();
        pages.push(feed_parsed);
        if !page_has_unseen {
            break;
        }
        match next {
            Some(n) => match next_page_url(&n, host, client.allow_http()) {
                Some(u) => page_url = u,
                None => {
                    record_rejection(
                        db,
                        host,
                        "WIST2-E01",
                        now,
                        None,
                        "feed next is not a URL in the publisher's own authority",
                    )?;
                    return Ok(report);
                }
            },
            None => break,
        }
    }

    let mut chain_pos: i64 = 0;
    let delta_ids: Vec<String> = if suspended {
        Vec::new()
    } else {
        pages
            .iter()
            .rev()
            .flat_map(|p| p.feed.deltas.iter().cloned())
            .collect()
    };
    'process: for id in &delta_ids {
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
        let (_, delta_value) = match meter.get(client, &delta_url) {
            Ok(Some(v)) => v,
            Ok(None) => {
                suspended = true;
                break 'process;
            }
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

        if !url_in_scope(&delta_env.delta.url, host, &subdomain_scope) {
            record_rejection(
                db,
                host,
                "WIST1-E03",
                now,
                Some(id.as_str()),
                "delta url is outside the publisher's authority (scope rule)",
            )?;
            report.rejected.push((id.clone(), "WIST1-E03".to_string()));
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
            let (payload_raw, payload_value) = match meter.get(client, &payload_url) {
                Ok(Some(v)) => v,
                Ok(None) => {
                    suspended = true;
                    break 'process;
                }
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

        db.record_accepted_delta(host, id, &delta_value, chain_pos, &delta_env.delta.url, id)?;
        report.accepted.push(id.clone());
        chain_pos += 1;
    }

    db.set_walk_suspended(host, suspended)?;
    report.suspended = suspended;
    if !suspended {
        if !unseen_any && report.accepted.is_empty() && report.rejected.is_empty() {
            report.noise = Some("WIST2-E02");
        }
        db.set_publisher_pulled(host, now)?;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_bare_authority_accepts_host_and_host_port() {
        assert!(is_bare_authority("example.com"));
        assert!(is_bare_authority("127.0.0.1:8080"));
        assert!(is_bare_authority("EXAMPLE.com"));
    }

    #[test]
    fn is_bare_authority_rejects_scheme_path_query_fragment_userinfo() {
        assert!(!is_bare_authority(""));
        assert!(!is_bare_authority("https://example.com"));
        assert!(!is_bare_authority("example.com/x"));
        assert!(!is_bare_authority("example.com?x=1"));
        assert!(!is_bare_authority("example.com#frag"));
        assert!(!is_bare_authority("trusted.example@evil.example"));
        assert!(!is_bare_authority("example.com/../../etc/passwd"));
        assert!(!is_bare_authority("exa mple.com"));
    }

    #[test]
    fn canonical_authority_normalizes_case_and_idn_and_keeps_port() {
        assert_eq!(
            canonical_authority("EXAMPLE.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            canonical_authority("BÜCHER.example:8080").as_deref(),
            Some("xn--bcher-kva.example:8080")
        );
        assert_eq!(
            canonical_authority("127.0.0.1:9").as_deref(),
            Some("127.0.0.1:9")
        );
        assert_eq!(canonical_authority("under_score.example"), None);
        assert_eq!(canonical_authority("https://example.com"), None);
        assert_eq!(canonical_authority(""), None);
    }

    #[test]
    fn url_in_scope_compares_canonical_hosts() {
        assert!(url_in_scope(
            "https://BÜCHER.example/a",
            "xn--bcher-kva.example",
            &[]
        ));
        assert!(url_in_scope(
            "https://xn--bcher-kva.example/a",
            "bücher.example",
            &[]
        ));
        assert!(url_in_scope(
            "https://sub.example.com/a",
            "example.com",
            &["SUB.EXAMPLE.COM".to_string()]
        ));
        assert!(url_in_scope("https://example.com/a", "EXAMPLE.COM", &[]));
        assert!(!url_in_scope(
            "https://bücher.example/a",
            "example.com",
            &[]
        ));
    }

    #[test]
    fn url_in_scope_matches_domain_or_subdomain_scope() {
        assert!(url_in_scope("https://example.com/a", "example.com", &[]));
        assert!(url_in_scope(
            "https://blog.example.com/a",
            "example.com",
            &["blog.example.com".to_string()]
        ));
        assert!(!url_in_scope(
            "https://other.example/a",
            "example.com",
            &["blog.example.com".to_string()]
        ));
        assert!(!url_in_scope("not a url", "example.com", &[]));
    }
}
