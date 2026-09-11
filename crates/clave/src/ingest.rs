use crate::db::Db;
use crate::error::Result;
use crate::fetch::Client;
use serde_json::Value;
use std::path::Path;
use wist_core::delta::{content_bytes, delta_id, verify_commitment};
use wist_core::objects::{DeltaEnvelope, FeedEnvelope, Payload, Publisher};

use crate::declaration::{self, Decision};
use crate::registry;

#[derive(Debug, Default)]
pub struct IngestReport {
    pub accepted: Vec<String>,
    pub queued: Vec<String>,
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

/// WIST-2 §3.2: a sealed Page is verified against the Key Set current at
/// its `generated_at`, or, where that set does not hold the signing key,
/// against the Key Set of the first Declaration sealed after it. A Page
/// verifying under neither is `WIST2-E04`; one MUST NOT be rejected
/// merely because its key has since been retired, because Pages are
/// immutable and never re-signed on rotation.
enum PrevChain {
    Resolved(Vec<String>),
    Unresolved,
    BudgetExhausted,
}

/// WIST-2 §5 step 3 with WIST-1 §3.5: walk back from a Delta's `prev`
/// through Deltas the Aggregator has not sealed until the chain reaches
/// the tip it holds, fetching each under the per-domain budget. The
/// bodies are kept so the caller validates each in chain order without
/// paying for the fetch twice.
#[allow(clippy::too_many_arguments)]
fn retrieve_prev_chain(
    db: &Db,
    client: &Client,
    meter: &Meter<'_>,
    base: &str,
    prev: Option<&str>,
    tip: Option<&str>,
    prefetched: &mut std::collections::HashMap<String, Value>,
) -> Result<PrevChain> {
    let mut chain = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cursor = prev.map(str::to_string);
    loop {
        let Some(id) = cursor else {
            // A chain that starts here links up only when the Aggregator
            // holds no tip for the URL; otherwise it is a fork.
            if tip.is_some() {
                return Ok(PrevChain::Unresolved);
            }
            break;
        };
        if Some(id.as_str()) == tip || db.is_delta_seen(&id)? {
            break;
        }
        if !seen.insert(id.clone()) {
            return Ok(PrevChain::Unresolved);
        }
        let Some(hex) = id.strip_prefix("sha256:") else {
            return Ok(PrevChain::Unresolved);
        };
        let fetched = match meter.get(client, &format!("{base}deltas/{hex}.json")) {
            Ok(Some((_, value))) => value,
            Ok(None) => return Ok(PrevChain::BudgetExhausted),
            Err(_) => return Ok(PrevChain::Unresolved),
        };
        cursor = fetched["delta"]["prev"].as_str().map(str::to_string);
        prefetched.insert(id.clone(), fetched);
        chain.push(id);
    }
    chain.reverse();
    Ok(PrevChain::Resolved(chain))
}

fn page_declarations(
    db: &Db,
    host: &str,
    current: &Value,
) -> Result<Vec<(i64, u64, Vec<wist_core::objects::PublisherKey>)>> {
    let mut out = Vec::new();
    for d in db.sealed_declarations(host)? {
        let Ok(at) = d.sealed_at.parse::<jiff::Timestamp>() else {
            continue;
        };
        let doc: Value = serde_json::from_slice(&d.declaration_json)?;
        if let Ok(publisher) = declaration::publisher_of(&doc) {
            out.push((at.as_second(), d.seq, publisher.keys));
        }
    }
    // A Declaration the Aggregator has accepted but not yet sealed seals
    // after every Page already cut, so it is the last candidate for
    // §3.2's second resolution.
    if let Ok(publisher) = declaration::publisher_of(current) {
        if !out.iter().any(|(_, seq, _)| *seq == publisher.seq) {
            out.push((i64::MAX, publisher.seq, publisher.keys));
        }
    }
    Ok(out)
}

fn verify_sealed_page(
    declarations: &[(i64, u64, Vec<wist_core::objects::PublisherKey>)],
    doc: &Value,
    generated_at: &str,
) -> bool {
    let Ok(cut) = generated_at.parse::<jiff::Timestamp>() else {
        return false;
    };
    let cut = cut.as_second();
    let entries: Vec<wist_core::keyset::DeclarationAtInstant> = declarations
        .iter()
        .map(|(at, seq, keys)| wist_core::keyset::DeclarationAtInstant {
            seq: *seq,
            sealed_at_s: *at,
            keys: keys.iter().map(|k| k.key_id.clone()).collect(),
        })
        .collect();
    let signer = doc["sig"]["key_id"].as_str().unwrap_or_default();
    let resolved = match wist_core::keyset::page_resolution(&entries, cut, signer) {
        Some(wist_core::keyset::PageResolution::Current) => {
            wist_core::keyset::page_key_set_current(&entries, cut)
        }
        Some(wist_core::keyset::PageResolution::Next) => {
            wist_core::keyset::page_key_set_next(&entries, cut)
        }
        None => return false,
    };
    let keys: Vec<&wist_core::objects::PublisherKey> = declarations
        .iter()
        .flat_map(|(_, _, keys)| keys.iter())
        .filter(|k| resolved.contains(&k.key_id))
        .collect();
    declaration::verify_signed(&keys, doc, "feed", None).is_ok()
}

fn key_set_cache_expired(db: &Db, host: &str, now: &str) -> Result<bool> {
    let ttl = registry::effective(db, "keyset_cache_ttl_seconds", now)?;
    let Some(fetched_at) = db.declaration_fetched_at(host)? else {
        return Ok(true);
    };
    let (Ok(fetched), Ok(now_ts)) = (
        fetched_at.parse::<jiff::Timestamp>(),
        now.parse::<jiff::Timestamp>(),
    ) else {
        return Ok(true);
    };
    Ok(now_ts.as_second() - fetched.as_second() > ttl)
}

fn onboard_publisher(
    db: &Db,
    client: &Client,
    base: &str,
    host: &str,
    now: &str,
) -> Result<Option<()>> {
    let publisher_url = format!("{base}publisher.json");
    let (raw, value) = match client.get_json(&publisher_url) {
        Ok(v) => v,
        Err(e) => {
            record_rejection(db, host, "WIST2-E04", now, None, &e.to_string())?;
            return Ok(None);
        }
    };

    let publisher = match declaration::evaluate_initial(&value) {
        Ok(publisher) => publisher,
        Err((code, detail)) => {
            record_rejection(
                db,
                host,
                "WIST2-E04",
                now,
                None,
                &format!("{code}: {detail}"),
            )?;
            return Ok(None);
        }
    };
    if canonical_authority(&publisher.domain).as_deref() != Some(host) {
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

    let key = match publisher.keys.first() {
        Some(k) => k,
        None => {
            record_rejection(db, host, "WIST2-E04", now, None, "publisher has no keys")?;
            return Ok(None);
        }
    };

    db.record_publisher_declaration(host, &raw, &key.key_id, &key.public_key, &value)?;
    db.mark_declaration_fetched(host, now)?;

    Ok(Some(()))
}

struct Meter<'a> {
    db: &'a Db,
    domain: &'a str,
    day: &'a str,
    budget: i64,
    subdomain_scope: Vec<String>,
}

impl Meter<'_> {
    fn get(&self, client: &Client, url: &str) -> Result<Option<(Vec<u8>, Value)>> {
        if self.db.ingest_bytes(self.domain, self.day)? >= self.budget {
            return Ok(None);
        }
        let (raw, value) = client.get_json_in_scope(url, &self.subdomain_scope)?;
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
    if crate::sanctions::sanction_level(db, host, now)? >= 3 {
        return Ok(report);
    }
    let scheme = crate::fetch::scheme_for_host(host, client.allow_http());
    let base = format!("{scheme}://{host}/.well-known/wist/");

    let day = now.get(..10).unwrap_or(now);
    let budget = crate::registry::effective(db, "ingest_budget_bytes_day", now)?;
    let stored_scope = db
        .get_publisher_declaration(host)?
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .and_then(|doc| declaration::publisher_of(&doc).ok())
        .and_then(|p| p.subdomain_scope)
        .unwrap_or_default();
    let meter = Meter {
        db,
        domain: host,
        day,
        budget,
        subdomain_scope: stored_scope,
    };

    let known = db.get_publisher(host)?.is_some();
    if !known && onboard_publisher(db, client, &base, host, now)?.is_none() {
        report.noise = Some("WIST2-E04");
        return Ok(report);
    }

    let stored_raw = db
        .get_publisher_declaration(host)?
        .ok_or_else(|| crate::error::Error::Fetch("publisher row lost mid-ingest".into()))?;
    let mut current_doc: Value = serde_json::from_slice(&stored_raw)?;

    if known {
        let publisher_url = format!("{base}publisher.json");
        match meter.get(client, &publisher_url) {
            Ok(Some((raw, value))) => {
                let open_window = db.get_recovery_window(host)?;
                match declaration::evaluate(&current_doc, &value) {
                    Ok(Decision::Unchanged) => {}
                    Ok(decision) => {
                        let (key_id, public_key) = value
                            .pointer("/publisher/keys/0")
                            .map(|k| {
                                (
                                    k["key_id"].as_str().unwrap_or_default().to_string(),
                                    k["public_key"].as_str().unwrap_or_default().to_string(),
                                )
                            })
                            .unwrap_or_default();
                        db.update_publisher_declaration(host, &raw, &key_id, &public_key, &value)?;
                        match &open_window {
                            None => {
                                if decision == Decision::Recovery {
                                    db.open_recovery_window(host, &raw, &stored_raw)?;
                                }
                            }
                            Some(window) => {
                                let head: Value = serde_json::from_slice(&window.declaration_json)?;
                                if declaration::follows_chain_head(&head, &value) {
                                    db.update_recovery_chain_head(host, &raw)?;
                                }
                            }
                        }
                        current_doc = value;
                    }
                    Err((code, detail)) => {
                        record_rejection(db, host, code, now, None, &detail)?;
                    }
                }
                db.mark_declaration_fetched(host, now)?;
            }
            // WIST-1 §5.1: a cached Key Set is valid for at most
            // keyset_cache_ttl_seconds. Past that, a discovery failure
            // leaves no Key Set to validate against and the pull fails
            // closed with WIST1-E02 rather than sealing under a
            // declaration of any age.
            Ok(None) => {}
            Err(e) => {
                if key_set_cache_expired(db, host, now)? {
                    record_rejection(
                        db,
                        host,
                        "WIST1-E02",
                        now,
                        None,
                        &format!("Key Set cache expired and rediscovery failed: {e}"),
                    )?;
                    return Ok(report);
                }
            }
        }
    }

    let current_p: Publisher = match declaration::publisher_of(&current_doc) {
        Ok(p) => p,
        Err(e) => {
            record_rejection(db, host, "WIST2-E04", now, None, &e)?;
            report.noise = Some("WIST2-E04");
            return Ok(report);
        }
    };
    let window = db.get_recovery_window(host)?;
    let window_open = window.is_some();
    let recovery_sources = window
        .as_ref()
        .map(|window| {
            [
                &window.prior_declaration_json,
                &window.owner_declaration_json,
            ]
            .into_iter()
            .map(|raw| {
                let doc: Value = serde_json::from_slice(raw)?;
                declaration::publisher_of(&doc).map_err(crate::error::Error::History)
            })
            .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let key_set: Vec<_> = match &recovery_sources {
        Some(sources) => sources
            .iter()
            .flat_map(|source| source.keys.iter())
            .collect(),
        None => current_p.keys.iter().collect(),
    };
    let feed_keys: Vec<_> = current_p.keys.iter().collect();
    let subdomain_scope = current_p.subdomain_scope.clone().unwrap_or_default();

    let page_key_sets = page_declarations(db, host, &current_doc)?;
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
        let live_page = pages.is_empty();
        let verified = if live_page {
            declaration::verify_signed(&feed_keys, &feed_value, "feed", None).is_ok()
        } else {
            let generated_at = feed_value["feed"]["generated_at"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            verify_sealed_page(&page_key_sets, &feed_value, &generated_at)
        };
        if !verified {
            record_rejection(
                db,
                host,
                "WIST2-E04",
                now,
                None,
                "feed signature does not verify against the domain's Key Set",
            )?;
            report.noise = Some("WIST2-E04");
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
                "WIST2-E04",
                now,
                None,
                "feed domain does not match the host it was fetched from",
            )?;
            report.noise = Some("WIST2-E04");
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
    let mut delta_ids = delta_ids;
    let mut prefetched: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    let mut resolved_prev: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut position = 0usize;
    'process: while position < delta_ids.len() {
        let id = &delta_ids[position].clone();
        position += 1;
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
        let delta_value = match prefetched.remove(id) {
            Some(v) => v,
            None => match meter.get(client, &delta_url) {
                Ok(Some((_, v))) => v,
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
            },
        };
        let observed_at = delta_value["delta"]["observed_at"]
            .as_str()
            .unwrap_or_default();
        if let Err(code) =
            declaration::verify_signed(&key_set, &delta_value, "delta", Some(observed_at))
        {
            record_rejection(
                db,
                host,
                code,
                now,
                Some(id.as_str()),
                "key set validation failed",
            )?;
            report.rejected.push((id.clone(), code.to_string()));
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
            // WIST-2 §5 step 3: retrieve and validate any `prev` not yet
            // sealed, in chain order, before the Delta naming it.
            if resolved_prev.insert(id.clone()) {
                match retrieve_prev_chain(
                    db,
                    client,
                    &meter,
                    &base,
                    delta_env.delta.prev.as_deref(),
                    expected_prev.as_deref(),
                    &mut prefetched,
                )? {
                    PrevChain::Resolved(ancestors) if !ancestors.is_empty() => {
                        let at = position - 1;
                        prefetched.insert(id.clone(), delta_value);
                        delta_ids.splice(at..at, ancestors);
                        position = at;
                        continue;
                    }
                    PrevChain::BudgetExhausted => {
                        suspended = true;
                        break 'process;
                    }
                    _ => {}
                }
            }
            record_rejection(
                db,
                host,
                "WIST1-E07",
                now,
                Some(id.as_str()),
                "prev does not match the chain tip and could not be retrieved",
            )?;
            report.rejected.push((id.clone(), "WIST1-E07".to_string()));
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

        if window_open {
            db.queue_delta(host, id, &delta_value, &delta_env.delta.url, id, chain_pos)?;
            report.queued.push(id.clone());
        } else {
            db.record_accepted_delta(host, id, &delta_value, chain_pos, &delta_env.delta.url, id)?;
            report.accepted.push(id.clone());
        }
        chain_pos += 1;
    }

    db.set_walk_suspended(host, suspended)?;
    report.suspended = suspended;
    if !suspended {
        if !unseen_any
            && report.accepted.is_empty()
            && report.queued.is_empty()
            && report.rejected.is_empty()
        {
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
