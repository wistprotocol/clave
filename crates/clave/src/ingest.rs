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
    domain: &str,
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
        if Some(id.as_str()) == tip || db.is_delta_seen_for(&id, domain)? {
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
        let rejected_source = declaration::delta_publisher(&fetched) != Ok(domain);
        cursor = fetched["delta"]["prev"].as_str().map(str::to_string);
        prefetched.insert(id.clone(), fetched);
        chain.push(id);
        if rejected_source {
            break;
        }
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
    let current = declarations
        .iter()
        .filter(|(at, _, _)| *at <= cut)
        .max_by_key(|(at, seq, _)| (*at, *seq));
    let next = declarations
        .iter()
        .filter(|(at, _, _)| *at > cut)
        .min_by_key(|(at, seq, _)| (*at, std::cmp::Reverse(*seq)));
    current.into_iter().chain(next).any(|(_, _, keys)| {
        declaration::verify_signed(&keys.iter().collect::<Vec<_>>(), doc, "feed", None).is_ok()
    })
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

fn accepted_recovery_head(
    db: &Db,
    data_dir: &Path,
    host: &str,
    window: &crate::db::RecoveryWindowRow,
) -> Result<Value> {
    let mut head = if window.opened_block.is_some() {
        let state =
            crate::history::declarations::Declarations::reconstruct(data_dir, db.last_block()?)?;
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
        let owner: Value = serde_json::from_slice(&window.owner_declaration_json)?;
        let prior: Value = serde_json::from_slice(&window.prior_declaration_json)?;
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
        .collect();
    pending.sort_by_key(|entry| entry.entry_json["publisher"]["seq"].as_u64());
    for entry in pending {
        if declaration::follows_chain_head(&head, &entry.entry_json) {
            head = entry.entry_json;
        }
    }
    Ok(head)
}

fn settle_before_admission(
    db: &Db,
    data_dir: &Path,
    host: &str,
    clock: &impl Fn() -> jiff::Timestamp,
) -> Result<()> {
    if db
        .get_recovery_window(host)?
        .is_some_and(|window| window.opened_block.is_some())
    {
        crate::recovery::settle(db, data_dir, &clock().to_string())?;
    }
    Ok(())
}

fn delta_admission_sources(db: &Db, host: &str) -> Result<(bool, Vec<Publisher>)> {
    let window = db.get_recovery_window(host)?;
    let raw = match &window {
        Some(window) => vec![
            window.prior_declaration_json.clone(),
            window.owner_declaration_json.clone(),
        ],
        None => vec![db.get_publisher_declaration(host)?.ok_or_else(|| {
            crate::error::Error::History("missing Delta admission Declaration".into())
        })?],
    };
    let sources = raw
        .iter()
        .map(|raw| {
            let doc: Value = serde_json::from_slice(raw)?;
            declaration::publisher_of(&doc).map_err(crate::error::Error::History)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((window.is_some(), sources))
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
    let clock = now
        .parse::<jiff::Timestamp>()
        .map_err(|e| crate::error::Error::Clock(e.to_string()))?;
    run_with_clock(db, client, data_dir, host, now, || clock)
}

pub fn run_with_clock(
    db: &Db,
    client: &Client,
    data_dir: &Path,
    host: &str,
    now: &str,
    clock: impl Fn() -> jiff::Timestamp,
) -> Result<IngestReport> {
    let mut report = IngestReport::default();
    let Some(host) = canonical_authority(host) else {
        return Ok(report);
    };
    let host = host.as_str();
    crate::recovery::settle(db, data_dir, now)?;
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
                settle_before_admission(db, data_dir, host, &clock)?;
                let mutation = db.mutation()?;
                let stored_raw = db.get_publisher_declaration(host)?.ok_or_else(|| {
                    crate::error::Error::History(
                        "publisher row lost before Declaration admission".into(),
                    )
                })?;
                current_doc = serde_json::from_slice(&stored_raw)?;
                let open_window = db.get_recovery_window(host)?;
                let recovery_head = open_window
                    .as_ref()
                    .map(|window| accepted_recovery_head(db, data_dir, host, window))
                    .transpose()?;
                if let Some(head) = &recovery_head {
                    db.update_recovery_chain_head(host, &serde_json::to_vec(head)?)?;
                }
                let floor = db.highest_accepted_declaration_seq(host)?.ok_or_else(|| {
                    crate::error::Error::History(
                        "missing accepted Declaration sequence floor".into(),
                    )
                })?;
                match declaration::evaluate_with_heads(
                    &current_doc,
                    recovery_head.as_ref(),
                    floor,
                    &value,
                ) {
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
                            Some(_) => {
                                if declaration::follows_chain_head(
                                    recovery_head.as_ref().unwrap(),
                                    &value,
                                ) {
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
                mutation.commit()?;
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

    match declaration::publisher_of(&current_doc) {
        Ok(_) => {}
        Err(e) => {
            record_rejection(db, host, "WIST2-E04", now, None, &e)?;
            report.noise = Some("WIST2-E04");
            return Ok(report);
        }
    };

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
        settle_before_admission(db, data_dir, host, &clock)?;
        let live_page = pages.is_empty();
        let verified = if live_page {
            let raw = db.get_publisher_declaration(host)?.ok_or_else(|| {
                crate::error::Error::History("missing Feed admission Declaration".into())
            })?;
            let doc = serde_json::from_slice(&raw)?;
            let publisher =
                declaration::publisher_of(&doc).map_err(crate::error::Error::History)?;
            declaration::verify_signed(
                &publisher.keys.iter().collect::<Vec<_>>(),
                &feed_value,
                "feed",
                None,
            )
            .is_ok()
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
            if !db.is_delta_seen_for(id, host)? {
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
        settle_before_admission(db, data_dir, host, &clock)?;
        if db.is_delta_seen_for(id, host)? {
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
        let association = match declaration::delta_publisher(&delta_value) {
            Err(_) => Err("WIST1-E14"),
            Ok(domain) if domain != host => Err("WIST2-E03"),
            Ok(_) => Ok(()),
        };
        if let Err(code) = association {
            record_rejection(
                db,
                host,
                code,
                now,
                Some(id),
                "Delta Publisher does not match the logical Feed",
            )?;
            report.rejected.push((id.clone(), code.into()));
            continue;
        }
        settle_before_admission(db, data_dir, host, &clock)?;
        let (_, sources) = delta_admission_sources(db, host)?;
        if let Err(code) =
            declaration::verify_delta_authority(&sources.iter().collect::<Vec<_>>(), &delta_value)
        {
            record_rejection(
                db,
                host,
                code,
                now,
                Some(id.as_str()),
                "Delta signing and scope authority failed",
            )?;
            report.rejected.push((id.clone(), code.to_string()));
            continue;
        }
        let validation_clock = clock();
        let profile_at = jiff::Timestamp::from_second(
            validation_clock.as_nanosecond().div_euclid(1_000_000_000) as i64,
        )
        .map_err(|e| crate::error::Error::Clock(e.to_string()))?
        .to_string();
        let allowance_s = registry::effective(db, "clock_skew_seconds", &profile_at)?;
        if let Err(code) =
            declaration::verify_delta_clock(&delta_value, validation_clock, allowance_s)
        {
            record_rejection(
                db,
                host,
                code,
                now,
                Some(id.as_str()),
                "observed_at exceeds the clock_skew_seconds allowance",
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

        let expected_prev = db.url_tip(host, &delta_env.delta.url)?;
        if delta_env.delta.prev != expected_prev {
            // WIST-2 §5 step 3: retrieve and validate any `prev` not yet
            // sealed, in chain order, before the Delta naming it.
            if resolved_prev.insert(id.clone()) {
                match retrieve_prev_chain(
                    db,
                    client,
                    &meter,
                    &base,
                    host,
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

        if let Some(prev) = &delta_env.delta.prev {
            let predecessor = db.accepted_delta(data_dir, host, prev)?;
            if let Err(code) = declaration::verify_delta_predecessor(&delta_value, &predecessor) {
                record_rejection(
                    db,
                    host,
                    code,
                    now,
                    Some(id),
                    "Delta does not strictly follow its predecessor observation",
                )?;
                report.rejected.push((id.clone(), code.into()));
                continue;
            }
        }

        let payload_raw = if let Some(commitment) = &delta_env.delta.payload {
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

            Some(payload_raw)
        } else {
            None
        };

        settle_before_admission(db, data_dir, host, &clock)?;
        let (window_open, sources) = delta_admission_sources(db, host)?;
        if let Err(code) =
            declaration::verify_delta_authority(&sources.iter().collect::<Vec<_>>(), &delta_value)
        {
            record_rejection(
                db,
                host,
                code,
                now,
                Some(id),
                "Delta authority changed before admission",
            )?;
            report.rejected.push((id.clone(), code.into()));
            continue;
        }
        if delta_env.delta.prev != db.url_tip(host, &delta_env.delta.url)? {
            resolved_prev.remove(id);
            prefetched.insert(id.clone(), delta_value);
            position -= 1;
            continue;
        }
        if let Some(raw) = payload_raw {
            let payloads_dir = data_dir.join("payloads");
            std::fs::create_dir_all(&payloads_dir)?;
            std::fs::write(payloads_dir.join(format!("{hex}.json")), &raw)?;
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
    fn signed_pages_consume_keyset_resolution_vectors() {
        let root = std::env::var_os("WIST_SPEC_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
            });
        let vector: Value = serde_json::from_slice(
            &std::fs::read(root.join("vectors/wist2/page-keyset.json")).unwrap(),
        )
        .unwrap();
        let seeds = std::collections::BTreeMap::from([
            ("k1", [21; 32]),
            ("k2", [22; 32]),
            ("k3", [23; 32]),
        ]);
        for case in vector["cases"].as_array().unwrap() {
            let mut declarations: Vec<_> = case["declarations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|declaration| {
                    let keys = declaration["keys"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|key| {
                            let id = key.as_str().unwrap();
                            wist_core::objects::PublisherKey {
                                key_id: id.into(),
                                alg: "Ed25519".into(),
                                public_key: wist_core::crypto::b64u_encode(
                                    &ed25519_dalek::SigningKey::from_bytes(&seeds[id])
                                        .verifying_key()
                                        .to_bytes(),
                                ),
                                valid_from: "2099-01-01T00:00:00Z".into(),
                            }
                        })
                        .collect();
                    (
                        declaration["sealed_at_s"].as_i64().unwrap(),
                        declaration["seq"].as_u64().unwrap(),
                        keys,
                    )
                })
                .collect();
            for (page, expected) in case["pages"]
                .as_array()
                .unwrap()
                .iter()
                .zip(case["expected"].as_array().unwrap())
            {
                let cut = jiff::Timestamp::from_second(page["generated_at_s"].as_i64().unwrap())
                    .unwrap()
                    .to_string();
                let signer = page["signer"].as_str().unwrap();
                let body = serde_json::json!({
                    "wist_version": "1.0.0", "domain": "example.com",
                    "generated_at": cut, "deltas": [], "next": null
                });
                let key = wist_core::crypto::SigningKey::from_seed(&seeds[signer]);
                let mut doc =
                    wist_core::envelope::sign_envelope(&body, "feed", signer, &key).unwrap();
                for _ in 0..2 {
                    assert_eq!(
                        verify_sealed_page(&declarations, &doc, &cut),
                        expected["verifies"].as_bool().unwrap(),
                        "{}: {}",
                        case["name"],
                        page["page"]
                    );
                    declarations.reverse();
                }
                doc["feed"]["domain"] = "tampered.example".into();
                assert!(!verify_sealed_page(&declarations, &doc, &cut));
            }
        }
    }

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
    fn scope_requires_normalized_urls_and_literal_canonical_hosts() {
        for url in [
            "https://example.com/a",
            "https://example.com:8443/a",
            "https://xn--bcher-kva.example/a",
        ] {
            assert!(declaration::url_in_scope(
                url,
                "example.com",
                &["xn--bcher-kva.example".into()]
            ));
        }
        for url in [
            "https://EXAMPLE.com/a",
            "https://bücher.example/a",
            "https://example.com:443/a",
            "https://example.com/a#fragment",
            "https://example.com/a/../b",
            "https://example.com/%zz",
            "http://example.com/a",
            "https://other.example/a",
            "not a url",
        ] {
            assert!(!declaration::url_in_scope(url, "example.com", &[]), "{url}");
        }
        assert!(!declaration::url_in_scope(
            "https://sub.example.com/a",
            "example.com",
            &[]
        ));
        assert!(declaration::url_in_scope(
            "https://sub.example.com/a",
            "example.com",
            &["sub.example.com".into()]
        ));
    }

    #[test]
    fn signed_attribution_vectors_preserve_source_and_feed_identity() {
        let root = std::env::var_os("WIST_SPEC_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
            });
        let vector: Value = serde_json::from_slice(
            &std::fs::read(root.join("vectors/wist1/delta-attribution.json")).unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            for reverse in [false, true] {
                let mut sources: Vec<_> = case["declarations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|doc| declaration::evaluate_initial(doc).unwrap())
                    .collect();
                if reverse {
                    sources.reverse();
                }
                for (index, envelope) in case["envelopes"].as_array().unwrap().iter().enumerate() {
                    let original = envelope.clone();
                    let actual = (|| {
                        let domain = declaration::delta_publisher(envelope)?;
                        if case["feed_domain"]
                            .as_str()
                            .is_some_and(|feed| feed != domain)
                        {
                            return Err("WIST2-E03");
                        }
                        declaration::verify_delta_authority(
                            &sources.iter().collect::<Vec<_>>(),
                            envelope,
                        )?;
                        Ok(())
                    })();
                    assert_eq!(
                        actual.err().unwrap_or("accepted"),
                        case["expected"][index],
                        "{}",
                        case["name"]
                    );
                    assert_eq!(*envelope, original);
                }
            }
        }
    }
}
