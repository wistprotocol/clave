use crate::db::Db;
use crate::error::Result;
use crate::fetch::Client;
use crate::history::declarations::DeclarationsReplay;
use serde_json::Value;
use std::path::Path;
use wist_core::delta::delta_id;
use wist_core::objects::{DeltaEnvelope, FeedEnvelope, Publisher};

use crate::declaration::{self, Decision};
use crate::registry;

mod feed;

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

fn page_declarations(
    db: &Db,
    data_dir: &Path,
    host: &str,
) -> Result<Vec<(i64, u64, Vec<wist_core::objects::PublisherKey>)>> {
    let mut history = crate::history::History::open(data_dir, db.last_block()?)?;
    let mut state = crate::history::declarations::Declarations::default();
    let mut sources = Vec::new();
    let mut superseded = std::collections::BTreeSet::new();
    while let Some(block) = history.next_block()? {
        let effects = state.apply(&block)?;
        for settlement in effects.settlements {
            if settlement.domain == host {
                for source in settlement.superseded {
                    superseded.insert(source.hash().to_string());
                }
            }
        }
        for entry in block.block().entries.iter().filter(|entry| {
            entry["type"] == "publisher_declaration" && entry["body"]["publisher"]["domain"] == host
        }) {
            let source = &entry["body"];
            let publisher =
                declaration::publisher_of(source).map_err(crate::error::Error::History)?;
            sources.push((
                declaration::inner_hash(source).map_err(crate::error::Error::History)?,
                (block.sealed_at_s(), publisher.seq, publisher.keys),
            ));
        }
    }
    Ok(sources
        .into_iter()
        .filter_map(|(hash, source)| (!superseded.contains(&hash)).then_some(source))
        .collect())
}

fn verify_sealed_page(
    declarations: &[(i64, u64, Vec<wist_core::objects::PublisherKey>)],
    doc: &Value,
    generated_at: &str,
) -> bool {
    let Ok(cut) = registry::epoch(generated_at) else {
        return false;
    };
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
            let doc: Value = crate::json::parse(raw)?;
            declaration::publisher_of(&doc).map_err(crate::error::Error::History)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((window.is_some(), sources))
}

fn admit_fetched_declaration(
    db: &Db,
    data_dir: &Path,
    host: &str,
    now: &str,
    clock: &impl Fn() -> jiff::Timestamp,
    raw: Vec<u8>,
    value: Value,
) -> Result<Value> {
    settle_before_admission(db, data_dir, host, clock)?;
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
    match declaration::evaluate_with_heads(&current_doc, recovery_head.as_ref(), floor, &value) {
        Ok(Decision::Unchanged) => {
            db.mark_declaration_fetched(host, now)?;
        }
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
                    if declaration::follows_chain_head(recovery_head.as_ref().unwrap(), &value) {
                        db.update_recovery_chain_head(host, &raw)?;
                    }
                }
            }
            current_doc = value;
            db.mark_declaration_fetched(host, now)?;
        }
        Err((code, detail)) => {
            record_rejection(db, host, code, now, None, &detail)?;
        }
    }
    mutation.commit()?;
    Ok(current_doc)
}

fn verify_live_feed(db: &Db, host: &str, feed: &Value) -> Result<bool> {
    let raw = db
        .get_publisher_declaration(host)?
        .ok_or_else(|| crate::error::Error::History("missing Feed admission Declaration".into()))?;
    let doc = crate::json::parse(&raw)?;
    let publisher = declaration::publisher_of(&doc).map_err(crate::error::Error::History)?;
    Ok(declaration::verify_signed(
        &publisher.keys.iter().collect::<Vec<_>>(),
        feed,
        "feed",
        None,
    )
    .is_ok())
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

/// The work one pull may do before it suspends the walk for a later pull
/// to resume, below the per-domain daily budget of WIST-2 §5.
#[derive(Debug, Clone, Copy)]
pub struct PullLimits {
    pub work_bytes: u64,
    pub work_objects: u32,
}

impl Default for PullLimits {
    fn default() -> Self {
        PullLimits {
            work_bytes: 64 << 20,
            work_objects: 4096,
        }
    }
}

/// The kinds of content object a pull fetches under the byte budget, each
/// bounded while it streams.
#[derive(Debug, Clone, Copy)]
enum Object {
    Page,
    Delta,
    Payload,
}

/// Per-object bounds: Feed pages by the shared object cap, a Delta file
/// by its URL cap and fixed fields, a Payload by the content caps in
/// force plus its salt and framing.
struct ObjectCaps {
    delta: u64,
    payload: u64,
}

impl ObjectCaps {
    fn from_schedule(schedule: &wist_core::parameters::Schedule, at: i64) -> Self {
        let caps = crate::declaration::delta::SizeCaps::from_schedule(schedule, at);
        ObjectCaps {
            delta: 16_384 + 2 * caps.url_cap_bytes as u64,
            payload: crate::payload::cap_bytes(&caps),
        }
    }

    fn of(&self, object: Object) -> u64 {
        match object {
            Object::Page => crate::fetch::OBJECT_CAP_BYTES,
            Object::Delta => self.delta,
            Object::Payload => self.payload,
        }
    }
}

struct Meter<'a> {
    db: &'a Db,
    domain: &'a str,
    day: &'a str,
    budget: i64,
    caps: ObjectCaps,
    work: std::cell::Cell<(u64, u32)>,
}

impl Meter<'_> {
    /// WIST-2 §8: the hosts a redirect may reach are those the Publisher's
    /// Declaration lists at the moment the request is issued, so a
    /// replacement admitted earlier in the pull governs the requests after
    /// it; before the first accepted Declaration a redirect stays on the
    /// requested host.
    fn scope(&self) -> Result<Vec<String>> {
        Ok(self
            .db
            .get_publisher_declaration(self.domain)?
            .and_then(|raw| crate::json::parse(&raw).ok())
            .and_then(|doc| declaration::publisher_of(&doc).ok())
            .and_then(|p| p.subdomain_scope)
            .unwrap_or_default())
    }

    /// Fetches one content object under the remaining daily budget, the
    /// pull's work limits and the object's own cap. `None` suspends the
    /// walk: the budget or the work is spent, or the object would cross
    /// the budget, in which case the bytes read up to the bound are
    /// debited. An object above its own cap is a failed fetch.
    fn get(&self, client: &Client, url: &str, object: Object) -> Result<Option<(Vec<u8>, Value)>> {
        let spent = self.db.ingest_bytes(self.domain, self.day)?;
        let (work_bytes, work_objects) = self.work.get();
        if spent >= self.budget || work_bytes == 0 || work_objects == 0 {
            return Ok(None);
        }
        let cap = self.caps.of(object);
        let limit = cap.min((self.budget - spent) as u64).min(work_bytes);
        match client.get_json_bounded(url, &self.scope()?, limit) {
            Ok((raw, value)) => {
                self.db
                    .add_ingest_bytes(self.domain, self.day, raw.len() as i64)?;
                self.work
                    .set((work_bytes - raw.len() as u64, work_objects - 1));
                Ok(Some((raw, value)))
            }
            Err(crate::error::Error::Oversized(_)) if limit < cap => {
                self.db
                    .add_ingest_bytes(self.domain, self.day, limit as i64)?;
                self.work.set((work_bytes - limit, work_objects));
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// WIST-2 §3.2 target rule: a read `next` is fetched only when it is
/// byte-identical to its Normalized URL and begins with the requested
/// Canonical Host's well-known prefix. The scheme is re-derived per host
/// so a loopback deployment can follow the https URLs a Publisher writes
/// into sealed pages.
fn next_page_url(next: &str, host: &str, allow_http: bool) -> Option<String> {
    let prefix = format!("https://{host}/.well-known/wist/");
    if !next.starts_with(&prefix)
        || wist_core::extract::normalize_url(next, next).as_deref() != Some(next)
    {
        return None;
    }
    let scheme = crate::fetch::scheme_for_host(host, allow_http);
    Some(format!(
        "{scheme}://{host}{}",
        &next["https://".len() + host.len()..]
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_delta_with_refresh(
    db: &Db,
    client: &Client,
    data_dir: &Path,
    host: &str,
    now: &str,
    clock: &impl Fn() -> jiff::Timestamp,
    scope: &[String],
    base: &str,
    id: &str,
    envelope: &Value,
    attempted: &mut std::collections::HashSet<String>,
) -> Result<(bool, std::result::Result<(), &'static str>)> {
    settle_before_admission(db, data_dir, host, clock)?;
    let (mut window_open, sources) = delta_admission_sources(db, host)?;
    let mut authority =
        declaration::verify_delta_authority(&sources.iter().collect::<Vec<_>>(), envelope);
    if matches!(authority, Err("WIST1-E01" | "WIST1-E02")) && attempted.insert(id.into()) {
        if let Ok((raw, value)) = client.get_json_in_scope(&format!("{base}publisher.json"), scope)
        {
            admit_fetched_declaration(db, data_dir, host, now, clock, raw, value)?;
        }
        settle_before_admission(db, data_dir, host, clock)?;
        let sources;
        (window_open, sources) = delta_admission_sources(db, host)?;
        authority =
            declaration::verify_delta_authority(&sources.iter().collect::<Vec<_>>(), envelope);
    }
    Ok((window_open, authority))
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
    run_bounded(
        db,
        client,
        data_dir,
        host,
        now,
        clock,
        PullLimits::default(),
    )
}

pub fn run_bounded(
    db: &Db,
    client: &Client,
    data_dir: &Path,
    host: &str,
    now: &str,
    clock: impl Fn() -> jiff::Timestamp,
    limits: PullLimits,
) -> Result<IngestReport> {
    let mut report = IngestReport::default();
    let Some(host) = canonical_authority(host) else {
        return Ok(report);
    };
    let host = host.as_str();
    crate::recovery::settle(db, data_dir, now)?;
    let scheme = crate::fetch::scheme_for_host(host, client.allow_http());
    let base = format!("{scheme}://{host}/.well-known/wist/");

    let day = now.get(..10).unwrap_or(now);
    let budget = crate::registry::effective(db, "ingest_budget_bytes_day", now)?;
    let now_epoch = crate::registry::epoch(now)?;
    let meter = Meter {
        db,
        domain: host,
        day,
        budget,
        caps: ObjectCaps::from_schedule(&db.parameter_schedule(now_epoch)?, now_epoch),
        work: std::cell::Cell::new((limits.work_bytes, limits.work_objects)),
    };

    let known = db.get_publisher(host)?.is_some();
    if !known && onboard_publisher(db, client, &base, host, now)?.is_none() {
        report.noise = Some("WIST2-E04");
        return Ok(report);
    }

    let stored_raw = db
        .get_publisher_declaration(host)?
        .ok_or_else(|| crate::error::Error::Fetch("publisher row lost mid-ingest".into()))?;
    let mut current_doc: Value = crate::json::parse(&stored_raw)?;

    if known {
        let publisher_url = format!("{base}publisher.json");
        match client.get_json_in_scope(&publisher_url, &meter.scope()?) {
            Ok((raw, value)) => {
                current_doc =
                    admit_fetched_declaration(db, data_dir, host, now, &clock, raw, value)?;
            }
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

    if known && key_set_cache_expired(db, host, now)? {
        record_rejection(
            db,
            host,
            "WIST1-E02",
            now,
            None,
            "Key Set cache expired without an accepted Declaration refresh",
        )?;
        return Ok(report);
    }

    match declaration::publisher_of(&current_doc) {
        Ok(_) => {}
        Err(e) => {
            record_rejection(db, host, "WIST2-E04", now, None, &e)?;
            report.noise = Some("WIST2-E04");
            return Ok(report);
        }
    };

    let mut page_key_sets = None;
    let mut feed_refresh_attempted = false;
    let mut pages: Vec<FeedEnvelope> = Vec::new();
    let mut page_url = format!("{base}feed.json");
    let mut unseen_any = false;
    let mut suspended = false;
    loop {
        let fetched = match meter.get(client, &page_url, Object::Page) {
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
        let feed_parsed = match feed::validate_fields(&feed_value) {
            Ok(feed) => feed,
            Err(detail) => {
                record_rejection(db, host, "WIST2-E01", now, None, detail)?;
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
        settle_before_admission(db, data_dir, host, &clock)?;
        let live_page = pages.is_empty();
        let mut verified = if live_page {
            verify_live_feed(db, host, &feed_value)?
        } else {
            if page_key_sets.is_none() {
                page_key_sets = Some(page_declarations(db, data_dir, host)?);
            }
            let generated_at = feed_value["feed"]["generated_at"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            verify_sealed_page(page_key_sets.as_ref().unwrap(), &feed_value, &generated_at)
        };
        if !verified && !feed_refresh_attempted {
            feed_refresh_attempted = true;
            if let Ok((raw, value)) =
                client.get_json_in_scope(&format!("{base}publisher.json"), &meter.scope()?)
            {
                admit_fetched_declaration(db, data_dir, host, now, &clock, raw, value)?;
            }
            settle_before_admission(db, data_dir, host, &clock)?;
            verified = if live_page {
                verify_live_feed(db, host, &feed_value)?
            } else {
                verify_sealed_page(
                    page_key_sets.as_ref().unwrap(),
                    &feed_value,
                    feed_value["feed"]["generated_at"]
                        .as_str()
                        .unwrap_or_default(),
                )
            };
        }
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
        if live_page && !db.observe_feed_generated_at(host, &feed_parsed.feed.generated_at)? {
            record_rejection(
                db,
                host,
                "WIST2-E05",
                now,
                None,
                "live Feed generated_at precedes the retained authenticated observation",
            )?;
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
                        "feed next fails the target rule: not its Normalized URL under the requested host's well-known prefix",
                    )?;
                    break;
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
    let mut attempt_profiles =
        std::collections::HashMap::<String, declaration::delta::AdmissionProfile>::new();
    let mut resolved_prev: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut refreshed_deltas = std::collections::HashSet::new();
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
            None => match meter.get(client, &delta_url, Object::Delta) {
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
        let attempt = match attempt_profiles.remove(id) {
            Some(profile) => profile,
            None => declaration::delta::AdmissionProfile::start(db, data_dir, clock())?,
        };
        let size_caps = &attempt.sizes;
        let association = match declaration::delta_publisher(&delta_value) {
            Err(code) => Err(code),
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
        let (_, authority) = verify_delta_with_refresh(
            db,
            client,
            data_dir,
            host,
            now,
            &clock,
            &meter.scope()?,
            &base,
            id,
            &delta_value,
            &mut refreshed_deltas,
        )?;
        if let Err(code) = authority {
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
        if let Err(code) = size_caps.validate_delta(&delta_value) {
            record_rejection(
                db,
                host,
                code,
                now,
                Some(id),
                "Delta static validation failed",
            )?;
            report.rejected.push((id.clone(), code.into()));
            continue;
        }
        if let Err(code) =
            declaration::verify_delta_clock(&delta_value, attempt.clock, attempt.clock_skew_seconds)
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
        let delta_env: DeltaEnvelope =
            match serde_json::from_slice(&wist_core::jcs::canonicalize(&delta_value)?) {
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
            if resolved_prev.insert(id.clone()) {
                if let Some(prev) = delta_env.delta.prev.as_deref() {
                    if !db.is_delta_seen_for(prev, host)? {
                        let prev_url = format!("{base}deltas/{}.json", &prev[7..]);
                        match meter.get(client, &prev_url, Object::Delta) {
                            Ok(Some((_, predecessor))) => {
                                let at = position - 1;
                                attempt_profiles.insert(id.clone(), attempt);
                                prefetched.insert(id.clone(), delta_value);
                                prefetched.insert(prev.into(), predecessor);
                                delta_ids.insert(at, prev.into());
                                position = at;
                                continue;
                            }
                            Ok(None) => {
                                suspended = true;
                                break 'process;
                            }
                            Err(_) => {}
                        }
                    }
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
            let (payload_raw, payload_value) =
                match meter.get(client, &payload_url, Object::Payload) {
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
            if let Err(code) = crate::payload::validate(
                &payload_value,
                commitment,
                &delta_env.delta.publisher,
                size_caps,
            ) {
                record_rejection(db, host, "WIST2-E03", now, Some(id), code)?;
                report.rejected.push((id.clone(), "WIST2-E03".into()));
                continue;
            }
            Some(payload_raw)
        } else {
            None
        };

        let (_, authority) = verify_delta_with_refresh(
            db,
            client,
            data_dir,
            host,
            now,
            &clock,
            &meter.scope()?,
            &base,
            id,
            &delta_value,
            &mut refreshed_deltas,
        )?;
        if let Err(code) = authority {
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
        let admission = db.mutation()?;
        let (window_open, sources) = delta_admission_sources(db, host)?;
        let authority =
            declaration::verify_delta_authority(&sources.iter().collect::<Vec<_>>(), &delta_value);
        if authority.is_err() || delta_env.delta.prev != db.url_tip(host, &delta_env.delta.url)? {
            drop(admission);
            resolved_prev.remove(id);
            attempt_profiles.insert(id.clone(), attempt);
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
        admission.commit()?;
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
    fn next_targets_follow_the_feed_next_vectors() {
        let root = std::env::var_os("WIST_SPEC_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
            });
        let vector: Value = serde_json::from_slice(
            &std::fs::read(root.join("vectors/wist2/feed-next.json")).unwrap(),
        )
        .unwrap();
        let host = vector["host"].as_str().unwrap();
        let mut read = 0;
        for case in vector["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let parsed = feed::validate_fields(&case["envelope"]);
            assert_eq!(parsed.is_ok(), case["expected"] != "fields", "{name}");
            let Some(next) = parsed.ok().and_then(|envelope| envelope.feed.next) else {
                continue;
            };
            if !case["next_read"].as_bool().unwrap() {
                continue;
            }
            read += 1;
            let followed = next_page_url(&next, host, false);
            assert_eq!(followed.is_some(), case["expected"] == "followed", "{name}");
            assert_eq!(followed.as_deref(), case["fetch"].as_str(), "{name}");
            assert_eq!(
                next_page_url(&next, host, true).is_some(),
                followed.is_some(),
                "{name}"
            );
        }
        assert!(read >= 20);
    }

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
    fn signed_page_bindings_preserve_named_source_authority() {
        let root = std::env::var_os("WIST_SPEC_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
            });
        let vector: Value = serde_json::from_slice(
            &std::fs::read(root.join("vectors/wist2/page-bindings.json")).unwrap(),
        )
        .unwrap();
        let mut histories = std::collections::BTreeMap::new();
        for (name, sources) in vector["histories"].as_object().unwrap() {
            let mut previous = None;
            let mut declarations = Vec::new();
            for source in sources.as_array().unwrap() {
                let doc = &source["envelope"];
                if let Some(previous) = previous {
                    declaration::evaluate(previous, doc).unwrap();
                } else {
                    declaration::evaluate_initial(doc).unwrap();
                }
                previous = Some(doc);
                let publisher = declaration::publisher_of(doc).unwrap();
                let at = source["sealed_at"]
                    .as_str()
                    .unwrap()
                    .parse::<jiff::Timestamp>()
                    .unwrap()
                    .as_second();
                declarations.push((at, publisher.seq, publisher.keys));
            }
            histories.insert(name.as_str(), declarations);
        }
        for probe in vector["probes"].as_array().unwrap() {
            let mut declarations = histories[probe["history"].as_str().unwrap()].clone();
            let doc = &probe["envelope"];
            let cut = doc["feed"]["generated_at"].as_str().unwrap();
            for _ in 0..2 {
                assert_eq!(
                    verify_sealed_page(&declarations, doc, cut),
                    probe["expected"] != "WIST2-E04",
                    "{}",
                    probe["name"]
                );
                declarations.reverse();
            }
            let mut damaged = doc.clone();
            damaged["feed"]["domain"] = "tampered.example".into();
            assert!(!verify_sealed_page(&declarations, &damaged, cut));
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
