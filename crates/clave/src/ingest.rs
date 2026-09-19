use crate::db::Db;
use crate::error::Result;
use crate::fetch::Client;
use crate::history::declarations::DeclarationsReplay;
use serde_json::Value;
use std::path::Path;
use wist_core::objects::{FeedEnvelope, Publisher, PublisherEnvelope, PublisherKey};

use crate::declaration;
use crate::registry;

mod admit;
mod feed;
mod fetch_stage;
mod verify;

use admit::{Admission, Step};
use fetch_stage::{FetchRequest, Outcome, Walk};

#[derive(Debug, Default)]
pub struct IngestReport {
    pub accepted: Vec<String>,
    pub queued: Vec<String>,
    pub rejected: Vec<(String, String)>,
    /// Label and Dispute IDs accepted for sealing from the Label Feed.
    pub labels: Vec<String>,
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

fn page_declarations(
    db: &Db,
    data_dir: &Path,
    host: &str,
) -> Result<Vec<(i64, u64, Vec<PublisherKey>)>> {
    let mut history = crate::history::History::open(db, data_dir, db.last_epoch()?)?;
    let mut state = crate::history::declarations::Declarations::default();
    let mut sources = Vec::new();
    let mut superseded = std::collections::BTreeSet::new();
    // WIST-2 §3.2 resolves a Page against the Key Set WIST-1 §5.2 resolves
    // at the sealing Epoch, which excludes a Declaration that is pending,
    // that a reversal discarded, or that a recovery superseded. A pending
    // head enters at the instant it activates, not the instant it sealed.
    let mut pending = std::collections::BTreeSet::new();
    let mut excluded = std::collections::BTreeSet::new();
    while let Some(epoch) = history.next_epoch()? {
        let effects = state.apply(&epoch)?;
        for settlement in &effects.settlements {
            if settlement.domain == host {
                for source in &settlement.superseded {
                    superseded.insert(source.hash().to_string());
                }
            }
        }
        for installation in &effects.installations {
            if installation.declaration.envelope()["publisher"]["domain"] != host {
                continue;
            }
            if installation.pending {
                pending.insert(installation.declaration.hash().to_string());
            }
            if installation.reversed.is_some() {
                excluded.append(&mut pending);
            }
        }
        for activation in effects
            .activations
            .iter()
            .filter(|activation| activation.domain == host)
        {
            pending.remove(activation.activated.hash());
            let publisher = declaration::publisher_of(activation.activated.envelope())
                .map_err(crate::error::Error::History)?;
            sources.push((
                activation.activated.hash().to_string(),
                (epoch.sealed_at_s(), publisher.seq, publisher.keys),
            ));
        }
        for entry in epoch.entries().iter().filter(|entry| {
            entry["type"] == "publisher_declaration" && entry["body"]["publisher"]["domain"] == host
        }) {
            let source = &entry["body"];
            let hash = declaration::inner_hash(source).map_err(crate::error::Error::History)?;
            if pending.contains(&hash) || excluded.contains(&hash) {
                continue;
            }
            let publisher =
                declaration::publisher_of(source).map_err(crate::error::Error::History)?;
            sources.push((hash, (epoch.sealed_at_s(), publisher.seq, publisher.keys)));
        }
    }
    Ok(sources
        .into_iter()
        .filter_map(|(hash, source)| {
            (!superseded.contains(&hash) && !excluded.contains(&hash)).then_some(source)
        })
        .collect())
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

/// The keys of the Declaration the domain holds, which a live Feed or
/// Label Feed verifies under.
fn live_page_keys(db: &Db, host: &str) -> Result<Vec<PublisherKey>> {
    let raw = db
        .get_publisher_declaration(host)?
        .ok_or_else(|| crate::error::Error::History("missing Feed admission Declaration".into()))?;
    let doc = crate::json::parse(&raw)?;
    Ok(declaration::publisher_of(&doc)
        .map_err(crate::error::Error::History)?
        .keys)
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
/// The kinds of object a pull fetches, each under its own WIST-2 §8 bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    Page,
    Delta,
    Payload,
    /// A Label or Dispute Envelope, bounded as a Delta file is.
    Label,
}

/// Per-object bounds: Feed pages by the shared object cap, a Delta file
/// by its URL cap and fixed fields, a Payload by the content caps in
/// force plus its salt and framing.
pub struct ObjectCaps {
    delta: u64,
    payload: u64,
}

impl ObjectCaps {
    pub fn from_schedule(schedule: &wist_core::parameters::Schedule, at: i64) -> Self {
        let caps = crate::declaration::delta::SizeCaps::from_schedule(schedule, at);
        ObjectCaps {
            delta: 16_384 + 2 * caps.url_cap_bytes as u64,
            payload: crate::payload::cap_bytes(&caps),
        }
    }

    pub fn of(&self, object: Object) -> u64 {
        match object {
            Object::Page => crate::fetch::OBJECT_CAP_BYTES,
            Object::Delta | Object::Label => self.delta,
            Object::Payload => self.payload,
        }
    }
}

/// The daily budget of the Registrable Domain a pull is metered on
/// (WIST-2 §5) and the work the pull has left.
struct Meter {
    unit: String,
    day: String,
    budget: i64,
    caps: ObjectCaps,
    work_bytes: u64,
    work_objects: u32,
}

/// A metered fetch's result as the coordinator applies it.
enum Got {
    Body(Vec<u8>, Value),
    /// The budget or the pull's work is spent, or the object would cross
    /// it: the walk suspends.
    Suspend,
    Failed(String),
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

/// Pulls `host` once (WIST-2 §5): stage 2 fetches, stage 3 verifies and
/// stage 4 admits one object at a time, in the order the pull's
/// diagnostics and budget require.
pub fn run_bounded(
    db: &Db,
    client: &Client,
    data_dir: &Path,
    host: &str,
    now: &str,
    clock: impl Fn() -> jiff::Timestamp,
    limits: PullLimits,
) -> Result<IngestReport> {
    let Some(host) = canonical_authority(host) else {
        return Ok(IngestReport::default());
    };
    let host = host.as_str();
    crate::recovery::settle(db, data_dir, now)?;
    let scheme = crate::fetch::scheme_for_host(host, client.allow_http());
    let now_unix = registry::unix(now)?;
    let meter = Meter {
        day: now.get(..10).unwrap_or(now).to_string(),
        budget: registry::effective(db, "ingest_budget_bytes_day", now)?,
        unit: crate::suffix_list::unit_at(db, host, now)?,
        caps: ObjectCaps::from_schedule(&db.parameter_schedule(now_unix)?, now_unix),
        work_bytes: limits.work_bytes,
        work_objects: limits.work_objects,
    };
    let mut pull = Pull {
        db,
        client,
        data_dir,
        host,
        base: format!("{scheme}://{host}/.well-known/wist/"),
        now,
        now_unix,
        clock,
        meter,
        report: IngestReport::default(),
    };
    pull.run()?;
    Ok(pull.report)
}

/// The walk of a domain's Feed as far as one pull took it.
struct FeedWalk {
    pages: Vec<FeedEnvelope>,
    unseen_any: bool,
    suspended: bool,
}

/// The coordinator of one pull: it reads the store, issues each fetch,
/// hands the result to verification and the verified object to
/// admission.
struct Pull<'a, C: Fn() -> jiff::Timestamp> {
    db: &'a Db,
    client: &'a Client,
    data_dir: &'a Path,
    host: &'a str,
    base: String,
    now: &'a str,
    now_unix: i64,
    clock: C,
    meter: Meter,
    report: IngestReport,
}

impl<C: Fn() -> jiff::Timestamp> Pull<'_, C> {
    /// WIST-2 §8: the hosts a redirect may reach are those the Publisher's
    /// Declaration lists at the moment the request is issued, so a
    /// replacement admitted earlier in the pull governs the requests after
    /// it; before the first accepted Declaration a redirect stays on the
    /// requested host.
    fn scope(&self) -> Result<Vec<String>> {
        Ok(self
            .db
            .get_publisher_declaration(self.host)?
            .and_then(|raw| crate::json::parse(&raw).ok())
            .and_then(|doc| declaration::publisher_of(&doc).ok())
            .and_then(|p| p.subdomain_scope)
            .unwrap_or_default())
    }

    /// Fetches one content object under the remaining daily budget, the
    /// pull's work limits and the object's own cap, and debits what it
    /// read. The walk suspends when the budget or the work is spent, or
    /// the object would cross the budget, in which case the bytes read up
    /// to the bound are debited. An object above its own cap is a failed
    /// fetch.
    fn get(&mut self, url: &str, object: Object) -> Result<Got> {
        let spent = self.db.ingest_bytes(&self.meter.unit, &self.meter.day)?;
        let (work_bytes, work_objects) = (self.meter.work_bytes, self.meter.work_objects);
        if spent >= self.meter.budget || work_bytes == 0 || work_objects == 0 {
            return Ok(Got::Suspend);
        }
        let cap = self.meter.caps.of(object);
        let limit = cap.min((self.meter.budget - spent) as u64).min(work_bytes);
        let request = FetchRequest {
            url: url.to_string(),
            scope: self.scope()?,
            limit,
            cap,
            metered: true,
        };
        let outcome = fetch_stage::fetch(self.client, &request);
        let debited = outcome.debited();
        Ok(match outcome {
            Outcome::Body { raw, value } => {
                admit::debit(self.db, &self.meter.unit, &self.meter.day, debited)?;
                self.meter.work_bytes = work_bytes - debited;
                self.meter.work_objects = work_objects - 1;
                Got::Body(raw, value)
            }
            Outcome::Bounded { .. } => {
                admit::debit(self.db, &self.meter.unit, &self.meter.day, debited)?;
                self.meter.work_bytes = work_bytes - debited;
                Got::Suspend
            }
            Outcome::Failed { detail } => Got::Failed(detail),
        })
    }

    /// Requests `publisher.json` outside the budget under the redirect
    /// scope `scope`.
    fn get_declaration(&self, scope: Vec<String>) -> std::result::Result<(Vec<u8>, Value), String> {
        let request = FetchRequest {
            url: format!("{}publisher.json", self.base),
            scope,
            limit: crate::fetch::OBJECT_CAP_BYTES,
            cap: crate::fetch::OBJECT_CAP_BYTES,
            metered: false,
        };
        match fetch_stage::fetch(self.client, &request) {
            Outcome::Body { raw, value } => Ok((raw, value)),
            Outcome::Failed { detail } => Err(detail),
            Outcome::Bounded { .. } => Err("unmetered request stopped at a bound".into()),
        }
    }

    fn reject(&self, code: &str, detail: &str) -> Result<()> {
        admit::reject(self.db, self.host, code, self.now, None, detail)
    }

    /// Rejects one listed Delta, Label or dispute and reports it.
    fn reject_item(&mut self, id: &str, code: &str, detail: &str) -> Result<()> {
        admit::reject(self.db, self.host, code, self.now, Some(id), detail)?;
        self.report
            .rejected
            .push((id.to_string(), code.to_string()));
        Ok(())
    }

    fn settle(&self) -> Result<()> {
        admit::settle_if_due(self.db, self.data_dir, self.host, &self.clock)
    }

    fn admit_declaration(&self, raw: &[u8], value: Value) -> Result<Value> {
        admit::admit_declaration(
            self.db,
            self.data_dir,
            self.host,
            self.now,
            &self.clock,
            raw,
            value,
        )
    }

    fn run(&mut self) -> Result<()> {
        let (db, host, now) = (self.db, self.host, self.now);
        let known = db.get_publisher(host)?.is_some();
        if !known {
            let first = self
                .get_declaration(self.scope()?)
                .and_then(|(raw, value)| {
                    let publisher = verify::initial_declaration(&value, host)?;
                    Ok((raw, value, publisher))
                });
            match first {
                Ok((raw, value, publisher)) => {
                    admit::onboard(db, host, now, &raw, &value, &publisher)?
                }
                Err(detail) => {
                    self.reject("WIST2-E04", &detail)?;
                    self.report.noise = Some("WIST2-E04");
                    return Ok(());
                }
            }
        }

        let stored_raw = db
            .get_publisher_declaration(host)?
            .ok_or_else(|| crate::error::Error::Fetch("publisher row lost mid-ingest".into()))?;
        let mut current_doc: Value = crate::json::parse(&stored_raw)?;
        if known {
            match self.get_declaration(self.scope()?) {
                Ok((raw, value)) => current_doc = self.admit_declaration(&raw, value)?,
                Err(e) => {
                    if key_set_cache_expired(db, host, now)? {
                        self.reject(
                            "WIST1-E02",
                            &format!("Key Set cache expired and rediscovery failed: {e}"),
                        )?;
                        return Ok(());
                    }
                }
            }
        }
        if known && key_set_cache_expired(db, host, now)? {
            self.reject(
                "WIST1-E02",
                "Key Set cache expired without an accepted Declaration refresh",
            )?;
            return Ok(());
        }
        if let Err(e) = declaration::publisher_of(&current_doc) {
            self.reject("WIST2-E04", &e)?;
            self.report.noise = Some("WIST2-E04");
            return Ok(());
        }

        let Some(walk) = self.walk_feed()? else {
            return Ok(());
        };
        let mut suspended = walk.suspended;
        if !suspended {
            suspended = self.process_deltas(&walk.pages)?;
        }
        if !suspended {
            let sizes = declaration::delta::SizeCaps::from_schedule(
                &db.parameter_schedule(self.now_unix)?,
                self.now_unix,
            );
            suspended = self.pull_labels(sizes.url_cap_bytes)?;
        }
        self.report.suspended = suspended;
        if !suspended
            && !walk.unseen_any
            && self.report.accepted.is_empty()
            && self.report.queued.is_empty()
            && self.report.rejected.is_empty()
            && self.report.labels.is_empty()
        {
            self.report.noise = Some("WIST2-E02");
        }
        admit::close_run(db, host, now, suspended)
    }

    /// Walks the Feed from `feed.json` through its sealed Pages (WIST-2
    /// §3.2, §5 step 1) until a page lists no unseen ID, `next` ends or
    /// fails the target rule, or the walk suspends. `None` ends the pull.
    fn walk_feed(&mut self) -> Result<Option<FeedWalk>> {
        let (db, host) = (self.db, self.host);
        let mut page_key_sets = None;
        let mut refresh_used = false;
        let mut pages: Vec<FeedEnvelope> = Vec::new();
        let mut page_url = format!("{}feed.json", self.base);
        let mut unseen_any = false;
        loop {
            let value = match self.get(&page_url, Object::Page)? {
                Got::Body(_, value) => value,
                Got::Suspend => {
                    return Ok(Some(FeedWalk {
                        pages,
                        unseen_any,
                        suspended: true,
                    }))
                }
                Got::Failed(detail) => {
                    self.reject("WIST2-E01", &detail)?;
                    return Ok(None);
                }
            };
            let checks = verify::page(&value, host);
            let parsed = match checks.fields {
                Ok(parsed) => parsed,
                Err(detail) => {
                    self.reject("WIST2-E01", detail)?;
                    return Ok(None);
                }
            };
            if !checks.domain_matches {
                self.reject(
                    "WIST2-E04",
                    "feed domain does not match the host it was fetched from",
                )?;
                self.report.noise = Some("WIST2-E04");
                return Ok(None);
            }
            self.settle()?;
            let live = pages.is_empty();
            let generated_at = parsed.feed.generated_at.as_str();
            if !live && page_key_sets.is_none() {
                page_key_sets = Some(page_declarations(db, self.data_dir, host)?);
            }
            let verify = |pull: &Self| -> Result<bool> {
                Ok(match &page_key_sets {
                    Some(sources) if !live => verify::sealed_page(sources, &value, generated_at),
                    _ => verify::live_page(&live_page_keys(pull.db, host)?, &value),
                })
            };
            let mut verified = verify(self)?;
            if !verified && !refresh_used {
                refresh_used = true;
                if let Ok((raw, fetched)) = self.get_declaration(self.scope()?) {
                    self.admit_declaration(&raw, fetched)?;
                }
                self.settle()?;
                verified = verify(self)?;
            }
            if !verified {
                self.reject(
                    "WIST2-E04",
                    "feed signature does not verify against the domain's Key Set",
                )?;
                self.report.noise = Some("WIST2-E04");
                return Ok(None);
            }
            let next = parsed
                .feed
                .next
                .as_deref()
                .map(|next| verify::next_page_url(next, host, self.client.allow_http()));
            let admission = admit::admit_page(db, host, self.now, Walk::Feed, live, &parsed, next)?;
            if let Step::Refused = admission.step {
                return Ok(None);
            }
            unseen_any |= admission.unseen;
            pages.push(parsed);
            match admission.step {
                Step::Continue(url) => page_url = url,
                _ => break,
            }
        }
        Ok(Some(FeedWalk {
            pages,
            unseen_any,
            suspended: false,
        }))
    }

    /// WIST-2 §5 steps 2–4 over the walked pages' Delta IDs, oldest page
    /// first. Returns whether the walk suspended.
    fn process_deltas(&mut self, pages: &[FeedEnvelope]) -> Result<bool> {
        use std::collections::{HashMap, HashSet};
        let (db, host, data_dir) = (self.db, self.host, self.data_dir);
        let mut ids: Vec<String> = pages
            .iter()
            .rev()
            .flat_map(|page| page.feed.deltas.iter().cloned())
            .collect();
        let mut chain_pos: i64 = 0;
        let mut prefetched: HashMap<String, Value> = HashMap::new();
        let mut profiles = HashMap::<String, declaration::delta::AdmissionProfile>::new();
        let mut resolved_prev: HashSet<String> = HashSet::new();
        let mut refreshed = HashSet::new();
        let mut position = 0usize;
        while position < ids.len() {
            let id = ids[position].clone();
            position += 1;
            self.settle()?;
            if db.is_delta_seen_for(&id, host)? {
                continue;
            }
            let Some(hex) = id.strip_prefix("sha256:") else {
                self.reject_item(&id, "WIST2-E03", "malformed delta id")?;
                continue;
            };
            let doc = match prefetched.remove(&id) {
                Some(doc) => doc,
                None => {
                    let url = format!("{}deltas/{hex}.json", self.base);
                    match self.get(&url, Object::Delta)? {
                        Got::Body(_, doc) => doc,
                        Got::Suspend => return Ok(true),
                        Got::Failed(detail) => {
                            self.reject_item(&id, "WIST2-E03", &detail)?;
                            continue;
                        }
                    }
                }
            };
            let attempt = match profiles.remove(&id) {
                Some(profile) => profile,
                None => declaration::delta::AdmissionProfile::start(db, data_dir, (self.clock)())?,
            };
            let checks = verify::delta(
                &doc,
                host,
                &id,
                &attempt.sizes,
                attempt.clock,
                attempt.clock_skew_seconds,
            );
            if let Err(code) = checks.association {
                self.reject_item(&id, code, "Delta Publisher does not match the logical Feed")?;
                continue;
            }
            if let Err(code) = self.authority(&id, &doc, &mut refreshed)? {
                self.reject_item(&id, code, "Delta signing and scope authority failed")?;
                continue;
            }
            if let Err(code) = checks.static_fields {
                self.reject_item(&id, code, "Delta static validation failed")?;
                continue;
            }
            if let Err(code) = checks.clock {
                self.reject_item(
                    &id,
                    code,
                    "observed_at exceeds the clock_skew_seconds allowance",
                )?;
                continue;
            }
            let envelope = match checks.decoded {
                Ok(verified) => verified.envelope,
                Err(verify::Undecoded::Canonical(e)) => return Err(e.into()),
                Err(verify::Undecoded::Envelope(detail)) => {
                    self.reject_item(&id, "WIST2-E03", &detail)?;
                    continue;
                }
            };
            if let Err(detail) = checks.id {
                self.reject_item(&id, "WIST2-E03", &detail)?;
                continue;
            }

            if envelope.delta.prev != db.url_tip(host, &envelope.delta.url)? {
                if resolved_prev.insert(id.clone()) {
                    if let Some(prev) = envelope.delta.prev.as_deref() {
                        if !db.is_delta_seen_for(prev, host)? {
                            let url = format!("{}deltas/{}.json", self.base, &prev[7..]);
                            match self.get(&url, Object::Delta)? {
                                Got::Body(_, predecessor) => {
                                    let at = position - 1;
                                    profiles.insert(id.clone(), attempt);
                                    prefetched.insert(id.clone(), doc);
                                    prefetched.insert(prev.into(), predecessor);
                                    ids.insert(at, prev.into());
                                    position = at;
                                    continue;
                                }
                                Got::Suspend => return Ok(true),
                                Got::Failed(_) => {}
                            }
                        }
                    }
                }
                self.reject_item(
                    &id,
                    "WIST1-E07",
                    "prev does not match the chain tip and could not be retrieved",
                )?;
                continue;
            }

            if let Some(prev) = &envelope.delta.prev {
                let predecessor = db.accepted_delta(data_dir, host, prev)?;
                if let Err(code) = declaration::verify_delta_predecessor(&doc, &predecessor) {
                    self.reject_item(
                        &id,
                        code,
                        "Delta does not strictly follow its predecessor observation",
                    )?;
                    continue;
                }
            }

            let payload_raw = if envelope.delta.payload.is_some() {
                let url = format!("{}payloads/{hex}.json", self.base);
                let (raw, value) = match self.get(&url, Object::Payload)? {
                    Got::Body(raw, value) => (raw, value),
                    Got::Suspend => return Ok(true),
                    Got::Failed(detail) => {
                        self.reject_item(&id, "WIST2-E03", &detail)?;
                        continue;
                    }
                };
                if let Err(code) = verify::payload(&value, &envelope, &attempt.sizes) {
                    self.reject_item(&id, "WIST2-E03", code)?;
                    continue;
                }
                Some(raw)
            } else {
                None
            };

            if let Err(code) = self.authority(&id, &doc, &mut refreshed)? {
                self.reject_item(&id, code, "Delta authority changed before admission")?;
                continue;
            }
            match admit::admit_delta(
                db,
                data_dir,
                host,
                &id,
                &doc,
                &envelope,
                payload_raw.as_deref(),
                chain_pos,
            )? {
                Admission::Stale => {
                    resolved_prev.remove(&id);
                    profiles.insert(id.clone(), attempt);
                    prefetched.insert(id.clone(), doc);
                    position -= 1;
                    continue;
                }
                Admission::Queued => self.report.queued.push(id.clone()),
                Admission::Accepted => self.report.accepted.push(id.clone()),
            }
            chain_pos += 1;
        }
        Ok(false)
    }

    /// WIST-1 §5.1 authority of a Delta under the admission sources after
    /// any settlement due, with the one Declaration retry WIST-2 §5 allows
    /// each Delta ID per pull on a binding failure.
    fn authority(
        &self,
        id: &str,
        doc: &Value,
        refreshed: &mut std::collections::HashSet<String>,
    ) -> Result<std::result::Result<(), &'static str>> {
        let scope = self.scope()?;
        self.settle()?;
        let (_, sources) = delta_admission_sources(self.db, self.host)?;
        let mut authority = verify::delta_authority(&sources, doc);
        if matches!(authority, Err("WIST1-E01" | "WIST1-E02")) && refreshed.insert(id.into()) {
            if let Ok((raw, value)) = self.get_declaration(scope) {
                self.admit_declaration(&raw, value)?;
            }
            self.settle()?;
            let (_, sources) = delta_admission_sources(self.db, self.host)?;
            authority = verify::delta_authority(&sources, doc);
        }
        Ok(authority)
    }

    /// WIST-2 §3.3: pulls the domain's Label Feed beside its Feed, walking
    /// it under §3.2's rules and the ingest budget, validates each unseen
    /// Label or dispute under the accepted Declaration and queues it as a
    /// `label` or `dispute` Entry; a failure is `WIST2-E06` at the status
    /// endpoint. Returns whether the walk suspended under the budget: a
    /// Label walk that cannot begin under a spent budget waits for the
    /// next pull without suspending the Feed walk that completed before
    /// it.
    fn pull_labels(&mut self, url_cap_bytes: i64) -> Result<bool> {
        let (db, host) = (self.db, self.host);
        let Some(raw) = db.get_publisher_declaration(host)? else {
            return Ok(false);
        };
        let declaration_doc = crate::json::parse(&raw)?;
        let declaration = PublisherEnvelope {
            publisher: declaration::publisher_of(&declaration_doc)
                .map_err(crate::error::Error::History)?,
            sig: serde_json::from_value(declaration_doc["sig"].clone())?,
        };
        let mut page_url = format!("{}label-feed.json", self.base);
        let mut pages: Vec<Vec<String>> = Vec::new();
        let mut page_key_sets = None;
        loop {
            let live = pages.is_empty();
            let value = match self.get(&page_url, Object::Page)? {
                Got::Body(_, value) => value,
                Got::Suspend => return Ok(!live),
                Got::Failed(detail) => {
                    if !live {
                        self.reject("WIST2-E01", &detail)?;
                    }
                    break;
                }
            };
            let checks = verify::page(&value, host);
            let parsed = match checks.fields {
                Ok(parsed) => parsed,
                Err(detail) => {
                    self.reject("WIST2-E06", detail)?;
                    break;
                }
            };
            if !checks.domain_matches {
                self.reject(
                    "WIST2-E06",
                    "label feed domain does not match the host it was fetched from",
                )?;
                break;
            }
            let verified = if live {
                verify::live_page(&live_page_keys(db, host)?, &value)
            } else {
                if page_key_sets.is_none() {
                    page_key_sets = Some(page_declarations(db, self.data_dir, host)?);
                }
                verify::sealed_page(
                    page_key_sets.as_ref().unwrap(),
                    &value,
                    &parsed.feed.generated_at,
                )
            };
            if !verified {
                self.reject(
                    "WIST2-E06",
                    "label feed signature does not verify against the domain's Key Set",
                )?;
                break;
            }
            let next = parsed
                .feed
                .next
                .as_deref()
                .map(|next| verify::next_page_url(next, host, self.client.allow_http()));
            let admission =
                admit::admit_page(db, host, self.now, Walk::Label, live, &parsed, next)?;
            if let Step::Refused = admission.step {
                break;
            }
            pages.push(parsed.feed.deltas);
            match admission.step {
                Step::Continue(url) => page_url = url,
                _ => break,
            }
        }
        let ids: Vec<String> = pages.iter().rev().flatten().cloned().collect();
        for id in ids {
            if db.is_label_seen_for(&id, host)? {
                continue;
            }
            let Some(hex) = id.strip_prefix("sha256:") else {
                self.reject_item(&id, "WIST2-E06", "malformed Label ID")?;
                continue;
            };
            let url = format!("{}labels/{hex}.json", self.base);
            let doc = match self.get(&url, Object::Label)? {
                Got::Body(_, doc) => doc,
                Got::Suspend => return Ok(true),
                Got::Failed(detail) => {
                    self.reject_item(&id, "WIST2-E06", &detail)?;
                    continue;
                }
            };
            let checks = verify::label(&doc, &id, &declaration, url_cap_bytes);
            let Some(kind) = checks.kind else {
                self.reject_item(
                    &id,
                    "WIST2-E06",
                    "file carries neither a Label nor a dispute",
                )?;
                continue;
            };
            if !checks.id_matches {
                self.reject_item(&id, "WIST2-E06", "file does not carry the listed ID")?;
                continue;
            }
            match admit::admit_label(
                db,
                host,
                self.now,
                &id,
                kind,
                &doc,
                &declaration,
                checks.label,
            )? {
                None => self.report.labels.push(id),
                Some(rejection) => self.report.rejected.push((id, rejection.code().into())),
            }
        }
        Ok(false)
    }
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
            let followed = verify::next_page_url(&next, host, false);
            assert_eq!(followed.is_some(), case["expected"] == "followed", "{name}");
            assert_eq!(followed.as_deref(), case["fetch"].as_str(), "{name}");
            assert_eq!(
                verify::next_page_url(&next, host, true).is_some(),
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
                            wist_core::objects::PublisherKey::new(
                                &wist_core::crypto::b64u_encode(
                                    &ed25519_dalek::SigningKey::from_bytes(&seeds[id])
                                        .verifying_key()
                                        .to_bytes(),
                                ),
                                4_070_908_800,
                                None,
                            )
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
                let kid = wist_core::objects::publisher::thumbprint(&key.public().to_b64u());
                let mut doc =
                    wist_core::envelope::sign_envelope(&body, "feed", &kid, &key).unwrap();
                for _ in 0..2 {
                    assert_eq!(
                        verify::sealed_page(&declarations, &doc, &cut),
                        expected["verifies"].as_bool().unwrap(),
                        "{}: {}",
                        case["name"],
                        page["page"]
                    );
                    declarations.reverse();
                }
                doc["feed"]["domain"] = "tampered.example".into();
                assert!(!verify::sealed_page(&declarations, &doc, &cut));
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
                    verify::sealed_page(&declarations, doc, cut),
                    probe["expected"] != "WIST2-E04",
                    "{}",
                    probe["name"]
                );
                declarations.reverse();
            }
            let mut damaged = doc.clone();
            damaged["feed"]["domain"] = "tampered.example".into();
            assert!(!verify::sealed_page(&declarations, &damaged, cut));
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
