use crate::db::{Db, NewRun, Phase, PullObject, PullRun, Settled, Status, WalkPage};
use crate::error::Result;
use crate::fetch::Client;
use crate::history::declarations::DeclarationsReplay;
use serde_json::Value;
use std::path::Path;
use wist_core::objects::{PublisherEnvelope, PublisherKey};

use crate::declaration;
use crate::registry;

mod admit;
mod feed;
mod fetch_stage;
#[cfg(test)]
mod stage_tests;
mod verify;

use fetch_stage::{Attempt, FetchRequest, ObjectKey, Outcome, Walk};

#[derive(Debug, Default)]
pub struct IngestReport {
    pub accepted: Vec<String>,
    pub queued: Vec<String>,
    pub rejected: Vec<(String, String)>,
    /// Label and Dispute IDs accepted for sealing from the Label Feed.
    pub labels: Vec<String>,
    pub noise: Option<&'static str>,
    /// The rejection code the pull, or its Feed walk alone, ended at.
    pub ended: Option<String>,
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

/// The Declarations WIST-2 §3.2 resolves a sealed Page's Key Set
/// through, as the Log stands at the height `at`, which a run pins so
/// that resuming it reads the same sources.
fn page_declarations(
    db: &Db,
    data_dir: &Path,
    host: &str,
    at: Option<u64>,
) -> Result<Vec<(i64, u64, Vec<PublisherKey>)>> {
    let head = match at {
        Some(height) => db.epoch_at(height)?,
        None => None,
    };
    let mut history = crate::history::History::open(db, data_dir, head)?;
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    wist_core::crypto::hex_encode(&sha2::Sha256::digest(bytes))
}

/// The version of the domain's accepted Declaration and recovery window
/// with the admission sources they yield: the window's prior and owner
/// Declarations while one is open, the accepted Declaration otherwise.
fn declaration_ref(db: &Db, host: &str) -> Result<verify::DeclarationRef> {
    let window = db.get_recovery_window(host)?;
    let stored = db.get_publisher_declaration(host)?;
    let raw = match &window {
        Some(window) => vec![
            window.prior_declaration_json.clone(),
            window.owner_declaration_json.clone(),
        ],
        None => vec![stored.clone().ok_or_else(|| {
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
    let seq = stored
        .as_deref()
        .and_then(|raw| crate::json::parse(raw).ok())
        .and_then(|doc| declaration::publisher_of(&doc).ok())
        .map(|publisher| publisher.seq);
    Ok(verify::DeclarationRef {
        hash: stored.as_deref().map(sha256_hex),
        seq,
        window: window.map(|window| verify::WindowRef {
            prior: sha256_hex(&window.prior_declaration_json),
            owner: sha256_hex(&window.owner_declaration_json),
            head: sha256_hex(&window.declaration_json),
            opened_epoch: window.opened_epoch,
        }),
        sources,
    })
}

/// Issues the references of one Delta attempt at its clock sample. The
/// schedule's height is read before the schedule, so a seal that lands
/// between them makes admission recheck the caps rather than miss them.
fn issue_refs(
    db: &Db,
    data_dir: &Path,
    host: &str,
    clock: jiff::Timestamp,
) -> Result<verify::IssuedRefs> {
    let schedule_at = db.last_epoch()?.map(|epoch| epoch.epoch_number);
    let profile = declaration::delta::AdmissionProfile::start(db, data_dir, clock)?;
    Ok(verify::IssuedRefs {
        decl: declaration_ref(db, host)?,
        sizes: profile.sizes,
        clock,
        clock_skew_seconds: profile.clock_skew_seconds,
        schedule_at,
    })
}

/// The domain's accepted Declaration, which Labels and disputes validate
/// under, with its version.
fn label_declaration(
    db: &Db,
    host: &str,
) -> Result<Option<(PublisherEnvelope, verify::DeclarationRef)>> {
    let Some(raw) = db.get_publisher_declaration(host)? else {
        return Ok(None);
    };
    let doc = crate::json::parse(&raw)?;
    let declaration = PublisherEnvelope {
        publisher: declaration::publisher_of(&doc).map_err(crate::error::Error::History)?,
        sig: serde_json::from_value(doc["sig"].clone())?,
    };
    Ok(Some((declaration, declaration_ref(db, host)?)))
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
/// (WIST-2 §5) and the per-object bounds in force at it.
struct Meter {
    budget: i64,
    caps: ObjectCaps,
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

/// Pulls `host` once (WIST-2 §5) and closes the run it ran under.
pub fn run_bounded(
    db: &Db,
    client: &Client,
    data_dir: &Path,
    host: &str,
    now: &str,
    clock: impl Fn() -> jiff::Timestamp,
    limits: PullLimits,
) -> Result<IngestReport> {
    match open_pull(db, client, data_dir, host, now, clock, limits)? {
        Some(run_id) => admit::close_run(db, run_id),
        None => Ok(IngestReport::default()),
    }
}

/// Closes the run of a finished pull, schedules the domain's next pull
/// and records the pull's noise disposition, all in one transaction: a
/// takeover between a pull's end and its completion leaves the run for
/// the new holder rather than a closed run with no next pull. `run` is
/// `None` where no run was opened, which schedules nothing further.
///
/// WIST-2 §4: a noise disposition counts against the Ping quota of the
/// Registrable Domain in force at the Ping, on the UTC day of the Ping.
/// The pull therefore counts only the Ping it serves, if it serves one:
/// a baseline poll, a resumption and a retry cost the domain nothing.
pub fn finish_pull(
    db: &Db,
    task: &crate::db::PullTask,
    owner: &str,
    started_at: i64,
    run: Option<i64>,
    now: i64,
) -> Result<IngestReport> {
    let mutation = db.mutation()?;
    let report = match run {
        Some(run_id) => admit::close_run(db, run_id)?,
        None => IngestReport::default(),
    };
    if let (true, Some(pinged_at)) = (report.noise.is_some(), task.pinged_at) {
        let at = registry::instant(pinged_at)?;
        let unit = crate::suffix_list::unit_at(db, &task.domain, &at)?;
        db.bump_noise_ping(&unit, at.get(..10).unwrap_or(&at))?;
    }
    let outcome = match report.ended.as_deref() {
        Some("WIST2-E01") => crate::db::PullOutcome::FeedUnusable,
        _ => crate::db::PullOutcome::Pulled {
            suspended: report.suspended,
        },
    };
    db.complete_pull(task, owner, started_at, outcome, now)?;
    mutation.commit()?;
    Ok(report)
}

/// Pulls `host` once and leaves its run open for the caller to close
/// beside whatever else the pull's completion records. A run an
/// interrupted pull left open is dropped rather than continued (WIST-2 §5:
/// resumption is a later pull). `None` means `host` is no bare authority
/// and nothing was pulled.
pub fn open_pull(
    db: &Db,
    client: &Client,
    data_dir: &Path,
    host: &str,
    now: &str,
    clock: impl Fn() -> jiff::Timestamp,
    limits: PullLimits,
) -> Result<Option<i64>> {
    let Some(host) = canonical_authority(host) else {
        return Ok(None);
    };
    let host = host.as_str();
    let run = db.start_pull_run(&NewRun {
        domain: host,
        now,
        day: now.get(..10).unwrap_or(now),
        unit: &crate::suffix_list::unit_at(db, host, now)?,
        work_bytes: limits.work_bytes,
        work_objects: limits.work_objects,
        pages_epoch: db.last_epoch()?.map(|epoch| epoch.epoch_number),
    })?;
    let run_id = run.run_id;
    let now_unix = registry::unix(&run.now)?;
    let scheme = crate::fetch::scheme_for_host(host, client.allow_http());
    let mut pull = Pull {
        db,
        client,
        data_dir,
        host,
        base: format!("{scheme}://{host}/.well-known/wist/"),
        now_unix,
        clock,
        meter: Meter {
            budget: registry::effective(db, "ingest_budget_bytes_day", &run.now)?,
            caps: ObjectCaps::from_schedule(&db.parameter_schedule(now_unix)?, now_unix),
        },
        run,
    };
    match pull.run() {
        Ok(()) => Ok(Some(run_id)),
        Err(crate::error::Error::Fenced) => Err(crate::error::Error::Fenced),
        Err(e) => {
            db.delete_pull_run(run_id)?;
            Err(e)
        }
    }
}

/// The coordinator of one pull: it reads the store, issues each fetch,
/// hands the result to verification and the verified object to
/// admission, and persists every handoff under the run.
struct Pull<'a, C: Fn() -> jiff::Timestamp> {
    db: &'a Db,
    client: &'a Client,
    data_dir: &'a Path,
    host: &'a str,
    base: String,
    now_unix: i64,
    clock: C,
    meter: Meter,
    run: PullRun,
}

impl<C: Fn() -> jiff::Timestamp> Pull<'_, C> {
    fn now(&self) -> String {
        self.run.now.clone()
    }

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

    fn settle(&self) -> Result<()> {
        admit::settle_if_due(self.db, self.data_dir, self.host, &self.clock)
    }

    /// The run's object ID for `key`: the key's name, and for a listed
    /// item the attempt of its ID that is still open, or a further one
    /// once admission is done with the last.
    fn slot(&self, key: &ObjectKey) -> Result<String> {
        let name = key.name();
        if !key.per_attempt() {
            return Ok(name);
        }
        let attempt = match self
            .db
            .latest_pull_attempt(self.run.run_id, key.kind(), &name)?
        {
            Some((attempt, status)) if status.is_final() => attempt + 1,
            Some((attempt, _)) => attempt,
            None => 0,
        };
        Ok(format!("{name}#{attempt}"))
    }

    /// What a persisted object hands the coordinator, so a resumed pull
    /// and a repeated occurrence read the response the run already holds
    /// rather than request it again.
    fn stored(&self, object: &PullObject) -> Result<Got> {
        if let Some(raw) = &object.raw {
            let value = crate::json::parse(raw)?;
            return Ok(Got::Body(raw.to_vec(), value));
        }
        Ok(match failure_detail(object) {
            Some(detail) => Got::Failed(detail),
            None => Got::Suspend,
        })
    }

    /// Fetches one content object under the remaining daily budget, the
    /// pull's work limits and the object's own cap, reserving the bound
    /// against the budget before the request and settling it to the bytes
    /// read when the response persists. The walk suspends when the budget
    /// or the work is spent, or the object would cross the budget, in
    /// which case the bytes read up to the bound are debited. An object
    /// above its own cap is a failed fetch.
    fn get(&mut self, key: &ObjectKey, slot: &str, url: &str, object: Object) -> Result<Got> {
        let (db, kind) = (self.db, key.kind());
        let held = db.pull_object(self.run.run_id, kind, slot)?;
        let reserved = match &held {
            Some(object) if object.status == Status::Issued => object.debited,
            Some(object) => return self.stored(object),
            None => 0,
        };
        let spent = db.ingest_bytes(&self.run.unit, &self.run.day)? - reserved as i64;
        let (work_bytes, work_objects) = (self.run.work_bytes, self.run.work_objects);
        if spent >= self.meter.budget || work_bytes == 0 || work_objects == 0 {
            if held.is_some() {
                let run = self.run.clone();
                db.settle_pull_object(&run, kind, slot, Settled::Bounded(0))?;
            }
            return Ok(Got::Suspend);
        }
        let cap = self.meter.caps.of(object);
        let limit = cap.min((self.meter.budget - spent) as u64).min(work_bytes);
        db.reserve_pull_object(
            self.run.run_id,
            kind,
            slot,
            url,
            &self.run.unit,
            &self.run.day,
            limit,
        )?;
        let outcome = fetch_stage::fetch(
            self.client,
            &FetchRequest {
                url: url.to_string(),
                scope: self.scope()?,
                limit,
                cap,
                metered: true,
            },
        );
        let mut run = self.run.clone();
        let settled = match &outcome {
            Outcome::Body { raw, .. } => {
                run.work_bytes = work_bytes.saturating_sub(raw.len() as u64);
                run.work_objects = work_objects.saturating_sub(1);
                Settled::Body(raw)
            }
            Outcome::Bounded { debited } => {
                run.work_bytes = work_bytes.saturating_sub(*debited);
                Settled::Bounded(*debited)
            }
            Outcome::Failed { detail } => Settled::Failed(detail),
        };
        db.settle_pull_object(&run, kind, slot, settled)?;
        self.run = run;
        Ok(match outcome {
            Outcome::Body { raw, value } => Got::Body(raw, value),
            Outcome::Bounded { .. } => Got::Suspend,
            Outcome::Failed { detail } => Got::Failed(detail),
        })
    }

    /// Requests `publisher.json` outside the budget under the redirect
    /// scope `scope`, unless the run already holds the response.
    fn get_declaration(
        &self,
        key: &ObjectKey,
        scope: Vec<String>,
        checks: Option<&str>,
    ) -> Result<std::result::Result<(Vec<u8>, Value), String>> {
        let (kind, slot) = (key.kind(), key.name());
        if let Some(object) = self.db.pull_object(self.run.run_id, kind, &slot)? {
            return Ok(match self.stored(&object)? {
                Got::Body(raw, value) => Ok((raw, value)),
                Got::Failed(detail) => Err(detail),
                Got::Suspend => Err(String::new()),
            });
        }
        let url = format!("{}publisher.json", self.base);
        let outcome = fetch_stage::fetch(
            self.client,
            &FetchRequest {
                url: url.clone(),
                scope,
                limit: crate::fetch::OBJECT_CAP_BYTES,
                cap: crate::fetch::OBJECT_CAP_BYTES,
                metered: false,
            },
        );
        Ok(match outcome {
            Outcome::Body { raw, value } => {
                self.db.record_pull_object(
                    self.run.run_id,
                    kind,
                    &slot,
                    &url,
                    Status::Fetched,
                    Some(&raw),
                    checks,
                )?;
                Ok((raw, value))
            }
            Outcome::Bounded { .. } | Outcome::Failed { .. } => {
                let detail = match outcome {
                    Outcome::Failed { detail } => detail,
                    _ => String::new(),
                };
                let mut record = serde_json::json!({ "detail": detail });
                if let Some(checks) = checks {
                    let checks: Value = serde_json::from_str(checks)?;
                    if let (Some(record), Some(checks)) =
                        (record.as_object_mut(), checks.as_object())
                    {
                        record.extend(checks.clone());
                    }
                }
                self.db.record_pull_object(
                    self.run.run_id,
                    kind,
                    &slot,
                    &url,
                    Status::Failed,
                    None,
                    Some(&record.to_string()),
                )?;
                Err(detail)
            }
        })
    }

    /// Requests `publisher.json` for the retry `key` carries and admits
    /// what it returns, spending the retry either way.
    fn refresh(&mut self, key: &ObjectKey, scope: Vec<String>) -> Result<()> {
        match self.get_declaration(key, scope, None)? {
            Ok((raw, value)) => {
                self.admit_declaration(key, &raw, value)?;
            }
            Err(_) => admit::consume_attempt(self.db, &mut self.run, key)?,
        }
        Ok(())
    }

    fn admit_declaration(&mut self, key: &ObjectKey, raw: &[u8], value: Value) -> Result<Value> {
        let clock = &self.clock;
        admit::admit_declaration(
            self.db,
            self.data_dir,
            &mut self.run,
            self.host,
            clock,
            key,
            raw,
            value,
        )
    }

    fn abort(&mut self, key: Option<&ObjectKey>, code: &str, detail: &str) -> Result<()> {
        admit::abort(self.db, &mut self.run, self.host, key, code, detail)
    }

    /// Ends the pull's work, suspended or complete, leaving the run to be
    /// closed.
    fn finish(&mut self, suspended: bool) -> Result<()> {
        self.run.phase = Phase::Closing;
        self.run.suspended = suspended;
        self.db.update_pull_run(&self.run)
    }

    fn run(&mut self) -> Result<()> {
        crate::recovery::settle(self.db, self.data_dir, &self.now())?;
        if self.run.phase == Phase::Walk && self.discover()? {
            self.walk_feed()?;
        }
        if self.run.phase == Phase::Deltas {
            self.process_deltas()?;
        }
        if self.run.phase == Phase::Labels {
            self.walk_labels()?;
        }
        if self.run.phase == Phase::LabelItems {
            self.process_labels()?;
        }
        Ok(())
    }

    /// WIST-2 §5 step 0 and ADR-0031: the domain's first-contact or
    /// periodic `publisher.json`, then the Key Set cache's age. `false`
    /// ends the pull.
    fn discover(&mut self) -> Result<bool> {
        let (db, host) = (self.db, self.host);
        let key = ObjectKey::Declaration {
            attempt: Attempt::Periodic,
        };
        let held = db.pull_object(self.run.run_id, key.kind(), &key.name())?;
        let first_contact = match &held {
            Some(object) => checks_flag(object, "first_contact"),
            None => db.get_publisher(host)?.is_none(),
        };
        let discovered = held.is_some_and(|object| object.status == Status::Admitted);
        let checks = serde_json::json!({ "first_contact": first_contact }).to_string();
        if first_contact && !discovered {
            let first = self
                .get_declaration(&key, self.scope()?, Some(&checks))?
                .and_then(|(raw, value)| {
                    let publisher = verify::initial_declaration(&value, host)?;
                    Ok((raw, value, publisher))
                });
            match first {
                Ok((raw, value, publisher)) => {
                    admit::onboard(db, &mut self.run, host, &key, &raw, &value, &publisher)?
                }
                Err(detail) => {
                    self.abort(Some(&key), "WIST2-E04", &detail)?;
                    return Ok(false);
                }
            }
        }
        let stored_raw = db
            .get_publisher_declaration(host)?
            .ok_or_else(|| crate::error::Error::Fetch("publisher row lost mid-ingest".into()))?;
        let mut current_doc: Value = crate::json::parse(&stored_raw)?;
        if !first_contact && !discovered {
            match self.get_declaration(&key, self.scope()?, Some(&checks))? {
                Ok((raw, value)) => current_doc = self.admit_declaration(&key, &raw, value)?,
                Err(e) => {
                    if key_set_cache_expired(db, host, &self.now())? {
                        self.abort(
                            None,
                            "WIST1-E02",
                            &format!("Key Set cache expired and rediscovery failed: {e}"),
                        )?;
                        return Ok(false);
                    }
                }
            }
        }
        if !first_contact && key_set_cache_expired(db, host, &self.now())? {
            self.abort(
                None,
                "WIST1-E02",
                "Key Set cache expired without an accepted Declaration refresh",
            )?;
            return Ok(false);
        }
        if let Err(e) = declaration::publisher_of(&current_doc) {
            self.abort(None, "WIST2-E04", &e)?;
            return Ok(false);
        }
        Ok(true)
    }

    /// The pages of `walk` an earlier pull left in the domain's cursor,
    /// by URL. The live page at `live_url` is never among them: it is
    /// always re-fetched, since the Publisher rewrites it, while a sealed
    /// Page is immutable and the walk resumes over the ones it holds
    /// (WIST-2 §5's resumption from where the walk stopped), each checked
    /// again since §3.2's sources may have changed since it was walked.
    fn cursor(
        &self,
        walk: Walk,
        live_url: &str,
    ) -> Result<std::collections::HashMap<String, WalkPage>> {
        Ok(self
            .db
            .walk_pages(self.host, walk.as_str())?
            .into_iter()
            .filter(|page| page.url != live_url)
            .map(|page| (page.url.clone(), page))
            .collect())
    }

    /// The Envelope of the page at `url`: the octets the cursor holds for
    /// it, whose request and budget debit alone are skipped, or a fetch.
    fn page_envelope(
        &mut self,
        key: &ObjectKey,
        url: &str,
        held: Option<&WalkPage>,
    ) -> Result<Got> {
        if let Some(raw) = held.and_then(|page| page.raw.as_deref()) {
            if let Ok(value) = crate::json::parse(raw) {
                self.db.record_pull_object(
                    self.run.run_id,
                    key.kind(),
                    &key.name(),
                    url,
                    Status::Fetched,
                    Some(raw),
                    None,
                )?;
                return Ok(Got::Body(raw.to_vec(), value));
            }
        }
        self.get(key, &key.name(), url, Object::Page)
    }

    /// The page at `index` of `walk` as the run's cursor holds it, once
    /// its admission recorded it.
    fn walked(&self, key: &ObjectKey, walk: Walk, index: u32) -> Result<Option<WalkPage>> {
        let object = self
            .db
            .pull_object(self.run.run_id, key.kind(), &key.name())?;
        match object.map(|object| object.status) {
            Some(Status::Admitted) => self.db.walk_page(self.host, walk.as_str(), index),
            _ => Ok(None),
        }
    }

    /// Walks the Feed from `feed.json` through its sealed Pages (WIST-2
    /// §3.2, §5 step 1) until a page lists no unseen ID, `next` ends,
    /// fails the target rule or names a Page the walk cannot use, or the
    /// walk suspends.
    fn walk_feed(&mut self) -> Result<()> {
        let (db, host) = (self.db, self.host);
        let mut pages: Vec<Vec<String>> = Vec::new();
        let mut url = format!("{}feed.json", self.base);
        let cursor = self.cursor(Walk::Feed, &url)?;
        let mut sealed_sources = None;
        loop {
            let index = pages.len() as u32;
            let key = ObjectKey::Page {
                feed: Walk::Feed,
                index,
            };
            let admitted = match self.walked(&key, Walk::Feed, index)? {
                Some(page) => {
                    let unseen = admit::unseen(db, host, Walk::Feed, &page.ids)?;
                    Some((page, unseen))
                }
                None => {
                    let (raw, value) = match self.page_envelope(&key, &url, cursor.get(&url))? {
                        Got::Body(raw, value) => (raw, value),
                        Got::Suspend => return self.finish(true),
                        Got::Failed(detail) if index == 0 => {
                            return self.abort(Some(&key), "WIST2-E01", &detail)
                        }
                        Got::Failed(detail) => {
                            admit::stop_walk(db, &mut self.run, host, &key, "WIST2-E01", &detail)?;
                            break;
                        }
                    };
                    let checks = verify::page(&value, host);
                    let parsed = match checks.fields {
                        Ok(parsed) => parsed,
                        Err(detail) if index == 0 => {
                            return self.abort(Some(&key), "WIST2-E01", detail);
                        }
                        Err(detail) => {
                            admit::stop_walk(db, &mut self.run, host, &key, "WIST2-E01", detail)?;
                            break;
                        }
                    };
                    if !checks.domain_matches {
                        return self.abort(
                            Some(&key),
                            "WIST2-E04",
                            "feed domain does not match the host it was fetched from",
                        );
                    }
                    self.settle()?;
                    let live = index == 0;
                    if !live && sealed_sources.is_none() {
                        sealed_sources = Some(page_declarations(
                            db,
                            self.data_dir,
                            host,
                            self.run.pages_epoch,
                        )?);
                    }
                    let verified = |pull: &Self| -> Result<bool> {
                        Ok(match &sealed_sources {
                            Some(sources) if !live => {
                                verify::sealed_page(sources, &value, &parsed.feed.generated_at)
                            }
                            _ => verify::live_page(&live_page_keys(pull.db, host)?, &value),
                        })
                    };
                    let mut passed = verified(self)?;
                    if !passed && !self.run.feed_retry_used {
                        let retry = ObjectKey::Declaration {
                            attempt: Attempt::Feed,
                        };
                        self.refresh(&retry, self.scope()?)?;
                        self.settle()?;
                        passed = verified(self)?;
                    }
                    if !passed {
                        return self.abort(
                            Some(&key),
                            "WIST2-E04",
                            "feed signature does not verify against the domain's Key Set",
                        );
                    }
                    let next =
                        parsed.feed.next.as_deref().map(|next| {
                            verify::next_page_url(next, host, self.client.allow_http())
                        });
                    admit::admit_page(
                        db,
                        &mut self.run,
                        host,
                        &key,
                        Walk::Feed,
                        live,
                        index,
                        &url,
                        &parsed,
                        &raw,
                        next,
                    )?
                }
            };
            let Some((page, unseen)) = admitted else {
                return Ok(());
            };
            pages.push(page.ids);
            match (unseen, page.next_url) {
                (true, Some(next)) => url = next,
                _ => break,
            }
        }
        let walked = pages.len() as u32;
        let queue = pages.into_iter().rev().flatten().collect();
        admit::end_walk(
            db,
            &mut self.run,
            host,
            Walk::Feed,
            Some(walked),
            Phase::Deltas,
            queue,
        )
    }

    /// WIST-2 §5 steps 2–4 over the walked pages' Delta IDs, oldest page
    /// first.
    fn process_deltas(&mut self) -> Result<()> {
        let (db, host, data_dir) = (self.db, self.host, self.data_dir);
        while self.run.position < self.run.queue.len() {
            let index = self.run.position;
            let id = self.run.queue[index].clone();
            self.settle()?;
            if db.is_delta_seen_for(&id, host)? {
                self.run.position = index + 1;
                continue;
            }
            let key = ObjectKey::Delta { id: id.clone() };
            let slot = self.slot(&key)?;
            let mut refusal = admit::Refusal {
                index,
                id: &id,
                kind: "delta",
                slot: &slot,
                consumed: None,
                resolved_prev: false,
            };
            let Some(hex) = id.strip_prefix("sha256:") else {
                admit::reject_item(
                    db,
                    &mut self.run,
                    host,
                    &refusal,
                    "WIST2-E03",
                    "malformed delta id",
                )?;
                continue;
            };
            let url = format!("{}deltas/{hex}.json", self.base);
            let doc = match self.get(&key, &slot, &url, Object::Delta)? {
                Got::Body(_, doc) => doc,
                Got::Suspend => return self.finish(true),
                Got::Failed(detail) => {
                    admit::reject_item(db, &mut self.run, host, &refusal, "WIST2-E03", &detail)?;
                    continue;
                }
            };
            let mut attempt = match db
                .pull_object(self.run.run_id, "delta", &slot)?
                .and_then(|object| object.refs_json)
            {
                Some(stored) => verify::IssuedRefs::from_json(&stored)?,
                None => {
                    let refs = issue_refs(db, data_dir, host, (self.clock)())?;
                    db.set_pull_object_refs(self.run.run_id, "delta", &slot, &refs.to_json()?)?;
                    refs
                }
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
                admit::reject_item(
                    db,
                    &mut self.run,
                    host,
                    &refusal,
                    code,
                    "Delta Publisher does not match the logical Feed",
                )?;
                continue;
            }
            if let Err(code) = self.authority(&id, &doc, &mut attempt)? {
                admit::reject_item(
                    db,
                    &mut self.run,
                    host,
                    &refusal,
                    code,
                    "Delta signing and scope authority failed",
                )?;
                continue;
            }
            if let Err(code) = checks.static_fields {
                admit::reject_item(
                    db,
                    &mut self.run,
                    host,
                    &refusal,
                    code,
                    "Delta static validation failed",
                )?;
                continue;
            }
            if let Err(code) = checks.clock {
                admit::reject_item(
                    db,
                    &mut self.run,
                    host,
                    &refusal,
                    code,
                    "observed_at exceeds the clock_skew_seconds allowance",
                )?;
                continue;
            }
            let envelope = match checks.decoded {
                Ok(verified) => verified.envelope,
                Err(verify::Undecoded::Canonical(e)) => return Err(e.into()),
                Err(verify::Undecoded::Envelope(detail)) => {
                    admit::reject_item(db, &mut self.run, host, &refusal, "WIST2-E03", &detail)?;
                    continue;
                }
            };
            if let Err(detail) = checks.id {
                admit::reject_item(db, &mut self.run, host, &refusal, "WIST2-E03", &detail)?;
                continue;
            }
            let facts = serde_json::json!({
                "url": envelope.delta.url,
                "prev": envelope.delta.prev,
                "observed_at": envelope.delta.observed_at,
            })
            .to_string();
            db.advance_pull_object(
                self.run.run_id,
                "delta",
                &slot,
                &[Status::Fetched],
                Status::Verified,
                Some(&facts),
            )?;

            if envelope.delta.prev != db.url_tip(host, &envelope.delta.url)? {
                let retrievable = !db.pull_attempted(self.run.run_id, "resolved_prev", &id)?;
                let mut consumed = None;
                if retrievable {
                    if let Some(prev) = envelope.delta.prev.as_deref() {
                        if !db.is_delta_seen_for(prev, host)? {
                            let key = ObjectKey::Delta { id: prev.into() };
                            let slot = self.slot(&key)?;
                            let url = format!("{}deltas/{}.json", self.base, &prev[7..]);
                            match self.get(&key, &slot, &url, Object::Delta)? {
                                Got::Body(..) => {
                                    admit::splice_predecessor(db, &mut self.run, &id, prev, index)?;
                                    continue;
                                }
                                Got::Suspend => return self.finish(true),
                                Got::Failed(_) => consumed = Some(("delta", slot)),
                            }
                        }
                    }
                }
                refusal.consumed = consumed;
                refusal.resolved_prev = retrievable;
                admit::reject_item(
                    db,
                    &mut self.run,
                    host,
                    &refusal,
                    "WIST1-E07",
                    "prev does not match the chain tip and could not be retrieved",
                )?;
                continue;
            }

            if let Some(prev) = &envelope.delta.prev {
                let predecessor = db.accepted_delta(data_dir, host, prev)?;
                if let Err(code) = declaration::verify_delta_predecessor(&doc, &predecessor) {
                    admit::reject_item(
                        db,
                        &mut self.run,
                        host,
                        &refusal,
                        code,
                        "Delta does not strictly follow its predecessor observation",
                    )?;
                    continue;
                }
            }

            let payload = if envelope.delta.payload.is_some() {
                let key = ObjectKey::Payload {
                    delta_id: id.clone(),
                };
                let payload_slot = self.slot(&key)?;
                let url = format!("{}payloads/{hex}.json", self.base);
                let (raw, value) = match self.get(&key, &payload_slot, &url, Object::Payload)? {
                    Got::Body(raw, value) => (raw, value),
                    Got::Suspend => return self.finish(true),
                    Got::Failed(detail) => {
                        refusal.consumed = Some(("payload", payload_slot));
                        admit::reject_item(
                            db,
                            &mut self.run,
                            host,
                            &refusal,
                            "WIST2-E03",
                            &detail,
                        )?;
                        continue;
                    }
                };
                if let Err(code) = verify::payload(&value, &envelope, &attempt.sizes) {
                    refusal.consumed = Some(("payload", payload_slot));
                    admit::reject_item(db, &mut self.run, host, &refusal, "WIST2-E03", code)?;
                    continue;
                }
                db.advance_pull_object(
                    self.run.run_id,
                    "payload",
                    &payload_slot,
                    &[Status::Fetched],
                    Status::Verified,
                    None,
                )?;
                Some((raw, payload_slot))
            } else {
                None
            };

            if let Err(code) = self.authority(&id, &doc, &mut attempt)? {
                refusal.consumed = payload.as_ref().map(|(_, slot)| ("payload", slot.clone()));
                admit::reject_item(
                    db,
                    &mut self.run,
                    host,
                    &refusal,
                    code,
                    "Delta authority changed before admission",
                )?;
                continue;
            }
            let item = admit::DeltaItem {
                index,
                id: &id,
                slot: &slot,
                payload_slot: payload.as_ref().map(|(_, slot)| slot.as_str()),
            };
            match admit::admit_delta(
                db,
                data_dir,
                &mut self.run,
                host,
                &item,
                &doc,
                &envelope,
                payload.as_ref().map(|(raw, _)| raw.as_slice()),
                &attempt,
            )? {
                admit::Admission::Stale(stale) => {
                    tracing::debug!(domain = host, delta = %id, ?stale, "re-issuing a stale Delta admission");
                    let refs = self.reissue(attempt)?;
                    admit::reissue(db, &self.run, &id, &slot, &refs)?;
                }
                _ => continue,
            }
        }
        admit::end_walk(
            db,
            &mut self.run,
            host,
            Walk::Feed,
            None,
            Phase::Labels,
            Vec::new(),
        )
    }

    /// WIST-1 §5.1 authority of a Delta under the admission sources after
    /// any settlement due, with the one Declaration retry WIST-2 §5 allows
    /// each Delta ID per pull on a binding failure. The attempt's
    /// Declaration reference becomes the version the check read.
    fn authority(
        &mut self,
        id: &str,
        doc: &Value,
        attempt: &mut verify::IssuedRefs,
    ) -> Result<std::result::Result<(), &'static str>> {
        let scope = self.scope()?;
        self.settle()?;
        attempt.decl = declaration_ref(self.db, self.host)?;
        let mut authority = verify::delta_authority(&attempt.decl.sources, doc);
        if matches!(authority, Err("WIST1-E01" | "WIST1-E02"))
            && !self
                .db
                .pull_attempted(self.run.run_id, "delta_refresh", id)?
        {
            let key = ObjectKey::Declaration {
                attempt: Attempt::Delta(id.to_string()),
            };
            self.refresh(&key, scope)?;
            self.settle()?;
            attempt.decl = declaration_ref(self.db, self.host)?;
            authority = verify::delta_authority(&attempt.decl.sources, doc);
        }
        Ok(authority)
    }

    /// Re-issues a stale attempt's references at its frozen clock: the
    /// current Declaration version and, when an Epoch was sealed since,
    /// the caps of the schedule it extended.
    fn reissue(&self, refs: verify::IssuedRefs) -> Result<verify::IssuedRefs> {
        let schedule_at = self.db.last_epoch()?.map(|epoch| epoch.epoch_number);
        if schedule_at != refs.schedule_at {
            return issue_refs(self.db, self.data_dir, self.host, refs.clock);
        }
        Ok(verify::IssuedRefs {
            decl: declaration_ref(self.db, self.host)?,
            ..refs
        })
    }

    /// WIST-2 §3.3: walks the domain's Label Feed beside its Feed, under
    /// §3.2's rules and the ingest budget. A Label walk that cannot begin
    /// under a spent budget waits for the next pull without suspending the
    /// Feed walk that completed before it.
    fn walk_labels(&mut self) -> Result<()> {
        let (db, host) = (self.db, self.host);
        if label_declaration(db, host)?.is_none() {
            return self.finish(false);
        }
        let mut pages: Vec<Vec<String>> = Vec::new();
        let mut url = format!("{}label-feed.json", self.base);
        let cursor = self.cursor(Walk::Label, &url)?;
        let mut sealed_sources = None;
        loop {
            let index = pages.len() as u32;
            let live = index == 0;
            let key = ObjectKey::Page {
                feed: Walk::Label,
                index,
            };
            if db
                .pull_object(self.run.run_id, key.kind(), &key.name())?
                .is_some_and(|object| object.status == Status::Rejected)
            {
                break;
            }
            let admitted = match self.walked(&key, Walk::Label, index)? {
                Some(page) => {
                    let unseen = admit::unseen(db, host, Walk::Label, &page.ids)?;
                    Some((page, unseen))
                }
                None => {
                    let (raw, value) = match self.page_envelope(&key, &url, cursor.get(&url))? {
                        Got::Body(raw, value) => (raw, value),
                        Got::Suspend => return self.finish(!live),
                        Got::Failed(detail) => {
                            if !live {
                                admit::reject_page(
                                    db,
                                    &self.run,
                                    host,
                                    &key,
                                    "WIST2-E01",
                                    &detail,
                                )?;
                            }
                            break;
                        }
                    };
                    let checks = verify::page(&value, host);
                    let parsed = match checks.fields {
                        Ok(parsed) => parsed,
                        Err(detail) => {
                            admit::reject_page(db, &self.run, host, &key, "WIST2-E06", detail)?;
                            break;
                        }
                    };
                    if !checks.domain_matches {
                        admit::reject_page(
                            db,
                            &self.run,
                            host,
                            &key,
                            "WIST2-E06",
                            "label feed domain does not match the host it was fetched from",
                        )?;
                        break;
                    }
                    let verified = if live {
                        verify::live_page(&live_page_keys(db, host)?, &value)
                    } else {
                        if sealed_sources.is_none() {
                            sealed_sources = Some(page_declarations(
                                db,
                                self.data_dir,
                                host,
                                self.run.pages_epoch,
                            )?);
                        }
                        verify::sealed_page(
                            sealed_sources.as_ref().unwrap(),
                            &value,
                            &parsed.feed.generated_at,
                        )
                    };
                    if !verified {
                        admit::reject_page(
                            db,
                            &self.run,
                            host,
                            &key,
                            "WIST2-E06",
                            "label feed signature does not verify against the domain's Key Set",
                        )?;
                        break;
                    }
                    let next =
                        parsed.feed.next.as_deref().map(|next| {
                            verify::next_page_url(next, host, self.client.allow_http())
                        });
                    admit::admit_page(
                        db,
                        &mut self.run,
                        host,
                        &key,
                        Walk::Label,
                        live,
                        index,
                        &url,
                        &parsed,
                        &raw,
                        next,
                    )?
                }
            };
            let Some((page, unseen)) = admitted else {
                break;
            };
            pages.push(page.ids);
            match (unseen, page.next_url) {
                (true, Some(next)) => url = next,
                _ => break,
            }
        }
        let walked = pages.len() as u32;
        let queue = pages.into_iter().rev().flatten().collect();
        admit::end_walk(
            db,
            &mut self.run,
            host,
            Walk::Label,
            Some(walked),
            Phase::LabelItems,
            queue,
        )
    }

    /// Fetches each unseen Label or dispute of the walked Label Feed
    /// pages, validates it under the accepted Declaration and queues it as
    /// a `label` or `dispute` Entry; a failure is `WIST2-E06` at the
    /// status endpoint.
    fn process_labels(&mut self) -> Result<()> {
        let (db, host) = (self.db, self.host);
        let Some(mut declaration) = label_declaration(db, host)? else {
            return self.finish(false);
        };
        let url_cap_bytes = declaration::delta::SizeCaps::from_schedule(
            &db.parameter_schedule(self.now_unix)?,
            self.now_unix,
        )
        .url_cap_bytes;
        while self.run.position < self.run.queue.len() {
            let index = self.run.position;
            let id = self.run.queue[index].clone();
            if db.is_label_seen_for(&id, host)? {
                self.run.position = index + 1;
                continue;
            }
            let key = ObjectKey::Label { id: id.clone() };
            let slot = self.slot(&key)?;
            let refusal = admit::Refusal {
                index,
                id: &id,
                kind: "label",
                slot: &slot,
                consumed: None,
                resolved_prev: false,
            };
            let Some(hex) = id.strip_prefix("sha256:") else {
                admit::reject_item(
                    db,
                    &mut self.run,
                    host,
                    &refusal,
                    "WIST2-E06",
                    "malformed Label ID",
                )?;
                continue;
            };
            let url = format!("{}labels/{hex}.json", self.base);
            let doc = match self.get(&key, &slot, &url, Object::Label)? {
                Got::Body(_, doc) => doc,
                Got::Suspend => return self.finish(true),
                Got::Failed(detail) => {
                    admit::reject_item(db, &mut self.run, host, &refusal, "WIST2-E06", &detail)?;
                    continue;
                }
            };
            loop {
                let checks = verify::label(&doc, &id, &declaration.0, url_cap_bytes);
                let Some(kind) = checks.kind else {
                    admit::reject_item(
                        db,
                        &mut self.run,
                        host,
                        &refusal,
                        "WIST2-E06",
                        "file carries neither a Label nor a dispute",
                    )?;
                    break;
                };
                if !checks.id_matches {
                    admit::reject_item(
                        db,
                        &mut self.run,
                        host,
                        &refusal,
                        "WIST2-E06",
                        "file does not carry the listed ID",
                    )?;
                    break;
                }
                if let admit::LabelAdmission::Stale = admit::admit_label(
                    db,
                    &mut self.run,
                    host,
                    index,
                    &id,
                    &slot,
                    kind,
                    &doc,
                    &declaration,
                    checks.label,
                )? {
                    declaration = label_declaration(db, host)?.ok_or_else(|| {
                        crate::error::Error::History(
                            "the Label admission Declaration was lost mid-pull".into(),
                        )
                    })?;
                    continue;
                }
                break;
            }
        }
        db.clear_walk(host, Walk::Label.as_str())?;
        self.finish(false)
    }
}

/// A recorded flag of an object's checks.
fn checks_flag(object: &PullObject, name: &str) -> bool {
    object
        .checks_json
        .as_deref()
        .and_then(|checks| serde_json::from_str::<Value>(checks).ok())
        .is_some_and(|checks| checks[name] == true)
}

/// The failure a fetch recorded, if it failed rather than suspended the
/// walk at a bound.
fn failure_detail(object: &PullObject) -> Option<String> {
    object
        .checks_json
        .as_deref()
        .and_then(|checks| serde_json::from_str::<Value>(checks).ok())
        .and_then(|checks| checks["detail"].as_str().map(str::to_string))
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
