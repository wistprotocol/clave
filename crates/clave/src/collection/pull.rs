use super::site::{Answer, Held, Object, Request, Site};
use super::state::{
    AcceptedCatalog, Admission, CollectionState, Discovered, ItemKind, ListItem, Place,
    QueuedCatalog, ServedFile, State, WaitingUrl,
};
use crate::error::{Error, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use wist_core::catalog::{self, Attempt, Fetch, Pull, Window};
use wist_core::collection::{self, Limits};
use wist_core::constants::CATALOG_FILE_READ_MAX_BYTES;
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::declaration::{self, Decision};
use wist_core::declarations::{Declarations, Domain, Projection};
use wist_core::item::{self, SizeCaps};
use wist_core::objects::{Catalog, PageItem, Publisher};
use wist_core::parameters::WIRE_INTEGER_MAX;
use wist_core::tree::{self, TreeBounds, TreeFetch, Walk};

/// WIST-1 §5.2, Sources of a pull: a pending head stays pending at every pull.
const NEVER_ACTIVATES: i64 = WIRE_INTEGER_MAX;

const UNAVAILABLE: &str = "WIST2-E01";
const NOT_ADMITTED: &str = "WIST2-E03";
const ORDER: &str = "WIST2-E05";
const TREE_REFUSED: &str = "WIST2-E07";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parameters(BTreeMap<String, i64>);

impl Parameters {
    pub fn new(map: BTreeMap<String, i64>) -> Self {
        Parameters(map)
    }

    pub fn set(&mut self, name: &str, value: i64) {
        self.0.insert(name.into(), value);
    }

    pub fn value(&self, name: &str) -> Result<i64> {
        self.0
            .get(name)
            .copied()
            .or_else(|| wist_core::parameters::spec(name).and_then(|spec| spec.default))
            .ok_or_else(|| Error::Param(name.into()))
    }

    pub fn limits(&self) -> Result<Limits> {
        Ok(Limits::new(
            self.value("collections_max")?,
            self.value("scope_entries_max")?,
            self.value("url_cap_bytes")?,
        )?)
    }

    pub fn size_caps(&self) -> Result<SizeCaps> {
        Ok(SizeCaps::new(
            self.value("url_cap_bytes")?,
            self.value("extract_cap_bytes")?,
            self.value("links_cap_bytes")?,
            self.value("link_url_cap_bytes")?,
            self.value("summary_cap_bytes")?,
        )?)
    }

    pub fn tree_bounds(&self) -> Result<TreeBounds> {
        Ok(TreeBounds::new(
            self.value("tree_file_cap_bytes")?,
            self.value("tree_depth_max")?,
        )?)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PullInput<'a> {
    pub publisher: &'a str,
    pub at: &'a str,
    pub parameters: &'a Parameters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationReport {
    pub outcome: String,
    pub proceeds: bool,
    pub first_contact: bool,
    pub discovered: bool,
    pub reduces_authority: bool,
    pub sources: Vec<String>,
    pub window: bool,
}

impl DeclarationReport {
    /// WIST-2 §5.1 step 0.
    pub fn disposition(&self) -> Option<&'static str> {
        match (self.proceeds, self.first_contact) {
            (true, _) => None,
            (false, true) => Some("WIST2-E04"),
            (false, false) => Some(UNAVAILABLE),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogOutcome {
    Unavailable,
    Suspended,
    Accepted,
    Idempotent,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discard {
    pub condition: &'static str,
    pub catalog: String,
    pub change_list: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemOutcome {
    Admitted,
    NotAdmitted,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadSource {
    Withdrawn,
    Record,
    Held,
    Fetched,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemReport {
    pub url: String,
    pub item: String,
    pub outcome: ItemOutcome,
    pub codes: Vec<&'static str>,
    pub payload: Option<PayloadSource>,
    pub payload_code: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogReport {
    pub collection: String,
    pub outcome: CatalogOutcome,
    pub catalog: Option<String>,
    pub codes: Vec<&'static str>,
    pub dropped: Vec<String>,
    pub sources: Vec<String>,
    pub tree_files_fetched: Vec<String>,
    pub chain: Option<Discard>,
    pub base: bool,
    pub key: Option<String>,
    pub queued: bool,
    pub items: Vec<ItemReport>,
    pub suspended: bool,
}

impl CatalogReport {
    pub fn new(collection: &str, outcome: CatalogOutcome) -> Self {
        CatalogReport {
            collection: collection.into(),
            outcome,
            catalog: None,
            codes: Vec::new(),
            dropped: Vec::new(),
            sources: Vec::new(),
            tree_files_fetched: Vec::new(),
            chain: None,
            base: false,
            key: None,
            queued: false,
            items: Vec::new(),
            suspended: false,
        }
    }

    fn refused(mut self, codes: Vec<&'static str>) -> Self {
        self.outcome = CatalogOutcome::Refused;
        self.codes = codes;
        self
    }

    pub fn codes_recorded(&self) -> Vec<&'static str> {
        self.chain
            .iter()
            .map(|_| "WIST2-E08")
            .chain(self.codes.iter().copied())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullReport {
    pub event: u64,
    pub declaration: DeclarationReport,
    pub collections_pulled: Vec<String>,
    pub catalogs: Vec<CatalogReport>,
    pub suspended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    pub code: Option<&'static str>,
    pub noise: bool,
}

impl PullReport {
    pub fn codes_recorded(&self) -> Vec<&'static str> {
        self.catalogs
            .iter()
            .flat_map(CatalogReport::codes_recorded)
            .collect()
    }

    /// WIST-2 §5.4.
    pub fn resolution(&self, labels_admitted: usize) -> Resolution {
        if let Some(code) = self.declaration.disposition() {
            return Resolution {
                code: Some(code),
                noise: self.declaration.first_contact,
            };
        }
        let accepted = self
            .catalogs
            .iter()
            .any(|catalog| catalog.outcome == CatalogOutcome::Accepted);
        let admitted = self.catalogs.iter().any(|catalog| {
            catalog
                .items
                .iter()
                .any(|item| item.outcome == ItemOutcome::Admitted)
        });
        if self.suspended
            || self.declaration.discovered
            || accepted
            || admitted
            || labels_admitted > 0
        {
            return Resolution {
                code: None,
                noise: false,
            };
        }
        Resolution {
            code: Some("WIST2-E02"),
            noise: true,
        }
    }
}

struct Source {
    hash: String,
    publisher: Publisher,
}

struct Context<'a> {
    publisher: &'a str,
    at: &'a str,
    parameters: &'a Parameters,
    sources: Vec<Source>,
    event: u64,
    queues: bool,
    window_opened: bool,
}

pub fn pull(
    state: &mut State,
    site: &mut impl Site,
    held: &mut impl Held,
    input: &PullInput<'_>,
) -> Result<PullReport> {
    let event = state.events;
    state.events += 1;
    let (declaration, sources) = read_declaration(state, site, input, event)?;
    let mut report = PullReport {
        event,
        declaration,
        collections_pulled: Vec::new(),
        catalogs: Vec::new(),
        suspended: false,
    };
    if !report.declaration.proceeds {
        return Ok(report);
    }
    let mut names: Vec<String> = Vec::new();
    for source in &sources {
        for name in collection::names(&source.publisher) {
            if !names.iter().any(|known| known == name) {
                names.push(name.to_owned());
            }
        }
    }
    let order = place_order(state, input.publisher, &sources[0].publisher, &names);
    let context = Context {
        publisher: input.publisher,
        at: input.at,
        parameters: input.parameters,
        queues: sources.len() > 1,
        window_opened: report.declaration.window,
        sources,
        event,
    };
    for name in &names {
        let catalog = pull_collection(state, site, held, &context, name, order[name])?;
        let stops = catalog.outcome == CatalogOutcome::Suspended || catalog.suspended;
        report.catalogs.push(catalog);
        if stops {
            report.suspended = true;
            break;
        }
    }
    report.collections_pulled = names;
    if !context.queues {
        refresh_waiting(state, held, input.publisher, event, &order)?;
    }
    Ok(report)
}

fn place_order(
    state: &State,
    publisher: &str,
    declaration: &Publisher,
    pulled: &[String],
) -> BTreeMap<String, u64> {
    let named: Vec<&str> = collection::names(declaration);
    let mut rest: BTreeSet<String> = state.collection_names(publisher).into_iter().collect();
    rest.extend(pulled.iter().cloned());
    named
        .iter()
        .map(|name| name.to_string())
        .chain(
            rest.into_iter()
                .filter(|name| !named.contains(&name.as_str())),
        )
        .enumerate()
        .map(|(position, name)| (name, position as u64))
        .collect()
}

fn publisher_entry(envelope: &Value) -> Value {
    json!({"type": "publisher_declaration", "body": envelope})
}

fn unbounded_limits() -> Result<Limits> {
    let largest = |name| {
        wist_core::parameters::spec(name)
            .and_then(|spec| spec.max)
            .unwrap_or(WIRE_INTEGER_MAX)
    };
    Ok(Limits::new(
        largest("collections_max"),
        largest("scope_entries_max"),
        largest("url_cap_bytes"),
    )?)
}

fn project(
    sealed: &Declarations,
    at: &str,
    recovery_window_days: i64,
    envelopes: &[&Value],
) -> Result<std::result::Result<Projection, String>> {
    let mut entries: Vec<Value> = envelopes
        .iter()
        .map(|envelope| publisher_entry(envelope))
        .collect();
    wist_core::epoch::sort_entries(&mut entries)?;
    match sealed.project(
        at,
        recovery_window_days,
        NEVER_ACTIVATES,
        &unbounded_limits()?,
        &entries,
    ) {
        Ok(projection) => Ok(Ok(projection)),
        Err(error) => match error.code() {
            Some(code) => Ok(Err(code.to_owned())),
            None => Err(error.into()),
        },
    }
}

fn projection_instant(state: &State, at: &str) -> Result<(String, i64)> {
    let at_s = wist_core::timestamp::log_seconds(at)?;
    let after = match &state.sealed_at {
        Some(sealed_at) => wist_core::timestamp::log_seconds(sealed_at)? + 1,
        None => i64::MIN,
    };
    let instant_s = at_s.max(after);
    Ok((wist_core::timestamp::instant(instant_s)?, instant_s))
}

fn head_hashes(domain: &Domain) -> (Option<&str>, Option<&str>) {
    (
        domain.window().map(|window| window.head().hash()),
        domain.pending().map(|pending| pending.head().hash()),
    )
}

enum Classified {
    Idempotent,
    ChainHead,
    Install,
}

fn read_declaration(
    state: &mut State,
    site: &mut impl Site,
    input: &PullInput<'_>,
    event: u64,
) -> Result<(DeclarationReport, Vec<Source>)> {
    let publisher = input.publisher;
    let recovery_window_days = input.parameters.value("recovery_window_days")?;
    let (at, at_s) = projection_instant(state, input.at)?;
    let sealed_domain = state.declarations.domains().get(publisher);
    let mut admitted: Vec<Value> = Vec::new();
    let mut view: Option<Projection> = None;
    for found in state.discovered.get(publisher).into_iter().flatten() {
        let trial: Vec<&Value> = admitted
            .iter()
            .chain(std::iter::once(&found.envelope))
            .collect();
        if let Ok(projection) = project(&state.declarations, &at, recovery_window_days, &trial)? {
            admitted.push(found.envelope.clone());
            view = Some(projection);
        }
    }
    let settles = sealed_domain
        .and_then(Domain::window)
        .is_some_and(|window| window.end_s() <= i128::from(at_s));
    if view.is_none() && settles {
        view = Some(
            project(&state.declarations, &at, recovery_window_days, &[])?
                .map_err(Error::History)?,
        );
    }
    let domain = match &view {
        Some(projection) => projection.domains().get(publisher),
        None => sealed_domain,
    };
    let first_contact = domain.is_none();
    let stopped = |outcome: &str| DeclarationReport {
        outcome: outcome.into(),
        proceeds: false,
        first_contact,
        discovered: false,
        reduces_authority: false,
        sources: Vec::new(),
        window: false,
    };
    let stored = state.declaration_files.get(publisher).cloned();
    let answer = site.fetch(&Request {
        object: Object::Declaration,
        bound: crate::fetch::OBJECT_CAP_BYTES,
        validator: stored.as_ref().and_then(|file| file.validator.as_deref()),
    })?;
    let octets = match answer {
        Answer::Octets { octets, validator } => {
            if octets.len() as u64 > crate::fetch::OBJECT_CAP_BYTES {
                return Ok((stopped("not_fetched"), Vec::new()));
            }
            state.declaration_files.insert(
                publisher.into(),
                ServedFile {
                    octets: octets.clone(),
                    validator,
                },
            );
            octets
        }
        Answer::NotModified => match stored {
            Some(file) => file.octets,
            None => return Ok((stopped("not_fetched"), Vec::new())),
        },
        Answer::Failed | Answer::Suspended => return Ok((stopped("not_fetched"), Vec::new())),
    };
    let Ok(fetched) = crate::json::parse(&octets) else {
        return Ok((stopped("WIST1-E05"), Vec::new()));
    };
    let incoming = match declaration::validate_fields(&fetched, None) {
        Ok(envelope) => envelope.publisher,
        Err((code, _)) => return Ok((stopped(code), Vec::new())),
    };
    let hash = declaration::inner_hash(&fetched).map_err(Error::History)?;
    let limits = input.parameters.limits()?;
    let classified = match domain {
        Some(domain) => {
            let (window_head, pending_head) = head_hashes(domain);
            if hash == domain.current().hash() || pending_head == Some(hash.as_str()) {
                Classified::Idempotent
            } else if window_head == Some(hash.as_str()) {
                Classified::ChainHead
            } else {
                match declaration::evaluate_with_heads(
                    domain.current().envelope(),
                    domain.window().map(|window| window.head().envelope()),
                    domain.pending().map(|pending| pending.head().envelope()),
                    domain.highest_accepted_seq(),
                    &fetched,
                    &limits,
                ) {
                    Err((code, _)) => return Ok((stopped(code), Vec::new())),
                    Ok(Decision::Unchanged) => Classified::Idempotent,
                    Ok(_) => Classified::Install,
                }
            }
        }
        None => {
            if incoming.domain != publisher {
                return Ok((stopped("WIST2-E04"), Vec::new()));
            }
            if let Err((code, _)) = declaration::evaluate_initial(&fetched, &limits) {
                return Ok((stopped(code), Vec::new()));
            }
            Classified::Install
        }
    };
    let window_opened = sealed_domain.and_then(Domain::window).is_some();
    let (outcome, installed) = match classified {
        Classified::Idempotent => ("idempotent".to_owned(), None),
        Classified::ChainHead => ("recovery_chain_head".to_owned(), None),
        Classified::Install => {
            let trial: Vec<&Value> = admitted.iter().chain(std::iter::once(&fetched)).collect();
            let projection = match project(&state.declarations, &at, recovery_window_days, &trial)?
            {
                Ok(projection) => projection,
                Err(code) => return Ok((stopped(&code), Vec::new())),
            };
            let kind = projection
                .effects()
                .transitions
                .iter()
                .rev()
                .find(|transition| {
                    transition.domain == publisher && transition.declaration.hash() == hash
                })
                .map(|transition| transition.kind.as_str())
                .ok_or_else(|| {
                    Error::History("an installed Declaration has no transition".into())
                })?;
            (kind.to_owned(), Some(projection))
        }
    };
    let mut discovered = false;
    let mut reduces = false;
    if installed.is_some()
        && !state
            .discovered
            .get(publisher)
            .is_some_and(|found| found.iter().any(|found| found.hash == hash))
    {
        discovered = true;
        let predecessor = domain.and_then(|domain| {
            std::iter::once(domain.current())
                .chain(domain.window().map(|window| window.head()))
                .chain(domain.pending().map(|pending| pending.head()))
                .find(|head| Some(head.hash()) == incoming.prev_declaration.as_deref())
        });
        if let Some(predecessor) = predecessor {
            let predecessor =
                declaration::publisher_of(predecessor.envelope()).map_err(Error::History)?;
            reduces = collection::reduces_authority(&predecessor, &incoming);
        }
        let epochs = input.parameters.value("record_seal_epochs")?;
        let epochs =
            u64::try_from(epochs).map_err(|_| Error::Param("record_seal_epochs".into()))?;
        let last_seal_height = match (reduces, state.height) {
            (false, _) => None,
            (true, Some(height)) => collection::last_seal_height(height, epochs),
            (true, None) => Some(epochs),
        };
        state
            .discovered
            .entry(publisher.into())
            .or_default()
            .push(Discovered {
                envelope: fetched.clone(),
                hash: hash.clone(),
                event,
                last_sealed_at_discovery: state.height,
                reduces_authority: reduces,
                last_seal_height,
            });
    }
    let sealed_domain = state.declarations.domains().get(publisher);
    let domain = match &installed {
        Some(projection) => projection.domains().get(publisher),
        None => match &view {
            Some(projection) => projection.domains().get(publisher),
            None => sealed_domain,
        },
    }
    .ok_or_else(|| Error::History("an accepted Declaration left no domain state".into()))?;
    let sources = domain
        .admission_sources()
        .into_iter()
        .map(|source| {
            Ok(Source {
                hash: source.hash().to_owned(),
                publisher: declaration::publisher_of(source.envelope()).map_err(Error::History)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        DeclarationReport {
            outcome,
            proceeds: true,
            first_contact,
            discovered,
            reduces_authority: reduces,
            sources: sources.iter().map(|source| source.hash.clone()).collect(),
            window: window_opened && domain.window().is_some(),
        },
        sources,
    ))
}

fn catalog_signer(key: &str) -> Result<PublicKey> {
    Ok(PublicKey::from_b64u(key)?)
}

fn pull_collection(
    state: &mut State,
    site: &mut impl Site,
    held: &mut impl Held,
    context: &Context<'_>,
    name: &str,
    position: u64,
) -> Result<CatalogReport> {
    let publisher = context.publisher;
    let key = (publisher.to_owned(), name.to_owned());
    let current = state.collections.get(&key).cloned().unwrap_or_default();
    let stored = current.catalog_file.clone();
    let answer = site.fetch(&Request {
        object: Object::Catalog { collection: name },
        bound: CATALOG_FILE_READ_MAX_BYTES,
        validator: stored.as_ref().and_then(|file| file.validator.as_deref()),
    })?;
    let unavailable = || {
        let mut report = CatalogReport::new(name, CatalogOutcome::Unavailable);
        report.codes = vec![UNAVAILABLE];
        report
    };
    let octets = match answer {
        Answer::Suspended => return Ok(CatalogReport::new(name, CatalogOutcome::Suspended)),
        Answer::Failed => return Ok(unavailable()),
        Answer::NotModified => match stored {
            Some(file) => file.octets,
            None => return Ok(unavailable()),
        },
        Answer::Octets { octets, validator } => {
            if octets.len() as u64 <= CATALOG_FILE_READ_MAX_BYTES {
                state
                    .collections
                    .entry(key.clone())
                    .or_default()
                    .catalog_file = Some(ServedFile {
                    octets: octets.clone(),
                    validator,
                });
            }
            octets
        }
    };
    let latest = current
        .latest
        .as_ref()
        .map(|latest| &latest.envelope["catalog"]);
    let last_accepted = current
        .last_accepted()
        .map(|(envelope, _)| &envelope["catalog"]);
    let fetch = Fetch {
        publisher,
        collection: name,
        last_accepted,
        latest,
    };
    let queued: Vec<(Value, PublicKey)> = state
        .queue
        .iter()
        .filter(|((p, n, _), _)| p == publisher && n == name)
        .map(|((_, _, signer), queued)| {
            Ok((queued.envelope["catalog"].clone(), catalog_signer(signer)?))
        })
        .collect::<Result<_>>()?;
    let waiting = current
        .waiting()
        .map(|waiting| {
            Ok::<_, Error>((
                waiting.envelope["catalog"].clone(),
                catalog_signer(&waiting.key)?,
            ))
        })
        .transpose()?;
    let window = Window {
        opened: context.window_opened,
        queued: &queued,
        waiting: waiting.as_ref(),
    };
    let skew = context.parameters.value("clock_skew_seconds")?;
    let items_max = context.parameters.value("catalog_items_max")?;
    let mut judged = Vec::new();
    for source in &context.sources {
        let attempt = Attempt::new(&source.publisher, context.at, skew, items_max)?;
        judged.push(if context.queues {
            catalog::pull_in_window(&fetch, &window, &octets, &attempt)
        } else {
            catalog::pull(&fetch, &octets, &attempt)
        });
    }
    if judged.contains(&Pull::Failed) {
        return Ok(unavailable());
    }
    let mut report = CatalogReport::new(name, CatalogOutcome::Refused);
    let envelope = crate::json::parse(&octets)?;
    let inner = envelope["catalog"].clone();
    let catalog_id = catalog::catalog_id(&inner)?;
    report.catalog = Some(catalog_id.clone());
    let under = |wanted: fn(&Pull) -> bool| -> Vec<&Source> {
        context
            .sources
            .iter()
            .zip(&judged)
            .filter(|(_, pull)| wanted(pull))
            .map(|(source, _)| source)
            .collect()
    };
    let accepting = under(|pull| matches!(pull, Pull::Accepted(_)));
    let idempotent = under(|pull| *pull == Pull::Idempotent);
    let signer = judged.iter().find_map(|pull| match pull {
        Pull::Accepted(signer) => signer.clone(),
        _ => None,
    });
    if accepting.is_empty() && idempotent.is_empty() {
        let regressed = judged.contains(&Pull::Refused(ORDER));
        let codes: BTreeSet<&'static str> = if regressed {
            BTreeSet::from([ORDER])
        } else {
            judged
                .iter()
                .filter_map(|pull| match pull {
                    Pull::Refused(code) => Some(*code),
                    _ => None,
                })
                .collect()
        };
        return Ok(report.refused(codes.into_iter().collect()));
    }
    let catalog: Catalog = serde_json::from_value(inner.clone())?;
    if accepting.is_empty() {
        report.outcome = CatalogOutcome::Idempotent;
        report.sources = idempotent
            .iter()
            .map(|source| source.hash.clone())
            .collect();
        let Some(list) = held.list(publisher, name, &catalog_id)? else {
            return Ok(report);
        };
        let suspended = judge_items(
            state,
            site,
            held,
            context,
            &catalog,
            &catalog_id,
            &list,
            &idempotent,
            &mut report.items,
            true,
        )?;
        report.suspended = suspended;
        return Ok(report);
    }
    let signer =
        signer.ok_or_else(|| Error::History("an accepted Catalog has no signer".into()))?;
    report.sources = accepting.iter().map(|source| source.hash.clone()).collect();
    let list = match obtain_list(state, site, held, context, name, &catalog, &mut report)? {
        Listing::Listed(list) => list,
        Listing::Refused => return Ok(report.refused(vec![TREE_REFUSED])),
        Listing::Suspended => {
            report.outcome = CatalogOutcome::Suspended;
            return Ok(report);
        }
    };
    held.hold_list(publisher, name, &catalog_id, &inner, &list)?;
    let present: BTreeSet<&str> = list
        .iter()
        .filter_map(|item| item["url"].as_str())
        .collect();
    let floor = current.floor();
    let base = wist_core::sealing::base_against_floor(&catalog.generated_at, floor)?;
    let dropped: Vec<String> = state
        .records
        .range((publisher.to_owned(), String::new())..)
        .take_while(|((p, _), _)| p == publisher)
        .filter(|((_, url), record)| {
            record.collection == name
                && !present.contains(url.as_str())
                && context
                    .sources
                    .iter()
                    .any(|source| collection::covers(&source.publisher, name, url))
        })
        .map(|((_, url), _)| url.clone())
        .collect();
    if !dropped.is_empty() && !base {
        report.dropped = dropped;
        return Ok(report.refused(vec![TREE_REFUSED]));
    }
    report.outcome = CatalogOutcome::Accepted;
    report.base = base;
    let signer_key = signer.to_b64u();
    report.key = Some(signer_key.clone());
    let place = Place::catalog(context.event, position);
    if context.queues {
        let slot = (publisher.to_owned(), name.to_owned(), signer_key);
        let first_place = state
            .queue
            .get(&slot)
            .map_or(place, |queued| queued.first_place);
        state.queue.insert(
            slot,
            QueuedCatalog {
                envelope: envelope.clone(),
                catalog_id: catalog_id.clone(),
                place,
                first_place,
                sources: report.sources.clone(),
            },
        );
        report.queued = true;
    } else {
        let next_epoch = state.first_epoch_after();
        let collection = state.collections.entry(key).or_default();
        let (place, eligibility) = match collection.waiting() {
            Some(waiting) => (waiting.place, waiting.eligibility),
            None => (place, next_epoch),
        };
        collection.accepted = Some(AcceptedCatalog {
            envelope: envelope.clone(),
            catalog_id: catalog_id.clone(),
            key: signer_key,
            base_against_floor: base,
            failed_c1: false,
            failed_c4: false,
            place,
            eligibility,
        });
    }
    state.lists.insert(
        (publisher.into(), name.into(), catalog_id.clone()),
        unjudged(&list)?,
    );
    let suspended = judge_items(
        state,
        site,
        held,
        context,
        &catalog,
        &catalog_id,
        &list,
        &accepting,
        &mut report.items,
        false,
    )?;
    report.suspended = suspended;
    Ok(report)
}

fn unjudged(list: &[Value]) -> Result<Vec<ListItem>> {
    list.iter()
        .map(|item| {
            Ok(ListItem {
                url: item["url"].as_str().unwrap_or_default().to_owned(),
                item_id: item::item_id(item)?,
                kind: match item::kind(item) {
                    item::Kind::Page => ItemKind::Page,
                    item::Kind::Removed => ItemKind::Removed,
                },
                admission: Admission::Unjudged,
                code: None,
            })
        })
        .collect()
}

pub enum Chain {
    NotRead,
    Listed(Vec<Value>),
    Discarded(Discard),
}

enum Listing {
    Listed(Vec<Value>),
    Refused,
    Suspended,
}

fn read_chain(
    _state: &mut State,
    _site: &mut impl Site,
    _held: &mut impl Held,
    _context: &Context<'_>,
    _name: &str,
    _catalog: &Catalog,
) -> Result<Chain> {
    Ok(Chain::NotRead)
}

fn obtain_list(
    state: &mut State,
    site: &mut impl Site,
    held: &mut impl Held,
    context: &Context<'_>,
    name: &str,
    catalog: &Catalog,
    report: &mut CatalogReport,
) -> Result<Listing> {
    let publisher = context.publisher;
    if let Some(list) = held.list_with_root(publisher, name, catalog.size, &catalog.root)? {
        return Ok(Listing::Listed(list));
    }
    match read_chain(state, site, held, context, name, catalog)? {
        Chain::Listed(list) => return Ok(Listing::Listed(list)),
        Chain::Discarded(discard) => report.chain = Some(discard),
        Chain::NotRead => {}
    }
    let bounds = context.parameters.tree_bounds()?;
    let mut fetched = Vec::new();
    let mut failure = None;
    let walk = tree::walk(catalog, &bounds, |hex| {
        match fetch_tree_file(site, held, publisher, name, hex, &bounds, &mut fetched) {
            Ok(answer) => answer,
            Err(error) => {
                failure = Some(error);
                TreeFetch::Suspended
            }
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    fetched.sort();
    report.tree_files_fetched = fetched;
    Ok(match walk {
        Walk::Listed(list) => Listing::Listed(list),
        Walk::Refused(_) => Listing::Refused,
        Walk::Suspended => Listing::Suspended,
    })
}

fn fetch_tree_file(
    site: &mut impl Site,
    held: &mut impl Held,
    publisher: &str,
    name: &str,
    hex: &str,
    bounds: &TreeBounds,
    fetched: &mut Vec<String>,
) -> Result<TreeFetch> {
    if let Some(octets) = held.tree_file(publisher, name, hex)? {
        return Ok(TreeFetch::Octets(octets));
    }
    let answer = site.fetch(&Request {
        object: Object::TreeFile {
            collection: name,
            hex,
        },
        bound: bounds.tree_file_cap_bytes(),
        validator: None,
    })?;
    if answer == Answer::Suspended {
        return Ok(TreeFetch::Suspended);
    }
    fetched.push(hex.to_owned());
    let Answer::Octets { octets, .. } = answer else {
        return Ok(TreeFetch::Failed);
    };
    if octets.len() as u64 <= bounds.tree_file_cap_bytes()
        && hex_encode(&Sha256::digest(&octets)) == hex
    {
        held.hold_tree_file(publisher, name, hex, &octets)?;
    }
    Ok(TreeFetch::Octets(octets))
}

fn item_report(url: &str, item_id: &str, outcome: ItemOutcome) -> ItemReport {
    ItemReport {
        url: url.into(),
        item: item_id.into(),
        outcome,
        codes: Vec::new(),
        payload: None,
        payload_code: None,
    }
}

fn not_admitted(
    url: &str,
    item_id: &str,
    payload: PayloadSource,
    payload_code: Option<&'static str>,
) -> ItemReport {
    ItemReport {
        codes: vec![NOT_ADMITTED],
        payload: Some(payload),
        payload_code,
        ..item_report(url, item_id, ItemOutcome::NotAdmitted)
    }
}

#[allow(clippy::too_many_arguments)]
fn judge_items(
    state: &mut State,
    site: &mut impl Site,
    held: &mut impl Held,
    context: &Context<'_>,
    catalog: &Catalog,
    catalog_id: &str,
    list: &[Value],
    sources: &[&Source],
    out: &mut Vec<ItemReport>,
    retry: bool,
) -> Result<bool> {
    let caps = context.parameters.size_caps()?;
    let list_key = (
        context.publisher.to_owned(),
        catalog.collection.clone(),
        catalog_id.to_owned(),
    );
    if !state.lists.contains_key(&list_key) {
        state.lists.insert(list_key.clone(), unjudged(list)?);
    }
    for (index, item) in list.iter().enumerate() {
        let admitted = state.lists[&list_key]
            .get(index)
            .is_some_and(|status| status.admission == Admission::Admitted);
        if retry && admitted {
            continue;
        }
        let Some(report) = judge_item(state, site, held, context, catalog, item, sources, &caps)?
        else {
            return Ok(true);
        };
        if let Some(status) = state
            .lists
            .get_mut(&list_key)
            .and_then(|statuses| statuses.get_mut(index))
        {
            status.admission = match report.outcome {
                ItemOutcome::Admitted => Admission::Admitted,
                ItemOutcome::NotAdmitted => Admission::NotAdmitted,
                ItemOutcome::Refused => Admission::Refused,
            };
            status.code = report.codes.first().map(|code| code.to_string());
        }
        out.push(report);
    }
    Ok(false)
}

/// WIST-2 §5.1 step 4.
#[allow(clippy::too_many_arguments)]
fn judge_item(
    state: &State,
    site: &mut impl Site,
    held: &mut impl Held,
    context: &Context<'_>,
    catalog: &Catalog,
    item: &Value,
    sources: &[&Source],
    caps: &SizeCaps,
) -> Result<Option<ItemReport>> {
    let url = item["url"].as_str().unwrap_or_default();
    let item_id = item::item_id(item)?;
    let page = item::kind(item) == item::Kind::Page;
    if item::check_form(item).is_ok() && page && state.withdrawals.is_withdrawn(&item_id) {
        return Ok(Some(not_admitted(
            url,
            &item_id,
            PayloadSource::Withdrawn,
            None,
        )));
    }
    let judged: Vec<std::result::Result<(), &'static str>> = sources
        .iter()
        .map(|source| item::judge(item, catalog, &source.publisher, caps))
        .collect();
    if judged.iter().all(std::result::Result::is_err) {
        let codes: BTreeSet<&'static str> = judged.iter().filter_map(|r| r.err()).collect();
        return Ok(Some(ItemReport {
            codes: codes.into_iter().collect(),
            ..item_report(url, &item_id, ItemOutcome::Refused)
        }));
    }
    if !page {
        return Ok(Some(item_report(url, &item_id, ItemOutcome::Admitted)));
    }
    if state
        .record(context.publisher, url)
        .is_some_and(|record| record.item_id == item_id)
    {
        return Ok(Some(ItemReport {
            payload: Some(PayloadSource::Record),
            ..item_report(url, &item_id, ItemOutcome::Admitted)
        }));
    }
    let page_item: PageItem = serde_json::from_value(item.clone())?;
    let admitted = |payload| ItemReport {
        payload: Some(payload),
        ..item_report(url, &item_id, ItemOutcome::Admitted)
    };
    if let Some(octets) = held.payload(&item_id)? {
        return Ok(Some(
            match item::judge_payload_octets(&page_item, &octets, caps) {
                Ok(()) => admitted(PayloadSource::Held),
                Err(code) => not_admitted(url, &item_id, PayloadSource::Failed, Some(code)),
            },
        ));
    }
    let bound = crate::payload::cap_bytes(caps);
    let hex = item::payload_name(item)?;
    let answer = site.fetch(&Request {
        object: Object::Payload {
            collection: &catalog.collection,
            hex: &hex,
        },
        bound,
        validator: None,
    })?;
    Ok(Some(match answer {
        Answer::Suspended => return Ok(None),
        Answer::Octets { octets, .. } if octets.len() as u64 <= bound => {
            match item::judge_payload_octets(&page_item, &octets, caps) {
                Ok(()) => {
                    held.hold_payload(&item_id, &octets)?;
                    admitted(PayloadSource::Fetched)
                }
                Err(code) => not_admitted(url, &item_id, PayloadSource::Failed, Some(code)),
            }
        }
        _ => not_admitted(url, &item_id, PayloadSource::Unavailable, None),
    }))
}

struct Candidate {
    collection: String,
    index: u64,
    item_id: String,
    covered: bool,
    generated_at: String,
    catalog_id: String,
}

fn prefer(candidate: &Candidate, held: &Candidate) -> Result<bool> {
    Ok(match candidate.covered.cmp(&held.covered) {
        Ordering::Equal => {
            wist_core::several_logs::catalog_order(
                (&candidate.generated_at, &candidate.catalog_id),
                (&held.generated_at, &held.catalog_id),
            )? == Ordering::Greater
        }
        order => order == Ordering::Greater,
    })
}

fn reads_against_no_record(collection: &CollectionState) -> bool {
    collection.accepted.as_ref().is_some_and(|accepted| {
        !accepted.failed_c1
            && accepted.base_against_floor
            && collection
                .latest
                .as_ref()
                .is_none_or(|latest| latest.catalog_id != accepted.catalog_id)
    })
}

/// WIST-3 §3.3, I7.
fn i7_holds(state: &State, publisher: &str, name: &str, status: &ListItem, base: bool) -> bool {
    let record = state
        .record(publisher, &status.url)
        .filter(|record| !(base && record.collection == name));
    match status.kind {
        ItemKind::Page => {
            record.is_none_or(|record| record.item_id != status.item_id)
                && !state.withdrawals.is_withdrawn(&status.item_id)
        }
        ItemKind::Removed => record.is_some(),
    }
}

/// WIST-3 §3.3: a URL takes its place at the pull from which it waits.
fn refresh_waiting(
    state: &mut State,
    held: &impl Held,
    publisher: &str,
    event: u64,
    order: &BTreeMap<String, u64>,
) -> Result<()> {
    let in_force = state
        .declarations
        .domains()
        .get(publisher)
        .map(|domain| declaration::publisher_of(domain.current().envelope()))
        .transpose()
        .map_err(Error::History)?;
    let mut candidates: BTreeMap<String, Candidate> = BTreeMap::new();
    for name in state.collection_names(publisher) {
        let Some(collection) = state.collection(publisher, &name) else {
            continue;
        };
        let Some((envelope, catalog_id)) = collection.last_accepted() else {
            continue;
        };
        let Some(statuses) = state.list(publisher, &name, catalog_id) else {
            continue;
        };
        if held.list(publisher, &name, catalog_id)?.is_none() {
            continue;
        }
        let base = reads_against_no_record(collection);
        let generated_at = envelope["catalog"]["generated_at"]
            .as_str()
            .unwrap_or_default();
        for (index, status) in statuses.iter().enumerate() {
            if status.admission != Admission::Admitted
                || !i7_holds(state, publisher, &name, status, base)
            {
                continue;
            }
            let candidate = Candidate {
                collection: name.clone(),
                index: index as u64,
                item_id: status.item_id.clone(),
                covered: in_force
                    .as_ref()
                    .is_some_and(|declaration| collection::covers(declaration, &name, &status.url)),
                generated_at: generated_at.to_owned(),
                catalog_id: catalog_id.to_owned(),
            };
            let replaces = match candidates.get(&status.url) {
                Some(held) => prefer(&candidate, held)?,
                None => true,
            };
            if replaces {
                candidates.insert(status.url.clone(), candidate);
            }
        }
    }
    let next_epoch = state.first_epoch_after();
    state
        .urls
        .retain(|(p, url), _| p != publisher || candidates.contains_key(url));
    let fallback = order.len() as u64;
    for (url, candidate) in candidates {
        let position = order
            .get(&candidate.collection)
            .copied()
            .unwrap_or(fallback);
        state
            .urls
            .entry((publisher.to_owned(), url))
            .and_modify(|waiting| {
                waiting.collection.clone_from(&candidate.collection);
                waiting.item_id.clone_from(&candidate.item_id);
            })
            .or_insert(WaitingUrl {
                collection: candidate.collection.clone(),
                item_id: candidate.item_id.clone(),
                place: Place::url(event, position, candidate.index),
                eligibility: next_epoch,
            });
    }
    Ok(())
}
