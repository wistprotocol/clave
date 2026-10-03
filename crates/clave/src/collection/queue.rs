use super::pull::{self, Parameters};
use super::site::Held;
use super::state::{AcceptedCatalog, Place, QueuedCatalog, RecoveryQueue, State, WaitingUrl};
use crate::error::{Error, Result};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use wist_core::catalog::{self, Attempt};
use wist_core::declaration;
use wist_core::objects::Publisher;
use wist_core::timestamp::log_seconds;

pub const REJECTED: &str = "WIST1-E13";
pub const REGRESSED: &str = "WIST2-E05";
const NO_CANDIDATE: &str = "WIST1-E02";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettledOutcome {
    Survivor,
    NotLatest,
    Regressed,
    Rejected(&'static str),
}

impl SettledOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            SettledOutcome::Survivor => "survivor",
            SettledOutcome::NotLatest => "not_latest",
            SettledOutcome::Regressed => REGRESSED,
            SettledOutcome::Rejected(_) => REJECTED,
        }
    }

    pub fn condition_code(self) -> Option<&'static str> {
        match self {
            SettledOutcome::Rejected(code) => Some(code),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub publisher: String,
    pub collection: String,
    pub key: String,
    pub catalog: String,
    pub place: Place,
    pub outcome: SettledOutcome,
}

pub(super) struct Settling<'a> {
    pub source: Option<&'a Publisher>,
    pub order: Option<&'a Publisher>,
    pub clock: &'a str,
    pub parameters: &'a Parameters,
    pub eligibility: u64,
    pub event: u64,
    pub waited: Option<BTreeMap<String, u64>>,
}

fn generated_at(queued: &QueuedCatalog) -> Result<&str> {
    queued.envelope["catalog"]["generated_at"]
        .as_str()
        .ok_or_else(|| Error::History("a queued Catalog without generated_at".into()))
}

/// WIST-1 §3.5, the Catalog order.
fn later(queued: &QueuedCatalog, other: &QueuedCatalog) -> Result<bool> {
    Ok(wist_core::several_logs::catalog_order(
        (generated_at(queued)?, &queued.catalog_id),
        (generated_at(other)?, &other.catalog_id),
    )? == Ordering::Greater)
}

/// WIST-1 §5.2, Queue.
pub(super) fn enqueue(
    queue: &mut RecoveryQueue,
    name: &str,
    key: &str,
    entry: QueuedCatalog,
) -> Result<()> {
    let first = queue.first.entry(name.to_owned()).or_insert(entry.place);
    *first = (*first).min(entry.place);
    let slot = (name.to_owned(), key.to_owned());
    let replaces = match queue.queued.get(&slot) {
        Some(queued) => later(&entry, queued)?,
        None => true,
    };
    if replaces {
        queue.queued.insert(slot, entry);
    }
    Ok(())
}

/// WIST-1 §5.2, Queue.
fn absorb(state: &mut State, publisher: &str) -> Result<BTreeMap<String, u64>> {
    let mut waited = BTreeMap::new();
    for name in state.collection_names(publisher) {
        let key = (publisher.to_owned(), name.clone());
        let Some(waiting) = state.collections[&key].waiting().cloned() else {
            continue;
        };
        waited.insert(name.clone(), waiting.eligibility);
        let queue = state.queues.entry(publisher.to_owned()).or_default();
        enqueue(
            queue,
            &name,
            &waiting.key,
            QueuedCatalog {
                envelope: waiting.envelope,
                catalog_id: waiting.catalog_id,
                place: waiting.place,
                sources: waiting.read,
            },
        )?;
        if let Some(collection) = state.collections.get_mut(&key) {
            collection.accepted = None;
        }
    }
    Ok(waited)
}

pub(super) fn open_discovery(state: &mut State, publisher: &str, owner: &str) {
    state
        .queues
        .entry(publisher.to_owned())
        .or_insert_with(|| RecoveryQueue {
            owner: owner.to_owned(),
            ..RecoveryQueue::default()
        });
}

/// WIST-1 §5.2, Publications during recovery.
pub(super) fn open_windows(state: &mut State) -> Result<()> {
    let opening: Vec<(String, String, i128)> = state
        .declarations
        .domains()
        .iter()
        .filter_map(|(domain, sealed)| {
            sealed.window().map(|window| {
                (
                    domain.clone(),
                    window.owner().hash().to_owned(),
                    window.end_s(),
                )
            })
        })
        .filter(|(domain, _, _)| !state.window_holds(domain))
        .collect();
    for (publisher, owner, end_s) in opening {
        let queue = state.queues.entry(publisher.clone()).or_default();
        queue.owner = owner;
        queue.end_s = Some(end_s);
        absorb(state, &publisher)?;
    }
    Ok(())
}

fn drop_discovered(state: &mut State, publisher: &str, hashes: BTreeSet<String>) {
    let Some(found) = state.discovered.get_mut(publisher) else {
        return;
    };
    let mut gone = hashes;
    loop {
        let grown: Vec<String> = found
            .iter()
            .filter(|found| {
                !gone.contains(&found.hash)
                    && found.envelope["publisher"]["prev_declaration"]
                        .as_str()
                        .is_some_and(|prev| gone.contains(prev))
            })
            .map(|found| found.hash.clone())
            .collect();
        if grown.is_empty() {
            break;
        }
        gone.extend(grown);
    }
    found.retain(|found| !gone.contains(&found.hash));
    if found.is_empty() {
        state.discovered.remove(publisher);
        if !state.declarations.domains().contains_key(publisher) {
            state.floors.remove(publisher);
        }
    }
}

/// WIST-1 §5.2, Unsealed Declarations at settlement.
pub(super) fn supersede(state: &mut State, publisher: &str) {
    let ended = state
        .declarations
        .domains()
        .get(publisher)
        .and_then(|domain| domain.window())
        .map(|window| window.owner().hash().to_owned());
    let competitors: BTreeSet<String> = state
        .discovered
        .get(publisher)
        .into_iter()
        .flatten()
        .filter(|found| {
            found.competitor
                && found
                    .competes_with
                    .as_ref()
                    .is_none_or(|owner| Some(owner) == ended.as_ref())
        })
        .map(|found| found.hash.clone())
        .collect();
    if !competitors.is_empty() {
        drop_discovered(state, publisher, competitors);
    }
}

pub(super) fn sealed_window_ended(state: &State, publisher: &str, at_s: i64) -> bool {
    state
        .declarations
        .domains()
        .get(publisher)
        .and_then(|domain| domain.window())
        .is_some_and(|window| i128::from(at_s) >= window.end_s())
}

pub(super) fn due(state: &State, publisher: &str, at_s: i64) -> bool {
    state
        .queues
        .get(publisher)
        .and_then(|queue| queue.end_s)
        .is_some_and(|end_s| i128::from(at_s) >= end_s)
}

pub(super) fn settlement_source(state: &State, publisher: &str) -> Result<Publisher> {
    let window = state
        .declarations
        .domains()
        .get(publisher)
        .and_then(|domain| domain.window())
        .ok_or_else(|| Error::History(format!("{publisher} settles no window of the Log")))?;
    declaration::publisher_of(window.head().envelope()).map_err(Error::History)
}

/// WIST-1 §5.2, Settlement.
pub(super) fn settle(
    state: &mut State,
    held: &impl Held,
    publisher: &str,
    settling: &Settling<'_>,
) -> Result<Vec<Settled>> {
    let Some(queue) = state.queues.remove(publisher) else {
        return Ok(Vec::new());
    };
    let skew = settling.parameters.value("clock_skew_seconds")?;
    let items_max = settling.parameters.value("catalog_items_max")?;
    let attempt = settling
        .source
        .map(|source| Attempt::new(source, settling.clock, skew, items_max))
        .transpose()?;
    let mut rows: Vec<(&(String, String), &QueuedCatalog)> = queue.queued.iter().collect();
    rows.sort_by(|a, b| (a.1.place, &a.0 .1).cmp(&(b.1.place, &b.0 .1)));
    let mut results = Vec::new();
    let mut survivors: BTreeMap<String, (String, &QueuedCatalog)> = BTreeMap::new();
    for ((name, key), queued) in rows {
        let floor = state
            .collection(publisher, name)
            .and_then(|collection| collection.floor())
            .map(log_seconds)
            .transpose()?;
        let at = log_seconds(generated_at(queued)?)?;
        let outcome = if floor.is_some_and(|floor| at <= floor) {
            SettledOutcome::Regressed
        } else {
            match attempt
                .as_ref()
                .map(|attempt| catalog::judge(&queued.envelope, attempt))
            {
                None => SettledOutcome::Rejected(NO_CANDIDATE),
                Some(Err(code)) => SettledOutcome::Rejected(code),
                Some(Ok(_)) => {
                    let better = match survivors.get(name) {
                        Some((_, survivor)) => later(queued, survivor)?,
                        None => true,
                    };
                    if better {
                        survivors.insert(name.clone(), (key.clone(), queued));
                    }
                    SettledOutcome::Survivor
                }
            }
        };
        results.push(Settled {
            publisher: publisher.to_owned(),
            collection: name.clone(),
            key: key.clone(),
            catalog: queued.catalog_id.clone(),
            place: queued.place,
            outcome,
        });
    }
    for result in &mut results {
        let chosen = survivors
            .get(&result.collection)
            .is_some_and(|(key, _)| *key == result.key);
        if result.outcome == SettledOutcome::Survivor && !chosen {
            result.outcome = SettledOutcome::NotLatest;
        }
    }
    let mut names: BTreeSet<String> = state.collection_names(publisher).into_iter().collect();
    names.extend(queue.queued.keys().map(|(name, _)| name.clone()));
    for name in names {
        let collection = state
            .collections
            .entry((publisher.to_owned(), name.clone()))
            .or_default();
        collection.accepted = match survivors.get(&name) {
            Some((key, queued)) => {
                let generated_at = queued.envelope["catalog"]["generated_at"]
                    .as_str()
                    .unwrap_or_default();
                let place = queue.first_place(&name).unwrap_or(queued.place);
                let eligibility = settling
                    .waited
                    .as_ref()
                    .and_then(|waited| waited.get(&name).copied())
                    .unwrap_or(settling.eligibility);
                Some(AcceptedCatalog {
                    envelope: queued.envelope.clone(),
                    catalog_id: queued.catalog_id.clone(),
                    key: key.clone(),
                    base_against_floor: wist_core::sealing::base_against_floor(
                        generated_at,
                        collection.floor(),
                    )?,
                    failed_c1: false,
                    failed_c4: false,
                    place,
                    eligibility,
                    read: queued.sources.clone(),
                })
            }
            None => None,
        };
    }
    supersede(state, publisher);
    let frozen: BTreeMap<String, WaitingUrl> = state
        .urls
        .iter()
        .filter(|((owner, _), _)| owner == publisher)
        .map(|((_, url), waiting)| (url.clone(), waiting.clone()))
        .collect();
    state.urls.retain(|(owner, _), _| owner != publisher);
    let candidates = pull::waiting_candidates(state, held, publisher, settling.order)?;
    let order = pull::place_order(state, publisher, settling.order, &[]);
    let fallback = order.len() as u64;
    for (url, candidate) in candidates {
        let (place, eligibility) = match frozen.get(&url) {
            Some(waited) => (
                waited.place,
                match settling.waited {
                    Some(_) => waited.eligibility,
                    None => settling.eligibility,
                },
            ),
            None => {
                let place = match survivors.get(&candidate.collection) {
                    Some((_, queued)) => {
                        Place::url(queued.place.event, queued.place.position, candidate.index)
                    }
                    None => Place::url(
                        settling.event,
                        order
                            .get(&candidate.collection)
                            .copied()
                            .unwrap_or(fallback),
                        candidate.index,
                    ),
                };
                (place, settling.eligibility)
            }
        };
        state.urls.insert(
            (publisher.to_owned(), url),
            WaitingUrl {
                collection: candidate.collection,
                item_id: candidate.item_id,
                place,
                eligibility,
            },
        );
    }
    Ok(results)
}

/// WIST-1 §5.2, Discovery.
pub(super) fn settle_orphans(
    state: &mut State,
    held: &impl Held,
    clock: &str,
    parameters: &Parameters,
    eligibility: u64,
    event: u64,
) -> Result<Vec<Settled>> {
    let orphans: Vec<String> = state
        .queues
        .iter()
        .filter(|(publisher, queue)| {
            !queue.opened()
                && !state
                    .discovered
                    .get(*publisher)
                    .is_some_and(|found| found.iter().any(|found| found.hash == queue.owner))
        })
        .map(|(publisher, _)| publisher.clone())
        .collect();
    let mut results = Vec::new();
    for publisher in orphans {
        let source = pull::log_declaration(state, &publisher)?;
        let waited = absorb(state, &publisher)?;
        results.extend(settle(
            state,
            held,
            &publisher,
            &Settling {
                source: source.as_ref(),
                order: source.as_ref(),
                clock,
                parameters,
                eligibility,
                event,
                waited: Some(waited),
            },
        )?);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection::MemoryHeld;

    #[test]
    fn a_queue_of_a_publisher_with_no_declaration_in_force_settles_with_every_catalog_failing_c1() {
        let mut state = State::default();
        let mut queue = RecoveryQueue {
            owner: "sha256:gone".into(),
            ..RecoveryQueue::default()
        };
        enqueue(
            &mut queue,
            "default",
            "key",
            QueuedCatalog {
                envelope: serde_json::json!({"catalog": {"generated_at": "2026-08-09T12:00:00Z"}}),
                catalog_id: "sha256:queued".into(),
                place: Place::catalog(0, 0),
                sources: Vec::new(),
            },
        )
        .unwrap();
        state.queues.insert("example.com".into(), queue);
        let settled = settle_orphans(
            &mut state,
            &MemoryHeld::default(),
            "2026-08-09T13:00:00Z",
            &Parameters::default(),
            1,
            2,
        )
        .unwrap();
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].catalog, "sha256:queued");
        assert_eq!(settled[0].outcome, SettledOutcome::Rejected("WIST1-E02"));
        assert!(state.queues.is_empty());
        assert!(state
            .collection("example.com", "default")
            .is_some_and(|collection| collection.accepted.is_none()));
    }
}
