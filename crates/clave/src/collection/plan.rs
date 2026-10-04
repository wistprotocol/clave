use super::pull::{self, Parameters};
use super::queue::{self, Settled, Settling};
use super::site::Held;
use super::state::{
    Admission, CollectionKey, ItemKind, LabelKind, Place, Record, Removal, SealedCatalog, State,
};
use crate::error::{Error, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use wist_core::crypto::PublicKey;
use wist_core::declaration;
use wist_core::item;
use wist_core::objects::{
    CollectionEntry, PageItem, Publisher, RecordEntry, RemovalEntry, StateEntry,
};
use wist_core::sealing::{Condition, Epoch, Failure, Judgment, Outcome, Removed, Replay};
use wist_core::suffix_list::{registrable_domain, SuffixList};

const CANDIDATE_ROOT: &str = "candidate";
const NOT_ADMITTED: &str = "WIST2-E03";
const CONTRACT_FAILED: &str = "WIST4-E04";
const ITEM_OVER_BOUND: &str = "WIST1-E04";
const ENTRY_OVER_BOUND: &str = "WIST3-E03";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inclusion {
    rows: Vec<(u64, u64)>,
}

impl Inclusion {
    pub fn constant(max_inclusion_epochs: u64) -> Self {
        Inclusion {
            rows: vec![(0, max_inclusion_epochs)],
        }
    }

    pub fn schedule(rows: Vec<(u64, u64)>) -> Result<Self> {
        let ascending = rows.windows(2).all(|pair| pair[0].0 < pair[1].0);
        if rows.first().map(|row| row.0) != Some(0) || !ascending {
            return Err(Error::Param(
                "an inclusion schedule starts at height 0 and ascends".into(),
            ));
        }
        Ok(Inclusion { rows })
    }

    pub fn at(&self, height: u64) -> u64 {
        self.rows
            .iter()
            .rev()
            .find(|(start, _)| *start <= height)
            .map_or(0, |(_, value)| *value)
    }

    /// WIST-3 §3.3, Eligibility; WIST-4 §5.
    pub fn ceiling(&self, eligibility: u64) -> u64 {
        eligibility.saturating_add(self.at(eligibility))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unsealed {
    Catalog {
        publisher: String,
        collection: String,
    },
    Item {
        publisher: String,
        url: String,
    },
    Label {
        id: String,
    },
}

pub struct EpochInput<'a> {
    pub height: u64,
    pub sealed_at: &'a str,
    pub parameters: &'a Parameters,
    pub inclusion: &'a Inclusion,
    pub suffix_list: Option<&'a SuffixList>,
    pub declarations: &'a [Value],
    pub updates: &'a [Value],
    pub unsealed: &'a BTreeSet<Unsealed>,
    pub log_key: &'a dyn Fn(&str) -> Option<PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publication {
    Catalog {
        publisher: String,
        collection: String,
        catalog: String,
    },
    Item {
        publisher: String,
        collection: String,
        url: String,
        item: String,
    },
    Label {
        kind: LabelKind,
        publisher: String,
        id: String,
    },
}

impl Publication {
    pub fn publisher(&self) -> &str {
        match self {
            Publication::Catalog { publisher, .. }
            | Publication::Item { publisher, .. }
            | Publication::Label { publisher, .. } => publisher,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deferral {
    RecoveryWindow,
    Capacity,
    CatalogWaiting,
    LatestFailsI4,
}

impl Deferral {
    pub fn as_str(self) -> &'static str {
        match self {
            Deferral::RecoveryWindow => "recovery_window",
            Deferral::Capacity => "capacity",
            Deferral::CatalogWaiting => "catalog_waiting",
            Deferral::LatestFailsI4 => "latest_fails_i4",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    AuthorityReduction,
    CatalogWaiting,
}

impl Hold {
    pub fn as_str(self) -> &'static str {
        match self {
            Hold::AuthorityReduction => "authority_reduction",
            Hold::CatalogWaiting => "catalog_waiting",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftCondition {
    C1,
    C4,
    I5,
    I7,
    Payload,
    EntrySize,
}

impl LeftCondition {
    pub fn as_str(self) -> &'static str {
        match self {
            LeftCondition::C1 => "C1",
            LeftCondition::C4 => "C4",
            LeftCondition::I5 => "I5",
            LeftCondition::I7 => "I7",
            LeftCondition::Payload => "payload",
            LeftCondition::EntrySize => "entry_size",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub publication: Publication,
    pub catalog: Option<String>,
    pub eligibility: u64,
    pub ceiling: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferred {
    pub publication: Publication,
    pub place: Place,
    pub reasons: Vec<Deferral>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldBack {
    pub publication: Publication,
    pub place: Place,
    pub reason: Hold,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Left {
    pub publication: Publication,
    pub condition: LeftCondition,
    pub codes: Vec<&'static str>,
    pub reported: bool,
    pub payload_code: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftUnsealed {
    pub publication: Publication,
    pub place: Place,
    pub ceiling: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelRejection {
    pub id: String,
    pub code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationFailure {
    pub declaration: String,
    pub code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationLeft {
    pub declaration: String,
    pub names: String,
    pub code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRefused {
    pub item_id: String,
    pub subject: String,
    pub code: &'static str,
}

#[derive(Debug, Clone)]
pub struct Planned {
    pub event: u64,
    pub settlement: Vec<Settled>,
    pub entries: Vec<Value>,
    pub sealed: Vec<Sealed>,
    pub left: Vec<Left>,
    pub deferred: Vec<Deferred>,
    pub held: Vec<HeldBack>,
    pub held_late: Vec<LeftUnsealed>,
    pub unsealed: Vec<LeftUnsealed>,
    pub rejections: Vec<LabelRejection>,
    pub declarations_failed: Vec<DeclarationFailure>,
    pub declarations_left: Vec<DeclarationLeft>,
    pub updates_refused: Vec<UpdateRefused>,
    pub records_removed: Vec<Removed>,
    pub payloads_destroyed: Vec<String>,
    pub state: State,
}

type PlaceKey = (u64, String, u64, Option<u64>);

type TurnKey = (u8, PlaceKey);

fn place_key(place: Place, publisher: &str) -> PlaceKey {
    (
        place.event,
        publisher.to_owned(),
        place.position,
        place.index,
    )
}

fn kind_turn(kind: ItemKind) -> u8 {
    match kind {
        ItemKind::Removed => 1,
        ItemKind::Page => 2,
    }
}

fn item_kind(item: &Value) -> ItemKind {
    match item::kind(item) {
        item::Kind::Page => ItemKind::Page,
        item::Kind::Removed => ItemKind::Removed,
    }
}

fn history(message: impl Into<String>) -> Error {
    Error::History(message.into())
}

/// WIST-3 §3.3, An Entry fits one leaf.
fn over_entry_bound(entry: &Value) -> Result<bool> {
    Ok(wist_core::jcs::canonicalize(entry)?.len() as u64 > wist_core::tiles::ENTRY_MAX_BYTES)
}

fn declaration_entry(envelope: &Value) -> Value {
    json!({"type": "publisher_declaration", "body": envelope})
}

fn canonical(entries: Vec<Value>) -> Result<(Vec<Value>, Vec<usize>)> {
    let mut keyed = entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let group = wist_core::epoch::entry_group(&entry)?;
            let (_, hash) = wist_core::epoch::entry_leaf(&entry)?;
            Ok(((group, hash), index, entry))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by_key(|(key, _, _)| *key);
    let origin = keyed.iter().map(|(_, index, _)| *index).collect();
    Ok((
        keyed.into_iter().map(|(_, _, entry)| entry).collect(),
        origin,
    ))
}

fn tuples(state: &State, publishers: &BTreeSet<String>) -> Vec<StateEntry> {
    let mut out = Vec::new();
    for ((publisher, name), collection) in &state.collections {
        if let (true, Some(latest)) = (publishers.contains(publisher), &collection.latest) {
            out.push(StateEntry::Collection(CollectionEntry {
                publisher: publisher.clone(),
                collection: name.clone(),
                envelope: latest.envelope.clone(),
                sealing_height: latest.sealing_height,
            }));
        }
    }
    for ((publisher, url), record) in &state.records {
        if publishers.contains(publisher) {
            out.push(StateEntry::Record(RecordEntry {
                publisher: publisher.clone(),
                url: url.clone(),
                item: record.item.clone(),
                collection: record.collection.clone(),
                catalog_id: record.catalog_id.clone(),
                generated_at: record.generated_at.clone(),
            }));
        }
    }
    for ((publisher, url), removal) in &state.removals {
        if publishers.contains(publisher) {
            out.push(StateEntry::Removal(RemovalEntry {
                publisher: publisher.clone(),
                url: url.clone(),
                item_id: removal.item_id.clone(),
                catalog_id: removal.catalog_id.clone(),
                generated_at: removal.generated_at.clone(),
            }));
        }
    }
    out.extend(
        state
            .withdrawals
            .entries()
            .into_iter()
            .map(StateEntry::Withdrawal),
    );
    out
}

fn changed_domains(state: &State, input: &EpochInput<'_>, entries: &[Value]) -> BTreeSet<String> {
    let declarations: Vec<Value> = entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_declaration")
        .cloned()
        .collect();
    let projected = (|| -> Result<_> {
        Ok(state.declarations.project(
            input.sealed_at,
            input.parameters.value("recovery_window_days")?,
            input.parameters.value("declaration_activation_epochs")?,
            &input.parameters.limits()?,
            &declarations,
        )?)
    })();
    let Ok(projection) = projected else {
        return BTreeSet::new();
    };
    let effects = projection.effects();
    effects
        .transitions
        .iter()
        .map(|transition| transition.domain.clone())
        .chain(effects.activations.iter().map(|a| a.domain.clone()))
        .chain(effects.settlements.iter().map(|s| s.domain.clone()))
        .collect()
}

fn judged_publishers(
    state: &State,
    entries: &[Value],
    mut out: BTreeSet<String>,
) -> BTreeSet<String> {
    for entry in entries {
        let body = &entry["body"];
        match entry["type"].as_str() {
            Some("publisher_catalog") => {
                if let Some(publisher) = body["catalog"]["publisher"].as_str() {
                    out.insert(publisher.to_owned());
                }
            }
            Some("publisher_item") => {
                if let Some(publisher) = body["item"]["publisher"].as_str() {
                    out.insert(publisher.to_owned());
                }
                let named = state.collections.iter().find(|(_, collection)| {
                    collection
                        .latest
                        .as_ref()
                        .is_some_and(|latest| body["catalog"] == latest.catalog_id.as_str())
                });
                if let Some(((publisher, _), _)) = named {
                    out.insert(publisher.clone());
                }
            }
            _ => {}
        }
    }
    out
}

pub struct Judged {
    pub outcome: Outcome,
    pub replay: Replay,
    pub publishers: BTreeSet<String>,
}

/// Resumed from the tuples of the Publishers the Epoch's Entries and transitions touch: no
/// other Publisher's state enters a judgment of WIST-3 §3.3.
pub fn judge(state: &State, input: &EpochInput<'_>, entries: &[Value]) -> Result<Judged> {
    let parameters = input.parameters.sealing()?;
    let publishers = judged_publishers(state, entries, changed_domains(state, input, entries));
    let mut replay = match state.height {
        None => Replay::new(),
        Some(height) => Replay::resumed(
            height,
            &wist_core::timestamp::instant(
                state
                    .declarations
                    .sealed_at_s()
                    .ok_or_else(|| history("a sealed Epoch without its sealed_at"))?,
            )?,
            state.declarations.clone(),
            &tuples(state, &publishers),
        )?,
    };
    let outcome = replay.epoch(&Epoch {
        height: input.height,
        root: CANDIDATE_ROOT,
        sealed_at: input.sealed_at,
        parameters: &parameters,
        suffix_list: input.suffix_list,
        log_key: input.log_key,
        entries,
    })?;
    Ok(Judged {
        outcome,
        replay,
        publishers,
    })
}

/// WIST-3 §3.3, Waiting.
pub fn verify(state: &State, input: &EpochInput<'_>, entries: &[Value]) -> Result<()> {
    match judge(state, input, entries)?.outcome {
        Outcome::Rejected { codes } => Err(Error::Seal(format!(
            "the planned Epoch {} is rejected: {}",
            input.height,
            codes.join(", ")
        ))),
        Outcome::Accepted {
            entries: judged, ..
        } => {
            match judged
                .iter()
                .position(|judgment| matches!(judgment, Some(Judgment::Ignored(_))))
            {
                Some(index) => Err(Error::Seal(format!(
                    "Entry {index} of the planned Epoch {} is ignored: {:?}",
                    input.height, judged[index]
                ))),
                None => Ok(()),
            }
        }
    }
}

fn absorb(next: &mut State, judged: &Judged, height: u64) {
    let replay = &judged.replay;
    next.declarations = replay.declarations().clone();
    next.withdrawals = replay.withdrawals().clone();
    for (publisher, name, latest) in replay.latest_catalogs() {
        if !judged.publishers.contains(publisher) {
            continue;
        }
        let collection = next
            .collections
            .entry((publisher.to_owned(), name.to_owned()))
            .or_default();
        let kept = collection
            .latest
            .as_ref()
            .filter(|old| old.catalog_id == latest.catalog_id)
            .map(|old| old.base);
        collection.latest = Some(SealedCatalog {
            envelope: latest.envelope.clone(),
            catalog_id: latest.catalog_id.clone(),
            sealing_height: latest.sealing_height,
            base: latest.base.or(kept).unwrap_or(false),
        });
    }
    for publisher in &judged.publishers {
        let own = |(p, _): &CollectionKey| p == publisher;
        let old: BTreeMap<CollectionKey, Record> = next
            .records
            .iter()
            .filter(|(key, _)| own(key))
            .map(|(key, record)| (key.clone(), record.clone()))
            .collect();
        next.records.retain(|key, _| !own(key));
        next.removals.retain(|key, _| !own(key));
        for (owner, url, record) in replay.records().records() {
            if owner != publisher {
                continue;
            }
            let key = (owner.to_owned(), url.to_owned());
            let sealing_height = old
                .get(&key)
                .filter(|old| old.item_id == record.item_id)
                .map_or(height, |old| old.sealing_height);
            next.records.insert(
                key,
                Record {
                    item: record.item.clone(),
                    item_id: record.item_id.clone(),
                    collection: record.collection.clone(),
                    catalog_id: record.catalog.clone(),
                    generated_at: record.generated_at.clone(),
                    sealing_height,
                },
            );
        }
        for (owner, url, removal) in replay.records().removals() {
            if owner == publisher {
                next.removals.insert(
                    (owner.to_owned(), url.to_owned()),
                    Removal {
                        item_id: removal.item_id.clone(),
                        catalog_id: removal.catalog.clone(),
                        generated_at: removal.generated_at.clone(),
                    },
                );
            }
        }
    }
}

type ListKey = (String, String, String);

#[derive(Default)]
struct Lists {
    held: BTreeMap<ListKey, (Vec<Value>, BTreeMap<String, usize>)>,
}

impl Lists {
    fn get(
        &mut self,
        held: &impl Held,
        publisher: &str,
        name: &str,
        catalog_id: &str,
        catalog: Option<&Value>,
    ) -> Result<&(Vec<Value>, BTreeMap<String, usize>)> {
        let key = (publisher.to_owned(), name.to_owned(), catalog_id.to_owned());
        if !self.held.contains_key(&key) {
            let list = match held.list(publisher, name, catalog_id)? {
                Some(list) => Some(list),
                None => match catalog {
                    Some(inner) => held.list_with_root(
                        publisher,
                        name,
                        inner["size"].as_u64().unwrap_or_default(),
                        inner["root"].as_str().unwrap_or_default(),
                    )?,
                    None => None,
                },
            }
            .ok_or_else(|| {
                history(format!(
                    "no list is held for Catalog {catalog_id} of {publisher} {name}"
                ))
            })?;
            let index = list
                .iter()
                .enumerate()
                .filter_map(|(at, item)| item["url"].as_str().map(|url| (url.to_owned(), at)))
                .collect();
            self.held.insert(key.clone(), (list, index));
        }
        Ok(&self.held[&key])
    }
}

fn last_accepted_id(state: &State, publisher: &str, name: &str) -> Option<String> {
    state
        .collection(publisher, name)
        .and_then(|collection| collection.last_accepted())
        .map(|(_, catalog_id)| catalog_id.to_owned())
}

fn waiting_item(
    state: &State,
    held: &impl Held,
    lists: &mut Lists,
    publisher: &str,
    url: &str,
) -> Result<(Value, usize)> {
    let waiting = &state.urls[&(publisher.to_owned(), url.to_owned())];
    let catalog_id = last_accepted_id(state, publisher, &waiting.collection)
        .ok_or_else(|| history(format!("{url} waits with no last accepted Catalog")))?;
    let (list, index) = lists.get(held, publisher, &waiting.collection, &catalog_id, None)?;
    let at = *index
        .get(url)
        .ok_or_else(|| history(format!("{url} waits with no Item in its list")))?;
    Ok((list[at].clone(), at))
}

fn item_read(state: &State, publisher: &str, url: &str) -> Vec<String> {
    let waiting = &state.urls[&(publisher.to_owned(), url.to_owned())];
    last_accepted_id(state, publisher, &waiting.collection)
        .and_then(|catalog_id| state.list(publisher, &waiting.collection, &catalog_id))
        .and_then(|statuses| {
            statuses
                .iter()
                .find(|status| status.url == url && status.item_id == waiting.item_id)
        })
        .map(|status| status.read.clone())
        .unwrap_or_default()
}

/// WIST-1 §5.2, Queue.
fn held_kind(state: &State, publisher: &str, url: &str) -> ItemKind {
    let waiting = &state.urls[&(publisher.to_owned(), url.to_owned())];
    state
        .lists
        .iter()
        .filter(|((owner, name, _), _)| owner == publisher && *name == waiting.collection)
        .flat_map(|(_, statuses)| statuses)
        .find(|status| status.url == url && status.item_id == waiting.item_id)
        .map_or(ItemKind::Page, |status| status.kind)
}

fn set_admission(
    state: &mut State,
    publisher: &str,
    name: &str,
    index: usize,
    admission: Admission,
    code: &str,
) {
    if let Some(catalog_id) = last_accepted_id(state, publisher, name) {
        if let Some(status) = state
            .lists
            .get_mut(&(publisher.to_owned(), name.to_owned(), catalog_id))
            .and_then(|statuses| statuses.get_mut(index))
        {
            status.admission = admission;
            status.code = Some(code.to_owned());
        }
    }
}

struct Turn<'a, 'b, H: Held> {
    input: &'a EpochInput<'b>,
    held: &'a H,
    caps: item::SizeCaps,
    capacity: u64,
    labeler_cap: u64,
    in_force: BTreeMap<String, Publisher>,
    windows: BTreeSet<String>,
    holding: BTreeSet<String>,
    kept_out: BTreeSet<String>,
    destroyed: BTreeSet<String>,
    deferred_i4: BTreeSet<CollectionKey>,
}

impl<H: Held> Turn<'_, '_, H> {
    fn ceiling(&self, eligibility: u64) -> u64 {
        self.input.inclusion.ceiling(eligibility)
    }

    /// WIST-3 §3.3, Declaration sealing obligation.
    fn reads_kept_out(&self, read: &[String]) -> bool {
        read.iter().any(|hash| self.kept_out.contains(hash))
    }

    fn unit(&self, publisher: &str) -> String {
        registrable_domain(publisher, self.input.suffix_list).domain
    }

    fn latest_fails_i4(&self, publisher: &str, name: &str, envelope: &Value) -> bool {
        match self.in_force.get(publisher) {
            None => true,
            Some(declaration) => {
                !wist_core::collection::names(declaration).contains(&name)
                    || wist_core::catalog::authenticate(envelope, declaration).is_err()
            }
        }
    }
}

struct PlannedEntry {
    publication: Publication,
    catalog: Option<String>,
    entry: Value,
    eligibility: u64,
}

#[derive(Default)]
struct Pass {
    planned: Vec<PlannedEntry>,
    deferred: Vec<Deferred>,
    holding: Vec<(HeldBack, u64)>,
    dropped: Vec<(TurnKey, Left)>,
    unsealed: Vec<LeftUnsealed>,
}

#[derive(Default)]
struct Room {
    domain: BTreeMap<String, u64>,
    labeler: BTreeMap<String, u64>,
}

enum Slot {
    Url(String, String),
    Label(String),
}

impl Slot {
    fn tie(&self) -> &str {
        match self {
            Slot::Url(_, url) => url,
            Slot::Label(id) => id,
        }
    }
}

fn run_pass<H: Held>(
    next: &mut State,
    turn: &Turn<'_, '_, H>,
    lists: &mut Lists,
    gone: &mut BTreeSet<CollectionKey>,
) -> Result<Pass> {
    let height = turn.input.height;
    let mut pass = Pass::default();
    let mut room = Room::default();
    let free = |room: &Room, publisher: &str| {
        room.domain
            .get(&turn.unit(publisher))
            .copied()
            .unwrap_or(turn.capacity)
    };
    let take = |room: &mut Room, publisher: &str| {
        let unit = turn.unit(publisher);
        let left = room.domain.get(&unit).copied().unwrap_or(turn.capacity);
        room.domain.insert(unit, left.saturating_sub(1));
    };
    let leave_unsealed = |pass: &mut Pass, publication: Publication, place: Place, eligibility| {
        pass.unsealed.push(LeftUnsealed {
            publication,
            place,
            ceiling: turn.ceiling(eligibility),
        });
        Ok::<(), Error>(())
    };
    let mut waiting: Vec<(PlaceKey, String, String)> = next
        .collections
        .iter()
        .filter_map(|((publisher, name), collection)| {
            collection
                .waiting()
                .filter(|waiting| waiting.eligibility <= height)
                .map(|waiting| {
                    (
                        place_key(waiting.place, publisher),
                        publisher.clone(),
                        name.clone(),
                    )
                })
        })
        .collect();
    waiting.sort();
    let mut sealed_names: BTreeMap<CollectionKey, (String, Value)> = BTreeMap::new();
    let mut deferred_names: BTreeSet<CollectionKey> = BTreeSet::new();
    for (_, publisher, name) in waiting {
        let key = (publisher.clone(), name.clone());
        let accepted = next.collections[&key]
            .accepted
            .clone()
            .ok_or_else(|| history("a waiting Catalog that is not accepted"))?;
        let publication = Publication::Catalog {
            publisher: publisher.clone(),
            collection: name.clone(),
            catalog: accepted.catalog_id.clone(),
        };
        let window = turn.windows.contains(&publisher);
        if !window && turn.holding.contains(&publisher) {
            pass.holding.push((
                HeldBack {
                    publication,
                    place: accepted.place,
                    reason: Hold::AuthorityReduction,
                },
                accepted.eligibility,
            ));
            continue;
        }
        let reasons = if window {
            vec![Deferral::RecoveryWindow]
        } else if free(&room, &publisher) == 0 {
            vec![Deferral::Capacity]
        } else {
            Vec::new()
        };
        if !reasons.is_empty() {
            pass.deferred.push(Deferred {
                publication,
                place: accepted.place,
                reasons,
            });
            deferred_names.insert(key);
            continue;
        }
        if turn.input.unsealed.contains(&Unsealed::Catalog {
            publisher: publisher.clone(),
            collection: name.clone(),
        }) || turn.reads_kept_out(&accepted.read)
        {
            leave_unsealed(&mut pass, publication, accepted.place, accepted.eligibility)?;
            continue;
        }
        let entry = json!({"type": "publisher_catalog", "body": accepted.envelope});
        if over_entry_bound(&entry)? {
            if let Some(waiting) = next
                .collections
                .get_mut(&key)
                .and_then(|collection| collection.accepted.as_mut())
            {
                waiting.failed_c1 = true;
            }
            pass.dropped.push((
                (0, place_key(accepted.place, &publisher)),
                Left {
                    publication,
                    condition: LeftCondition::EntrySize,
                    codes: vec![ENTRY_OVER_BOUND],
                    reported: true,
                    payload_code: None,
                },
            ));
            continue;
        }
        take(&mut room, &publisher);
        sealed_names.insert(
            key,
            (accepted.catalog_id.clone(), accepted.envelope.clone()),
        );
        pass.planned.push(PlannedEntry {
            publication,
            catalog: None,
            entry,
            eligibility: accepted.eligibility,
        });
    }
    for kind in [ItemKind::Removed, ItemKind::Page] {
        let mut candidates: Vec<(PlaceKey, Slot)> = Vec::new();
        let urls: Vec<(CollectionKey, Place, u64)> = next
            .urls
            .iter()
            .map(|(key, waiting)| (key.clone(), waiting.place, waiting.eligibility))
            .collect();
        for ((publisher, url), place, eligibility) in urls {
            let due = eligibility <= height || next.window_holds(&publisher);
            if gone.contains(&(publisher.clone(), url.clone())) || !due {
                continue;
            }
            let held_kind = if turn.windows.contains(&publisher) {
                held_kind(next, &publisher, &url)
            } else {
                item_kind(&waiting_item(next, turn.held, lists, &publisher, &url)?.0)
            };
            if held_kind == kind {
                candidates.push((place_key(place, &publisher), Slot::Url(publisher, url)));
            }
        }
        if kind == ItemKind::Page {
            for (id, label) in &next.labels {
                if label.eligibility <= height {
                    candidates.push((
                        place_key(label.place, &label.publisher),
                        Slot::Label(id.clone()),
                    ));
                }
            }
        }
        candidates.sort_by(|a, b| (&a.0, a.1.tie()).cmp(&(&b.0, b.1.tie())));
        for (key, slot) in candidates {
            let (publisher, url) = match slot {
                Slot::Label(id) => {
                    let label = next.labels[&id].clone();
                    let publication = Publication::Label {
                        kind: label.kind,
                        publisher: label.publisher.clone(),
                        id: id.clone(),
                    };
                    let unit = turn.unit(&label.publisher);
                    let labeler_free = room.labeler.get(&unit).copied().unwrap_or(turn.labeler_cap);
                    let reason = if turn.windows.contains(&label.publisher) {
                        Some(Deferral::RecoveryWindow)
                    } else if free(&room, &label.publisher) == 0 || labeler_free == 0 {
                        Some(Deferral::Capacity)
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        pass.deferred.push(Deferred {
                            publication,
                            place: label.place,
                            reasons: vec![reason],
                        });
                        continue;
                    }
                    if turn
                        .input
                        .unsealed
                        .contains(&Unsealed::Label { id: id.clone() })
                    {
                        leave_unsealed(&mut pass, publication, label.place, label.eligibility)?;
                        continue;
                    }
                    take(&mut room, &label.publisher);
                    room.labeler.insert(unit, labeler_free - 1);
                    pass.planned.push(PlannedEntry {
                        publication,
                        catalog: None,
                        entry: json!({"type": label.kind.as_str(), "body": label.envelope}),
                        eligibility: label.eligibility,
                    });
                    continue;
                }
                Slot::Url(publisher, url) => (publisher, url),
            };
            let waiting = next.urls[&(publisher.clone(), url.clone())].clone();
            let name = waiting.collection.clone();
            let collection_key = (publisher.clone(), name.clone());
            let publication = Publication::Item {
                publisher: publisher.clone(),
                collection: name.clone(),
                url: url.clone(),
                item: waiting.item_id.clone(),
            };
            let window = turn.windows.contains(&publisher);
            let mut reasons = if window {
                vec![Deferral::RecoveryWindow]
            } else {
                Vec::new()
            };
            let catalog_waits = next
                .collection(&publisher, &name)
                .is_some_and(|collection| collection.waiting().is_some());
            let catalog_unsealed = catalog_waits && !sealed_names.contains_key(&collection_key);
            let catalog_deferred = deferred_names.contains(&collection_key);
            if !window && catalog_unsealed && catalog_deferred {
                reasons.push(Deferral::CatalogWaiting);
            }
            let latest = sealed_names.get(&collection_key).cloned().or_else(|| {
                next.collection(&publisher, &name)
                    .and_then(|collection| collection.latest.as_ref())
                    .map(|latest| (latest.catalog_id.clone(), latest.envelope.clone()))
            });
            let undeferred_catalog = catalog_unsealed && !catalog_deferred;
            if let (false, false, Some((_, envelope))) = (window, undeferred_catalog, &latest) {
                if turn.deferred_i4.contains(&collection_key)
                    || turn.latest_fails_i4(&publisher, &name, envelope)
                {
                    reasons.push(Deferral::LatestFailsI4);
                }
            }
            if reasons.is_empty() && (turn.holding.contains(&publisher) || catalog_unsealed) {
                let reason = if turn.holding.contains(&publisher) {
                    Hold::AuthorityReduction
                } else {
                    Hold::CatalogWaiting
                };
                pass.holding.push((
                    HeldBack {
                        publication,
                        place: waiting.place,
                        reason,
                    },
                    waiting.eligibility,
                ));
                continue;
            }
            if reasons.is_empty() && free(&room, &publisher) == 0 {
                reasons.push(Deferral::Capacity);
            }
            if !reasons.is_empty() {
                pass.deferred.push(Deferred {
                    publication,
                    place: waiting.place,
                    reasons,
                });
                continue;
            }
            if turn.input.unsealed.contains(&Unsealed::Item {
                publisher: publisher.clone(),
                url: url.clone(),
            }) || turn.reads_kept_out(&item_read(next, &publisher, &url))
            {
                leave_unsealed(&mut pass, publication, waiting.place, waiting.eligibility)?;
                continue;
            }
            let (item, index) = waiting_item(next, turn.held, lists, &publisher, &url)?;
            if kind == ItemKind::Page {
                if let Err(payload_code) = payload_check(turn, &item, &waiting.item_id)? {
                    set_admission(
                        next,
                        &publisher,
                        &name,
                        index,
                        Admission::NotAdmitted,
                        NOT_ADMITTED,
                    );
                    gone.insert((publisher.clone(), url.clone()));
                    pass.dropped.push((
                        (kind_turn(kind), key),
                        Left {
                            publication,
                            condition: LeftCondition::Payload,
                            codes: vec![NOT_ADMITTED],
                            reported: true,
                            payload_code,
                        },
                    ));
                    continue;
                }
            }
            let (latest_id, latest_envelope) =
                latest.ok_or_else(|| history(format!("{url} waits with no latest Catalog")))?;
            let inner = &latest_envelope["catalog"];
            let catalog: wist_core::objects::Catalog = serde_json::from_value(inner.clone())?;
            let (list, positions) =
                lists.get(turn.held, &publisher, &name, &latest_id, Some(inner))?;
            let at = *positions
                .get(&url)
                .ok_or_else(|| history(format!("the latest Catalog does not list {url}")))?;
            let body = wist_core::publisher_item::build(list, at as u64, &catalog)?;
            let entry = json!({"type": "publisher_item", "body": body});
            if over_entry_bound(&entry)? {
                set_admission(
                    next,
                    &publisher,
                    &name,
                    index,
                    Admission::Refused,
                    ITEM_OVER_BOUND,
                );
                gone.insert((publisher.clone(), url.clone()));
                pass.dropped.push((
                    (kind_turn(kind), key),
                    Left {
                        publication,
                        condition: LeftCondition::EntrySize,
                        codes: vec![ITEM_OVER_BOUND],
                        reported: true,
                        payload_code: None,
                    },
                ));
                continue;
            }
            take(&mut room, &publisher);
            pass.planned.push(PlannedEntry {
                publication,
                catalog: Some(latest_id),
                entry,
                eligibility: waiting.eligibility,
            });
        }
    }
    Ok(pass)
}

/// WIST-3 §3.3: a Payload not held at the Item's turn fails the check.
fn payload_check<H: Held>(
    turn: &Turn<'_, '_, H>,
    item: &Value,
    item_id: &str,
) -> Result<std::result::Result<(), Option<&'static str>>> {
    let octets = if turn.destroyed.contains(item_id) {
        None
    } else {
        turn.held.payload(item_id)?
    };
    let Some(octets) = octets else {
        return Ok(Err(None));
    };
    let page: PageItem = serde_json::from_value(item.clone())?;
    Ok(item::judge_payload_octets(&page, &octets, &turn.caps).map_err(Some))
}

struct Candidates {
    envelopes: Vec<Value>,
    failed: Vec<DeclarationFailure>,
    left: Vec<DeclarationLeft>,
}

fn prev_declaration(envelope: &Value) -> Option<&str> {
    envelope["publisher"]["prev_declaration"].as_str()
}

/// WIST-1 §5.2, An accepted Declaration that fails at sealing.
fn candidate_checks(
    next: &mut State,
    envelopes: &[Value],
    limits: &wist_core::collection::Limits,
) -> Result<Candidates> {
    let mut failed: BTreeMap<String, &'static str> = BTreeMap::new();
    for envelope in envelopes {
        if let Err((code, _)) = declaration::validate_fields(envelope, Some(limits)) {
            failed.insert(
                declaration::inner_hash(envelope).map_err(Error::History)?,
                code,
            );
        }
    }
    if failed.is_empty() {
        return Ok(Candidates {
            envelopes: envelopes.to_vec(),
            failed: Vec::new(),
            left: Vec::new(),
        });
    }
    let mut known: Vec<(String, &Value)> = Vec::new();
    for envelope in next
        .discovered
        .values()
        .flatten()
        .map(|found| &found.envelope)
        .chain(envelopes)
    {
        known.push((
            declaration::inner_hash(envelope).map_err(Error::History)?,
            envelope,
        ));
    }
    let mut cause: BTreeMap<String, &'static str> = BTreeMap::new();
    for (hash, code) in &failed {
        let mut chain: BTreeSet<String> = BTreeSet::from([hash.clone()]);
        loop {
            let grown: Vec<String> = known
                .iter()
                .filter(|(own, envelope)| {
                    !chain.contains(own)
                        && prev_declaration(envelope).is_some_and(|prev| chain.contains(prev))
                })
                .map(|(own, _)| own.clone())
                .collect();
            if grown.is_empty() {
                break;
            }
            chain.extend(grown);
        }
        for descendant in chain {
            cause.entry(descendant).or_insert(code);
        }
    }
    let names: BTreeMap<String, String> = known
        .iter()
        .filter_map(|(own, envelope)| {
            prev_declaration(envelope).map(|prev| (own.clone(), prev.to_owned()))
        })
        .collect();
    let publishers: Vec<String> = next.discovered.keys().cloned().collect();
    for publisher in publishers {
        let found = next.discovered.entry(publisher.clone()).or_default();
        found.retain(|found| !cause.contains_key(&found.hash));
        if found.is_empty() {
            next.discovered.remove(&publisher);
            if !next.declarations.domains().contains_key(&publisher) {
                next.floors.remove(&publisher);
            }
        }
    }
    let left = cause
        .iter()
        .filter(|(hash, _)| !failed.contains_key(*hash))
        .map(|(hash, code)| DeclarationLeft {
            declaration: hash.clone(),
            names: names.get(hash).cloned().unwrap_or_default(),
            code,
        })
        .collect();
    let mut kept = Vec::new();
    for envelope in envelopes {
        if !cause.contains_key(&declaration::inner_hash(envelope).map_err(Error::History)?) {
            kept.push(envelope.clone());
        }
    }
    Ok(Candidates {
        envelopes: kept,
        failed: failed
            .into_iter()
            .map(|(declaration, code)| DeclarationFailure { declaration, code })
            .collect(),
        left,
    })
}

fn publishers(state: &State) -> BTreeSet<String> {
    state
        .collections
        .keys()
        .chain(state.urls.keys())
        .map(|(publisher, _)| publisher.clone())
        .collect()
}

fn refresh_all<H: Held>(
    next: &mut State,
    held: &H,
    event: u64,
    eligibility: u64,
    in_force: &BTreeMap<String, Publisher>,
    only: Option<&BTreeSet<String>>,
) -> Result<()> {
    for publisher in publishers(next) {
        if only.is_some_and(|only| !only.contains(&publisher)) {
            continue;
        }
        let declaration = in_force.get(&publisher);
        let order = pull::place_order(next, &publisher, declaration, &[]);
        pull::refresh_waiting(
            next,
            held,
            &publisher,
            event,
            &order,
            declaration,
            eligibility,
        )?;
    }
    Ok(())
}

fn in_force_of(
    declarations: &wist_core::declarations::Declarations,
) -> Result<BTreeMap<String, Publisher>> {
    declarations
        .domains()
        .iter()
        .map(|(domain, state)| {
            Ok((
                domain.clone(),
                declaration::publisher_of(state.current().envelope()).map_err(Error::History)?,
            ))
        })
        .collect()
}

fn failure_codes(failed: &[Failure], only: Option<Condition>) -> Vec<&'static str> {
    let codes: BTreeSet<&'static str> = failed
        .iter()
        .filter(|failure| only.is_none_or(|condition| failure.condition == condition))
        .map(|failure| failure.code)
        .collect();
    codes.into_iter().collect()
}

fn has(failed: &[Failure], condition: Condition) -> bool {
    failed.iter().any(|failure| failure.condition == condition)
}

/// WIST-1 §5.2, Settlement: the Epoch of settlement settles before any of its Declarations
/// applies.
fn settle_due(
    next: &mut State,
    held: &impl Held,
    input: &EpochInput<'_>,
    event: u64,
) -> Result<Vec<Settled>> {
    let sealed_at_s = wist_core::timestamp::log_seconds(input.sealed_at)?;
    let due: Vec<String> = next
        .queues
        .keys()
        .filter(|publisher| queue::due(next, publisher, sealed_at_s))
        .cloned()
        .collect();
    let mut settled = Vec::new();
    for publisher in due {
        let source = queue::settlement_source(next, &publisher)?;
        settled.extend(queue::settle(
            next,
            held,
            &publisher,
            &Settling {
                source: Some(&source),
                order: Some(&source),
                clock: input.sealed_at,
                parameters: input.parameters,
                eligibility: input.height,
                event,
                waited: None,
            },
        )?);
    }
    let ended: Vec<String> = next
        .declarations
        .domains()
        .keys()
        .filter(|publisher| queue::sealed_window_ended(next, publisher, sealed_at_s))
        .cloned()
        .collect();
    for publisher in ended {
        queue::supersede(next, &publisher);
    }
    Ok(settled)
}

/// WIST-3 §3.2–§3.3 and §7.
pub fn plan(state: &State, held: &impl Held, input: &EpochInput<'_>) -> Result<Planned> {
    let height = input.height;
    let mut next = state.clone();
    let event = next.events;
    next.events += 1;
    let parameters = input.parameters;
    let limits = parameters.limits()?;
    let mut fixed: Vec<Value> = Vec::new();
    let mut updates: Vec<Value> = Vec::new();
    let mut updates_refused = Vec::new();
    let mut destroyed: BTreeSet<String> = BTreeSet::new();
    let mut settlement = settle_due(&mut next, held, input, event)?;
    for update in input.updates {
        let inner = &update["update"];
        if inner["action"] != "payload_withdrawal" {
            updates.push(update.clone());
            continue;
        }
        let item_id = inner["details"]["delta_id"].as_str().unwrap_or_default();
        let subject = inner["subject"].as_str().unwrap_or_default();
        if next.sealed_items.meets_contract(item_id, subject, height) == Some(true) {
            updates.push(update.clone());
            destroyed.insert(item_id.to_owned());
        } else {
            updates_refused.push(UpdateRefused {
                item_id: item_id.to_owned(),
                subject: subject.to_owned(),
                code: CONTRACT_FAILED,
            });
        }
    }
    let candidates = candidate_checks(&mut next, input.declarations, &limits)?;
    settlement.extend(queue::settle_orphans(
        &mut next,
        held,
        input.sealed_at,
        parameters,
        height,
        event,
    )?);
    let mut sealed_hashes: BTreeSet<String> = BTreeSet::new();
    for envelope in &candidates.envelopes {
        sealed_hashes.insert(declaration::inner_hash(envelope).map_err(Error::History)?);
        fixed.push(declaration_entry(envelope));
    }
    let mut declaration_entries = fixed.clone();
    wist_core::epoch::sort_entries(&mut declaration_entries)?;
    fixed.extend(
        updates
            .iter()
            .map(|update| json!({"type": "registry_update", "body": update})),
    );
    let mut probe = next.declarations.clone();
    probe.apply_epoch(
        height,
        CANDIDATE_ROOT,
        input.sealed_at,
        parameters.value("recovery_window_days")?,
        parameters.value("declaration_activation_epochs")?,
        &limits,
        &declaration_entries,
    )?;
    let in_force = in_force_of(&probe)?;
    let windows: BTreeSet<String> = probe
        .domains()
        .iter()
        .filter(|(_, domain)| domain.window().is_some())
        .map(|(domain, _)| domain.clone())
        .chain(
            next.queues
                .iter()
                .filter(|(_, queue)| queue.opened())
                .map(|(publisher, _)| publisher.clone()),
        )
        .collect();
    refresh_all(&mut next, held, event, height + 1, &in_force, None)?;
    let holding: BTreeSet<String> = next
        .discovered
        .iter()
        .filter(|(_, found)| {
            found
                .iter()
                .any(|found| found.reduces_authority && !sealed_hashes.contains(&found.hash))
        })
        .map(|(publisher, _)| publisher.clone())
        .collect();
    let kept_out: BTreeSet<String> = next
        .discovered
        .values()
        .flatten()
        .filter(|found| !sealed_hashes.contains(&found.hash))
        .map(|found| found.hash.clone())
        .collect();
    let positive = |name: &str| -> Result<u64> {
        u64::try_from(parameters.value(name)?).map_err(|_| Error::Param(name.into()))
    };
    let mut turn = Turn {
        input,
        held,
        caps: parameters.size_caps()?,
        capacity: positive("domain_epoch_entries_max")?,
        labeler_cap: positive("labeler_epoch_entries_max")?,
        in_force,
        windows,
        holding,
        kept_out,
        destroyed,
        deferred_i4: BTreeSet::new(),
    };
    let mut lists = Lists::default();
    let mut gone: BTreeSet<CollectionKey> = BTreeSet::new();
    let mut left: Vec<(TurnKey, Left)> = Vec::new();
    let mut replaced: BTreeMap<CollectionKey, (String, String)> = BTreeMap::new();
    let mut rejections: Vec<LabelRejection> = Vec::new();
    let (pass, entries, judged, records_removed) = loop {
        let pass = run_pass(&mut next, &turn, &mut lists, &mut gone)?;
        left.extend(pass.dropped.iter().cloned());
        let combined: Vec<Value> = fixed
            .iter()
            .cloned()
            .chain(pass.planned.iter().map(|planned| planned.entry.clone()))
            .collect();
        let (entries, origin) = canonical(combined)?;
        let judged = judge(state, input, &entries)?;
        let (judgments, records_removed) = match &judged.outcome {
            Outcome::Rejected { codes } => {
                return Err(Error::Seal(format!(
                    "the planned Epoch {height} is rejected: {}",
                    codes.join(", ")
                )))
            }
            Outcome::Accepted {
                entries,
                records_removed,
            } => (entries.clone(), records_removed.clone()),
        };
        let mut failures: Vec<(usize, Vec<Failure>)> = Vec::new();
        for (position, judgment) in judgments.iter().enumerate() {
            if let Some(Judgment::Ignored(failed)) = judgment {
                let index = origin[position];
                if index < fixed.len() {
                    return Err(Error::Seal(format!(
                        "a Declaration or Registry Update of Epoch {height} is ignored: {failed:?}"
                    )));
                }
                failures.push((index - fixed.len(), failed.clone()));
            }
        }
        if failures.is_empty() {
            break (pass, entries, judged, records_removed);
        }
        let failed_catalogs: BTreeSet<String> = failures
            .iter()
            .filter_map(|(index, _)| match &pass.planned[*index].publication {
                Publication::Catalog { catalog, .. } => Some(catalog.clone()),
                _ => None,
            })
            .collect();
        let catalog_entries: Vec<Value> = pass
            .planned
            .iter()
            .filter(|planned| matches!(planned.publication, Publication::Catalog { .. }))
            .map(|planned| planned.entry.clone())
            .collect();
        let mut after_catalogs: Option<State> = None;
        let mut touched: BTreeSet<String> = BTreeSet::new();
        for (index, failed) in failures {
            let planned = &pass.planned[index];
            match &planned.publication {
                Publication::Catalog {
                    publisher,
                    collection,
                    ..
                } => {
                    touched.insert(publisher.clone());
                    let key = (publisher.clone(), collection.clone());
                    let state_of = next
                        .collections
                        .get_mut(&key)
                        .ok_or_else(|| history("a planned Catalog of no Collection"))?;
                    let was_base = pull::reads_against_no_record(state_of);
                    let accepted = state_of
                        .accepted
                        .as_mut()
                        .ok_or_else(|| history("a planned Catalog that is not accepted"))?;
                    let catalog_turn = (0, place_key(accepted.place, publisher));
                    if has(&failed, Condition::C1) {
                        accepted.failed_c1 = true;
                        left.push((
                            catalog_turn,
                            Left {
                                publication: planned.publication.clone(),
                                condition: LeftCondition::C1,
                                codes: failure_codes(&failed, Some(Condition::C1)),
                                reported: true,
                                payload_code: None,
                            },
                        ));
                        if was_base {
                            let leaving = base_leaves(
                                state,
                                &next,
                                held,
                                input,
                                &fixed,
                                &catalog_entries,
                                &judged,
                                publisher,
                                collection,
                            )?;
                            for (url, place, kind, publication, codes) in leaving {
                                gone.insert((publisher.clone(), url));
                                left.push((
                                    (kind_turn(kind), place_key(place, publisher)),
                                    Left {
                                        publication,
                                        condition: LeftCondition::I7,
                                        codes,
                                        reported: false,
                                        payload_code: None,
                                    },
                                ));
                            }
                        }
                    } else if has(&failed, Condition::C4) {
                        accepted.failed_c4 = true;
                        left.push((
                            catalog_turn,
                            Left {
                                publication: planned.publication.clone(),
                                condition: LeftCondition::C4,
                                codes: failure_codes(&failed, None),
                                reported: false,
                                payload_code: None,
                            },
                        ));
                    } else {
                        return Err(history(format!(
                            "a waiting Catalog fails {failed:?} at its turn"
                        )));
                    }
                }
                Publication::Item {
                    publisher,
                    collection,
                    url,
                    item,
                } => {
                    if planned
                        .catalog
                        .as_ref()
                        .is_some_and(|catalog| failed_catalogs.contains(catalog))
                    {
                        continue;
                    }
                    touched.insert(publisher.clone());
                    let slot = (publisher.clone(), url.clone());
                    let (value, list_index) =
                        waiting_item(&next, held, &mut lists, publisher, url)?;
                    let waiting = next.urls[&slot].clone();
                    let item_turn = (
                        kind_turn(item_kind(&value)),
                        place_key(waiting.place, publisher),
                    );
                    let codes = failure_codes(&failed, None);
                    if has(&failed, Condition::I7) {
                        if after_catalogs.is_none() {
                            let (ordered, _) =
                                canonical(fixed.iter().chain(&catalog_entries).cloned().collect())?;
                            let applied = judge(state, input, &ordered)?;
                            let mut temp = next.clone();
                            absorb(&mut temp, &applied, height);
                            after_catalogs = Some(temp);
                        }
                        let temp = after_catalogs.as_ref().expect("computed above");
                        let replacing = pull::waiting_candidates(
                            temp,
                            held,
                            publisher,
                            turn.in_force.get(publisher),
                        )?
                        .remove(url);
                        if let Some(candidate) = replacing {
                            if &candidate.item_id != item && !replaced.contains_key(&slot) {
                                replaced.insert(
                                    slot.clone(),
                                    (candidate.collection.clone(), candidate.item_id.clone()),
                                );
                                if let Some(waiting) = next.urls.get_mut(&slot) {
                                    waiting.collection = candidate.collection;
                                    waiting.item_id = candidate.item_id;
                                }
                                continue;
                            }
                        }
                        gone.insert(slot);
                        left.push((
                            item_turn,
                            Left {
                                publication: planned.publication.clone(),
                                condition: LeftCondition::I7,
                                codes,
                                reported: false,
                                payload_code: None,
                            },
                        ));
                    } else if has(&failed, Condition::I4) {
                        turn.deferred_i4
                            .insert((publisher.clone(), collection.clone()));
                    } else if failed
                        .iter()
                        .all(|failure| failure.condition == Condition::I5)
                    {
                        set_admission(
                            &mut next,
                            publisher,
                            collection,
                            list_index,
                            Admission::Refused,
                            codes.first().copied().unwrap_or_default(),
                        );
                        gone.insert(slot);
                        left.push((
                            item_turn,
                            Left {
                                publication: planned.publication.clone(),
                                condition: LeftCondition::I5,
                                codes,
                                reported: true,
                                payload_code: None,
                            },
                        ));
                    } else {
                        return Err(history(format!(
                            "a waiting Item fails {failed:?} at its turn"
                        )));
                    }
                }
                Publication::Label { id, .. } => {
                    let code = failed
                        .first()
                        .map(|failure| failure.code)
                        .ok_or_else(|| history("a Label ignored without a failure"))?;
                    next.labels.remove(id);
                    rejections.push(LabelRejection {
                        id: id.clone(),
                        code,
                    });
                }
            }
        }
        refresh_all(
            &mut next,
            held,
            event,
            height + 1,
            &turn.in_force,
            Some(&touched),
        )?;
        for (slot, (name, item_id)) in &replaced {
            if let Some(waiting) = next.urls.get_mut(slot) {
                waiting.collection.clone_from(name);
                waiting.item_id.clone_from(item_id);
            }
        }
    };
    let held_late: Vec<LeftUnsealed> = pass
        .holding
        .iter()
        .filter(|(holding, eligibility)| {
            holding.reason == Hold::AuthorityReduction && turn.ceiling(*eligibility) <= height
        })
        .map(|(holding, eligibility)| LeftUnsealed {
            publication: holding.publication.clone(),
            place: holding.place,
            ceiling: turn.ceiling(*eligibility),
        })
        .collect();
    absorb(&mut next, &judged, height);
    next.height = Some(height);
    for planned in &pass.planned {
        if let Publication::Item { publisher, .. } = &planned.publication {
            let body = &planned.entry["body"];
            let kind = item::kind(&body["item"]);
            next.sealed_items
                .seal(&item::item_id(&body["item"])?, publisher, kind, height);
        }
    }
    for found in next.discovered.values_mut() {
        found.retain(|found| !sealed_hashes.contains(&found.hash));
    }
    next.discovered.retain(|_, found| !found.is_empty());
    let log = in_force_of(&next.declarations)?;
    refresh_all(&mut next, held, event, height + 1, &log, None)?;
    queue::open_windows(&mut next)?;
    for deferred in &pass.deferred {
        match &deferred.publication {
            Publication::Catalog {
                publisher,
                collection,
                ..
            } => {
                let key = (publisher.clone(), collection.clone());
                if let Some(collection) = next.collections.get_mut(&key) {
                    if collection.waiting().is_some() {
                        if let Some(accepted) = collection.accepted.as_mut() {
                            accepted.eligibility = height + 1;
                        }
                    }
                }
            }
            Publication::Item { publisher, url, .. } => {
                if next.window_holds(publisher) {
                    continue;
                }
                if let Some(waiting) = next.urls.get_mut(&(publisher.clone(), url.clone())) {
                    waiting.eligibility = height + 1;
                }
            }
            Publication::Label { id, .. } => {
                if let Some(label) = next.labels.get_mut(id) {
                    label.eligibility = height + 1;
                }
            }
        }
    }
    for planned in &pass.planned {
        if let Publication::Label { id, .. } = &planned.publication {
            next.labels.remove(id);
            next.sealed_labels.insert(id.clone());
        }
    }
    left.sort_by(|a, b| a.0.cmp(&b.0));
    let sealed = pass
        .planned
        .iter()
        .map(|planned| Sealed {
            publication: planned.publication.clone(),
            catalog: planned.catalog.clone(),
            eligibility: planned.eligibility,
            ceiling: turn.ceiling(planned.eligibility),
        })
        .collect();
    Ok(Planned {
        event,
        settlement,
        entries,
        sealed,
        left: left.into_iter().map(|(_, left)| left).collect(),
        deferred: pass
            .deferred
            .into_iter()
            .filter(|deferred| !matches!(deferred.publication, Publication::Label { .. }))
            .collect(),
        held: pass.holding.into_iter().map(|(held, _)| held).collect(),
        held_late,
        unsealed: pass.unsealed,
        rejections,
        declarations_failed: candidates.failed,
        declarations_left: candidates.left,
        updates_refused,
        records_removed,
        payloads_destroyed: turn.destroyed.into_iter().collect(),
        state: next,
    })
}

type Leaving = (String, Place, ItemKind, Publication, Vec<&'static str>);

/// WIST-3 §3.3: a base failing C1 ends the reading of I7 against no record.
#[allow(clippy::too_many_arguments)]
fn base_leaves(
    state: &State,
    next: &State,
    held: &impl Held,
    input: &EpochInput<'_>,
    fixed: &[Value],
    catalog_entries: &[Value],
    judged: &Judged,
    publisher: &str,
    name: &str,
) -> Result<Vec<Leaving>> {
    let Some(latest) = judged.replay.latest(publisher, name) else {
        return Ok(Vec::new());
    };
    let Some(collection) = next.collection(publisher, name) else {
        return Ok(Vec::new());
    };
    let Some((_, catalog_id)) = collection.last_accepted() else {
        return Ok(Vec::new());
    };
    let Some(statuses) = next.list(publisher, name, catalog_id) else {
        return Ok(Vec::new());
    };
    let base = pull::reads_against_no_record(collection);
    let inner = &latest.envelope["catalog"];
    let catalog: wist_core::objects::Catalog = serde_json::from_value(inner.clone())?;
    let mut lists = Lists::default();
    let (list, positions) = lists.get(held, publisher, name, &latest.catalog_id, Some(inner))?;
    let mut leaving = Vec::new();
    let mut bodies = Vec::new();
    for ((owner, url), waiting) in &next.urls {
        if owner != publisher || waiting.collection != name {
            continue;
        }
        let Some(status) = statuses.iter().find(|status| {
            &status.url == url
                && status.admission == Admission::Admitted
                && !pull::i7_holds(next, publisher, name, status, base)
        }) else {
            continue;
        };
        let Some(at) = positions.get(url) else {
            continue;
        };
        let body = wist_core::publisher_item::build(list, *at as u64, &catalog)?;
        bodies.push(json!({"type": "publisher_item", "body": body}));
        leaving.push((
            url.clone(),
            waiting.place,
            status.kind,
            Publication::Item {
                publisher: publisher.to_owned(),
                collection: name.to_owned(),
                url: url.clone(),
                item: status.item_id.clone(),
            },
        ));
    }
    if leaving.is_empty() {
        return Ok(Vec::new());
    }
    let (ordered, origin) = canonical(
        fixed
            .iter()
            .chain(catalog_entries)
            .chain(&bodies)
            .cloned()
            .collect(),
    )?;
    let first_body = fixed.len() + catalog_entries.len();
    let mut codes: BTreeMap<usize, Vec<&'static str>> = BTreeMap::new();
    if let Outcome::Accepted { entries, .. } = judge(state, input, &ordered)?.outcome {
        for (position, judgment) in entries.into_iter().enumerate() {
            if let (true, Some(Judgment::Ignored(failed))) =
                (origin[position] >= first_body, judgment)
            {
                codes.insert(origin[position] - first_body, failure_codes(&failed, None));
            }
        }
    }
    Ok(leaving
        .into_iter()
        .enumerate()
        .map(|(index, (url, place, kind, publication))| {
            (
                url,
                place,
                kind,
                publication,
                codes.remove(&index).unwrap_or_default(),
            )
        })
        .collect())
}
