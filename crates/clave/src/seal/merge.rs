use super::prepare::PreparedEpoch;
use crate::collection::plan;
pub(super) use crate::collection::plan::Publication;
use crate::collection::pull;
use crate::collection::state::{
    of_publisher, AcceptedCatalog, CollectionKey, CollectionState, ListItem, ListKey, Place,
    PublisherKey, Record, SealedCatalog, State,
};
use crate::db::{Db, Sealed, StoreHeld};
use crate::error::Result;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Merge {
    Done(Vec<String>),
    Replan(Vec<String>),
}

// WIST-3 §3.3, Capacity order: a pull committed during the plan is a later event than the
// Epoch, so what it accepts is left unsealed and takes no room.
pub(super) fn into_current(
    db: &Db,
    data_dir: &Path,
    prepared: &mut PreparedEpoch<'_>,
    changed: &[String],
) -> Result<Merge> {
    let publishers: BTreeSet<String> = changed.iter().cloned().collect();
    let current = db.load_state(Sealed::of(&prepared.before), &publishers)?;
    let fresh = Fresh::new(
        prepared.planned.event,
        prepared.planned.state.events.max(current.events),
        prepared.epoch_number + 1,
    );
    let mut replan = Vec::new();
    for publisher in &publishers {
        let settles = prepared
            .planned
            .settlement
            .iter()
            .any(|settled| settled.publisher == *publisher);
        let spliced = if settles {
            Err("settles a recovery queue in the Epoch".to_owned())
        } else {
            splice(
                &mut prepared.before,
                &current,
                &mut prepared.planned.state,
                publisher,
                &fresh,
            )
        };
        if let Err(reason) = spliced {
            replan.push(format!("{publisher}: {reason}"));
        }
    }
    if !replan.is_empty() {
        return Ok(Merge::Replan(replan));
    }
    let height = prepared.epoch_number;
    let held = StoreHeld::new(db, data_dir, &prepared.sealed_at);
    let merged = &mut prepared.planned.state;
    if fresh.used.get() {
        merged.events = fresh.event + 1;
    }
    let in_force = plan::in_force_of(&merged.declarations)?;
    for publisher in &publishers {
        let declaration = in_force.get(publisher);
        let order = pull::place_order(merged, publisher, declaration, &[]);
        pull::refresh_waiting(
            merged,
            &held,
            publisher,
            prepared.planned.event,
            &order,
            declaration,
            height + 1,
        )?;
        plan::defer_eligibility(merged, &prepared.planned.deferred, height, Some(publisher));
    }
    let planned = &mut prepared.planned;
    let follow = |state: &State, publication: &mut Publication| {
        !publishers.contains(publication.publisher()) || follows_place(state, publication)
    };
    planned
        .deferred
        .retain_mut(|deferred| follow(&planned.state, &mut deferred.publication));
    planned
        .held
        .retain_mut(|held| follow(&planned.state, &mut held.publication));
    Ok(Merge::Done(publishers.into_iter().collect()))
}

// WIST-3 §3.3, Waiting: a replacement takes the place of what it replaces, so a report of
// the place names the replacement.
pub(super) fn follows_place(state: &State, publication: &mut Publication) -> bool {
    match publication {
        Publication::Catalog {
            publisher,
            collection,
            catalog,
        } => match state
            .collection(publisher, collection)
            .and_then(|collection| collection.accepted.as_ref())
        {
            Some(accepted) => {
                catalog.clone_from(&accepted.catalog_id);
                true
            }
            None => false,
        },
        Publication::Item {
            publisher,
            url,
            item,
            ..
        } => match state.urls.get(&(publisher.clone(), url.clone())) {
            Some(waiting) => {
                item.clone_from(&waiting.item_id);
                true
            }
            None => false,
        },
        Publication::Label { .. } => true,
    }
}

pub(super) struct Fresh {
    epoch_event: u64,
    event: u64,
    eligibility: u64,
    used: Cell<bool>,
}

impl Fresh {
    pub(super) fn new(epoch_event: u64, event: u64, eligibility: u64) -> Fresh {
        Fresh {
            epoch_event,
            event,
            eligibility,
            used: Cell::new(false),
        }
    }

    // WIST-3 §3.3, Waiting (Place column): a replacement keeps the place of the one waiting after
    // the Epoch; once the Epoch sealed or left that one, the pull, a later event, places it afresh.
    fn place(&self, place: &mut Place, eligibility: &mut u64, plan_waiting: Option<(Place, u64)>) {
        if place.event > self.epoch_event {
            return;
        }
        match plan_waiting {
            Some(planned) => (*place, *eligibility) = planned,
            None => {
                self.used.set(true);
                place.event = self.event;
                *eligibility = self.eligibility;
            }
        }
    }
}

type Taken<V> = std::result::Result<Option<V>, String>;

fn kept<V: Clone>(now: Option<&V>, what: impl FnOnce() -> String) -> Taken<V> {
    now.cloned()
        .map(Some)
        .ok_or_else(|| format!("the pull removed {}", what()))
}

fn three_way<K: Ord + Clone, V: Clone + PartialEq>(
    base: &mut BTreeMap<K, V>,
    current: &BTreeMap<K, V>,
    merged: &mut BTreeMap<K, V>,
    keys: BTreeSet<K>,
    mut take: impl FnMut(&K, Option<&V>, Option<&V>, Option<&V>) -> Taken<V>,
) -> std::result::Result<(), String> {
    let mut decided = Vec::new();
    for key in keys {
        let (was, now) = (base.get(&key), current.get(&key));
        if was == now {
            continue;
        }
        let taken = take(&key, was, now, merged.get(&key))?;
        decided.push((key, now.cloned(), taken));
    }
    for (key, now, taken) in decided {
        match taken {
            Some(value) => merged.insert(key.clone(), value),
            None => merged.remove(&key),
        };
        match now {
            Some(value) => base.insert(key, value),
            None => base.remove(&key),
        };
    }
    Ok(())
}

fn publisher_keys<K: PublisherKey + Clone, V>(
    maps: [&BTreeMap<K, V>; 3],
    publisher: &str,
) -> BTreeSet<K> {
    maps.into_iter()
        .flat_map(|map| of_publisher(map, publisher))
        .map(|(key, _)| key.clone())
        .collect()
}

fn without_plan_effects(collection: Option<&CollectionState>) -> Option<CollectionState> {
    collection.map(|collection| {
        let mut stripped = collection.clone();
        stripped.latest = None;
        if let Some(accepted) = stripped.accepted.as_mut() {
            accepted.eligibility = 0;
        }
        stripped
    })
}

struct Floor<'a> {
    before: &'a BTreeMap<CollectionKey, Record>,
    sealed: &'a BTreeMap<CollectionKey, Record>,
    lists: &'a BTreeMap<ListKey, Vec<ListItem>>,
    publisher: &'a str,
}

impl Floor<'_> {
    fn read_by(
        &self,
        name: &str,
        accepted: &AcceptedCatalog,
        latest: Option<&CollectionState>,
        latest_moved: bool,
    ) -> std::result::Result<(), String> {
        let generated_at = accepted.envelope["catalog"]["generated_at"]
            .as_str()
            .unwrap_or_default();
        let floor = latest.and_then(CollectionState::floor);
        let base = wist_core::sealing::base_against_floor(generated_at, floor)
            .map_err(|error| format!("Catalog {}: {error:?}", accepted.catalog_id))?;
        if latest_moved && base != accepted.base_against_floor {
            return Err(format!(
                "Catalog {} of {name} was accepted against a floor the Epoch moves",
                accepted.catalog_id
            ));
        }
        if base {
            return Ok(());
        }
        let listed: BTreeSet<&str> = self
            .lists
            .get(&(
                self.publisher.to_owned(),
                name.to_owned(),
                accepted.catalog_id.clone(),
            ))
            .into_iter()
            .flatten()
            .map(|status| status.url.as_str())
            .collect();
        let unlisted = of_publisher(self.sealed, self.publisher).find(|(key, record)| {
            record.collection == name
                && self.before.get(*key) != Some(*record)
                && !listed.contains(key.1.as_str())
        });
        match unlisted {
            Some(((_, url), _)) => Err(format!(
                "Catalog {} of {name} does not list {url}, which the Epoch seals",
                accepted.catalog_id
            )),
            None => Ok(()),
        }
    }
}

fn accepted_id(collection: Option<&CollectionState>) -> Option<&str> {
    collection
        .and_then(|collection| collection.accepted.as_ref())
        .map(|accepted| accepted.catalog_id.as_str())
}

fn sealed_catalogs<'s>(
    state: &'s State,
    publisher: &'s str,
) -> Vec<(&'s CollectionKey, &'s SealedCatalog)> {
    of_publisher(&state.collections, publisher)
        .filter_map(|(key, collection)| collection.latest.as_ref().map(|latest| (key, latest)))
        .collect()
}

pub(super) fn splice(
    base: &mut State,
    current: &State,
    merged: &mut State,
    publisher: &str,
    fresh: &Fresh,
) -> std::result::Result<(), String> {
    if [&*base, current, &*merged]
        .iter()
        .any(|state| state.queues.contains_key(publisher) || state.window_holds(publisher))
    {
        return Err("holds a recovery queue".into());
    }
    if current.discovered.get(publisher) != base.discovered.get(publisher) {
        return Err("discovered a Declaration".into());
    }
    if current.declaration_files.get(publisher) != base.declaration_files.get(publisher) {
        return Err("served another Declaration file".into());
    }
    if !of_publisher(&base.records, publisher).eq(of_publisher(&current.records, publisher))
        || !of_publisher(&base.removals, publisher).eq(of_publisher(&current.removals, publisher))
    {
        return Err("changed its records".into());
    }
    if sealed_catalogs(base, publisher) != sealed_catalogs(current, publisher) {
        return Err("changed its sealed Catalogs".into());
    }
    let refused_in: BTreeSet<String> = of_publisher(&base.lists, publisher)
        .chain(of_publisher(&merged.lists, publisher))
        .filter(|(key, _)| base.lists.get(*key) != merged.lists.get(*key))
        .map(|((_, name, _), _)| name.clone())
        .collect();
    if let Some(name) = refused_in.iter().find(|name| {
        accepted_id(base.collection(publisher, name))
            != accepted_id(current.collection(publisher, name))
    }) {
        return Err(format!(
            "the Epoch refused an Item of Collection {name}, whose Catalog the pull replaced"
        ));
    }
    let floor = Floor {
        before: &base.records,
        sealed: &merged.records,
        lists: &current.lists,
        publisher,
    };
    let keys = publisher_keys(
        [&base.collections, &current.collections, &merged.collections],
        publisher,
    );
    three_way(
        &mut base.collections,
        &current.collections,
        &mut merged.collections,
        keys,
        |(_, name), was, now, plan| {
            if without_plan_effects(plan) != without_plan_effects(was) {
                return Err(format!(
                    "the Epoch and the pull both change Collection {name}"
                ));
            }
            let Some(now) = now else {
                return Err(format!("the pull removed Collection {name}"));
            };
            let latest_moved = plan.map(|plan| &plan.latest) != was.map(|was| &was.latest);
            let replaced = accepted_id(Some(now)) != accepted_id(was);
            if let (true, Some(accepted)) = (replaced, now.accepted.as_ref()) {
                floor.read_by(name, accepted, plan, latest_moved)?;
            }
            let mut taken = now.clone();
            if let Some(plan) = plan {
                taken.latest.clone_from(&plan.latest);
            }
            if replaced && taken.waiting().is_some() {
                let plan_waiting = plan
                    .and_then(CollectionState::waiting)
                    .map(|waiting| (waiting.place, waiting.eligibility));
                if let Some(accepted) = taken.accepted.as_mut() {
                    fresh.place(&mut accepted.place, &mut accepted.eligibility, plan_waiting);
                }
            }
            Ok(Some(taken))
        },
    )?;
    let keys = publisher_keys([&base.lists, &current.lists, &merged.lists], publisher);
    three_way(
        &mut base.lists,
        &current.lists,
        &mut merged.lists,
        keys,
        |(_, name, catalog_id), was, now, plan| {
            if plan != was {
                return Err(format!(
                    "the Epoch and the pull both change the list of Catalog {catalog_id} of {name}"
                ));
            }
            kept(now, || {
                format!("the list of Catalog {catalog_id} of {name}")
            })
        },
    )?;
    let keys = publisher_keys([&base.urls, &current.urls, &merged.urls], publisher);
    three_way(
        &mut base.urls,
        &current.urls,
        &mut merged.urls,
        keys,
        |_, _, now, plan| {
            let mut taken = now.cloned();
            if let Some(waiting) = taken.as_mut() {
                let plan_waiting = plan.map(|plan| (plan.place, plan.eligibility));
                fresh.place(&mut waiting.place, &mut waiting.eligibility, plan_waiting);
            }
            Ok(taken)
        },
    )?;
    let keys: BTreeSet<String> = [&base.labels, &current.labels, &merged.labels]
        .into_iter()
        .flat_map(|labels| labels.iter())
        .filter(|(_, label)| label.publisher == publisher)
        .map(|(id, _)| id.clone())
        .collect();
    three_way(
        &mut base.labels,
        &current.labels,
        &mut merged.labels,
        keys,
        |id, was, now, plan| {
            if plan != was {
                return Err(format!("the Epoch and the pull both change Label {id}"));
            }
            let mut taken = kept(now, || format!("Label {id}"))?;
            if let Some(label) = taken.as_mut() {
                let plan_waiting = plan.map(|plan| (plan.place, plan.eligibility));
                fresh.place(&mut label.place, &mut label.eligibility, plan_waiting);
            }
            Ok(taken)
        },
    )?;
    let keys = publisher_keys([&base.floors, &current.floors, &merged.floors], publisher);
    three_way(
        &mut base.floors,
        &current.floors,
        &mut merged.floors,
        keys,
        |_, was, now, plan| {
            if plan != was {
                return Err("the Epoch and the pull both change its discovery floor".into());
            }
            kept(now, || "its discovery floor".into())
        },
    )?;
    Ok(())
}
