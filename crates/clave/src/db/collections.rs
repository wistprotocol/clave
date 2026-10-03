use super::Db;
use crate::collection::site::Held;
use crate::collection::state::{
    AcceptedCatalog, Admission, CollectionKey, CollectionState, Discard, DiscardedChain,
    Discovered, ItemKind, LabelKind, ListItem, ListKey, Place, QueuedCatalog, Record,
    RecoveryQueue, Removal, SealedCatalog, ServedFile, State, WaitingLabel, WaitingUrl,
    CHAIN_DISCARDED,
};
use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use wist_core::declarations::Declarations;
use wist_core::withdrawal::{SealedItems, WithdrawalReplay};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS collections(publisher TEXT NOT NULL, name TEXT NOT NULL, latest_envelope BLOB, latest_id TEXT, latest_height INTEGER, latest_base INTEGER, accepted_envelope BLOB, accepted_id TEXT, accepted_key TEXT, accepted_base INTEGER, accepted_failed_c1 INTEGER, accepted_failed_c4 INTEGER, accepted_event INTEGER, accepted_position INTEGER, accepted_eligibility INTEGER, left_chain INTEGER NOT NULL, catalog_octets BLOB, catalog_validator TEXT, waiting_deferrals TEXT, waiting_held TEXT, accepted_read TEXT, PRIMARY KEY(publisher, name));
CREATE TABLE IF NOT EXISTS catalog_queues(publisher TEXT PRIMARY KEY, owner TEXT NOT NULL, end_s INTEGER);
CREATE TABLE IF NOT EXISTS catalog_queue(publisher TEXT NOT NULL, name TEXT NOT NULL, key_x TEXT NOT NULL, envelope BLOB NOT NULL, catalog_id TEXT NOT NULL, place_event INTEGER NOT NULL, place_position INTEGER NOT NULL, sources_json TEXT NOT NULL, PRIMARY KEY(publisher, name, key_x));
CREATE TABLE IF NOT EXISTS catalog_queue_first(publisher TEXT NOT NULL, name TEXT NOT NULL, place_event INTEGER NOT NULL, place_position INTEGER NOT NULL, PRIMARY KEY(publisher, name));
CREATE TABLE IF NOT EXISTS held_lists(publisher TEXT NOT NULL, name TEXT NOT NULL, catalog_id TEXT NOT NULL, size INTEGER NOT NULL, root TEXT NOT NULL, items BLOB NOT NULL, PRIMARY KEY(publisher, name, catalog_id));
CREATE INDEX IF NOT EXISTS held_lists_root ON held_lists(publisher, name, size, root);
CREATE TABLE IF NOT EXISTS tree_files(sha256 TEXT PRIMARY KEY, octets BLOB NOT NULL, last_read TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lists(publisher TEXT NOT NULL, name TEXT NOT NULL, catalog_id TEXT NOT NULL, PRIMARY KEY(publisher, name, catalog_id));
CREATE TABLE IF NOT EXISTS list_items(publisher TEXT NOT NULL, name TEXT NOT NULL, catalog_id TEXT NOT NULL, idx INTEGER NOT NULL, url TEXT NOT NULL, item_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('page','removed')), admission TEXT NOT NULL CHECK(admission IN ('unjudged','admitted','refused','not_admitted')), code TEXT, read TEXT, PRIMARY KEY(publisher, name, catalog_id, idx));
CREATE TABLE IF NOT EXISTS waiting_urls(publisher TEXT NOT NULL, url TEXT NOT NULL, collection TEXT NOT NULL, item_id TEXT NOT NULL, place_event INTEGER NOT NULL, place_position INTEGER NOT NULL, place_index INTEGER NOT NULL, eligibility INTEGER NOT NULL, deferrals TEXT, held TEXT, PRIMARY KEY(publisher, url));
CREATE TABLE IF NOT EXISTS records(publisher TEXT NOT NULL, url TEXT NOT NULL, item BLOB NOT NULL, item_id TEXT NOT NULL, collection TEXT NOT NULL, catalog_id TEXT NOT NULL, generated_at TEXT NOT NULL, sealing_height INTEGER NOT NULL, PRIMARY KEY(publisher, url));
CREATE TABLE IF NOT EXISTS removals(publisher TEXT NOT NULL, url TEXT NOT NULL, item_id TEXT NOT NULL, catalog_id TEXT NOT NULL, generated_at TEXT NOT NULL, PRIMARY KEY(publisher, url));
CREATE TABLE IF NOT EXISTS sealed_items(item_id TEXT NOT NULL, publisher TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('page','removed')), first_height INTEGER NOT NULL, PRIMARY KEY(item_id, publisher, kind));
CREATE TABLE IF NOT EXISTS payload_duties(item_id TEXT PRIMARY KEY, publisher TEXT NOT NULL, url TEXT NOT NULL, until TEXT NOT NULL, served INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS discovered_declarations(domain TEXT NOT NULL, hash TEXT NOT NULL, ord INTEGER NOT NULL, envelope BLOB NOT NULL, event INTEGER NOT NULL, last_sealed_at_discovery INTEGER, reduces_authority INTEGER NOT NULL, last_seal_height INTEGER, competitor INTEGER NOT NULL, competes_with TEXT, PRIMARY KEY(domain, hash));
CREATE TABLE IF NOT EXISTS discovery_floors(domain TEXT PRIMARY KEY, seq INTEGER NOT NULL);
";

pub(super) fn create(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

pub struct Sealed {
    pub height: Option<u64>,
    pub declarations: Declarations,
    pub withdrawals: WithdrawalReplay,
    pub sealed_items: SealedItems,
    pub sealed_labels: BTreeSet<String>,
}

impl Sealed {
    pub fn of(state: &State) -> Sealed {
        Sealed {
            height: state.height,
            declarations: state.declarations.clone(),
            withdrawals: state.withdrawals.clone(),
            sealed_items: state.sealed_items.clone(),
            sealed_labels: state.sealed_labels.clone(),
        }
    }
}

fn int(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn uint(value: i64) -> u64 {
    value.max(0) as u64
}

fn json(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn parse(octets: &[u8]) -> Result<Value> {
    Ok(crate::json::parse(octets)?)
}

fn admission_str(admission: Admission) -> &'static str {
    match admission {
        Admission::Unjudged => "unjudged",
        Admission::Admitted => "admitted",
        Admission::Refused => "refused",
        Admission::NotAdmitted => "not_admitted",
    }
}

fn admission_of(value: &str) -> Result<Admission> {
    Ok(match value {
        "unjudged" => Admission::Unjudged,
        "admitted" => Admission::Admitted,
        "refused" => Admission::Refused,
        "not_admitted" => Admission::NotAdmitted,
        other => return Err(Error::History(format!("unknown admission state {other}"))),
    })
}

fn read_of(read: Option<String>) -> Result<Vec<String>> {
    Ok(match read {
        Some(read) => serde_json::from_str(&read)?,
        None => Vec::new(),
    })
}

fn kind_str(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Page => "page",
        ItemKind::Removed => "removed",
    }
}

fn kind_of(value: &str) -> Result<ItemKind> {
    Ok(match value {
        "page" => ItemKind::Page,
        "removed" => ItemKind::Removed,
        other => return Err(Error::History(format!("unknown Item kind {other}"))),
    })
}

fn condition_str(discard: &Discard) -> Result<String> {
    Ok(serde_json::to_value(discard.condition)?
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

impl Db {
    pub fn sealed_state(&self, data_dir: &Path) -> Result<Sealed> {
        let mut history = crate::history::History::open(self, data_dir, self.last_epoch()?)?;
        while history.next_epoch()?.is_some() {}
        self.sealed_from(&history)
    }

    pub fn sealed_from(&self, history: &crate::history::History<'_>) -> Result<Sealed> {
        let replay = history.replay();
        let sealed_labels = self
            .conn
            .prepare("SELECT label_id FROM labels UNION SELECT dispute_id FROM disputes")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
        Ok(Sealed {
            height: history.height(),
            declarations: replay.declarations().clone(),
            withdrawals: replay.withdrawals().clone(),
            sealed_items: self.sealed_items()?,
            sealed_labels,
        })
    }

    pub fn sealed_items(&self) -> Result<SealedItems> {
        let mut sealed_items = SealedItems::new();
        for (item_id, publisher, kind, height) in self
            .conn
            .prepare("SELECT item_id, publisher, kind, first_height FROM sealed_items")?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        {
            let kind = match kind_of(&kind)? {
                ItemKind::Page => wist_core::item::Kind::Page,
                ItemKind::Removed => wist_core::item::Kind::Removed,
            };
            sealed_items.seal(&item_id, &publisher, kind, uint(height));
        }
        Ok(sealed_items)
    }

    pub fn record_sealed_item(
        &self,
        item_id: &str,
        publisher: &str,
        kind: ItemKind,
        height: u64,
    ) -> Result<()> {
        self.execute(
            "INSERT INTO sealed_items(item_id, publisher, kind, first_height) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(item_id, publisher, kind) DO UPDATE SET first_height = MIN(first_height, excluded.first_height)",
            (item_id, publisher, kind_str(kind), int(height)),
        )?;
        Ok(())
    }

    pub(crate) fn insert_waiting_label(&self, id: &str, label: &WaitingLabel) -> Result<()> {
        insert_waiting_label(&self.conn, id, label)
    }

    pub fn pull_scope(&self, publisher: &str) -> Result<BTreeSet<String>> {
        let mut scope: BTreeSet<String> = self
            .conn
            .prepare("SELECT publisher FROM catalog_queues")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?;
        scope.insert(publisher.to_owned());
        Ok(scope)
    }

    pub fn waiting_publishers(&self) -> Result<BTreeSet<String>> {
        Ok(self
            .conn
            .prepare(
                "SELECT publisher FROM collections WHERE accepted_id IS NOT NULL AND (latest_id IS NULL OR latest_id != accepted_id)
                UNION SELECT publisher FROM waiting_urls
                UNION SELECT publisher FROM catalog_queues
                UNION SELECT domain FROM discovered_declarations
                UNION SELECT domain FROM pending_entries WHERE label_id IS NOT NULL",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    pub fn load_waiting_state(&self, sealed: Sealed) -> Result<State> {
        let publishers = self.waiting_publishers()?;
        self.load_state(sealed, &publishers)
    }

    pub fn load_state(&self, sealed: Sealed, publishers: &BTreeSet<String>) -> Result<State> {
        let events: i64 = self.conn.query_row(
            "SELECT position FROM acceptance_clock WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        let mut state = State {
            events: uint(events) + 1,
            height: sealed.height,
            declarations: sealed.declarations,
            withdrawals: sealed.withdrawals,
            sealed_items: sealed.sealed_items,
            sealed_labels: sealed.sealed_labels,
            ..State::default()
        };
        for publisher in publishers {
            load_publisher(&self.conn, &mut state, publisher)?;
        }
        Ok(state)
    }

    pub fn store_state(
        &self,
        before: &State,
        after: &State,
        publishers: &BTreeSet<String>,
        at: &str,
    ) -> Result<()> {
        let mutation = self.mutation()?;
        store_changes(self, before, after, publishers, at)?;
        mutation.commit()
    }
}

fn place(event: i64, position: i64, index: Option<i64>) -> Place {
    Place {
        event: uint(event),
        position: uint(position),
        index: index.map(uint),
    }
}

fn load_publisher(conn: &Connection, state: &mut State, publisher: &str) -> Result<()> {
    let mut statement = conn.prepare_cached("SELECT name, latest_envelope, latest_id, latest_height, latest_base, accepted_envelope, accepted_id, accepted_key, accepted_base, accepted_failed_c1, accepted_failed_c4, accepted_event, accepted_position, accepted_eligibility, left_chain, catalog_octets, catalog_validator, accepted_read FROM collections WHERE publisher = ?1")?;
    let rows = statement
        .query_map([publisher], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<bool>>(4)?,
                (
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<bool>>(8)?,
                    row.get::<_, Option<bool>>(9)?,
                    row.get::<_, Option<bool>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                ),
                row.get::<_, bool>(14)?,
                row.get::<_, Option<Vec<u8>>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<String>>(17)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (
        name,
        latest,
        latest_id,
        latest_height,
        latest_base,
        accepted,
        left_chain,
        octets,
        validator,
        read,
    ) in rows
    {
        let latest = match (latest, latest_id) {
            (Some(envelope), Some(catalog_id)) => Some(SealedCatalog {
                envelope: parse(&envelope)?,
                catalog_id,
                sealing_height: uint(latest_height.unwrap_or_default()),
                base: latest_base.unwrap_or_default(),
            }),
            _ => None,
        };
        let accepted = match accepted {
            (
                Some(envelope),
                Some(catalog_id),
                Some(key),
                base,
                failed_c1,
                failed_c4,
                Some(event),
                Some(position),
                Some(eligibility),
            ) => Some(AcceptedCatalog {
                envelope: parse(&envelope)?,
                catalog_id,
                key,
                base_against_floor: base.unwrap_or_default(),
                failed_c1: failed_c1.unwrap_or_default(),
                failed_c4: failed_c4.unwrap_or_default(),
                place: place(event, position, None),
                eligibility: uint(eligibility),
                read: read_of(read)?,
            }),
            _ => None,
        };
        let discarded_chain = conn
            .query_row(
                "SELECT at, id, condition, change_list FROM rejections WHERE domain = ?1 AND collection = ?2 AND code = ?3 ORDER BY rowid DESC LIMIT 1",
                (publisher, &name, CHAIN_DISCARDED),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?
            .map(|(at, catalog, condition, change_list)| {
                Ok::<_, Error>(DiscardedChain {
                    at,
                    discard: Discard {
                        condition: serde_json::from_value(Value::String(
                            condition.unwrap_or_default(),
                        ))?,
                        catalog: catalog.unwrap_or_default(),
                        change_list: change_list.unwrap_or_default(),
                    },
                })
            })
            .transpose()?;
        state.collections.insert(
            (publisher.to_owned(), name),
            CollectionState {
                latest,
                accepted,
                left_chain,
                discarded_chain,
                catalog_file: octets.map(|octets| ServedFile { octets, validator }),
            },
        );
    }

    let mut statement =
        conn.prepare_cached("SELECT name, catalog_id FROM lists WHERE publisher = ?1")?;
    let keys = statement
        .query_map([publisher], |row| {
            Ok((
                publisher.to_owned(),
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for key in keys {
        state.lists.insert(key, Vec::new());
    }
    let mut statement = conn.prepare_cached("SELECT name, catalog_id, idx, url, item_id, kind, admission, code, read FROM list_items WHERE publisher = ?1 ORDER BY name, catalog_id, idx")?;
    let rows = statement
        .query_map([publisher], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (name, catalog_id, url, item_id, kind, admission, code, read) in rows {
        state
            .lists
            .entry((publisher.to_owned(), name, catalog_id))
            .or_default()
            .push(ListItem {
                url,
                item_id,
                kind: kind_of(&kind)?,
                admission: admission_of(&admission)?,
                code,
                read: read_of(read)?,
            });
    }

    let mut statement = conn.prepare_cached("SELECT url, collection, item_id, place_event, place_position, place_index, eligibility FROM waiting_urls WHERE publisher = ?1")?;
    let rows = statement
        .query_map([publisher], |row| {
            Ok((
                row.get::<_, String>(0)?,
                WaitingUrl {
                    collection: row.get(1)?,
                    item_id: row.get(2)?,
                    place: place(row.get(3)?, row.get(4)?, Some(row.get(5)?)),
                    eligibility: uint(row.get(6)?),
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (url, waiting) in rows {
        state.urls.insert((publisher.to_owned(), url), waiting);
    }

    let queue = conn
        .query_row(
            "SELECT owner, end_s FROM catalog_queues WHERE publisher = ?1",
            [publisher],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    if let Some((owner, end_s)) = queue {
        let mut queue = RecoveryQueue {
            owner,
            end_s: end_s.map(i128::from),
            ..RecoveryQueue::default()
        };
        let mut statement = conn.prepare_cached("SELECT name, key_x, envelope, catalog_id, place_event, place_position, sources_json FROM catalog_queue WHERE publisher = ?1")?;
        let rows = statement
            .query_map([publisher], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        for (name, key, envelope, catalog_id, event, position, sources) in rows {
            queue.queued.insert(
                (name, key),
                QueuedCatalog {
                    envelope: parse(&envelope)?,
                    catalog_id,
                    place: place(event, position, None),
                    sources: serde_json::from_str(&sources)?,
                },
            );
        }
        let mut statement = conn.prepare_cached(
            "SELECT name, place_event, place_position FROM catalog_queue_first WHERE publisher = ?1",
        )?;
        queue.first = statement
            .query_map([publisher], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    place(row.get(1)?, row.get(2)?, None),
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        state.queues.insert(publisher.to_owned(), queue);
    }

    let mut statement = conn.prepare_cached("SELECT url, item, item_id, collection, catalog_id, generated_at, sealing_height FROM records WHERE publisher = ?1")?;
    let rows = statement
        .query_map([publisher], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (url, item, item_id, collection, catalog_id, generated_at, height) in rows {
        state.records.insert(
            (publisher.to_owned(), url),
            Record {
                item: parse(&item)?,
                item_id,
                collection,
                catalog_id,
                generated_at,
                sealing_height: uint(height),
            },
        );
    }

    let mut statement = conn.prepare_cached(
        "SELECT url, item_id, catalog_id, generated_at FROM removals WHERE publisher = ?1",
    )?;
    let rows = statement
        .query_map([publisher], |row| {
            Ok((
                row.get::<_, String>(0)?,
                Removal {
                    item_id: row.get(1)?,
                    catalog_id: row.get(2)?,
                    generated_at: row.get(3)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (url, removal) in rows {
        state.removals.insert((publisher.to_owned(), url), removal);
    }

    let mut statement = conn.prepare_cached("SELECT envelope, hash, event, last_sealed_at_discovery, reduces_authority, last_seal_height, competitor, competes_with FROM discovered_declarations WHERE domain = ?1 ORDER BY ord")?;
    let rows = statement
        .query_map([publisher], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (
        envelope,
        hash,
        event,
        sealed_at_discovery,
        reduces,
        last_seal_height,
        competitor,
        competes_with,
    ) in rows
    {
        state
            .discovered
            .entry(publisher.to_owned())
            .or_default()
            .push(Discovered {
                envelope: parse(&envelope)?,
                hash,
                event: uint(event),
                last_sealed_at_discovery: sealed_at_discovery.map(uint),
                reduces_authority: reduces,
                last_seal_height: last_seal_height.map(uint),
                competitor,
                competes_with,
            });
    }
    if let Some(seq) = conn
        .query_row(
            "SELECT seq FROM discovery_floors WHERE domain = ?1",
            [publisher],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    {
        state.floors.insert(publisher.to_owned(), uint(seq));
    }

    let mut statement = conn.prepare_cached("SELECT entry_type, label_id, entry_json, place_event, place_position, place_index, eligibility FROM pending_entries WHERE domain = ?1 AND label_id IS NOT NULL AND place_event IS NOT NULL")?;
    let rows = statement
        .query_map([publisher], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                place(row.get(3)?, row.get(4)?, row.get(5)?),
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (kind, id, envelope, place, eligibility) in rows {
        state.labels.insert(
            id,
            WaitingLabel {
                kind: if kind == "dispute" {
                    LabelKind::Dispute
                } else {
                    LabelKind::Label
                },
                publisher: publisher.to_owned(),
                envelope: parse(&envelope)?,
                place,
                eligibility: uint(eligibility),
            },
        );
    }
    Ok(())
}

fn in_scope<'a, K: Ord, V: PartialEq>(
    before: &'a BTreeMap<K, V>,
    after: &'a BTreeMap<K, V>,
    publishers: &BTreeSet<String>,
    publisher: impl Fn(&K) -> &str,
) -> Vec<(&'a K, Option<&'a V>)> {
    let keys: BTreeSet<&K> = before
        .keys()
        .chain(after.keys())
        .filter(|key| publishers.contains(publisher(key)))
        .collect();
    keys.into_iter()
        .filter(|key| before.get(key) != after.get(key))
        .map(|key| (key, after.get(key)))
        .collect()
}

fn store_collection(
    conn: &Connection,
    (publisher, name): &CollectionKey,
    collection: Option<&CollectionState>,
    before: Option<&CollectionState>,
    at: &str,
) -> Result<()> {
    let Some(collection) = collection else {
        conn.execute(
            "DELETE FROM collections WHERE publisher = ?1 AND name = ?2",
            (publisher, name),
        )?;
        return Ok(());
    };
    let latest = collection.latest.as_ref();
    let accepted = collection.accepted.as_ref();
    conn.execute(
        "INSERT OR REPLACE INTO collections(publisher, name, latest_envelope, latest_id, latest_height, latest_base, accepted_envelope, accepted_id, accepted_key, accepted_base, accepted_failed_c1, accepted_failed_c4, accepted_event, accepted_position, accepted_eligibility, left_chain, catalog_octets, catalog_validator, accepted_read) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        rusqlite::params![
            publisher,
            name,
            latest.map(|latest| json(&latest.envelope)).transpose()?,
            latest.map(|latest| &latest.catalog_id),
            latest.map(|latest| int(latest.sealing_height)),
            latest.map(|latest| latest.base),
            accepted.map(|accepted| json(&accepted.envelope)).transpose()?,
            accepted.map(|accepted| &accepted.catalog_id),
            accepted.map(|accepted| &accepted.key),
            accepted.map(|accepted| accepted.base_against_floor),
            accepted.map(|accepted| accepted.failed_c1),
            accepted.map(|accepted| accepted.failed_c4),
            accepted.map(|accepted| int(accepted.place.event)),
            accepted.map(|accepted| int(accepted.place.position)),
            accepted.map(|accepted| int(accepted.eligibility)),
            collection.left_chain,
            collection.catalog_file.as_ref().map(|file| &file.octets),
            collection
                .catalog_file
                .as_ref()
                .and_then(|file| file.validator.as_ref()),
            accepted
                .map(|accepted| serde_json::to_string(&accepted.read))
                .transpose()?,
        ],
    )?;
    let previous = before.and_then(|before| before.discarded_chain.as_ref());
    if let Some(chain) = &collection.discarded_chain {
        if previous != Some(chain) {
            conn.execute(
                "DELETE FROM rejections WHERE domain = ?1 AND collection = ?2 AND code = ?3",
                (publisher, name, CHAIN_DISCARDED),
            )?;
            let at = if chain.at.is_empty() { at } else { &chain.at };
            conn.execute(
                "INSERT INTO rejections(domain, code, at, id, collection, condition, change_list) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                (
                    publisher,
                    CHAIN_DISCARDED,
                    at,
                    &chain.discard.catalog,
                    name,
                    condition_str(&chain.discard)?,
                    &chain.discard.change_list,
                ),
            )?;
        }
    }
    Ok(())
}

fn insert_list_item(conn: &Connection, key: &ListKey, idx: usize, item: &ListItem) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO list_items(publisher, name, catalog_id, idx, url, item_id, kind, admission, code, read) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            key.0,
            key.1,
            key.2,
            idx as i64,
            item.url,
            item.item_id,
            kind_str(item.kind),
            admission_str(item.admission),
            item.code,
            serde_json::to_string(&item.read)?,
        ],
    )?;
    Ok(())
}

fn store_list(
    conn: &Connection,
    key: &ListKey,
    list: Option<&Vec<ListItem>>,
    before: Option<&Vec<ListItem>>,
) -> Result<()> {
    match (before, list) {
        (Some(before), Some(list)) if before.len() == list.len() => {
            for (idx, (old, new)) in before.iter().zip(list).enumerate() {
                if old != new {
                    insert_list_item(conn, key, idx, new)?;
                }
            }
        }
        _ => {
            conn.execute(
                "DELETE FROM list_items WHERE publisher = ?1 AND name = ?2 AND catalog_id = ?3",
                (&key.0, &key.1, &key.2),
            )?;
            match list {
                Some(_) => conn.execute(
                    "INSERT OR IGNORE INTO lists(publisher, name, catalog_id) VALUES (?1, ?2, ?3)",
                    (&key.0, &key.1, &key.2),
                )?,
                None => conn.execute(
                    "DELETE FROM lists WHERE publisher = ?1 AND name = ?2 AND catalog_id = ?3",
                    (&key.0, &key.1, &key.2),
                )?,
            };
            for (idx, item) in list.into_iter().flatten().enumerate() {
                insert_list_item(conn, key, idx, item)?;
            }
        }
    }
    Ok(())
}

fn store_queue(conn: &Connection, publisher: &str, queue: Option<&RecoveryQueue>) -> Result<()> {
    for table in ["catalog_queues", "catalog_queue", "catalog_queue_first"] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE publisher = ?1"),
            [publisher],
        )?;
    }
    let Some(queue) = queue else {
        return Ok(());
    };
    let end_s =
        queue.end_s.map(i64::try_from).transpose().map_err(|_| {
            Error::History("a recovery window ends outside the stored range".into())
        })?;
    conn.execute(
        "INSERT INTO catalog_queues(publisher, owner, end_s) VALUES (?1, ?2, ?3)",
        (publisher, &queue.owner, end_s),
    )?;
    for ((name, key), queued) in &queue.queued {
        conn.execute(
            "INSERT INTO catalog_queue(publisher, name, key_x, envelope, catalog_id, place_event, place_position, sources_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                publisher,
                name,
                key,
                json(&queued.envelope)?,
                queued.catalog_id,
                int(queued.place.event),
                int(queued.place.position),
                serde_json::to_string(&queued.sources)?,
            ],
        )?;
    }
    for (name, first) in &queue.first {
        conn.execute(
            "INSERT INTO catalog_queue_first(publisher, name, place_event, place_position) VALUES (?1, ?2, ?3, ?4)",
            (publisher, name, int(first.event), int(first.position)),
        )?;
    }
    Ok(())
}

fn store_discovered(
    conn: &Connection,
    publisher: &str,
    found: Option<&Vec<Discovered>>,
) -> Result<()> {
    conn.execute(
        "DELETE FROM discovered_declarations WHERE domain = ?1",
        [publisher],
    )?;
    for (ord, found) in found.into_iter().flatten().enumerate() {
        conn.execute(
            "INSERT INTO discovered_declarations(domain, hash, ord, envelope, event, last_sealed_at_discovery, reduces_authority, last_seal_height, competitor, competes_with) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                publisher,
                found.hash,
                ord as i64,
                json(&found.envelope)?,
                int(found.event),
                found.last_sealed_at_discovery.map(int),
                found.reduces_authority,
                found.last_seal_height.map(int),
                found.competitor,
                found.competes_with,
            ],
        )?;
    }
    Ok(())
}

fn store_label(conn: &Connection, id: &str, label: Option<&WaitingLabel>) -> Result<()> {
    let Some(label) = label else {
        conn.execute("DELETE FROM pending_entries WHERE label_id = ?1", [id])?;
        return Ok(());
    };
    let updated = conn.execute(
        "UPDATE pending_entries SET place_event = ?2, place_position = ?3, place_index = ?4, eligibility = ?5 WHERE label_id = ?1",
        rusqlite::params![
            id,
            int(label.place.event),
            int(label.place.position),
            label.place.index.map(int),
            int(label.eligibility),
        ],
    )?;
    if updated == 0 {
        insert_waiting_label(conn, id, label)?;
    }
    Ok(())
}

fn insert_waiting_label(conn: &Connection, id: &str, label: &WaitingLabel) -> Result<()> {
    conn.execute(
        "INSERT INTO pending_entries(entry_type, domain, entry_json, chain_pos, label_id, place_event, place_position, place_index, eligibility) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            label.kind.as_str(),
            label.publisher,
            json(&label.envelope)?,
            id,
            int(label.place.event),
            int(label.place.position),
            label.place.index.map(int),
            int(label.eligibility),
        ],
    )?;
    Ok(())
}

pub(crate) fn store_changes(
    db: &Db,
    before: &State,
    after: &State,
    publishers: &BTreeSet<String>,
    at: &str,
) -> Result<()> {
    let conn = &db.conn;
    if after.events > before.events {
        if after.events - 1 > i64::MAX as u64 {
            return Err(Error::History(
                "the acceptance clock has no event left to assign".into(),
            ));
        }
        conn.execute(
            "UPDATE acceptance_clock SET position = MAX(position, ?1) WHERE id = 1",
            [int(after.events - 1)],
        )?;
    }
    for (key, collection) in in_scope(&before.collections, &after.collections, publishers, |k| {
        &k.0
    }) {
        store_collection(conn, key, collection, before.collections.get(key), at)?;
    }
    for (key, list) in in_scope(&before.lists, &after.lists, publishers, |k| &k.0) {
        store_list(conn, key, list, before.lists.get(key))?;
    }
    for ((publisher, url), waiting) in in_scope(&before.urls, &after.urls, publishers, |k| &k.0) {
        match waiting {
            None => conn.execute(
                "DELETE FROM waiting_urls WHERE publisher = ?1 AND url = ?2",
                (publisher, url),
            )?,
            Some(waiting) => conn.execute(
                "INSERT OR REPLACE INTO waiting_urls(publisher, url, collection, item_id, place_event, place_position, place_index, eligibility) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    publisher,
                    url,
                    waiting.collection,
                    waiting.item_id,
                    int(waiting.place.event),
                    int(waiting.place.position),
                    int(waiting.place.index.unwrap_or_default()),
                    int(waiting.eligibility),
                ],
            )?,
        };
    }
    for (publisher, queue) in in_scope(&before.queues, &after.queues, publishers, |k| k) {
        store_queue(conn, publisher, queue)?;
    }
    for ((publisher, url), record) in
        in_scope(&before.records, &after.records, publishers, |k| &k.0)
    {
        match record {
            None => conn.execute(
                "DELETE FROM records WHERE publisher = ?1 AND url = ?2",
                (publisher, url),
            )?,
            Some(record) => conn.execute(
                "INSERT OR REPLACE INTO records(publisher, url, item, item_id, collection, catalog_id, generated_at, sealing_height) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    publisher,
                    url,
                    json(&record.item)?,
                    record.item_id,
                    record.collection,
                    record.catalog_id,
                    record.generated_at,
                    int(record.sealing_height),
                ],
            )?,
        };
    }
    for ((publisher, url), removal) in
        in_scope(&before.removals, &after.removals, publishers, |k| &k.0)
    {
        match removal {
            None => conn.execute(
                "DELETE FROM removals WHERE publisher = ?1 AND url = ?2",
                (publisher, url),
            )?,
            Some(removal) => conn.execute(
                "INSERT OR REPLACE INTO removals(publisher, url, item_id, catalog_id, generated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                (publisher, url, &removal.item_id, &removal.catalog_id, &removal.generated_at),
            )?,
        };
    }
    let discovered_changed = |publisher: &String| {
        before
            .discovered
            .get(publisher)
            .map(Vec::as_slice)
            .unwrap_or_default()
            != after
                .discovered
                .get(publisher)
                .map(Vec::as_slice)
                .unwrap_or_default()
    };
    for publisher in publishers
        .iter()
        .filter(|publisher| discovered_changed(publisher))
    {
        store_discovered(conn, publisher, after.discovered.get(publisher))?;
    }
    for (publisher, floor) in in_scope(&before.floors, &after.floors, publishers, |k| k) {
        match floor {
            None => conn.execute(
                "DELETE FROM discovery_floors WHERE domain = ?1",
                [publisher],
            )?,
            Some(seq) => conn.execute(
                "INSERT OR REPLACE INTO discovery_floors(domain, seq) VALUES (?1, ?2)",
                (publisher, int(*seq)),
            )?,
        };
    }
    let label_publisher = |id: &String| {
        after
            .labels
            .get(id)
            .or_else(|| before.labels.get(id))
            .map_or("", |label| label.publisher.as_str())
    };
    let ids: BTreeSet<&String> = before.labels.keys().chain(after.labels.keys()).collect();
    for id in ids {
        if publishers.contains(label_publisher(id)) && before.labels.get(id) != after.labels.get(id)
        {
            store_label(conn, id, after.labels.get(id))?;
        }
    }
    Ok(())
}

type HeldList = (u64, String, Vec<Value>);

pub struct StoreHeld<'a> {
    db: &'a Db,
    data_dir: &'a Path,
    at: String,
    lists: BTreeMap<ListKey, HeldList>,
    tree_files: BTreeMap<String, Vec<u8>>,
    read: std::cell::RefCell<BTreeSet<String>>,
    payloads: BTreeMap<String, Vec<u8>>,
}

fn payload_name(item_id: &str) -> Result<String> {
    item_id
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|hex| format!("{hex}.json"))
        .ok_or_else(|| Error::History(format!("{item_id} names no Payload file")))
}

pub fn held_payload_path(data_dir: &Path, item_id: &str) -> Result<std::path::PathBuf> {
    Ok(data_dir.join("held/payloads").join(payload_name(item_id)?))
}

pub fn served_payload_path(data_dir: &Path, item_id: &str) -> Result<std::path::PathBuf> {
    Ok(data_dir.join("payloads").join(payload_name(item_id)?))
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(octets) => Ok(Some(octets)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

impl<'a> StoreHeld<'a> {
    pub fn new(db: &'a Db, data_dir: &'a Path, at: &str) -> Self {
        StoreHeld {
            db,
            data_dir,
            at: at.to_owned(),
            lists: BTreeMap::new(),
            tree_files: BTreeMap::new(),
            read: std::cell::RefCell::default(),
            payloads: BTreeMap::new(),
        }
    }

    /// Payload files are written before the enclosing transaction commits: a rollback leaves a
    /// file no row names, never a row without its file.
    pub(crate) fn flush(&mut self) -> Result<()> {
        let conn = &self.db.conn;
        for ((publisher, name, catalog_id), (size, root, items)) in std::mem::take(&mut self.lists)
        {
            conn.execute(
                "INSERT OR REPLACE INTO held_lists(publisher, name, catalog_id, size, root, items) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    publisher,
                    name,
                    catalog_id,
                    int(size),
                    root,
                    wist_core::jcs::canonicalize(&Value::Array(items))?,
                ],
            )?;
        }
        for (hex, octets) in std::mem::take(&mut self.tree_files) {
            conn.execute(
                "INSERT OR REPLACE INTO tree_files(sha256, octets, last_read) VALUES (?1, ?2, ?3)",
                (&hex, octets, &self.at),
            )?;
        }
        for hex in self.read.take() {
            conn.execute(
                "UPDATE tree_files SET last_read = ?2 WHERE sha256 = ?1",
                (&hex, &self.at),
            )?;
        }
        for (item_id, octets) in std::mem::take(&mut self.payloads) {
            if self.db.is_withdrawn(&item_id)? {
                continue;
            }
            let path = held_payload_path(self.data_dir, &item_id)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let partial = path.with_extension("json.partial");
            std::fs::write(&partial, &octets)?;
            std::fs::rename(&partial, &path)?;
        }
        Ok(())
    }

    pub(crate) fn discard(&mut self) {
        self.lists.clear();
        self.tree_files.clear();
        self.read.take();
        self.payloads.clear();
    }

    pub fn store(&mut self) -> Result<()> {
        let mutation = self.db.mutation()?;
        self.flush()?;
        mutation.commit()
    }

    fn stored_list(&self, sql: &str, params: impl rusqlite::Params) -> Result<Option<Vec<Value>>> {
        self.db
            .conn
            .query_row(sql, params, |row| row.get::<_, Vec<u8>>(0))
            .optional()?
            .map(|items| match parse(&items)? {
                Value::Array(items) => Ok(items),
                _ => Err(Error::History("a held list is not an array".into())),
            })
            .transpose()
    }
}

impl Held for StoreHeld<'_> {
    fn list(
        &self,
        publisher: &str,
        collection: &str,
        catalog_id: &str,
    ) -> Result<Option<Vec<Value>>> {
        let key = (
            publisher.to_owned(),
            collection.to_owned(),
            catalog_id.to_owned(),
        );
        if let Some((_, _, items)) = self.lists.get(&key) {
            return Ok(Some(items.clone()));
        }
        self.stored_list(
            "SELECT items FROM held_lists WHERE publisher = ?1 AND name = ?2 AND catalog_id = ?3",
            (publisher, collection, catalog_id),
        )
    }

    fn list_with_root(
        &self,
        publisher: &str,
        collection: &str,
        size: u64,
        root: &str,
    ) -> Result<Option<Vec<Value>>> {
        if let Some((_, (_, _, items))) = self.lists.iter().find(|((p, c, _), (s, r, _))| {
            p == publisher && c == collection && *s == size && r == root
        }) {
            return Ok(Some(items.clone()));
        }
        self.stored_list(
            "SELECT items FROM held_lists WHERE publisher = ?1 AND name = ?2 AND size = ?3 AND root = ?4 ORDER BY catalog_id LIMIT 1",
            (publisher, collection, int(size), root),
        )
    }

    fn hold_list(
        &mut self,
        publisher: &str,
        collection: &str,
        catalog_id: &str,
        catalog: &Value,
        items: &[Value],
    ) -> Result<()> {
        let size = catalog["size"].as_u64().unwrap_or_default();
        let root = catalog["root"].as_str().unwrap_or_default().to_owned();
        self.lists.insert(
            (
                publisher.to_owned(),
                collection.to_owned(),
                catalog_id.to_owned(),
            ),
            (size, root, items.to_vec()),
        );
        Ok(())
    }

    fn holds_list(&self, publisher: &str, collection: &str) -> Result<bool> {
        if self
            .lists
            .keys()
            .any(|(p, c, _)| p == publisher && c == collection)
        {
            return Ok(true);
        }
        Ok(self.db.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM held_lists WHERE publisher = ?1 AND name = ?2)",
            (publisher, collection),
            |row| row.get(0),
        )?)
    }

    fn tree_file(&self, hex: &str) -> Result<Option<Vec<u8>>> {
        if let Some(octets) = self.tree_files.get(hex) {
            return Ok(Some(octets.clone()));
        }
        let held: Option<Vec<u8>> = self
            .db
            .conn
            .query_row(
                "SELECT octets FROM tree_files WHERE sha256 = ?1",
                [hex],
                |row| row.get(0),
            )
            .optional()?;
        if held.is_some() {
            self.read.borrow_mut().insert(hex.to_owned());
        }
        Ok(held)
    }

    fn hold_tree_file(&mut self, hex: &str, octets: &[u8]) -> Result<()> {
        self.tree_files.insert(hex.to_owned(), octets.to_vec());
        Ok(())
    }

    fn payload(&self, item_id: &str) -> Result<Option<Vec<u8>>> {
        if let Some(octets) = self.payloads.get(item_id) {
            return Ok(Some(octets.clone()));
        }
        match read_optional(&held_payload_path(self.data_dir, item_id)?)? {
            Some(octets) => Ok(Some(octets)),
            None => read_optional(&served_payload_path(self.data_dir, item_id)?),
        }
    }

    fn hold_payload(&mut self, item_id: &str, octets: &[u8]) -> Result<()> {
        self.payloads.insert(item_id.to_owned(), octets.to_vec());
        Ok(())
    }
}
