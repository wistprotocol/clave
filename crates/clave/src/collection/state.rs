use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use wist_core::declarations::Declarations;
use wist_core::objects::status::{RejectionCondition, StatusRejection};
use wist_core::withdrawal::{SealedItems, WithdrawalReplay};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "Vec<u64>", try_from = "Vec<u64>")]
pub struct Place {
    pub event: u64,
    pub position: u64,
    pub index: Option<u64>,
}

impl Place {
    pub fn catalog(event: u64, position: u64) -> Self {
        Place {
            event,
            position,
            index: None,
        }
    }

    pub fn url(event: u64, position: u64, index: u64) -> Self {
        Place {
            event,
            position,
            index: Some(index),
        }
    }
}

impl From<Place> for Vec<u64> {
    fn from(place: Place) -> Self {
        let mut out = vec![place.event, place.position];
        out.extend(place.index);
        out
    }
}

impl TryFrom<Vec<u64>> for Place {
    type Error = String;

    fn try_from(value: Vec<u64>) -> Result<Self, Self::Error> {
        match value[..] {
            [event, position] => Ok(Place::catalog(event, position)),
            [event, position, index] => Ok(Place::url(event, position, index)),
            _ => Err(format!("a place has two or three members, not {value:?}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServedFile {
    pub octets: Vec<u8>,
    pub validator: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedCatalog {
    pub envelope: Value,
    pub catalog_id: String,
    pub sealing_height: u64,
    pub base: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcceptedCatalog {
    pub envelope: Value,
    pub catalog_id: String,
    pub key: String,
    pub base_against_floor: bool,
    pub failed_c1: bool,
    pub failed_c4: bool,
    pub place: Place,
    pub eligibility: u64,
    #[serde(default)]
    pub read: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discard {
    pub condition: RejectionCondition,
    pub catalog: String,
    pub change_list: String,
}

pub const CHAIN_DISCARDED: &str = "WIST2-E08";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscardedChain {
    pub at: String,
    pub discard: Discard,
}

impl DiscardedChain {
    pub fn rejection(&self, collection: &str) -> StatusRejection {
        StatusRejection {
            code: CHAIN_DISCARDED.into(),
            at: self.at.clone(),
            id: Some(self.discard.catalog.clone()),
            collection: Some(collection.into()),
            urls: None,
            condition: Some(self.discard.condition),
            change_list: Some(self.discard.change_list.clone()),
            detail: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CollectionState {
    pub latest: Option<SealedCatalog>,
    pub accepted: Option<AcceptedCatalog>,
    pub left_chain: bool,
    pub discarded_chain: Option<DiscardedChain>,
    pub catalog_file: Option<ServedFile>,
}

impl CollectionState {
    pub fn last_accepted(&self) -> Option<(&Value, &str)> {
        match &self.accepted {
            Some(accepted) if !accepted.failed_c1 => {
                Some((&accepted.envelope, accepted.catalog_id.as_str()))
            }
            _ => self
                .latest
                .as_ref()
                .map(|latest| (&latest.envelope, latest.catalog_id.as_str())),
        }
    }

    pub fn waiting(&self) -> Option<&AcceptedCatalog> {
        self.accepted.as_ref().filter(|accepted| {
            !accepted.failed_c1
                && !accepted.failed_c4
                && self
                    .latest
                    .as_ref()
                    .is_none_or(|latest| latest.catalog_id != accepted.catalog_id)
        })
    }

    pub fn floor(&self) -> Option<&str> {
        self.latest
            .as_ref()
            .and_then(|latest| latest.envelope["catalog"]["generated_at"].as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    Unjudged,
    Admitted,
    Refused,
    NotAdmitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Page,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListItem {
    pub url: String,
    pub item_id: String,
    pub kind: ItemKind,
    pub admission: Admission,
    pub code: Option<String>,
    #[serde(default)]
    pub read: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitingUrl {
    pub collection: String,
    pub item_id: String,
    pub place: Place,
    pub eligibility: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueuedCatalog {
    pub envelope: Value,
    pub catalog_id: String,
    pub place: Place,
    pub sources: Vec<String>,
}

pub type QueueSlot = (String, String);

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RecoveryQueue {
    pub owner: String,
    pub end_s: Option<i128>,
    pub queued: BTreeMap<QueueSlot, QueuedCatalog>,
    pub first: BTreeMap<String, Place>,
}

impl RecoveryQueue {
    pub fn opened(&self) -> bool {
        self.end_s.is_some()
    }

    pub fn first_place(&self, name: &str) -> Option<Place> {
        self.first.get(name).copied()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub item: Value,
    pub item_id: String,
    pub collection: String,
    pub catalog_id: String,
    pub generated_at: String,
    pub sealing_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removal {
    pub item_id: String,
    pub catalog_id: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelKind {
    Label,
    Dispute,
}

impl LabelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LabelKind::Label => "label",
            LabelKind::Dispute => "dispute",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WaitingLabel {
    pub kind: LabelKind,
    pub publisher: String,
    pub envelope: Value,
    pub place: Place,
    pub eligibility: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Discovered {
    pub envelope: Value,
    pub hash: String,
    pub event: u64,
    pub last_sealed_at_discovery: Option<u64>,
    pub reduces_authority: bool,
    pub last_seal_height: Option<u64>,
    #[serde(default)]
    pub competitor: bool,
    #[serde(default)]
    pub competes_with: Option<String>,
}

pub type CollectionKey = (String, String);

pub type ListKey = (String, String, String);

#[derive(Debug, Clone, Default)]
pub struct State {
    pub events: u64,
    pub height: Option<u64>,
    pub declarations: Declarations,
    pub discovered: BTreeMap<String, Vec<Discovered>>,
    pub declaration_files: BTreeMap<String, ServedFile>,
    pub collections: BTreeMap<CollectionKey, CollectionState>,
    pub lists: BTreeMap<ListKey, Vec<ListItem>>,
    pub urls: BTreeMap<CollectionKey, WaitingUrl>,
    pub queues: BTreeMap<String, RecoveryQueue>,
    pub records: BTreeMap<CollectionKey, Record>,
    pub removals: BTreeMap<CollectionKey, Removal>,
    pub withdrawals: WithdrawalReplay,
    pub sealed_items: SealedItems,
    pub labels: BTreeMap<String, WaitingLabel>,
    pub sealed_labels: BTreeSet<String>,
    pub label_subjects: BTreeMap<String, Option<String>>,
    pub floors: BTreeMap<String, u64>,
}

impl State {
    pub fn collection(&self, publisher: &str, name: &str) -> Option<&CollectionState> {
        self.collections.get(&(publisher.into(), name.into()))
    }

    pub fn collection_names(&self, publisher: &str) -> Vec<String> {
        self.collections
            .keys()
            .filter(|(p, _)| p == publisher)
            .map(|(_, name)| name.clone())
            .collect()
    }

    pub fn record(&self, publisher: &str, url: &str) -> Option<&Record> {
        self.records.get(&(publisher.into(), url.into()))
    }

    pub fn list(&self, publisher: &str, name: &str, catalog_id: &str) -> Option<&Vec<ListItem>> {
        self.lists
            .get(&(publisher.into(), name.into(), catalog_id.into()))
    }

    pub fn reductions_pending(&self) -> impl Iterator<Item = (&str, &Discovered)> {
        self.discovered.iter().flat_map(|(publisher, found)| {
            found
                .iter()
                .filter(|found| found.reduces_authority)
                .map(move |found| (publisher.as_str(), found))
        })
    }

    pub fn window_holds(&self, publisher: &str) -> bool {
        self.queues
            .get(publisher)
            .is_some_and(RecoveryQueue::opened)
    }

    pub fn first_epoch_after(&self) -> u64 {
        self.height.map_or(0, |height| height + 1)
    }
}
