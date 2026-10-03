use crate::error::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use wist_core::crypto::hex_encode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object<'a> {
    Declaration,
    Catalog { collection: &'a str },
    TreeFile { collection: &'a str, hex: &'a str },
    ChangeList { collection: &'a str, hex: &'a str },
    Payload { collection: &'a str, hex: &'a str },
}

impl Object<'_> {
    pub fn path(&self) -> String {
        match self {
            Object::Declaration => "publisher.json".into(),
            Object::Catalog { collection } => format!("collections/{collection}/catalog.json"),
            Object::TreeFile { collection, hex } => format!("collections/{collection}/tree/{hex}"),
            Object::ChangeList { collection, hex } => {
                format!("collections/{collection}/changes/{hex}.json")
            }
            Object::Payload { collection, hex } => {
                format!("collections/{collection}/payloads/{hex}.json")
            }
        }
    }

    pub fn metered(&self) -> bool {
        !matches!(self, Object::Declaration)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    pub object: Object<'a>,
    pub bound: u64,
    pub validator: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Octets {
        octets: Vec<u8>,
        validator: Option<String>,
    },
    NotModified,
    Failed,
    Suspended,
}

pub trait Site {
    fn fetch(&mut self, request: &Request<'_>) -> Result<Answer>;
}

pub trait Held {
    fn list(
        &self,
        publisher: &str,
        collection: &str,
        catalog_id: &str,
    ) -> Result<Option<Vec<Value>>>;

    fn list_with_root(
        &self,
        publisher: &str,
        collection: &str,
        size: u64,
        root: &str,
    ) -> Result<Option<Vec<Value>>>;

    fn hold_list(
        &mut self,
        publisher: &str,
        collection: &str,
        catalog_id: &str,
        catalog: &Value,
        items: &[Value],
    ) -> Result<()>;

    fn tree_file(&self, publisher: &str, collection: &str, hex: &str) -> Result<Option<Vec<u8>>>;

    fn hold_tree_file(
        &mut self,
        publisher: &str,
        collection: &str,
        hex: &str,
        octets: &[u8],
    ) -> Result<()>;

    fn payload(&self, item_id: &str) -> Result<Option<Vec<u8>>>;

    fn hold_payload(&mut self, item_id: &str, octets: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metered {
    Read,
    Failed,
    Suspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meter {
    pub budget_remaining: u64,
    pub bytes_remaining: Option<u64>,
    pub objects_remaining: Option<u64>,
}

impl Meter {
    pub fn unbounded() -> Self {
        Meter {
            budget_remaining: u64::MAX,
            bytes_remaining: None,
            objects_remaining: None,
        }
    }

    /// WIST-2 §5.2: the bound met first decides.
    pub fn read(&mut self, bound: u64, octets: u64) -> (Metered, u64) {
        if self.objects_remaining == Some(0) {
            return (Metered::Suspended, 0);
        }
        if let Some(objects) = &mut self.objects_remaining {
            *objects -= 1;
        }
        let remainder = self.bytes_remaining.map_or(self.budget_remaining, |bytes| {
            bytes.min(self.budget_remaining)
        });
        let (metered, debited) = if remainder < bound.saturating_add(1) {
            if octets > remainder {
                (Metered::Suspended, remainder)
            } else {
                (Metered::Read, octets)
            }
        } else if octets > bound {
            (Metered::Failed, 0)
        } else {
            (Metered::Read, octets)
        };
        self.budget_remaining -= debited;
        if let Some(bytes) = &mut self.bytes_remaining {
            *bytes -= debited;
        }
        (metered, debited)
    }
}

pub fn validator(octets: &[u8]) -> String {
    format!("\"{}\"", hex_encode(&Sha256::digest(octets)))
}

#[derive(Debug, Clone)]
pub struct ServedSite {
    pub files: BTreeMap<String, Vec<u8>>,
    pub meter: Meter,
    pub requested: Vec<String>,
}

impl ServedSite {
    pub fn new(meter: Meter) -> Self {
        ServedSite {
            files: BTreeMap::new(),
            meter,
            requested: Vec::new(),
        }
    }

    pub fn serve(&mut self, object: Object<'_>, octets: impl Into<Vec<u8>>) {
        self.files.insert(object.path(), octets.into());
    }

    pub fn withdraw(&mut self, object: Object<'_>) {
        self.files.remove(&object.path());
    }
}

impl Site for ServedSite {
    fn fetch(&mut self, request: &Request<'_>) -> Result<Answer> {
        let path = request.object.path();
        let served = self.files.get(&path);
        let unchanged = served.is_some_and(|octets| request.validator == Some(&validator(octets)));
        if request.object.metered() {
            let octets = served
                .filter(|_| !unchanged)
                .map_or(0, |octets| octets.len() as u64);
            match self.meter.read(request.bound, octets).0 {
                Metered::Suspended => return Ok(Answer::Suspended),
                Metered::Failed => {
                    self.requested.push(path);
                    return Ok(Answer::Failed);
                }
                Metered::Read => {}
            }
        }
        self.requested.push(path);
        Ok(match served {
            None => Answer::Failed,
            Some(_) if unchanged => Answer::NotModified,
            Some(octets) if octets.len() as u64 > request.bound => Answer::Failed,
            Some(octets) => Answer::Octets {
                octets: octets.clone(),
                validator: Some(validator(octets)),
            },
        })
    }
}

type ListKey = (String, String, String);

#[derive(Debug, Clone, Default)]
pub struct MemoryHeld {
    pub lists: BTreeMap<ListKey, (u64, String, Vec<Value>)>,
    pub tree_files: BTreeMap<ListKey, Vec<u8>>,
    pub payloads: BTreeMap<String, Vec<u8>>,
}

fn key(publisher: &str, collection: &str, name: &str) -> ListKey {
    (publisher.into(), collection.into(), name.into())
}

impl Held for MemoryHeld {
    fn list(
        &self,
        publisher: &str,
        collection: &str,
        catalog_id: &str,
    ) -> Result<Option<Vec<Value>>> {
        Ok(self
            .lists
            .get(&key(publisher, collection, catalog_id))
            .map(|(_, _, items)| items.clone()))
    }

    fn list_with_root(
        &self,
        publisher: &str,
        collection: &str,
        size: u64,
        root: &str,
    ) -> Result<Option<Vec<Value>>> {
        Ok(self
            .lists
            .iter()
            .find(|((p, c, _), (held_size, held_root, _))| {
                p == publisher && c == collection && *held_size == size && held_root == root
            })
            .map(|(_, (_, _, items))| items.clone()))
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
            key(publisher, collection, catalog_id),
            (size, root, items.to_vec()),
        );
        Ok(())
    }

    fn tree_file(&self, publisher: &str, collection: &str, hex: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .tree_files
            .get(&key(publisher, collection, hex))
            .cloned())
    }

    fn hold_tree_file(
        &mut self,
        publisher: &str,
        collection: &str,
        hex: &str,
        octets: &[u8],
    ) -> Result<()> {
        self.tree_files
            .insert(key(publisher, collection, hex), octets.to_vec());
        Ok(())
    }

    fn payload(&self, item_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.payloads.get(item_id).cloned())
    }

    fn hold_payload(&mut self, item_id: &str, octets: &[u8]) -> Result<()> {
        self.payloads.insert(item_id.into(), octets.to_vec());
        Ok(())
    }
}
