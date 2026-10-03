use super::pull::{CatalogReport, Parameters};
use super::site::{Answer, Held, Object, Request, Site};
use super::state::{Discard, DiscardedChain, State};
use crate::error::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use wist_core::change_list;
use wist_core::constants::{CHANGE_CHAIN_MAX, CHANGE_LIST_CAP_BYTES};
use wist_core::crypto::hex_encode;
use wist_core::item;
use wist_core::objects::status::RejectionCondition;
use wist_core::objects::{Catalog, ChangeList};
use wist_core::tree::{self, TreeBounds, TreeFetch, Walk};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainRead {
    Held,
    NoListHeld,
    Accepted { previous: String },
    Discarded,
    Suspended,
    Left,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListStep {
    pub chain: ChainRead,
    pub lists_read: Vec<String>,
}

pub(super) enum Listing {
    Listed(Vec<Value>),
    Refused,
    Suspended,
}

pub(super) struct Target<'a> {
    pub publisher: &'a str,
    pub at: &'a str,
    pub parameters: &'a Parameters,
    pub name: &'a str,
    pub catalog: &'a Catalog,
    pub catalog_id: &'a str,
}

enum Chain {
    Listed { list: Vec<Value>, previous: String },
    Discarded(Discard),
    Suspended,
}

/// WIST-2 §5.3.
pub(super) fn obtain(
    state: &mut State,
    site: &mut impl Site,
    held: &mut impl Held,
    target: &Target<'_>,
    report: &mut CatalogReport,
) -> Result<Listing> {
    let (publisher, name, catalog) = (target.publisher, target.name, target.catalog);
    let collection = state
        .collections
        .entry((publisher.to_owned(), name.to_owned()))
        .or_default();
    let mut step = ListStep {
        chain: ChainRead::Held,
        lists_read: Vec::new(),
    };
    if let Some(list) = held.list_with_root(publisher, name, catalog.size, &catalog.root)? {
        collection.left_chain = false;
        report.list = Some(step);
        return Ok(Listing::Listed(list));
    }
    step.chain = if collection.left_chain {
        ChainRead::Left
    } else if !held.holds_list(publisher, name)? {
        ChainRead::NoListHeld
    } else {
        match read_chain(site, held, target, &mut step.lists_read)? {
            Chain::Listed { list, previous } => {
                step.chain = ChainRead::Accepted { previous };
                report.list = Some(step);
                return Ok(Listing::Listed(list));
            }
            Chain::Suspended => {
                collection.left_chain = true;
                step.chain = ChainRead::Suspended;
                report.list = Some(step);
                return Ok(Listing::Suspended);
            }
            Chain::Discarded(discard) => {
                collection.discarded_chain = Some(DiscardedChain {
                    at: target.at.to_owned(),
                    discard: discard.clone(),
                });
                report.chain = Some(discard);
                ChainRead::Discarded
            }
        }
    };
    report.list = Some(step);
    let listing = walk(site, held, target, report)?;
    if matches!(listing, Listing::Listed(_)) {
        if let Some(collection) = state
            .collections
            .get_mut(&(publisher.to_owned(), name.to_owned()))
        {
            collection.left_chain = false;
        }
    }
    Ok(listing)
}

fn read_chain(
    site: &mut impl Site,
    held: &impl Held,
    target: &Target<'_>,
    lists_read: &mut Vec<String>,
) -> Result<Chain> {
    let discard = |condition, change_list: &str| {
        Ok(Chain::Discarded(Discard {
            condition,
            catalog: target.catalog_id.to_owned(),
            change_list: change_list.to_owned(),
        }))
    };
    let mut read: Vec<ChangeList> = Vec::new();
    let mut leads_to = target.catalog_id.to_owned();
    let base = loop {
        let hex = &leads_to["sha256:".len()..];
        let answer = site.fetch(&Request {
            object: Object::ChangeList {
                collection: target.name,
                hex,
            },
            bound: CHANGE_LIST_CAP_BYTES,
            validator: None,
        })?;
        let octets = match answer {
            Answer::Suspended | Answer::Interrupted => return Ok(Chain::Suspended),
            Answer::Failed | Answer::NotModified => {
                return discard(RejectionCondition::Fetch, &leads_to)
            }
            Answer::Oversized => return discard(RejectionCondition::Size, &leads_to),
            Answer::Octets { octets, .. } if octets.len() as u64 > CHANGE_LIST_CAP_BYTES => {
                return discard(RejectionCondition::Size, &leads_to)
            }
            Answer::Octets { octets, .. } => octets,
        };
        lists_read.push(leads_to.clone());
        let Ok(change) = change_list::read(hex, &octets) else {
            return discard(RejectionCondition::Form, &leads_to);
        };
        let previous = change.previous.clone();
        read.push(change);
        if let Some(base) = held.list(target.publisher, target.name, &previous)? {
            break base;
        }
        if read.len() as u64 == CHANGE_CHAIN_MAX {
            return discard(RejectionCondition::Chain, &leads_to);
        }
        leads_to = previous;
    };
    let previous = read
        .last()
        .map(|change| change.previous.clone())
        .unwrap_or_default();
    let mut list = base;
    for change in read.iter().rev() {
        list = change_list::apply(&list, change)?;
    }
    let root = format!("sha256:{}", hex_encode(&item::root(&list)?));
    if list.len() as u64 != target.catalog.size || root != target.catalog.root {
        return discard(RejectionCondition::Result, target.catalog_id);
    }
    Ok(Chain::Listed { list, previous })
}

fn walk(
    site: &mut impl Site,
    held: &mut impl Held,
    target: &Target<'_>,
    report: &mut CatalogReport,
) -> Result<Listing> {
    let bounds = target.parameters.tree_bounds()?;
    let mut fetched = Vec::new();
    let mut failure = None;
    let walk = tree::walk(target.catalog, &bounds, |hex| {
        match fetch_tree_file(site, held, target, hex, &bounds, &mut fetched) {
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
    target: &Target<'_>,
    hex: &str,
    bounds: &TreeBounds,
    fetched: &mut Vec<String>,
) -> Result<TreeFetch> {
    let name = target.name;
    if let Some(octets) = held.tree_file(hex)? {
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
    let octets = match answer {
        Answer::Octets { octets, .. } => octets,
        Answer::Interrupted => return Ok(TreeFetch::Suspended),
        _ => return Ok(TreeFetch::Failed),
    };
    if octets.len() as u64 <= bounds.tree_file_cap_bytes()
        && hex_encode(&Sha256::digest(&octets)) == hex
    {
        held.hold_tree_file(hex, &octets)?;
    }
    Ok(TreeFetch::Octets(octets))
}
