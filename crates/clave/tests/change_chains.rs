mod common;

use base64::Engine;
use clave::collection::pull::{CatalogOutcome, CatalogReport, ItemOutcome};
use clave::collection::site::Answer;
use clave::collection::{
    pull, ChainRead, Held, MemoryHeld, Meter, Object, Parameters, PullInput, PullReport, Request,
    ServedSite, Site, State,
};
use common::{key_entry, kid, K1_SEED};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::objects::status::RejectionCondition;

const DOMAIN: &str = "example.com";
const JOURNAL_SEED: [u8; 32] = [0xc6; 32];
const STORE_SEED: [u8; 32] = [0xd7; 32];
const KEYS_FROM: &str = "2026-08-01T00:00:00Z";
const SEALED_AT: &str = "2026-10-01T00:00:00Z";
const PULLED_AT: &str = "2026-10-19T00:00:00Z";

fn spec_dir() -> std::path::PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
}

fn read_vector(relative: &str) -> Value {
    serde_json::from_slice(&std::fs::read(spec_dir().join(relative)).unwrap()).unwrap()
}

fn octets(value: &Value) -> Vec<u8> {
    wist_core::jcs::canonicalize(value).unwrap()
}

fn seed_of(collection: &str) -> [u8; 32] {
    match collection {
        "journal" => JOURNAL_SEED,
        "store" => STORE_SEED,
        other => panic!("no key for {other}"),
    }
}

fn declaration(collections: &[&str]) -> Value {
    let publisher = json!({
        "wist_version": "1.0.0",
        "seq": 0,
        "domain": DOMAIN,
        "keys": [key_entry(&K1_SEED, KEYS_FROM)],
        "collections": collections
            .iter()
            .map(|name| json!({
                "name": name,
                "scope": [{"url": format!("https://example.com/{name}/"), "match": "prefix"}],
                "keys": [key_entry(&seed_of(name), KEYS_FROM)],
            }))
            .collect::<Vec<_>>(),
    });
    wist_core::envelope::sign_envelope(
        &publisher,
        "publisher",
        &kid(&K1_SEED),
        &SigningKey::from_seed(&K1_SEED),
    )
    .unwrap()
}

fn sealed_state(declaration: &Value) -> State {
    let mut state = State::default();
    let entries = vec![json!({"type": "publisher_declaration", "body": declaration})];
    state
        .declarations
        .apply_epoch(
            0,
            "height 0",
            SEALED_AT,
            7,
            24,
            &Parameters::default().limits().unwrap(),
            &entries,
        )
        .unwrap();
    state.height = Some(0);
    state.sealed_at = Some(SEALED_AT.into());
    state
}

fn signed_catalog(inner: &Value) -> Value {
    let seed = seed_of(inner["collection"].as_str().unwrap());
    wist_core::envelope::sign_envelope(inner, "catalog", &kid(&seed), &SigningKey::from_seed(&seed))
        .unwrap()
}

fn catalog_of(
    collection: &str,
    items: &[Value],
    generated_at: &str,
) -> (Value, Vec<(String, Vec<u8>)>) {
    let built = wist_core::tree::build(items, &wist_core::tree::TreeBounds::suite()).unwrap();
    let inner = json!({
        "wist_version": "1.0.0",
        "publisher": DOMAIN,
        "collection": collection,
        "generated_at": generated_at,
        "size": items.len(),
        "root": root_of(items),
        "tree": built.tree,
    });
    (inner, built.files.into_iter().collect())
}

fn root_of(items: &[Value]) -> String {
    format!(
        "sha256:{}",
        hex_encode(&wist_core::item::root(items).unwrap())
    )
}

fn hold(held: &mut MemoryHeld, collection: &str, catalog_id: &str, items: &[Value]) {
    let catalog = json!({"size": items.len(), "root": root_of(items)});
    held.hold_list(DOMAIN, collection, catalog_id, &catalog, items)
        .unwrap();
}

fn item_ids(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .map(|item| wist_core::item::item_id(item).unwrap())
        .collect()
}

#[derive(Default)]
struct Debits {
    change_lists: u64,
    tree_files: u64,
}

struct Recording {
    site: ServedSite,
    debits: Debits,
}

impl Site for Recording {
    fn fetch(&mut self, request: &Request<'_>) -> clave::error::Result<Answer> {
        let before = self.site.meter;
        if matches!(request.object, Object::Catalog { .. }) {
            self.site.meter = Meter::unbounded();
        }
        let answer = self.site.fetch(request)?;
        if matches!(request.object, Object::Catalog { .. }) {
            self.site.meter = before;
        }
        let debited = before.budget_remaining - self.site.meter.budget_remaining;
        match request.object {
            Object::ChangeList { .. } => self.debits.change_lists += debited,
            Object::TreeFile { .. } => self.debits.tree_files += debited,
            _ => {}
        }
        Ok(answer)
    }
}

struct ChainVectors {
    large: BTreeMap<String, Vec<Value>>,
    payloads: Vec<(String, Vec<u8>)>,
}

impl ChainVectors {
    fn read(vector: &Value) -> Self {
        let large = vector["large_item_sets"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, set)| {
                let mut items: Vec<Value> = set["urls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| {
                        let prefix = entry[0].as_str().unwrap();
                        let fill = entry[1].as_u64().unwrap() as usize;
                        json!({
                            "publisher": set["publisher"],
                            "observed_at": set["observed_at"],
                            "url": format!("{prefix}{}", "x".repeat(fill)),
                            "removed": true,
                        })
                    })
                    .collect();
                items.sort_by_key(|item| wist_core::item::key(item["url"].as_str().unwrap()));
                (name.clone(), items)
            })
            .collect();
        let payloads = vector["payloads"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(hex, payload)| (hex.clone(), octets(payload)))
            .collect();
        ChainVectors { large, payloads }
    }

    fn list(&self, elements: &Value) -> Vec<Value> {
        elements
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|element| match element.as_str() {
                Some(set) => self.large[set].clone(),
                None => vec![element.clone()],
            })
            .collect()
    }

    fn change_list(&self, served: &Value) -> Vec<u8> {
        match served.as_str() {
            Some(text) => text.as_bytes().to_vec(),
            None => {
                let mut compact = served.clone();
                compact["items"] = json!(self.large[served["items"].as_str().unwrap()]);
                octets(&compact)
            }
        }
    }
}

fn seed_pull(held: &mut MemoryHeld, pull: &Value, vectors: &ChainVectors) {
    for (member, collection) in [("held", "journal"), ("held_other_collection", "store")] {
        for (catalog_id, list) in pull[member].as_object().unwrap() {
            hold(held, collection, catalog_id, &vectors.list(list));
        }
    }
    for (hex, file) in pull["tree_files_held"].as_object().unwrap() {
        held.hold_tree_file(DOMAIN, "journal", hex, file.as_str().unwrap().as_bytes())
            .unwrap();
    }
}

fn chain_site(pull: &Value, declaration: &Value, vectors: &ChainVectors) -> Recording {
    let meter = Meter {
        budget_remaining: pull["budget"].as_u64().unwrap_or(u64::MAX),
        bytes_remaining: None,
        objects_remaining: pull.get("objects").and_then(Value::as_u64),
    };
    let mut site = ServedSite::new(meter);
    site.serve(Object::Declaration, octets(declaration));
    site.serve(
        Object::Catalog {
            collection: "journal",
        },
        octets(&signed_catalog(&pull["catalog"])),
    );
    for (hex, served) in pull["change_lists"].as_object().unwrap() {
        site.serve(
            Object::ChangeList {
                collection: "journal",
                hex,
            },
            vectors.change_list(served),
        );
    }
    for (hex, file) in pull["tree_files_served"].as_object().unwrap() {
        site.serve(
            Object::TreeFile {
                collection: "journal",
                hex,
            },
            file.as_str().unwrap().as_bytes().to_vec(),
        );
    }
    for (hex, payload) in &vectors.payloads {
        site.serve(
            Object::Payload {
                collection: "journal",
                hex,
            },
            payload.clone(),
        );
    }
    Recording {
        site,
        debits: Debits::default(),
    }
}

fn parameters(map: &Value) -> Parameters {
    let mut out = Parameters::default();
    for (name, value) in map.as_object().into_iter().flatten() {
        out.set(name, value.as_i64().unwrap());
    }
    out
}

fn run(
    state: &mut State,
    site: &mut impl Site,
    held: &mut MemoryHeld,
    parameters: &Parameters,
) -> PullReport {
    pull(
        state,
        site,
        held,
        &PullInput {
            publisher: DOMAIN,
            at: PULLED_AT,
            parameters,
        },
    )
    .unwrap()
}

fn report_of<'a>(report: &'a PullReport, collection: &str) -> &'a CatalogReport {
    report
        .catalogs
        .iter()
        .find(|catalog| catalog.collection == collection)
        .unwrap()
}

fn held_list_ids(held: &MemoryHeld, catalog_id: &str) -> Option<Vec<String>> {
    held.list(DOMAIN, "journal", catalog_id)
        .unwrap()
        .map(|list| item_ids(&list))
}

fn observed(
    state: &State,
    held: &MemoryHeld,
    catalog: &CatalogReport,
    debits: &Debits,
    carried: bool,
) -> Value {
    let catalog_id = catalog
        .catalog
        .clone()
        .unwrap_or_else(|| panic!("{catalog:?}"));
    let step = catalog
        .list
        .clone()
        .expect("the pull reached the list step");
    let chain = match &step.chain {
        ChainRead::Held => "held",
        ChainRead::NoListHeld => "none",
        ChainRead::Accepted { .. } => "accepted",
        ChainRead::Discarded => "discarded",
        ChainRead::Suspended => "suspended",
        ChainRead::Left => "after_suspension",
    };
    let mut out = json!({
        "chain": chain,
        "lists_read": step.lists_read,
        "octets": debits.change_lists,
    });
    if let ChainRead::Accepted { previous } = &step.chain {
        out["previous"] = json!(previous);
    }
    if matches!(step.chain, ChainRead::Held | ChainRead::Accepted { .. }) {
        out["list"] = json!(held_list_ids(held, &catalog_id).unwrap());
    }
    if let Some(discard) = &catalog.chain {
        out["report"] = json!({
            "code": "WIST2-E08",
            "condition": discard.condition,
            "catalog": discard.catalog,
            "change_list": discard.change_list,
        });
        let stored = state
            .collection(DOMAIN, "journal")
            .unwrap()
            .discarded_chain
            .clone()
            .unwrap();
        assert_eq!(&stored.discard, discard);
    }
    if matches!(
        step.chain,
        ChainRead::Discarded | ChainRead::NoListHeld | ChainRead::Left
    ) {
        let mut walk = match catalog.outcome {
            CatalogOutcome::Suspended => json!({"suspended": true}),
            CatalogOutcome::Refused if catalog.dropped.is_empty() => {
                assert_eq!(catalog.codes, ["WIST2-E07"]);
                json!({"refused": "WIST2-E07"})
            }
            _ => json!({"list": held_list_ids(held, &catalog_id).unwrap()}),
        };
        walk["tree_files_fetched"] = json!(catalog.tree_files_fetched);
        walk["octets"] = json!(debits.tree_files);
        out["walk"] = walk;
    } else {
        assert!(catalog.tree_files_fetched.is_empty());
        assert_eq!(debits.tree_files, 0);
    }
    if carried {
        let mut ids: Vec<&String> = held
            .lists
            .keys()
            .filter(|(p, c, _)| p == DOMAIN && c == "journal")
            .map(|(_, _, id)| id)
            .collect();
        ids.sort();
        out["held_after"] = json!(ids);
    }
    out
}

fn assert_list_outcome(state: &State, catalog: &CatalogReport, name: &str) {
    let step = catalog.list.as_ref().unwrap();
    let collection = state.collection(DOMAIN, "journal").unwrap();
    match catalog.outcome {
        CatalogOutcome::Suspended => assert!(collection.accepted.is_none(), "{name}"),
        CatalogOutcome::Accepted => assert_eq!(
            collection.accepted.as_ref().map(|a| &a.catalog_id),
            catalog.catalog.as_ref(),
            "{name}"
        ),
        CatalogOutcome::Refused => assert!(collection.accepted.is_none(), "{name}"),
        other => panic!("{name}: a Catalog that reached its list step is {other:?}"),
    }
    let left = step.chain == ChainRead::Suspended
        || (catalog.outcome != CatalogOutcome::Accepted && step.chain == ChainRead::Left);
    assert_eq!(collection.left_chain, left, "{name}");
}

#[test]
fn every_change_chain_case_replays_through_the_pull_machine() {
    let vector = read_vector("vectors/wist2/change-chains.json");
    let vectors = ChainVectors::read(&vector);
    let declaration = declaration(&["journal"]);
    let cases = vector["cases"].as_array().unwrap();
    let mut pulls = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let carried = case.get("carried").is_some_and(|c| c == true);
        let mut state = sealed_state(&declaration);
        let mut held = MemoryHeld::default();
        let expected = case["expected"].as_array().unwrap();
        for (index, pull) in case["pulls"].as_array().unwrap().iter().enumerate() {
            if !carried {
                state = sealed_state(&declaration);
                held = MemoryHeld::default();
            }
            if !carried || index == 0 {
                seed_pull(&mut held, pull, &vectors);
            }
            let mut site = chain_site(pull, &declaration, &vectors);
            let report = run(
                &mut state,
                &mut site,
                &mut held,
                &parameters(&pull["parameters"]),
            );
            let catalog = report_of(&report, "journal");
            let seen = observed(&state, &held, catalog, &site.debits, carried);
            assert_eq!(seen, expected[index], "{name}, pull {index}");
            assert_list_outcome(&state, catalog, name);
            pulls += 1;
        }
        assert_eq!(expected.len(), case["pulls"].as_array().unwrap().len());
    }
    assert_eq!(cases.len(), 53);
    assert_eq!(pulls, 64);
}

struct Page {
    item: Value,
    payload: Value,
}

fn page(collection: &str, path: &str, seed: u8) -> Page {
    let url = format!("https://example.com/{collection}/{path}");
    let content = json!({
        "extract": format!("Text of {url}."),
        "links": {"total": 0, "urls": []},
        "summary": {"title": format!("Title {url}")},
    });
    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([seed; 16]);
    let item = json!({
        "publisher": DOMAIN,
        "url": url,
        "observed_at": "2026-09-30T10:00:00Z",
        "payload": {
            "alg": "HMAC-SHA256",
            "bytes": octets(&content).len(),
            "commitment": wist_core::item::commitment(&salt, &content).unwrap(),
        },
        "meta": {"lang": "en"},
    });
    let payload = json!({"wist_version": "1.0.0", "salt": salt, "content": content});
    Page { item, payload }
}

fn removed(collection: &str, path: &str) -> Value {
    json!({
        "publisher": DOMAIN,
        "url": format!("https://example.com/{collection}/{path}"),
        "observed_at": "2026-09-30T10:00:00Z",
        "removed": true,
    })
}

fn serve_catalog(site: &mut ServedSite, inner: &Value, files: &[(String, Vec<u8>)]) {
    let collection = inner["collection"].as_str().unwrap();
    site.serve(
        Object::Catalog { collection },
        octets(&signed_catalog(inner)),
    );
    for (hex, file) in files {
        site.serve(Object::TreeFile { collection, hex }, file.clone());
    }
}

fn serve_page(site: &mut ServedSite, collection: &str, page: &Page) {
    let hex = wist_core::item::payload_name(&page.item).unwrap();
    site.serve(
        Object::Payload {
            collection,
            hex: &hex,
        },
        octets(&page.payload),
    );
}

fn catalog_id(inner: &Value) -> String {
    wist_core::catalog::catalog_id(inner).unwrap()
}

fn change_list(
    previous: &Value,
    previous_list: &[Value],
    next: &Value,
    list: &[Value],
) -> (String, Vec<u8>) {
    let previous: wist_core::objects::Catalog = serde_json::from_value(previous.clone()).unwrap();
    let next: wist_core::objects::Catalog = serde_json::from_value(next.clone()).unwrap();
    let written = wist_core::change_list::write(
        Some(wist_core::change_list::Listed {
            catalog: &previous,
            list: previous_list,
        }),
        wist_core::change_list::Listed {
            catalog: &next,
            list,
        },
    )
    .unwrap()
    .unwrap();
    (written.name, written.octets)
}

#[test]
fn the_resolution_cases_with_a_discarded_chain_resolve_from_a_driven_pull() {
    let vector = read_vector("vectors/wist2/fetch-bounds.json");
    let cases: Vec<&Value> = vector["resolution_cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| {
            case["collections"]
                .as_array()
                .unwrap()
                .iter()
                .any(|collection| collection.get("chain").is_some())
        })
        .collect();
    for case in &cases {
        let label = case["label"].as_str().unwrap();
        let collections = case["collections"].as_array().unwrap();
        let names: Vec<&str> = ["journal", "store"][..collections.len()].to_vec();
        let declaration = declaration(&names);
        let mut state = match case["declaration"].as_str().unwrap() {
            "accepted" => sealed_state(&declaration),
            "discovered" => State::default(),
            other => panic!("{label}: no driven pull for a Declaration {other}"),
        };
        let mut held = MemoryHeld::default();
        let mut site = ServedSite::new(Meter::unbounded());
        site.serve(Object::Declaration, octets(&declaration));
        for (name, collection) in names.iter().zip(collections) {
            match (
                collection["catalog"].as_str().unwrap(),
                collection.get("chain").and_then(Value::as_str),
            ) {
                ("refused", Some("discarded")) => {
                    let earlier = vec![removed(name, "a")];
                    let (earlier_inner, _) = catalog_of(name, &earlier, "2026-10-02T00:00:00Z");
                    hold(&mut held, name, &catalog_id(&earlier_inner), &earlier);
                    let later = vec![removed(name, "a"), removed(name, "b")];
                    let (inner, _) = catalog_of(name, &later, "2026-10-03T00:00:00Z");
                    serve_catalog(&mut site, &inner, &[]);
                }
                ("accepted", None) => {
                    let page = page(name, "p", 3);
                    let (inner, files) = catalog_of(
                        name,
                        std::slice::from_ref(&page.item),
                        "2026-10-03T00:00:00Z",
                    );
                    serve_catalog(&mut site, &inner, &files);
                    serve_page(&mut site, name, &page);
                }
                other => panic!("{label}: no driven Collection for {other:?}"),
            }
        }
        let report = run(&mut state, &mut site, &mut held, &Parameters::default());
        for (name, collection) in names.iter().zip(collections) {
            let catalog = report_of(&report, name);
            if collection.get("chain").is_some() {
                assert_eq!(catalog.outcome, CatalogOutcome::Refused, "{label}");
                assert_eq!(
                    catalog.chain.as_ref().unwrap().condition,
                    RejectionCondition::Fetch,
                    "{label}"
                );
            }
            let admitted = catalog
                .items
                .iter()
                .filter(|item| item.outcome == ItemOutcome::Admitted)
                .count() as u64;
            assert_eq!(
                admitted,
                collection["items_admitted"].as_u64().unwrap_or(0),
                "{label}"
            );
        }
        assert_eq!(report.suspended, case["suspended"], "{label}");
        let resolution = report.resolution(case["labels_admitted"].as_u64().unwrap() as usize);
        assert_eq!(resolution.code, case["resolution"].as_str(), "{label}");
        assert_eq!(resolution.noise, case["noise"], "{label}");
        assert_eq!(
            json!(report.codes_recorded()),
            case["codes_recorded"],
            "{label}"
        );
    }
    assert_eq!(cases.len(), 4);
}

struct Published {
    inner: Value,
    id: String,
    items: Vec<Value>,
    files: Vec<(String, Vec<u8>)>,
}

fn published(items: Vec<Value>, generated_at: &str) -> Published {
    let mut items = items;
    items.sort_by_key(|item| wist_core::item::key(item["url"].as_str().unwrap()));
    let (inner, files) = catalog_of("journal", &items, generated_at);
    Published {
        id: catalog_id(&inner),
        inner,
        items,
        files,
    }
}

fn removed_items(range: std::ops::Range<u32>) -> Vec<Value> {
    range
        .map(|n| removed("journal", &format!("r{n}")))
        .collect()
}

fn journal_site(meter: Meter, declaration: &Value, catalog: &Published) -> ServedSite {
    let mut site = ServedSite::new(meter);
    site.serve(Object::Declaration, octets(declaration));
    serve_catalog(&mut site, &catalog.inner, &catalog.files);
    site
}

fn serve_change_list(site: &mut ServedSite, from: &Published, to: &Published) -> Vec<u8> {
    let (hex, written) = change_list(&from.inner, &from.items, &to.inner, &to.items);
    site.serve(
        Object::ChangeList {
            collection: "journal",
            hex: &hex,
        },
        written.clone(),
    );
    written
}

fn requested_change_lists(site: &ServedSite) -> usize {
    site.requested
        .iter()
        .filter(|path| path.contains("/changes/"))
        .count()
}

fn journal_state(state: &State) -> &clave::collection::state::CollectionState {
    state.collection(DOMAIN, "journal").unwrap()
}

#[test]
fn a_chain_left_at_a_suspension_reads_no_change_list_until_a_walk_obtains_a_list() {
    let declaration = declaration(&["journal"]);
    let mut state = sealed_state(&declaration);
    let mut held = MemoryHeld::default();
    let earlier = published(removed_items(0..48), "2026-10-02T00:00:00Z");
    hold(&mut held, "journal", &earlier.id, &earlier.items);
    let later = published(removed_items(0..50), "2026-10-03T00:00:00Z");
    assert!(later.files.len() > 2);
    let catalog_octets = octets(&signed_catalog(&later.inner)).len() as u64;

    let mut probe = journal_site(Meter::unbounded(), &declaration, &later);
    let chain_octets = serve_change_list(&mut probe, &earlier, &later).len() as u64;
    let short = Meter {
        budget_remaining: catalog_octets + chain_octets - 1,
        ..Meter::unbounded()
    };
    let mut site = journal_site(short, &declaration, &later);
    serve_change_list(&mut site, &earlier, &later);
    let suspended = run(&mut state, &mut site, &mut held, &Parameters::default());
    let catalog = report_of(&suspended, "journal");
    assert_eq!(catalog.outcome, CatalogOutcome::Suspended);
    assert_eq!(catalog.list.as_ref().unwrap().chain, ChainRead::Suspended);
    assert!(catalog.chain.is_none());
    assert!(suspended.suspended);
    assert_eq!(suspended.resolution(0).code, None);
    assert!(journal_state(&state).left_chain);
    assert!(journal_state(&state).discarded_chain.is_none());

    let two_objects = Meter {
        objects_remaining: Some(2),
        ..Meter::unbounded()
    };
    let mut site = journal_site(two_objects, &declaration, &later);
    serve_change_list(&mut site, &earlier, &later);
    let walking = run(&mut state, &mut site, &mut held, &Parameters::default());
    let catalog = report_of(&walking, "journal");
    assert_eq!(catalog.list.as_ref().unwrap().chain, ChainRead::Left);
    assert_eq!(catalog.outcome, CatalogOutcome::Suspended);
    assert_eq!(catalog.tree_files_fetched.len(), 1);
    assert_eq!(requested_change_lists(&site), 0);
    assert!(journal_state(&state).left_chain);

    let mut site = journal_site(Meter::unbounded(), &declaration, &later);
    serve_change_list(&mut site, &earlier, &later);
    let listed = run(&mut state, &mut site, &mut held, &Parameters::default());
    let catalog = report_of(&listed, "journal");
    assert_eq!(catalog.list.as_ref().unwrap().chain, ChainRead::Left);
    assert_eq!(catalog.outcome, CatalogOutcome::Accepted);
    assert_eq!(catalog.tree_files_fetched.len(), later.files.len() - 1);
    assert_eq!(requested_change_lists(&site), 0);
    assert!(!journal_state(&state).left_chain);

    let next = published(removed_items(1..50), "2026-10-04T00:00:00Z");
    let mut site = journal_site(Meter::unbounded(), &declaration, &next);
    serve_change_list(&mut site, &later, &next);
    let chained = run(&mut state, &mut site, &mut held, &Parameters::default());
    let catalog = report_of(&chained, "journal");
    assert_eq!(catalog.outcome, CatalogOutcome::Accepted);
    assert_eq!(
        catalog.list.as_ref().unwrap().chain,
        ChainRead::Accepted {
            previous: later.id.clone()
        }
    );
    assert!(catalog.tree_files_fetched.is_empty());
}

#[test]
fn a_discarded_chain_is_reported_as_wist2_e08_and_a_later_discard_replaces_the_report() {
    let declaration = declaration(&["journal"]);
    let mut state = sealed_state(&declaration);
    let mut held = MemoryHeld::default();
    let first = published(removed_items(0..3), "2026-10-02T00:00:00Z");
    hold(&mut held, "journal", &first.id, &first.items);

    let second = published(removed_items(0..4), "2026-10-03T00:00:00Z");
    let mut site = journal_site(Meter::unbounded(), &declaration, &second);
    let report = run(&mut state, &mut site, &mut held, &Parameters::default());
    let catalog = report_of(&report, "journal");
    assert_eq!(catalog.outcome, CatalogOutcome::Accepted);
    assert_eq!(report.codes_recorded(), ["WIST2-E08"]);
    let rejection = journal_state(&state)
        .discarded_chain
        .as_ref()
        .unwrap()
        .rejection("journal");
    assert_eq!(
        serde_json::to_value(&rejection).unwrap(),
        json!({
            "code": "WIST2-E08",
            "at": PULLED_AT,
            "id": second.id,
            "collection": "journal",
            "condition": "fetch",
            "change_list": second.id,
        })
    );

    let third = published(removed_items(0..5), "2026-10-04T00:00:00Z");
    let mut site = journal_site(Meter::unbounded(), &declaration, &third);
    let mut written = serve_change_list(&mut site, &second, &third);
    written.push(b' ');
    site.serve(
        Object::ChangeList {
            collection: "journal",
            hex: &third.id["sha256:".len()..],
        },
        written,
    );
    run(&mut state, &mut site, &mut held, &Parameters::default());
    let stored = journal_state(&state).discarded_chain.clone().unwrap();
    assert_eq!(stored.discard.condition, RejectionCondition::Form);
    assert_eq!(stored.discard.catalog, third.id);

    let fourth = published(removed_items(0..6), "2026-10-05T00:00:00Z");
    let mut site = journal_site(Meter::unbounded(), &declaration, &fourth);
    serve_change_list(&mut site, &third, &fourth);
    let accepted = run(&mut state, &mut site, &mut held, &Parameters::default());
    let catalog = report_of(&accepted, "journal");
    assert!(matches!(
        catalog.list.as_ref().unwrap().chain,
        ChainRead::Accepted { .. }
    ));
    assert!(accepted.codes_recorded().is_empty());
    assert_eq!(journal_state(&state).discarded_chain, Some(stored));
}

#[test]
fn a_list_obtained_by_a_chain_is_refused_for_a_dropped_record_and_stays_held() {
    let declaration = declaration(&["journal"]);
    let mut state = sealed_state(&declaration);
    let mut held = MemoryHeld::default();
    let earlier = published(removed_items(0..3), "2026-10-02T00:00:00Z");
    hold(&mut held, "journal", &earlier.id, &earlier.items);
    let gone = removed("journal", "r2");
    let dropped = gone["url"].as_str().unwrap().to_owned();
    state.records.insert(
        (DOMAIN.into(), dropped.clone()),
        clave::collection::state::Record {
            item_id: wist_core::item::item_id(&gone).unwrap(),
            item: gone,
            collection: "journal".into(),
            catalog_id: earlier.id.clone(),
            generated_at: "2026-10-02T00:00:00Z".into(),
            sealing_height: 0,
        },
    );
    let later = published(removed_items(0..2), "2026-10-03T00:00:00Z");
    let mut site = journal_site(Meter::unbounded(), &declaration, &later);
    serve_change_list(&mut site, &earlier, &later);
    let report = run(&mut state, &mut site, &mut held, &Parameters::default());
    let catalog = report_of(&report, "journal");
    assert_eq!(catalog.outcome, CatalogOutcome::Refused);
    assert_eq!(catalog.codes, ["WIST2-E07"]);
    assert_eq!(catalog.dropped, [dropped]);
    assert!(matches!(
        catalog.list.as_ref().unwrap().chain,
        ChainRead::Accepted { .. }
    ));
    assert!(catalog.tree_files_fetched.is_empty());
    assert!(!site.requested.iter().any(|path| path.contains("/tree/")));
    assert_eq!(
        held.list(DOMAIN, "journal", &later.id).unwrap(),
        Some(later.items.clone())
    );
    let again = run(&mut state, &mut site, &mut held, &Parameters::default());
    assert_eq!(
        report_of(&again, "journal").list.as_ref().unwrap().chain,
        ChainRead::Held
    );
}
