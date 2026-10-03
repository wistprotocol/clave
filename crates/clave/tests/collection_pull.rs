use base64::Engine;
use clave::collection::pull::{CatalogOutcome, CatalogReport, ItemOutcome, PayloadSource};
use clave::collection::state::{Place, Record, SealedCatalog, WaitingUrl};
use clave::collection::{
    pull, Held, MemoryHeld, Meter, Object, Parameters, PullInput, PullReport, ServedSite, State,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use wist_core::crypto::{hex_encode, SigningKey};

const DOMAIN: &str = "example.com";
const JOURNAL_SEED: [u8; 32] = [0xc6; 32];
const JOURNAL_KID: &str = "e6uOIB9gFydR5y7WXWxjsTMZNh7fEbczAAwPBbxuiw8";
const SEALED_AT: &str = "2026-10-01T00:00:00Z";
const PULLED_AT: &str = "2026-10-01T00:05:00Z";

fn spec_dir() -> std::path::PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
}

fn declaration() -> Value {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist2/declaration-pull.json")).unwrap(),
    )
    .unwrap();
    vector["state_pull_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "first contact: pulled under the fetched Declaration")
        .unwrap()["declarations"]["G"]
        .clone()
}

fn octets(value: &Value) -> Vec<u8> {
    wist_core::jcs::canonicalize(value).unwrap()
}

fn sealed_state() -> State {
    let mut state = State::default();
    let entries = vec![json!({"type": "publisher_declaration", "body": declaration()})];
    let suite = Parameters::default();
    state
        .declarations
        .apply_epoch(
            0,
            "height 0",
            SEALED_AT,
            7,
            24,
            &suite.limits().unwrap(),
            &entries,
        )
        .unwrap();
    state.height = Some(0);
    state
}

struct Page {
    item: Value,
    payload: Value,
}

fn page(path: &str, seed: u8) -> Page {
    let url = format!("https://example.com/journal/{path}");
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

fn removed(path: &str) -> Value {
    json!({
        "publisher": DOMAIN,
        "url": format!("https://example.com/journal/{path}"),
        "observed_at": "2026-09-30T10:00:00Z",
        "removed": true,
    })
}

struct Published {
    envelope: Value,
    catalog_id: String,
    files: Vec<(String, Vec<u8>)>,
}

fn publish(items: &[Value], generated_at: &str) -> Published {
    let built = wist_core::tree::build(items, &wist_core::tree::TreeBounds::suite()).unwrap();
    let inner = json!({
        "wist_version": "1.0.0",
        "publisher": DOMAIN,
        "collection": "journal",
        "generated_at": generated_at,
        "size": items.len(),
        "root": format!("sha256:{}", hex_encode(&wist_core::item::root(items).unwrap())),
        "tree": built.tree,
    });
    let envelope = wist_core::envelope::sign_envelope(
        &inner,
        "catalog",
        JOURNAL_KID,
        &SigningKey::from_seed(&JOURNAL_SEED),
    )
    .unwrap();
    Published {
        catalog_id: wist_core::catalog::catalog_id(&inner).unwrap(),
        envelope,
        files: built.files.into_iter().collect(),
    }
}

fn site(meter: Meter, published: &Published, pages: &[&Page]) -> ServedSite {
    let mut site = ServedSite::new(meter);
    site.serve(Object::Declaration, octets(&declaration()));
    site.serve(
        Object::Catalog {
            collection: "journal",
        },
        octets(&published.envelope),
    );
    for (hex, file) in &published.files {
        site.serve(
            Object::TreeFile {
                collection: "journal",
                hex,
            },
            file.clone(),
        );
    }
    for page in pages {
        let hex = payload_hex(&page.item);
        site.serve(
            Object::Payload {
                collection: "journal",
                hex: &hex,
            },
            octets(&page.payload),
        );
    }
    site
}

fn payload_hex(item: &Value) -> String {
    wist_core::item::payload_name(item).unwrap()
}

fn payload_path(item: &Value) -> String {
    Object::Payload {
        collection: "journal",
        hex: &payload_hex(item),
    }
    .path()
}

fn run(state: &mut State, site: &mut ServedSite, held: &mut MemoryHeld) -> PullReport {
    pull(
        state,
        site,
        held,
        &PullInput {
            publisher: DOMAIN,
            at: PULLED_AT,
            parameters: &Parameters::default(),
        },
    )
    .unwrap()
}

fn journal(report: &PullReport) -> &CatalogReport {
    report
        .catalogs
        .iter()
        .find(|catalog| catalog.collection == "journal")
        .unwrap()
}

fn item_id(item: &Value) -> String {
    wist_core::item::item_id(item).unwrap()
}

fn limited(objects: u64) -> Meter {
    Meter {
        objects_remaining: Some(objects),
        ..Meter::unbounded()
    }
}

#[test]
fn an_accepted_catalog_admits_its_items_and_its_urls_take_places_at_the_pull() {
    let pages = [page("a", 1), page("b", 2)];
    let items: Vec<Value> = pages.iter().map(|page| page.item.clone()).collect();
    let published = publish(&items, SEALED_AT);
    let mut state = sealed_state();
    let mut site = site(Meter::unbounded(), &published, &[&pages[0], &pages[1]]);
    let mut held = MemoryHeld::default();
    let report = run(&mut state, &mut site, &mut held);
    assert_eq!(report.collections_pulled, ["journal", "store", "default"]);
    let catalog = journal(&report);
    assert_eq!(catalog.outcome, CatalogOutcome::Accepted);
    assert_eq!(
        catalog.catalog.as_deref(),
        Some(published.catalog_id.as_str())
    );
    assert!(catalog
        .items
        .iter()
        .all(|item| item.outcome == ItemOutcome::Admitted
            && item.payload == Some(PayloadSource::Fetched)));
    assert_eq!(catalog.items.len(), 2);
    assert_eq!(report.resolution(0).code, None);
    let accepted = state
        .collection(DOMAIN, "journal")
        .unwrap()
        .waiting()
        .unwrap();
    assert_eq!(accepted.place, Place::catalog(report.event, 0));
    assert_eq!(accepted.eligibility, 1);
    for (index, item) in catalog.items.iter().enumerate() {
        let waiting = &state.urls[&(DOMAIN.to_owned(), item.url.clone())];
        assert_eq!(
            *waiting,
            WaitingUrl {
                collection: "journal".into(),
                item_id: item.item.clone(),
                place: Place::url(report.event, 0, index as u64),
                eligibility: 1,
            }
        );
    }
}

#[test]
fn a_walk_resumed_from_held_tree_files_fetches_only_the_missing_ones() {
    let items: Vec<Value> = (0..48).map(|n| removed(&format!("r{n}"))).collect();
    let published = publish(&items, SEALED_AT);
    assert!(published.files.len() > 3);
    let mut state = sealed_state();
    let mut held = MemoryHeld::default();
    let mut first = site(limited(3), &published, &[]);
    let suspended = run(&mut state, &mut first, &mut held);
    let catalog = journal(&suspended);
    assert_eq!(catalog.outcome, CatalogOutcome::Suspended);
    assert_eq!(catalog.tree_files_fetched.len(), 2);
    assert!(suspended.suspended);
    assert_eq!(suspended.resolution(0).code, None);
    assert!(state
        .collection(DOMAIN, "journal")
        .unwrap()
        .accepted
        .is_none());
    let mut second = site(Meter::unbounded(), &published, &[]);
    let resumed = run(&mut state, &mut second, &mut held);
    let catalog = journal(&resumed);
    assert_eq!(catalog.outcome, CatalogOutcome::Accepted);
    let before: BTreeSet<&String> = journal(&suspended).tree_files_fetched.iter().collect();
    let after: BTreeSet<&String> = catalog.tree_files_fetched.iter().collect();
    let all: BTreeSet<&String> = published.files.iter().map(|(hex, _)| hex).collect();
    assert!(before.is_disjoint(&after));
    assert_eq!(before.union(&after).copied().collect::<BTreeSet<_>>(), all);
    assert_eq!(catalog.items.len(), 48);
}

#[test]
fn a_per_pull_object_limit_suspends_the_items_of_an_accepted_catalog_without_refusing_it() {
    let pages: Vec<Page> = (0..4).map(|n| page(&format!("p{n}"), n + 1)).collect();
    let items: Vec<Value> = pages.iter().map(|page| page.item.clone()).collect();
    let published = publish(&items, SEALED_AT);
    let objects = 1 + published.files.len() as u64 + 2;
    let mut state = sealed_state();
    let mut held = MemoryHeld::default();
    let served: Vec<&Page> = pages.iter().collect();
    let mut first = site(limited(objects), &published, &served);
    let report = run(&mut state, &mut first, &mut held);
    let catalog = journal(&report);
    assert_eq!(catalog.outcome, CatalogOutcome::Accepted);
    assert!(catalog.suspended && report.suspended);
    assert_eq!(catalog.items.len(), 2);
    assert_eq!(report.catalogs.len(), 1);
    assert!(report.collections_pulled.len() > 1);
    let judged: Vec<String> = catalog.items.iter().map(|item| item.url.clone()).collect();
    let mut second = site(Meter::unbounded(), &published, &served);
    let retried = run(&mut state, &mut second, &mut held);
    let catalog = journal(&retried);
    assert_eq!(catalog.outcome, CatalogOutcome::Idempotent);
    assert!(catalog.tree_files_fetched.is_empty());
    assert_eq!(catalog.items.len(), 2);
    assert!(catalog
        .items
        .iter()
        .all(|item| !judged.contains(&item.url) && item.outcome == ItemOutcome::Admitted));
}

#[test]
fn an_answer_304_is_judged_as_the_catalog_whose_validator_was_sent() {
    let pages = [page("a", 1)];
    let published = publish(&[pages[0].item.clone()], SEALED_AT);
    let mut state = sealed_state();
    let mut held = MemoryHeld::default();
    let mut site = site(Meter::unbounded(), &published, &[&pages[0]]);
    let mut forged = published.envelope.clone();
    forged["catalog"]["generated_at"] = json!("2026-10-01T00:01:00Z");
    site.serve(
        Object::Catalog {
            collection: "journal",
        },
        octets(&forged),
    );
    let refused = run(&mut state, &mut site, &mut held);
    assert_eq!(journal(&refused).outcome, CatalogOutcome::Refused);
    assert_eq!(journal(&refused).codes, ["WIST1-E01"]);
    let requested = site.requested.len();
    let budget = site.meter.budget_remaining;
    let again = run(&mut state, &mut site, &mut held);
    assert_eq!(site.meter.budget_remaining, budget);
    assert_eq!(journal(&again).outcome, CatalogOutcome::Refused);
    assert_eq!(journal(&again).codes, ["WIST1-E01"]);
    assert!(site.requested[requested..].contains(&"collections/journal/catalog.json".to_owned()));
    site.serve(
        Object::Catalog {
            collection: "journal",
        },
        octets(&published.envelope),
    );
    let accepted = run(&mut state, &mut site, &mut held);
    assert_eq!(journal(&accepted).outcome, CatalogOutcome::Accepted);
    let budget = site.meter.budget_remaining;
    let unchanged = run(&mut state, &mut site, &mut held);
    assert_eq!(site.meter.budget_remaining, budget);
    let catalog = journal(&unchanged);
    assert_eq!(catalog.outcome, CatalogOutcome::Idempotent);
    assert_eq!(
        catalog.catalog.as_deref(),
        Some(published.catalog_id.as_str())
    );
    assert!(catalog.tree_files_fetched.is_empty());
}

#[test]
fn an_item_withdrawn_in_the_log_is_not_admitted_and_its_payload_is_not_fetched() {
    let pages = [page("a", 1), page("b", 2)];
    let items: Vec<Value> = pages.iter().map(|page| page.item.clone()).collect();
    let published = publish(&items, SEALED_AT);
    let mut state = sealed_state();
    state.withdrawals.adopt(&item_id(&pages[0].item), DOMAIN, 0);
    let mut held = MemoryHeld::default();
    let mut site = site(Meter::unbounded(), &published, &[&pages[0], &pages[1]]);
    let report = run(&mut state, &mut site, &mut held);
    let catalog = journal(&report);
    let withdrawn = catalog
        .items
        .iter()
        .find(|item| item.item == item_id(&pages[0].item))
        .unwrap();
    assert_eq!(withdrawn.outcome, ItemOutcome::NotAdmitted);
    assert_eq!(withdrawn.codes, ["WIST2-E03"]);
    assert_eq!(withdrawn.payload, Some(PayloadSource::Withdrawn));
    assert!(!site.requested.contains(&payload_path(&pages[0].item)));
    assert!(site.requested.contains(&payload_path(&pages[1].item)));
    assert!(held.payload(&item_id(&pages[0].item)).unwrap().is_none());
    assert!(!state.urls.contains_key(&(
        DOMAIN.to_owned(),
        pages[0].item["url"].as_str().unwrap().into()
    )));
}

fn record(url: &str) -> Record {
    Record {
        item: json!({
            "publisher": DOMAIN,
            "url": url,
            "observed_at": "2026-09-14T00:00:00Z",
            "removed": true,
        }),
        item_id: "sha256:00".into(),
        collection: "journal".into(),
        catalog_id: "sha256:01".into(),
        generated_at: "2026-09-15T00:00:00Z".into(),
        sealing_height: 0,
    }
}

fn floor_at(state: &mut State, generated_at: &str) {
    let inner = json!({
        "wist_version": "1.0.0",
        "publisher": DOMAIN,
        "collection": "journal",
        "generated_at": generated_at,
        "size": 0,
        "root": format!("sha256:{}", hex_encode(&[0; 32])),
        "tree": format!("sha256:{}", hex_encode(&[0; 32])),
    });
    state
        .collections
        .entry((DOMAIN.into(), "journal".into()))
        .or_default()
        .latest = Some(SealedCatalog {
        catalog_id: wist_core::catalog::catalog_id(&inner).unwrap(),
        envelope: json!({"catalog": inner}),
        sealing_height: 0,
        base: false,
    });
}

fn hold_records(state: &mut State, urls: &[&str]) {
    for url in urls {
        state
            .records
            .insert((DOMAIN.to_owned(), url.to_string()), record(url));
    }
}

#[test]
fn a_list_that_drops_the_url_of_a_held_record_is_refused_with_wist2_e07_and_stays_held() {
    let items = vec![removed("kept")];
    let published = publish(&items, SEALED_AT);
    let mut state = sealed_state();
    floor_at(&mut state, "2026-09-15T00:00:00Z");
    hold_records(
        &mut state,
        &[
            "https://example.com/journal/gone",
            "https://example.com/journal/also-gone",
            "https://example.com/elsewhere",
        ],
    );
    let mut held = MemoryHeld::default();
    let mut site = site(Meter::unbounded(), &published, &[]);
    let report = run(&mut state, &mut site, &mut held);
    let catalog = journal(&report);
    assert_eq!(catalog.outcome, CatalogOutcome::Refused);
    assert_eq!(catalog.codes, ["WIST2-E07"]);
    assert_eq!(
        catalog.dropped,
        [
            "https://example.com/journal/also-gone",
            "https://example.com/journal/gone"
        ]
    );
    assert!(!catalog.base);
    assert!(catalog.items.is_empty());
    assert!(state
        .collection(DOMAIN, "journal")
        .unwrap()
        .accepted
        .is_none());
    assert_eq!(
        held.list(DOMAIN, "journal", &published.catalog_id).unwrap(),
        Some(items)
    );
    let again = run(&mut state, &mut site, &mut held);
    let catalog = journal(&again);
    assert_eq!(catalog.outcome, CatalogOutcome::Refused);
    assert!(catalog.tree_files_fetched.is_empty());
    assert_eq!(again.resolution(0).code, Some("WIST2-E02"));
}

#[test]
fn a_base_against_the_floor_is_exempt_from_the_dropped_record_refusal() {
    let items = vec![removed("kept")];
    let published = publish(&items, SEALED_AT);
    let mut state = sealed_state();
    floor_at(&mut state, "2026-03-01T00:00:00Z");
    hold_records(&mut state, &["https://example.com/journal/gone"]);
    let mut held = MemoryHeld::default();
    let mut site = site(Meter::unbounded(), &published, &[]);
    let report = run(&mut state, &mut site, &mut held);
    let catalog = journal(&report);
    assert_eq!(catalog.outcome, CatalogOutcome::Accepted);
    assert!(catalog.base);
    assert!(catalog.dropped.is_empty());
    let accepted = state
        .collection(DOMAIN, "journal")
        .unwrap()
        .accepted
        .clone()
        .unwrap();
    assert!(accepted.base_against_floor);
}

#[test]
fn a_declaration_that_reduces_authority_is_discovered_with_its_sealing_deadline() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist2/declaration-pull.json")).unwrap(),
    )
    .unwrap();
    let case = vector["pull_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["acceptance"] == "ordinary_rotation")
        .unwrap();
    assert_eq!(case["known"], declaration());
    let mut state = sealed_state();
    let mut site = ServedSite::new(Meter::unbounded());
    site.serve(Object::Declaration, octets(&case["fetched"]));
    let report = run(&mut state, &mut site, &mut MemoryHeld::default());
    assert_eq!(report.declaration.outcome, "ordinary_rotation");
    assert!(report.declaration.discovered && report.declaration.reduces_authority);
    let found = &state.discovered[DOMAIN];
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].last_sealed_at_discovery, Some(0));
    assert_eq!(found[0].last_seal_height, Some(25));
    assert_eq!(report.resolution(0).code, None);
    let again = run(&mut state, &mut site, &mut MemoryHeld::default());
    assert_eq!(again.declaration.outcome, "idempotent");
    assert!(!again.declaration.discovered);
    assert_eq!(state.discovered[DOMAIN].len(), 1);
}
