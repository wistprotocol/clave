use clave::collection::pull::{CatalogOutcome, CatalogReport, DeclarationReport, ItemOutcome};
use clave::collection::site::{validator, Metered};
use clave::collection::state::{Discovered, ServedFile};
use clave::collection::{
    pull, MemoryHeld, Meter, Object, Parameters, PullInput, PullReport, ServedSite, State,
};
use serde_json::Value;
use std::collections::BTreeMap;
use wist_core::declarations::Position;

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

fn octets(envelope: &Value) -> Vec<u8> {
    wist_core::jcs::canonicalize(envelope).unwrap()
}

fn parameters(maps: &[&Value]) -> Parameters {
    let mut out = Parameters::default();
    for map in maps {
        for (name, value) in map.as_object().into_iter().flatten() {
            out.set(name, value.as_i64().unwrap());
        }
    }
    out
}

fn limits(map: &Parameters) -> wist_core::collection::Limits {
    map.limits().unwrap()
}

fn serve_declaration(
    state: &mut State,
    site: &mut ServedSite,
    domain: &str,
    outcome: &str,
    fetched: Option<&Value>,
) {
    match outcome {
        "failed" | "timed_out" => assert!(fetched.is_none()),
        "new_octets" | "same_octets" => site.serve(Object::Declaration, octets(fetched.unwrap())),
        "not_modified" => {
            let served = octets(fetched.unwrap());
            state.declaration_files.insert(
                domain.into(),
                ServedFile {
                    validator: Some(validator(&served)),
                    octets: served.clone(),
                },
            );
            site.serve(Object::Declaration, served);
        }
        other => panic!("unknown fetch outcome {other}"),
    }
}

fn run(
    state: &mut State,
    site: &mut ServedSite,
    domain: &str,
    at: &str,
    map: &Parameters,
) -> PullReport {
    pull(
        state,
        site,
        &mut MemoryHeld::default(),
        &PullInput {
            publisher: domain,
            at,
            parameters: map,
        },
    )
    .unwrap()
}

fn assert_declaration_stop(report: &PullReport, name: &str) {
    if !report.declaration.proceeds {
        assert!(report.catalogs.is_empty(), "{name}");
        assert!(report.collections_pulled.is_empty(), "{name}");
    }
}

#[test]
fn a_pull_applies_the_fetched_declaration_against_the_current_one() {
    let vector = read_vector("vectors/wist2/declaration-pull.json");
    let cases = vector["pull_cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let known = &case["known"];
        let domain = known["publisher"]["domain"].as_str().unwrap();
        let sealed_at = "2026-10-01T00:00:00Z";
        let sealed_at_s = wist_core::timestamp::log_seconds(sealed_at).unwrap();
        let mut state = State::default();
        state
            .declarations
            .adopt(
                domain,
                known.clone(),
                Position {
                    epoch_number: 0,
                    entry_index: 0,
                },
                sealed_at_s,
                known["publisher"]["seq"].as_u64().unwrap(),
                None,
                None,
            )
            .unwrap();
        state.declarations.seed_head(0, "root", Some(sealed_at_s));
        state.height = Some(0);
        let known_octets = octets(known);
        state.declaration_files.insert(
            domain.into(),
            ServedFile {
                validator: Some(validator(&known_octets)),
                octets: known_octets,
            },
        );
        let mut site = ServedSite::new(Meter::unbounded());
        let outcome = case["fetch_outcome"].as_str().unwrap();
        let fetched = if outcome == "not_modified" {
            Some(known)
        } else {
            Some(&case["fetched"]).filter(|fetched| !fetched.is_null())
        };
        serve_declaration(&mut state, &mut site, domain, outcome, fetched);
        let map = Parameters::default();
        let report = run(&mut state, &mut site, domain, "2026-10-01T01:00:00Z", &map);
        let acceptance = match report.declaration.outcome.as_str() {
            "fresh_identity_pending" => "fresh_identity",
            other => other,
        };
        assert_eq!(acceptance, case["acceptance"], "{name}");
        assert_eq!(report.declaration.proceeds, case["proceeds"], "{name}");
        assert_eq!(
            serde_json::json!(report.collections_pulled),
            case["collections_pulled"],
            "{name}"
        );
        assert_declaration_stop(&report, name);
    }
    assert_eq!(cases.len(), 8);
}

fn replay_epochs(state: &mut State, case: &Value, history: &Value) -> BTreeMap<String, String> {
    let envelopes = case["declarations"].as_object().unwrap();
    let labels: BTreeMap<String, String> = envelopes
        .iter()
        .map(|(label, envelope)| {
            (
                wist_core::declaration::inner_hash(envelope).unwrap(),
                label.clone(),
            )
        })
        .collect();
    for epoch in case["epochs"].as_array().unwrap() {
        let map = parameters(&[history, &epoch["parameters"]]);
        let height = epoch["height"].as_u64().unwrap();
        let mut entries: Vec<Value> = epoch["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|label| {
                serde_json::json!({
                    "type": "publisher_declaration",
                    "body": envelopes[label.as_str().unwrap()],
                })
            })
            .collect();
        wist_core::epoch::sort_entries(&mut entries).unwrap();
        let sealed_at = epoch["sealed_at"].as_str().unwrap();
        state
            .declarations
            .apply_epoch(
                height,
                &format!("height {height}"),
                sealed_at,
                map.value("recovery_window_days").unwrap(),
                map.value("declaration_activation_epochs").unwrap(),
                &limits(&map),
                &entries,
            )
            .unwrap();
        state.height = Some(height);
    }
    labels
}

fn declaration_view(report: &DeclarationReport, labels: &BTreeMap<String, String>) -> Value {
    serde_json::json!({
        "acceptance": report.outcome,
        "proceeds": report.proceeds,
        "sources": report.sources.iter().map(|hash| labels[hash].clone()).collect::<Vec<_>>(),
        "disposition": report.disposition(),
    })
}

#[test]
fn a_pull_reads_the_sources_the_publisher_state_gives_once_the_fetched_declaration_applies() {
    let vector = read_vector("vectors/wist2/declaration-pull.json");
    let cases = vector["state_pull_cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let history = case
            .get("history_parameters")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let mut state = State::default();
        let labels = replay_epochs(&mut state, case, &history);
        let domain = case["declarations"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["publisher"]["domain"]
            .as_str()
            .unwrap()
            .to_owned();
        for label in case["discovered"].as_array().unwrap() {
            let envelope = case["declarations"][label.as_str().unwrap()].clone();
            state
                .discovered
                .entry(domain.clone())
                .or_default()
                .push(Discovered {
                    hash: wist_core::declaration::inner_hash(&envelope).unwrap(),
                    envelope,
                    event: 0,
                    last_sealed_at_discovery: state.height,
                    reduces_authority: false,
                    last_seal_height: None,
                    competitor: false,
                    competes_with: None,
                });
        }
        let request = &case["pull"];
        let map = parameters(&[&history, &request["parameters"]]);
        let fetched = request["fetched"]
            .as_str()
            .map(|label| &case["declarations"][label]);
        let mut site = ServedSite::new(Meter::unbounded());
        serve_declaration(
            &mut state,
            &mut site,
            &domain,
            request["fetch_outcome"].as_str().unwrap(),
            fetched,
        );
        let report = run(
            &mut state,
            &mut site,
            &domain,
            request["sealed_at"].as_str().unwrap(),
            &map,
        );
        let expected = &case["expected"];
        let mut view = declaration_view(&report.declaration, &labels);
        view["collections_pulled"] = serde_json::json!(report.collections_pulled);
        view["noise"] = (!report.declaration.proceeds && report.resolution(0).noise).into();
        let wanted = serde_json::json!({
            "acceptance": expected["acceptance"],
            "proceeds": expected["proceeds"],
            "sources": expected["sources"],
            "disposition": expected["disposition"],
            "collections_pulled": expected["collections_pulled"],
            "noise": expected["noise"],
        });
        assert_eq!(view, wanted, "{name}");
        assert_declaration_stop(&report, name);
    }
    assert_eq!(cases.len(), 32);
}

#[test]
fn a_fetch_under_the_budget_and_per_pull_limits_is_decided_by_the_bound_met_first() {
    let vector = read_vector("vectors/wist2/fetch-bounds.json");
    let cases = vector["work_cases"].as_array().unwrap();
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let number = |member: &str| case[member].as_u64().unwrap();
        let mut meter = Meter {
            budget_remaining: number("budget_remaining"),
            bytes_remaining: Some(number("work_bytes_remaining")),
            objects_remaining: Some(number("work_objects_remaining")),
        };
        let (metered, debited) = meter.read(number("object_bound"), number("object_bytes"));
        let outcome = match metered {
            Metered::Read => "fetched",
            Metered::Failed => "failed",
            Metered::Suspended => "suspended",
        };
        assert_eq!(outcome, case["outcome"], "{label}");
        assert_eq!(debited, number("debited"), "{label}");
        assert_eq!(
            meter.budget_remaining,
            number("budget_remaining") - debited,
            "{label}"
        );
    }
    assert_eq!(cases.len(), 11);
}

const CATALOG_CODES: [&str; 4] = ["WIST2-E01", "WIST2-E04", "WIST2-E05", "WIST2-E07"];

fn resolution_report(case: &Value) -> (PullReport, usize) {
    let declaration = case["declaration"].as_str().unwrap();
    let mut report = PullReport {
        event: 0,
        settlement: Vec::new(),
        declaration: DeclarationReport {
            outcome: "idempotent".into(),
            proceeds: !declaration.starts_with("stopped"),
            first_contact: declaration == "stopped_first_contact",
            discovered: declaration == "discovered",
            reduces_authority: false,
            sources: Vec::new(),
            window: false,
        },
        collections_pulled: Vec::new(),
        positions: 0,
        catalogs: Vec::new(),
        suspended: case["suspended"].as_bool().unwrap(),
    };
    for (index, collection) in case["collections"].as_array().unwrap().iter().enumerate() {
        let name = format!("c{index}");
        let outcome = match collection["catalog"].as_str().unwrap() {
            "accepted" => CatalogOutcome::Accepted,
            "idempotent" => CatalogOutcome::Idempotent,
            "refused" => CatalogOutcome::Refused,
            "fetch_failed" => CatalogOutcome::Unavailable,
            "suspended" => CatalogOutcome::Suspended,
            other => panic!("unknown catalog outcome {other}"),
        };
        let mut catalog = CatalogReport::new(&name, outcome);
        catalog.codes = collection
            .get("codes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|code| code.as_str().unwrap())
            .map(|code| *CATALOG_CODES.iter().find(|known| **known == code).unwrap())
            .collect();
        for item in 0..collection["items_admitted"].as_u64().unwrap_or(0) {
            catalog.items.push(clave::collection::pull::ItemReport {
                url: format!("https://example.com/{item}"),
                item: format!("sha256:{item}"),
                outcome: ItemOutcome::Admitted,
                codes: Vec::new(),
                payload: None,
                payload_code: None,
            });
        }
        report.collections_pulled.push(name);
        report.catalogs.push(catalog);
    }
    (report, case["labels_admitted"].as_u64().unwrap() as usize)
}

#[test]
fn a_pull_that_discovers_accepts_and_admits_nothing_resolves_to_wist2_e02() {
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
                .all(|collection| collection.get("chain").is_none())
        })
        .collect();
    for case in &cases {
        let label = case["label"].as_str().unwrap();
        let (report, labels_admitted) = resolution_report(case);
        let resolution = report.resolution(labels_admitted);
        assert_eq!(resolution.code, case["resolution"].as_str(), "{label}");
        assert_eq!(resolution.noise, case["noise"], "{label}");
        assert_eq!(
            serde_json::json!(report.codes_recorded()),
            case["codes_recorded"],
            "{label}"
        );
    }
    assert_eq!(cases.len(), 13);
}

fn state_pull_case<'a>(vector: &'a Value, name: &str) -> &'a Value {
    vector["state_pull_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no state_pull_case {name}"))
}

#[test]
fn a_sealed_pending_head_due_at_the_pull_height_stays_pending_beside_a_fetched_replacement() {
    let vector = read_vector("vectors/wist2/declaration-pull.json");
    let case = state_pull_case(
        &vector,
        "replacement of the pending head signed by a recovery key is a pending replacement, pulled under the current Declaration alone",
    );
    let history = serde_json::json!({"declaration_activation_epochs": 1});
    let mut state = State::default();
    let labels = replay_epochs(&mut state, case, &history);
    let domain = "example.com";
    let pending = state.declarations.domains()[domain].pending().unwrap();
    assert_eq!(pending.activation_height(), state.first_epoch_after());
    let map = parameters(&[&history, &case["pull"]["parameters"]]);
    let mut site = ServedSite::new(Meter::unbounded());
    serve_declaration(
        &mut state,
        &mut site,
        domain,
        "new_octets",
        Some(&case["declarations"]["Q"]),
    );
    let at = case["pull"]["sealed_at"].as_str().unwrap();
    let report = run(&mut state, &mut site, domain, at, &map);
    let view = declaration_view(&report.declaration, &labels);
    assert_eq!(
        view,
        serde_json::json!({
            "acceptance": "pending_replacement",
            "proceeds": true,
            "sources": ["G"],
            "disposition": null,
        })
    );
    assert_eq!(
        report.collections_pulled,
        case["expected"]["collections_pulled"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    let sealed = &state.declarations.domains()[domain];
    assert_eq!(
        sealed.current().hash(),
        wist_core::declaration::inner_hash(&case["declarations"]["G"]).unwrap()
    );
    assert!(sealed.pending().is_some());
}

#[test]
fn a_pull_whose_instant_precedes_the_last_sealed_at_proceeds_under_the_sealed_state() {
    let vector = read_vector("vectors/wist2/declaration-pull.json");
    let case = state_pull_case(
        &vector,
        "replacement of the pending head signed by a recovery key is a pending replacement, pulled under the current Declaration alone",
    );
    let history = serde_json::json!({});
    let mut state = State::default();
    let labels = replay_epochs(&mut state, case, &history);
    let domain = "example.com";
    let map = parameters(&[&history, &case["pull"]["parameters"]]);
    let mut site = ServedSite::new(Meter::unbounded());
    serve_declaration(
        &mut state,
        &mut site,
        domain,
        "new_octets",
        Some(&case["declarations"]["P"]),
    );
    let report = run(&mut state, &mut site, domain, "2026-10-01T00:30:00Z", &map);
    assert_eq!(
        declaration_view(&report.declaration, &labels),
        serde_json::json!({
            "acceptance": "idempotent",
            "proceeds": true,
            "sources": ["G"],
            "disposition": null,
        })
    );
}
