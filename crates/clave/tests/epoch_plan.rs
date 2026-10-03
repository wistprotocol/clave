use clave::collection::plan::{
    self, Deferred, EpochInput, HeldBack, Inclusion, Left, Planned, Publication, Sealed, Unsealed,
};
use clave::collection::pull::{
    accept_labels, CatalogOutcome, CatalogReport, ItemOutcome, LabelOutcome, LabelReport,
    PayloadSource,
};
use clave::collection::state::Place;
use clave::collection::{
    pull, MemoryHeld, Meter, Object, Parameters, PullInput, PullReport, ServedSite, Settled, State,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use wist_core::crypto::PublicKey;
use wist_core::sealing::{Epoch, Outcome, Replay};
use wist_core::suffix_list::SuffixList;

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

fn parameters(map: &Value) -> Parameters {
    let mut out = Parameters::default();
    for (name, value) in map.as_object().unwrap() {
        out.set(name, value.as_i64().unwrap());
    }
    out
}

fn place(place: Place) -> Value {
    json!(Vec::<u64>::from(place))
}

fn label_id(envelope: &Value) -> String {
    let inner = envelope
        .get("label")
        .or_else(|| envelope.get("dispute"))
        .unwrap();
    wist_core::label::label_id(inner).unwrap()
}

struct History<'a> {
    name: &'a str,
    vector: &'a Value,
    keys: &'a Value,
    names: BTreeMap<String, String>,
    inclusion: Inclusion,
    suffix_list: Option<SuffixList>,
    log_key: PublicKey,
    log_kid: String,
}

impl<'a> History<'a> {
    fn read(keys: &'a Value, vector: &'a Value) -> Self {
        let names = vector["declarations"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, envelope)| {
                (
                    wist_core::declaration::inner_hash(envelope).unwrap(),
                    name.clone(),
                )
            })
            .collect();
        let inclusion = match vector.get("inclusion_schedule") {
            Some(rows) => Inclusion::schedule(
                rows.as_array()
                    .unwrap()
                    .iter()
                    .map(|row| (row[0].as_u64().unwrap(), row[1].as_u64().unwrap()))
                    .collect(),
            )
            .unwrap(),
            None => {
                let first = vector["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|event| event["event"] == "epoch")
                    .unwrap();
                Inclusion::constant(
                    first["parameters"]["max_inclusion_epochs"]
                        .as_u64()
                        .unwrap(),
                )
            }
        };
        let suffix_list = vector.get("suffix_list").map(|rules| {
            let text: Vec<&str> = rules
                .as_array()
                .unwrap()
                .iter()
                .map(|rule| rule.as_str().unwrap())
                .collect();
            SuffixList::parse(format!("{}\n", text.join("\n")).as_bytes()).unwrap()
        });
        History {
            name: vector["name"].as_str().unwrap(),
            vector,
            keys,
            names,
            inclusion,
            suffix_list,
            log_key: PublicKey::from_b64u(keys["log"]["x"].as_str().unwrap()).unwrap(),
            log_kid: keys["log"]["kid"].as_str().unwrap().to_owned(),
        }
    }

    fn declaration(&self, name: &str) -> &Value {
        &self.vector["declarations"][name]
    }

    fn label_name(&self, hash: &str) -> String {
        self.names
            .get(hash)
            .cloned()
            .unwrap_or_else(|| panic!("{}: an unnamed Declaration {hash}", self.name))
    }

    fn key_name(&self, x: &str) -> String {
        self.keys
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, key)| key["x"] == x)
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| x.to_owned())
    }

    fn key_id(&self, x: &str) -> String {
        self.keys
            .as_object()
            .unwrap()
            .values()
            .find(|key| key["x"] == x)
            .map(|key| key["kid"].as_str().unwrap().to_owned())
            .unwrap_or_else(|| x.to_owned())
    }

    fn ceiling(&self, eligibility: u64) -> u64 {
        self.inclusion.ceiling(eligibility)
    }
}

fn publication(publication: &Publication) -> Value {
    match publication {
        Publication::Catalog {
            publisher,
            collection,
            catalog,
        } => json!({
            "type": "publisher_catalog",
            "publisher": publisher,
            "collection": collection,
            "catalog": catalog,
        }),
        Publication::Item {
            publisher,
            collection,
            url,
            item,
        } => json!({
            "type": "publisher_item",
            "publisher": publisher,
            "collection": collection,
            "url": url,
            "item": item,
        }),
        Publication::Label {
            kind,
            publisher,
            id,
        } => json!({"type": kind.as_str(), "publisher": publisher, "label": id}),
    }
}

fn with(mut value: Value, members: Value) -> Value {
    for (name, member) in members.as_object().unwrap() {
        value[name] = member.clone();
    }
    value
}

fn sealed_view(sealed: &Sealed) -> Value {
    let mut out = publication(&sealed.publication);
    if let Some(catalog) = &sealed.catalog {
        out["catalog"] = json!(catalog);
    }
    with(
        out,
        json!({"eligibility": sealed.eligibility, "ceiling": sealed.ceiling}),
    )
}

fn deferred_view(deferred: &Deferred) -> Value {
    with(
        publication(&deferred.publication),
        json!({
            "place": place(deferred.place),
            "reasons": deferred.reasons.iter().map(|reason| reason.as_str()).collect::<Vec<_>>(),
        }),
    )
}

fn held_view(held: &HeldBack) -> Value {
    with(
        publication(&held.publication),
        json!({"place": place(held.place), "reasons": [held.reason.as_str()]}),
    )
}

fn left_view(left: &Left) -> Value {
    let mut out = with(
        publication(&left.publication),
        json!({
            "condition": left.condition.as_str(),
            "codes": left.codes,
            "reported": left.reported,
        }),
    );
    if let Some(code) = left.payload_code {
        out["payload_code"] = json!(code);
    }
    out
}

fn assert_left(history: &History<'_>, at: usize, got: &[Left], wanted: &Value) {
    let wanted = wanted.as_array().unwrap();
    assert_eq!(
        got.len(),
        wanted.len(),
        "{} event {at}: left {got:?}",
        history.name
    );
    for (left, wanted) in got.iter().zip(wanted) {
        let mut view = left_view(left);
        let codes: Vec<&str> = wanted["codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap())
            .collect();
        assert!(
            !left.codes.is_empty() && left.codes.iter().all(|code| codes.contains(code)),
            "{} event {at}: left codes {:?} outside {codes:?}",
            history.name,
            left.codes
        );
        view["codes"] = wanted["codes"].clone();
        assert_eq!(&view, wanted, "{} event {at}: left", history.name);
    }
}

fn state_view(history: &History<'_>, state: &State, shown: &BTreeSet<(String, String)>) -> Value {
    let collections: Vec<Value> = state
        .collections
        .iter()
        .filter(|(key, _)| shown.contains(*key))
        .map(|((publisher, name), collection)| {
            json!({
                "publisher": publisher,
                "collection": name,
                "latest": collection.latest.as_ref().map(|latest| &latest.catalog_id),
                "last_accepted": collection.last_accepted().map(|(_, id)| id),
                "waiting": collection.waiting().map(|waiting| json!({
                    "catalog": waiting.catalog_id,
                    "place": place(waiting.place),
                    "eligibility": waiting.eligibility,
                    "ceiling": history.ceiling(waiting.eligibility),
                })),
            })
        })
        .collect();
    let mut urls: Vec<_> = state.urls.iter().collect();
    urls.sort_by_key(|((publisher, url), waiting)| {
        (
            waiting.place.event,
            publisher.clone(),
            waiting.place.position,
            waiting.place.index,
            url.clone(),
        )
    });
    let urls: Vec<Value> = urls
        .into_iter()
        .map(|((publisher, url), waiting)| {
            let held = state.window_holds(publisher);
            json!({
                "publisher": publisher,
                "url": url,
                "collection": waiting.collection,
                "item": waiting.item_id,
                "place": place(waiting.place),
                "eligibility": (!held).then_some(waiting.eligibility),
                "ceiling": (!held).then(|| history.ceiling(waiting.eligibility)),
            })
        })
        .collect();
    let mut queue: Vec<(String, Place, String, Value)> = Vec::new();
    for (publisher, window) in &state.queues {
        for ((name, key), queued) in &window.queued {
            queue.push((
                publisher.clone(),
                queued.place,
                history.key_id(key),
                json!({
                    "publisher": publisher,
                    "collection": name,
                    "key": history.key_name(key),
                    "catalog": queued.catalog_id,
                    "place": place(queued.place),
                    "first_place": place(window.first_place(name).unwrap()),
                }),
            ));
        }
    }
    queue.sort_by(|a, b| (&a.0, a.1, &a.2).cmp(&(&b.0, b.1, &b.2)));
    let queue: Vec<Value> = queue.into_iter().map(|(_, _, _, row)| row).collect();
    let reductions: Vec<Value> = state
        .reductions_pending()
        .map(|(publisher, found)| {
            json!({"publisher": publisher, "declaration": history.label_name(&found.hash)})
        })
        .collect();
    let records: Vec<Value> = state
        .records
        .iter()
        .map(|((publisher, url), record)| {
            json!({
                "publisher": publisher,
                "url": url,
                "collection": record.collection,
                "item": record.item_id,
                "catalog": record.catalog_id,
            })
        })
        .collect();
    let mut out = json!({
        "collections": collections,
        "urls": urls,
        "queue": queue,
        "reductions_pending": reductions,
        "records": records,
    });
    if !state.labels.is_empty() {
        let mut labels: Vec<_> = state.labels.iter().collect();
        labels.sort_by_key(|(id, label)| {
            (
                label.place.event,
                label.publisher.clone(),
                label.place.position,
                label.place.index,
                (*id).clone(),
            )
        });
        out["labels"] = labels
            .into_iter()
            .map(|(id, label)| {
                json!({
                    "type": label.kind.as_str(),
                    "publisher": label.publisher,
                    "label": id,
                    "place": place(label.place),
                    "eligibility": label.eligibility,
                    "ceiling": history.ceiling(label.eligibility),
                })
            })
            .collect();
    }
    out
}

fn settlement_view(history: &History<'_>, settled: &[Settled]) -> Value {
    let mut rows: Vec<&Settled> = settled.iter().collect();
    rows.sort_by(|a, b| {
        (&a.publisher, a.place, history.key_id(&a.key)).cmp(&(
            &b.publisher,
            b.place,
            history.key_id(&b.key),
        ))
    });
    rows.into_iter()
        .map(|row| {
            let mut out = json!({
                "publisher": row.publisher,
                "collection": row.collection,
                "key": history.key_name(&row.key),
                "catalog": row.catalog,
                "outcome": row.outcome.as_str(),
            });
            if let Some(code) = row.outcome.condition_code() {
                out["condition_code"] = json!(code);
            }
            out
        })
        .collect()
}

fn catalog_outcome(outcome: CatalogOutcome) -> &'static str {
    match outcome {
        CatalogOutcome::Unavailable => "unavailable",
        CatalogOutcome::Suspended => "suspended",
        CatalogOutcome::Accepted => "accepted",
        CatalogOutcome::Idempotent => "idempotent",
        CatalogOutcome::Refused => "refused",
    }
}

fn payload_source(source: PayloadSource) -> &'static str {
    match source {
        PayloadSource::Withdrawn => "withdrawn",
        PayloadSource::Record => "record",
        PayloadSource::Held => "held",
        PayloadSource::Fetched => "fetched",
        PayloadSource::Unavailable => "unavailable",
        PayloadSource::Failed => "failed",
    }
}

fn assert_codes(at: &str, got: &[&str], wanted: &Value) {
    let wanted: Vec<&str> = wanted
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap())
        .collect();
    assert!(
        !got.is_empty() && got.iter().all(|code| wanted.contains(code)),
        "{at}: codes {got:?} outside {wanted:?}"
    );
}

fn assert_catalog(history: &History<'_>, at: &str, got: &CatalogReport, wanted: &Value) {
    let at = format!("{at} {}", got.collection);
    let view = json!({
        "collection": got.collection,
        "outcome": catalog_outcome(got.outcome),
        "catalog": got.catalog,
        "sources": got.sources.iter().map(|hash| history.label_name(hash)).collect::<Vec<_>>(),
        "tree_files_fetched": got.tree_files_fetched,
        "base": got.base,
        "key": got.key.as_deref().map(|x| history.key_name(x)),
        "queued": got.queued,
        "dropped": got.dropped,
        "suspended": got.suspended,
    });
    if let Some(codes) = wanted.get("codes") {
        assert_codes(&at, &got.codes, codes);
    }
    for (member, value) in wanted.as_object().unwrap() {
        match member.as_str() {
            "codes" | "reason" => {}
            "tree_files_fetched" => {
                for hex in value.as_array().unwrap() {
                    assert!(
                        got.tree_files_fetched.iter().any(|got| got == hex),
                        "{at}: tree file {hex} not fetched"
                    );
                }
            }
            "items" => {
                let items = value.as_array().unwrap();
                assert_eq!(got.items.len(), items.len(), "{at}: items {:?}", got.items);
                for (item, wanted) in got.items.iter().zip(items) {
                    let mut out = json!({
                        "url": item.url,
                        "item": item.item,
                        "outcome": match item.outcome {
                            ItemOutcome::Admitted => "admitted",
                            ItemOutcome::NotAdmitted => "not_admitted",
                            ItemOutcome::Refused => "refused",
                        },
                    });
                    if let Some(payload) = item.payload {
                        out["payload"] = json!(payload_source(payload));
                    }
                    if let Some(code) = item.payload_code {
                        out["payload_code"] = json!(code);
                    }
                    if let Some(codes) = wanted.get("codes") {
                        assert_codes(&at, &item.codes, codes);
                        out["codes"] = codes.clone();
                    }
                    if wanted.get("payload").is_some_and(Value::is_null) {
                        out["payload"] = Value::Null;
                    }
                    assert_eq!(&out, wanted, "{at}: item");
                }
            }
            _ => assert_eq!(&view[member.as_str()], value, "{at}: {member}"),
        }
    }
}

fn assert_pull(
    history: &History<'_>,
    at: usize,
    report: &PullReport,
    labels: usize,
    wanted: &Value,
) {
    let at = format!("{} event {at}", history.name);
    assert_eq!(
        settlement_view(history, &report.settlement),
        wanted["settlement"],
        "{at}: settlement"
    );
    let declaration = &report.declaration;
    assert_eq!(
        json!({
            "outcome": declaration.outcome,
            "discovered": declaration.discovered,
            "reduces_authority": declaration.reduces_authority,
            "sources": declaration
                .sources
                .iter()
                .map(|hash| history.label_name(hash))
                .collect::<Vec<_>>(),
            "window": declaration.window,
        }),
        wanted["declaration"],
        "{at}: declaration"
    );
    assert_eq!(
        json!(report.collections_pulled),
        wanted["collections_pulled"],
        "{at}: collections pulled"
    );
    let catalogs = wanted["catalogs"].as_array().unwrap();
    assert_eq!(
        report.catalogs.len(),
        catalogs.len(),
        "{at}: catalogs {:?}",
        report.catalogs
    );
    for (got, wanted) in report.catalogs.iter().zip(catalogs) {
        assert_catalog(history, &at, got, wanted);
    }
    assert_eq!(
        report.suspended,
        wanted.get("suspended").is_some_and(|value| value == true),
        "{at}: suspended"
    );
    let resolution = report.resolution(labels);
    assert_eq!(
        resolution.noise && report.declaration.proceeds,
        wanted.get("noise").is_some_and(|value| value == true),
        "{at}: noise"
    );
}

fn labels_view(reports: &[LabelReport]) -> Value {
    reports
        .iter()
        .map(|report| {
            let mut out = json!({"type": report.kind.as_str(), "label": report.id});
            match report.outcome {
                LabelOutcome::Accepted(at) => {
                    out["outcome"] = json!("accepted");
                    out["place"] = place(at);
                }
                LabelOutcome::Seen => out["outcome"] = json!("seen"),
            }
            out
        })
        .collect()
}

fn serve_pull(history: &History<'_>, event: &Value) -> ServedSite {
    let meter = match event.get("limit_objects") {
        Some(limit) => Meter {
            budget_remaining: u64::MAX,
            bytes_remaining: None,
            objects_remaining: Some(limit.as_u64().unwrap()),
        },
        None => Meter::unbounded(),
    };
    let mut site = ServedSite::new(meter);
    if let Some(name) = event["declaration"].as_str() {
        site.serve(Object::Declaration, octets(history.declaration(name)));
    }
    for (collection, served) in event["collections"].as_object().unwrap() {
        if let Some(catalog) = served["catalog"].as_str() {
            site.serve(
                Object::Catalog { collection },
                octets(&history.vector["catalogs"][catalog]),
            );
        }
        for hex in served["tree_files"].as_array().into_iter().flatten() {
            let hex = hex.as_str().unwrap();
            site.serve(
                Object::TreeFile { collection, hex },
                history.vector["tree_files"][hex]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            );
        }
        for (hex, payload) in served["payloads"].as_object().into_iter().flatten() {
            site.serve(Object::Payload { collection, hex }, octets(payload));
        }
    }
    site
}

struct Run<'a> {
    history: History<'a>,
    state: State,
    shown: BTreeSet<(String, String)>,
    held: MemoryHeld,
    full: Replay,
    compared: usize,
    restricted: usize,
}

fn named_labels(history: &History<'_>, names: &Value) -> Vec<Value> {
    names
        .as_array()
        .into_iter()
        .flatten()
        .map(|name| history.vector["labels"][name.as_str().unwrap()].clone())
        .collect()
}

fn epoch_input_parts(
    history: &History<'_>,
    event: &Value,
) -> (Parameters, Vec<Value>, Vec<Value>, BTreeSet<Unsealed>) {
    let map = parameters(&event["parameters"]);
    let declarations = event["declarations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| history.declaration(name.as_str().unwrap()).clone())
        .collect();
    let updates = event["updates"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|name| history.vector["registry_updates"][name.as_str().unwrap()].clone())
        .collect();
    let unsealed = event["unsealed"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| match row["type"].as_str().unwrap() {
            "publisher_item" => Unsealed::Item {
                publisher: row["publisher"].as_str().unwrap().to_owned(),
                url: row["url"].as_str().unwrap().to_owned(),
            },
            _ => Unsealed::Label {
                id: label_id(&history.vector["labels"][row["label"].as_str().unwrap()]),
            },
        })
        .collect();
    (map, declarations, updates, unsealed)
}

fn planned_view(history: &History<'_>, planned: &Planned) -> Value {
    let out = json!({
        "entries": planned.entries,
        "sealed": planned.sealed.iter().map(sealed_view).collect::<Vec<_>>(),
        "deferred": planned.deferred.iter().map(deferred_view).collect::<Vec<_>>(),
        "held": planned.held.iter().map(held_view).collect::<Vec<_>>(),
        "records_removed": planned.records_removed.iter().map(|removed| json!({
            "publisher": removed.publisher,
            "url": removed.url,
            "cause": removed.cause.as_str(),
        })).collect::<Vec<_>>(),
        "unsealed": planned.unsealed.iter().map(|unsealed| with(
            publication(&unsealed.publication),
            json!({"place": place(unsealed.place)}),
        )).collect::<Vec<_>>(),
        "rejections": planned.rejections.iter().map(|rejection| json!({
            "id": rejection.id,
            "code": rejection.code,
        })).collect::<Vec<_>>(),
        "declarations_failed": planned.declarations_failed.iter().map(|failed| json!({
            "declaration": history.label_name(&failed.declaration),
            "code": failed.code,
        })).collect::<Vec<_>>(),
        "declarations_left": planned.declarations_left.iter().map(|left| json!({
            "declaration": history.label_name(&left.declaration),
            "names": history.label_name(&left.names),
            "code": left.code,
        })).collect::<Vec<_>>(),
        "updates_refused": planned.updates_refused.iter().map(|refused| json!({
            "delta_id": refused.item_id,
            "subject": refused.subject,
            "code": refused.code,
        })).collect::<Vec<_>>(),
    });
    out
}

fn expected_epoch(expected: &Value) -> Value {
    let list = |member: &str| expected.get(member).cloned().unwrap_or(json!([]));
    json!({
        "settlement": list("settlement"),
        "entries": expected["entries"],
        "sealed": expected["sealed"],
        "deferred": expected["deferred"],
        "held": list("held"),
        "records_removed": expected["records_removed"],
        "unsealed": list("unsealed"),
        "rejections": list("rejections"),
        "declarations_failed": list("declarations_failed"),
        "declarations_left": list("declarations_left"),
        "updates_refused": list("updates_refused"),
    })
}

impl<'a> Run<'a> {
    fn new(keys: &'a Value, vector: &'a Value) -> Self {
        Run {
            history: History::read(keys, vector),
            state: State::default(),
            shown: BTreeSet::new(),
            held: MemoryHeld::default(),
            full: Replay::new(),
            compared: 0,
            restricted: 0,
        }
    }

    fn show(&mut self) {
        for (key, collection) in &self.state.collections {
            if collection.latest.is_some() || collection.accepted.is_some() {
                self.shown.insert(key.clone());
            }
        }
    }

    fn show_settled(&mut self, settled: &[Settled]) {
        for row in settled {
            self.shown
                .insert((row.publisher.clone(), row.collection.clone()));
        }
    }

    fn epoch(&mut self, at: usize, event: &Value, expected: &Value) {
        let history = &self.history;
        let (map, declarations, updates, unsealed) = epoch_input_parts(history, event);
        let log_kid = history.log_kid.clone();
        let log_key = history.log_key.clone();
        let key = move |kid: &str| (kid == log_kid).then(|| log_key.clone());
        let input = EpochInput {
            height: event["height"].as_u64().unwrap(),
            sealed_at: event["sealed_at"].as_str().unwrap(),
            parameters: &map,
            inclusion: &history.inclusion,
            suffix_list: history.suffix_list.as_ref(),
            declarations: &declarations,
            updates: &updates,
            unsealed: &unsealed,
            log_key: &key,
        };
        let planned = plan::plan(&self.state, &self.held, &input)
            .unwrap_or_else(|error| panic!("{} event {at}: {error}", history.name));
        plan::verify(&self.state, &input, &planned.entries)
            .unwrap_or_else(|error| panic!("{} event {at}: {error}", history.name));
        let judged = plan::judge(&self.state, &input, &planned.entries).unwrap();
        let domains = self.state.declarations.domains().len();
        if !judged.publishers.is_empty() && judged.publishers.len() < domains {
            self.restricted += 1;
        }
        let sealing = map.sealing().unwrap();
        let full = self
            .full
            .epoch(&Epoch {
                height: input.height,
                root: "full",
                sealed_at: input.sealed_at,
                parameters: &sealing,
                suffix_list: input.suffix_list,
                log_key: &key,
                entries: &planned.entries,
            })
            .unwrap();
        assert!(
            matches!(full, Outcome::Accepted { .. }),
            "{} event {at}",
            history.name
        );
        assert_eq!(
            judged.outcome, full,
            "{} event {at}: restricted resume",
            history.name
        );
        self.compared += 1;
        let mut view = planned_view(history, &planned);
        view["settlement"] = settlement_view(history, &planned.settlement);
        let wanted = expected_epoch(expected);
        assert_left(history, at, &planned.left, &expected["left"]);
        view["entries"] = json!(planned.entries);
        assert_eq!(view, wanted, "{} event {at}", history.name);
        self.show_settled(&planned.settlement);
        for item_id in &planned.payloads_destroyed {
            self.held.payloads.remove(item_id);
        }
        self.state = planned.state;
    }

    fn pull(&mut self, at: usize, event: &Value, expected: &Value) {
        let history = &self.history;
        let mut site = serve_pull(history, event);
        let map = parameters(&event["parameters"]);
        let publisher = event["publisher"].as_str().unwrap();
        let report = pull(
            &mut self.state,
            &mut site,
            &mut self.held,
            &PullInput {
                publisher,
                at: event["at"].as_str().unwrap(),
                parameters: &map,
            },
        )
        .unwrap_or_else(|error| panic!("{} event {at}: {error}", history.name));
        let envelopes = named_labels(history, &event["labels"]);
        let labels = accept_labels(&mut self.state, &report, publisher, &envelopes).unwrap();
        if let Some(wanted) = expected.get("labels") {
            assert_eq!(
                &labels_view(&labels),
                wanted,
                "{} event {at}: labels",
                history.name
            );
        }
        let admitted = labels
            .iter()
            .filter(|label| matches!(label.outcome, LabelOutcome::Accepted(_)))
            .count();
        assert_pull(history, at, &report, admitted, expected);
        self.show_settled(&report.settlement);
    }
}

fn replay_history(keys: &Value, vector: &Value) -> (usize, usize) {
    let mut run = Run::new(keys, vector);
    let events = vector["events"].as_array().unwrap();
    let expected = vector["expected"].as_array().unwrap();
    assert_eq!(events.len(), expected.len());
    for (at, (event, expected)) in events.iter().zip(expected).enumerate() {
        match event["event"].as_str().unwrap() {
            "epoch" => run.epoch(at, event, expected),
            "pull" => run.pull(at, event, expected),
            other => panic!("unknown event {other}"),
        }
        run.show();
        assert_eq!(
            state_view(&run.history, &run.state, &run.shown),
            expected["state"],
            "{} event {at}: state",
            run.history.name
        );
    }
    (run.compared, run.restricted)
}

fn replay_file(relative: &str) -> usize {
    let vector = read_vector(relative);
    for history in vector["histories"].as_array().unwrap() {
        replay_history(&vector["keys"], history);
    }
    vector["histories"].as_array().unwrap().len()
}

#[test]
fn every_catalog_waiting_history_replays_through_pull_and_plan() {
    assert_eq!(replay_file("vectors/wist3/catalog-waiting.json"), 42);
}

#[test]
fn every_collection_pull_history_replays_through_pull_and_plan() {
    assert_eq!(replay_file("vectors/wist2/collection-pull.json"), 20);
}

#[test]
fn every_catalog_recovery_history_replays_through_pull_and_plan() {
    assert_eq!(replay_file("vectors/wist1/catalog-recovery.json"), 30);
}

fn history_named<'a>(vector: &'a Value, name: &str) -> &'a Value {
    vector["histories"]
        .as_array()
        .unwrap()
        .iter()
        .find(|history| history["name"] == name)
        .unwrap_or_else(|| panic!("no history {name}"))
}

#[test]
fn a_replay_resumed_from_the_touched_publishers_judges_each_planned_epoch_as_a_full_replay() {
    let mut compared = 0;
    let mut restricted = 0;
    let mut epochs = 0;
    for (relative, names) in [
        (
            "vectors/wist3/catalog-waiting.json",
            &[
                "places taken at one Epoch by two Publishers of one Registrable Domain",
                "a base: a Catalog 15552001 seconds after the floor",
                "a base that fails C1 at its turn",
                "a pending head that narrows a Collection",
                "an Item sealed again after narrowing and a later widening",
                "capacity order: Catalogs, removed Items, then page Items, by place",
            ][..],
        ),
        (
            "vectors/wist2/collection-pull.json",
            &[
                "a withdrawn Item that a later list names",
                "a withdrawal of an Item not yet sealed is held back until its Item is sealed",
            ][..],
        ),
    ] {
        let vector = read_vector(relative);
        for name in names {
            let history = history_named(&vector, name);
            epochs += history["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|event| event["event"] == "epoch")
                .count();
            let (judged, narrower) = replay_history(&vector["keys"], history);
            compared += judged;
            restricted += narrower;
        }
    }
    assert_eq!(compared, epochs);
    assert!(restricted > 0);
}

#[test]
fn a_planned_epoch_with_an_entry_the_judgment_ignores_or_out_of_order_fails_verification() {
    let vector = read_vector("vectors/wist3/catalog-waiting.json");
    let history = history_named(
        &vector,
        "a Catalog accepted at a pull and sealed with its Items in the next Epoch",
    );
    let mut run = Run::new(&vector["keys"], history);
    let events = history["events"].as_array().unwrap();
    let expected = history["expected"].as_array().unwrap();
    run.epoch(0, &events[0], &expected[0]);
    run.pull(1, &events[1], &expected[1]);
    let event = &events[2];
    let (map, declarations, updates, unsealed) = epoch_input_parts(&run.history, event);
    let key = |_: &str| None;
    let input = EpochInput {
        height: event["height"].as_u64().unwrap(),
        sealed_at: event["sealed_at"].as_str().unwrap(),
        parameters: &map,
        inclusion: &run.history.inclusion,
        suffix_list: None,
        declarations: &declarations,
        updates: &updates,
        unsealed: &unsealed,
        log_key: &key,
    };
    let planned = plan::plan(&run.state, &run.held, &input).unwrap();
    assert_eq!(planned.entries.len(), 3);
    plan::verify(&run.state, &input, &planned.entries).unwrap();
    let mut wrong_proof = planned.entries.clone();
    let item = wrong_proof
        .iter_mut()
        .find(|entry| entry["type"] == "publisher_item")
        .unwrap();
    let index = item["body"]["proof"]["index"].as_u64().unwrap();
    item["body"]["proof"]["index"] = json!(1 - index);
    assert!(plan::verify(&run.state, &input, &wrong_proof).is_err());
    let mut reordered = planned.entries.clone();
    reordered.reverse();
    assert!(plan::verify(&run.state, &input, &reordered).is_err());
}

#[test]
fn a_label_of_a_labeler_whose_recovery_window_is_open_waits_with_its_eligibility_moved() {
    let vector = read_vector("vectors/wist3/catalog-waiting.json");
    let history = history_named(
        &vector,
        "Labels and a dispute that fit the capacity are sealed together",
    );
    let envelope = &history["declarations"]["G"];
    let label = &history["labels"]["L1"];
    let sealed_at_s = wist_core::timestamp::log_seconds("2026-10-01T00:00:00Z").unwrap();
    let event = &history["events"][3];
    let (map, _, _, unsealed) = epoch_input_parts(&History::read(&vector["keys"], history), event);
    let key = |_: &str| None;
    let inclusion = Inclusion::constant(4);
    for window in [false, true] {
        let mut state = State::default();
        let position = wist_core::declarations::Position {
            epoch_number: 0,
            entry_index: 0,
        };
        let open = window.then(|| {
            (
                envelope.clone(),
                position,
                sealed_at_s,
                i128::from(sealed_at_s) + 7 * 86_400,
            )
        });
        state
            .declarations
            .adopt(
                "example.com",
                envelope.clone(),
                position,
                sealed_at_s,
                0,
                open,
                None,
            )
            .unwrap();
        state.declarations.seed_head(0, "root", Some(sealed_at_s));
        state.height = Some(0);
        let report = clave::collection::PullReport {
            event: 0,
            settlement: Vec::new(),
            declaration: clave::collection::pull::DeclarationReport {
                outcome: "idempotent".into(),
                proceeds: true,
                first_contact: false,
                discovered: false,
                reduces_authority: false,
                sources: Vec::new(),
                window: false,
            },
            collections_pulled: Vec::new(),
            positions: 2,
            catalogs: Vec::new(),
            suspended: false,
        };
        accept_labels(
            &mut state,
            &report,
            "example.com",
            std::slice::from_ref(label),
        )
        .unwrap();
        state.events = 1;
        let input = EpochInput {
            height: 1,
            sealed_at: "2026-10-01T01:00:00Z",
            parameters: &map,
            inclusion: &inclusion,
            suffix_list: None,
            declarations: &[],
            updates: &[],
            unsealed: &unsealed,
            log_key: &key,
        };
        let planned = plan::plan(&state, &MemoryHeld::default(), &input).unwrap();
        assert!(planned.deferred.is_empty());
        let waiting: Vec<u64> = planned
            .state
            .labels
            .values()
            .map(|label| label.eligibility)
            .collect();
        if window {
            assert!(planned.entries.is_empty());
            assert_eq!(waiting, vec![2]);
        } else {
            assert_eq!(planned.entries.len(), 1);
            assert!(waiting.is_empty());
        }
    }
}

#[test]
fn a_pull_after_the_one_that_settled_the_queue_settles_nothing_again() {
    let vector = read_vector("vectors/wist1/catalog-recovery.json");
    let history = history_named(
        &vector,
        "settlement at a pull between the window's end and the Epoch of settlement",
    );
    let mut run = Run::new(&vector["keys"], history);
    let events = history["events"].as_array().unwrap();
    let expected = history["expected"].as_array().unwrap();
    for at in 0..8 {
        match events[at]["event"].as_str().unwrap() {
            "epoch" => run.epoch(at, &events[at], &expected[at]),
            _ => run.pull(at, &events[at], &expected[at]),
        }
    }
    assert!(run.state.queues.is_empty());
    let urls = run.state.urls.clone();
    let events_before = run.state.events;
    let again = &events[7];
    let mut site = serve_pull(&run.history, again);
    let map = parameters(&again["parameters"]);
    let report = pull(
        &mut run.state,
        &mut site,
        &mut run.held,
        &PullInput {
            publisher: again["publisher"].as_str().unwrap(),
            at: "2026-10-08T02:30:00Z",
            parameters: &map,
        },
    )
    .unwrap();
    assert!(report.settlement.is_empty());
    assert!(!report.declaration.window);
    assert_eq!(run.state.events, events_before + 1);
    assert_eq!(report.catalogs[0].outcome, CatalogOutcome::Idempotent);
    assert_eq!(run.state.urls, urls);
    run.epoch(8, &events[8], &expected[8]);
}
