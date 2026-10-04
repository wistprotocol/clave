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
                let mut wanted: Vec<&str> = value
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|hex| hex.as_str().unwrap())
                    .collect();
                wanted.sort_unstable();
                assert_eq!(got.tree_files_fetched, wanted, "{at}: tree files fetched");
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
    checked: bool,
    sealed_declarations: BTreeSet<String>,
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
            checked: true,
            sealed_declarations: BTreeSet::new(),
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
        let (_, declarations, _, _) = epoch_input_parts(&self.history, event);
        self.epoch_with(at, event, expected, declarations);
    }

    fn sealer_choice(&self, event: &Value) -> Vec<Value> {
        let (_, listed, _, _) = epoch_input_parts(&self.history, event);
        let mut chosen: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for (publisher, found) in &self.state.discovered {
            chosen
                .entry(publisher.clone())
                .or_default()
                .extend(found.iter().map(|found| found.envelope.clone()));
        }
        for envelope in listed {
            let hash = wist_core::declaration::inner_hash(&envelope).unwrap();
            let domain = envelope["publisher"]["domain"].as_str().unwrap().to_owned();
            let held = chosen.entry(domain).or_default();
            if !self.sealed_declarations.contains(&hash) && !held.contains(&envelope) {
                held.push(envelope);
            }
        }
        chosen.into_values().flatten().collect()
    }

    fn epoch_with(
        &mut self,
        at: usize,
        event: &Value,
        expected: &Value,
        declarations: Vec<Value>,
    ) -> Vec<Value> {
        let history = &self.history;
        let (map, _, updates, unsealed) = epoch_input_parts(history, event);
        let unsealed = if self.checked {
            unsealed
        } else {
            BTreeSet::new()
        };
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
        if self.checked {
            let mut view = planned_view(history, &planned);
            view["settlement"] = settlement_view(history, &planned.settlement);
            let wanted = expected_epoch(expected);
            assert_left(history, at, &planned.left, &expected["left"]);
            view["entries"] = json!(planned.entries);
            assert_eq!(view, wanted, "{} event {at}", history.name);
        }
        for entry in &planned.entries {
            if entry["type"] == "publisher_declaration" {
                self.sealed_declarations
                    .insert(wist_core::declaration::inner_hash(&entry["body"]).unwrap());
            }
        }
        self.show_settled(&planned.settlement);
        for item_id in &planned.payloads_destroyed {
            self.held.payloads.remove(item_id);
        }
        self.state = planned.state;
        planned.entries
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
        for row in &report.settlement {
            self.shown
                .insert((row.publisher.clone(), row.collection.clone()));
        }
        if !self.checked {
            return;
        }
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
    assert_eq!(replay_file("vectors/wist1/catalog-recovery.json"), 31);
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
    let events = history["events"].as_array().unwrap();
    let pulled = events
        .iter()
        .position(|event| {
            event["labels"]
                .as_array()
                .is_some_and(|labels| labels.contains(&json!("L1")))
        })
        .unwrap();
    let event = events[pulled..]
        .iter()
        .find(|event| event["event"] == "epoch")
        .unwrap();
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

type Served = std::sync::Arc<std::sync::Mutex<BTreeMap<String, Vec<u8>>>>;

fn serve_validated(files: Served) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!(
        "http://{}/.well-known/wist/",
        listener.local_addr().unwrap()
    );
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let app = axum::Router::new().fallback(
                    move |headers: axum::http::HeaderMap, uri: axum::http::Uri| {
                        let path = uri
                            .path()
                            .trim_start_matches("/.well-known/wist/")
                            .to_owned();
                        let served = files.lock().unwrap().get(&path).cloned();
                        async move {
                            use axum::http::{header, HeaderValue, StatusCode};
                            let Some(octets) = served else {
                                return (
                                    StatusCode::NOT_FOUND,
                                    axum::http::HeaderMap::new(),
                                    Vec::new(),
                                );
                            };
                            let validator = clave::collection::site::validator(&octets);
                            let mut answer = axum::http::HeaderMap::new();
                            answer.insert(header::ETAG, HeaderValue::from_str(&validator).unwrap());
                            if headers
                                .get(header::IF_NONE_MATCH)
                                .and_then(|v| v.to_str().ok())
                                == Some(validator.as_str())
                            {
                                return (StatusCode::NOT_MODIFIED, answer, Vec::new());
                            }
                            (StatusCode::OK, answer, octets)
                        }
                    },
                );
                axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                    .await
                    .unwrap();
            });
    });
    base
}

struct HttpSite<'a> {
    client: &'a clave::fetch::Client,
    base: &'a str,
    meter: Meter,
}

impl clave::collection::Site for HttpSite<'_> {
    fn fetch(
        &mut self,
        request: &clave::collection::Request<'_>,
    ) -> clave::error::Result<clave::collection::Answer> {
        use clave::collection::site::Metered;
        use clave::collection::Answer;
        let metered = request.object.metered();
        let no_object_left = self.meter.objects_remaining == Some(0);
        if metered && no_object_left {
            self.meter.read(request.bound, 0);
            return Ok(Answer::Suspended);
        }
        let url = format!("{}{}", self.base, request.object.path());
        let fetched = self
            .client
            .get_octets(&url, &[], 1 << 30, request.validator)
            .ok();
        if metered {
            let octets = match &fetched {
                Some(clave::fetch::Octets::Read { octets, .. }) => octets.len() as u64,
                _ => 0,
            };
            match self.meter.read(request.bound, octets).0 {
                Metered::Suspended => return Ok(Answer::Interrupted),
                Metered::Failed => return Ok(Answer::Oversized),
                Metered::Read => {}
            }
        }
        Ok(match fetched {
            None => Answer::Failed,
            Some(clave::fetch::Octets::NotModified) => Answer::NotModified,
            Some(clave::fetch::Octets::Read { octets, .. })
                if octets.len() as u64 > request.bound =>
            {
                Answer::Oversized
            }
            Some(clave::fetch::Octets::Read {
                octets, validator, ..
            }) => Answer::Octets { octets, validator },
        })
    }
}

fn publishers_of(state: &State) -> BTreeSet<String> {
    state
        .collections
        .keys()
        .map(|(publisher, _)| publisher.clone())
        .chain(state.discovered.keys().cloned())
        .chain(state.queues.keys().cloned())
        .chain(state.urls.keys().map(|(publisher, _)| publisher.clone()))
        .chain(state.records.keys().map(|(publisher, _)| publisher.clone()))
        .chain(state.labels.values().map(|label| label.publisher.clone()))
        .chain(state.floors.keys().cloned())
        .collect()
}

struct StoreRun {
    data: tempfile::TempDir,
    db: clave::db::Db,
    sealed: State,
    client: clave::fetch::Client,
    files: Served,
    base: String,
}

impl StoreRun {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example", data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let files: Served = Default::default();
        let base = serve_validated(files.clone());
        StoreRun {
            data,
            db,
            sealed: State::default(),
            client: clave::fetch::Client::with_builder(
                true,
                reqwest::blocking::Client::builder().no_proxy(),
            ),
            files,
            base,
        }
    }

    fn load(&self, publishers: &BTreeSet<String>) -> State {
        self.db
            .load_state(clave::db::Sealed::of(&self.sealed), publishers)
            .unwrap()
    }

    fn store(&self, before: &State, after: &State, publishers: &BTreeSet<String>) {
        self.db
            .store_state(before, after, publishers, "2026-08-09T00:00:00Z")
            .unwrap();
    }

    fn pull(&mut self, history: &History<'_>, event: &Value) -> (u64, u64) {
        let served = serve_pull(history, event);
        *self.files.lock().unwrap() = served.files.clone();
        let publisher = event["publisher"].as_str().unwrap();
        let scope = self.db.pull_scope(publisher).unwrap();
        let before = self.load(&scope);
        let mut state = before.clone();
        let mut held =
            clave::db::StoreHeld::new(&self.db, self.data.path(), "2026-08-09T00:00:00Z");
        let mut site = HttpSite {
            client: &self.client,
            base: &self.base,
            meter: served.meter,
        };
        let map = parameters(&event["parameters"]);
        let report = pull(
            &mut state,
            &mut site,
            &mut held,
            &PullInput {
                publisher,
                at: event["at"].as_str().unwrap(),
                parameters: &map,
            },
        )
        .unwrap();
        let envelopes = named_labels(history, &event["labels"]);
        accept_labels(&mut state, &report, publisher, &envelopes).unwrap();
        held.store().unwrap();
        self.store(&before, &state, &scope);
        (before.events, state.events)
    }

    fn epoch(&mut self, history: &History<'_>, event: &Value, memory: &State) -> (u64, u64) {
        let publishers = publishers_of(memory);
        let before = self.load(&publishers);
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
        let held = clave::db::StoreHeld::new(&self.db, self.data.path(), "2026-08-09T00:00:00Z");
        let planned = plan::plan(&before, &held, &input).unwrap();
        for item_id in &planned.payloads_destroyed {
            let _ = std::fs::remove_file(
                self.data
                    .path()
                    .join(format!("payloads/{}.json", &item_id["sha256:".len()..])),
            );
        }
        let after = planned.state;
        let scope: BTreeSet<String> = publishers.union(&publishers_of(&after)).cloned().collect();
        self.store(&before, &after, &scope);
        let events = (before.events, after.events);
        self.sealed = after;
        events
    }
}

/// The store's clock also orders the Labels a pull admits, so its events are the vector's in
/// order but not in number.
fn renumber(state: &mut State, events: &BTreeMap<u64, u64>) {
    let at = |place: &mut Place| place.event = events[&place.event];
    for collection in state.collections.values_mut() {
        if let Some(accepted) = collection.accepted.as_mut() {
            at(&mut accepted.place);
        }
    }
    for waiting in state.urls.values_mut() {
        at(&mut waiting.place);
    }
    for queue in state.queues.values_mut() {
        queue
            .queued
            .values_mut()
            .for_each(|queued| at(&mut queued.place));
        queue.first.values_mut().for_each(at);
    }
    for label in state.labels.values_mut() {
        at(&mut label.place);
    }
    for found in state.discovered.values_mut().flatten() {
        found.event = events[&found.event];
    }
}

fn replay_through_the_store(keys: &Value, vector: &Value) {
    let mut run = Run::new(keys, vector);
    let mut store = StoreRun::new();
    let mut numbers = BTreeMap::new();
    let events = vector["events"].as_array().unwrap();
    let expected = vector["expected"].as_array().unwrap();
    for (at, (event, expected)) in events.iter().zip(expected).enumerate() {
        let first = run.state.events;
        let (from, to) = match event["event"].as_str().unwrap() {
            "epoch" => {
                let taken = store.epoch(&run.history, event, &run.state);
                run.epoch(at, event, expected);
                taken
            }
            _ => {
                let taken = store.pull(&run.history, event);
                run.pull(at, event, expected);
                taken
            }
        };
        assert_eq!(
            to - from,
            run.state.events - first,
            "{} event {at}",
            run.history.name
        );
        numbers.extend((from..to).map(|event| (event, first + event - from)));
        run.show();
        let publishers = publishers_of(&run.state);
        let mut stored = store.load(&publishers);
        renumber(&mut stored, &numbers);
        assert_eq!(
            state_view(&run.history, &stored, &run.shown),
            state_view(&run.history, &run.state, &run.shown),
            "{} event {at}: the store",
            run.history.name
        );
        let name = run.history.name;
        assert_eq!(stored.lists, run.state.lists, "{name} event {at}: lists");
        assert_eq!(stored.urls, run.state.urls, "{name} event {at}: urls");
        assert_eq!(stored.queues, run.state.queues, "{name} event {at}: queues");
        assert_eq!(
            stored.discovered, run.state.discovered,
            "{name} event {at}: discovered"
        );
        assert_eq!(stored.floors, run.state.floors, "{name} event {at}: floors");
        assert_eq!(stored.labels, run.state.labels, "{name} event {at}: labels");
        assert_eq!(
            stored.records, run.state.records,
            "{name} event {at}: records"
        );
        assert_eq!(
            stored.removals, run.state.removals,
            "{name} event {at}: removals"
        );

        assert_eq!(
            stored.collections, run.state.collections,
            "{} event {at}: collections",
            run.history.name
        );
    }
}

fn replay_file_through_the_store(relative: &str) -> usize {
    let vector = read_vector(relative);
    for history in vector["histories"].as_array().unwrap() {
        replay_through_the_store(&vector["keys"], history);
    }
    vector["histories"].as_array().unwrap().len()
}

#[test]
fn every_catalog_waiting_history_pulled_over_http_into_the_store_reaches_the_replayed_state() {
    assert_eq!(
        replay_file_through_the_store("vectors/wist3/catalog-waiting.json"),
        42
    );
}

#[test]
fn every_collection_pull_history_pulled_over_http_into_the_store_reaches_the_replayed_state() {
    assert_eq!(
        replay_file_through_the_store("vectors/wist2/collection-pull.json"),
        20
    );
}

#[test]
fn every_catalog_recovery_history_pulled_over_http_into_the_store_reaches_the_replayed_state() {
    assert_eq!(
        replay_file_through_the_store("vectors/wist1/catalog-recovery.json"),
        31
    );
}

const OPERATOR_BOUNDS: [&str; 3] = [
    "domain_epoch_entries_max",
    "labeler_epoch_entries_max",
    "max_inclusion_epochs",
];

const HOUR: i64 = 3600;
const GRACE: i64 = 8 * 86_400;

fn epochs_of(vector: &Value) -> impl Iterator<Item = &Value> {
    vector["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["event"] == "epoch")
}

fn instant_s(at: &Value) -> i64 {
    wist_core::timestamp::log_seconds(at.as_str().unwrap()).unwrap()
}

fn log_amendments(vector: &Value) -> Vec<(String, i64, String)> {
    let mut amendments = Vec::new();
    let mut in_force: BTreeMap<String, i64> = BTreeMap::new();
    for epoch in epochs_of(vector) {
        for (name, value) in epoch["parameters"].as_object().unwrap() {
            if OPERATOR_BOUNDS.contains(&name.as_str()) {
                continue;
            }
            let value = value.as_i64().unwrap();
            let current = in_force
                .get(name)
                .copied()
                .or(wist_core::parameters::spec(name).unwrap().default);
            if current != Some(value) {
                in_force.insert(name.clone(), value);
                amendments.push((
                    name.clone(),
                    value,
                    epoch["sealed_at"].as_str().unwrap().to_owned(),
                ));
            }
        }
    }
    let mut epochs = epochs_of(vector);
    let first = epochs.next().unwrap()["sealed_at"].as_str().unwrap();
    if epochs_of(vector).any(|epoch| instant_s(&epoch["sealed_at"]) % HOUR != 0) {
        amendments.push(("epoch_cadence_seconds".into(), 1, first.to_owned()));
    }
    amendments
}

struct SealerRun {
    store: StoreRun,
    sk: wist_core::crypto::SigningKey,
    offset: u64,
}

impl SealerRun {
    fn new(history: &History<'_>) -> Self {
        let store = StoreRun::new();
        store.db.set_param("epoch_cadence_seconds", 1).unwrap();
        let sk = clave::keys::load(&store.data.path().join("keys/seed")).unwrap();
        let mut run = SealerRun {
            store,
            sk,
            offset: 0,
        };
        run.amend_the_log(history);
        run
    }

    fn amend_the_log(&mut self, history: &History<'_>) {
        let amendments = log_amendments(history.vector);
        if amendments.is_empty() && history.suffix_list.is_none() {
            return;
        }
        let (db, data) = (&self.store.db, self.store.data.path());
        let first = instant_s(&epochs_of(history.vector).next().unwrap()["sealed_at"]);
        let setup = first - GRACE;
        for (name, value, effective_at) in &amendments {
            clave::param_change::run(db, &self.sk, name, *value, Some(effective_at), setup)
                .unwrap_or_else(|error| panic!("{}: {name}: {error}", history.name));
        }
        if let Some(rules) = history.vector.get("suffix_list") {
            let text: Vec<&str> = rules
                .as_array()
                .unwrap()
                .iter()
                .map(|rule| rule.as_str().unwrap())
                .collect();
            let file = data.join("suffix-list.dat");
            std::fs::write(&file, format!("{}\n", text.join("\n"))).unwrap();
            clave::suffix_list::pin(db, data, &self.sk, &file, setup).unwrap();
        }
        let report = clave::seal::run(db, data, &self.sk, setup)
            .unwrap_or_else(|error| panic!("{}: amending the Log: {error}", history.name));
        assert!(report.dropped.is_empty(), "{:?}", report.dropped);
        assert_eq!(
            db.epoch_entries(0).unwrap().len(),
            amendments.len() + usize::from(history.suffix_list.is_some()),
            "{}",
            history.name
        );
        self.offset = 1;
    }

    fn load(&self, publishers: &BTreeSet<String>) -> State {
        let sealed = self.store.db.sealed_state(self.store.data.path()).unwrap();
        self.store.db.load_state(sealed, publishers).unwrap()
    }

    fn observed(&self, publishers: &BTreeSet<String>) -> State {
        let mut state = self.load(publishers);
        let offset = self.offset;
        let height = |height: &mut u64| *height -= offset;
        for collection in state.collections.values_mut() {
            if let Some(latest) = collection.latest.as_mut() {
                height(&mut latest.sealing_height);
            }
            if let Some(accepted) = collection.accepted.as_mut() {
                height(&mut accepted.eligibility);
            }
        }
        state
            .urls
            .values_mut()
            .for_each(|waiting| height(&mut waiting.eligibility));
        state
            .records
            .values_mut()
            .for_each(|record| height(&mut record.sealing_height));
        state
            .labels
            .values_mut()
            .for_each(|label| height(&mut label.eligibility));
        for found in state.discovered.values_mut().flatten() {
            found.last_sealed_at_discovery.iter_mut().for_each(height);
            found.last_seal_height.iter_mut().for_each(height);
        }
        state
    }

    fn pull(&mut self, history: &History<'_>, event: &Value) -> (u64, u64) {
        let store = &self.store;
        let served = serve_pull(history, event);
        *store.files.lock().unwrap() = served.files.clone();
        let publisher = event["publisher"].as_str().unwrap();
        let scope = store.db.pull_scope(publisher).unwrap();
        let before = self.load(&scope);
        let mut state = before.clone();
        let mut held =
            clave::db::StoreHeld::new(&store.db, store.data.path(), "2026-08-09T00:00:00Z");
        let mut site = HttpSite {
            client: &store.client,
            base: &store.base,
            meter: served.meter,
        };
        let map = parameters(&event["parameters"]);
        let report = pull(
            &mut state,
            &mut site,
            &mut held,
            &PullInput {
                publisher,
                at: event["at"].as_str().unwrap(),
                parameters: &map,
            },
        )
        .unwrap();
        let envelopes = named_labels(history, &event["labels"]);
        accept_labels(&mut state, &report, publisher, &envelopes).unwrap();
        held.store().unwrap();
        store.store(&before, &state, &scope);
        (before.events, state.events)
    }

    fn clock(&self) -> u64 {
        let events: i64 = rusqlite::Connection::open(self.store.data.path().join("clave.sqlite"))
            .unwrap()
            .query_row(
                "SELECT position FROM acceptance_clock WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        events as u64 + 1
    }

    fn epoch(
        &mut self,
        history: &History<'_>,
        event: &Value,
        declarations: &[Value],
        entries: &[Value],
    ) -> (u64, u64) {
        let db = &self.store.db;
        let sealed_at = event["sealed_at"].as_str().unwrap();
        let sealed_s = instant_s(&event["sealed_at"]);
        let schedule = db.parameter_schedule(sealed_s).unwrap();
        for (name, value) in event["parameters"].as_object().unwrap() {
            if OPERATOR_BOUNDS.contains(&name.as_str()) {
                db.set_param(name, value.as_i64().unwrap()).unwrap();
            } else {
                assert_eq!(
                    schedule.value_at(name, sealed_s),
                    value.as_i64(),
                    "{}: {name} is the Log's",
                    history.name
                );
            }
        }
        for envelope in declarations {
            let domain = envelope["publisher"]["domain"].as_str().unwrap();
            db.hold_discovered_declaration(domain, envelope).unwrap();
        }
        let key_id = db.signing_key_id(&self.sk.public()).unwrap();
        let mut wanted = json!(entries);
        for name in event["updates"].as_array().into_iter().flatten() {
            let update = &history.vector["registry_updates"][name.as_str().unwrap()]["update"];
            let envelope =
                wist_core::envelope::sign_envelope(update, "update", &key_id, &self.sk).unwrap();
            db.insert_pending_entry("registry_update", "", &envelope, 0)
                .unwrap();
            for entry in wanted.as_array_mut().unwrap() {
                if entry["type"] == "registry_update" && entry["body"]["update"] == *update {
                    entry["body"] = envelope.clone();
                }
            }
        }
        let before = db.last_epoch().unwrap();
        let from = self.clock();
        let report = clave::seal::run(db, self.store.data.path(), &self.sk, sealed_s)
            .unwrap_or_else(|error| panic!("{} at {sealed_at}: {error}", history.name));
        let height = event["height"].as_u64().unwrap() + self.offset;
        assert_eq!(report.epoch_number, height, "{}", history.name);
        assert_eq!(
            before.map_or(0, |epoch| epoch.epoch_number + 1),
            height,
            "{}",
            history.name
        );
        assert_eq!(
            json!(db.epoch_entries(height).unwrap()),
            wanted,
            "{} at {sealed_at}: the sealed Entries",
            history.name
        );
        (from, self.clock())
    }
}

fn replay_through_the_sealer(keys: &Value, vector: &Value, choice: Choice) {
    let mut run = Run::new(keys, vector);
    run.checked = choice == Choice::Vector;
    let mut sealer = SealerRun::new(&run.history);
    let mut numbers = BTreeMap::new();
    let events = vector["events"].as_array().unwrap();
    let expected = vector["expected"].as_array().unwrap();
    for (at, (event, expected)) in events.iter().zip(expected).enumerate() {
        let first = run.state.events;
        let (from, to) = match event["event"].as_str().unwrap() {
            "epoch" => {
                let declarations = match choice {
                    Choice::Vector => epoch_input_parts(&run.history, event).1,
                    Choice::Sealer => run.sealer_choice(event),
                };
                let entries = run.epoch_with(at, event, expected, declarations.clone());
                let wanted = match choice {
                    Choice::Vector => expected["entries"].as_array().unwrap().clone(),
                    Choice::Sealer => entries,
                };
                sealer.epoch(&run.history, event, &declarations, &wanted)
            }
            _ => {
                let taken = sealer.pull(&run.history, event);
                run.pull(at, event, expected);
                taken
            }
        };
        assert_eq!(
            to - from,
            run.state.events - first,
            "{} event {at}",
            run.history.name
        );
        numbers.extend((from..to).map(|event| (event, first + event - from)));
        run.show();
        let publishers = publishers_of(&run.state);
        let mut stored = sealer.observed(&publishers);
        renumber(&mut stored, &numbers);
        let name = run.history.name;
        assert_eq!(
            state_view(&run.history, &stored, &run.shown),
            state_view(&run.history, &run.state, &run.shown),
            "{name} event {at}: the sealed store"
        );
        assert_eq!(
            stored.collections, run.state.collections,
            "{name} event {at}"
        );
        assert_eq!(stored.urls, run.state.urls, "{name} event {at}");
        assert_eq!(stored.records, run.state.records, "{name} event {at}");
        assert_eq!(stored.removals, run.state.removals, "{name} event {at}");
        assert_eq!(stored.discovered, run.state.discovered, "{name} event {at}");
        assert_eq!(stored.queues, run.state.queues, "{name} event {at}");
        assert_eq!(stored.labels, run.state.labels, "{name} event {at}");
        assert_eq!(
            stored.declarations.domains().keys().collect::<Vec<_>>(),
            run.state.declarations.domains().keys().collect::<Vec<_>>(),
            "{name} event {at}"
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Choice {
    Vector,
    Sealer,
}

const SEALER_CHOICE: &[&str] = &[
    "a competitor that reduces authority, superseded unsealed at settlement",
    "a competitor that fails at its candidate Epoch while a follower is current",
    "a queue settled when the rotation fails keeps what waited at the discovery",
    "a queued Catalog not later than the floor at settlement does not survive",
    "a Declaration that reduces authority, discovered at a pull",
    "a fresh identity that becomes pending, discovered at a pull",
    "the hold keeps eligibility Epochs and ceilings, and a Catalog of another root defers nothing",
    "a pending replacement that reduces authority, discarded by a reversal before it is sealed",
    "a reversal that fails at its candidate Epoch",
    "the latest Catalog fails I4 while a Catalog of the Collection waits that nothing defers",
    "an eligible Item the Aggregator leaves unsealed takes no room",
    "a Label the Aggregator leaves unsealed takes no room under the per-Labeler cap",
];

fn replay_file_through_the_sealer(relative: &str) -> (usize, usize) {
    let vector = read_vector(relative);
    let histories = vector["histories"].as_array().unwrap();
    let mut followed = 0;
    for history in histories {
        let choice = if SEALER_CHOICE.contains(&history["name"].as_str().unwrap()) {
            followed += 1;
            Choice::Sealer
        } else {
            Choice::Vector
        };
        replay_through_the_sealer(&vector["keys"], history, choice);
    }
    (histories.len(), followed)
}

#[test]
fn every_catalog_waiting_history_pulled_over_http_and_sealed_agrees_with_the_machine() {
    assert_eq!(
        replay_file_through_the_sealer("vectors/wist3/catalog-waiting.json"),
        (42, 8)
    );
}

#[test]
fn every_collection_pull_history_pulled_over_http_and_sealed_agrees_with_the_machine() {
    assert_eq!(
        replay_file_through_the_sealer("vectors/wist2/collection-pull.json"),
        (20, 0)
    );
}

#[test]
fn every_catalog_recovery_history_pulled_over_http_and_sealed_agrees_with_the_machine() {
    assert_eq!(
        replay_file_through_the_sealer("vectors/wist1/catalog-recovery.json"),
        (31, 4)
    );
}

#[test]
fn a_history_whose_epochs_the_sealer_chooses_otherwise_seals_entries_the_vector_does_not() {
    for relative in [
        "vectors/wist1/catalog-recovery.json",
        "vectors/wist3/catalog-waiting.json",
    ] {
        let vector = read_vector(relative);
        for history in vector["histories"].as_array().unwrap() {
            let name = history["name"].as_str().unwrap();
            if !SEALER_CHOICE.contains(&name) {
                continue;
            }
            let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                replay_through_the_sealer(&vector["keys"], history, Choice::Vector)
            }))
            .expect_err(name);
            let message = failed
                .downcast_ref::<String>()
                .map(String::as_str)
                .unwrap_or_default();
            assert!(message.contains("the sealed Entries"), "{name}: {message}");
        }
    }
}
