mod common;

use clave::collection::state::Discovered;
use clave::collection::{MemoryHeld, Meter, Object, Parameters, PullInput, ServedSite, State};
use clave::db::Db;
use clave::declaration::{evaluate_with_heads, Decision};
use clave::history::declarations::Declarations;
use clave::history::declarations::DeclarationsReplay;
use serde_json::{json, Value};
use wist_core::declarations::TransitionKind;
use wist_core::{envelope, epoch, jcs};

const DOMAIN: &str = "example.com";

fn machine(db: &Db, path: &std::path::Path) -> State {
    let sealed = db.sealed_state(path).unwrap();
    State {
        height: sealed.height,
        declarations: sealed.declarations,
        ..State::default()
    }
}

fn pull(state: &mut State, served: &Value, at: &str) -> bool {
    let mut site = ServedSite::new(Meter::unbounded());
    site.serve(Object::Declaration, jcs::canonicalize(served).unwrap());
    let parameters = Parameters::default();
    let report = clave::collection::pull(
        state,
        &mut site,
        &mut MemoryHeld::default(),
        &PullInput {
            publisher: DOMAIN,
            at,
            parameters: &parameters,
        },
    )
    .unwrap();
    report.declaration.proceeds
}

fn discover(state: &mut State, sealed: &[Value], envelope: &Value, at: &str) {
    if sealed.contains(envelope) {
        return;
    }
    let hash = clave::declaration::inner_hash(envelope).unwrap();
    let mut entries: Vec<Value> = state
        .discovered
        .get(DOMAIN)
        .into_iter()
        .flatten()
        .map(|found| json!({"type": "publisher_declaration", "body": found.envelope}))
        .chain(std::iter::once(
            json!({"type": "publisher_declaration", "body": envelope}),
        ))
        .collect();
    epoch::sort_entries(&mut entries).unwrap();
    let projection = state
        .declarations
        .project_pull(at, 7, 24, &Default::default(), &entries)
        .ok();
    let competes_with = projection.as_ref().and_then(|projection| {
        projection
            .effects()
            .transitions
            .iter()
            .find(|transition| transition.declaration.hash() == hash)
            .filter(|transition| transition.kind == TransitionKind::InWindowCompetitor)
            .and_then(|_| projection.domains().get(DOMAIN))
            .and_then(|domain| domain.window())
            .map(|window| window.owner().hash().to_owned())
    });
    let seq = envelope["publisher"]["seq"].as_u64().unwrap();
    let floor = state.floors.entry(DOMAIN.to_owned()).or_default();
    *floor = (*floor).max(seq);
    state
        .discovered
        .entry(DOMAIN.to_owned())
        .or_default()
        .push(Discovered {
            envelope: envelope.clone(),
            hash,
            event: 0,
            last_sealed_at_discovery: state.height,
            reduces_authority: false,
            last_seal_height: None,
            competitor: competes_with.is_some(),
            competes_with,
        });
}

fn settled_head(state: &State) -> Value {
    state.declarations.domains()[DOMAIN].window().map_or_else(
        || {
            state.declarations.domains()[DOMAIN]
                .current()
                .envelope()
                .clone()
        },
        |window| window.head().envelope().clone(),
    )
}

struct Admission {
    current: Value,
    floor: u64,
    window: Option<String>,
    retained: Vec<Value>,
}

fn admission(state: &State, at: &str) -> Admission {
    let (_, domain) =
        clave::collection::pull::admission(state, DOMAIN, at, &Parameters::default()).unwrap();
    let domain = domain.unwrap();
    Admission {
        current: state
            .discovered
            .get(DOMAIN)
            .and_then(|found| found.last())
            .map(|found| found.envelope.clone())
            .unwrap_or_else(|| {
                domain
                    .pending()
                    .map_or_else(|| domain.current(), |pending| pending.head())
                    .envelope()
                    .clone()
            }),
        floor: domain
            .highest_accepted_seq()
            .max(state.floors.get(DOMAIN).copied().unwrap_or_default()),
        window: domain
            .window()
            .map(|window| window.owner().hash().to_owned()),
        retained: state
            .discovered
            .get(DOMAIN)
            .into_iter()
            .flatten()
            .map(|found| found.envelope.clone())
            .collect(),
    }
}

fn append(db: &Db, path: &std::path::Path, sk: &wist_core::crypto::SigningKey, doc: &Value) {
    let checkpoint =
        wist_core::checkpoint::Checkpoint::parse(doc["checkpoint"].as_str().unwrap()).unwrap();
    let entries: Vec<Value> = serde_json::from_value(doc["entries"].clone()).unwrap();
    let anchor = clave::history::anchor(path).unwrap();
    db.commit_seal(
        sk,
        &anchor.log_id,
        &[],
        checkpoint.epoch_number(),
        checkpoint.sealed_at(),
        &entries,
        epoch::epoch_octets(&entries).unwrap(),
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
    )
    .unwrap();
    clave::publication::recover(db, path).unwrap();
}

#[test]
fn signed_pending_declaration_settlement_vectors_survive_reopen_and_repeat() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(common::spec_dir().join("vectors/wist1/recovery-admission.json")).unwrap(),
    )
    .unwrap();
    let declarations = &vector["declarations"];
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let data = tempfile::tempdir().unwrap();
        clave::init::run("log.example.com", data.path()).unwrap();
        let key = wist_core::crypto::SigningKey::from_seed(&std::array::from_fn(|i| i as u8));
        let anchor = envelope::sign_envelope(
            &json!({
                "wist_version": "1.0.0", "log_id": "log.example.com",
                "genesis_key": {"key_id": "test-log-k1", "alg": "Ed25519",
                    "public_key": vector["log_key"]["public_key"]},
                "created_at": "2026-08-02T00:00:00Z"
            }),
            "anchor",
            "test-log-k1",
            &key,
        )
        .unwrap();
        std::fs::write(
            data.path().join("anchor.json"),
            jcs::canonicalize(&anchor).unwrap(),
        )
        .unwrap();
        let database = data.path().join("clave.sqlite");
        let mut db = Db::open(&database).unwrap();
        for epoch in vector["epochs"].as_array().unwrap() {
            append(&db, data.path(), &key, epoch);
        }
        assert_eq!(
            db.last_epoch().unwrap().unwrap().root,
            vector["pinned_head"].as_str().unwrap()
        );
        let admitted: Vec<Value> = case["admitted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|declaration| declarations[declaration.as_str().unwrap()].clone())
            .collect();
        append(&db, data.path(), &key, &case["last_inside_epoch"]);
        assert_eq!(
            db.last_epoch().unwrap().unwrap().root,
            case["last_inside_pin"].as_str().unwrap()
        );
        db = Db::open(&database).unwrap();
        let mut state = machine(&db, data.path());
        let sealed: Vec<Value> = (0..=db.last_epoch().unwrap().unwrap().epoch_number)
            .flat_map(|height| db.epoch_entries(height).unwrap())
            .map(|entry| entry["body"].clone())
            .collect();
        for declaration in &admitted {
            discover(
                &mut state,
                &sealed,
                declaration,
                case["admitted_at"].as_str().unwrap(),
            );
        }
        let deadline = vector["deadline"].as_str().unwrap();
        let served = settled_head(&state);
        pull(&mut state, &served, deadline);
        let settled = admission(&state, deadline);
        let expected = &case["expected_settlement"];
        assert_eq!(
            settled.current,
            declarations[expected["current"].as_str().unwrap()],
            "{name}"
        );
        assert_eq!(Some(settled.floor), expected["floor"].as_u64(), "{name}");
        let sealed_owner = state.declarations.domains()[DOMAIN]
            .window()
            .map(|window| window.owner().hash().to_owned());
        assert!(sealed_owner.is_some(), "{name}");
        assert_ne!(settled.window, sealed_owner, "{name}");
        let retained = expected["retained"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| declarations[name.as_str().unwrap()].clone())
            .collect::<Vec<_>>();
        assert_eq!(settled.retained, retained, "{name}");
        for probe in case["at_deadline"].as_array().unwrap() {
            let doc = &declarations[probe["declaration"].as_str().unwrap()];
            let settled = admission(&state, deadline);
            let result = evaluate_with_heads(
                &settled.current,
                None,
                None,
                settled.floor,
                doc,
                &Default::default(),
            );
            let outcome = match result {
                Ok(Decision::FreshIdentity) => {
                    assert!(pull(&mut state, doc, deadline), "{name}");
                    "fresh_identity"
                }
                Err((code, _)) => code,
                other => panic!("{name}: {other:?}"),
            };
            assert_eq!(outcome, probe["expected"], "{name}");
        }
        pull(&mut state, &served, deadline);
        let repeated = admission(&state, deadline);
        let expected = &case["expected_after_repeat"];
        assert_eq!(
            repeated.current,
            declarations[expected["current"].as_str().unwrap()],
            "{name}"
        );
        assert_eq!(Some(repeated.floor), expected["floor"].as_u64(), "{name}");
        let mut pending: Vec<Value> = repeated
            .retained
            .iter()
            .map(|body| json!({"type": "publisher_declaration", "body": body}))
            .collect();
        epoch::sort_entries(&mut pending).unwrap();
        let history =
            Declarations::reconstruct(&db, data.path(), db.last_epoch().unwrap()).unwrap();
        let entries = pending
            .iter()
            .map(|entry| serde_json::from_value(entry.clone()).unwrap())
            .collect::<Vec<_>>();
        let projection = history
            .project(
                deadline,
                7,
                vector["declaration_activation_epochs"]
                    .as_i64()
                    .unwrap_or(24),
                &Default::default(),
                &entries,
            )
            .unwrap();
        let state = &projection.domains()[DOMAIN];
        assert_eq!(
            state.current().envelope(),
            &declarations[case["expected_log"]["current"].as_str().unwrap()],
            "{name}"
        );
        assert_eq!(
            state.highest_accepted_seq(),
            case["expected_log"]["floor"].as_u64().unwrap(),
            "{name}"
        );
        if let Some(owner) = case["expected_window_owner"].as_str() {
            assert_eq!(
                state.window().unwrap().owner().envelope(),
                &declarations[owner],
                "{name}"
            );
        } else {
            assert!(state.window().is_none(), "{name}");
        }
    }
}
