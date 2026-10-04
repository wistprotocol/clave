use clave::db::EpochRow;
use clave::declaration::Decision;
use clave::history::declarations::DeclarationsReplay;
use clave::history::declarations::{Declarations, Domain, Effects};
use clave::history::History;
use serde_json::{json, Value};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::{envelope, epoch, jcs};

fn vector(name: &str) -> Value {
    let root = std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        });
    serde_json::from_slice(&std::fs::read(root.join(format!("vectors/{name}.json"))).unwrap())
        .unwrap()
}

#[test]
fn field_rejection_preserves_the_complete_declaration_prefix() {
    for name in [
        "wist1/base64url",
        "wist1/declaration-fields",
        "wist1/declaration-hosts",
    ] {
        let vector = vector(name);
        for case in vector["epoch_cases"].as_array().unwrap() {
            let mut epochs = vector["prefixes"][case["prefix"].as_str().unwrap()]
                .as_array()
                .unwrap()
                .clone();
            let prefix_length = epochs.len();
            epochs.push(case["epoch"].clone());
            let fixture = Fixture::new(&epochs);
            assert_eq!(
                fixture.head().unwrap().root,
                case["pinned_head"].as_str().unwrap()
            );
            let mut reader = fixture.reader();
            let mut state = Declarations::default();
            for _ in 0..prefix_length {
                state.apply(&reader.next_epoch().unwrap().unwrap()).unwrap();
            }
            let before = format!("{state:?}");
            let epoch = reader.next_epoch().unwrap().unwrap();
            let projection = state.project(
                epoch.sealed_at(),
                reader
                    .schedule()
                    .unwrap()
                    .value_at("recovery_window_days", epoch.sealed_at_s())
                    .unwrap(),
                reader
                    .schedule()
                    .unwrap()
                    .value_at("declaration_activation_epochs", epoch.sealed_at_s())
                    .unwrap(),
                &Default::default(),
                epoch.entries(),
            );
            assert_eq!(format!("{state:?}"), before);
            let result = state.apply(&epoch);
            assert_eq!(projection.is_ok(), result.is_ok());
            if let Ok(projected) = projection {
                assert_eq!(
                    format!("{:?}", projected.domains()),
                    format!("{:?}", state.domains())
                );
            }
            if case["expected"] == "accepted" {
                assert!(result.is_ok(), "{}: {result:?}", case["name"]);
                if let Some(domains) = case.get("expected_domains") {
                    assert_eq!(
                        serde_json::to_value(state.domains().keys().collect::<Vec<_>>()).unwrap(),
                        *domains
                    );
                }
                assert_eq!(
                    state.head().unwrap().1,
                    case["pinned_head"].as_str().unwrap()
                );
                assert_eq!(
                    format!("{:?}", fixture.restore().unwrap()),
                    format!("{state:?}")
                );
            } else {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains(case["expected"].as_str().unwrap()),
                    "{}: {error}",
                    case["name"]
                );
                assert_eq!(format!("{state:?}"), before, "{}", case["name"]);
                assert!(epoch.rejected().is_some(), "{}", case["name"]);
                let restored = fixture.restore().unwrap();
                assert_eq!(
                    format!("{:?}", restored.domains()),
                    format!("{:?}", state.domains()),
                    "{}",
                    case["name"]
                );
                assert_eq!(
                    restored.head(),
                    Some((epoch.epoch_number(), epoch.root())),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

fn log_key() -> SigningKey {
    SigningKey::from_seed(&std::array::from_fn(|i| i as u8))
}

fn timestamp(at: i64) -> String {
    clave::registry::instant(at).unwrap()
}

fn sealed_at(epoch: &Value) -> String {
    match epoch.get("checkpoint").and_then(Value::as_str) {
        Some(note) => wist_core::checkpoint::Checkpoint::parse(note)
            .unwrap()
            .sealed_at()
            .to_owned(),
        None => epoch["sealed_at"].as_str().unwrap().to_owned(),
    }
}

fn entries_of(epoch: &Value) -> Vec<Value> {
    serde_json::from_value(epoch["entries"].clone()).unwrap()
}

fn digest(value: &Value) -> String {
    use sha2::Digest;
    format!(
        "sha256:{}",
        hex_encode(&sha2::Sha256::digest(jcs::canonicalize(value).unwrap()))
    )
}

fn signed_epoch(prefix: &[Value], at: &str, mut entries: Vec<Value>) -> Value {
    let _ = prefix;
    epoch::sort_entries(&mut entries).unwrap();
    json!({"sealed_at": at, "entries": entries})
}

struct Fixture {
    data: tempfile::TempDir,
    db: clave::db::Db,
    head: Option<EpochRow>,
}

impl Fixture {
    fn new(epochs: &[Value]) -> Self {
        Self::with_key_id(epochs, "test-log-k1")
    }

    fn with_key_id(epochs: &[Value], key_id: &str) -> Self {
        let data = tempfile::tempdir().unwrap();
        let anchor = json!({"wist_version":"1.0.0", "log_id":"log.example.org", "genesis_key":{"key_id":key_id,"alg":"Ed25519","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},"created_at":"2026-08-02T00:00:00Z"});
        let anchor = envelope::sign_envelope(&anchor, "anchor", key_id, &log_key()).unwrap();
        std::fs::write(
            data.path().join("anchor.json"),
            jcs::canonicalize(&anchor).unwrap(),
        )
        .unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        let mut head = None;
        for (height, epoch) in epochs.iter().enumerate() {
            let mut entries = entries_of(epoch);
            epoch::sort_entries(&mut entries).unwrap();
            head = Some(
                db.commit_seal(
                    &log_key(),
                    "log.example.org",
                    &[],
                    height as u64,
                    &sealed_at(epoch),
                    &entries,
                    epoch::epoch_octets(&entries).unwrap(),
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .unwrap(),
            );
        }
        Self { data, db, head }
    }

    fn head(&self) -> Option<EpochRow> {
        self.head.clone()
    }

    fn reader(&self) -> History<'_> {
        History::open(&self.db, self.data.path(), self.head()).unwrap()
    }

    fn restore(&self) -> clave::error::Result<Declarations> {
        Declarations::reconstruct(&self.db, self.data.path(), self.head())
    }
}

fn summary(domain: &Domain, windows: u64) -> Value {
    json!({"current_declaration":domain.current().hash(),"recovery_head":domain.window().map(|w| w.head().hash()),"highest_accepted_seq":domain.highest_accepted_seq(),"window_end":domain.window().map(|w| timestamp(w.end_s().try_into().unwrap())),"windows_opened":windows})
}

fn outcome(effects: &Effects) -> &'static str {
    effects
        .installations
        .last()
        .map_or("idempotent", |i| match i.decision {
            None => "initial",
            Some(Decision::Ordinary) => "ordinary_rotation",
            Some(Decision::Recovery) => "recovery_rotation",
            Some(Decision::FreshIdentity) => "fresh_identity",
            Some(Decision::Unchanged) => unreachable!(),
        })
}

fn probe(epochs: &[Value], probe: &Value) -> (Declarations, Result<Effects, String>, u64) {
    let height = probe["prefix_height"].as_u64().unwrap() as usize;
    let mut candidate = epochs[..=height].to_vec();
    let mut entries = if let Some(candidates) = probe["candidates"].as_array() {
        candidates
            .iter()
            .map(|c| json!({"type":"publisher_declaration","body":c}))
            .collect()
    } else {
        vec![json!({"type":"publisher_declaration","body":probe["candidate"]})]
    };
    if !probe["successor"].is_null() {
        entries.push(json!({"type":"publisher_declaration","body":probe["successor"]}));
    }
    let next = signed_epoch(
        &candidate,
        probe["candidate_sealed_at"].as_str().unwrap(),
        entries,
    );
    candidate.push(next);
    let fixture = Fixture::new(&candidate);
    let mut history = fixture.reader();
    let mut state = Declarations::default();
    let mut windows = 0;
    for _ in 0..=height {
        let effects = state
            .apply(&history.next_epoch().unwrap().unwrap())
            .unwrap();
        windows += effects
            .installations
            .iter()
            .filter(|i| i.opens_window)
            .count() as u64;
    }
    let before = format!("{state:?}");
    let candidate = history.next_epoch().unwrap().unwrap();
    let projection = state.project(
        candidate.sealed_at(),
        history
            .schedule()
            .unwrap()
            .value_at("recovery_window_days", candidate.sealed_at_s())
            .unwrap(),
        history
            .schedule()
            .unwrap()
            .value_at("declaration_activation_epochs", candidate.sealed_at_s())
            .unwrap(),
        &Default::default(),
        candidate.entries(),
    );
    assert_eq!(format!("{state:?}"), before);
    let result = state.apply(&candidate).map_err(|e| e.to_string());
    match (&projection, &result) {
        (Ok(projected), Ok(effects)) => {
            assert_eq!(
                format!("{:?}", projected.domains()),
                format!("{:?}", state.domains())
            );
            assert_eq!(format!("{:?}", projected.effects()), format!("{effects:?}"));
            assert_eq!(projected.epoch_number(), candidate.epoch_number());
            assert_eq!(projected.sealed_at_s(), candidate.sealed_at_s());
        }
        (Err(projected), Err(applied)) => assert_eq!(projected.to_string(), *applied),
        _ => panic!("projection disagrees with authenticated application"),
    }
    if let Ok(effects) = &result {
        windows += effects
            .installations
            .iter()
            .filter(|i| i.opens_window)
            .count() as u64;
        assert_eq!(
            outcome(effects),
            probe
                .get("expected_successor_result")
                .unwrap_or(&probe["expected_result"]),
            "{}",
            probe["name"]
        );
    } else {
        assert!(
            result
                .as_ref()
                .unwrap_err()
                .contains(probe["expected_result"].as_str().unwrap()),
            "{probe}"
        );
        assert_eq!(format!("{state:?}"), before);
    }
    (state, result, windows)
}

#[test]
fn recovery_ownership_uses_sequence_with_original_canonical_positions() {
    for case in vector("wist1/recovery-order")["cases"].as_array().unwrap() {
        let epochs = case["epochs"].as_array().unwrap();
        let fixture = Fixture::new(epochs);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        let mut sequences = Vec::new();
        let mut windows = 0;
        while let Some(epoch) = reader.next_epoch().unwrap() {
            for installation in state.apply(&epoch).unwrap().installations {
                let declaration = installation.declaration;
                let position = declaration.position();
                assert_eq!(
                    &epochs[position.epoch_number as usize]["entries"][position.entry_index]
                        ["body"],
                    declaration.envelope()
                );
                sequences.push(declaration.envelope()["publisher"]["seq"].clone());
                windows += u64::from(installation.opens_window);
            }
        }
        assert_eq!(json!(sequences), case["expected"]["application_sequences"]);
        assert_eq!(windows, case["expected"]["windows_opened"]);
        let window = state.domains()["example.com"].window().unwrap();
        assert_eq!(window.owner().hash(), case["expected"]["owner_declaration"]);
        assert_eq!(
            window.owner().position().epoch_number,
            case["expected"]["owner_height"]
        );
        assert_eq!(state.head().unwrap().1, case["pinned_head"]);
        assert_eq!(
            format!("{:?}", fixture.restore().unwrap()),
            format!("{state:?}")
        );
    }
}

#[test]
fn recovery_heads_sequence_floors_and_named_predecessors_match_signed_vectors() {
    let vector = vector("wist1/recovery-heads");
    for branch in std::iter::once(&vector).chain(vector["branches"].as_array().unwrap()) {
        let epochs = branch["epochs"].as_array().unwrap();
        let fixture = Fixture::new(epochs);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        let mut windows = 0;
        while let Some(epoch) = reader.next_epoch().unwrap() {
            let effects = state.apply(&epoch).unwrap();
            windows += effects
                .installations
                .iter()
                .filter(|i| i.opens_window)
                .count() as u64;
            if let Some(expected_states) = branch["expected_prefix_states"].as_array() {
                for expected in expected_states {
                    if expected["height"] == epoch.epoch_number() {
                        assert_eq!(
                            summary(&state.domains()["example.com"], windows),
                            expected["state"]
                        );
                    }
                }
            }
        }
        for candidate in branch["probes"].as_array().into_iter().flatten() {
            let selected_epochs = candidate["branch"].as_u64().map_or(epochs, |index| {
                vector["branches"][index as usize]["epochs"]
                    .as_array()
                    .unwrap()
            });
            let (state, result, windows) = probe(selected_epochs, candidate);
            if result.is_ok() {
                assert_eq!(
                    summary(&state.domains()["example.com"], windows),
                    candidate["expected_state"],
                    "{}",
                    candidate["name"]
                );
            }
        }
        if !branch["expected_state"].is_null() {
            assert_eq!(
                summary(&state.domains()["example.com"], windows),
                branch["expected_state"]
            );
        }
        assert_eq!(state.head().unwrap().1, branch["pinned_head"]);
    }
}

fn apply_under(
    state: &mut Declarations,
    epoch: &clave::history::VerifiedEpoch,
    days: i64,
    activation_epochs: i64,
) -> Result<clave::history::declarations::Effects, clave::Error> {
    Ok(state.apply_epoch(
        epoch.epoch_number(),
        epoch.root(),
        epoch.sealed_at(),
        days,
        activation_epochs,
        &Default::default(),
        epoch.entries(),
    )?)
}

#[test]
fn conflicting_groups_and_failed_authors_reject_epochs_atomically() {
    let vector = vector("wist1/declaration-conflicts");
    let days = vector["recovery_window_days"].as_i64().unwrap();
    let activation_epochs = vector["declaration_activation_epochs"].as_i64().unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let mut epochs = vector["prefixes"][case["prefix"].as_str().unwrap()]
            .as_array()
            .unwrap()
            .clone();
        epochs.push(case["epoch"].clone());
        let fixture = Fixture::new(&epochs);
        let mut history = fixture.reader();
        let mut state = Declarations::default();
        let mut windows = std::collections::BTreeMap::<String, u64>::new();
        while let Some(epoch) = history.next_epoch().unwrap() {
            let before = format!("{state:?}");
            match apply_under(&mut state, &epoch, days, activation_epochs) {
                Ok(effects) => {
                    for installation in effects.installations {
                        let domain = installation.declaration.envelope()["publisher"]["domain"]
                            .as_str()
                            .unwrap()
                            .to_string();
                        *windows.entry(domain).or_default() += u64::from(installation.opens_window);
                    }
                    if epoch.epoch_number() as usize == epochs.len() - 1 {
                        assert!(case["expected_results"]
                            .as_array()
                            .unwrap()
                            .contains(&json!("accepted")));
                    }
                }
                Err(error) => {
                    assert_eq!(epoch.epoch_number() as usize, epochs.len() - 1);
                    assert!(
                        case["expected_results"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|c| error.to_string().contains(c.as_str().unwrap())),
                        "{}: {error}",
                        case["name"]
                    );
                    assert_eq!(format!("{state:?}"), before);
                    assert!(epoch.rejected().is_some(), "{}", case["name"]);
                    let restored = fixture.restore().unwrap();
                    assert_eq!(
                        format!("{:?}", restored.domains()),
                        format!("{:?}", state.domains())
                    );
                    assert_eq!(restored.head(), Some((epoch.epoch_number(), epoch.root())));
                }
            }
        }
        let actual:serde_json::Map<_,_>=state.domains().iter().map(|(name,domain)|(name.clone(),json!({"current_envelope":digest(domain.current().envelope()),"recovery_envelope":domain.window().map(|w|digest(w.head().envelope())),"highest_accepted_seq":domain.highest_accepted_seq(),"window_end":domain.window().map(|w|timestamp(w.end_s().try_into().unwrap())),"windows_opened":windows[name],"reset_height":domain.reset().map(|p|p.epoch_number)}))).collect();
        assert_eq!(
            Value::Object(actual),
            case["expected_state"],
            "{}",
            case["name"]
        );
        let empty_tree = format!("sha256:{}", hex_encode(&wist_core::merkle::EMPTY_ROOT));
        assert_eq!(
            state.head().map_or(empty_tree.as_str(), |h| h.1),
            case["expected_accepted_head"]
        );
    }
}

#[test]
fn settlement_restores_authenticated_chain_and_reports_competitors() {
    for case in vector("wist1/recovery-settlement")["cases"]
        .as_array()
        .unwrap()
    {
        let epochs = case["epochs"].as_array().unwrap();
        let fixture = Fixture::new(epochs);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        let mut superseded = Vec::new();
        while let Some(epoch) = reader.next_epoch().unwrap() {
            for settlement in state.apply(&epoch).unwrap().settlements {
                superseded.extend(settlement.superseded.iter().map(|d| d.hash().to_string()));
            }
        }
        assert_eq!(
            state.domains()["example.com"].current().hash(),
            case["expected"]["effective_declaration"]
        );
        assert_eq!(json!(superseded), case["expected"]["superseded"]);
        for candidate in case["probes"].as_array().unwrap() {
            let mut candidate = candidate.clone();
            let height = candidate["prefix_height"].as_u64().unwrap() as usize;
            candidate["candidate_sealed_at"] = timestamp(
                sealed_at(&epochs[height])
                    .as_str()
                    .parse::<jiff::Timestamp>()
                    .unwrap()
                    .as_second()
                    + 3600,
            )
            .into();
            assert!(probe(epochs, &candidate).1.is_err());
        }
    }
}

#[test]
fn reconstruction_requires_complete_pinned_history_and_sequential_application() {
    let vector = vector("wist1/recovery-heads");
    let epochs = vector["epochs"].as_array().unwrap();
    let fixture = Fixture::new(epochs);
    let mut reader = fixture.reader();
    let first = reader.next_epoch().unwrap().unwrap();
    let second = reader.next_epoch().unwrap().unwrap();
    let mut state = Declarations::default();
    assert!(state.apply(&second).is_err());
    assert!(state.domains().is_empty());
    state.apply(&first).unwrap();
    assert!(state.apply(&first).is_err());
    state.apply(&second).unwrap();
    assert!(fixture.restore().is_ok());
    let mut wrong_head = fixture.head().unwrap();
    wrong_head.root = "sha256:wrong".into();
    assert!(Declarations::reconstruct(&fixture.db, fixture.data.path(), Some(wrong_head)).is_err());
    rusqlite::Connection::open(fixture.data.path().join("clave.sqlite"))
        .unwrap()
        .execute(
            "DELETE FROM epochs WHERE epoch_number = ?1",
            [(epochs.len() - 1) as i64],
        )
        .unwrap();
    assert!(fixture.restore().is_err());
}

fn recovery_declaration(previous: Option<&Value>) -> Value {
    let signing = SigningKey::from_seed(&[42; 32]);
    let recovery = SigningKey::from_seed(&[43; 32]);
    let signing_entry =
        wist_core::objects::PublisherKey::new(&signing.public().to_b64u(), 1_767_225_600, None);
    let recovery_entry =
        wist_core::objects::PublisherKey::new(&recovery.public().to_b64u(), 1_767_225_600, None);
    let mut publisher = json!({"wist_version":"1.0.0","domain":"example.com","seq":previous.map_or(0,|p|p["publisher"]["seq"].as_u64().unwrap()+1),"keys":[signing_entry],"recovery_keys":[recovery_entry]});
    if let Some(previous) = previous {
        publisher["prev_declaration"] = digest(&previous["publisher"]).into();
    }
    let (kid, key) = if previous.is_some() {
        (&recovery_entry.kid, &recovery)
    } else {
        (&signing_entry.kid, &signing)
    };
    envelope::sign_envelope(&publisher, "publisher", kid, key).unwrap()
}

#[test]
fn authenticated_parameter_schedules_freeze_window_length_at_each_owner() {
    let vector = vector("wist4/parameter-combinations");
    let base = vector["recovery_window_base_s"].as_i64().unwrap();
    for case in vector["recovery_window_cases"].as_array().unwrap() {
        let initial = recovery_declaration(None);
        let mut entries = vec![json!({"type":"publisher_declaration","body":initial})];
        let rejected_amendments = case["rejected_amendments"].as_array().unwrap();
        for amendment in case["accepted_amendments"]
            .as_array()
            .unwrap()
            .iter()
            .chain(rejected_amendments)
        {
            assert_eq!(amendment["sealed_at_s"], 0);
            let update = json!({"wist_version":"1.0.0","action":"parameter_change","subject":"recovery_window_days","effective_at":timestamp(base+amendment["effective_at_s"].as_i64().unwrap()),"details":{"parameter":"recovery_window_days","value":amendment["value"]}});
            entries.push(json!({"type":"registry_update","body":envelope::sign_envelope(&update,"update","test-log-k1",&log_key()).unwrap()}));
        }
        let events = case["eligible_recoveries"].as_array().unwrap();
        let probes = case["probes"].as_array().unwrap();
        let unsealable = events
            .iter()
            .find(|event| event["sealable"] == false)
            .map(|event| event["sealed_at_s"].as_i64().unwrap());
        let mut timeline = std::collections::BTreeMap::<i64, Vec<Value>>::new();
        timeline.insert(0, entries);
        let mut previous = initial;
        for event in events {
            let declaration = recovery_declaration(Some(&previous));
            timeline
                .entry(event["sealed_at_s"].as_i64().unwrap())
                .or_default()
                .push(json!({"type":"publisher_declaration","body":declaration}));
            previous = declaration;
        }
        for probe in probes {
            timeline
                .entry(probe["at_s"].as_i64().unwrap().div_euclid(3600) * 3600)
                .or_default();
        }
        let mut epochs = Vec::new();
        for (at, entries) in timeline {
            epochs.push(signed_epoch(&epochs, &timestamp(base + at), entries));
        }
        let fixture = Fixture::new(&epochs);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        let mut stopped = false;
        while let Some(epoch) = reader.next_epoch().unwrap() {
            let at = epoch.sealed_at_s() - base;
            assert_eq!(
                epoch.rejected_parameters().len(),
                if at == 0 {
                    rejected_amendments.len()
                } else {
                    0
                },
                "{}",
                case["label"]
            );
            if unsealable == Some(at) {
                let failure = state
                    .apply(&epoch)
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                assert!(
                    failure.contains("WIST1-E08"),
                    "{}: {failure}",
                    case["label"]
                );
                stopped = true;
                break;
            }
            state.apply(&epoch).unwrap();
            for event in events.iter().filter(|event| event["sealed_at_s"] == at) {
                let window = state.domains()["example.com"].window().unwrap();
                assert_eq!(
                    window.owner().sealed_at_s(),
                    base + event["owner_at_s"].as_i64().unwrap()
                );
                assert_eq!(
                    window.end_s(),
                    i128::from(base)
                        + event["window_end_s"]
                            .as_str()
                            .unwrap()
                            .parse::<i128>()
                            .unwrap()
                );
                assert_eq!(
                    window.before().envelope()["publisher"]["seq"]
                        .as_u64()
                        .unwrap()
                        + 1,
                    window.owner().envelope()["publisher"]["seq"]
                        .as_u64()
                        .unwrap()
                );
            }
            for probe in probes
                .iter()
                .filter(|probe| probe["at_s"].as_i64().unwrap().div_euclid(3600) * 3600 == at)
            {
                assert_eq!(
                    state.domains()["example.com"].window().is_some(),
                    probe["open"].as_bool().unwrap(),
                    "{} at {at}",
                    case["label"]
                );
            }
        }
        if stopped {
            assert_eq!(
                format!("{:?}", fixture.restore().unwrap().domains()),
                format!("{:?}", state.domains()),
                "{}",
                case["label"]
            );
        } else {
            assert_eq!(
                format!("{:?}", fixture.restore().unwrap()),
                format!("{state:?}")
            );
        }
    }
}

#[test]
fn candidate_projection_requires_valid_time_profile_and_entry_order() {
    let vector = vector("wist1/recovery-heads");
    let epochs = vector["epochs"].as_array().unwrap();
    let state = Fixture::new(&epochs[..2]).restore().unwrap();
    let before = format!("{state:?}");
    let at = sealed_at(&epochs[2]);
    let at = at.as_str();
    for invalid in [
        sealed_at(&epochs[0]).as_str(),
        sealed_at(&epochs[1]).as_str(),
        "2026-08-04T02:00:60Z",
        "2026-08-04T02:00:00.0Z",
        "2026-08-04T02:00:00+00:00",
    ] {
        assert!(state
            .project(invalid, 7, 0, &Default::default(), &[])
            .is_err());
    }
    assert!(state.project(at, 0, 0, &Default::default(), &[]).is_err());
    assert!(state
        .project(at, i64::MAX, 0, &Default::default(), &[])
        .is_err());
    let malformed = json!({"type":"publisher_declaration","body":null});
    assert!(state
        .project(at, 7, 0, &Default::default(), &[malformed])
        .is_err());
    let mut entries = vec![
        json!({"type":"label","body":{}}),
        epochs[2]["entries"][0].clone(),
    ];
    assert!(state
        .project(at, 7, 0, &Default::default(), &entries)
        .is_err());
    entries.reverse();
    assert!(state
        .project(at, 7, 0, &Default::default(), &entries)
        .is_ok());
    assert_eq!(format!("{state:?}"), before);
}
