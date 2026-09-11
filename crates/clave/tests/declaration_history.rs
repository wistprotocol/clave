use clave::db::BlockRow;
use clave::declaration::Decision;
use clave::history::declarations::{Declarations, Domain, Effects};
use clave::history::History;
use serde_json::{json, Value};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::{block, envelope, jcs, merkle};

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
        for case in vector["block_cases"].as_array().unwrap() {
            let mut blocks = vector["prefixes"][case["prefix"].as_str().unwrap()]
                .as_array()
                .unwrap()
                .clone();
            let prefix_length = blocks.len();
            blocks.push(case["block"].clone());
            assert_eq!(
                digest(&blocks.last().unwrap()["header"]),
                case["pinned_head"]
            );
            let fixture = Fixture::new(&blocks);
            let mut reader = fixture.reader();
            let mut state = Declarations::default();
            for _ in 0..prefix_length {
                state.apply(&reader.next_block().unwrap().unwrap()).unwrap();
            }
            let before = format!("{state:?}");
            let result = state.apply(&reader.next_block().unwrap().unwrap());
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
                assert!(fixture
                    .restore()
                    .unwrap_err()
                    .to_string()
                    .contains(case["expected"].as_str().unwrap()));
            }
        }
    }
}

#[test]
fn delta_bindings_use_frozen_authenticated_recovery_sources() {
    let vector = vector("wist1/recovery-bindings");
    let mut prefixes = std::collections::BTreeMap::new();
    for (name, history) in vector["histories"].as_object().unwrap() {
        let blocks = history["blocks"].as_array().unwrap();
        assert_eq!(
            digest(&blocks.last().unwrap()["header"]),
            history["pinned_head"]
        );
        let fixture = Fixture::new(blocks);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        while let Some(block) = reader.next_block().unwrap() {
            state.apply(&block).unwrap();
            if state.domains()["example.com"].window().is_some() {
                prefixes.insert(
                    (name.clone(), block.block().header.block_number),
                    state.clone(),
                );
            }
        }
        assert_eq!(
            format!("{:?}", fixture.restore().unwrap()),
            format!("{state:?}")
        );
    }
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let state = &prefixes[&(
            case["history"].as_str().unwrap().to_owned(),
            case["prefix_height"].as_u64().unwrap(),
        )];
        let before = format!("{state:?}");
        let window = state.domains()["example.com"].window().unwrap();
        assert_eq!(window.owner().position().block_number, 1);
        assert_eq!(window.before().position().block_number, 0);
        let prior = clave::declaration::publisher_of(window.before().envelope()).unwrap();
        let owner = clave::declaration::publisher_of(window.owner().envelope()).unwrap();
        let mut keys: Vec<_> = prior.keys.iter().chain(&owner.keys).collect();
        let envelope = &case["envelope"];
        let check = |keys: &[&wist_core::objects::PublisherKey], doc: &Value| {
            clave::declaration::verify_signed(
                keys,
                doc,
                "delta",
                doc["delta"]["observed_at"].as_str(),
            )
            .err()
            .unwrap_or("accepted")
        };
        assert_eq!(check(&keys, envelope), case["expected"], "{name}");
        keys.reverse();
        assert_eq!(check(&keys, envelope), case["expected"], "{name}");
        if case["expected"] == "accepted" {
            let mut altered = envelope.clone();
            altered["delta"]["url"] = json!("https://example.com/changed");
            assert_eq!(check(&keys, &altered), "WIST1-E01", "{name}");
        }
        assert_eq!(format!("{state:?}"), before, "{name}");
    }
}

#[test]
fn delta_scope_stays_with_its_authenticated_declaration_source() {
    let vector = vector("wist1/recovery-scope");
    let key_id = vector["log_key"]["key_id"].as_str().unwrap();
    let mut sources = std::collections::BTreeMap::new();
    for (name, history) in vector["histories"].as_object().unwrap() {
        let blocks = history["blocks"].as_array().unwrap();
        assert_eq!(
            digest(&blocks.last().unwrap()["header"]),
            history["pinned_head"]
        );
        let fixture = Fixture::with_key_id(blocks, key_id);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        while let Some(block) = reader.next_block().unwrap() {
            let effects = state.apply(&block).unwrap();
            let height = block.block().header.block_number;
            let domain = &state.domains()["example.com"];
            fn parse(doc: &Value) -> wist_core::objects::Publisher {
                clave::declaration::publisher_of(doc).unwrap()
            }
            let admission = match domain.window() {
                Some(window) => vec![
                    parse(window.before().envelope()),
                    parse(window.owner().envelope()),
                ],
                None => vec![parse(domain.current().envelope())],
            };
            sources.insert((name.clone(), height, "admission"), admission);
            sources.insert(
                (name.clone(), height, "sealing"),
                vec![parse(domain.current().envelope())],
            );
            for settlement in effects.settlements {
                assert_eq!(settlement.domain, "example.com");
                sources.insert(
                    (name.clone(), height, "settlement"),
                    vec![parse(settlement.restored.envelope())],
                );
            }
            if vector["probes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|probe| probe["history"] == *name && probe["height"] == height)
            {
                let restored = Fixture::with_key_id(&blocks[..=height as usize], key_id)
                    .restore()
                    .unwrap();
                assert_eq!(format!("{restored:?}"), format!("{state:?}"));
            }
        }
        assert_eq!(
            format!("{:?}", fixture.restore().unwrap()),
            format!("{state:?}")
        );
    }
    for probe in vector["probes"].as_array().unwrap() {
        let stage = probe["stage"].as_str().unwrap();
        let source = &sources[&(
            probe["history"].as_str().unwrap().to_owned(),
            probe["height"].as_u64().unwrap(),
            stage,
        )];
        let envelope = &probe["envelope"];
        let original = envelope.clone();
        for reverse in [false, true] {
            let mut source: Vec<_> = source.iter().collect();
            if reverse {
                source.reverse();
            }
            let check = |doc| match clave::declaration::verify_delta_authority(&source, doc) {
                Ok(()) => "accepted",
                Err("WIST1-E14") => "WIST1-E14",
                Err(_) if stage == "settlement" => "WIST1-E13",
                Err("WIST1-E01") if stage == "sealing" => "WIST1-E02",
                Err(code) => code,
            };
            assert_eq!(check(envelope), probe["expected"], "{}", probe["name"]);
            if probe["expected"] == "accepted" {
                let mut altered = envelope.clone();
                let signature = altered["sig"]["value"].as_str().unwrap();
                altered["sig"]["value"] = format!(
                    "{}{}",
                    if signature.starts_with('A') { "B" } else { "A" },
                    &signature[1..]
                )
                .into();
                assert_ne!(check(&altered), "accepted", "{}", probe["name"]);
            }
        }
        assert_eq!(*envelope, original);
    }
}

fn log_key() -> SigningKey {
    SigningKey::from_seed(&std::array::from_fn(|i| i as u8))
}

fn timestamp(at: i64) -> String {
    jiff::Timestamp::from_second(at).unwrap().to_string()
}

fn digest(value: &Value) -> String {
    use sha2::Digest;
    format!(
        "sha256:{}",
        hex_encode(&sha2::Sha256::digest(jcs::canonicalize(value).unwrap()))
    )
}

fn signed_block(prefix: &[Value], at: &str, mut entries: Vec<Value>) -> Value {
    entries.sort_by_key(|entry| {
        let rank = match entry["type"].as_str().unwrap() {
            "publisher_declaration" => 0,
            "registry_update" => 1,
            "publisher_delta" => 2,
            "audit_record" => 3,
            _ => unreachable!(),
        };
        (rank, merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()))
    });
    let leaves: Vec<_> = entries
        .iter()
        .map(|entry| merkle::leaf_hash(&jcs::canonicalize(entry).unwrap()))
        .collect();
    let root = if leaves.is_empty() {
        merkle::leaf_hash(&[])
    } else {
        merkle::merkle_root(&leaves).unwrap()
    };
    let header = json!({"wist_version":"1.0.0", "block_number":prefix.len(),
        "prev_block_hash":prefix.last().map_or("sha256:genesis".into(), |b| digest(&b["header"])),
        "sealed_at":at, "entry_count":entries.len(), "merkle_root":format!("sha256:{}",hex_encode(&root))});
    json!({"sig":{"key_id":"test-log-k1","alg":"Ed25519","value":log_key().sign(&jcs::canonicalize(&header).unwrap())},"header":header,"entries":entries})
}

struct Fixture {
    data: tempfile::TempDir,
    head: Option<BlockRow>,
}

impl Fixture {
    fn new(blocks: &[Value]) -> Self {
        Self::with_key_id(blocks, "test-log-k1")
    }
    fn with_key_id(blocks: &[Value], key_id: &str) -> Self {
        let data = tempfile::tempdir().unwrap();
        let anchor = json!({"wist_version":"1.0.0", "log_id":"log.example.org", "genesis_key":{"key_id":key_id,"alg":"Ed25519","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},"created_at":"2026-08-02T00:00:00Z"});
        let anchor = envelope::sign_envelope(&anchor, "anchor", key_id, &log_key()).unwrap();
        std::fs::write(
            data.path().join("anchor.json"),
            jcs::canonicalize(&anchor).unwrap(),
        )
        .unwrap();
        std::fs::create_dir_all(data.path().join("log/blocks")).unwrap();
        for (height, block) in blocks.iter().enumerate() {
            std::fs::write(
                data.path().join(format!("log/blocks/{height:09}.json.zst")),
                zstd::bulk::compress(&jcs::canonicalize(block).unwrap(), 1).unwrap(),
            )
            .unwrap();
        }
        let head = blocks.last().map(|last| BlockRow {
            block_number: last["header"]["block_number"].as_u64().unwrap(),
            block_hash: block::block_hash(&last["header"]).unwrap(),
            sealed_at: last["header"]["sealed_at"].as_str().unwrap().into(),
        });
        Self { data, head }
    }
    fn head(&self) -> Option<BlockRow> {
        self.head.as_ref().map(|head| BlockRow {
            block_number: head.block_number,
            block_hash: head.block_hash.clone(),
            sealed_at: head.sealed_at.clone(),
        })
    }
    fn reader(&self) -> History {
        History::open(self.data.path(), self.head()).unwrap()
    }
    fn restore(&self) -> clave::error::Result<Declarations> {
        Declarations::reconstruct(self.data.path(), self.head())
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

fn probe(blocks: &[Value], probe: &Value) -> (Declarations, Result<Effects, String>, u64) {
    let height = probe["prefix_height"].as_u64().unwrap() as usize;
    let mut candidate = blocks[..=height].to_vec();
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
    let next = signed_block(
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
            .apply(&history.next_block().unwrap().unwrap())
            .unwrap();
        windows += effects
            .installations
            .iter()
            .filter(|i| i.opens_window)
            .count() as u64;
    }
    let before = format!("{state:?}");
    let result = state
        .apply(&history.next_block().unwrap().unwrap())
        .map_err(|e| e.to_string());
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
        let blocks = case["blocks"].as_array().unwrap();
        let fixture = Fixture::new(blocks);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        let mut sequences = Vec::new();
        let mut windows = 0;
        while let Some(block) = reader.next_block().unwrap() {
            for installation in state.apply(&block).unwrap().installations {
                let declaration = installation.declaration;
                let position = declaration.position();
                assert_eq!(
                    &blocks[position.block_number as usize]["entries"][position.entry_index]
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
            window.owner().position().block_number,
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
        let blocks = branch["blocks"].as_array().unwrap();
        let fixture = Fixture::new(blocks);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        let mut windows = 0;
        while let Some(block) = reader.next_block().unwrap() {
            let effects = state.apply(&block).unwrap();
            windows += effects
                .installations
                .iter()
                .filter(|i| i.opens_window)
                .count() as u64;
            if let Some(expected_states) = branch["expected_prefix_states"].as_array() {
                for expected in expected_states {
                    if expected["height"] == block.block().header.block_number {
                        assert_eq!(
                            summary(&state.domains()["example.com"], windows),
                            expected["state"]
                        );
                    }
                }
            }
        }
        for candidate in branch["probes"].as_array().into_iter().flatten() {
            let selected_blocks = candidate["branch"].as_u64().map_or(blocks, |index| {
                vector["branches"][index as usize]["blocks"]
                    .as_array()
                    .unwrap()
            });
            let (state, result, windows) = probe(selected_blocks, candidate);
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

#[test]
fn conflicting_groups_and_failed_authors_reject_blocks_atomically() {
    let vector = vector("wist1/declaration-conflicts");
    for case in vector["cases"].as_array().unwrap() {
        let mut blocks = vector["prefixes"][case["prefix"].as_str().unwrap()]
            .as_array()
            .unwrap()
            .clone();
        blocks.push(case["block"].clone());
        let fixture = Fixture::new(&blocks);
        let mut history = fixture.reader();
        let mut state = Declarations::default();
        let mut windows = std::collections::BTreeMap::<String, u64>::new();
        while let Some(block) = history.next_block().unwrap() {
            let before = format!("{state:?}");
            match state.apply(&block) {
                Ok(effects) => {
                    for installation in effects.installations {
                        let domain = installation.declaration.envelope()["publisher"]["domain"]
                            .as_str()
                            .unwrap()
                            .to_string();
                        *windows.entry(domain).or_default() += u64::from(installation.opens_window);
                    }
                    if block.block().header.block_number as usize == blocks.len() - 1 {
                        assert!(case["expected_results"]
                            .as_array()
                            .unwrap()
                            .contains(&json!("accepted")));
                    }
                }
                Err(error) => {
                    assert_eq!(block.block().header.block_number as usize, blocks.len() - 1);
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
                    assert!(fixture.restore().is_err());
                }
            }
        }
        let actual:serde_json::Map<_,_>=state.domains().iter().map(|(name,domain)|(name.clone(),json!({"current_envelope":digest(domain.current().envelope()),"recovery_envelope":domain.window().map(|w|digest(w.head().envelope())),"highest_accepted_seq":domain.highest_accepted_seq(),"window_end":domain.window().map(|w|timestamp(w.end_s().try_into().unwrap())),"windows_opened":windows[name],"reset_height":domain.reset().map(|p|p.block_number)}))).collect();
        assert_eq!(
            Value::Object(actual),
            case["expected_state"],
            "{}",
            case["name"]
        );
        assert_eq!(
            state.head().map_or("sha256:genesis", |h| h.1),
            case["expected_accepted_head"]
        );
    }
}

#[test]
fn recovery_competitors_preserve_identity_and_settlement_has_no_reset() {
    for case in vector("wist4/recovery-identity")["cases"]
        .as_array()
        .unwrap()
    {
        let blocks = case["blocks"].as_array().unwrap();
        let fixture = Fixture::new(blocks);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        let mut resets = Vec::new();
        while let Some(block) = reader.next_block().unwrap() {
            for installation in state.apply(&block).unwrap().installations {
                if installation.resets_identity {
                    resets.push(installation.declaration.position().block_number);
                }
            }
        }
        assert_eq!(json!(resets), case["expected_resets"]);
        for candidate in case["probes"].as_array().unwrap() {
            let (state, _, _) = probe(blocks, candidate);
            assert_eq!(
                json!(state.domains()["example.com"]
                    .reset()
                    .map(|p| p.block_number)),
                candidate["expected_reset"]
            );
        }
    }
}

#[test]
fn settlement_restores_authenticated_chain_and_reports_competitors() {
    for case in vector("wist1/recovery-settlement")["cases"]
        .as_array()
        .unwrap()
    {
        let blocks = case["blocks"].as_array().unwrap();
        let fixture = Fixture::new(blocks);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        let mut superseded = Vec::new();
        while let Some(block) = reader.next_block().unwrap() {
            for settlement in state.apply(&block).unwrap().settlements {
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
                blocks[height]["header"]["sealed_at"]
                    .as_str()
                    .unwrap()
                    .parse::<jiff::Timestamp>()
                    .unwrap()
                    .as_second()
                    + 3600,
            )
            .into();
            assert!(probe(blocks, &candidate).1.is_err());
        }
    }
}

#[test]
fn appeal_key_source_tracks_recovery_heads() {
    for case in vector("wist4/recovery-appeals")["cases"]
        .as_array()
        .unwrap()
    {
        let fixture = Fixture::new(case["blocks"].as_array().unwrap());
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        while let Some(block) = reader.next_block().unwrap() {
            state.apply(&block).unwrap();
            for expected in case["expected_authority"].as_array().unwrap() {
                if expected["height"] == block.block().header.block_number {
                    let declaration = state.domains()["example.com"].appeal_declaration();
                    assert_eq!(declaration.hash(), expected["declaration"]);
                    assert_eq!(
                        declaration.envelope()["publisher"]["keys"],
                        expected["keys"]
                    );
                }
            }
        }
    }
}

#[test]
fn reconstruction_requires_complete_pinned_history_and_sequential_application() {
    let vector = vector("wist1/recovery-heads");
    let blocks = vector["blocks"].as_array().unwrap();
    let fixture = Fixture::new(blocks);
    let mut reader = fixture.reader();
    let first = reader.next_block().unwrap().unwrap();
    let second = reader.next_block().unwrap().unwrap();
    let mut state = Declarations::default();
    assert!(state.apply(&second).is_err());
    assert!(state.domains().is_empty());
    state.apply(&first).unwrap();
    assert!(state.apply(&first).is_err());
    state.apply(&second).unwrap();
    assert!(fixture.restore().is_ok());
    let mut wrong_head = fixture.head().unwrap();
    wrong_head.block_hash = "sha256:wrong".into();
    assert!(Declarations::reconstruct(fixture.data.path(), Some(wrong_head)).is_err());
    std::fs::remove_file(
        fixture
            .data
            .path()
            .join(format!("log/blocks/{:09}.json.zst", blocks.len() - 1)),
    )
    .unwrap();
    assert!(fixture.restore().is_err());
}

fn recovery_declaration(previous: Option<&Value>) -> Value {
    let signing = SigningKey::from_seed(&[42; 32]);
    let recovery = SigningKey::from_seed(&[43; 32]);
    let mut publisher = json!({"wist_version":"1.0.0","domain":"example.com","seq":previous.map_or(0,|p|p["publisher"]["seq"].as_u64().unwrap()+1),"keys":[{"key_id":"signing","alg":"Ed25519","public_key":signing.public().to_b64u(),"valid_from":"2026-01-01T00:00:00Z"}],"recovery_keys":[{"key_id":"recovery","alg":"Ed25519","public_key":recovery.public().to_b64u(),"valid_from":"2026-01-01T00:00:00Z"}]});
    if let Some(previous) = previous {
        publisher["prev_declaration"] = digest(&previous["publisher"]).into();
    }
    let (key_id, key) = if previous.is_some() {
        ("recovery", &recovery)
    } else {
        ("signing", &signing)
    };
    envelope::sign_envelope(&publisher, "publisher", key_id, key).unwrap()
}

#[test]
fn authenticated_parameter_schedules_freeze_window_length_at_each_owner() {
    const BASE: i64 = 1_800_000_000;
    for case in vector("wist4/parameter-combinations")["recovery_window_cases"]
        .as_array()
        .unwrap()
    {
        let initial = recovery_declaration(None);
        let mut entries = vec![json!({"type":"publisher_declaration","body":initial})];
        for amendment in case["accepted_amendments"].as_array().unwrap() {
            assert_eq!(amendment["sealed_at_s"], 0);
            let update = json!({"wist_version":"1.0.0","action":"parameter_change","subject":"recovery_window_days","effective_at":timestamp(BASE+amendment["effective_at_s"].as_i64().unwrap()),"details":{"parameter":"recovery_window_days","value":amendment["value"]}});
            entries.push(json!({"type":"registry_update","body":envelope::sign_envelope(&update,"update","test-log-k1",&log_key()).unwrap()}));
        }
        let events = case["eligible_recoveries"].as_array().unwrap();
        let probes = case["probes"].as_array().unwrap();
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
        let mut blocks = Vec::new();
        for (at, entries) in timeline {
            blocks.push(signed_block(&blocks, &timestamp(BASE + at), entries));
        }
        let fixture = Fixture::new(&blocks);
        let mut reader = fixture.reader();
        let mut state = Declarations::default();
        while let Some(block) = reader.next_block().unwrap() {
            assert!(block.rejected_parameters().is_empty());
            state.apply(&block).unwrap();
            let at = block.sealed_at_s() - BASE;
            for event in events.iter().filter(|event| event["sealed_at_s"] == at) {
                let window = state.domains()["example.com"].window().unwrap();
                assert_eq!(
                    window.owner().sealed_at_s(),
                    BASE + event["owner_at_s"].as_i64().unwrap()
                );
                assert_eq!(
                    window.end_s(),
                    i128::from(BASE)
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
        assert_eq!(
            format!("{:?}", fixture.restore().unwrap()),
            format!("{state:?}")
        );
    }
}

#[test]
fn legacy_recovery_owners_require_authenticated_matching_history() {
    let vector = vector("wist1/recovery-bindings");
    for (name, history) in vector["histories"].as_object().unwrap() {
        for mutation in ["none", "opening", "prior", "missing_block", "corrupt_block"] {
            let blocks = history["blocks"].as_array().unwrap();
            let fixture = Fixture::new(blocks);
            let state = fixture.restore().unwrap();
            let window = state.domains()["example.com"].window().unwrap();
            let path = fixture.data.path().join("clave.sqlite");
            let db = clave::db::Db::open(&path).unwrap();
            for block in blocks {
                db.commit_seal(
                    &[],
                    block["header"]["block_number"].as_u64().unwrap(),
                    &digest(&block["header"]),
                    block["header"]["sealed_at"].as_str().unwrap(),
                    &[],
                    &[],
                    &[],
                    &[],
                    jcs::canonicalize(block).unwrap().len() as u64,
                )
                .unwrap();
            }
            db.open_recovery_window(
                "example.com",
                &serde_json::to_vec(window.head().envelope()).unwrap(),
                &serde_json::to_vec(if mutation == "prior" {
                    window.owner().envelope()
                } else {
                    window.before().envelope()
                })
                .unwrap(),
            )
            .unwrap();
            db.activate_recovery_window(
                "example.com",
                if mutation == "opening" { 0 } else { 1 },
                &timestamp(window.end_s().try_into().unwrap()),
            )
            .unwrap();
            drop(db);
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute(
                    "ALTER TABLE recovery_windows DROP COLUMN owner_declaration_json",
                    [],
                )
                .unwrap();
            drop(connection);
            let block_path = fixture.data.path().join("log/blocks/000000001.json.zst");
            if mutation == "missing_block" {
                std::fs::remove_file(&block_path).unwrap();
            } else if mutation == "corrupt_block" {
                std::fs::write(&block_path, b"invalid frame").unwrap();
            }
            let restored = clave::db::Db::open(&path);
            if mutation == "none" {
                let db = restored.unwrap();
                let row = db.get_recovery_window("example.com").unwrap().unwrap();
                assert_eq!(
                    serde_json::from_slice::<Value>(&row.owner_declaration_json).unwrap(),
                    *window.owner().envelope(),
                    "{name}"
                );
                assert_eq!(
                    serde_json::from_slice::<Value>(&row.declaration_json).unwrap(),
                    *window.head().envelope(),
                    "{name}"
                );
                drop(db);
                assert!(clave::db::Db::open(&path).is_ok());
            } else {
                assert!(restored.is_err(), "{name}: {mutation}");
                let connection = rusqlite::Connection::open(&path).unwrap();
                assert!(connection
                    .query_row(
                        "SELECT owner_declaration_json IS NULL FROM recovery_windows",
                        [],
                        |row| row.get::<_, bool>(0)
                    )
                    .unwrap());
            }
        }
    }
}
