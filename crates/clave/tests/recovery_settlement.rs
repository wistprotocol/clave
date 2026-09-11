use clave::declaration::{evaluate, evaluate_initial, inner_hash, Decision};
use serde_json::Value;
use wist_core::crypto::PublicKey;

#[test]
fn authenticated_settlement_declarations_and_rejection_twins() {
    let path = std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
        .join("vectors/wist1/recovery-settlement.json");
    let vector: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let key = PublicKey::from_b64u(vector["log_key"]["public_key"].as_str().unwrap()).unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut current: Option<Value> = None;
        let mut chain: Option<Value> = None;
        let mut floor = 0;
        let mut previous_block = "sha256:genesis".to_string();
        let mut prefixes = Vec::new();
        let mut superseded = Vec::new();
        for (height, block) in case["blocks"].as_array().unwrap().iter().enumerate() {
            wist_core::block::verify_block(block, &key).unwrap();
            assert_eq!(block["header"]["block_number"], height, "{name}");
            assert_eq!(block["header"]["prev_block_hash"], previous_block, "{name}");
            previous_block = wist_core::block::block_hash(&block["header"]).unwrap();
            if height == 169 {
                current = chain.take();
            }
            for entry in block["entries"].as_array().unwrap() {
                let incoming = &entry["body"];
                if current.is_none() {
                    evaluate_initial(incoming).unwrap();
                } else {
                    assert!(incoming["publisher"]["seq"].as_u64().unwrap() > floor);
                    let previous = current
                        .iter()
                        .chain(chain.iter())
                        .find(|env| {
                            inner_hash(env).unwrap() == incoming["publisher"]["prev_declaration"]
                        })
                        .expect("eligible named predecessor");
                    let decision = evaluate(previous, incoming).unwrap();
                    if chain.is_some() {
                        if Some(previous) == chain.as_ref()
                            && matches!(decision, Decision::Ordinary | Decision::Recovery)
                        {
                            chain = Some(incoming.clone());
                        } else {
                            superseded.push(inner_hash(incoming).unwrap());
                        }
                    } else if decision == Decision::Recovery {
                        assert_eq!(height, 1);
                        chain = Some(incoming.clone());
                    }
                }
                floor = incoming["publisher"]["seq"].as_u64().unwrap();
                current = Some(incoming.clone());
            }
            prefixes.push((current.clone().unwrap(), chain.clone(), floor));
        }
        assert_eq!(previous_block, case["pinned_head"], "{name}");
        assert_eq!(
            inner_hash(current.as_ref().unwrap()).unwrap(),
            case["expected"]["effective_declaration"],
            "{name}"
        );
        assert_eq!(
            serde_json::to_value(superseded).unwrap(),
            case["expected"]["superseded"],
            "{name}"
        );
        for probe in case["probes"].as_array().unwrap() {
            let (current, chain, floor) =
                &prefixes[probe["prefix_height"].as_u64().unwrap() as usize];
            let candidate = &probe["candidate"];
            let previous = std::iter::once(current)
                .chain(chain.iter())
                .find(|env| inner_hash(env).unwrap() == candidate["publisher"]["prev_declaration"]);
            let result = if candidate["publisher"]["seq"].as_u64().unwrap() <= *floor {
                "WIST1-E08"
            } else if let Some(previous) = previous {
                evaluate(previous, candidate).unwrap_err().0
            } else {
                "WIST1-E08"
            };
            assert_eq!(
                result, probe["expected_result"],
                "{name}: {}",
                probe["name"]
            );
        }
    }
}
