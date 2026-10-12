use crate::db::Db;
use crate::error::{Error, Result};
use crate::keys;
use crate::WIST_VERSION;
use std::path::Path;
use wist_core::envelope::sign_envelope;
use wist_core::objects::{Anchor, GenesisKey};

pub fn run(log_id: &str, data_dir: &Path) -> Result<String> {
    run_with(log_id, data_dir, &[])
}

pub fn run_with(log_id: &str, data_dir: &Path, genesis: &[(String, i64)]) -> Result<String> {
    for (index, (parameter, _)) in genesis.iter().enumerate() {
        if genesis[..index]
            .iter()
            .any(|(earlier, _)| earlier == parameter)
        {
            return Err(Error::ParamChange(format!(
                "{parameter} is given more than once"
            )));
        }
    }
    let genesis: Vec<crate::db::GenesisAmendment> = genesis
        .iter()
        .map(|(parameter, value)| crate::db::GenesisAmendment::at_genesis(parameter, *value))
        .collect();
    crate::param_change::check_genesis(&genesis)?;
    std::fs::create_dir_all(data_dir)?;

    let (seed, sk) = keys::generate();
    keys::save_seed(&data_dir.join("keys/seed"), &seed)?;

    let public_key = keys::public_b64u(&seed);
    let created_at = jiff::Timestamp::from_second(jiff::Timestamp::now().as_second())
        .expect("current Unix second is in range")
        .to_string();

    let anchor = Anchor {
        wist_version: WIST_VERSION.into(),
        log_id: log_id.into(),
        genesis_key: GenesisKey {
            key_id: keys::GENESIS_KEY_ID.into(),
            alg: "Ed25519".into(),
            public_key,
        },
        created_at,
        predecessor: None,
    };

    let inner = serde_json::to_value(&anchor)?;
    let envelope = sign_envelope(&inner, "anchor", keys::GENESIS_KEY_ID, &sk)?;
    let bytes = serde_json::to_vec(&envelope)?;
    std::fs::write(data_dir.join("anchor.json"), bytes)?;

    for dir in [
        "log/checkpoints",
        "log/suffix-lists",
        "tile/entries",
        "payloads",
        "snapshots",
    ] {
        std::fs::create_dir_all(data_dir.join(dir))?;
    }

    let db = Db::open(&data_dir.join("clave.sqlite"))?;
    for amendment in &genesis {
        db.record_genesis_amendment(amendment)?;
    }
    let verifier_key = wist_core::checkpoint::verifier_key(log_id, &sk.public());
    db.admit_aggregator_key(
        &wist_core::crypto::hex_encode(&wist_core::checkpoint::aggregator_key_id(
            log_id,
            &sk.public(),
        )),
        keys::GENESIS_KEY_ID,
        &keys::public_b64u(&seed),
        0,
    )?;

    Ok(verifier_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_verifiable_anchor_and_layout() {
        let tmp = tempfile::tempdir().unwrap();
        run("127.0.0.1:8080", tmp.path()).unwrap();
        let sk = crate::keys::load(&tmp.path().join("keys/seed")).unwrap();
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.path().join("anchor.json")).unwrap())
                .unwrap();
        wist_core::envelope::verify_envelope(&doc, "anchor", &sk.public()).unwrap();
        let parsed: wist_core::objects::LogAnchorEnvelope = serde_json::from_value(doc).unwrap();
        assert_eq!(parsed.anchor.log_id, "127.0.0.1:8080");
        for d in ["log/checkpoints", "tile/entries", "payloads", "snapshots"] {
            assert!(tmp.path().join(d).is_dir());
        }
        let db = crate::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(db.genesis_amendments().unwrap().is_empty());
    }

    #[test]
    fn init_records_genesis_amendments_and_no_local_parameter_value() {
        let tmp = tempfile::tempdir().unwrap();
        run_with(
            "example.com",
            tmp.path(),
            &[
                ("epoch_cadence_seconds".into(), 900),
                ("feed_window".into(), 500),
            ],
        )
        .unwrap();
        let db = crate::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert_eq!(
            db.genesis_amendments().unwrap(),
            [
                crate::db::GenesisAmendment::at_genesis("epoch_cadence_seconds", 900),
                crate::db::GenesisAmendment::at_genesis("feed_window", 500)
            ]
        );
        for spec in crate::registry::PARAMS {
            assert!(db.param(spec.name).is_err(), "{}", spec.name);
        }
    }

    #[test]
    fn init_refuses_a_repeated_genesis_parameter_before_writing_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("log");
        assert!(run_with(
            "example.com",
            &data,
            &[("feed_window".into(), 500), ("feed_window".into(), 600)],
        )
        .is_err());
        assert!(!data.exists());
    }

    #[test]
    fn init_sets_genesis_key_id_log1() {
        let tmp = tempfile::tempdir().unwrap();
        run("example.com", tmp.path()).unwrap();
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.path().join("anchor.json")).unwrap())
                .unwrap();
        assert_eq!(doc["anchor"]["genesis_key"]["key_id"], "log1");
        assert_eq!(doc["sig"]["key_id"], "log1");
    }

    #[cfg(unix)]
    #[test]
    fn init_sets_seed_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        run("example.com", tmp.path()).unwrap();
        let mode = std::fs::metadata(tmp.path().join("keys/seed"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
