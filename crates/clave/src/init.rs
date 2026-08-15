use crate::db::Db;
use crate::error::Result;
use crate::keys;
use crate::WIST_VERSION;
use std::path::Path;
use wist_core::envelope::sign_envelope;
use wist_core::objects::{Anchor, GenesisKey};

const GENESIS_KEY_ID: &str = "log1";

pub fn run(log_id: &str, data_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;

    let (seed, sk) = keys::generate();
    keys::save_seed(&data_dir.join("keys/seed"), &seed)?;

    let public_key = keys::public_b64u(&seed);
    let created_at = jiff::Timestamp::from_second(jiff::Timestamp::now().as_second())
        .expect("current epoch second is in range")
        .to_string();

    let anchor = Anchor {
        wist_version: WIST_VERSION.into(),
        log_id: log_id.into(),
        genesis_key: GenesisKey {
            key_id: GENESIS_KEY_ID.into(),
            alg: "Ed25519".into(),
            public_key,
        },
        created_at,
        predecessor: None,
    };

    let inner = serde_json::to_value(&anchor)?;
    let envelope = sign_envelope(&inner, "anchor", GENESIS_KEY_ID, &sk)?;
    let bytes = serde_json::to_vec(&envelope)?;
    std::fs::write(data_dir.join("anchor.json"), bytes)?;

    for dir in ["log/blocks", "log/checkpoints", "payloads", "snapshots"] {
        std::fs::create_dir_all(data_dir.join(dir))?;
    }

    let db = Db::open(&data_dir.join("clave.sqlite"))?;
    for spec in crate::registry::PARAMS {
        if let Some(default) = spec.default {
            db.set_param(spec.name, default)?;
        }
    }

    Ok(())
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
        for d in ["log/blocks", "log/checkpoints", "payloads", "snapshots"] {
            assert!(tmp.path().join(d).is_dir());
        }
        let db = crate::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert_eq!(db.param("block_cadence_seconds").unwrap(), 3600);
    }

    #[test]
    fn init_seeds_every_registry_default() {
        let tmp = tempfile::tempdir().unwrap();
        run("example.com", tmp.path()).unwrap();
        let db = crate::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        for spec in crate::registry::PARAMS {
            if let Some(default) = spec.default {
                assert_eq!(db.param(spec.name).unwrap(), default, "{}", spec.name);
            }
        }
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
