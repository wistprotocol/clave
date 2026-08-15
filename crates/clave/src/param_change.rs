use crate::db::Db;
use crate::error::{Error, Result};
use crate::registry;
use crate::WIST_VERSION;
use sha2::{Digest, Sha256};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;

const GENESIS_KEY_ID: &str = "log1";

pub struct ParamChangeReport {
    pub update_id: String,
    pub effective_at: String,
}

fn whole_second(epoch: i64) -> Result<String> {
    Ok(jiff::Timestamp::from_second(epoch)
        .map_err(|_| Error::ParamChange("timestamp out of range".into()))?
        .to_string())
}

pub fn run(
    db: &Db,
    sk: &SigningKey,
    parameter: &str,
    value: i64,
    effective_at: Option<&str>,
    now_epoch: i64,
) -> Result<ParamChangeReport> {
    let now = whole_second(now_epoch)?;
    let lookup = |n: &str| {
        registry::effective(db, n, &now)
            .unwrap_or_else(|_| registry::spec(n).and_then(|s| s.default).unwrap_or(0))
    };
    registry::validate(parameter, value, lookup)?;

    let grace_days = registry::effective(db, "param_grace_days", &now)?;
    let cadence = registry::effective(db, "block_cadence_seconds", &now)?;
    let earliest_epoch = now_epoch + grace_days * 86400;
    let effective_at = match effective_at {
        Some(given) => {
            let ts: jiff::Timestamp = given
                .parse()
                .map_err(|_| Error::ParamChange(format!("unparseable effective_at {given:?}")))?;
            let canonical = whole_second(ts.as_second())?;
            if canonical != given {
                return Err(Error::ParamChange(format!(
                    "effective_at must be whole-second UTC with trailing Z, got {given:?}"
                )));
            }
            if ts.as_second() < earliest_epoch {
                return Err(Error::ParamChange(format!(
                    "effective_at {given} is inside the {grace_days}-day grace period"
                )));
            }
            canonical
        }
        None => whole_second(earliest_epoch + cadence)?,
    };

    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "parameter_change",
        "subject": parameter,
        "details": {"parameter": parameter, "value": value},
        "effective_at": effective_at,
    });
    let update_id = format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(wist_core::jcs::canonicalize(&update)?))
    );
    let envelope = sign_envelope(&update, "update", GENESIS_KEY_ID, sk)?;
    db.insert_pending_entry("registry_update", "", &envelope, 0)?;
    Ok(ParamChangeReport {
        update_id,
        effective_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_770_000_000;

    fn setup() -> (tempfile::TempDir, Db, SigningKey) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        db.set_param("block_cadence_seconds", 3600).unwrap();
        let sk = SigningKey::from_seed(&[9u8; 32]);
        (tmp, db, sk)
    }

    #[test]
    fn run_enqueues_signed_registry_update() {
        let (_tmp, db, sk) = setup();
        let report = run(&db, &sk, "feed_window", 500, None, NOW).unwrap();
        let (pending, _) = db.peek_pending_entries().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].entry_type, "registry_update");
        let doc = &pending[0].entry_json;
        wist_core::envelope::verify_envelope(doc, "update", &sk.public()).unwrap();
        assert_eq!(doc["update"]["action"], "parameter_change");
        assert_eq!(doc["update"]["subject"], "feed_window");
        assert_eq!(doc["update"]["details"]["parameter"], "feed_window");
        assert_eq!(doc["update"]["details"]["value"], 500);
        assert_eq!(doc["update"]["wist_version"], crate::WIST_VERSION);
        assert_eq!(doc["sig"]["key_id"], "log1");
        assert_eq!(
            doc["update"]["effective_at"].as_str().unwrap(),
            report.effective_at
        );
        assert!(report.update_id.starts_with("sha256:"));
    }

    #[test]
    fn run_defaults_effective_at_past_grace_period() {
        let (_tmp, db, sk) = setup();
        let report = run(&db, &sk, "feed_window", 500, None, NOW).unwrap();
        let eff = jiff::Timestamp::from_second(NOW + 7 * 86400)
            .unwrap()
            .to_string();
        assert!(report.effective_at.as_str() >= eff.as_str());
    }

    #[test]
    fn run_rejects_effective_at_inside_grace_period() {
        let (_tmp, db, sk) = setup();
        let too_soon = jiff::Timestamp::from_second(NOW + 86400)
            .unwrap()
            .to_string();
        assert!(run(&db, &sk, "feed_window", 500, Some(&too_soon), NOW).is_err());
    }

    #[test]
    fn run_accepts_explicit_effective_at_past_grace() {
        let (_tmp, db, sk) = setup();
        let later = jiff::Timestamp::from_second(NOW + 30 * 86400)
            .unwrap()
            .to_string();
        let report = run(&db, &sk, "feed_window", 500, Some(&later), NOW).unwrap();
        assert_eq!(report.effective_at, later);
    }

    #[test]
    fn run_rejects_out_of_bounds_value_without_enqueueing() {
        let (_tmp, db, sk) = setup();
        assert!(run(&db, &sk, "block_cadence_seconds", 0, None, NOW).is_err());
        let (pending, _) = db.peek_pending_entries().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn run_rejects_unknown_parameter() {
        let (_tmp, db, sk) = setup();
        assert!(run(&db, &sk, "no_such_param", 1, None, NOW).is_err());
    }

    #[test]
    fn run_rejects_subsecond_effective_at() {
        let (_tmp, db, sk) = setup();
        assert!(run(
            &db,
            &sk,
            "feed_window",
            500,
            Some("2026-12-01T00:00:00.5Z"),
            NOW
        )
        .is_err());
    }
}
