use crate::db::{Db, GenesisAmendment};
use crate::error::{Error, Result};
use crate::WIST_VERSION;
use sha2::{Digest, Sha256};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamChangeReport {
    Queued {
        update_id: String,
        effective_at: String,
    },
    Genesis {
        effective_at: Option<String>,
    },
}

pub fn check_genesis(amendments: &[GenesisAmendment]) -> Result<()> {
    for amendment in amendments {
        let value_of = |name: &str| {
            amendments
                .iter()
                .filter(|other| {
                    other.parameter == name && other.effective_at <= amendment.effective_at
                })
                .max_by(|a, b| a.effective_at.cmp(&b.effective_at))
                .map(|other| other.value)
                .or_else(|| crate::registry::spec(name).and_then(|spec| spec.default))
                .unwrap_or_default()
        };
        crate::registry::validate(&amendment.parameter, amendment.value, value_of)
            .map_err(|e| Error::ParamChange(format!("{}: {e}", amendment.parameter)))?;
    }
    Ok(())
}

pub fn record_genesis(db: &Db, amendment: &GenesisAmendment) -> Result<()> {
    let mut amendments: Vec<GenesisAmendment> = db
        .genesis_amendments()?
        .into_iter()
        .filter(|recorded| {
            recorded.parameter != amendment.parameter
                || recorded.effective_at != amendment.effective_at
        })
        .collect();
    amendments.push(amendment.clone());
    check_genesis(&amendments)?;
    db.record_genesis_amendment(amendment)
}

fn whole_second(unix: i64) -> Result<String> {
    Ok(jiff::Timestamp::from_second(unix)
        .map_err(|_| Error::ParamChange("timestamp out of range".into()))?
        .to_string())
}

fn whole_second_instant(given: &str) -> Result<i64> {
    let ts: jiff::Timestamp = given
        .parse()
        .map_err(|_| Error::ParamChange(format!("unparseable effective_at {given:?}")))?;
    if whole_second(ts.as_second())? != given {
        return Err(Error::ParamChange(format!(
            "effective_at must be whole-second UTC with trailing Z, got {given:?}"
        )));
    }
    Ok(ts.as_second())
}

pub fn run(
    db: &Db,
    sk: &SigningKey,
    parameter: &str,
    value: i64,
    effective_at: Option<&str>,
    now_unix: i64,
) -> Result<ParamChangeReport> {
    if db.last_epoch()?.is_none() {
        if let Some(given) = effective_at {
            whole_second_instant(given)?;
        }
        let amendment = GenesisAmendment {
            parameter: parameter.to_owned(),
            value,
            effective_at: effective_at.map(str::to_owned),
        };
        record_genesis(db, &amendment)?;
        return Ok(ParamChangeReport::Genesis {
            effective_at: amendment.effective_at,
        });
    }
    let schedule = db.parameter_schedule(now_unix)?;
    let grace_days = schedule.value_at("param_grace_days", now_unix).unwrap();
    let cadence = schedule
        .value_at("epoch_cadence_seconds", now_unix)
        .unwrap();
    let earliest_unix = i128::from(now_unix) + i128::from(grace_days) * 86400;
    let effective_at = match effective_at {
        Some(given) => {
            if i128::from(whole_second_instant(given)?) < earliest_unix {
                return Err(Error::ParamChange(format!(
                    "effective_at {given} is inside the {grace_days}-day grace period"
                )));
            }
            given.to_owned()
        }
        None => whole_second(
            i64::try_from(earliest_unix + i128::from(cadence))
                .map_err(|_| Error::ParamChange("effective_at out of range".into()))?,
        )?,
    };

    let update = serde_json::json!({
        "wist_version": WIST_VERSION,
        "action": "parameter_change",
        "subject": parameter,
        "details": {"parameter": parameter, "value": value},
        "effective_at": effective_at,
    });
    crate::seal::validate_pending_parameter(db, &update, sk, now_unix)?;
    let update_id = format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(wist_core::jcs::canonicalize(&update)?))
    );
    let envelope = sign_envelope(&update, "update", &db.signing_key_id(&sk.public())?, sk)?;
    db.insert_pending_entry("registry_update", "", &envelope, 0)?;
    Ok(ParamChangeReport::Queued {
        update_id,
        effective_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_770_000_000;

    fn unsealed() -> (tempfile::TempDir, Db, SigningKey) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        let sk = SigningKey::from_seed(&[9u8; 32]);
        (tmp, db, sk)
    }

    fn setup() -> (tempfile::TempDir, Db, SigningKey) {
        let (tmp, db, sk) = unsealed();
        crate::db::tests::seal_epoch(&db, 0, &crate::registry::instant(NOW - 3600).unwrap(), &[]);
        (tmp, db, sk)
    }

    fn queued(report: ParamChangeReport) -> (String, String) {
        match report {
            ParamChangeReport::Queued {
                update_id,
                effective_at,
            } => (update_id, effective_at),
            ParamChangeReport::Genesis { .. } => panic!("recorded as a genesis amendment"),
        }
    }

    #[test]
    fn run_enqueues_signed_registry_update() {
        let (_tmp, db, sk) = setup();
        let (update_id, effective_at) =
            queued(run(&db, &sk, "feed_window", 500, None, NOW).unwrap());
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
            effective_at
        );
        assert!(update_id.starts_with("sha256:"));
    }

    #[test]
    fn run_defaults_effective_at_past_grace_period() {
        let (_tmp, db, sk) = setup();
        let (_, effective_at) = queued(run(&db, &sk, "feed_window", 500, None, NOW).unwrap());
        let eff = jiff::Timestamp::from_second(NOW + 7 * 86400)
            .unwrap()
            .to_string();
        assert!(effective_at.as_str() >= eff.as_str());
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
        let (_, effective_at) =
            queued(run(&db, &sk, "feed_window", 500, Some(&later), NOW).unwrap());
        assert_eq!(effective_at, later);
    }

    #[test]
    fn run_rejects_out_of_bounds_value_without_enqueueing() {
        let (_tmp, db, sk) = setup();
        assert!(run(&db, &sk, "epoch_cadence_seconds", 0, None, NOW).is_err());
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

    #[test]
    fn run_before_epoch_0_records_a_genesis_amendment_without_queueing() {
        let (_tmp, db, sk) = unsealed();
        assert_eq!(
            run(&db, &sk, "epoch_cadence_seconds", 900, None, NOW).unwrap(),
            ParamChangeReport::Genesis { effective_at: None }
        );
        assert_eq!(
            db.genesis_amendments().unwrap(),
            [GenesisAmendment::at_genesis("epoch_cadence_seconds", 900)]
        );
        assert!(db.peek_pending_entries().unwrap().0.is_empty());
    }

    #[test]
    fn a_genesis_amendment_at_a_recorded_instant_replaces_it_and_another_instant_adds_one() {
        let (_tmp, db, sk) = unsealed();
        run(&db, &sk, "feed_window", 500, None, NOW).unwrap();
        run(&db, &sk, "feed_window", 600, None, NOW).unwrap();
        let later = crate::registry::instant(NOW + 86_400).unwrap();
        assert_eq!(
            run(&db, &sk, "feed_window", 700, Some(&later), NOW).unwrap(),
            ParamChangeReport::Genesis {
                effective_at: Some(later.clone())
            }
        );
        assert_eq!(
            db.genesis_amendments().unwrap(),
            [
                GenesisAmendment::at_genesis("feed_window", 600),
                GenesisAmendment {
                    parameter: "feed_window".into(),
                    value: 700,
                    effective_at: Some(later)
                }
            ]
        );
    }

    #[test]
    fn a_genesis_amendment_out_of_bounds_or_against_another_is_refused() {
        let (_tmp, db, sk) = unsealed();
        assert!(run(&db, &sk, "epoch_cadence_seconds", 0, None, NOW).is_err());
        run(&db, &sk, "labeler_epoch_entries_max", 200, None, NOW).unwrap();
        assert!(run(&db, &sk, "domain_epoch_entries_max", 150, None, NOW).is_err());
        assert!(run(
            &db,
            &sk,
            "feed_window",
            500,
            Some("2026-12-01T00:00:00.5Z"),
            NOW
        )
        .is_err());
        assert_eq!(
            db.genesis_amendments().unwrap(),
            [GenesisAmendment::at_genesis(
                "labeler_epoch_entries_max",
                200
            )]
        );
    }

    #[test]
    fn a_genesis_amendment_after_epoch_0_is_refused() {
        let (_tmp, db, _sk) = setup();
        assert!(record_genesis(&db, &GenesisAmendment::at_genesis("feed_window", 500)).is_err());
        assert!(db.genesis_amendments().unwrap().is_empty());
    }
}
