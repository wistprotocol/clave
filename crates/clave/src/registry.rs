use crate::error::{Error, Result};
pub use wist_core::parameters::{spec, ParamSpec, PARAMS};

pub fn effective(db: &crate::db::Db, name: &str, at: &str) -> Result<i64> {
    if let Some(v) = db.latest_param_change(name, at)? {
        return Ok(v);
    }
    match db.param(name) {
        Ok(v) => Ok(v),
        Err(Error::Param(_)) => spec(name)
            .and_then(|s| s.default)
            .ok_or_else(|| Error::Param(name.to_string())),
        Err(e) => Err(e),
    }
}

pub fn validate(name: &str, value: i64, lookup: impl Fn(&str) -> i64) -> Result<()> {
    wist_core::parameters::validate(name, value, lookup)
        .map_err(|err| Error::ParamChange(err.to_string()))
}

pub use wist_core::timestamp::LOG_TIMESTAMP_MIN_S;

/// The whole-second UTC spelling of an instant anywhere in the Log's
/// four-digit-year range, the inverse of `epoch`.
pub fn instant(epoch_s: i64) -> Result<String> {
    wist_core::timestamp::instant(epoch_s).map_err(|e| Error::ParamChange(e.to_string()))
}

pub(crate) fn epoch(at: &str) -> Result<i64> {
    wist_core::timestamp::log_seconds(at).map_err(|e| Error::ParamChange(e.to_string()))
}

pub(crate) fn accept(
    schedule: &mut wist_core::parameters::Schedule,
    amendment: wist_core::parameters::Amendment,
    largest_block: u64,
) -> Result<()> {
    schedule
        .try_accept_with_block_size(amendment, largest_block)
        .map_err(|e| Error::ParamChange(format!("WIST4-E03 {e}")))
}

pub(crate) fn block_cap(schedule: &wist_core::parameters::Schedule, at: i64) -> i64 {
    schedule.block_size_bounds(at).0 as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_round_trip_across_the_whole_log_range() {
        for (seconds, spelled) in [
            (LOG_TIMESTAMP_MIN_S, "0000-01-01T00:00:00Z"),
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (253_402_214_400, "9999-12-31T00:00:00Z"),
            (
                wist_core::parameters::LOG_TIMESTAMP_MAX_S,
                "9999-12-31T23:59:59Z",
            ),
        ] {
            assert_eq!(instant(seconds).unwrap(), spelled);
            assert_eq!(epoch(spelled).unwrap(), seconds);
        }
        assert!(instant(LOG_TIMESTAMP_MIN_S - 1).is_err());
        assert!(instant(wist_core::parameters::LOG_TIMESTAMP_MAX_S + 1).is_err());
    }

    fn defaults(name: &str) -> i64 {
        spec(name).unwrap().default.unwrap()
    }

    #[test]
    fn log_timestamp_vectors_reject_leap_seconds_without_normalization() {
        let dir = std::env::var("WIST_SPEC_DIR").unwrap_or_else(|_| "../../../spec".into());
        let vector: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(&dir).join("vectors/wist3/timestamps.json"))
                .unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let at = case["value"].as_str().unwrap();
            assert_eq!(epoch(at).ok(), case["epoch_seconds"].as_i64(), "{at:?}");
        }
        for case in vector["distances"].as_array().unwrap() {
            assert_eq!(
                epoch(case["to"].as_str().unwrap()).unwrap()
                    - epoch(case["from"].as_str().unwrap()).unwrap(),
                case["seconds"].as_i64().unwrap()
            );
        }
    }

    #[test]
    fn validate_rejects_unknown_identifier() {
        assert!(validate("no_such_param", 1, defaults).is_err());
    }

    #[test]
    fn validate_rejects_value_below_fixed_floor() {
        assert!(validate("block_cadence_seconds", 0, defaults).is_err());
    }

    #[test]
    fn validate_rejects_value_above_fixed_ceiling() {
        assert!(validate("block_cadence_seconds", 86401, defaults).is_err());
    }

    #[test]
    fn validate_accepts_in_range_value() {
        validate("block_cadence_seconds", 2700, defaults).unwrap();
    }

    #[test]
    fn validate_accepts_unbounded_parameter() {
        validate("clock_skew_seconds", 0, defaults).unwrap();
    }

    #[test]
    fn validate_rejects_links_cap_below_link_url_cap_plus_21() {
        assert!(validate("links_cap_bytes", 2000, defaults).is_err());
    }

    #[test]
    fn validate_rejects_retired_identifiers() {
        for name in [
            "sampling_floor",
            "similarity_consistent",
            "shingle_size",
            "quota_slope",
        ] {
            assert!(matches!(
                validate(name, 1, defaults),
                Err(Error::ParamChange(_))
            ));
        }
    }

    #[test]
    fn validate_checks_every_combination_participant_at_its_boundary() {
        for (name, accepted, rejected) in [
            ("links_cap_bytes", 2069, 2068),
            ("link_url_cap_bytes", 4075, 4076),
            ("payload_window_days", 540, 541),
            ("mirror_retention_days", 30, 29),
        ] {
            validate(name, accepted, defaults).unwrap();
            assert!(
                matches!(
                    validate(name, rejected, defaults),
                    Err(Error::ParamChange(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn validate_preserves_wire_bounds_and_exact_intermediate_arithmetic() {
        let max = wist_core::parameters::WIRE_INTEGER_MAX;
        validate("links_cap_bytes", max, defaults).unwrap();
        assert!(validate("links_cap_bytes", max + 1, defaults).is_err());
        validate("clock_skew_seconds", -max, defaults).unwrap();
        assert!(validate("clock_skew_seconds", -max - 1, defaults).is_err());
        for name in ["link_url_cap_bytes", "payload_window_days"] {
            assert!(validate(name, max, defaults).is_err(), "{name}");
        }
    }

    #[test]
    fn effective_prefers_change_then_param_row_then_default() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert_eq!(
            effective(&db, "feed_window", "2026-01-01T00:00:00Z").unwrap(),
            1000
        );
        db.set_param("feed_window", 700).unwrap();
        assert_eq!(
            effective(&db, "feed_window", "2026-01-01T00:00:00Z").unwrap(),
            700
        );
        db.commit_seal(
            &[],
            0,
            "sha256:h0",
            "2026-01-01T00:00:00Z",
            &[],
            &[crate::db::ParamChangeRow {
                entry_index: 0,
                parameter: "feed_window",
                value: 500,
                effective_at: "2026-01-10T00:00:00Z",
            }],
            &[],
            &[],
            &[],
            0,
        )
        .unwrap();
        assert_eq!(
            effective(&db, "feed_window", "2026-01-09T00:00:00Z").unwrap(),
            700
        );
        assert_eq!(
            effective(&db, "feed_window", "2026-01-10T00:00:00Z").unwrap(),
            500
        );
    }

    #[test]
    fn effective_without_spec_or_row_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(effective(&db, "no_such_param", "2026-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn spec_knows_every_schema_identifier_with_matching_bounds() {
        let dir = std::env::var("WIST_SPEC_DIR").unwrap_or_else(|_| "../../../spec".into());
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(&dir).join("schemas/registry-update.schema.json"))
                .unwrap(),
        )
        .unwrap();
        let clauses = schema["allOf"].as_array().unwrap();
        let param_clause = clauses
            .iter()
            .find(|c| {
                c["if"]["properties"]["update"]["properties"]["action"]["const"]
                    == "parameter_change"
            })
            .unwrap();
        let details = &param_clause["then"]["properties"]["update"]["properties"]["details"];
        let idents: Vec<&str> = details["properties"]["parameter"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for ident in &idents {
            assert!(spec(ident).is_some(), "missing identifier {ident}");
        }
        for s in PARAMS {
            assert!(
                idents.contains(&s.name),
                "{} is not amendable in the schema",
                s.name
            );
        }
        for clause in details["allOf"].as_array().unwrap() {
            let ident = clause["if"]["properties"]["parameter"]["const"]
                .as_str()
                .unwrap();
            let bounds = &clause["then"]["properties"]["value"];
            let s = spec(ident).unwrap();
            assert_eq!(s.min, bounds["minimum"].as_i64(), "min mismatch {ident}");
            assert_eq!(s.max, bounds["maximum"].as_i64(), "max mismatch {ident}");
        }
    }
}
