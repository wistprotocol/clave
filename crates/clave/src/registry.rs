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

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults(name: &str) -> i64 {
        spec(name).unwrap().default.unwrap()
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
    fn validate_rejects_sampling_ceiling_below_floor() {
        assert!(validate("sampling_ceiling", 100_000, defaults).is_err());
    }

    #[test]
    fn validate_rejects_similarity_consistent_at_variance_floor() {
        assert!(validate("similarity_consistent", 300_000, defaults).is_err());
    }

    #[test]
    fn validate_rejects_half_confirm_window_longer_than_coverage_deadline() {
        assert!(validate("confirm_window_hours", 200, defaults).is_err());
        assert!(validate("coverage_deadline_hours", 35, defaults).is_err());
        assert!(validate("coverage_deadline_hours", 36, defaults).is_ok());
    }

    #[test]
    fn validate_rejects_c_cap_below_provisional_audits() {
        assert!(validate("c_cap", 9, defaults).is_err());
    }

    #[test]
    fn validate_rejects_confirm_window_shorter_than_cadence() {
        assert!(validate("block_cadence_seconds", 86400, |n| match n {
            "confirm_window_hours" => 12,
            other => defaults(other),
        })
        .is_err());
    }

    #[test]
    fn validate_rejects_half_confirm_window_shorter_than_cadence() {
        assert!(validate("confirm_window_hours", 3, |n| match n {
            "block_cadence_seconds" => 7200,
            other => defaults(other),
        })
        .is_err());
    }

    #[test]
    fn validate_rejects_mirror_retention_below_appeal_span_sum() {
        assert!(validate("ruling_deadline_days", 80, defaults).is_err());
    }

    #[test]
    fn validate_rejects_links_cap_below_link_url_cap_plus_21() {
        assert!(validate("links_cap_bytes", 2000, defaults).is_err());
    }

    #[test]
    fn validate_rejects_link_variance_floor_at_agreement_consistent() {
        assert!(validate("link_variance_floor", 600_000, defaults).is_err());
    }

    #[test]
    fn validate_rejects_retired_identifiers() {
        for name in [
            "contradictions_max",
            "escalation_l2",
            "escalation_l3",
            "escalation_l4",
        ] {
            assert!(matches!(
                validate(name, 1, defaults),
                Err(Error::ParamChange(_))
            ));
        }
    }

    #[test]
    fn validate_checks_every_canary_combination_participant_at_its_boundary() {
        for (name, accepted, rejected) in [
            ("block_cadence_seconds", 2700, 2699),
            ("block_cadence_seconds", 5400, 5401),
            ("confirm_window_hours", 47, 46),
            ("record_seal_blocks", 36, 37),
            ("coverage_deadline_hours", 96, 97),
            ("epoch_blocks", 36, 37),
            ("canary_reveal_min_blocks", 144, 143),
            ("canary_reveal_min_blocks", 1415, 1416),
            ("canary_lead_blocks", 1271, 1272),
            ("canary_lifetime_blocks", 193, 192),
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
        let lookup = |name: &str| match name {
            "confirm_window_hours" => 96,
            other => defaults(other),
        };
        validate("record_seal_blocks", 48, lookup).unwrap();
        assert!(validate("record_seal_blocks", 49, lookup).is_err());
    }

    #[test]
    fn validate_preserves_wire_bounds_and_exact_intermediate_arithmetic() {
        let max = wist_core::parameters::WIRE_INTEGER_MAX;
        validate("canary_leaves_max", max, defaults).unwrap();
        assert!(validate("canary_leaves_max", max + 1, defaults).is_err());
        validate("clock_skew_seconds", -max, defaults).unwrap();
        assert!(validate("clock_skew_seconds", -max - 1, defaults).is_err());
        for name in [
            "epoch_blocks",
            "canary_reveal_min_blocks",
            "record_seal_blocks",
        ] {
            assert!(validate(name, max, defaults).is_err(), "{name}");
        }
    }

    #[test]
    fn observer_and_canary_defaults_match_vectors_and_work_without_database_rows() {
        let dir = std::env::var("WIST_SPEC_DIR").unwrap_or_else(|_| "../../../spec".into());
        let vector: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(&dir).join("vectors/wist4/canary.json")).unwrap(),
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        for name in [
            "epoch_blocks",
            "observer_checkpoint_budget",
            "canary_lead_blocks",
            "canary_leaves_max",
            "canary_commitments_max",
            "canary_reveal_min_blocks",
            "canary_lifetime_blocks",
        ] {
            let expected = vector["parameters"][name].as_i64().unwrap();
            assert_eq!(defaults(name), expected, "{name}");
            assert_eq!(
                effective(&db, name, "2026-01-01T00:00:00Z").unwrap(),
                expected,
                "{name}"
            );
            validate(name, expected, defaults).unwrap();
            assert!(
                validate(name, spec(name).unwrap().min.unwrap() - 1, defaults).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn validate_rejects_audit_budget_below_single_audit_cost() {
        assert!(validate("audit_domain_budget_bytes_day", 8_000_000, defaults).is_err());
    }

    #[test]
    fn validate_accepts_combination_rule_at_exact_boundary() {
        validate("mirror_retention_days", 51, defaults).unwrap();
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
                parameter: "feed_window",
                value: 500,
                effective_at: "2026-01-10T00:00:00Z",
            }],
            &[],
            &[],
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
