use crate::error::{Error, Result};

pub struct ParamSpec {
    pub name: &'static str,
    pub default: Option<i64>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

const fn p(
    name: &'static str,
    default: Option<i64>,
    min: Option<i64>,
    max: Option<i64>,
) -> ParamSpec {
    ParamSpec {
        name,
        default,
        min,
        max,
    }
}

pub const PARAMS: &[ParamSpec] = &[
    p("block_cadence_seconds", Some(3600), Some(1), Some(86400)),
    p(
        "block_decompressed_cap_bytes",
        Some(268_435_456),
        Some(1024),
        None,
    ),
    p("extract_cap_bytes", Some(32768), Some(2), None),
    p("summary_cap_bytes", Some(2048), Some(12), None),
    p("feed_window", Some(1000), Some(1), None),
    p("clock_skew_seconds", Some(600), None, None),
    p("baseline_poll_seconds", Some(86400), None, None),
    p("keyset_cache_ttl_seconds", Some(86400), None, None),
    p("recovery_window_days", Some(7), Some(1), None),
    p("sampling_floor", Some(200_000), Some(1), None),
    p("sampling_ceiling", Some(5_000_000), Some(1), None),
    p("sampling_slope", Some(3), None, None),
    p(
        "similarity_consistent",
        Some(600_000),
        Some(150_002),
        Some(1_000_000),
    ),
    p(
        "similarity_variance_floor",
        Some(300_000),
        Some(150_001),
        Some(300_000),
    ),
    p("shingle_size", Some(8), Some(1), None),
    p("confirm_auditors", Some(2), Some(2), None),
    p("confirm_window_hours", Some(72), Some(1), None),
    p("coverage_deadline_hours", Some(72), Some(1), None),
    p("age_norm_days", Some(730), Some(1), None),
    p("decay_constant_days", Some(180), Some(1), None),
    p("decay_horizon_days", Some(1825), Some(1), None),
    p("penalty_weight", Some(5), Some(1), None),
    p("c_cap", Some(500), Some(1), None),
    p("provisional_age_days", Some(30), None, None),
    p("provisional_audits", Some(10), None, None),
    p("provisional_cap_u", Some(100_000), None, None),
    p("quota_base", Some(100), None, None),
    p("quota_slope", Some(10000), None, None),
    p("latency_threshold_u", Some(500_000), None, None),
    p("escalation_l2", None, None, None),
    p("escalation_l3", None, None, None),
    p("escalation_l4", None, None, None),
    p("appeal_window_days", Some(14), Some(1), None),
    p("ruling_deadline_days", Some(30), Some(1), None),
    p("param_grace_days", Some(7), Some(1), None),
    p("payload_window_days", Some(180), Some(30), None),
    p("unauditable_horizon_days", Some(30), Some(7), None),
    p("mirror_retention_days", Some(90), Some(51), None),
    p("appeal_seal_days", Some(7), Some(1), None),
    p("url_cap_bytes", Some(2048), Some(14), None),
    p("links_cap_bytes", Some(4096), Some(21), None),
    p("link_url_cap_bytes", Some(2048), Some(14), None),
    p(
        "link_agreement_consistent",
        Some(600_000),
        Some(2),
        Some(1_000_000),
    ),
    p("link_variance_floor", Some(300_000), Some(1), Some(999_999)),
    p("warc_retention_days", Some(90), Some(51), None),
    p("record_seal_blocks", Some(24), Some(1), None),
    p("domain_block_entries_max", Some(10000), Some(1), None),
    p("max_inclusion_blocks", Some(4), Some(1), None),
    p(
        "ingest_budget_bytes_day",
        Some(1_073_741_824),
        Some(1_048_576),
        None,
    ),
    p("min_observed_words", Some(40), Some(1), None),
    p("extension_triggers_max", Some(3), Some(1), None),
    p("contradictions_max", Some(2), Some(1), None),
    p("audit_fetch_cap_bytes", Some(8_388_608), Some(65536), None),
    p(
        "audit_domain_budget_bytes_day",
        Some(1_073_741_824),
        None,
        None,
    ),
    p("audit_redirect_max", Some(5), Some(1), None),
    p("audit_fetch_timeout_seconds", Some(30), Some(1), None),
];

pub fn spec(name: &str) -> Option<&'static ParamSpec> {
    PARAMS.iter().find(|s| s.name == name)
}

type EffLookup<'a> = &'a dyn Fn(&str) -> i64;

struct ComboRule {
    participants: &'static [&'static str],
    description: &'static str,
    holds: fn(EffLookup) -> bool,
}

const COMBO_RULES: &[ComboRule] = &[
    ComboRule {
        participants: &["sampling_floor", "sampling_ceiling"],
        description: "sampling_ceiling must not be below sampling_floor",
        holds: |eff| eff("sampling_ceiling") >= eff("sampling_floor"),
    },
    ComboRule {
        participants: &["similarity_consistent", "similarity_variance_floor"],
        description: "similarity_consistent must be greater than similarity_variance_floor",
        holds: |eff| eff("similarity_consistent") > eff("similarity_variance_floor"),
    },
    ComboRule {
        participants: &["c_cap", "provisional_audits"],
        description: "c_cap must not be below provisional_audits",
        holds: |eff| eff("c_cap") >= eff("provisional_audits"),
    },
    ComboRule {
        participants: &["confirm_window_hours", "block_cadence_seconds"],
        description: "confirm_window_hours must not be shorter than block_cadence_seconds",
        holds: |eff| eff("confirm_window_hours") * 3600 >= eff("block_cadence_seconds"),
    },
    ComboRule {
        participants: &["coverage_deadline_hours", "block_cadence_seconds"],
        description: "coverage_deadline_hours must not be shorter than block_cadence_seconds",
        holds: |eff| eff("coverage_deadline_hours") * 3600 >= eff("block_cadence_seconds"),
    },
    ComboRule {
        participants: &["confirm_window_hours", "block_cadence_seconds"],
        description: "confirm_window_hours / 2 must not be shorter than block_cadence_seconds",
        holds: |eff| (eff("confirm_window_hours") / 2) * 3600 >= eff("block_cadence_seconds"),
    },
    ComboRule {
        participants: &[
            "mirror_retention_days",
            "appeal_window_days",
            "appeal_seal_days",
            "ruling_deadline_days",
        ],
        description: "mirror_retention_days must not be below appeal_window_days + appeal_seal_days + ruling_deadline_days",
        holds: |eff| {
            eff("mirror_retention_days")
                >= eff("appeal_window_days") + eff("appeal_seal_days") + eff("ruling_deadline_days")
        },
    },
    ComboRule {
        participants: &["links_cap_bytes", "link_url_cap_bytes"],
        description: "links_cap_bytes must not be below link_url_cap_bytes + 21",
        holds: |eff| eff("links_cap_bytes") >= eff("link_url_cap_bytes") + 21,
    },
    ComboRule {
        participants: &["link_variance_floor", "link_agreement_consistent"],
        description: "link_variance_floor must be below link_agreement_consistent",
        holds: |eff| eff("link_variance_floor") < eff("link_agreement_consistent"),
    },
    ComboRule {
        participants: &["contradictions_max", "extension_triggers_max"],
        description: "contradictions_max must be below extension_triggers_max",
        holds: |eff| eff("contradictions_max") < eff("extension_triggers_max"),
    },
    ComboRule {
        participants: &[
            "audit_domain_budget_bytes_day",
            "audit_fetch_cap_bytes",
            "extract_cap_bytes",
            "links_cap_bytes",
            "summary_cap_bytes",
        ],
        description: "audit_domain_budget_bytes_day must cover audit_fetch_cap_bytes + extract_cap_bytes + links_cap_bytes + summary_cap_bytes + 32",
        holds: |eff| {
            eff("audit_domain_budget_bytes_day")
                >= eff("audit_fetch_cap_bytes")
                    + eff("extract_cap_bytes")
                    + eff("links_cap_bytes")
                    + eff("summary_cap_bytes")
                    + 32
        },
    },
];

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
    let s = spec(name)
        .ok_or_else(|| Error::ParamChange(format!("unknown parameter identifier {name:?}")))?;
    if s.min.is_some_and(|min| value < min) || s.max.is_some_and(|max| value > max) {
        return Err(Error::ParamChange(format!(
            "{name} = {value} is outside the WIST-4 \u{a7}9 bounds table"
        )));
    }
    let eff = |n: &str| if n == name { value } else { lookup(n) };
    for rule in COMBO_RULES {
        if rule.participants.contains(&name) && !(rule.holds)(&eff) {
            return Err(Error::ParamChange(format!(
                "{name} = {value} violates: {}",
                rule.description
            )));
        }
    }
    Ok(())
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
        validate("block_cadence_seconds", 60, defaults).unwrap();
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
    fn validate_rejects_contradictions_max_at_extension_triggers_max() {
        assert!(validate("contradictions_max", 3, defaults).is_err());
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
            0,
            0,
            "sha256:h0",
            "2026-01-01T00:00:00Z",
            &[],
            &[crate::db::ParamChangeRow {
                parameter: "feed_window",
                value: 500,
                effective_at: "2026-01-10T00:00:00Z",
            }],
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
    fn effective_without_default_or_row_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        assert!(effective(&db, "escalation_l2", "2026-01-01T00:00:00Z").is_err());
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
