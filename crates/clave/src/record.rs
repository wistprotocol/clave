use serde_json::Value;
use wist_core::{crypto::PublicKey, envelope, jcs};

pub struct RecordEnvelope {
    envelope: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldValidation {
    non_evidence_valid: bool,
    evidence_valid: bool,
    supported_major: bool,
}

impl FieldValidation {
    pub fn diagnostic(self) -> Option<&'static str> {
        if !self.non_evidence_valid {
            Some("WIST4-E09")
        } else if !self.evidence_valid {
            Some("WIST4-E02")
        } else {
            None
        }
    }

    pub fn supported_major(self) -> bool {
        self.supported_major
    }

    pub fn non_evidence_valid(self) -> bool {
        self.non_evidence_valid
    }

    pub fn evidence_valid(self) -> bool {
        self.evidence_valid
    }
}

pub struct SigningBinding<'a> {
    pub auditor_id: &'a str,
    pub key_id: &'a str,
    pub public_key: &'a PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duty {
    Absent,
    Active,
    RemovedAfterAnchor,
}

pub struct ReplayContext<'a> {
    pub signing: Option<SigningBinding<'a>>,
    pub duty: Duty,
    pub coverage_failure: bool,
    pub semantic_evidence_error: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disposition {
    pub diagnostic: Option<&'static str>,
    pub discharges_coverage: bool,
}

impl RecordEnvelope {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        let envelope = crate::json::parse(raw).map_err(|_| "WIST1-E05")?;
        jcs::canonicalize(&envelope).map_err(|_| "WIST1-E05")?;
        Ok(Self { envelope })
    }

    pub(crate) fn from_included(envelope: &Value) -> Self {
        Self {
            envelope: envelope.clone(),
        }
    }

    pub fn envelope(&self) -> &Value {
        &self.envelope
    }

    pub fn fields(&self) -> FieldValidation {
        FieldValidation {
            non_evidence_valid: non_evidence_fields_valid(&self.envelope),
            evidence_valid: evidence_fields_valid(&self.envelope),
            supported_major: self
                .envelope
                .pointer("/record/wist_version")
                .and_then(Value::as_str)
                .is_some_and(|version| release(version) && version.split('.').next() == Some("1")),
        }
    }

    pub fn disposition(&self, context: &ReplayContext<'_>) -> Disposition {
        let fields = self.fields();
        let authentic = fields.non_evidence_valid
            && context.signing.as_ref().is_some_and(|binding| {
                self.envelope["record"]["auditor_id"] == binding.auditor_id
                    && self.envelope["sig"]["key_id"] == binding.key_id
                    && envelope::verify_envelope(&self.envelope, "record", binding.public_key)
                        .is_ok()
            });
        let discharges_coverage = fields.non_evidence_valid
            && fields.supported_major
            && authentic
            && context.duty != Duty::Absent;
        let diagnostic = fields.diagnostic().or_else(|| {
            if !fields.supported_major {
                Some("WIST4-E10")
            } else if !authentic || context.duty != Duty::Active || context.coverage_failure {
                Some("WIST4-E01")
            } else if context.semantic_evidence_error {
                Some("WIST4-E02")
            } else {
                None
            }
        });
        Disposition {
            diagnostic,
            discharges_coverage,
        }
    }
}

fn object(value: &Value, required: &[&str], optional: &[&str]) -> bool {
    value.as_object().is_some_and(|map| {
        required.iter().all(|key| map.contains_key(*key))
            && map
                .keys()
                .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
    })
}

pub(crate) fn release(version: &str) -> bool {
    version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn hash(value: &Value, prefix: &str) -> bool {
    value
        .as_str()
        .and_then(|value| value.strip_prefix(prefix))
        .is_some_and(|value| hex(value, 64))
}

pub(crate) fn hostname_subject(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn non_evidence_fields_valid(envelope: &Value) -> bool {
    if !object(envelope, &["record", "sig"], &[]) {
        return false;
    }
    let body = &envelope["record"];
    let sig = &envelope["sig"];
    object(
        body,
        &[
            "wist_version",
            "audited_delta",
            "auditor_id",
            "vrf_proof",
            "prev_record",
        ],
        &[
            "reference_delta",
            "fetched_at",
            "verdict",
            "response_commitment",
            "credit_commitment",
            "ref_extract_commitment",
            "evidence_commitment",
            "similarity",
            "link_agreement",
            "robots_excluded",
            "unmeasured",
        ],
    ) && body["wist_version"].as_str().is_some_and(release)
        && hash(&body["audited_delta"], "sha256:")
        && body["auditor_id"].as_str().is_some_and(hostname_subject)
        && body["vrf_proof"]
            .as_str()
            .is_some_and(|value| hex(value, 160))
        && (body["prev_record"].is_null() || hash(&body["prev_record"], "sha256:"))
        && object(sig, &["key_id", "alg", "value"], &[])
        && sig["key_id"]
            .as_str()
            .is_some_and(|value| value.chars().count() <= 64)
        && sig["alg"] == "Ed25519"
        && sig["value"].as_str().is_some_and(|value| {
            wist_core::crypto::b64u_decode(value).is_ok_and(|bytes| {
                bytes.len() == 64 && wist_core::crypto::b64u_encode(&bytes) == value
            })
        })
}

pub(crate) fn evidence_fields_valid(envelope: &Value) -> bool {
    let body = &envelope["record"];
    let Some(verdict) = body["verdict"].as_str() else {
        return false;
    };
    let measured = match verdict {
        "consistent" | "dynamic_variance" | "inconsistent" | "link_variance"
        | "link_inconsistent" => true,
        "unreachable" | "not_auditable" => false,
        _ => return false,
    };
    for field in [
        "response_commitment",
        "credit_commitment",
        "ref_extract_commitment",
        "evidence_commitment",
    ] {
        match body.get(field) {
            Some(value) if measured => {
                if !hash(value, "hmac-sha256:") {
                    return false;
                }
            }
            None if !measured => {}
            _ => return false,
        }
    }
    let micro = |value: &Value| {
        value
            .as_f64()
            .is_some_and(|n| (0.0..=1_000_000.0).contains(&n) && n.fract() == 0.0)
    };
    if body.get("similarity").is_some_and(micro) != measured
        || (!measured && body.get("similarity").is_some())
        || body
            .get("link_agreement")
            .is_some_and(|value| !measured || !micro(value))
        || (matches!(verdict, "link_variance" | "link_inconsistent")
            && body.get("link_agreement").is_none())
        || body
            .get("robots_excluded")
            .is_some_and(|value| verdict != "unreachable" || value != true)
    {
        return false;
    }
    if !hash(&body["reference_delta"], "sha256:")
        || !body["fetched_at"]
            .as_str()
            .is_some_and(|at| crate::registry::epoch(at).is_ok())
    {
        return false;
    }
    match body.get("unmeasured") {
        Some(value) => {
            verdict == "not_auditable" && matches!(value.as_str(), Some("observed" | "reference"))
        }
        None => verdict != "not_auditable",
    }
}
