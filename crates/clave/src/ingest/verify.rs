use crate::declaration;
use serde_json::Value;
use wist_core::objects::{FeedEnvelope, Publisher, PublisherEnvelope, PublisherKey};

use super::feed;

pub(super) type SealedSources = [(i64, u64, Vec<PublisherKey>)];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct WindowRef {
    pub prior: String,
    pub owner: String,
    pub head: String,
    pub opened_epoch: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct DeclarationRef {
    pub hash: Option<String>,
    pub seq: Option<u64>,
    pub window: Option<WindowRef>,
    pub sources: Vec<Publisher>,
}

impl DeclarationRef {
    pub fn same_version(&self, other: &DeclarationRef) -> bool {
        self.hash == other.hash && self.seq == other.seq && self.window == other.window
    }
}

pub(super) struct IssuedRefs {
    pub decl: DeclarationRef,
    pub clock: jiff::Timestamp,
    pub clock_skew_seconds: i64,
    pub schedule_at: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredRefs {
    decl: DeclarationRef,
    clock: String,
    clock_skew_seconds: i64,
    schedule_at: Option<u64>,
}

impl IssuedRefs {
    pub fn to_json(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string(&StoredRefs {
            decl: self.decl.clone(),
            clock: self.clock.to_string(),
            clock_skew_seconds: self.clock_skew_seconds,
            schedule_at: self.schedule_at,
        })?)
    }

    pub fn clock_floor_s(&self) -> i64 {
        let seconds = self.clock.as_second();
        if self.clock.subsec_nanosecond() < 0 {
            seconds - 1
        } else {
            seconds
        }
    }

    pub fn from_json(json: &str) -> crate::error::Result<Self> {
        let stored: StoredRefs = serde_json::from_str(json)?;
        Ok(IssuedRefs {
            decl: stored.decl,
            clock: stored
                .clock
                .parse()
                .map_err(|e: jiff::Error| crate::error::Error::Clock(e.to_string()))?,
            clock_skew_seconds: stored.clock_skew_seconds,
            schedule_at: stored.schedule_at,
        })
    }
}

pub(super) struct PageChecks {
    pub fields: Result<FeedEnvelope, &'static str>,
    pub domain_matches: bool,
}

pub(super) fn page(doc: &Value, host: &str) -> PageChecks {
    let fields = feed::validate_fields(doc);
    let domain_matches = fields
        .as_ref()
        .is_ok_and(|parsed| parsed.feed.domain == host);
    PageChecks {
        fields,
        domain_matches,
    }
}

/// WIST-2 §5: a live Feed verifies under the keys of the Declaration the
/// Aggregator holds.
pub(super) fn live_page(keys: &[PublisherKey], doc: &Value) -> bool {
    declaration::verify_signed(&keys.iter().collect::<Vec<_>>(), doc, "feed").is_ok()
}

/// WIST-2 §3.2: a sealed Page verifies under the Declaration current at
/// its `generated_at` or, failing that, the first one sealed after it.
pub(super) fn sealed_page(declarations: &SealedSources, doc: &Value, generated_at: &str) -> bool {
    let Ok(cut) = crate::registry::unix(generated_at) else {
        return false;
    };
    let current = declarations
        .iter()
        .filter(|(at, _, _)| *at <= cut)
        .max_by_key(|(at, seq, _)| (*at, *seq));
    let next = declarations
        .iter()
        .filter(|(at, _, _)| *at > cut)
        .min_by_key(|(at, seq, _)| (*at, std::cmp::Reverse(*seq)));
    current.into_iter().chain(next).any(|(_, _, keys)| {
        declaration::verify_signed(&keys.iter().collect::<Vec<_>>(), doc, "feed").is_ok()
    })
}

/// WIST-2 §3.2 target rule. The scheme is re-derived per host so a loopback
/// deployment can follow the https URLs a Publisher writes into sealed
/// pages.
pub(super) fn next_page_url(next: &str, host: &str, allow_http: bool) -> Option<String> {
    let prefix = format!("https://{host}/.well-known/wist/");
    if !next.starts_with(&prefix)
        || wist_core::extract::normalize_url(next, next).as_deref() != Some(next)
    {
        return None;
    }
    let scheme = crate::fetch::scheme_for_host(host, allow_http);
    Some(format!(
        "{scheme}://{host}{}",
        &next["https://".len() + host.len()..]
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LabelKind {
    Label,
    Dispute,
}

impl LabelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LabelKind::Label => "label",
            LabelKind::Dispute => "dispute",
        }
    }
}

/// WIST-2 §3.3 validation for a Label; a dispute's reads the sealed Labels
/// and happens at admission.
pub(super) struct LabelChecks {
    pub kind: Option<LabelKind>,
    pub id_matches: bool,
    pub label: Option<Result<(), wist_core::label::Rejection>>,
}

pub(super) fn label(
    doc: &Value,
    id: &str,
    declaration: &PublisherEnvelope,
    url_cap_bytes: i64,
    attempt: &IssuedRefs,
) -> LabelChecks {
    use wist_core::label;
    let (kind, computed) = if doc.get("label").is_some() {
        (Some(LabelKind::Label), label::label_id(&doc["label"]))
    } else if doc.get("dispute").is_some() {
        (Some(LabelKind::Dispute), label::dispute_id(&doc["dispute"]))
    } else {
        return LabelChecks {
            kind: None,
            id_matches: false,
            label: None,
        };
    };
    LabelChecks {
        kind,
        id_matches: computed.as_deref() == Ok(id),
        label: (kind == Some(LabelKind::Label)).then(|| {
            label::validate_label(
                doc,
                declaration,
                url_cap_bytes,
                attempt.clock_floor_s(),
                attempt.clock_skew_seconds,
            )
            .map(|_| ())
        }),
    }
}
