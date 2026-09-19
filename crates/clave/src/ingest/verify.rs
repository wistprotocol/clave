//! Stage 3: state-independent verification. Every check here reads only
//! the fetched bytes and the references the coordinator hands in, holds
//! no store connection and returns a bundle of results the coordinator
//! applies in the pull's order.
use crate::declaration::{self, delta::SizeCaps};
use serde_json::Value;
use wist_core::objects::{DeltaEnvelope, FeedEnvelope, Publisher, PublisherEnvelope, PublisherKey};

use super::feed;

/// The Key Set sources one sealed Page resolves through: each applicable
/// Declaration's sealing instant, `seq` and keys.
pub(super) type SealedSources = [(i64, u64, Vec<PublisherKey>)];

/// A recovery window's version: the hashes of its prior, owner and
/// chain-head Declarations and the Epoch it opened at, if it has.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct WindowRef {
    pub prior: String,
    pub owner: String,
    pub head: String,
    pub opened_epoch: Option<i64>,
}

/// The Declaration version a Delta or Label was verified under: the
/// hash and `seq` of the domain's accepted Declaration, its recovery
/// window if one is open, and the admission sources they yield.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct DeclarationRef {
    pub hash: Option<String>,
    pub seq: Option<u64>,
    pub window: Option<WindowRef>,
    pub sources: Vec<Publisher>,
}

impl DeclarationRef {
    /// Whether `other` names the same Declaration version.
    pub fn same_version(&self, other: &DeclarationRef) -> bool {
        self.hash == other.hash && self.seq == other.seq && self.window == other.window
    }
}

/// The references one Delta attempt is issued with: the Declaration
/// version, the size caps and clock allowance of the parameter schedule
/// at the attempt's one clock sample, and the height that schedule was
/// read at.
pub(super) struct IssuedRefs {
    pub decl: DeclarationRef,
    pub sizes: SizeCaps,
    pub clock: jiff::Timestamp,
    pub clock_skew_seconds: i64,
    pub schedule_at: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredRefs {
    decl: DeclarationRef,
    sizes: SizeCaps,
    clock: String,
    clock_skew_seconds: i64,
    schedule_at: Option<u64>,
}

impl IssuedRefs {
    pub fn to_json(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string(&StoredRefs {
            decl: self.decl.clone(),
            sizes: self.sizes.clone(),
            clock: self.clock.to_string(),
            clock_skew_seconds: self.clock_skew_seconds,
            schedule_at: self.schedule_at,
        })?)
    }

    pub fn from_json(json: &str) -> crate::error::Result<Self> {
        let stored: StoredRefs = serde_json::from_str(json)?;
        Ok(IssuedRefs {
            decl: stored.decl,
            sizes: stored.sizes,
            clock: stored
                .clock
                .parse()
                .map_err(|e: jiff::Error| crate::error::Error::Clock(e.to_string()))?,
            clock_skew_seconds: stored.clock_skew_seconds,
            schedule_at: stored.schedule_at,
        })
    }
}

/// A fetched Feed or Label Feed page's field and domain checks, which
/// precede any signature check.
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
    declaration::verify_signed(&keys.iter().collect::<Vec<_>>(), doc, "feed", None).is_ok()
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
        declaration::verify_signed(&keys.iter().collect::<Vec<_>>(), doc, "feed", None).is_ok()
    })
}

/// WIST-2 §3.2 target rule: a read `next` is fetched only when it is
/// byte-identical to its Normalized URL and begins with the requested
/// Canonical Host's well-known prefix. The scheme is re-derived per host
/// so a loopback deployment can follow the https URLs a Publisher writes
/// into sealed pages.
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

/// A first-contact Declaration's checks: WIST-1 §5.1 evaluation, its
/// domain against the pulled host and a first key to record.
pub(super) fn initial_declaration(value: &Value, host: &str) -> Result<Publisher, String> {
    let publisher = declaration::evaluate_initial(value)
        .map_err(|(code, detail)| format!("{code}: {detail}"))?;
    if super::canonical_authority(&publisher.domain).as_deref() != Some(host) {
        return Err("publisher declaration domain does not match ping host".into());
    }
    if publisher.keys.is_empty() {
        return Err("publisher has no keys".into());
    }
    Ok(publisher)
}

/// The facts a Delta file yields once it passed every state-independent
/// check.
pub(super) struct VerifiedDelta {
    pub envelope: DeltaEnvelope,
}

/// Why a Delta file does not decode to an Envelope: canonicalization is a
/// store-independent failure of the whole pull, a decoding failure one of
/// this Delta.
pub(super) enum Undecoded {
    Canonical(wist_core::Error),
    Envelope(String),
}

/// A Delta file's state-independent checks under the size caps and the
/// clock its attempt was issued with, in the order admission applies
/// them. Authority is checked apart, since it reads the admission
/// sources, which a Declaration refresh can change.
pub(super) struct DeltaChecks {
    pub association: Result<(), &'static str>,
    pub static_fields: Result<(), &'static str>,
    pub clock: Result<(), &'static str>,
    pub decoded: Result<VerifiedDelta, Undecoded>,
    pub id: Result<(), String>,
}

pub(super) fn delta(
    doc: &Value,
    host: &str,
    id: &str,
    sizes: &SizeCaps,
    clock: jiff::Timestamp,
    clock_skew_seconds: i64,
) -> DeltaChecks {
    let association = match declaration::delta_publisher(doc) {
        Err(code) => Err(code),
        Ok(domain) if domain != host => Err("WIST2-E03"),
        Ok(_) => Ok(()),
    };
    let decoded = match wist_core::jcs::canonicalize(doc) {
        Err(e) => Err(Undecoded::Canonical(e)),
        Ok(canonical) => serde_json::from_slice::<DeltaEnvelope>(&canonical)
            .map(|envelope| VerifiedDelta { envelope })
            .map_err(|e| Undecoded::Envelope(e.to_string())),
    };
    let id = match wist_core::delta::delta_id(&doc["delta"]) {
        Ok(computed) if computed == id => Ok(()),
        Ok(_) => Err("delta id mismatch".into()),
        Err(e) => Err(e.to_string()),
    };
    DeltaChecks {
        association,
        static_fields: sizes.validate_delta(doc),
        clock: declaration::verify_delta_clock(doc, clock, clock_skew_seconds),
        decoded,
        id,
    }
}

/// WIST-1 §5.1: a Delta's signing and scope authority under the
/// admission sources.
pub(super) fn delta_authority(sources: &[Publisher], doc: &Value) -> Result<(), &'static str> {
    declaration::verify_delta_authority(&sources.iter().collect::<Vec<_>>(), doc)
}

/// WIST-1 §3.6: a Payload against the Delta's commitment and caps.
pub(super) fn payload(
    doc: &Value,
    delta: &DeltaEnvelope,
    sizes: &SizeCaps,
) -> Result<(), &'static str> {
    let Some(commitment) = &delta.delta.payload else {
        return Ok(());
    };
    crate::payload::validate(doc, commitment, &delta.delta.publisher, sizes).map(|_| ())
}

/// Whether a fetched Label Feed file is a Label or a dispute.
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

/// A Label Feed file's state-independent checks: its kind, whether it
/// carries the listed ID and, for a Label, WIST-2 §3.3's validation under
/// the Declaration it was issued with. A dispute's validation reads the
/// sealed Labels and happens at admission.
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
        label: (kind == Some(LabelKind::Label))
            .then(|| label::validate_label(doc, declaration, url_cap_bytes).map(|_| ())),
    }
}
