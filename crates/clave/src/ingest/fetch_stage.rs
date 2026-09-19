//! Stage 2: fetch. One request under the bound the coordinator computed
//! from the store just before issuing it; the result carries its byte
//! size and holds no store connection.
use crate::error::Error;
use crate::fetch::Client;
use serde_json::Value;

/// Why a pull requests `publisher.json`: its initial or periodic
/// discovery, the one retry a failing Feed or Page shares, or the one
/// retry of a Delta's binding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Attempt {
    Periodic,
    Feed,
    Delta(String),
}

/// Which of a domain's two walks a page belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Walk {
    Feed,
    Label,
}

impl Walk {
    pub fn as_str(self) -> &'static str {
        match self {
            Walk::Feed => "feed",
            Walk::Label => "label",
        }
    }
}

/// The object one request fetches. A Declaration or page is fetched at
/// most once per pull; a Delta, Payload, Label or dispute once per
/// attempt of its ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ObjectKey {
    Declaration { attempt: Attempt },
    Page { feed: Walk, index: u32 },
    Delta { id: String },
    Payload { delta_id: String },
    Label { id: String },
}

impl ObjectKey {
    pub fn kind(&self) -> &'static str {
        match self {
            ObjectKey::Declaration { .. } => "declaration",
            ObjectKey::Page { .. } => "page",
            ObjectKey::Delta { .. } => "delta",
            ObjectKey::Payload { .. } => "payload",
            ObjectKey::Label { .. } => "label",
        }
    }

    /// The key's name within its kind; an item's attempts are numbered
    /// apart from it.
    pub fn name(&self) -> String {
        match self {
            ObjectKey::Declaration {
                attempt: Attempt::Periodic,
            } => "periodic".into(),
            ObjectKey::Declaration {
                attempt: Attempt::Feed,
            } => "feed".into(),
            ObjectKey::Declaration {
                attempt: Attempt::Delta(id),
            } => format!("delta:{id}"),
            ObjectKey::Page { feed, index } => format!("{}:{index}", feed.as_str()),
            ObjectKey::Delta { id } | ObjectKey::Label { id } => id.clone(),
            ObjectKey::Payload { delta_id } => delta_id.clone(),
        }
    }

    /// Whether each attempt of the key's ID is a distinct object.
    pub fn per_attempt(&self) -> bool {
        matches!(
            self,
            ObjectKey::Delta { .. } | ObjectKey::Payload { .. } | ObjectKey::Label { .. }
        )
    }
}

pub(super) struct FetchRequest {
    pub url: String,
    /// The Publisher's `subdomain_scope` when the request is issued.
    pub scope: Vec<String>,
    /// The bound the response is read to.
    pub limit: u64,
    /// The object's own response bound.
    pub cap: u64,
    /// Whether the request is debited against the ingest budget.
    pub metered: bool,
}

pub(super) enum Outcome {
    Body {
        raw: Vec<u8>,
        value: Value,
    },
    /// A metered object stopped at a bound below its own cap: the bytes
    /// read up to the bound are debited and the walk suspends.
    Bounded {
        debited: u64,
    },
    Failed {
        detail: String,
    },
}

pub(super) fn fetch(client: &Client, request: &FetchRequest) -> Outcome {
    match client.get_json_bounded(&request.url, &request.scope, request.limit) {
        Ok((raw, value)) => Outcome::Body { raw, value },
        Err(Error::Oversized(_)) if request.metered && request.limit < request.cap => {
            Outcome::Bounded {
                debited: request.limit,
            }
        }
        Err(e) => Outcome::Failed {
            detail: e.to_string(),
        },
    }
}
