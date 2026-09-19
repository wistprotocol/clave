//! Stage 2: fetch. One request under the bound the coordinator computed
//! from the store just before issuing it; the result carries its byte
//! size and holds no store connection.
use crate::error::Error;
use crate::fetch::Client;
use serde_json::Value;

/// Which of a domain's two walks a page belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Walk {
    Feed,
    Label,
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

impl Outcome {
    /// The bytes a metered fetch with this outcome debits.
    pub fn debited(&self) -> u64 {
        match self {
            Outcome::Body { raw, .. } => raw.len() as u64,
            Outcome::Bounded { debited } => *debited,
            Outcome::Failed { .. } => 0,
        }
    }
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
