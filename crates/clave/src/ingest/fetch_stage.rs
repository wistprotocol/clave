use crate::error::Error;
use crate::fetch::Client;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Walk {
    Label,
}

impl Walk {
    pub fn as_str(self) -> &'static str {
        match self {
            Walk::Label => "label",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ObjectKey {
    Declaration,
    Page { feed: Walk, index: u32 },
    Label { id: String },
}

impl ObjectKey {
    pub fn kind(&self) -> &'static str {
        match self {
            ObjectKey::Declaration => "declaration",
            ObjectKey::Page { .. } => "page",
            ObjectKey::Label { .. } => "label",
        }
    }

    pub fn name(&self) -> String {
        match self {
            ObjectKey::Declaration => "periodic".into(),
            ObjectKey::Page { feed, index } => format!("{}:{index}", feed.as_str()),
            ObjectKey::Label { id } => id.clone(),
        }
    }

    pub fn per_attempt(&self) -> bool {
        matches!(self, ObjectKey::Label { .. })
    }
}

pub(super) struct FetchRequest {
    pub url: String,
    pub scope: Vec<String>,
    pub limit: u64,
    pub cap: u64,
    pub metered: bool,
}

pub(super) enum Outcome {
    Body {
        raw: Vec<u8>,
        value: Value,
    },
    /// `debited` is in octets, read up to a bound below the object's own
    /// cap.
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
