use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] wist_core::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error("system RNG: {0}")]
    Rng(String),
    #[error("key material: {0}")]
    Key(String),
    #[error("unknown param: {0}")]
    Param(String),
    #[error("parameter change: {0}")]
    ParamChange(String),
    #[error("governance: {0}")]
    Governance(String),
    #[error("history: {0}")]
    History(String),
    #[error("fetch: {0}")]
    Fetch(String),
    #[error("fetch: {0}")]
    Oversized(String),
    #[error("Payload: {0}")]
    Payload(&'static str),
    #[error("clock: {0}")]
    Clock(String),
    #[error("instance: {0}")]
    Instance(String),
    #[error("seal: {0}")]
    Seal(String),
    #[error("snapshot: {0}")]
    Snapshot(String),
    #[error("the lease this work ran under was taken over; nothing was written")]
    Fenced,
    #[error("{}", published_ahead(.holder, *.published, *.store_head))]
    PublishedAhead {
        holder: String,
        published: u64,
        store_head: Option<u64>,
    },
    #[error("Mirror {url} could not be confirmed to hold no Checkpoint above the store's head ({reason}); sealing is refused until it answers with one at or below it or with 404")]
    MirrorUnconfirmed { url: String, reason: String },
}

fn published_ahead(holder: &str, published: u64, store_head: Option<u64>) -> String {
    let head = match store_head {
        Some(epoch_number) => format!("Epoch {epoch_number}"),
        None => "no Epoch".to_owned(),
    };
    format!(
        "a Checkpoint of Epoch {published} is published at {holder} that the store, whose head is {head}, does not hold; \
         signing another Checkpoint at or below Epoch {published} would equivocate (WIST-3 §5), so nothing is sealed or published. \
         Restore a backup whose head is at or above Epoch {published}, or end this Log and start a successor Log (WIST-3 §3.4); never seal below the published height"
    )
}

pub type Result<T> = std::result::Result<T, Error>;
