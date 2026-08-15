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
    #[error("fetch: {0}")]
    Fetch(String),
    #[error("seal: {0}")]
    Seal(String),
    #[error("snapshot: {0}")]
    Snapshot(String),
}

pub type Result<T> = std::result::Result<T, Error>;
