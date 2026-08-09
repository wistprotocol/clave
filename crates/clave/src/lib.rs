#![forbid(unsafe_code)]

pub mod db;
pub mod error;
pub mod fetch;
pub mod ingest;
pub mod init;
pub mod keys;

pub use error::Error;

pub const WIST_VERSION: &str = "1.0.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wist_version_matches_spec_example() {
        let dir = std::env::var("WIST_SPEC_DIR").unwrap_or_else(|_| "../../../spec".into());
        let delta: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(&dir).join("examples/delta.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(delta["delta"]["wist_version"], WIST_VERSION);
    }
}
