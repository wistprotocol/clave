#![forbid(unsafe_code)]

pub mod collection;
pub mod db;
pub mod declaration;
pub mod error;
pub mod fetch;
pub mod governance;
pub mod history;
pub mod ingest;
pub mod init;
mod json;
pub mod keys;
pub mod log_key;
pub mod mirrors;
pub mod param_change;
pub mod payload;
pub mod publication;
pub mod quota;
pub mod recovery;
pub mod registry;
pub mod scheduler;
pub mod seal;
pub mod serve;
pub mod snapshot;
pub mod suffix_list;
pub mod witness;

pub use error::Error;

pub const WIST_VERSION: &str = "1.0.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wist_version_matches_spec_example() {
        let dir = std::env::var("WIST_SPEC_DIR").unwrap_or_else(|_| "../../../spec".into());
        let catalog: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(&dir).join("examples/catalog.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(catalog["catalog"]["wist_version"], WIST_VERSION);
    }
}
