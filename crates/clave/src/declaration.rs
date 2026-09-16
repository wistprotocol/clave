use serde_json::Value;

pub mod delta;
mod time;

pub use wist_core::declaration::{
    delta_publisher, disjoint_key_sets, evaluate, evaluate_initial, evaluate_with_heads,
    follows_chain_head, inner_hash, publisher_of, resolve_signer, url_host, url_in_scope,
    usable_keys, validate_fields, verify_delta_authority, verify_delta_predecessor, verify_signed,
    Decision, Rejection,
};
pub use wist_core::delta_fields::verify_observation_order;

pub fn verify_delta_clock(
    doc: &Value,
    clock: jiff::Timestamp,
    allowance_s: i64,
) -> Result<(), &'static str> {
    let observed_at = doc["delta"]["observed_at"].as_str().ok_or("WIST1-E14")?;
    match time::within_clock_bound(observed_at, clock, allowance_s) {
        Some(true) => Ok(()),
        Some(false) => Err("WIST1-E06"),
        None => Err("WIST1-E14"),
    }
}

pub(crate) fn canonical_encoding(value: &str, length: usize) -> Result<(), String> {
    if wist_core::delta_fields::canonical_b64u(value, length) {
        Ok(())
    } else {
        Err(format!(
            "expected canonical base64url encoding of {length} octets"
        ))
    }
}
