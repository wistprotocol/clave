use serde_json::Value;
use wist_core::collection::Limits;
use wist_core::crypto::PublicKey;
use wist_core::envelope::{canonical_b64u, verify_envelope};
use wist_core::objects::publisher::thumbprint;
use wist_core::objects::PublisherKey;

pub use wist_core::declaration::{
    disjoint_key_sets, evaluate, evaluate_initial, evaluate_with_heads, follows_chain_head,
    inner_hash, publisher_of, resolve_signer, url_host, url_in_scope, usable_keys, validate_fields,
    Decision, Rejection,
};

/// WIST-2 §3.2: the named entry's key, without the `nbf`/`exp` window.
pub fn verify_signed(keys: &[&PublisherKey], doc: &Value, kind: &str) -> Result<(), &'static str> {
    if !canonical_b64u(doc["sig"]["value"].as_str().ok_or("WIST1-E14")?, 64) {
        return Err("WIST1-E14");
    }
    for key in keys {
        if !canonical_b64u(&key.x, 32) || key.kid != thumbprint(&key.x) {
            return Err("WIST1-E14");
        }
    }
    let key_id = doc["sig"]["key_id"].as_str().unwrap_or_default();
    let mut named = false;
    for key in keys.iter().filter(|key| key.kid == key_id) {
        let Ok(public) = PublicKey::from_b64u(&key.x) else {
            continue;
        };
        named = true;
        if verify_envelope(doc, kind, &public).is_ok() {
            return Ok(());
        }
    }
    if named {
        Err("WIST1-E01")
    } else {
        Err("WIST1-E02")
    }
}

pub fn limits(schedule: &wist_core::parameters::Schedule, at: i64) -> crate::error::Result<Limits> {
    let value = |name| {
        schedule
            .value_at(name, at)
            .ok_or_else(|| crate::error::Error::Param(name.to_string()))
    };
    Ok(Limits::new(
        value("collections_max")?,
        value("scope_entries_max")?,
        value("url_cap_bytes")?,
    )?)
}

pub fn size_caps(
    schedule: &wist_core::parameters::Schedule,
    at: i64,
) -> crate::error::Result<wist_core::item::SizeCaps> {
    let value = |name| {
        schedule
            .value_at(name, at)
            .ok_or_else(|| crate::error::Error::Param(name.to_string()))
    };
    Ok(wist_core::item::SizeCaps::new(
        value("url_cap_bytes")?,
        value("extract_cap_bytes")?,
        value("links_cap_bytes")?,
        value("link_url_cap_bytes")?,
        value("summary_cap_bytes")?,
    )?)
}

pub(crate) fn canonical_encoding(value: &str, length: usize) -> Result<(), String> {
    if canonical_b64u(value, length) {
        Ok(())
    } else {
        Err(format!(
            "expected canonical base64url encoding of {length} octets"
        ))
    }
}
