use wist_core::item::SizeCaps;
use wist_core::objects::{PageItem, Payload};

/// WIST-1 §3.6's content caps in force plus room for the salt, the version
/// and the object framing.
pub fn cap_bytes(caps: &SizeCaps) -> u64 {
    caps.extract_cap_bytes() + caps.links_cap_bytes() + caps.summary_cap_bytes() + 4096
}

pub fn judge(item: &PageItem, octets: &[u8], caps: &SizeCaps) -> Result<Payload, &'static str> {
    wist_core::item::judge_payload_octets(item, octets, caps)?;
    let payload = crate::json::parse(octets).map_err(|_| "WIST1-E05")?;
    let canonical = wist_core::jcs::canonicalize(&payload).map_err(|_| "WIST1-E05")?;
    serde_json::from_slice(&canonical).map_err(|_| "WIST1-E14")
}
