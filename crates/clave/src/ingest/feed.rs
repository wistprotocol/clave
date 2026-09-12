use serde_json::Value;
use wist_core::objects::FeedEnvelope;

pub(super) fn validate_fields(doc: &Value) -> Result<FeedEnvelope, &'static str> {
    wist_core::jcs::canonicalize(doc).map_err(|_| "Feed cannot be canonicalized")?;
    let envelope: FeedEnvelope =
        serde_json::from_value(doc.clone()).map_err(|_| "Feed Envelope fields are invalid")?;
    let feed = &envelope.feed;
    let version = &feed.wist_version;
    if version.split('.').count() != 3
        || version.split('.').any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err("Feed version spelling is invalid");
    }
    if !wist_core::host::canonical_host(&feed.domain)
        .is_ok_and(|canonical| canonical == feed.domain)
    {
        return Err("Feed domain is not a Canonical Host");
    }
    crate::registry::epoch(&feed.generated_at).map_err(|_| "Feed timestamp is invalid")?;
    let mut ids = std::collections::HashSet::new();
    if feed.deltas.len() > 1000
        || feed.deltas.iter().any(|id| {
            !id.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }) || !ids.insert(id)
        })
    {
        return Err("Feed Delta IDs are invalid, repeated or exceed 1000 entries");
    }
    if feed
        .next
        .as_ref()
        .is_some_and(|next| !next.starts_with("https://") || next.contains('#'))
    {
        return Err("Feed next field is invalid");
    }
    if envelope.sig.key_id.chars().count() > 64 || envelope.sig.alg != "Ed25519" {
        return Err("Feed signature fields are invalid");
    }
    crate::declaration::canonical_encoding(&envelope.sig.value, 64)
        .map_err(|_| "Feed signature encoding is invalid")?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_field_vectors_preserve_the_original_envelope() {
        let root = std::env::var_os("WIST_SPEC_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
            });
        let vector: Value = serde_json::from_slice(
            &std::fs::read(root.join("vectors/wist2/feed-fields.json")).unwrap(),
        )
        .unwrap();
        let publisher = crate::declaration::publisher_of(&vector["declaration"]).unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let original = case["envelope"].clone();
            let result = validate_fields(&original);
            assert_eq!(
                result.is_ok(),
                case["expected"] != "fields",
                "{}",
                case["name"]
            );
            if let Ok(parsed) = result {
                if case["expected"] == "accepted" {
                    let cut = crate::registry::epoch(&parsed.feed.generated_at).unwrap();
                    assert!(super::super::verify_sealed_page(
                        &[(cut, 0, publisher.keys.clone())],
                        &original,
                        &parsed.feed.generated_at,
                    ));
                }
                assert_eq!(serde_json::to_value(parsed).unwrap(), original);
            }
            assert_eq!(original, case["envelope"]);
        }
    }
}
