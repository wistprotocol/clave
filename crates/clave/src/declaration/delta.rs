use serde_json::Value;

fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, &'static str> {
    let map = value.as_object().ok_or("WIST1-E14")?;
    if required.iter().any(|key| !map.contains_key(*key))
        || map
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("WIST1-E14");
    }
    Ok(map)
}

fn string(value: &Value) -> Result<&str, &'static str> {
    value.as_str().ok_or("WIST1-E14")
}

fn hash(value: &Value, prefix: &str) -> bool {
    value
        .as_str()
        .and_then(|s| s.strip_prefix(prefix))
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub fn validate_fields(doc: &Value) -> Result<(), &'static str> {
    wist_core::jcs::canonicalize(doc).map_err(|_| "WIST1-E05")?;
    object(doc, &["delta", "sig"], &[])?;
    let body = &doc["delta"];
    object(
        body,
        &[
            "wist_version",
            "publisher",
            "url",
            "change_type",
            "observed_at",
            "meta",
        ],
        &["prev", "payload"],
    )?;
    let version = string(&body["wist_version"])?;
    if version.split('.').count() != 3
        || version.split('.').any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err("WIST1-E14");
    }
    wist_core::delta::publisher(body).map_err(|_| "WIST1-E14")?;
    string(&body["url"])?;
    if !super::time::valid(string(&body["observed_at"])?) {
        return Err("WIST1-E14");
    }
    let kind = string(&body["change_type"])?;
    if !["new", "update", "delete", "attest"].contains(&kind)
        || body.get("prev").is_some_and(|v| !hash(v, "sha256:"))
    {
        return Err("WIST1-E14");
    }
    if let Some(payload) = body.get("payload") {
        object(payload, &["commitment", "alg", "bytes"], &[])?;
        if !["new", "update"].contains(&kind)
            || !hash(&payload["commitment"], "hmac-sha256:")
            || payload["alg"] != "HMAC-SHA256"
            || !payload["bytes"].as_f64().is_some_and(|n| {
                n.is_finite() && (0.0..=9_007_199_254_740_991.0).contains(&n) && n.fract() == 0.0
            })
        {
            return Err("WIST1-E14");
        }
    }
    let meta = &body["meta"];
    object(meta, &["lang"], &["topics", "license"])?;
    let mut parts = string(&meta["lang"])?.split('-');
    let primary = parts.next().unwrap_or_default();
    if !(2..=3).contains(&primary.len())
        || !primary.bytes().all(|b| b.is_ascii_lowercase())
        || parts.any(|part| {
            !(1..=8).contains(&part.len()) || !part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
    {
        return Err("WIST1-E14");
    }
    if let Some(topics) = meta.get("topics") {
        let topics = topics.as_array().ok_or("WIST1-E14")?;
        if topics.len() > 10
            || topics
                .iter()
                .any(|v| !v.as_str().is_some_and(|s| s.chars().count() <= 64))
        {
            return Err("WIST1-E14");
        }
    }
    if meta
        .get("license")
        .is_some_and(|v| !v.as_str().is_some_and(|s| s.chars().count() <= 64))
    {
        return Err("WIST1-E14");
    }
    let sig = &doc["sig"];
    object(sig, &["key_id", "alg", "value"], &[])?;
    if string(&sig["key_id"])?.chars().count() > 64 || sig["alg"] != "Ed25519" {
        return Err("WIST1-E14");
    }
    super::canonical_encoding(string(&sig["value"])?, 64).map_err(|_| "WIST1-E14")?;
    Ok(())
}

pub fn validate_static(
    doc: &Value,
    url_cap: i64,
    commitment_cap: i128,
) -> Result<(), &'static str> {
    validate_fields(doc)?;
    let body = &doc["delta"];
    if let Some(payload) = body.get("payload") {
        if payload["bytes"].as_f64().unwrap() as i128 > commitment_cap {
            return Err("WIST1-E04");
        }
    } else if matches!(body["change_type"].as_str(), Some("new" | "update")) {
        return Err("WIST1-E09");
    }
    if body["change_type"] != "new" && body.get("prev").is_none() {
        return Err("WIST1-E07");
    }
    if wist_core::jcs::canonicalize(&body["url"])
        .map_err(|_| "WIST1-E05")?
        .len() as i128
        > i128::from(url_cap)
    {
        return Err("WIST1-E11");
    }
    Ok(())
}
