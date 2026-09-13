use serde_json::Value;
use std::collections::HashSet;
use wist_core::objects::PayloadLinks;

mod json;
pub use json::validate as validate_json;

fn object(value: &Value, required: &[&str], optional: &[&str]) -> Result<(), &'static str> {
    let map = value.as_object().ok_or("WIST1-E14")?;
    if required.iter().any(|key| !map.contains_key(*key))
        || map
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("WIST1-E14");
    }
    Ok(())
}

pub fn validate_fields(payload: &Value) -> Result<(), &'static str> {
    wist_core::jcs::canonicalize(payload).map_err(|_| "WIST1-E05")?;
    object(payload, &["wist_version", "salt", "content"], &[])?;
    let version = payload["wist_version"].as_str().ok_or("WIST1-E14")?;
    if version.split('.').count() != 3
        || version.split('.').any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err("WIST1-E14");
    }
    let salt = payload["salt"].as_str().ok_or("WIST1-E14")?;
    let decoded = wist_core::crypto::b64u_decode(salt).map_err(|_| "WIST1-E14")?;
    if decoded.len() < 16 || wist_core::crypto::b64u_encode(&decoded) != salt {
        return Err("WIST1-E14");
    }
    let content = &payload["content"];
    object(content, &["extract", "links", "summary"], &[])?;
    content["extract"].as_str().ok_or("WIST1-E14")?;
    let links = &content["links"];
    object(links, &["total", "urls"], &[])?;
    if !links["total"].as_f64().is_some_and(|n| {
        n.is_finite() && (0.0..=9_007_199_254_740_991.0).contains(&n) && n.fract() == 0.0
    }) || links["urls"]
        .as_array()
        .ok_or("WIST1-E14")?
        .iter()
        .any(|url| !url.is_string())
    {
        return Err("WIST1-E14");
    }
    let summary = &content["summary"];
    object(summary, &["title"], &["abstract"])?;
    if summary["title"]
        .as_str()
        .ok_or("WIST1-E14")?
        .chars()
        .count()
        > 256
        || summary.get("abstract").is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(|text| text.chars().count() <= 1500)
        })
    {
        return Err("WIST1-E14");
    }
    Ok(())
}

pub fn validate_version(payload: &Value) -> Result<(), &'static str> {
    validate_fields(payload)?;
    if payload["wist_version"].as_str().unwrap().split('.').next() != Some("1") {
        return Err("WIST1-E15");
    }
    Ok(())
}

pub fn validate_links(links: &PayloadLinks, publisher: &str) -> Result<(), &'static str> {
    if links.urls.len() as u128 > u128::from(links.total) {
        return Err("WIST1-E12");
    }
    let mut seen = HashSet::new();
    for url in &links.urls {
        if !seen.insert(url) || wist_core::extract::normalize_url(url, url).as_deref() != Some(url)
        {
            return Err("WIST1-E12");
        }
        let host = url["https://".len()..]
            .split(['/', ':'])
            .next()
            .unwrap_or_default();
        if host == publisher
            || host
                .strip_suffix(publisher)
                .is_some_and(|prefix| prefix.ends_with('.'))
        {
            return Err("WIST1-E12");
        }
    }
    Ok(())
}
