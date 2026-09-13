use std::collections::HashSet;
use wist_core::objects::PayloadLinks;

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
