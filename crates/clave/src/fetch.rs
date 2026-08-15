use crate::error::{Error, Result};
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 30;

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn guard_scheme(parsed: &url::Url, allow_http: bool) -> Result<()> {
    let host_ok = allow_http && parsed.host_str().is_some_and(is_loopback_host);
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if host_ok => Ok(()),
        other => Err(Error::Fetch(format!(
            "refusing to fetch {other} URL for non-loopback host or --allow-http not set: {parsed}"
        ))),
    }
}

pub fn scheme_for_host(host: &str, allow_http: bool) -> &'static str {
    let bare = url::Url::parse(&format!("http://{host}/"))
        .ok()
        .and_then(|u| u.host_str().map(str::to_string));
    match bare {
        Some(h) if allow_http && is_loopback_host(&h) => "http",
        _ => "https",
    }
}

pub struct Client {
    allow_http: bool,
    inner: reqwest::blocking::Client,
}

impl Client {
    pub fn new(allow_http: bool) -> Client {
        let inner = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .expect("reqwest client builds with a fixed timeout");
        Client { allow_http, inner }
    }

    pub fn allow_http(&self) -> bool {
        self.allow_http
    }

    pub fn get_json(&self, url: &str) -> Result<(Vec<u8>, serde_json::Value)> {
        let parsed =
            url::Url::parse(url).map_err(|e| Error::Fetch(format!("invalid URL {url}: {e}")))?;
        guard_scheme(&parsed, self.allow_http)?;

        let resp = self
            .inner
            .get(parsed)
            .send()
            .map_err(|e| Error::Fetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Fetch(format!("HTTP {} for {url}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| Error::Fetch(e.to_string()))?
            .to_vec();
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        Ok((bytes, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_scheme_allows_https_regardless_of_allow_http() {
        let url = url::Url::parse("https://example.com/x.json").unwrap();
        assert!(guard_scheme(&url, false).is_ok());
        assert!(guard_scheme(&url, true).is_ok());
    }

    #[test]
    fn guard_scheme_allows_http_loopback_only_when_allow_http_set() {
        let url = url::Url::parse("http://127.0.0.1:8080/x.json").unwrap();
        assert!(guard_scheme(&url, false).is_err());
        assert!(guard_scheme(&url, true).is_ok());

        let url = url::Url::parse("http://localhost:8080/x.json").unwrap();
        assert!(guard_scheme(&url, true).is_ok());
    }

    #[test]
    fn guard_scheme_rejects_http_non_loopback_even_with_allow_http() {
        let url = url::Url::parse("http://example.com/x.json").unwrap();
        assert!(guard_scheme(&url, true).is_err());
        assert!(guard_scheme(&url, false).is_err());
    }

    #[test]
    fn scheme_for_host_selects_http_only_for_loopback_under_allow_http() {
        assert_eq!(scheme_for_host("127.0.0.1:8080", true), "http");
        assert_eq!(scheme_for_host("localhost:9999", true), "http");
        assert_eq!(scheme_for_host("localhost", true), "http");
        assert_eq!(scheme_for_host("example.com", true), "https");
        assert_eq!(scheme_for_host("127.0.0.1:8080", false), "https");
        assert_eq!(scheme_for_host("example.com", false), "https");
    }

    #[test]
    fn get_json_rejects_non_json_body() {
        let client = Client::new(false);
        let err = client.get_json("https://").unwrap_err();
        assert!(matches!(err, Error::Fetch(_)));
    }
}
