use crate::error::{Error, Result};
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 30;

/// WIST-2 §8: a chain runs no more than five hops and never revisits a
/// URL it has already fetched.
const MAX_REDIRECTS: usize = 5;

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

/// WIST-1 §5.1 and WIST-2 §8: a redirect is followed only when the
/// target is `https` and its Canonical Host equals the request's or is
/// listed in the Publisher's `subdomain_scope`.
fn redirect_allowed(from: &url::Url, to: &url::Url, scope: &[String], allow_http: bool) -> bool {
    if guard_scheme(to, allow_http).is_err() {
        return false;
    }
    let canonical = |host: &str| wist_core::host::canonical_host(host).ok();
    let Some(target) = to.host_str().and_then(canonical) else {
        return false;
    };
    if from.host_str().and_then(canonical).as_deref() == Some(target.as_str()) {
        return true;
    }
    scope
        .iter()
        .filter_map(|h| canonical(h))
        .any(|h| h == target)
}

pub struct Client {
    allow_http: bool,
    inner: reqwest::blocking::Client,
}

impl Client {
    pub fn new(allow_http: bool) -> Client {
        Self::with_builder(allow_http, reqwest::blocking::Client::builder())
    }

    pub fn with_builder(allow_http: bool, builder: reqwest::blocking::ClientBuilder) -> Client {
        let inner = builder
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client builds with a fixed timeout");
        Client { allow_http, inner }
    }

    pub fn allow_http(&self) -> bool {
        self.allow_http
    }

    pub fn get_json(&self, url: &str) -> Result<(Vec<u8>, serde_json::Value)> {
        self.get_json_in_scope(url, &[])
    }

    pub fn get_json_in_scope(
        &self,
        url: &str,
        subdomain_scope: &[String],
    ) -> Result<(Vec<u8>, serde_json::Value)> {
        let mut parsed =
            url::Url::parse(url).map_err(|e| Error::Fetch(format!("invalid URL {url}: {e}")))?;
        guard_scheme(&parsed, self.allow_http)?;

        let mut hops = 0usize;
        let mut fetched = std::collections::HashSet::new();
        fetched.insert(parsed.clone());
        let resp = loop {
            let resp = self
                .inner
                .get(parsed.clone())
                .send()
                .map_err(|e| Error::Fetch(e.to_string()))?;
            if !resp.status().is_redirection() {
                break resp;
            }
            if hops == MAX_REDIRECTS {
                return Err(Error::Fetch(format!("too many redirects for {url}")));
            }
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Error::Fetch(format!("redirect without a location for {url}")))?;
            let target = parsed
                .join(location)
                .map_err(|e| Error::Fetch(format!("invalid redirect target {location}: {e}")))?;
            if !redirect_allowed(&parsed, &target, subdomain_scope, self.allow_http) {
                return Err(Error::Fetch(format!(
                    "refusing redirect from {parsed} to {target}: outside the Publisher's authority"
                )));
            }
            if !fetched.insert(target.clone()) {
                return Err(Error::Fetch(format!(
                    "refusing redirect to {target}: already fetched in this chain"
                )));
            }
            parsed = target;
            hops += 1;
        };
        if !resp.status().is_success() {
            return Err(Error::Fetch(format!("HTTP {} for {url}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| Error::Fetch(e.to_string()))?
            .to_vec();
        let value: serde_json::Value = crate::json::parse(&bytes)?;
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

    fn u(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn a_redirect_to_the_same_canonical_host_is_followed() {
        assert!(redirect_allowed(
            &u("https://example.com/a"),
            &u("https://EXAMPLE.com/b"),
            &[],
            false
        ));
    }

    #[test]
    fn a_redirect_to_a_host_in_subdomain_scope_is_followed() {
        let scope = vec!["www.example.com".to_string()];
        assert!(redirect_allowed(
            &u("https://example.com/a"),
            &u("https://www.example.com/a"),
            &scope,
            false
        ));
    }

    #[test]
    fn a_redirect_outside_the_publishers_authority_is_refused() {
        let scope = vec!["www.example.com".to_string()];
        assert!(!redirect_allowed(
            &u("https://example.com/a"),
            &u("https://evil.example.net/a"),
            &scope,
            false
        ));
        assert!(!redirect_allowed(
            &u("https://example.com/a"),
            &u("https://other.example.com/a"),
            &scope,
            false
        ));
    }

    #[test]
    fn a_redirect_to_plain_http_is_refused() {
        assert!(!redirect_allowed(
            &u("https://example.com/a"),
            &u("http://example.com/a"),
            &[],
            false
        ));
    }

    #[test]
    fn get_json_rejects_non_json_body() {
        let client = Client::new(false);
        let err = client.get_json("https://").unwrap_err();
        assert!(matches!(err, Error::Fetch(_)));
    }
}
