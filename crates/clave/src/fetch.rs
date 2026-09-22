use crate::error::{Error, Result};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 30;

/// WIST-2 §8: a chain runs no more than five hops and never revisits a
/// URL it has already fetched.
const MAX_REDIRECTS: usize = 5;

/// The bound on one fetched Declaration, Feed page or Mirror list: no
/// protocol object of those kinds approaches it, and a response above it
/// is refused while it streams.
pub const OBJECT_CAP_BYTES: u64 = 1 << 20;

const READ_CHUNK_BYTES: usize = 16 * 1024;

/// A name lookup, injectable so tests can script what a host resolves to.
pub type Lookup = Arc<dyn Fn(&str) -> std::io::Result<Vec<IpAddr>> + Send + Sync>;

fn system_lookup(host: &str) -> std::io::Result<Vec<IpAddr>> {
    Ok((host, 0)
        .to_socket_addrs()?
        .map(|address| address.ip())
        .collect())
}

/// A loopback literal, `localhost` or a name under `.localhost`, which
/// RFC 6761 §6.3 resolves to loopback by definition.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .strip_suffix(".localhost")
            .or_else(|| host.strip_suffix(".LOCALHOST"))
            .is_some_and(|prefix| !prefix.is_empty())
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn ipv4_class(ip: Ipv4Addr, allow_loopback: bool) -> Option<&'static str> {
    let octets = ip.octets();
    if ip.is_loopback() {
        return (!allow_loopback).then_some("loopback");
    }
    if ip.is_unspecified() {
        Some("unspecified")
    } else if ip.is_private() {
        Some("private")
    } else if ip.is_link_local() {
        Some("link-local")
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        Some("shared address space")
    } else if ip.is_broadcast() {
        Some("broadcast")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if ip.is_documentation() {
        Some("documentation")
    } else if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        Some("benchmarking")
    } else if octets[0] >= 240 {
        Some("reserved")
    } else {
        None
    }
}

fn ipv6_class(ip: Ipv6Addr, allow_loopback: bool) -> Option<&'static str> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return ipv4_class(mapped, allow_loopback);
    }
    let segments = ip.segments();
    if ip.is_loopback() {
        (!allow_loopback).then_some("loopback")
    } else if ip.is_unspecified() {
        Some("unspecified")
    } else if segments[0] & 0xfe00 == 0xfc00 {
        Some("unique local")
    } else if segments[0] & 0xffc0 == 0xfe80 {
        Some("link-local")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        Some("documentation")
    } else if segments[0] == 0x2002 {
        ipv4_class(
            Ipv4Addr::from(((segments[1] as u32) << 16) | segments[2] as u32),
            allow_loopback,
        )
    } else if segments[0] == 0x0064 && segments[1] == 0xff9b {
        ipv4_class(
            Ipv4Addr::from(((segments[6] as u32) << 16) | segments[7] as u32),
            allow_loopback,
        )
    } else {
        None
    }
}

/// The destination policy: a fetch connects only to a public unicast
/// address. Loopback is allowed under the loopback HTTP opt-in, the one
/// exception documented for running the stack on one machine; private,
/// link-local, shared, multicast, documentation, benchmarking, reserved
/// and unspecified addresses are never fetch destinations, whether named
/// by a literal, by a redirect or by what a name resolves to.
pub fn destination_allowed(ip: IpAddr, allow_loopback: bool) -> Result<()> {
    let class = match ip {
        IpAddr::V4(ip) => ipv4_class(ip, allow_loopback),
        IpAddr::V6(ip) => ipv6_class(ip, allow_loopback),
    };
    match class {
        None => Ok(()),
        Some(class) => Err(Error::Fetch(format!(
            "refusing {ip}: a {class} address is not a fetch destination"
        ))),
    }
}

struct PolicyResolver {
    allow_loopback: bool,
    lookup: Lookup,
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let lookup = self.lookup.clone();
        let allow_loopback = self.allow_loopback;
        Box::pin(async move {
            let resolved = tokio::task::spawn_blocking(move || lookup(&host))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))??;
            if resolved.is_empty() {
                return Err(std::io::Error::other("the name resolved to no address").into());
            }
            for ip in &resolved {
                destination_allowed(*ip, allow_loopback)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            let addresses: Addrs = Box::new(resolved.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addresses)
        })
    }
}

fn guard_target(parsed: &url::Url, allow_http: bool) -> Result<()> {
    let host_ok = allow_http && parsed.host_str().is_some_and(is_loopback_host);
    let scheme_ok = match parsed.scheme() {
        "https" => true,
        "http" => host_ok,
        _ => false,
    };
    if !scheme_ok {
        let scheme = parsed.scheme();
        return Err(Error::Fetch(format!(
            "refusing to fetch {scheme} URL for non-loopback host or --allow-http not set: {parsed}"
        )));
    }
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => destination_allowed(ip.into(), allow_http),
        Some(url::Host::Ipv6(ip)) => destination_allowed(ip.into(), allow_http),
        _ => Ok(()),
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
    if guard_target(to, allow_http).is_err() {
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

/// A transport error with its causes, since the destination policy and
/// the resolver report through the connector's error chain.
fn describe(error: reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(inner) = source {
        message.push_str(": ");
        message.push_str(&inner.to_string());
        source = inner.source();
    }
    message
}

fn read_bounded(
    mut response: reqwest::blocking::Response,
    limit: u64,
    url: &str,
) -> Result<Vec<u8>> {
    if let Some(declared) = response.content_length() {
        if declared > limit {
            return Err(Error::Oversized(format!(
                "response for {url} declares {declared} bytes, above the {limit}-byte bound"
            )));
        }
    }
    let mut body = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK_BYTES];
    loop {
        let read = response
            .read(&mut chunk)
            .map_err(|e| Error::Fetch(e.to_string()))?;
        if read == 0 {
            break;
        }
        if body.len() as u64 + read as u64 > limit {
            return Err(Error::Oversized(format!(
                "response for {url} exceeds the {limit}-byte bound"
            )));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

/// One posted request's answer: its status, its declared media type and
/// its body, whether or not the status is a success.
pub struct PostResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct Client {
    allow_http: bool,
    inner: reqwest::blocking::Client,
}

impl Client {
    pub fn new(allow_http: bool) -> Client {
        Self::with_builder(allow_http, reqwest::blocking::Client::builder())
    }

    pub fn with_builder(allow_http: bool, builder: reqwest::blocking::ClientBuilder) -> Client {
        Self::build(allow_http, builder, Arc::new(system_lookup))
    }

    /// A client whose name resolution goes through `lookup` before the
    /// destination policy, so a test can script what a host resolves to.
    pub fn with_lookup(allow_http: bool, lookup: Lookup) -> Client {
        Self::build(allow_http, reqwest::blocking::Client::builder(), lookup)
    }

    fn build(
        allow_http: bool,
        builder: reqwest::blocking::ClientBuilder,
        lookup: Lookup,
    ) -> Client {
        let resolver = Arc::new(PolicyResolver {
            allow_loopback: allow_http,
            lookup,
        });
        let inner = builder
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(resolver)
            .build()
            .expect("reqwest client builds with a fixed timeout");
        Client { allow_http, inner }
    }

    pub fn allow_http(&self) -> bool {
        self.allow_http
    }

    pub fn get_json(&self, url: &str) -> Result<(Vec<u8>, serde_json::Value)> {
        self.get_json_bounded(url, &[], OBJECT_CAP_BYTES)
    }

    pub fn get_json_in_scope(
        &self,
        url: &str,
        subdomain_scope: &[String],
    ) -> Result<(Vec<u8>, serde_json::Value)> {
        self.get_json_bounded(url, subdomain_scope, OBJECT_CAP_BYTES)
    }

    pub fn get_json_bounded(
        &self,
        url: &str,
        subdomain_scope: &[String],
        limit: u64,
    ) -> Result<(Vec<u8>, serde_json::Value)> {
        let bytes = self.get_bytes_bounded(url, subdomain_scope, limit)?;
        let value = crate::json::parse(&bytes)?;
        Ok((bytes, value))
    }

    pub fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        self.get_bytes_bounded(url, &[], OBJECT_CAP_BYTES)
    }

    /// Posts `body` to `url` through the scheme guard and the
    /// destination policy, following no redirect, and reads at most
    /// `limit` bytes of the response whatever its status, so a caller
    /// that acts on a refusal reads what the refusal states.
    pub fn post_bounded(&self, url: &str, body: Vec<u8>, limit: u64) -> Result<PostResponse> {
        let parsed =
            url::Url::parse(url).map_err(|e| Error::Fetch(format!("invalid URL {url}: {e}")))?;
        guard_target(&parsed, self.allow_http)?;
        let response = self
            .inner
            .post(parsed)
            .body(body)
            .send()
            .map_err(|e| Error::Fetch(describe(e)))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Ok(PostResponse {
            status,
            content_type,
            body: read_bounded(response, limit, url)?,
        })
    }

    /// Fetches `url` through the scheme guard, the destination policy on
    /// every hop and the redirect rules, reading at most `limit` bytes of
    /// the final response before refusing it.
    pub fn get_bytes_bounded(
        &self,
        url: &str,
        subdomain_scope: &[String],
        limit: u64,
    ) -> Result<Vec<u8>> {
        let mut parsed =
            url::Url::parse(url).map_err(|e| Error::Fetch(format!("invalid URL {url}: {e}")))?;
        guard_target(&parsed, self.allow_http)?;

        let mut hops = 0usize;
        let mut fetched = std::collections::HashSet::new();
        fetched.insert(parsed.clone());
        let resp = loop {
            let resp = self
                .inner
                .get(parsed.clone())
                .send()
                .map_err(|e| Error::Fetch(describe(e)))?;
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
        read_bounded(resp, limit, url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_scheme_allows_https_regardless_of_allow_http() {
        let url = url::Url::parse("https://example.com/x.json").unwrap();
        assert!(guard_target(&url, false).is_ok());
        assert!(guard_target(&url, true).is_ok());
    }

    #[test]
    fn guard_scheme_allows_http_loopback_only_when_allow_http_set() {
        let url = url::Url::parse("http://127.0.0.1:8080/x.json").unwrap();
        assert!(guard_target(&url, false).is_err());
        assert!(guard_target(&url, true).is_ok());

        let url = url::Url::parse("http://localhost:8080/x.json").unwrap();
        assert!(guard_target(&url, true).is_ok());
        let url = url::Url::parse("http://www.localhost:8080/x.json").unwrap();
        assert!(guard_target(&url, true).is_ok());
        assert!(guard_target(&url, false).is_err());
    }

    #[test]
    fn guard_scheme_rejects_http_non_loopback_even_with_allow_http() {
        let url = url::Url::parse("http://example.com/x.json").unwrap();
        assert!(guard_target(&url, true).is_err());
        assert!(guard_target(&url, false).is_err());
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
    fn destination_policy_names_every_non_public_class() {
        let class = |ip: &str, allow_loopback: bool| {
            destination_allowed(ip.parse().unwrap(), allow_loopback)
                .err()
                .map(|e| e.to_string())
        };
        for (ip, expected) in [
            ("10.0.0.5", "private"),
            ("172.16.0.1", "private"),
            ("192.168.1.1", "private"),
            ("169.254.169.254", "link-local"),
            ("100.64.0.1", "shared address space"),
            ("0.0.0.0", "unspecified"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "broadcast"),
            ("192.0.2.1", "documentation"),
            ("198.18.0.1", "benchmarking"),
            ("240.0.0.1", "reserved"),
            ("::", "unspecified"),
            ("fc00::1", "unique local"),
            ("fe80::1", "link-local"),
            ("ff02::1", "multicast"),
            ("2001:db8::1", "documentation"),
            ("::ffff:10.0.0.5", "private"),
            ("2002:0a00:0005::", "private"),
            ("64:ff9b::a00:5", "private"),
        ] {
            assert!(
                class(ip, true).is_some_and(|e| e.contains(expected)),
                "{ip} should be refused as {expected}"
            );
        }
        assert!(class("127.0.0.1", true).is_none());
        assert!(class("::1", true).is_none());
        assert!(class("127.0.0.1", false).is_some_and(|e| e.contains("loopback")));
        assert!(class("::1", false).is_some_and(|e| e.contains("loopback")));
        assert!(class("93.184.216.34", false).is_none());
        assert!(class("2606:2800:220:1:248:1893:25c8:1946", false).is_none());
    }

    #[test]
    fn a_literal_non_public_destination_is_refused_before_any_connection() {
        let client = Client::new(false);
        for url in [
            "https://10.0.0.5/x.json",
            "https://169.254.169.254/latest",
            "https://[fe80::1]/x.json",
            "https://127.0.0.1/x.json",
        ] {
            let err = client.get_bytes(url).unwrap_err().to_string();
            assert!(err.contains("is not a fetch destination"), "{url}: {err}");
        }
        let client = Client::new(true);
        let err = client
            .get_bytes("https://10.0.0.5/x.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("private"), "{err}");
    }

    #[test]
    fn a_redirect_to_a_non_public_literal_is_refused() {
        assert!(!redirect_allowed(
            &u("https://example.com/a"),
            &u("https://10.0.0.5/a"),
            &["10.0.0.5".to_string()],
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
