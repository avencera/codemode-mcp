//! `Host` header checks that blunt DNS rebinding without pinning exact names
//!
//! rmcp's own allow list only matches exact authorities, which cannot express
//! "any tailnet name or LAN address", so the server disables it and enforces
//! these rules in front of every route instead. The rules mirror homebased's.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header::HOST},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Which `Host` values the server answers to
#[derive(Debug, Clone, Default)]
pub struct HostPolicy {
    extra: Vec<String>,
}

impl HostPolicy {
    /// Built-in rules plus the configured extra names
    pub fn new(extra: &[String]) -> Self {
        Self {
            extra: extra
                .iter()
                .map(|name| name.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect(),
        }
    }

    /// Whether a `Host` header value (with optional port) is accepted
    pub fn allows(&self, header: &str) -> bool {
        let header = header.trim();
        let Some(host) = strip_port(header) else {
            return false;
        };
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return false;
        }
        let lower_header = header.to_ascii_lowercase();
        let lower_host = host.to_ascii_lowercase();
        if self
            .extra
            .iter()
            .any(|name| *name == lower_host || *name == lower_header)
        {
            return true;
        }
        if lower_host == "localhost" {
            return true;
        }
        if let Ok(address) = lower_host.parse::<IpAddr>() {
            return is_local_ip(address) || is_tailscale_ip(address);
        }

        has_suffix(&lower_host, ".ts.net")
            || has_suffix(&lower_host, ".local")
            || is_single_label(&lower_host)
    }
}

/// Axum middleware answering 403 for hosts the policy rejects
pub async fn host_guard(
    State(policy): State<Arc<HostPolicy>>,
    request: Request,
    next: Next,
) -> Response {
    // HTTP/2 carries the host as the URI authority instead of a header
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| request.uri().authority().map(ToString::to_string));
    if host.is_some_and(|host| policy.allows(&host)) {
        return next.run(request).await;
    }

    (StatusCode::FORBIDDEN, "forbidden: unexpected Host header").into_response()
}

fn strip_port(host: &str) -> Option<&str> {
    if let Some(rest) = host.strip_prefix('[') {
        let (address, suffix) = rest.split_once(']')?;
        address.parse::<Ipv6Addr>().ok()?;
        if !suffix.is_empty() {
            suffix.strip_prefix(':')?.parse::<u16>().ok()?;
        }

        return Some(address);
    }

    match host.rsplit_once(':') {
        // a bare IPv6 literal has several colons and no port
        Some((name, _)) if name.contains(':') => Some(host),
        Some((name, port)) => port.parse::<u16>().ok().map(|_| name),
        None => Some(host),
    }
}

fn is_local_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_local_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.to_ipv4_mapped().is_some_and(is_local_v4)
        }
    }
}

fn is_local_v4(address: Ipv4Addr) -> bool {
    address.is_loopback() || address.is_private() || address.is_link_local()
}

/// Tailscale addresses live in 100.64.0.0/10
fn is_tailscale_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let octets = v4.octets();

            octets[0] == 100 && (octets[1] & 0xc0) == 64
        }
        IpAddr::V6(_) => false,
    }
}

fn has_suffix(host: &str, suffix: &str) -> bool {
    host.strip_suffix(suffix).is_some_and(is_dns_labels)
}

fn is_single_label(host: &str) -> bool {
    !host.contains('.') && is_dns_labels(host)
}

fn is_dns_labels(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
}

/// Headers proxies add; `tailscale serve` sends `X-Forwarded-For` and the
/// `Tailscale-User-*` family, other proxies the rest
const PROXY_HEADERS: [&str; 5] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// Whether a request carries a header that only a proxy adds
pub fn proxied(headers: &HeaderMap) -> bool {
    PROXY_HEADERS
        .iter()
        .any(|header| headers.contains_key(*header))
        || headers
            .keys()
            .any(|name| name.as_str().starts_with("tailscale-"))
}

/// Whether a request came straight from a process on this machine: the TCP
/// peer is loopback and no proxy header is present
///
/// `tailscale serve` connects from 127.0.0.1, so the peer alone would let
/// the tailnet in. A missing peer (a router served without connect info) is
/// never local
pub fn is_direct_local(peer: Option<SocketAddr>, headers: &HeaderMap) -> bool {
    peer.is_some_and(|peer| peer.ip().to_canonical().is_loopback()) && !proxied(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_local_and_tailnet_names_and_rejects_public_ones() {
        let policy = HostPolicy::new(&["Agents.Example.com".to_owned()]);

        for host in [
            "localhost:7681",
            "127.0.0.1",
            "[::1]:7681",
            "192.168.0.10:7681",
            "169.254.1.1",
            "100.101.102.103:7681",
            "mac.tailnet-name.ts.net",
            "mac.local",
            "main",
            "agents.example.com:7681",
        ] {
            assert!(policy.allows(host), "{host} should be allowed");
        }
        for host in [
            "evil.example.com",
            "8.8.8.8",
            "100.128.0.1",
            "",
            "a..local",
            "x.ts.net.evil.com",
        ] {
            assert!(!policy.allows(host), "{host} should be rejected");
        }
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn headers(names: &[&str]) -> Result<HeaderMap, Box<dyn std::error::Error>> {
        let mut map = HeaderMap::new();
        for name in names {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes())?,
                "x".parse()?,
            );
        }

        Ok(map)
    }

    #[test]
    fn direct_local_needs_a_loopback_peer_and_no_proxy_headers() -> TestResult {
        let loopback: SocketAddr = "127.0.0.1:5000".parse()?;
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5000".parse()?;
        let lan: SocketAddr = "192.168.0.10:5000".parse()?;
        let tailnet: SocketAddr = "100.101.102.103:5000".parse()?;

        assert!(is_direct_local(Some(loopback), &headers(&[])?));
        assert!(is_direct_local(Some(mapped), &headers(&[])?));
        assert!(!is_direct_local(Some(lan), &headers(&[])?));
        assert!(!is_direct_local(Some(tailnet), &headers(&[])?));
        assert!(!is_direct_local(None, &headers(&[])?));
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip",
            "tailscale-user-login",
            "tailscale-user-name",
            "tailscale-user-profile-pic",
            "tailscale-app-capabilities",
        ] {
            assert!(
                !is_direct_local(Some(loopback), &headers(&[name])?),
                "{name}"
            );
        }

        Ok(())
    }
}
