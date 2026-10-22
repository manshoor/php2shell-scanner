//! Scan engine: resolve, guard against internal targets, fetch, classify.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::signatures::{Headers, Signature, Status};

const USER_AGENT: &str = "website-scanner/1.0 (+authorised vulnerability detection)";
const MAX_BODY_BYTES: usize = 65536;

/// One host's result.
pub struct ScanResult {
    pub target: String,
    pub signature: String,
    pub product: String,
    pub status: Status,
    pub version: Option<String>,
    pub cves: String,
    pub detail: String,
}

/// Is this IP one a scanner service must refuse (SSRF / cloud metadata)?
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()           // 10/8, 172.16/12, 192.168/16
                || v4.is_loopback()   // 127/8
                || v4.is_link_local() // 169.254/16 (incl. cloud metadata 169.254.169.254)
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                // Carrier-grade NAT 100.64/10.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || ((v6.segments()[0] & 0xfe00) == 0xfc00) // unique local fc00::/7
                || ((v6.segments()[0] & 0xffc0) == 0xfe80) // link-local fe80::/10
                || v6.to_ipv4_mapped().map(IpAddr::V4).map(is_blocked_ip).unwrap_or(false)
        }
    }
}

/// Add http:// to a bare host.
fn normalise(target: &str) -> String {
    let t = target.trim();
    if t.contains("://") {
        t.to_string()
    } else {
        format!("http://{t}")
    }
}

/// Host and port for resolution, taken from the SAME parser ureq connects with
/// (the `url` crate). `None` when the URL has no usable host.
fn parse_target(url: &str) -> Option<(url::Url, url::Host<String>, u16)> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host()?.to_owned();
    let port = parsed.port_or_known_default()?;
    Some((parsed, host, port))
}

/// A per-scan resolution snapshot. The connection resolver never queries DNS.
#[derive(Debug)]
struct PinnedTarget {
    netloc: String,
    addresses: Vec<SocketAddr>,
}

impl ureq::Resolver for PinnedTarget {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        if netloc != self.netloc {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refused unexpected connection destination",
            ));
        }
        Ok(self.addresses.clone())
    }
}

fn validate_addresses(
    netloc: String,
    addresses: Vec<SocketAddr>,
    allow_private: bool,
) -> Result<PinnedTarget, String> {
    if addresses.is_empty() {
        return Err(format!("dns returned no address for {netloc}"));
    }
    if !allow_private {
        if let Some(addr) = addresses.iter().find(|addr| is_blocked_ip(addr.ip())) {
            return Err(format!(
                "refused: {netloc} resolves to internal {}",
                addr.ip()
            ));
        }
    }
    Ok(PinnedTarget { netloc, addresses })
}

/// Use the same URL parser and netloc formatting as ureq, and resolve once.
fn guard_target(url: &str, allow_private: bool) -> Result<PinnedTarget, String> {
    resolve_target(url, allow_private, |netloc| {
        netloc.to_socket_addrs().map(Iterator::collect)
    })
}

fn resolve_target(
    url: &str,
    allow_private: bool,
    resolve: impl FnOnce(&str) -> std::io::Result<Vec<SocketAddr>>,
) -> Result<PinnedTarget, String> {
    let (_, host, port) = parse_target(url).ok_or_else(|| "cannot parse host".to_string())?;
    let netloc = format!("{host}:{port}");
    let addresses = match host {
        url::Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        url::Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        url::Host::Domain(_) => resolve(&netloc).map_err(|e| format!("dns failed: {e}"))?,
    };
    validate_addresses(netloc, addresses, allow_private)
}

fn agent_for(target: PinnedTarget) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .resolver(target)
        .try_proxy_from_env(false)
        .redirects(0)
        .user_agent(USER_AGENT)
        .build()
}

/// HTTP status failures still have useful headers; transport/body failures do not.
fn read_response(
    response: Result<ureq::Response, ureq::Error>,
) -> Result<(u16, Headers, String), String> {
    let resp = match response {
        Ok(resp) | Err(ureq::Error::Status(_, resp)) => resp,
        Err(ureq::Error::Transport(t)) => return Err(format!("request failed: {t}")),
    };
    let code = resp.status();
    let (headers, body) = read(resp).map_err(|e| format!("response body read failed: {e}"))?;
    Ok((code, headers, body))
}

/// Collect a ureq response's headers into a lower-cased map.
fn collect_headers(resp: &ureq::Response) -> Headers {
    let mut map: HashMap<String, String> = HashMap::new();
    for name in resp.headers_names() {
        if let Some(value) = resp.header(&name) {
            map.insert(name.to_ascii_lowercase(), value.to_string());
        }
    }
    Headers(map)
}

/// Scan one target against one signature.
///
/// `allow_private` lets the CLI test localhost/LAN on purpose; the web service
/// leaves it false so a user cannot aim the server at internal hosts.
pub fn scan_one(
    target: &str,
    sig: &Signature,
    timeout: Duration,
    allow_private: bool,
) -> ScanResult {
    let url = normalise(target);
    let mut result = ScanResult {
        target: target.to_string(),
        signature: sig.name.to_string(),
        product: sig.product.to_string(),
        status: Status::NotDetected,
        version: None,
        cves: sig.cves.join(", "),
        detail: String::new(),
    };

    let pinned = match guard_target(&url, allow_private) {
        Ok(pinned) => pinned,
        Err(reason) => {
            result.status = Status::Error;
            result.detail = reason;
            return result;
        }
    };
    let agent = agent_for(pinned);
    let (_, headers, body) = match read_response(agent.get(&url).timeout(timeout).call()) {
        Ok(response) => response,
        Err(reason) => {
            result.status = Status::Error;
            result.detail = reason;
            return result;
        }
    };

    let extracted = (sig.extract_version)(&headers, &body);
    let (status, _) = sig.classify(extracted.as_deref());
    result.status = status;
    result.version = match status {
        Status::NotDetected | Status::UnknownVersion => None,
        _ => extracted.clone(),
    };
    result.detail = match status {
        Status::NotDetected => format!("{} not fingerprinted", sig.product),
        Status::UnknownVersion => format!("{} present, version not disclosed", sig.product),
        Status::Patched => "at or above fixed release".into(),
        Status::Vulnerable => "affected version, below fixed release".into(),
        Status::Eol => "end-of-life branch, no official fix".into(),
        // Passive scan never emits these two; here only for exhaustiveness.
        Status::PossiblyVulnerable => "active probe: error signature".into(),
        Status::Error => "scan error".into(),
    };
    crate::signatures::append_backport_caveat(&mut result.detail, status, extracted.as_deref());
    result
}

/// Placeholder action id. Any value routes the request to the RSC action
/// handler; this one is obviously not a real action.
const PROBE_ACTION_ID: &str = "00000000000000000000000000000000000000ab";
/// Assetnote's published detection token. It is MALFORMED RSC input: it makes a
/// vulnerable deserializer raise an error. It does NOT execute code — it carries
/// no arithmetic / function payload, so it cannot compute, read, or run anything
/// on the target. A vulnerable server surfaces the error as 500 + a digest body.
const PROBE_BODY: &str = "[\"$1:a:a\"]";

/// react2shell active error-signature probe (opt-in, CLI only, authorised use).
///
/// Sends one POST carrying the malformed token above and reports whether the
/// host returns the vulnerable error signature (HTTP 500 with a `digest` body).
/// This is a LEAD, not a verdict: patched hosts normally do not produce it, but
/// a 500 alone is not proof. Confirm with the installed version. No
/// code-execution payload is ever sent.
pub fn active_probe_react2shell(
    target: &str,
    timeout: Duration,
    allow_private: bool,
) -> ScanResult {
    let sig = crate::signatures::by_name("react2shell").unwrap();
    let url = normalise(target);
    let mut result = ScanResult {
        target: target.to_string(),
        signature: sig.name.to_string(),
        product: sig.product.to_string(),
        status: Status::NotDetected,
        version: None,
        cves: sig.cves.join(", "),
        detail: String::new(),
    };

    let pinned = match guard_target(&url, allow_private) {
        Ok(pinned) => pinned,
        Err(reason) => {
            result.status = Status::Error;
            result.detail = reason;
            return result;
        }
    };
    let agent = agent_for(pinned);

    // Gate the POST on a successful bounded Next.js/RSC fingerprint read.
    let is_next = match read_response(agent.get(&url).timeout(timeout).call()) {
        Ok((_, headers, body)) => (sig.extract_version)(&headers, &body).is_some(),
        Err(reason) => {
            result.status = Status::Error;
            result.detail = format!("active probe fingerprint: {reason}");
            return result;
        }
    };
    if !is_next {
        result.detail = "not Next.js/RSC — active probe skipped".into();
        return result;
    }

    let send = agent
        .post(&url)
        .timeout(timeout)
        .set("Next-Action", PROBE_ACTION_ID)
        .set("Content-Type", "text/plain;charset=UTF-8")
        .set("Accept", "text/x-component")
        .send_string(PROBE_BODY);

    let (code, _, body) = match read_response(send) {
        Ok(response) => response,
        Err(reason) => {
            result.status = Status::Error;
            result.detail = format!("active probe POST: {reason}");
            return result;
        }
    };

    // Vulnerable signature: a 500 whose body carries an RSC digest error.
    let has_digest = body.contains("digest") || body.contains("E{");
    if code == 500 && has_digest {
        result.status = Status::PossiblyVulnerable;
        result.detail = "active probe: 500 + digest error signature (a lead, confirm the \
installed version)".into();
    } else {
        result.status = Status::UnknownVersion;
        result.detail = format!(
            "active probe inconclusive: HTTP {code}, no vulnerable error signature"
        );
    }
    result
}

fn read(resp: ureq::Response) -> std::io::Result<(Headers, String)> {
    let headers = collect_headers(&resp);
    let mut body = resp.into_reader().take(MAX_BODY_BYTES as u64);
    let mut buf = Vec::new();
    use std::io::Read;
    body.read_to_end(&mut buf)?;
    Ok((headers, String::from_utf8_lossy(&buf).into_owned()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn blocks_internal_ips() {
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn allows_public_ips() {
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            assert!(
                !is_blocked_ip(ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
        let _ = Ipv4Addr::LOCALHOST;
    }

    #[test]
    fn parses_target_host_port() {
        let (_, h, p) = parse_target("http://example.com/x").unwrap();
        assert_eq!((h, p), (url::Host::Domain("example.com".into()), 80));
        let (_, h, p) = parse_target("https://example.com").unwrap();
        assert_eq!((h, p), (url::Host::Domain("example.com".into()), 443));
        let (_, _, p) = parse_target("http://example.com:8080/a").unwrap();
        assert_eq!(p, 8080);
    }

    #[test]
    fn guard_blocks_numeric_and_crafted_localhost() {
        // These all denote 127.0.0.1 / loopback; the WHATWG parser canonicalises
        // them, so the guard must refuse every one. (Regression: the old parser
        // let crafted forms through.)
        for u in [
            "http://127.0.0.1/",
            "http://2130706433/",             // decimal 127.0.0.1
            "http://0x7f.0.0.1/",             // hex first octet
            "http://127.0.0.1:80@127.0.0.1/", // userinfo trick -> host is 127.0.0.1
            "http://[::1]/",
            "http://localhost./", // trailing dot still resolves to loopback
        ] {
            let r = guard_target(u, false);
            assert!(r.is_err(), "{u} must be refused, got {r:?}");
        }
    }

    #[test]
    fn pins_one_resolution_and_rejects_unexpected_destinations() {
        use std::cell::Cell;
        use ureq::Resolver;
        let calls = Cell::new(0);
        let dns = |_: &str| {
            calls.set(calls.get() + 1);
            Ok(vec![if calls.get() == 1 {
                "8.8.8.8:80"
            } else {
                "127.0.0.1:80"
            }
            .parse()
            .unwrap()])
        };
        let pinned = resolve_target("http://rebind.test/", false, dns).unwrap();
        for _ in 0..2 {
            assert_eq!(
                pinned.resolve("rebind.test:80").unwrap(),
                vec!["8.8.8.8:80".parse::<SocketAddr>().unwrap()]
            );
        }
        assert_eq!(calls.get(), 1);
        assert!(pinned.resolve("other.test:80").is_err());
        assert!(pinned.resolve("rebind.test:81").is_err());
        assert!(validate_addresses(
            "mixed.test:80".into(),
            vec![
                "8.8.8.8:80".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap()
            ],
            false
        )
        .is_err());
        assert!(validate_addresses("empty.test:80".into(), vec![], true).is_err());
        for url in ["http://127.0.0.1/", "http://[::1]/"] {
            let target =
                resolve_target(url, true, |_| panic!("literal IP must not query DNS")).unwrap();
            assert_eq!(target.resolve(&target.netloc).unwrap().len(), 1);
        }
    }

    /// Scripted local HTTP responses, with request capture and a bounded accept.
    pub(crate) fn http_fixture(
        responses: Vec<(Vec<u8>, Duration)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (response, delay) in responses {
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "expected request did not arrive"
                            );
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => panic!("accept failed: {e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                }
                let headers = String::from_utf8(bytes).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                requests.push(format!("{headers}{}", String::from_utf8_lossy(&body)));
                // Send headers immediately and optionally stall only the body.
                let end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                stream.write_all(&response[..end]).unwrap();
                std::thread::sleep(delay);
                let _ = stream.write_all(&response[end..]);
            }
            requests
        });
        (url, handle)
    }

    pub(crate) fn response(headers: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn agent_uses_pinned_addresses_for_get_and_post_and_preserves_host() {
        let (local, server) = http_fixture(vec![
            (response("", "ok"), Duration::ZERO),
            (response("", "ok"), Duration::ZERO),
        ]);
        let port = url::Url::parse(&local).unwrap().port().unwrap();
        let url = format!("http://pinned.invalid:{port}/");
        let calls = std::cell::Cell::new(0);
        let target = resolve_target(&url, true, |_| {
            calls.set(calls.get() + 1);
            assert_eq!(calls.get(), 1, "DNS must not be queried again");
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        })
        .unwrap();
        let agent = agent_for(target);
        assert!(read_response(agent.get(&url).call()).is_ok());
        assert!(read_response(agent.post(&url).send_string("probe")).is_ok());
        assert_eq!(calls.get(), 1);
        let requests = server.join().unwrap();
        for request in requests {
            assert!(request
                .to_ascii_lowercase()
                .contains(&format!("host: pinned.invalid:{port}")));
        }
    }

    #[test]
    fn passive_body_failures_are_errors_and_complete_or_capped_samples_succeed() {
        let broken = vec![
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\nshort".to_vec(), Duration::ZERO),
            (b"HTTP/1.1 500 Error\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZ\r\ninvalid\r\n".to_vec(), Duration::ZERO),
            (response("", "short"), Duration::from_millis(300)),
        ];
        for response in broken {
            let (url, server) = http_fixture(vec![response]);
            let result = scan_one(
                &url,
                crate::signatures::by_name("php2shell").unwrap(),
                Duration::from_millis(100),
                true,
            );
            assert_eq!(result.status, Status::Error, "{}", result.detail);
            assert!(
                result.detail.contains("body read failed"),
                "{}",
                result.detail
            );
            server.join().unwrap();
        }
        for body in ["complete".to_string(), "x".repeat(MAX_BODY_BYTES + 1)] {
            let (url, server) = http_fixture(vec![(response("", &body), Duration::ZERO)]);
            let result = scan_one(
                &url,
                crate::signatures::by_name("php2shell").unwrap(),
                Duration::from_secs(1),
                true,
            );
            assert_eq!(result.status, Status::NotDetected, "{}", result.detail);
            server.join().unwrap();
        }
    }

    #[test]
    fn active_probe_requires_successful_body_reads_at_both_stages() {
        let complete = response("X-Powered-By: Next.js\r\n", "next");
        let truncated = b"HTTP/1.1 500 Error\r\nX-Powered-By: Next.js\r\nContent-Length: 1000\r\nConnection: close\r\n\r\ndigest".to_vec();
        for responses in [
            vec![(truncated.clone(), Duration::ZERO)],
            vec![
                (complete.clone(), Duration::ZERO),
                (truncated, Duration::ZERO),
            ],
            vec![(complete.clone(), Duration::from_millis(300))],
            vec![
                (complete.clone(), Duration::ZERO),
                (complete.clone(), Duration::from_millis(300)),
            ],
        ] {
            let count = responses.len();
            let (url, server) = http_fixture(responses);
            let result = active_probe_react2shell(&url, Duration::from_millis(100), true);
            assert_eq!(result.status, Status::Error, "{}", result.detail);
            assert!(result.detail.contains("body read failed"));
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), count);
            if count == 2 {
                assert!(requests[1].starts_with("POST "));
            }
        }
        let (url, server) = http_fixture(vec![
            (complete, Duration::ZERO),
            (
                b"HTTP/1.1 500 Error\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndigest"
                    .to_vec(),
                Duration::ZERO,
            ),
        ]);
        assert_eq!(
            active_probe_react2shell(&url, Duration::from_secs(1), true).status,
            Status::PossiblyVulnerable
        );
        server.join().unwrap();
    }
}
