//! Minimal web UI: a single page plus a JSON scan endpoint.
//!
//! The server only ever runs the PASSIVE check, and `allow_private` is forced
//! off so a visitor cannot aim it at localhost, the LAN, or cloud metadata.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tiny_http::{Header, Method, Request, Response, Server};

use crate::scan::{scan_one, ScanResult};
use crate::signatures;

const MAX_INFLIGHT: usize = 16; // return 503 past this many concurrent scans
const POOL_THREADS: usize = 24; // > MAX_INFLIGHT so the page still loads mid-scan

/// A permit owns exactly one slot, including through unwinding.
struct ScanPermit<'a>(&'a AtomicUsize);

impl<'a> ScanPermit<'a> {
    fn acquire(inflight: &'a AtomicUsize) -> Option<Self> {
        inflight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current < MAX_INFLIGHT {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .ok()
            .map(|_| Self(inflight))
    }
}

impl Drop for ScanPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Run the web server until killed.
///
/// A pool of worker threads share the `Server` and each pull requests with
/// `recv()`. Requests are handled concurrently, so a slow scan occupies one
/// worker while the page and other requests are served by the rest — the
/// `MAX_INFLIGHT` cap then limits only the heavy `/api/scan` work.
pub fn serve(addr: &str, timeout: Duration) -> Result<(), String> {
    let server = Arc::new(Server::http(addr).map_err(|e| format!("cannot bind {addr}: {e}"))?);
    eprintln!("# web UI on http://{addr}  (passive detection, private targets blocked)");
    let inflight = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..POOL_THREADS {
        let server = server.clone();
        let inflight = inflight.clone();
        handles.push(thread::spawn(move || loop {
            match server.recv() {
                Ok(request) => handle_request(request, timeout, &inflight),
                Err(_) => break,
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Route and answer a single request. Runs on a worker thread.
fn handle_request(request: Request, timeout: Duration, inflight: &AtomicUsize) {
    let url = request.url().to_string();
    let method = request.method().clone();
    let path = url.split('?').next().unwrap_or("/");

    if method == Method::Get && (path == "/" || path == "/index.html") {
        let _ = request.respond(html_response(PAGE, "text/html; charset=utf-8"));
        return;
    }
    if method == Method::Get && path == "/api/scan" {
        // Concurrency cap -> 503 for the heavy scan work only.
        let Some(_permit) = ScanPermit::acquire(inflight) else {
            let _ = request.respond(
                html_response("{\"error\":\"busy\"}", "application/json").with_status_code(503),
            );
            return;
        };
        let body = handle_scan(&url, timeout);
        let _ = request.respond(html_response(&body, "application/json"));
        return;
    }
    let _ = request.respond(
        html_response("{\"error\":\"not found\"}", "application/json").with_status_code(404),
    );
}

fn html_response(body: &str, content_type: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap();
    Response::from_string(body).with_header(header)
}

/// Handle GET /api/scan?url=...&sig=php2shell . Always passive, never private.
fn handle_scan(raw_url: &str, timeout: Duration) -> String {
    let query = raw_url.split('?').nth(1).unwrap_or("");
    let mut target = String::new();
    let mut sig_name = String::from("php2shell");
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let value = percent_decode(v);
            match k {
                "url" => target = value,
                "sig" => sig_name = value,
                _ => {}
            }
        }
    }
    if target.trim().is_empty() {
        return json_err("missing url parameter");
    }
    let sig = match signatures::by_name(&sig_name) {
        Some(s) => s,
        None => return json_err("unknown signature"),
    };

    // Web path: allow_private = false (no SSRF into internal hosts).
    let r = scan_one(&target, sig, timeout, false);
    scan_json(&r)
}

fn scan_json(r: &ScanResult) -> String {
    let version = r.version.as_deref().unwrap_or_default();
    format!(
        "{{\"target\":\"{}\",\"signature\":\"{}\",\"product\":\"{}\",\
\"status\":\"{}\",\"version\":\"{}\",\"cves\":\"{}\",\"detail\":\"{}\",\
\"actionable\":{}}}",
        esc(&r.target),
        esc(&r.signature),
        esc(&r.product),
        r.status.as_str(),
        esc(&version),
        esc(&r.cves),
        esc(&r.detail),
        r.status.is_actionable(),
    )
}

fn json_err(msg: &str) -> String {
    format!("{{\"error\":\"{}\"}}", esc(msg))
}

/// Escape a string for embedding in a JSON string literal.
fn esc(s: &str) -> String {
    json_escape(s)
}

/// Public JSON-string escaper, shared with the CLI report writer.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Decode %XX and + in a query value.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex(bytes[i + 1]);
                let lo = hex(bytes[i + 2]);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The single-page UI. Self-contained, no external assets.
const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>php2shell website scanner</title>
<style>
:root{--bg:#0f1117;--card:#191c24;--fg:#e6e8ec;--muted:#9aa0ac;--line:#2a2e38;
--red:#ff5c5c;--green:#3fd27e;--amber:#f5c451;--grey:#6b7280;--accent:#6ea8fe}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
padding:16px}
.wrap{max-width:720px;margin:0 auto}
h1{font-size:22px;margin:24px 0 4px}
.sub{color:var(--muted);margin:0 0 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px;margin-bottom:16px}
label{display:block;margin:12px 0 6px;color:var(--muted);font-size:14px}
input[type=text]{width:100%;padding:12px;border-radius:8px;border:1px solid var(--line);
background:#11131a;color:var(--fg);font-size:15px}
.row{display:flex;gap:8px;align-items:flex-start;margin:12px 0}
.row input{margin-top:4px}
button{margin-top:16px;width:100%;padding:12px;border:0;border-radius:8px;
background:var(--accent);color:#06101f;font-weight:600;font-size:15px;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
.result{display:none;margin-top:8px}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:700;
font-size:13px;letter-spacing:.02em}
.VULNERABLE,.EOL_VULNERABLE{background:rgba(255,92,92,.15);color:var(--red)}
.PATCHED{background:rgba(63,210,126,.15);color:var(--green)}
.UNKNOWN_VERSION{background:rgba(245,196,81,.15);color:var(--amber)}
.NOT_DETECTED{background:rgba(107,114,128,.18);color:var(--grey)}
.kv{color:var(--muted);font-size:14px;margin:8px 0 0}
.kv b{color:var(--fg);font-weight:600}
.note{color:var(--muted);font-size:13px;margin-top:10px}
code{background:#11131a;padding:1px 6px;border-radius:5px}
a{color:var(--accent)}
</style>
</head>
<body>
<div class="wrap">
  <h1>php2shell website scanner</h1>
  <p class="sub">Passive check for CVE-2026-109618 / CVE-2026-109619. Reads the
  PHP version your server exposes. No exploit is sent.</p>

  <div class="card">
    <label for="sig">Vulnerability</label>
    <select id="sig" style="width:100%;padding:12px;border-radius:8px;border:1px solid var(--line);background:#11131a;color:var(--fg);font-size:15px">
      <option value="php2shell">php2shell — PHP RCE (CVE-2026-109618/109619)</option>
      <option value="react2shell">react2shell — Next.js/RSC RCE (CVE-2025-55182)</option>
    </select>
    <label for="url">Website URL</label>
    <input id="url" type="text" placeholder="https://example.com" autocomplete="off">
    <div class="row">
      <input id="auth" type="checkbox">
      <label for="auth" style="margin:0">I own this site or am authorised to test it.
      localhost and private networks are blocked.</label>
    </div>
    <button id="go" disabled>Check my website</button>
    <div id="result" class="result card" style="background:#11131a"></div>
  </div>

  <div class="card">
    <h3 style="margin-top:0">About the check</h3>
    <p class="note">This reads the version string your server discloses
    (<code>X-Powered-By</code>, <code>Server</code>). It never sends an attack
    payload and cannot crash a worker.</p>
    <p class="note"><b>A clean result does not guarantee safety.</b> Many
    hardened servers hide their version, so you may see
    <span class="badge UNKNOWN_VERSION">UNKNOWN_VERSION</span>. Confirm on the
    host with <code>php -v</code> and patch to 8.5.12 / 8.4.27 / 8.3.36 /
    8.2.35, or move off an end-of-life branch (8.1 and older).</p>
    <p class="note">Do not put secrets in the URL.</p>
  </div>
</div>
<script>
const url=document.getElementById('url'),auth=document.getElementById('auth'),
go=document.getElementById('go'),out=document.getElementById('result'),
sig=document.getElementById('sig');
function sync(){go.disabled=!(auth.checked && url.value.trim());}
auth.addEventListener('change',sync);url.addEventListener('input',sync);
go.addEventListener('click',async()=>{
  go.disabled=true;out.style.display='block';out.textContent='Checking…';
  try{
    const r=await fetch('/api/scan?sig='+encodeURIComponent(sig.value)+'&url='+encodeURIComponent(url.value.trim()));
    const d=await r.json();
    if(d.error){out.textContent='Error: '+d.error;sync();return;}
    const v=d.version?(' '+d.version):'';
    out.innerHTML='<span class="badge '+d.status+'">'+d.status+'</span>'
      +'<p class="kv"><b>'+d.product+v+'</b> — '+d.detail+'</p>'
      +'<p class="kv">'+d.cves+'</p>';
  }catch(e){out.textContent='Request failed: '+e;}
  sync();
});
</script>
</body>
</html>
"#;


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn permits_enforce_limit_under_contention_and_release() {
        const WORKERS: usize = 48;
        let inflight = AtomicUsize::new(0);
        let start = Barrier::new(WORKERS);
        let acquired = Barrier::new(WORKERS + 1);
        let release = Barrier::new(WORKERS + 1);
        let successes = AtomicUsize::new(0);
        thread::scope(|scope| {
            for _ in 0..WORKERS {
                scope.spawn(|| {
                    start.wait();
                    let permit = ScanPermit::acquire(&inflight);
                    if permit.is_some() {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                    acquired.wait();
                    release.wait();
                    drop(permit);
                });
            }
            acquired.wait();
            let held = inflight.load(Ordering::SeqCst);
            let admitted = successes.load(Ordering::SeqCst);
            let overflow = ScanPermit::acquire(&inflight);
            let at_capacity = overflow.is_none();
            drop(overflow);
            release.wait();
            // Release waiting workers even if an assertion detects a regression.
            assert_eq!(held, MAX_INFLIGHT);
            assert_eq!(admitted, MAX_INFLIGHT);
            assert!(at_capacity);
        });
        assert_eq!(inflight.load(Ordering::SeqCst), 0);
        drop(ScanPermit::acquire(&inflight).unwrap());
        assert_eq!(inflight.load(Ordering::SeqCst), 0);
        let _ = std::panic::catch_unwind(|| {
            let _permit = ScanPermit::acquire(&inflight).unwrap();
            panic!("simulate worker panic");
        });
        assert_eq!(inflight.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn busy_endpoint_returns_503_and_does_not_change_count() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap();
        let worker = thread::spawn(move || {
            let count = AtomicUsize::new(MAX_INFLIGHT);
            handle_request(
                server
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .unwrap(),
                Duration::from_secs(1),
                &count,
            );
            assert_eq!(count.load(Ordering::SeqCst), MAX_INFLIGHT);
        });
        let response = ureq::get(&format!("http://{address}/api/scan?url=127.0.0.1")).call();
        match response {
            Err(ureq::Error::Status(503, response)) => {
                assert_eq!(response.into_string().unwrap(), "{\"error\":\"busy\"}")
            }
            _ => panic!("expected busy 503 response"),
        }
        worker.join().unwrap();
    }

    #[test]
    fn http_distro_evidence_and_caveat_reach_web_json() {
        let (url, server) = crate::scan::tests::http_fixture(vec![(
            crate::scan::tests::response("X-Powered-By: PHP/8.3.6-0ubuntu0.24.04.13\r\n", ""),
            Duration::ZERO,
        )]);
        let result = scan_one(
            &url,
            signatures::by_name("php2shell").unwrap(),
            Duration::from_secs(1),
            true,
        );
        assert_eq!(result.version.as_deref(), Some("8.3.6-0ubuntu0.24.04.13"));
        assert_eq!(result.status, signatures::Status::Vulnerable);
        let json = scan_json(&result);
        assert!(json.contains("\"version\":\"8.3.6-0ubuntu0.24.04.13\""));
        assert!(json.contains("fixes may be backported"));
        assert!(json.contains("\"actionable\":true"));
        server.join().unwrap();
        // The public endpoint must still refuse localhost, regardless of query options.
        let blocked = handle_scan(
            "/api/scan?url=http%3A%2F%2F127.0.0.1&allow_private=true",
            Duration::from_secs(1),
        );
        assert!(blocked.contains("\"status\":\"ERROR\""));
    }
}
