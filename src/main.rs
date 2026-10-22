//! websitescanner — passive version-detection scanner for known CVEs.
//!
//! Two modes:
//!   scanner [options] <targets...>   scan hosts from the CLI
//!   scanner serve [--addr host:port] run the web UI
//!
//! It makes ordinary GET requests and reads the version the server discloses.
//! No exploit payload is sent. Authorised testing only.

mod scan;
mod signatures;
mod web;

use std::process::exit;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use scan::{scan_one, ScanResult};
use signatures::Status;

const DEFAULT_WORKERS: usize = 10;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_ADDR: &str = "127.0.0.1:8080";

struct Opts {
    targets: Vec<String>,
    file: Option<String>,
    sig: String,
    workers: usize,
    timeout: Duration,
    json: Option<String>,
    vuln_only: bool,
    no_colour: bool,
    allow_private: bool,
    active: bool,
    authorized: bool,
    local: bool,
    version_text: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "websitescanner — passive CVE version-detection (authorised testing only)\n\n\
Scan mode:\n\
  scanner [opts] <url|host> [more...]\n\
  scanner -f targets.txt\n\n\
Options:\n\
  -f, --file <path>     read targets, one per line (# comments ok)\n\
      --sig <name>      signature: php2shell (default), react2shell\n\
      --workers <n>     concurrent hosts (default {DEFAULT_WORKERS})\n\
      --timeout <secs>  per-request timeout (default {DEFAULT_TIMEOUT_SECS})\n\
      --json <path>     write a JSON report\n\
      --vuln-only       print only vulnerable / EOL hosts\n\
      --no-colour       plain output\n\
      --allow-private   allow localhost / private IP targets (CLI only)\n\n\
Host-side version check (definitive, no network to any target):\n\
      --version <v>     classify a version you already have, e.g. from\n\
                        `php -v` or `npm ls next`, against --sig's matrix\n\
      --local           run `php -v` on THIS machine and classify it\n\n\
Active probe (react2shell only, authorised testing):\n\
      --active          send the non-executing error-signature probe instead\n\
                        of the passive check. Needs --i-am-authorized. CLI only.\n\
      --i-am-authorized confirm you own or may test these hosts\n\n\
Web mode:\n\
  scanner serve [--addr {DEFAULT_ADDR}] [--timeout <secs>]\n"
    );
    exit(2);
}

fn parse_args() -> (bool, Opts, String) {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let serve = args.first().map(|a| a == "serve").unwrap_or(false);
    if serve {
        args.remove(0);
    }

    let mut o = Opts {
        targets: Vec::new(),
        file: None,
        sig: "php2shell".into(),
        workers: DEFAULT_WORKERS,
        timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        json: None,
        vuln_only: false,
        no_colour: false,
        allow_private: false,
        active: false,
        authorized: false,
        local: false,
        version_text: None,
    };
    let mut addr = DEFAULT_ADDR.to_string();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let mut next = || {
            i += 1;
            args.get(i).cloned().unwrap_or_else(|| usage())
        };
        match a.as_str() {
            "-h" | "--help" => usage(),
            "-f" | "--file" => o.file = Some(next()),
            "--sig" => o.sig = next(),
            "--workers" => o.workers = next().parse().unwrap_or(DEFAULT_WORKERS).max(1),
            "--timeout" => {
                o.timeout = Duration::from_secs(next().parse().unwrap_or(DEFAULT_TIMEOUT_SECS))
            }
            "--json" => o.json = Some(next()),
            "--addr" => addr = next(),
            "--vuln-only" => o.vuln_only = true,
            "--no-colour" | "--no-color" => o.no_colour = true,
            "--allow-private" => o.allow_private = true,
            "--active" => o.active = true,
            "--i-am-authorized" => o.authorized = true,
            "--local" => o.local = true,
            "--version" => o.version_text = Some(next()),
            s if s.starts_with('-') => {
                eprintln!("unknown option: {s}");
                usage();
            }
            _ => o.targets.push(a.clone()),
        }
        i += 1;
    }
    (serve, o, addr)
}

fn load_targets(o: &Opts) -> Vec<String> {
    let mut targets = o.targets.clone();
    if let Some(path) = &o.file {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                for line in text.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        targets.push(line.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("cannot read {path}: {e}");
                exit(2);
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    targets.retain(|t| seen.insert(t.clone()));
    targets
}

fn colour_for(status: Status) -> &'static str {
    match status {
        Status::Vulnerable | Status::Eol => "\x1b[1;31m",
        Status::PossiblyVulnerable => "\x1b[1;35m", // magenta: a lead, confirm
        Status::Patched => "\x1b[1;32m",
        Status::UnknownVersion => "\x1b[1;33m",
        Status::NotDetected => "\x1b[0;90m",
        Status::Error => "\x1b[1;36m", // cyan: the scan failed, not a verdict
    }
}

fn print_table(results: &[ScanResult], use_colour: bool) {
    let width = results.iter().map(|r| r.target.len()).max().unwrap_or(10);
    for r in results {
        let (c, reset) = if use_colour {
            (colour_for(r.status), "\x1b[0m")
        } else {
            ("", "")
        };
        let v = r.version.clone().unwrap_or_else(|| "-".into());
        println!(
            "{:<width$}  {c}{:<16}{reset}  {} {:<12}  {}",
            r.target, r.status.as_str(), r.product, v, r.detail,
            width = width
        );
    }
}

/// Write the JSON report. Returns false if the file could not be written.
fn write_json(results: &[ScanResult], path: &str) -> bool {
    let mut s = String::from("[\n");
    for (i, r) in results.iter().enumerate() {
        let v = match &r.version {
            Some(v) => format!("\"{}\"", web::json_escape(v)),
            None => "null".to_string(),
        };
        s.push_str(&format!(
            "  {{\"target\":\"{}\",\"signature\":\"{}\",\"product\":\"{}\",\
\"status\":\"{}\",\"version\":{},\"cves\":\"{}\",\"detail\":\"{}\"}}",
            web::json_escape(&r.target),
            web::json_escape(&r.signature),
            web::json_escape(&r.product),
            r.status.as_str(),
            v,
            web::json_escape(&r.cves),
            web::json_escape(&r.detail),
        ));
        s.push_str(if i + 1 < results.len() { ",\n" } else { "\n" });
    }
    s.push_str("]\n");
    // Report the write failure to the caller so it reaches the exit code.
    match std::fs::write(path, s) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("cannot write {path}: {e}");
            false
        }
    }
}

fn run_scan(o: Opts) -> i32 {
    let sig = match signatures::by_name(&o.sig) {
        Some(s) => s,
        None => {
            eprintln!("unknown signature: {}", o.sig);
            return 2;
        }
    };
    // Gate the active probe: react2shell only, and only with explicit consent.
    if o.active {
        if o.sig != "react2shell" {
            eprintln!("error: --active is only implemented for --sig react2shell");
            return 2;
        }
        if !o.authorized {
            eprintln!(
                "error: --active sends a crafted POST to each target to trigger a\n\
         vulnerable error signature. Re-run with --i-am-authorized to confirm\n\
         you own or are authorised to test these hosts. It is never exposed in\n\
         the web UI."
            );
            return 2;
        }
        eprintln!("# ACTIVE error-signature probe enabled (authorised). No code is executed on targets.\n");
    }

    let targets = load_targets(&o);
    if targets.is_empty() {
        eprintln!("no targets given (use -u arguments or -f file)");
        return 2;
    }

    eprintln!("# scanner: {}  ({})", sig.name, sig.cves.join(", "));
    eprintln!("# {}", sig.description);
    eprintln!("# {} target(s), {} worker(s)\n", targets.len(), o.workers);

    // Simple fan-out: a bounded set of worker threads over a shared queue.
    let (tx_job, rx_job) = mpsc::channel::<(usize, String)>();
    let (tx_res, rx_res) = mpsc::channel::<(usize, ScanResult)>();
    let rx_job = std::sync::Arc::new(std::sync::Mutex::new(rx_job));

    let timeout = o.timeout;
    let allow_private = o.allow_private;
    let active = o.active;
    let mut handles = Vec::new();
    for _ in 0..o.workers.min(targets.len()) {
        let rx_job = rx_job.clone();
        let tx_res = tx_res.clone();
        handles.push(thread::spawn(move || loop {
            let job = { rx_job.lock().unwrap().recv() };
            match job {
                Ok((idx, target)) => {
                    let r = if active {
                        scan::active_probe_react2shell(&target, timeout, allow_private)
                    } else {
                        scan_one(&target, sig, timeout, allow_private)
                    };
                    let _ = tx_res.send((idx, r));
                }
                Err(_) => break,
            }
        }));
    }
    drop(tx_res);
    for (idx, t) in targets.iter().enumerate() {
        tx_job.send((idx, t.clone())).unwrap();
    }
    drop(tx_job);

    let mut results: Vec<Option<ScanResult>> = (0..targets.len()).map(|_| None).collect();
    for (idx, r) in rx_res {
        results[idx] = Some(r);
    }
    for h in handles {
        let _ = h.join();
    }
    let results: Vec<ScanResult> = results.into_iter().flatten().collect();

    // --vuln-only still surfaces scan ERRORs, so a failed scan never silently
    // vanishes from the output.
    let shown: Vec<&ScanResult> = if o.vuln_only {
        results.iter().filter(|r| r.status.is_actionable() || r.status.is_error()).collect()
    } else {
        results.iter().collect()
    };
    let use_colour = !o.no_colour && atty_stdout();
    let shown_owned: Vec<ScanResult> = shown
        .iter()
        .map(|r| ScanResult {
            target: r.target.clone(),
            signature: r.signature.clone(),
            product: r.product.clone(),
            status: r.status,
            version: r.version.clone(),
            cves: r.cves.clone(),
            detail: r.detail.clone(),
        })
        .collect();
    print_table(&shown_owned, use_colour);

    let mut write_ok = true;
    if let Some(path) = &o.json {
        write_ok = write_json(&results, path);
    }

    // Summary line.
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for r in &results {
        *counts.entry(r.status.as_str()).or_default() += 1;
    }
    let summary: Vec<String> = counts.iter().map(|(k, v)| format!("{k}={v}")).collect();
    eprintln!("\n# done  |  {}", summary.join("  "));

    // Exit code: 2 if any host is actionable, else 1 on any scan error or a
    // failed report write (so failures never look like a clean run), else 0.
    let any_vuln = results.iter().any(|r| r.status.is_actionable());
    let any_error = results.iter().any(|r| r.status.is_error());
    if any_vuln {
        2
    } else if any_error || !write_ok {
        1
    } else {
        0
    }
}

/// Classify a known version string against the selected signature and print a
/// one-line verdict. No network. Returns the process exit code.
fn classify_and_report(sig: &signatures::Signature, version: &str) -> i32 {
    let (status, _) = sig.classify(Some(version));
    let shown = version.trim();
    let mut detail = match status {
        Status::Vulnerable => "affected, below the fixed release — patch now",
        Status::Eol => "end-of-life branch, no official fix — upgrade the runtime",
        Status::Patched => "at or above the fixed release / below the affected range — not vulnerable",
        Status::UnknownVersion => "version not recognised against the matrix",
        Status::NotDetected => "no version given",
        Status::PossiblyVulnerable => "error signature (active probe only)",
        Status::Error => "scan error",
    }
    .to_string();

    signatures::append_backport_caveat(&mut detail, status, Some(version));

    println!("{} {}  {}  {}", sig.product, shown, status.as_str(), detail);
    if status.is_actionable() { 2 } else { 0 }
}

/// --version: classify a pasted version, nothing else.
fn run_version(o: &Opts) -> i32 {
    let sig = match signatures::by_name(&o.sig) {
        Some(s) => s,
        None => { eprintln!("unknown signature: {}", o.sig); return 2; }
    };
    classify_and_report(sig, o.version_text.as_deref().unwrap())
}

/// --local: run `php -v` on this machine and classify it (php2shell).
fn run_local(o: &Opts) -> i32 {
    if o.sig != "php2shell" {
        eprintln!(
            "--local runs `php -v`, which only applies to --sig php2shell.\n\
             For react2shell, run `npm ls next` in the app dir and pass it with\n\
             --version, e.g.: scanner --sig react2shell --version 14.2.35"
        );
        return 2;
    }
    let out = match std::process::Command::new("php").arg("-v").output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("cannot run `php -v`: {e} (is PHP on PATH on this host?)");
            return 2;
        }
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // First line looks like: "PHP 8.3.12 (cli) (built: ...)".
    let version = text
        .split_whitespace()
        .nth(1)
        .filter(|v| v.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false));
    match version {
        Some(v) => {
            let sig = signatures::by_name("php2shell").unwrap();
            println!("# local host: php -v reports {v}");
            classify_and_report(sig, v)
        }
        None => {
            eprintln!("could not parse a version from `php -v` output");
            2
        }
    }
}

/// Best-effort TTY check without a dependency.
fn atty_stdout() -> bool {
    // If NO_COLOR is set, honour it. Otherwise assume a terminal.
    std::env::var_os("NO_COLOR").is_none()
}

fn main() {
    let (serve, opts, addr) = parse_args();
    if serve {
        if let Err(e) = web::serve(&addr, opts.timeout) {
            eprintln!("{e}");
            exit(1);
        }
        return;
    }
    // Host-side version checks: no target needed, no network to any site.
    if opts.version_text.is_some() {
        exit(run_version(&opts));
    }
    if opts.local {
        exit(run_local(&opts));
    }
    exit(run_scan(opts));
}
