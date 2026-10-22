//! Observable CLI contracts, using only scripted loopback HTTP responses.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

fn scanner(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scanner"))
        .args(args)
        .arg("--no-color")
        .output()
        .unwrap()
}

fn fixture(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "scanner did not connect");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        stream.write_all(&response).unwrap();
    });
    (url, handle)
}

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("scanner-regression-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn canary_exit_codes_and_original_evidence() {
    for (version, status, code) in [
        ("14.3.0-canary.76", "PATCHED", 0),
        ("14.3.0-canary.77", "VULNERABLE", 2),
        ("15.6.0-canary.58", "PATCHED", 0),
        ("16.1.0-canary.12", "PATCHED", 0),
    ] {
        let out = scanner(&["--sig", "react2shell", "--version", version]);
        assert_eq!(out.status.code(), Some(code));
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.contains(version), "{text}");
        assert!(text.contains(status), "{text}");
    }
    let version = "8.3.6-0ubuntu0.24.04.13";
    let out = scanner(&["--version", version]);
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(version));
    assert!(text.contains("fixes may be backported"));
}

#[test]
fn incomplete_body_is_visible_error_with_exit_one_and_json() {
    let scratch = Scratch::new();
    let report = scratch.0.join("report.json");
    let (url, server) = fixture(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\nshort".to_vec(),
    );
    let out = scanner(&[
        "--allow-private",
        "--vuln-only",
        "--json",
        report.to_str().unwrap(),
        &url,
    ]);
    server.join().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("ERROR"), "{text}");
    assert!(text.contains("response body read failed"));
    let json = std::fs::read_to_string(report).unwrap();
    assert!(json.contains("\"status\":\"ERROR\""));
    assert!(!json.contains("NOT_DETECTED"));
}

#[test]
fn http_distro_evidence_reaches_cli_and_report() {
    let scratch = Scratch::new();
    let report = scratch.0.join("report.json");
    let (url, server) = fixture(b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.3.6-0ubuntu0.24.04.13\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec());
    let out = scanner(&["--allow-private", "--json", report.to_str().unwrap(), &url]);
    server.join().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("8.3.6-0ubuntu0.24.04.13"));
    assert!(text.contains("fixes may be backported"));
    let json = std::fs::read_to_string(report).unwrap();
    assert!(json.contains("\"version\":\"8.3.6-0ubuntu0.24.04.13\""));
    assert!(json.contains("fixes may be backported"));
}

#[test]
fn blocked_target_remains_visible_under_vuln_only() {
    let out = scanner(&["--vuln-only", "http://127.0.0.1/"]);
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("ERROR"));
    assert!(text.contains("refused"));
}

#[test]
fn report_write_failure_exits_one_after_clean_scan() {
    let scratch = Scratch::new();
    let report = scratch.0.join("missing").join("report.json");
    let (url, server) =
        fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec());
    let out = scanner(&["--allow-private", "--json", report.to_str().unwrap(), &url]);
    server.join().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("NOT_DETECTED"));
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("cannot write"));
}
