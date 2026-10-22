//! Vulnerability signatures and version classification.
//!
//! Detection is NON-INTRUSIVE: it reads the version a server already discloses
//! in its HTTP response (headers / a leaked error page). No exploit payload is
//! ever sent. Add a new CVE by appending a `Signature` to `all()`.

use std::collections::HashMap;

/// Outcome of comparing an exposed version against the fixed releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Vulnerable,        // affected version, below the fixed release
    Eol,               // end-of-life branch, no official fix
    Patched,           // at or above the fixed release
    PossiblyVulnerable, // active probe saw the vulnerable error signature
    UnknownVersion,    // product present, version not disclosed
    NotDetected,       // product fingerprint not found
    Error,             // the scan itself failed (DNS, connection, TLS, refused)
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Vulnerable => "VULNERABLE",
            Status::Eol => "EOL_VULNERABLE",
            Status::Patched => "PATCHED",
            Status::PossiblyVulnerable => "POSSIBLY_VULNERABLE",
            Status::UnknownVersion => "UNKNOWN_VERSION",
            Status::NotDetected => "NOT_DETECTED",
            Status::Error => "ERROR",
        }
    }
    /// True for states an operator must act on.
    pub fn is_actionable(self) -> bool {
        matches!(self, Status::Vulnerable | Status::Eol | Status::PossiblyVulnerable)
    }
    /// True when the scan could not produce a verdict (counts toward exit code).
    pub fn is_error(self) -> bool {
        matches!(self, Status::Error)
    }
}

/// A semantic version as (major, minor, patch).
pub type Version = (u32, u32, u32);

/// Parse "8.3.12" or "8.3" into a comparable tuple. Leading digits per part,
/// so "27-ubuntu" -> 27. Returns None when no numeric component is found.
pub fn parse_version(text: &str) -> Option<Version> {
    let mut nums: Vec<u32> = Vec::new();
    for part in text.trim().split('.') {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        match digits.parse::<u32>() {
            Ok(n) => nums.push(n),
            Err(_) => break,
        }
    }
    if nums.is_empty() {
        return None;
    }
    while nums.len() < 3 {
        nums.push(0);
    }
    Some((nums[0], nums[1], nums[2]))
}

/// Does a version string carry a distro/build suffix (e.g.
/// "8.3.6-0ubuntu0.24.04.13", "7.2.34-18+ubuntu16.04.1+deb.sury.org+1")?
///
/// Distributions backport security fixes WITHOUT changing the upstream x.y.z, so
/// an upstream-version verdict for such a package can be a false positive. When
/// this is true the caller adds a "verify against your distro advisory" caveat.
pub fn has_distro_build_suffix(version_text: &str) -> bool {
    // Strip the leading numeric x.y.z, then look for a distro marker in the rest.
    let tail: String = version_text
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.')
        .to_ascii_lowercase();
    if tail.is_empty() {
        return false;
    }
    const MARKERS: [&str; 10] =
        ["ubuntu", "deb", "sury", "+", "~", ".el", "rhel", "fc", "amzn", "centos"];
    MARKERS.iter().any(|m| tail.contains(m))
}

/// Shared uncertainty notice for actionable upstream-version assessments.
pub fn append_backport_caveat(detail: &mut String, status: Status, version: Option<&str>) {
    if status.is_actionable() && version.is_some_and(has_distro_build_suffix) {
        detail.push_str(
            "  [distro build: fixes may be backported without changing this version — \
verify against your distro's security advisory]",
        );
    }
}

/// Lower-cased response headers, looked up case-insensitively.
pub struct Headers(pub HashMap<String, String>);

impl Headers {
    pub fn get(&self, key: &str) -> &str {
        self.0.get(&key.to_ascii_lowercase()).map(|s| s.as_str()).unwrap_or("")
    }
}

/// One vulnerability definition.
pub struct Signature {
    pub name: &'static str,
    pub cves: &'static [&'static str],
    pub product: &'static str,
    pub description: &'static str,
    /// Reads headers/body, returns the product version string if fingerprinted.
    pub extract_version: fn(&Headers, &str) -> Option<String>,
    /// Fixed patch level per "major.minor" branch.
    pub fixed_by_branch: &'static [((u32, u32), Version)],
    /// Branches that are affected but end-of-life (no official fix).
    pub eol_branches: &'static [(u32, u32)],
    /// How to treat a branch OLDER than every branch we track. For PHP, older
    /// means end-of-life and affected. For react2shell, older than 15.x (e.g.
    /// stable 14.2.x) is below the affected range and NOT vulnerable.
    pub below_range_is_eol: bool,

}

impl Signature {
    /// Classify an optionally-extracted version string.
    pub fn classify(&self, version_text: Option<&str>) -> (Status, Option<Version>) {
        let text = match version_text {
            None => return (Status::NotDetected, None),
            Some(t) => t,
        };
        if self.name == "react2shell" {
            return self.classify_react(text);
        }
        let version = match parse_version(text) {
            None => return (Status::UnknownVersion, None),
            Some(v) => v,
        };
        let branch = (version.0, version.1);

        // Known maintained branch: compare against its fixed release.
        for (b, fixed) in self.fixed_by_branch {
            if *b == branch {
                if version >= *fixed {
                    return (Status::Patched, Some(version));
                }
                return (Status::Vulnerable, Some(version));
            }
        }
        // Known end-of-life branch.
        if self.eol_branches.contains(&branch) {
            return (Status::Eol, Some(version));
        }
        // Older than every branch we track: still end-of-life and affected.
        let oldest = self
            .fixed_by_branch
            .iter()
            .map(|(b, _)| *b)
            .chain(self.eol_branches.iter().copied())
            .min();
        if let Some(oldest) = oldest {
            if branch < oldest {
                if self.below_range_is_eol {
                    return (Status::Eol, Some(version));
                }
                // Below the affected range entirely: not vulnerable.
                return (Status::Patched, Some(version));
            }
        }
        // Untracked newer branches need an advisory update before a verdict.
        (Status::UnknownVersion, Some(version))
    }

    fn classify_react(&self, text: &str) -> (Status, Option<Version>) {
        let v = match semver::Version::parse(text.trim()) {
            Ok(v) => v,
            Err(_) => return (Status::UnknownVersion, None),
        };
        let numeric = match (
            u32::try_from(v.major),
            u32::try_from(v.minor),
            u32::try_from(v.patch),
        ) {
            (Ok(a), Ok(b), Ok(c)) => (a, b, c),
            _ => return (Status::UnknownVersion, None),
        };
        let outcome = |status| (status, Some(numeric));
        if !v.pre.is_empty() {
            // Only advisory-supported canary identifiers are classified. Compare
            // numeric identifiers with SemVer ordering, never lexical ordering.
            let parts: Vec<_> = v.pre.as_str().split('.').collect();
            if parts.len() != 2
                || parts[0] != "canary"
                || !parts[1].bytes().all(|c| c.is_ascii_digit())
            {
                return outcome(Status::UnknownVersion);
            }
            let threshold = match numeric {
                (14, 3, 0) => Some(("14.3.0-canary.77", false)),
                (15, 6, 0) => Some(("15.6.0-canary.58", true)),
                (16, 1, 0) => Some(("16.1.0-canary.12", true)),
                _ => None,
            };
            if let Some((boundary, fixed)) = threshold {
                let at_or_above = v
                    .cmp_precedence(&semver::Version::parse(boundary).unwrap())
                    .is_ge();
                return outcome(if at_or_above == fixed {
                    Status::Patched
                } else {
                    Status::Vulnerable
                });
            }
            if !matches!(v.major, 15 | 16) {
                return outcome(Status::UnknownVersion);
            }
            // Known stable Next.js branches can still compare against the stable fix:
            // 15.3.6-canary.N precedes 15.3.6 and remains affected.
        } else if v.major < 15 {
            return outcome(Status::Patched);
        }
        for (branch, fixed) in self.fixed_by_branch {
            if *branch == (numeric.0, numeric.1) {
                let fixed = semver::Version::new(fixed.0.into(), fixed.1.into(), fixed.2.into());
                return outcome(if v.cmp_precedence(&fixed).is_ge() {
                    Status::Patched
                } else {
                    Status::Vulnerable
                });
            }
        }
        outcome(Status::UnknownVersion)
    }
}

/// Find a "PHP/x.y.z" token in a header or body string.
fn find_php_version(text: &str) -> Option<String> {
    // Keep the full package version token, stopping at surrounding punctuation.
    let lower = text.to_ascii_lowercase();
    let idx = lower.find("php/")?;
    let rest = &text[idx + 4..];
    let ver: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '~' | '_'))
        .collect();
    let trimmed = ver.trim_end_matches('.');
    if trimmed.starts_with(|c: char| c.is_ascii_digit()) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// php2shell version extraction: X-Powered-By, Server, leaked body, then a
/// "PHP present but version hidden" fallback via PHPSESSID / X-Powered-By.
fn php_extract(headers: &Headers, body: &str) -> Option<String> {
    for header in ["x-powered-by", "server"] {
        if let Some(v) = find_php_version(headers.get(header)) {
            return Some(v);
        }
    }
    if let Some(v) = find_php_version(body) {
        return Some(v);
    }
    let set_cookie = headers.get("set-cookie").to_ascii_lowercase();
    let powered = headers.get("x-powered-by").to_ascii_lowercase();
    if set_cookie.contains("phpsessid") || powered.contains("php") {
        // Present but no version -> classify() yields UNKNOWN_VERSION.
        return Some("unknown".to_string());
    }
    None
}

/// react2shell (CVE-2025-55182): passive framework fingerprint.
///
/// Next.js and React Server Components do NOT expose their version over HTTP, so
/// a passive scan can only confirm the framework is present, not its version. A
/// definitive vulnerable/patched verdict needs the active differential probe
/// (see README), which this passive function deliberately does not perform.
///
/// Returns Some(version) if a version ever leaks (classified against the matrix
/// below), Some("unknown") when the framework is detected without a version
/// (-> UNKNOWN_VERSION), or None when no Next.js/RSC marker is found.
fn react_extract(headers: &Headers, body: &str) -> Option<String> {
    let mut detected = false;

    // 1. X-Powered-By: Next.js  (default header unless poweredByHeader:false).
    if headers.get("x-powered-by").to_ascii_lowercase().contains("next.js") {
        detected = true;
    }
    // 2. App Router response headers.
    for h in ["x-nextjs-cache", "x-nextjs-prerender", "x-nextjs-stale-time"] {
        if !headers.get(h).is_empty() {
            detected = true;
        }
    }
    // 3. HTML markers for Next.js / RSC streaming.
    for marker in ["/_next/static/", "__NEXT_DATA__", "self.__next_f"] {
        if body.contains(marker) {
            detected = true;
        }
    }

    if detected {
        // Version is essentially never disclosed -> UNKNOWN_VERSION.
        Some("unknown".to_string())
    } else {
        None
    }
}

const PHP2SHELL: Signature = Signature {
    name: "php2shell",
    cves: &["CVE-2026-109618", "CVE-2026-109619"],
    product: "PHP",
    description: "Two critical PHP core RCE flaws (CVSSv4 9.2, unauthenticated RCE), \
patched 2026-10-21. Fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.",
    extract_version: php_extract,
    fixed_by_branch: &[
        ((8, 5), (8, 5, 12)),
        ((8, 4), (8, 4, 27)),
        ((8, 3), (8, 3, 36)),
        ((8, 2), (8, 2, 35)),
    ],
    // 8.1 and older are end-of-life: affected, no official binary release.
    eol_branches: &[
        (8, 1), (8, 0),
        (7, 4), (7, 3), (7, 2), (7, 1), (7, 0),
        (5, 6), (5, 4),
    ],
    // Pre-5.4 PHP is older still and just as end-of-life.
    below_range_is_eol: true,
};

const REACT2SHELL: Signature = Signature {
    name: "react2shell",
    cves: &["CVE-2025-55182"],
    product: "Next.js / RSC",
    description: "React Server Components RCE (max severity, unauthenticated). \
Next.js fixed in 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7; \
react-server-dom-* fixed in 19.0.1 / 19.1.2 / 19.2.1. Passive scan detects the \
framework only; version is not exposed over HTTP.",
    extract_version: react_extract,
    // Next.js patched release per minor branch. react-server-dom-* 19.x branches
    // are included too; both share the (major,minor)->fixed-patch model.
    fixed_by_branch: &[
        // Next.js 15.x / 16.x
        ((15, 0), (15, 0, 5)),
        ((15, 1), (15, 1, 9)),
        ((15, 2), (15, 2, 6)),
        ((15, 3), (15, 3, 6)),
        ((15, 4), (15, 4, 8)),
        ((15, 5), (15, 5, 7)),
        ((16, 0), (16, 0, 7)),
        // react-server-dom-webpack / -parcel / -turbopack 19.x
        ((19, 0), (19, 0, 1)),
        ((19, 1), (19, 1, 2)),
        ((19, 2), (19, 2, 1)),
    ],
    eol_branches: &[],
    // Next.js < 15 (e.g. stable 14.2.x) is below the affected range, not EOL.
    below_range_is_eol: false,
};

/// All registered signatures.
pub fn all() -> Vec<&'static Signature> {
    vec![&PHP2SHELL, &REACT2SHELL]
}

/// Look up a signature by name.
pub fn by_name(name: &str) -> Option<&'static Signature> {
    all().into_iter().find(|s| s.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        assert_eq!(parse_version("8.3.12"), Some((8, 3, 12)));
        assert_eq!(parse_version("8.3"), Some((8, 3, 0)));
        assert_eq!(parse_version("8.4.27-ubuntu"), Some((8, 4, 27)));
        assert_eq!(parse_version("unknown"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn classifies_php2shell() {
        let s = by_name("php2shell").unwrap();
        let cases = [
            ("8.3.12", Status::Vulnerable),
            ("8.3.36", Status::Patched),
            ("8.3.40", Status::Patched),
            ("8.2.35", Status::Patched),
            ("8.2.10", Status::Vulnerable),
            ("8.5.12", Status::Patched),
            ("8.5.11", Status::Vulnerable),
            ("8.1.20", Status::Eol),
            ("7.4.33", Status::Eol),
            ("5.6.40", Status::Eol),
            ("8.9.0", Status::UnknownVersion),
            ("unknown", Status::UnknownVersion),
        ];
        for (ver, want) in cases {
            let (got, _) = s.classify(Some(ver));
            assert_eq!(got, want, "version {ver}");
        }
        assert_eq!(s.classify(None).0, Status::NotDetected);
    }

    #[test]
    fn extracts_php_version() {
        let s = by_name("php2shell").unwrap();
        let mut h = HashMap::new();
        h.insert("x-powered-by".into(), "PHP/8.3.12".into());
        assert_eq!((s.extract_version)(&Headers(h), ""), Some("8.3.12".into()));

        let mut h = HashMap::new();
        h.insert("server".into(), "Apache/2.4.58 (Unix) PHP/8.2.20".into());
        assert_eq!((s.extract_version)(&Headers(h), ""), Some("8.2.20".into()));

        let mut h = HashMap::new();
        h.insert("set-cookie".into(), "PHPSESSID=abc; path=/".into());
        assert_eq!((s.extract_version)(&Headers(h), ""), Some("unknown".into()));

        let mut h = HashMap::new();
        h.insert("server".into(), "nginx".into());
        assert_eq!((s.extract_version)(&Headers(h), ""), None);
    }

    #[test]
    fn detects_nextjs_framework() {
        let s = by_name("react2shell").unwrap();

        // X-Powered-By header.
        let mut h = HashMap::new();
        h.insert("x-powered-by".into(), "Next.js".into());
        assert_eq!((s.extract_version)(&Headers(h), ""), Some("unknown".into()));

        // App Router response header.
        let mut h = HashMap::new();
        h.insert("x-nextjs-cache".into(), "HIT".into());
        assert_eq!((s.extract_version)(&Headers(h), ""), Some("unknown".into()));

        // HTML markers only.
        let body = "<script>self.__next_f.push([1])</script>";
        assert_eq!((s.extract_version)(&Headers(HashMap::new()), body), Some("unknown".into()));

        // No markers.
        let mut h = HashMap::new();
        h.insert("server".into(), "nginx".into());
        assert_eq!((s.extract_version)(&Headers(h), "<html></html>"), None);
    }

    #[test]
    fn classifies_react2shell_versions() {
        let s = by_name("react2shell").unwrap();
        // Framework detected but no version -> UNKNOWN_VERSION.
        assert_eq!(s.classify(Some("unknown")).0, Status::UnknownVersion);
        // If a version is known (e.g. from a lockfile), it classifies.
        assert_eq!(s.classify(Some("15.3.2")).0, Status::Vulnerable);
        assert_eq!(s.classify(Some("15.3.6")).0, Status::Patched);
        assert_eq!(s.classify(Some("16.0.6")).0, Status::Vulnerable);
        assert_eq!(s.classify(Some("16.0.7")).0, Status::Patched);
        assert_eq!(s.classify(Some("19.1.1")).0, Status::Vulnerable);
        assert_eq!(s.classify(Some("19.2.1")).0, Status::Patched);
        assert_eq!(s.classify(None).0, Status::NotDetected);
        // Stable Next.js 14.x is below the affected range -> not vulnerable.
        assert_eq!(s.classify(Some("14.2.35")).0, Status::Patched);
        assert_eq!(s.classify(Some("14.1.0")).0, Status::Patched);
        // Affected 14.3 canary line must NOT read PATCHED (regression).
        assert_eq!(s.classify(Some("14.3.0-canary.77")).0, Status::Vulnerable);
        assert_eq!(s.classify(Some("14.3.0")).0, Status::Patched);
        // 13.x and earlier are not affected.
        assert_eq!(s.classify(Some("13.5.0")).0, Status::Patched);
    }

    #[test]
    fn detects_distro_build_suffix() {
        assert!(has_distro_build_suffix("8.3.6-0ubuntu0.24.04.13"));
        assert!(has_distro_build_suffix("7.2.34-18+ubuntu16.04.1+deb.sury.org+1"));
        assert!(has_distro_build_suffix("8.1.2-1.el8"));
        // Plain upstream or prerelease versions are not distro builds.
        assert!(!has_distro_build_suffix("8.3.36"));
        assert!(!has_distro_build_suffix("14.3.0-canary.77"));
    }

    #[test]
    fn php_below_range_still_eol() {
        // Pre-5.4 PHP stays end-of-life (the php rule, unlike react2shell).
        let s = by_name("php2shell").unwrap();
        assert_eq!(s.classify(Some("5.3.29")).0, Status::Eol);
    }

    #[test]
    fn compares_canary_boundaries_and_preserves_prerelease_ordering() {
        let signature = by_name("react2shell").unwrap();
        for (text, expected) in [
            ("14.3.0-canary.9", Status::Patched),
            ("14.3.0-canary.76", Status::Patched),
            ("14.3.0-canary.77", Status::Vulnerable),
            ("14.3.0-canary.100", Status::Vulnerable),
            ("14.3.0", Status::Patched),
            ("15.6.0-canary.57", Status::Vulnerable),
            ("15.6.0-canary.58", Status::Patched),
            ("15.6.0-canary.100", Status::Patched),
            ("16.1.0-canary.11", Status::Vulnerable),
            ("16.1.0-canary.12", Status::Patched),
            ("15.3.6-canary.100", Status::Vulnerable),
            ("15.3.6", Status::Patched),
            ("15.3.7-canary.1", Status::Patched),
            ("14.3.0-canary.076", Status::UnknownVersion),
            ("14.3.0-canary", Status::UnknownVersion),
            ("14.3.0-canary.foo", Status::UnknownVersion),
            ("14.3.0-beta.77", Status::UnknownVersion),
            ("15.3.6-rc.1", Status::UnknownVersion),
            ("17.0.0-canary.1", Status::UnknownVersion),
            ("19.1.2-canary.1", Status::UnknownVersion),
        ] {
            assert_eq!(signature.classify(Some(text)).0, expected, "{text}");
        }
    }

    #[test]
    fn keeps_php_package_tokens_without_surrounding_punctuation() {
        for text in [
            "PHP/8.3.6-0ubuntu0.24.04.13",
            "Apache (PHP/8.3.6-0ubuntu0.24.04.13)",
            "<b>PHP/8.3.6-0ubuntu0.24.04.13</b>",
            "PHP/8.3.6-0ubuntu0.24.04.13; other",
            "PHP/8.3.6-0ubuntu0.24.04.13.",
        ] {
            assert_eq!(find_php_version(text).as_deref(), Some("8.3.6-0ubuntu0.24.04.13"), "{text}");
        }
        assert_eq!(find_php_version("PHP/7.2.34-18+ubuntu16.04.1+deb.sury.org+1").as_deref(), Some("7.2.34-18+ubuntu16.04.1+deb.sury.org+1"));
        assert_eq!(find_php_version("PHP/hidden"), None);
    }

}
