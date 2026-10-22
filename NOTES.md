# Notes

Operational and safety notes for this scanner. Read these before pointing it at
anything.

## Authorized use only

Run it only against hosts you own or are explicitly authorised to assess. The
passive scan behaves like a browser visiting the page; the opt-in react2shell
active probe sends a crafted request and is gated behind `--i-am-authorized`.

## Detection, not exploitation

This is a detection tool. It reads the version a server discloses and compares
it to the fixed releases. It does **not** carry a working exploit:

- **No php2shell crash probe.** It will not send the memory-exhaustion payload
  that crashes a PHP-FPM worker. That is a denial-of-service and an RCE trigger.
- **No react2shell code-execution probe.** The `--active` check sends only
  malformed RSC input that makes a vulnerable deserializer error out
  (`HTTP 500` + `digest`). It reports a lead (`POSSIBLY_VULNERABLE`), never runs
  code, and is never reachable from the web UI.

## Known limits of the verdict

- **Hidden versions.** A server that suppresses its version reads as
  `UNKNOWN_VERSION`; confirm with the host-side check (`--local`,
  `remote-check.sh`, or `php -v`).
- **Distro backports.** Distributions backport fixes without bumping the
  upstream `x.y.z`, so a distro package can read `VULNERABLE` while being
  patched. The tool flags a distro build; confirm against the distro's security
  tracker.
- **DNS rebinding.** The SSRF guard pins the validated address for the request,
  which closes the parse differential and the common rebinding window; treat a
  determined attacker-controlled resolver as out of scope for the public web UI.

## This tool does not patch anything

Finding a vulnerable host does not fix it. `apply-mitigations.sh` is an interim
stopgap you run on each box; the only complete fix is upgrading PHP to a patched
release (and, on end-of-life OSes, migrating). See the README's remediation
workflow.

## Mitigation values

The interim php.ini settings come from vendor guidance (CIQ, Microsoft, Sophos),
not the official PHP advisories. Confirm them against the advisories before a
wide production rollout, especially `memory_limit = -1`.

## References

- php2shell: CVE-2026-109618, CVE-2026-109619 (GHSA-w8hw-w9fx-j79w,
  GHSA-6wmf-4rv5-p3rp)
- react2shell: CVE-2025-55182

This project is an independent implementation. It contains no third-party
scanner code.
