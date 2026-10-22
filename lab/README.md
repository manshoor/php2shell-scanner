# php2shell patch-validation lab

A disposable Docker lab to validate detection and your upgrade path for
php2shell (CVE-2026-109618 / CVE-2026-109619). It runs several PHP versions
side by side so you can watch the scanner's verdict change and confirm that
patching flips a host from vulnerable to safe.

**There is no exploit here.** Each container is a stock PHP image serving a
one-line page. The lab validates *version detection and patching*, not
exploitation. Nothing in it attacks anything.

## Tested

A full `./run-lab.sh up` run: each node gets the expected verdict, and the
`php -v` cross-check confirms the true version even for the host that hides it
over HTTP.

![Lab run: scanner verdicts across the five PHP nodes](../docs/lab-run.webp)

## Services

| Port | PHP | Expected verdict | Mirrors |
|---|---|---|---|
| 8081 | 8.3.12 | `VULNERABLE` | an unpatched 8.3 host |
| 8082 | 8.3.36 | `PATCHED` | the fix for 8.3 |
| 8083 | 5.6 | `EOL_VULNERABLE` | a legacy PHP 5.6 deployment |
| 8084 | 7.2 | `EOL_VULNERABLE` | a legacy PHP 7.2 deployment |
| 8085 | 8.3.12, `expose_php=Off` | `UNKNOWN_VERSION` | a host that hides its version |

## Use

Build the scanner once, then drive the lab:

```bash
(cd .. && cargo build --release)
./run-lab.sh up      # start containers, wait, scan
./run-lab.sh scan    # re-scan without restarting
./run-lab.sh down    # stop and remove containers
```

## What it demonstrates

- **Detection is correct:** 8081 reads `VULNERABLE`, 8082 `PATCHED`, the two EOL
  nodes `EOL_VULNERABLE`.
- **The upgrade path:** change `vuln-8-3` in `docker-compose.yml` from
  `php:8.3.12-apache` to `php:8.3.36-apache`, then `./run-lab.sh up` again — the
  verdict flips `VULNERABLE` -> `PATCHED`. That is your patch, validated.
- **Hidden versions:** 8085 suppresses the version header, so the passive scan
  can only say `UNKNOWN_VERSION`. The lab confirms why some of your real hosts
  read that way, and the `php -v` cross-check shows the true version a hardened
  host won't reveal over HTTP.

The harness also prints `php -v` from inside each container, the same definitive
check `scanner --local` / `remote-check.sh` run on real hosts.

## Reset

`./run-lab.sh down` removes the containers. The images stay cached; remove them
with `docker image rm php:8.3.12-apache php:8.3.36-apache php:5.6-apache php:7.2-apache`.
