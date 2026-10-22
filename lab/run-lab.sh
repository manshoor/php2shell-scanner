#!/usr/bin/env bash
# run-lab.sh - bring the lab up, scan it, show the verdicts. No exploit.
#   ./run-lab.sh up     start containers and scan (default)
#   ./run-lab.sh scan   scan only (containers already up)
#   ./run-lab.sh down   stop and remove containers
set -euo pipefail
cd "$(dirname "$0")"
BIN="../target/release/scanner"
PORTS=(8081 8082 8083 8084 8085)

scan() {
  [ -x "$BIN" ] || { echo "build the scanner first: (cd .. && cargo build --release)"; exit 1; }
  targets=(); for p in "${PORTS[@]}"; do targets+=("http://127.0.0.1:$p"); done
  echo "== scanner verdicts (php2shell) =="
  "$BIN" --sig php2shell --allow-private --no-colour "${targets[@]}" || true
  echo
  echo "== cross-check: php -v inside each container (--local equivalent) =="
  for s in vuln-8-3 patched-8-3 eol-5-6 eol-7-2 hidden-8-3; do
    v="$(docker compose exec -T "$s" php -r 'echo PHP_VERSION;' 2>/dev/null || echo '?')"
    printf '  %-14s %s\n' "$s" "$v"
  done
}

case "${1:-up}" in
  up)
    docker compose up -d
    echo "waiting for containers to serve..."
    for p in "${PORTS[@]}"; do
      for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$p/" >/dev/null 2>&1 && break; sleep 1; done
    done
    echo; scan ;;
  scan) scan ;;
  down) docker compose down ;;
  *) echo "usage: $0 [up|scan|down]"; exit 2 ;;
esac
