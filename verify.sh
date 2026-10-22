#!/usr/bin/env bash
# verify.sh - independent check of exposed PHP version (php2shell / CVE-2026-109618/9).
# Reads the version the server discloses in its headers. Passive: one HEAD per host.
# Usage: ./verify.sh [host ...]     or     ./verify.sh -f targets.txt
set -u

# php2shell fixed releases per branch.
declare -A FIXED=( [8.5]=8.5.12 [8.4]=8.4.27 [8.3]=8.3.36 [8.2]=8.2.35 )

# $1 >= $2 ?  (semantic version compare via sort -V)
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

classify() { # $1 = version like 8.3.12
  local v=$1 major minor branch
  major=${v%%.*}; minor=$(echo "$v" | cut -d. -f2); branch="$major.$minor"
  if [ -n "${FIXED[$branch]:-}" ]; then
    if ver_ge "$v" "${FIXED[$branch]}"; then echo "PATCHED"; else echo "VULNERABLE"; fi
  elif ver_ge "$branch" "8.2"; then
    echo "UNKNOWN"          # newer branch than we track
  else
    echo "EOL_VULNERABLE"   # 8.1 and older: affected, no official fix
  fi
}

# Collect targets from args or -f file.
targets=()
if [ "${1:-}" = "-f" ]; then
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(echo "$line" | xargs)"
    [ -n "$line" ] && targets+=("$line")
  done < "${2:?need a file}"
else
  targets=("$@")
fi
[ ${#targets[@]} -eq 0 ] && { echo "usage: $0 [host ...] | -f targets.txt"; exit 2; }

printf '%-40s %-12s %-16s %s\n' "HOST" "PHP" "STATUS" "EVIDENCE"
vuln=0
for t in "${targets[@]}"; do
  case "$t" in *://*) url="$t";; *) url="http://$t";; esac
  hdr="$(curl -sI --max-time 15 "$url" 2>/dev/null)"
  # Pull PHP/x.y.z from X-Powered-By or Server.
  ver="$(printf '%s' "$hdr" | grep -i -oE 'PHP/[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d/ -f2)"
  if [ -z "$ver" ]; then
    printf '%-40s %-12s %-16s %s\n' "$t" "-" "NOT_DETECTED" "no PHP version in headers"
    continue
  fi
  st="$(classify "$ver")"
  ev="$(printf '%s' "$hdr" | grep -i -E 'x-powered-by|server:' | head -n1 | tr -d '\r' | sed 's/^[Ss]erver: *//; s/^[Xx]-[Pp]owered-[Bb]y: */X-Powered-By: /')"
  printf '%-40s %-12s %-16s %s\n' "$t" "$ver" "$st" "$ev"
  case "$st" in VULNERABLE|EOL_VULNERABLE) vuln=$((vuln+1));; esac
done
echo
echo "# $vuln host(s) vulnerable / EOL"
exit $([ "$vuln" -gt 0 ] && echo 2 || echo 0)
