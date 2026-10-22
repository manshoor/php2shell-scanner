#!/usr/bin/env bash
# remote-check.sh - definitive php2shell check across a fleet, over SSH.
# Reads the installed PHP version on each host (php -v). No probing of any
# web app; uses YOUR existing ssh access (keys / ~/.ssh/config).
#
# Usage:
#   ./remote-check.sh user@host1 user@host2 ...
#   ./remote-check.sh -f hosts.txt      # one ssh target per line, # comments ok
set -u

declare -A FIXED=( [8.5]=8.5.12 [8.4]=8.4.27 [8.3]=8.3.36 [8.2]=8.2.35 )
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

classify() {
  local v=$1 branch; branch="${v%.*}"
  if [ -n "${FIXED[$branch]:-}" ]; then
    if ver_ge "$v" "${FIXED[$branch]}"; then echo "PATCHED"; else echo "VULNERABLE"; fi
  elif ver_ge "$branch" "8.2"; then echo "UNKNOWN"
  else echo "EOL_VULNERABLE"; fi
}

hosts=()
if [ "${1:-}" = "-f" ]; then
  while IFS= read -r l; do l="${l%%#*}"; l="$(echo "$l" | xargs)"; [ -n "$l" ] && hosts+=("$l"); done < "${2:?need a file}"
else
  hosts=("$@")
fi
[ ${#hosts[@]} -eq 0 ] && { echo "usage: $0 user@host ... | -f hosts.txt"; exit 2; }

printf '%-28s %-10s %-16s\n' "HOST" "PHP" "STATUS"
vuln=0
for h in "${hosts[@]}"; do
  # -n: no stdin, so the loop isn't consumed. BatchMode: fail fast if no key.
  raw="$(ssh -n -o BatchMode=yes -o ConnectTimeout=8 "$h" 'php -v 2>/dev/null | head -n1' 2>/dev/null)"
  v="$(printf '%s' "$raw" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  if [ -z "$v" ]; then
    printf '%-28s %-10s %-16s\n' "$h" "-" "NO_PHP/UNREACH"
    continue
  fi
  st="$(classify "$v")"
  printf '%-28s %-10s %-16s\n' "$h" "$v" "$st"
  case "$st" in VULNERABLE|EOL_VULNERABLE) vuln=$((vuln+1));; esac
done
echo; echo "# $vuln host(s) vulnerable / EOL"
exit $([ "$vuln" -gt 0 ] && echo 2 || echo 0)
