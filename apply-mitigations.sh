#!/usr/bin/env bash
# apply-mitigations.sh
#
# Interim mitigation for php2shell (CVE-2026-109618 / CVE-2026-109619).
#
# IMPORTANT: this is a STOPGAP, not a fix. The only complete fix is upgrading to
# PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or a vendor backport) and restarting
# workers. This script lowers exposure until you can upgrade.
#
# What it does:
#   1. Discovers every PHP it can find (all `php*` and `php-fpm*` binaries, plus
#      common multi-version / FPM config trees).
#   2. Reports each version and whether it is VULNERABLE / EOL / PATCHED.
#   3. Writes a conf.d drop-in with the interim settings to each config dir.
#
# Safe by default: DRY RUN unless you pass --apply. It backs up anything it
# would overwrite, and the drop-in is a single file you can delete to revert.
#
# Usage:
#   ./apply-mitigations.sh                 # dry run: show what it found + would write
#   ./apply-mitigations.sh --apply         # write the drop-in(s)
#   ./apply-mitigations.sh --apply --reload  # ...and reload php-fpm / apache
#   ./apply-mitigations.sh --apply --oom-workaround  # also add the memory_limit=-1 set
#
# Run as root (or via sudo) to write into system config dirs.
set -u

APPLY=0; RELOAD=0; OOM=0
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    --reload) RELOAD=1 ;;
    --oom-workaround) OOM=1 ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done

DROPIN="zz-php2shell-mitigation.ini"

# --- version classification (same matrix as the scanner) --------------------
declare -A FIXED=( [8.5]=8.5.12 [8.4]=8.4.27 [8.3]=8.3.36 [8.2]=8.2.35 )
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }
classify() {
  local v=$1 branch; branch="$(echo "$v" | cut -d. -f1,2)"
  if [ -n "${FIXED[$branch]:-}" ]; then
    if ver_ge "$v" "${FIXED[$branch]}"; then echo PATCHED; else echo VULNERABLE; fi
  elif ver_ge "$branch" "8.2"; then echo UNKNOWN
  else echo EOL_VULNERABLE; fi
}

# --- discover PHP binaries --------------------------------------------------
# Candidate names and locations across distros, cPanel EA, Remi, Homebrew.
discover_binaries() {
  {
    for n in php php-fpm; do command -v "$n" 2>/dev/null; done
    for d in /usr/bin /usr/local/bin /usr/sbin /usr/local/sbin /opt/homebrew/bin; do
      ls "$d"/php[0-9]* "$d"/php-fpm[0-9]* 2>/dev/null
    done
    # cPanel EasyApache and Remi SCL layouts.
    ls /opt/cpanel/ea-php*/root/usr/bin/php 2>/dev/null
    ls /opt/remi/php*/root/usr/bin/php 2>/dev/null
    ls /etc/php/*/fpm/php-fpm.conf 2>/dev/null | sed 's#/fpm/php-fpm.conf##; s#/etc/php/#/usr/sbin/php-fpm#'
  } 2>/dev/null | sort -u
}

# Config dirs a given php binary scans for extra .ini files.
confd_of() {
  local bin=$1
  "$bin" -i 2>/dev/null \
    | awk -F'=>' '/Scan this dir for additional .ini files/{gsub(/ /,"",$2);print $2}' \
    | head -n1
}

# For a CLI conf.d like /etc/php/8.3/cli/conf.d, the FPM/apache siblings.
sapi_siblings() {
  local confd=$1
  case "$confd" in
    */cli/conf.d)
      for s in fpm apache2; do
        local p="${confd/\/cli\//\/$s\/}"
        [ -d "$p" ] && echo "$p"
      done ;;
  esac
}

echo "== php2shell mitigation =="
echo "mode: $([ $APPLY -eq 1 ] && echo APPLY || echo 'DRY RUN (pass --apply to write)')"
[ $OOM -eq 1 ] && echo "oom-workaround: ON (memory_limit=-1 + capped post size)"
echo

# Collect unique (version, confd) pairs.
declare -A SEEN_DIR=()
TARGETS=()  # "version|confd"
printf '%-46s %-10s %s\n' "PHP BINARY" "VERSION" "STATUS"
while IFS= read -r bin; do
  [ -x "$bin" ] || continue
  v="$("$bin" -v 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  [ -z "$v" ] && continue
  st="$(classify "$v")"
  printf '%-46s %-10s %s\n' "$bin" "$v" "$st"
  cd1="$(confd_of "$bin")"
  for d in "$cd1" $(sapi_siblings "$cd1"); do
    [ -n "$d" ] && [ -d "$d" ] || continue
    if [ -z "${SEEN_DIR[$d]:-}" ]; then SEEN_DIR[$d]=1; TARGETS+=("$v|$d"); fi
  done
done < <(discover_binaries)

# Also pick up Debian/RHEL FPM conf.d that no CLI binary pointed at.
for d in /etc/php/*/fpm/conf.d /etc/php.d /etc/opt/remi/php*/php.d \
         /opt/cpanel/ea-php*/root/etc/php.d /usr/local/etc/php/conf.d; do
  [ -d "$d" ] || continue
  if [ -z "${SEEN_DIR[$d]:-}" ]; then SEEN_DIR[$d]=1; TARGETS+=("?|$d"); fi
done

echo
if [ ${#TARGETS[@]} -eq 0 ]; then
  echo "no PHP config dirs found. Is PHP installed and on PATH?"; exit 1
fi

# --- build the drop-in content ----------------------------------------------
build_ini() { # $1 = version (or ?)
  local v=$1
  cat <<EOF
; php2shell (CVE-2026-109618 / CVE-2026-109619) interim mitigation.
; STOPGAP ONLY — upgrade to a patched PHP and restart workers for the real fix.
; Remove this file to revert. Written by apply-mitigations.sh.

; CVE-2026-109619: disable the upload-progress session handler.
session.upload_progress.enabled = 0

; Reduce fingerprinting (not a fix for the RCE, just stops leaking the version).
expose_php = Off
EOF
  # fatal_error_backtraces exists on PHP 8.5+ only.
  case "$v" in 8.5.*) echo "fatal_error_backtraces = 0" ;; esac
  if [ $OOM -eq 1 ]; then
    cat <<EOF

; --oom-workaround for CVE-2026-109618: avoid the out-of-memory path.
; WARNING: memory_limit=-1 is UNLIMITED. Only safe with a small request cap
; (below) AND a container/cgroup memory limit. Do NOT use RLIMIT_AS/RLIMIT_DATA
; ulimits — the PHP team warns they can TRIGGER the bug.
memory_limit = -1
post_max_size = 32M
upload_max_filesize = 16M
EOF
  fi
}

# --- apply ------------------------------------------------------------------
wrote=0
for t in "${TARGETS[@]}"; do
  v="${t%%|*}"; d="${t#*|}"
  dest="$d/$DROPIN"
  if [ $APPLY -eq 0 ]; then
    echo "would write: $dest  (version ${v})"
    continue
  fi
  if [ ! -w "$d" ]; then
    echo "SKIP (no write permission, run as root): $dest"
    continue
  fi
  [ -f "$dest" ] && cp -p "$dest" "$dest.bak.$(date +%Y%m%d%H%M%S)"
  build_ini "$v" > "$dest" && { echo "wrote: $dest"; wrote=$((wrote+1)); }
done

if [ $APPLY -eq 0 ]; then
  echo
  echo "dry run only. Re-run with --apply (as root) to write the files above."
  echo "preview of the drop-in:"; echo "----"; build_ini "8.5.0"; echo "----"
  exit 0
fi

echo; echo "$wrote file(s) written."

# --- reload -----------------------------------------------------------------
if [ $RELOAD -eq 1 ]; then
  echo "reloading services..."
  reloaded=0
  if command -v systemctl >/dev/null 2>&1; then
    for svc in $(systemctl list-units --type=service --no-legend 2>/dev/null \
                 | awk '{print $1}' | grep -E '^php.*fpm.*\.service$'); do
      systemctl reload "$svc" 2>/dev/null && { echo "  reloaded $svc"; reloaded=1; }
    done
  fi
  for a in apache2ctl apachectl; do
    command -v "$a" >/dev/null 2>&1 && "$a" -k graceful 2>/dev/null && { echo "  reloaded apache"; reloaded=1; }
  done
  [ $reloaded -eq 0 ] && echo "  no php-fpm/apache service reloaded — reload your web stack manually."
else
  echo "run with --reload to reload php-fpm/apache, or reload your web stack manually."
fi
echo
echo "REMINDER: this is interim. Upgrade PHP to a patched release and restart workers."
