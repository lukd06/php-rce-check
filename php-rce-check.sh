#!/usr/bin/env bash
# =============================================================================
# php-rce-check.sh
#
# Checks whether this system is affected by the PHP remote code execution
# vulnerabilities from the PHP security advisory of 2026-10-21:
#   CVE-2026-109618  RCE via OOM corruption       (GHSA-w8hw-w9fx-j79w)
#   CVE-2026-109619  RCE via stale global state   (GHSA-6wmf-4rv5-p3rp)
#
# Fixed in: 8.5.12, 8.4.27, 8.3.36, 8.2.35 (or distro / LTS vendor backports)
#
# What it checks:
#   1. Installed PHP binaries (CLI, FPM, CGI, LiteSpeed, FrankenPHP)
#   2. Apache mod_php modules
#   3. Running processes: is the patched version actually running? (restart?)
#   4. Docker / Podman containers running PHP
#   5. Mitigations from the advisory (only relevant if you cannot update yet)
#   6. Available package updates (from the local package cache)
#
# Read-only - changes nothing. Run as root for complete results.
#
# Usage:  sudo bash php-rce-check.sh [--no-containers] [--no-color]
# Exit:   0 = nothing vulnerable found
#         1 = at least one vulnerable installation or running process
#         2 = nothing clearly vulnerable, but open items (warnings)
# =============================================================================

set -u
export LC_ALL=C

CVE_RE='CVE-2026-10961[89]'
CHECK_CONTAINERS=1
USE_COLOR=1

for a in "$@"; do
  case "$a" in
    --no-containers) CHECK_CONTAINERS=0 ;;
    --no-color)      USE_COLOR=0 ;;
    -h|--help)       sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "Unknown option: $a" >&2; exit 64 ;;
  esac
done

[ -t 1 ] || USE_COLOR=0
if [ "$USE_COLOR" = 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
else
  R=''; G=''; Y=''; B=''; N=''
fi

N_VULN=0
N_WARN=0
vuln()    { printf '  %s[VULNERABLE]%s %s\n' "$R" "$N" "$*"; N_VULN=$((N_VULN+1)); }
warn()    { printf '  %s[WARNING]%s    %s\n' "$Y" "$N" "$*"; N_WARN=$((N_WARN+1)); }
ok()      { printf '  %s[OK]%s         %s\n' "$G" "$N" "$*"; }
info()    { printf '  [INFO]       %s\n' "$*"; }
section() { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
# Mitigation findings only count as warnings if something is vulnerable
mit()     { if [ "$N_VULN" -gt 0 ]; then warn "$*"; else info "(hardening) $*"; fi; }

printf '%sPHP RCE check - CVE-2026-109618 / CVE-2026-109619%s\n' "$B" "$N"
printf 'Host: %s   Date: %s\n' "$(hostname 2>/dev/null)" "$(date '+%F %T %Z')"
if [ "$(id -u)" -ne 0 ]; then
  printf '%sNote:%s not running as root - processes, configs and containers may be incomplete.\n' "$Y" "$N"
fi

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Upstream status of a version: fixed | vulnerable | eol | newer | unknown
upstream_status() {
  local v=$1 maj min pat fixed
  [[ $v =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || { echo unknown; return; }
  maj=${BASH_REMATCH[1]}; min=${BASH_REMATCH[2]}; pat=${BASH_REMATCH[3]}
  case "$maj.$min" in
    8.5) fixed=12 ;;
    8.4) fixed=27 ;;
    8.3) fixed=36 ;;
    8.2) fixed=35 ;;
    *)
      if (( maj > 8 || (maj == 8 && min > 5) )); then echo newer; else echo eol; fi
      return ;;
  esac
  if (( 10#$pat >= fixed )); then echo fixed; else echo vulnerable; fi
}

# PHP version (x.y.z) of a binary. $1 = path, $2 = optional name
get_version() {
  local b=$1 name=${2:-$(basename "$1")} out
  case "$name" in
    frankenphp*) out=$(timeout 10 "$b" version 2>/dev/null) ;;
    *)           out=$(timeout 10 "$b" -v 2>/dev/null) ;;
  esac
  grep -oE 'PHP[ /v]*[0-9]+\.[0-9]+\.[0-9]+' <<<"$out" | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
}

# Version of mod_php (libphp*.so) - the string is embedded at compile time
modphp_version() {
  grep -aoE 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+' "$1" 2>/dev/null | head -1 | sed 's#.*PHP/##'
}

# Package info + backport evidence. Sets PKG, PKGVER, BACKPORT (yes|no|unknown|none)
pkg_info() {
  local f=$1 src d cl
  PKG=''; PKGVER=''; BACKPORT=none

  if command -v dpkg-query >/dev/null 2>&1 && PKG=$(dpkg -S "$f" 2>/dev/null | head -1 | cut -d: -f1) && [ -n "$PKG" ]; then
    PKGVER=$(dpkg-query -W -f='${Version}' "$PKG" 2>/dev/null)
    src=$(dpkg-query -W -f='${source:Package}' "$PKG" 2>/dev/null)
    BACKPORT=unknown
    for d in "$PKG" "${src}-common" "$src"; do
      cl=/usr/share/doc/$d/changelog.Debian.gz
      if [ -r "$cl" ]; then
        if zgrep -qE "$CVE_RE" "$cl" 2>/dev/null; then BACKPORT=yes; else BACKPORT=no; fi
        break
      fi
    done
    return
  fi

  if command -v rpm >/dev/null 2>&1 && PKG=$(rpm -qf --qf '%{NAME}\n' "$f" 2>/dev/null | head -1) && [ -n "$PKG" ]; then
    PKGVER=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$PKG" 2>/dev/null)
    if rpm -q --changelog "$PKG" 2>/dev/null | grep -qE "$CVE_RE"; then BACKPORT=yes; else BACKPORT=no; fi
    return
  fi

  if command -v apk >/dev/null 2>&1; then
    local o; o=$(apk info --who-owns "$f" 2>/dev/null)
    if [[ $o == *"is owned by"* ]]; then
      PKG=${o##*is owned by }; PKGVER=''
      BACKPORT=unknown   # apk has no changelog; Alpine uses upstream versions
      return
    fi
  fi
  PKG=''
}

# Assessment. $1 = description, $2 = version, $3 = file for package check (optional)
evaluate() {
  local desc=$1 ver=$2 file=${3:-} st p=''
  st=$(upstream_status "$ver")
  PKG=''; PKGVER=''; BACKPORT=none
  [ -n "$file" ] && pkg_info "$file"
  [ -n "$PKG" ] && p=" [package: $PKG${PKGVER:+ $PKGVER}]"

  case "$st" in
    fixed)   ok   "$desc: PHP $ver - patched$p" ;;
    newer)   warn "$desc: PHP $ver - unknown newer branch, check manually$p" ;;
    unknown) warn "$desc: could not determine version$p" ;;
    vulnerable|eol)
      case "$BACKPORT" in
        yes)     ok   "$desc: PHP $ver - distro backport, changelog lists the CVEs$p" ;;
        unknown) warn "$desc: PHP $ver ($st) - backport cannot be verified, check with your vendor$p" ;;
        *)
          if [ "$st" = eol ]; then
            vuln "$desc: PHP $ver - EOL branch, no fix detectable$p"
            info "             (Built from the php-src backport branches yourself? Then confirm manually.)"
          else
            vuln "$desc: PHP $ver - older than the fixed release, no backport in changelog$p"
          fi ;;
      esac ;;
  esac
}

# "128M" -> bytes, "-1" -> -1, invalid -> empty
to_bytes() {
  local v=${1//[\"\' ]/} n u
  [ -z "$v" ] && return
  [ "$v" = "-1" ] && { echo -1; return; }
  [[ $v =~ ^([0-9]+)([KkMmGg]?)$ ]] || return
  n=${BASH_REMATCH[1]}; u=${BASH_REMATCH[2]}
  case "$u" in
    K|k) n=$((n*1024)) ;;
    M|m) n=$((n*1024*1024)) ;;
    G|g) n=$((n*1024*1024*1024)) ;;
  esac
  echo "$n"
}

is_on() {
  case "$(tr '[:upper:]' '[:lower:]' <<<"${1//[\"\' ]/}")" in
    0|off|false|no|none|'') return 1 ;;
    *) return 0 ;;
  esac
}

# Last value set for an ini key across several files
ini_get() {
  local key=$1 f line val=''
  shift
  for f in "$@"; do
    [ -r "$f" ] || continue
    line=$(grep -E "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$f" 2>/dev/null | tail -1)
    [ -n "$line" ] && val=$(sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*;.*$//; s/^"(.*)"$/\1/; s/[[:space:]]+$//' <<<"$line")
  done
  printf '%s' "$val"
}

# Parse FPM pool files -> "pool<TAB>admin|value|-<TAB>key<TAB>value"
parse_pools() {
  awk '
    /^[[:space:]]*;/ { next }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      p=$0; gsub(/[][[:space:]]/, "", p); pool=p
      if (pool != "global") print pool "\t-\t-\t-"
      next
    }
    pool != "" && pool != "global" && /^[[:space:]]*php_(admin_)?(value|flag)\[[^]]+\][[:space:]]*=/ {
      t = ($0 ~ /php_admin_/) ? "admin" : "value"
      k = $0; sub(/^[^[]*\[/, "", k); sub(/\].*$/, "", k)
      v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*;.*$/, "", v)
      sub(/[[:space:]]+$/, "", v); gsub(/^"|"$/, "", v)
      print pool "\t" t "\t" k "\t" v
    }' "$@" 2>/dev/null
}

in_container() { # does the PID run under a different root filesystem?
  [ "$(stat -Lc '%d:%i' "/proc/$1/root" 2>/dev/null)" != "$(stat -Lc '%d:%i' / 2>/dev/null)" ]
}

declare -A EVALUATED=()

# -----------------------------------------------------------------------------
section "1. Installed PHP binaries"
# -----------------------------------------------------------------------------
mapfile -t BINS < <(
  {
    compgen -c 2>/dev/null | grep -E '^(php|php-fpm|php-cgi|lsphp|frankenphp)[0-9.]*$' | sort -u |
      while read -r c; do command -v "$c"; done
    ls -1 /usr/sbin/php-fpm* /usr/bin/php* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
          /usr/local/bin/frankenphp /usr/bin/frankenphp \
          /opt/remi/*/root/usr/bin/php /opt/remi/*/root/usr/sbin/php-fpm \
          /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php \
          /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
          /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
          /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/sbin/php-fpm 2>/dev/null
  } | while read -r f; do
        [ -x "$f" ] || continue
        r=$(readlink -f "$f") || continue
        [[ $(basename "$r") =~ ^(php|php-fpm|php-cgi|lsphp|frankenphp)[0-9.]*$ ]] && echo "$r"
      done | sort -u
)

if [ "${#BINS[@]}" -eq 0 ]; then
  info "No PHP binaries found on the host."
else
  for b in "${BINS[@]}"; do
    v=$(get_version "$b")
    evaluate "$b" "${v:-?}" "$b"
    EVALUATED[$b]=1
  done
fi

# -----------------------------------------------------------------------------
section "2. Apache mod_php"
# -----------------------------------------------------------------------------
mapfile -t MODS < <(ls -1 /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
  /usr/lib/httpd/modules/libphp*.so /usr/local/apache2/modules/libphp*.so \
  /usr/libexec/apache2/libphp*.so /usr/local/libexec/apache24/libphp*.so 2>/dev/null)

MODPHP_LOADED=0
for c in apache2ctl apachectl httpd; do
  if command -v "$c" >/dev/null 2>&1; then
    if timeout 10 "$c" -M 2>/dev/null | grep -qiE 'php[0-9_]*_module'; then MODPHP_LOADED=1; fi
    break
  fi
done

if [ "${#MODS[@]}" -eq 0 ]; then
  info "No mod_php installed."
else
  for m in "${MODS[@]}"; do
    v=$(modphp_version "$m")
    evaluate "$m" "${v:-?}" "$m"
    EVALUATED[$(readlink -f "$m")]=1
  done
  if [ "$MODPHP_LOADED" = 1 ]; then
    warn "mod_php is loaded in Apache - highest risk per the advisory (exploit demonstrated before any application code runs)."
  else
    info "mod_php is installed but not loaded according to 'apachectl -M'."
  fi
fi

# -----------------------------------------------------------------------------
section "3. Running processes"
# -----------------------------------------------------------------------------
declare -A SEEN=()
FPM_MASTERS=()
APACHE_PID=''
MODPHP_RUNNING_LIB=''
RUNNING_ANY=0

while read -r pid ppid comm; do
  [ -d "/proc/$pid" ] || continue
  case "$comm" in
    php-fpm*|php-cgi*|lsphp*|frankenphp*)
      if in_container "$pid"; then
        [ -z "${SEEN[ctr:$comm]:-}" ] && info "PID $pid ($comm) runs inside a container - see section 4."
        SEEN[ctr:$comm]=1
        continue
      fi
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
      [ -n "${SEEN[exe:$exe]:-}" ] && continue
      SEEN[exe:$exe]=1
      RUNNING_ANY=1
      ver=$(get_version "/proc/$pid/exe" "$comm")
      if [[ $exe == *" (deleted)" ]]; then
        vuln "PID $pid ($comm) is still running the OLD binary that has since been replaced (PHP ${ver:-?}) -> restart the service"
      elif [ -z "${EVALUATED[$exe]:-}" ]; then
        evaluate "PID $pid ($comm, $exe)" "${ver:-?}" "$exe"
        EVALUATED[$exe]=1
      else
        info "PID $pid ($comm) runs $exe (PHP ${ver:-?}), see section 1 for the assessment."
      fi
      ;;
    apache2|httpd)
      in_container "$pid" && continue
      lib=$(awk '$6 ~ /libphp[^\/]*\.so/ { print $6 ($7 ? " " $7 : ""); exit }' "/proc/$pid/maps" 2>/dev/null)
      [ -z "$lib" ] && continue
      if [ "$ppid" = 1 ] || [ -z "$APACHE_PID" ]; then APACHE_PID=$pid; fi
      MODPHP_RUNNING_LIB=${lib% (deleted)}
      [ -n "${SEEN[lib:$lib]:-}" ] && continue
      SEEN[lib:$lib]=1
      RUNNING_ANY=1
      if [[ $lib == *" (deleted)" ]]; then
        vuln "Apache (PID $pid) still uses the OLD, replaced mod_php ($MODPHP_RUNNING_LIB) -> restart Apache"
      else
        info "Apache (PID $pid) has mod_php loaded: $lib"
      fi
      ;;
  esac
done < <(ps -eo pid=,ppid=,comm= 2>/dev/null)

while read -r pid _; do
  in_container "$pid" && continue
  FPM_MASTERS+=("$pid")
done < <(ps -eo pid=,args= 2>/dev/null | grep -E 'php-fpm[^ ]*: master process' | grep -v grep)

[ "$RUNNING_ANY" = 0 ] && info "No running PHP web processes (FPM/CGI/LiteSpeed/FrankenPHP/mod_php) found on the host."

# RLIMIT_AS / RLIMIT_DATA: the advisory says NOT to use these (they trigger the bug)
declare -A LIM_SEEN=()
while read -r pid comm; do
  case "$comm" in php-fpm*|php-cgi*|lsphp*|frankenphp*|apache2|httpd) ;; *) continue ;; esac
  [ -n "${LIM_SEEN[$comm]:-}" ] && continue
  LIM_SEEN[$comm]=1
  for lim in "Max address space" "Max data size"; do
    soft=$(grep "^$lim" "/proc/$pid/limits" 2>/dev/null | awk '{print $(NF-2)}')
    if [ -n "$soft" ] && [ "$soft" != unlimited ]; then
      warn "$comm (PID $pid): '$lim' is limited ($soft) - the advisory advises against RLIMIT_AS/RLIMIT_DATA (check LimitAS/LimitDATA in systemd), use a cgroup/container limit instead."
    fi
  done
done < <(ps -eo pid=,comm= 2>/dev/null)

# -----------------------------------------------------------------------------
section "4. Containers"
# -----------------------------------------------------------------------------
if [ "$CHECK_CONTAINERS" = 0 ]; then
  info "Skipped (--no-containers)."
else
  CT_FOUND=0
  for rt in docker podman; do
    command -v "$rt" >/dev/null 2>&1 || continue
    mapfile -t CTS < <(timeout 20 "$rt" ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null)
    for line in "${CTS[@]}"; do
      read -r id name image <<<"$line"
      out=$(timeout 20 "$rt" exec "$id" sh -c '
        for b in php php-fpm php-cgi frankenphp $(ls /usr/sbin/php-fpm* /usr/local/sbin/php-fpm /usr/bin/php[0-9]* 2>/dev/null); do
          p=$(command -v "$b" 2>/dev/null) || continue
          case "$b" in frankenphp) v=$("$p" version 2>/dev/null | head -n1);; *) v=$("$p" -v 2>/dev/null | head -n1);; esac
          [ -n "$v" ] && echo "BIN $p $v"
        done
        for c in /usr/share/doc/php*-common/changelog.Debian.gz; do
          [ -r "$c" ] && zcat "$c" 2>/dev/null | grep -qE "CVE-2026-10961[89]" && echo BACKPORT && break
        done
        command -v rpm >/dev/null 2>&1 && rpm -qa --changelog "php*" 2>/dev/null | grep -qE "CVE-2026-10961[89]" && echo BACKPORT
      ' 2>/dev/null) || continue
      grep -q '^BIN ' <<<"$out" || continue
      CT_FOUND=1
      bp=0; grep -q '^BACKPORT' <<<"$out" && bp=1
      declare -A CT_SEEN=()
      while read -r _ path rest; do
        v=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<<"$rest" | head -1)
        key="$v"; [ -n "${CT_SEEN[$key]:-}" ] && continue; CT_SEEN[$key]=1
        st=$(upstream_status "${v:-x}")
        desc="$rt:$name ($image) $path"
        if [ "$st" = fixed ]; then ok "$desc: PHP $v - patched"
        elif [ "$bp" = 1 ]; then ok "$desc: PHP $v - backport found in the container's package"
        elif [ "$st" = unknown ] || [ "$st" = newer ]; then warn "$desc: PHP ${v:-?} - check manually"
        else vuln "$desc: PHP $v - not patched -> rebuild/pull the image and recreate the container"
        fi
      done < <(grep '^BIN ' <<<"$out")
      unset CT_SEEN
    done
  done
  [ "$CT_FOUND" = 0 ] && info "No running containers with PHP found (or no Docker/Podman)."
fi

# -----------------------------------------------------------------------------
section "5. Mitigations (only relevant if you cannot update right away)"
# -----------------------------------------------------------------------------
if [ "$N_VULN" -eq 0 ]; then
  info "Nothing detected as vulnerable - the following items are informational only."
fi

# Assess the effective values of one context (pool / mod_php)
judge() { # label mm ml ml_src pms umf sup feb
  local label=$1 mm=$2 ml=$3 ml_src=$4 pms=$5 umf=$6 sup=$7 feb=$8 b pb ub
  printf '  %s%s%s\n' "$B" "$label" "$N"

  b=$(to_bytes "$ml")
  if [ "$b" = "-1" ]; then
    if [ "$ml_src" = admin ]; then ok "memory_limit=-1 via php_admin_value (cannot be overridden by the application)"
    else mit "memory_limit=-1, but only via $ml_src - the application can set a limit again via ini_set(); use php_admin_value"; fi
  else
    mit "memory_limit=$ml (source: $ml_src) - mitigation for CVE-2026-109618: -1 via php_admin_value"
  fi

  pb=$(to_bytes "$pms"); ub=$(to_bytes "$umf")
  if [ "$pb" = 0 ]; then
    mit "post_max_size=0 (unlimited!) - recommended: 8M without uploads, otherwise at most 32M"
  elif [ -n "$pb" ] && [ "$pb" -gt $((32*1024*1024)) ]; then
    mit "post_max_size=$pms - recommended: 8M without uploads, otherwise at most 32M"
  elif [ -n "$pb" ] && [ "$pb" -gt $((8*1024*1024)) ]; then
    info "post_max_size=$pms - fine if file uploads are needed (otherwise 8M)"
  else
    ok "post_max_size=$pms"
  fi
  if [ -n "$pb" ] && [ -n "$ub" ] && [ "$pb" -gt 0 ] && [ "$ub" -ge "$pb" ]; then
    mit "upload_max_filesize=$umf is not below post_max_size=$pms"
  fi

  if is_on "$sup"; then
    mit "session.upload_progress.enabled=$sup - mitigation for CVE-2026-109619: set to 0 (php.ini/pool, NOT ini_set/.user.ini) and restart all workers"
  else
    ok "session.upload_progress.enabled=0"
  fi

  if [ "$mm" = "8.5" ]; then
    if is_on "$feb"; then mit "fatal_error_backtraces=$feb - set to 0 on PHP 8.5 and restart all workers"
    else ok "fatal_error_backtraces=0"; fi
  fi
}

ini_files_for() { # ini scandir -> list of files
  local ini=$1 scan=$2
  [ -r "$ini" ] && echo "$ini"
  [ -d "$scan" ] && ls -1 "$scan"/*.ini 2>/dev/null | sort
}

restart_check() { # pid label files...
  local pid=$1 label=$2 et start newest f m
  shift 2
  et=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
  [ -z "$et" ] && return
  start=$(( $(date +%s) - et )); newest=0
  for f in "$@"; do
    m=$(stat -c %Y "$f" 2>/dev/null) || continue
    [ "$m" -gt "$newest" ] && newest=$m
  done
  if [ "$newest" -gt "$start" ]; then
    warn "$label: configuration changed after the process started - changes only apply after restarting all workers"
  fi
}

CTX=0

# --- PHP-FPM (running masters) ---
for mpid in "${FPM_MASTERS[@]}"; do
  CTX=1
  conf=$(ps -o args= -p "$mpid" 2>/dev/null | sed -nE 's/.*master process \(([^)]*)\).*/\1/p')
  phpi=$(timeout 10 "/proc/$mpid/exe" -i 2>/dev/null)
  ver=$(grep -m1 -E '^PHP Version' <<<"$phpi" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  [ -z "$ver" ] && ver=$(get_version "/proc/$mpid/exe" php-fpm)
  mm=$(grep -oE '^[0-9]+\.[0-9]+' <<<"${ver:-0.0}")
  ini=$(sed -nE 's/^Loaded Configuration File => (.*)$/\1/p' <<<"$phpi")
  scan=$(sed -nE 's/^Scan this dir for additional .ini files => (.*)$/\1/p' <<<"$phpi")
  [ "$ini" = "(none)" ] && ini=''
  mapfile -t INIF < <(ini_files_for "$ini" "$scan")

  # Find pool files via include= in php-fpm.conf
  POOLF=()
  if [ -r "$conf" ]; then
    POOLF+=("$conf")
    while read -r pat; do
      for cand in "$pat" "/usr/local/$pat" "$(dirname "$conf")/$pat" "$(dirname "$(dirname "$conf")")/$pat"; do
        mapfile -t g < <(compgen -G "$cand" 2>/dev/null)
        [ "${#g[@]}" -gt 0 ] && { POOLF+=("${g[@]}"); break; }
      done
    done < <(sed -nE 's/^[[:space:]]*include[[:space:]]*=[[:space:]]*//p' "$conf")
  fi

  base_ml=$(ini_get memory_limit "${INIF[@]}");                     base_ml=${base_ml:-128M}
  base_pms=$(ini_get post_max_size "${INIF[@]}");                   base_pms=${base_pms:-8M}
  base_umf=$(ini_get upload_max_filesize "${INIF[@]}");             base_umf=${base_umf:-2M}
  base_sup=$(ini_get session.upload_progress.enabled "${INIF[@]}"); base_sup=${base_sup:-1}
  base_feb=$(ini_get fatal_error_backtraces "${INIF[@]}");          base_feb=${base_feb:-1}

  printf '\n  %sPHP-FPM %s (master PID %s, %s)%s\n' "$B" "${ver:-?}" "$mpid" "${conf:-?}" "$N"
  info "php.ini: ${ini:-none}   conf.d: ${scan:-none}"
  restart_check "$mpid" "FPM PID $mpid" "${INIF[@]}" "${POOLF[@]}"

  if [ "${#POOLF[@]}" -eq 0 ]; then
    judge "(ini level, pools not found)" "$mm" "$base_ml" "php.ini" "$base_pms" "$base_umf" "$base_sup" "$base_feb"
    continue
  fi

  declare -A PV=()
  POOLS=()
  while IFS=$'\t' read -r pool typ key val; do
    if [ "$typ" = "-" ]; then
      [ -z "${PV[$pool|seen]:-}" ] && POOLS+=("$pool")
      PV[$pool|seen]=1
    elif [ "$typ" = admin ]; then
      PV[$pool|$key]=$val; PV[$pool|$key|src]='admin'
    elif [ "${PV[$pool|$key|src]:-}" != admin ]; then
      PV[$pool|$key]=$val; PV[$pool|$key|src]=php_value
    fi
  done < <(parse_pools "${POOLF[@]}")

  for pool in "${POOLS[@]}"; do
    judge "Pool [$pool]" "$mm" \
      "${PV[$pool|memory_limit]:-$base_ml}" "${PV[$pool|memory_limit|src]:-php.ini}" \
      "${PV[$pool|post_max_size]:-$base_pms}" "${PV[$pool|upload_max_filesize]:-$base_umf}" \
      "${PV[$pool|session.upload_progress.enabled]:-$base_sup}" \
      "${PV[$pool|fatal_error_backtraces]:-$base_feb}"
  done
  unset PV
done

# --- mod_php ---
if [ -n "$MODPHP_RUNNING_LIB" ] || [ "$MODPHP_LOADED" = 1 ]; then
  CTX=1
  lib=${MODPHP_RUNNING_LIB:-${MODS[0]:-}}
  ver=$(modphp_version "$lib"); mm=$(grep -oE '^[0-9]+\.[0-9]+' <<<"${ver:-0.0}")
  if   [ -r "/etc/php/$mm/apache2/php.ini" ]; then ini=/etc/php/$mm/apache2/php.ini; scan=/etc/php/$mm/apache2/conf.d
  elif [ -r /usr/local/etc/php/php.ini ] || [ -d /usr/local/etc/php/conf.d ]; then ini=/usr/local/etc/php/php.ini; scan=/usr/local/etc/php/conf.d
  else ini=/etc/php.ini; scan=/etc/php.d; fi
  mapfile -t INIF < <(ini_files_for "$ini" "$scan")

  APCONF=$(ls -d /etc/apache2 /etc/httpd /usr/local/apache2/conf /usr/local/etc/apache24 2>/dev/null | head -1)
  apget() { # key -> "admin:val" | "php_value:val" (last match, global across all configs)
    local k=${1//./\\.} a v
    [ -z "$APCONF" ] && return
    a=$(grep -rhiE "^[[:space:]]*php_admin_(value|flag)[[:space:]]+${k}[[:space:]]" "$APCONF" 2>/dev/null | tail -1 | awk '{print $3}')
    [ -n "$a" ] && { echo "admin:$a"; return; }
    v=$(grep -rhiE "^[[:space:]]*php_(value|flag)[[:space:]]+${k}[[:space:]]" "$APCONF" 2>/dev/null | tail -1 | awk '{print $3}')
    [ -n "$v" ] && echo "php_value:$v"
  }
  pick() { # key default
    local r; r=$(apget "$1")
    if [ -n "$r" ]; then echo "${r#*:}|${r%%:*}"; else local i; i=$(ini_get "$1" "${INIF[@]}"); echo "${i:-$2}|php.ini"; fi
  }
  IFS='|' read -r ml ml_src <<<"$(pick memory_limit 128M)"
  IFS='|' read -r pms _ <<<"$(pick post_max_size 8M)"
  IFS='|' read -r umf _ <<<"$(pick upload_max_filesize 2M)"
  IFS='|' read -r sup _ <<<"$(pick session.upload_progress.enabled 1)"
  IFS='|' read -r feb _ <<<"$(pick fatal_error_backtraces 1)"

  printf '\n  %smod_php %s (Apache)%s\n' "$B" "${ver:-?}" "$N"
  info "php.ini: $ini   Apache config: ${APCONF:-?}  (check vhost-specific values individually)"
  [ -n "$APACHE_PID" ] && mapfile -t APF < <(find "${APCONF:-/nonexistent}" -type f 2>/dev/null) && \
    restart_check "$APACHE_PID" "Apache PID $APACHE_PID" "${INIF[@]}" "${APF[@]}"
  judge "mod_php (global)" "$mm" "$ml" "$ml_src" "$pms" "$umf" "$sup" "$feb"
fi

# --- Other SAPIs ---
if ps -eo comm= 2>/dev/null | grep -qE '^(php-cgi|lsphp|frankenphp)'; then
  CTX=1
  info "php-cgi / LiteSpeed / FrankenPHP are running: check their ini values (for FrankenPHP e.g. php_ini in the Caddyfile) against the mitigations manually."
fi
[ "$CTX" = 0 ] && info "No running web SAPIs on the host - no mitigations to check."

# --- Per-directory overrides ---
mapfile -t OVR < <(find /var/www /srv /home/*/public_html /usr/share/nginx -maxdepth 6 \
  \( -name .htaccess -o -name .user.ini \) -type f \
  -exec grep -lE '(memory_limit|session\.upload_progress|post_max_size)' {} + 2>/dev/null | head -20)
if [ "${#OVR[@]}" -gt 0 ]; then
  mit "Per-directory overrides found (may undermine the mitigations, ${#OVR[@]} file(s), max. 20 shown):"
  for f in "${OVR[@]}"; do info "    $f"; done
fi

# -----------------------------------------------------------------------------
section "6. Available package updates (local cache, run 'apt update' / 'dnf makecache' first)"
# -----------------------------------------------------------------------------
UPD=''
if command -v apt >/dev/null 2>&1; then
  UPD=$(apt list --upgradable 2>/dev/null | grep -E '^(php|libapache2-mod-php|libphp)' )
elif command -v dnf >/dev/null 2>&1; then
  UPD=$(dnf -q -C check-update 'php*' 2>/dev/null | grep -E '^php')
elif command -v yum >/dev/null 2>&1; then
  UPD=$(yum -q -C check-update 'php*' 2>/dev/null | grep -E '^php')
elif command -v apk >/dev/null 2>&1; then
  UPD=$(apk version -l '<' 2>/dev/null | grep -E '^php')
fi
if [ -n "$UPD" ]; then
  warn "PHP updates available:"
  while read -r l; do info "    $l"; done <<<"$UPD"
else
  info "No PHP updates found in the local package cache."
fi

# -----------------------------------------------------------------------------
section "Result"
# -----------------------------------------------------------------------------
if [ "$N_VULN" -gt 0 ]; then
  printf '  %s%d vulnerable finding(s), %d warning(s).%s\n' "$R" "$N_VULN" "$N_WARN" "$N"
  printf '  -> Update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or your vendor package and restart ALL workers / Apache.\n'
  printf '  -> Advisory: https://www.php.net/archive/2026.php#2026-10-21-5\n'
  exit 1
elif [ "$N_WARN" -gt 0 ]; then
  printf '  %sNothing clearly vulnerable, but %d warning(s) - please review.%s\n' "$Y" "$N_WARN" "$N"
  exit 2
else
  printf '  %sNo vulnerable PHP installation found.%s\n' "$G" "$N"
  exit 0
fi
