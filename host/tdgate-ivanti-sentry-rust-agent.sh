#!/bin/sh
# TDGate and Zenbox-miner host triage: 0 clean, 1 findings, 2 incomplete coverage.

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root on the host" >&2; exit 2; }

found=0
incomplete=0
proc_seen=0
env_seen=0
read_errors=0
tmpdirs=$(printf '/tmp\n/var/tmp\n/dev/shm')

say() { printf '%s\n' "$*"; found=1; }
warn() { printf 'COVERAGE ERROR: %s\n' "$*" >&2; incomplete=1; }

# Inspect userspace processes for deleted executables, masquerade names, and TD_* state.
for d in /proc/[0-9]*; do
  [ -d "$d" ] || continue
  exe=$(readlink "$d/exe" 2>/dev/null) || continue
  proc_seen=$((proc_seen + 1))
  pid=${d#/proc/}
  comm=$(cat "$d/comm" 2>/dev/null) || { read_errors=$((read_errors + 1)); continue; }
  ppid=$(awk '/^PPid:/{print $2}' "$d/status" 2>/dev/null || true)
  case "$exe" in *" (deleted)") say "DELETED-EXE pid=$pid ppid=$ppid comm=$comm exe=$exe" ;; esac
  case "$comm" in "["*|kworker/*) say "USERSPACE-KWORKER pid=$pid ppid=$ppid comm=$comm exe=$exe" ;; esac

  if env_lines=$(tr '\0' '\n' < "$d/environ" 2>/dev/null); then
    env_seen=$((env_seen + 1))
    td=$(printf '%s\n' "$env_lines" | grep -E '^TD_[A-Z]+=' | tr '\n' ' ' || true)
    [ -n "$td" ] && say "TDGATE-ENV pid=$pid ppid=$ppid exe=$exe $td"
    td_tmp=$(printf '%s\n' "$env_lines" | grep -m1 '^TMPDIR=' | cut -d= -f2- || true)
    case "$td_tmp" in /) tmpdirs=$(printf '%s\n/' "$tmpdirs") ;; /*/) tmpdirs=$(printf '%s\n%s' "$tmpdirs" "${td_tmp%/}") ;; /*) tmpdirs=$(printf '%s\n%s' "$tmpdirs" "$td_tmp") ;; esac
  else
    read_errors=$((read_errors + 1))
  fi
done

[ "$proc_seen" -gt 0 ] || warn "no userspace executables were readable in /proc"
[ "$env_seen" -gt 0 ] || warn "no process environments were readable in /proc"
[ "$read_errors" -eq 0 ] || warn "$read_errors process records became unreadable"

# Check standard and process-supplied temporary directories.
sorted_tmpdirs=$(printf '%s\n' "$tmpdirs" | sort -u)
while IFS= read -r d; do
  [ -d "$d" ] || continue
  out=$(find "$d" -xdev -maxdepth 2 \( -name '.ia' -o -name '.cache_*' -o -name '.dsync_rs*' -o -name '.td-www' -o -name 'ag_dbg.log' \) -exec ls -ld {} + 2>&1)
  rc=$?
  [ "$rc" -eq 0 ] || warn "find failed under $d: $out"
  [ "$rc" -ne 0 ] || [ -z "$out" ] || say "$out"
done <<EOF
$sorted_tmpdirs
EOF

out=$(find /var/lib /etc/cron.d -maxdepth 2 \( -name '.systemd-private-*' -o -name '0hourly-sysstat' -o -name '.nm-inst.sh' -o -name '.nm.conf' -o -name 'systemd-resolved-helper' \) -exec ls -ld {} + 2>&1)
rc=$?
[ "$rc" -eq 0 ] || warn "persistence scan failed: $out"
[ "$rc" -ne 0 ] || [ -z "$out" ] || say "$out"

# Inventory wildcard listeners for comparison with deleted-executable PIDs.
echo "Wildcard TCP listeners:"
if command -v ss >/dev/null 2>&1; then
  listeners=$(ss -tlnp 2>&1); rc=$?
elif command -v netstat >/dev/null 2>&1; then
  listeners=$(netstat -tlnp 2>&1); rc=$?
else
  listeners=""; rc=127
fi
[ "$rc" -eq 0 ] || warn "listener inventory unavailable: ${listeners:-ss and netstat missing}"
[ "$rc" -ne 0 ] || printf '%s\n' "$listeners" | awk 'NR==1 || $4 ~ /^(0\.0\.0\.0|\*|\[::\]):/'

[ "$incomplete" -eq 0 ] || exit 2
exit "$found"
