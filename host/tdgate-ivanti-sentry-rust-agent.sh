#!/bin/sh
set -eu

fail() {
  echo "ERROR: $*" >&2
  exit 2
}

[ "$(id -u)" -eq 0 ] || fail "run as root with host PID, mount, and network namespaces"
pid1_exe=$(readlink /proc/1/exe 2>/dev/null || true)
case "$pid1_exe" in
  */systemd|*/init) ;;
  *) fail "cannot confirm host PID namespace (PID 1: ${pid1_exe:-unreadable})" ;;
esac

for marker in /.dockerenv /run/.containerenv; do
  [ ! -e "$marker" ] || fail "container marker detected: $marker"
done
virt=$(command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container 2>/dev/null || true)
case "$virt" in ""|none|wsl) ;; *) fail "container virtualization detected: $virt" ;; esac
container_env=$(tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -m1 '^container=' | cut -d= -f2- || true)
case "$container_env" in ""|wsl) ;; *) fail "PID 1 reports container=$container_env" ;; esac
grep -Eiq '(docker|containerd|kubepods|libpod|lxc)' /proc/1/cgroup 2>/dev/null && fail "container cgroup detected"

for ns in pid mnt net; do
  self_ns=$(readlink "/proc/self/ns/$ns" 2>/dev/null || true)
  init_ns=$(readlink "/proc/1/ns/$ns" 2>/dev/null || true)
  [ -n "$self_ns" ] && [ "$self_ns" = "$init_ns" ] || fail "host $ns namespace required"
done

readable_exe=0
readable_env=0
read_errors=0
user_processes=0
tmpdirs=$(printf '/tmp\n/var/tmp\n/dev/shm')

for p in /proc/[0-9]*; do
  [ -d "$p" ] || continue
  if ! cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null); then
    [ -d "$p" ] && { echo "COVERAGE ERROR: unreadable cmdline $p" >&2; read_errors=$((read_errors + 1)); }
    continue
  fi
  [ -n "$cmd" ] || continue
  user_processes=$((user_processes + 1))

  if [ -r "$p/environ" ] && env_lines=$(tr '\0' '\n' < "$p/environ" 2>/dev/null); then
    readable_env=$((readable_env + 1))
    hits=$(printf '%s\n' "$env_lines" | grep -E '^TD_[A-Z]+=' || true)
    [ -z "$hits" ] || printf 'TDGATE ENV: %s\n%s\n' "$p" "$hits"
    td_tmp=$(printf '%s\n' "$env_lines" | grep -m1 '^TMPDIR=' | cut -d= -f2- || true)
    case "$td_tmp" in
      /) tmpdirs=$(printf '%s\n/' "$tmpdirs") ;;
      /*/) tmpdirs=$(printf '%s\n%s' "$tmpdirs" "${td_tmp%/}") ;;
      /*) tmpdirs=$(printf '%s\n%s' "$tmpdirs" "$td_tmp") ;;
    esac
  else
    [ -d "$p" ] && { echo "COVERAGE ERROR: unreadable environ $p" >&2; read_errors=$((read_errors + 1)); }
  fi
done

sorted_tmpdirs=$(printf '%s\n' "$tmpdirs" | sort -u)
for p in /proc/[0-9]*; do
  [ -d "$p" ] || continue
  if ! cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null); then
    [ -d "$p" ] && { echo "COVERAGE ERROR: unreadable cmdline $p" >&2; read_errors=$((read_errors + 1)); }
    continue
  fi
  [ -n "$cmd" ] || continue

  exe=$(readlink "$p/exe" 2>/dev/null || true)
  if [ -n "$exe" ]; then
    readable_exe=$((readable_exe + 1))
    while IFS= read -r d; do
      case "$d" in
        /) case "$exe" in /*" (deleted)") printf 'DELETED EXECUTABLE: %s exe=%s\n' "$p" "$exe" ;; esac ;;
        *) case "$exe" in "$d"/*" (deleted)") printf 'DELETED EXECUTABLE: %s exe=%s\n' "$p" "$exe" ;; esac ;;
      esac
    done <<EOF
$sorted_tmpdirs
EOF
  elif [ -d "$p" ]; then
    echo "COVERAGE ERROR: unreadable exe $p" >&2
    read_errors=$((read_errors + 1))
  fi

  if comm=$(cat "$p/comm" 2>/dev/null); then
    case "$comm" in
      kworker/*|\[kworker/*)
        [ -z "$exe$cmd" ] || printf 'USERSPACE KWORKER: %s comm=%s exe=%s cmd=%s\n' "$p" "$comm" "$exe" "$cmd"
        ;;
    esac
  elif [ -d "$p" ]; then
    echo "COVERAGE ERROR: unreadable comm $p" >&2
    read_errors=$((read_errors + 1))
  fi
done

fs_checked=0
fs_failed=0
fs_missing=0
scan_tmpdir() {
  d=$1
  if [ ! -d "$d" ]; then
    printf 'FILESYSTEM MISSING: %s\n' "$d"
    fs_missing=$((fs_missing + 1))
  elif find "$d" -maxdepth 2 \( -name '.dsync_rs*' -o -name '.td-www' -o -name '.cache_*' -o -name '.ia' -o -name 'ag_dbg.log' \) -ls; then
    fs_checked=$((fs_checked + 1))
  else
    echo "FILESYSTEM ERROR: $d" >&2
    fs_failed=$((fs_failed + 1))
  fi
}
while IFS= read -r d; do scan_tmpdir "$d"; done <<EOF
$sorted_tmpdirs
EOF

for d in /var/lib /etc/cron.d; do
  if [ ! -d "$d" ]; then
    echo "FILESYSTEM ERROR: required directory missing: $d" >&2
    fs_failed=$((fs_failed + 1))
  elif find "$d" -maxdepth 2 \( -name '.systemd-private-*' -o -name '0hourly-sysstat' -o -name '.nm-inst.sh' -o -name '.nm.conf' -o -name 'systemd-resolved-helper' \) -ls; then
    fs_checked=$((fs_checked + 1))
  else
    echo "FILESYSTEM ERROR: $d" >&2
    fs_failed=$((fs_failed + 1))
  fi
done

listener_failed=0
if command -v ss >/dev/null 2>&1; then
  echo 'LISTENERS:'
  ss -lntp || listener_failed=1
else
  echo 'LISTENER ERROR: ss unavailable' >&2
  listener_failed=1
fi

printf 'COVERAGE: userspace=%s readable_exe=%s readable_env=%s read_errors=%s\n' "$user_processes" "$readable_exe" "$readable_env" "$read_errors"
printf 'FILESYSTEM COVERAGE: checked=%s failed=%s missing=%s\n' "$fs_checked" "$fs_failed" "$fs_missing"
if [ "$user_processes" -eq 0 ] || [ "$readable_exe" -eq 0 ] || [ "$readable_env" -eq 0 ] || [ "$read_errors" -ne 0 ] || [ "$fs_failed" -ne 0 ] || [ "$listener_failed" -ne 0 ]; then
  exit 3
fi
