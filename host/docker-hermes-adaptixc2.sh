# docker-hermes-adaptixc2.sh
# A Miner Was Only the First Clue: From Docker to Hermes and AdaptixC2
# https://github.com/boredchilada/cyfar-detections

# --- hermes-internal and kworker masquerade hunt ---
#!/bin/sh
# Hunt for hermes-internal AdaptixC2 persistence and all retained miner placements.
# Run as root in the host PID and mount namespaces. Read-only — no changes.
set -eu

echo "=== hermes-internal binary ==="
for p in /usr/local/bin/hermes-internal /usr/bin/hermes-internal; do
  [ -f "$p" ] && echo "FOUND: $p ($(stat -c'%s bytes, modified %y' "$p"))" && sha256sum "$p"
done

echo "=== hermes-internal systemd unit ==="
for u in /etc/systemd/system/hermes-internal.service /etc/systemd/system/multi-user.target.wants/hermes-internal.service; do
  [ -f "$u" ] && echo "FOUND: $u" && cat "$u"
done
systemctl is-active hermes-internal 2>/dev/null && echo "SERVICE ACTIVE" || true

echo "=== hermes-internal plugin directory ==="
find /root/.hermes/plugins /home/*/.hermes/plugins -maxdepth 2 -name 'hermes-internal' -type d 2>/dev/null | while read d; do
  echo "FOUND: $d"
  ls -la "$d/" 2>/dev/null
done

echo "=== kworker miner masquerade ==="
# Compare the displayed argv with the executable path; process titles alone are not verdicts.
for proc in /proc/[0-9]*; do
  args=$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)
  exe=$(readlink "$proc/exe" 2>/dev/null || true)
  case "$args" in
    *kworker/u2:1*)
      case "$exe" in */bash|*/sh|*/busybox) continue;; esac
      echo "SUSPICIOUS: $proc argv=$args exe=$exe"
      continue
      ;;
  esac
  case "$exe" in
    */.kdaemon|*/.kwork|*/.cache/.kh|*/.cache/.x/.kh|*/dev/shm/.s|*/tmp/.s)
      echo "SUSPICIOUS: $proc argv=$args exe=$exe"
      ;;
  esac
done

echo "=== miner staging files ==="
find /root /home /tmp /dev/shm -xdev -type f \( -name '.kdaemon' -o -name '.kwork' -o -name '.kwd' -o -name '.kwd*' -o -name '.kh' -o -name '.kwdb' -o -name '.kw.json' -o -name '.kworker' -o -name '.kw.gz' \) -print 2>/dev/null | while read f; do
  echo "FOUND: $f ($(stat -c'%s bytes, modified %y' "$f"))"
  sha256sum "$f"
done

echo "=== fsweep miner placements ==="
# A generic .s file is not sufficient by itself; record its hash and any matching process.
for p in /dev/shm/.s /tmp/.s /opt/data/.sysmon /tmp/.sysmon; do
  [ -f "$p" ] || continue
  echo "FOUND: $p ($(stat -c'%s bytes, modified %y' "$p"))"
  sha256sum "$p"
  for proc in /proc/[0-9]*; do
    [ "$(readlink "$proc/exe" 2>/dev/null || true)" = "$p" ] || continue
    echo "RUNNING: $proc -> $p"
    tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true
    echo
  done
done

echo "=== credential stealer output files ==="
find /opt/data /tmp /root /home -maxdepth 3 \( -name '.exk.out' -o -name '.exk2.out' -o -name '.fsweep.out' -o -name '.wk.out' \) 2>/dev/null | while read f; do
  echo "FOUND: $f ($(stat -c'%s bytes, modified %y' "$f"))"
done

echo "=== cron persistence ==="
find /etc/cron.d /var/spool/cron \( -name '.sysmon' -o -name '*kinst*' \) -type f 2>/dev/null | while read f; do
  echo "FOUND: $f" && sed -n '1,40p' "$f"
done

echo "=== systemservice miner ==="
[ -d /opt/systemservice ] && echo "FOUND: /opt/systemservice" && ls -la /opt/systemservice/
systemctl is-active systemservice 2>/dev/null && echo "SERVICE ACTIVE" || true

echo "=== docker containers with sysmon name ==="
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null | grep -i sysmon && echo "CONTAINER FOUND" || true

echo "=== DONE ==="
