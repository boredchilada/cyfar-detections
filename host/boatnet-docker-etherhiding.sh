# boatnet-docker-etherhiding.sh
# Get Boated: Docker-Delivered Mirai-Linked Malware With EtherHiding C2
# https://github.com/boredchilada/cyfar-detections

# --- Boatnet Filesystem and Process Artifacts ---
# Boatnet drop, update, and lock paths
for p in /dev/shm/b1 /tmp/b1 /var/cache/.dk /tmp/.dkprobe /tmp/.X-lock /tmp/.bot_updating /var/cache/.upd_boat /etc/.upd_boat /var/tmp/.upd_boat /dev/shm/.upd_boat; do [ -e "$p" ] && echo "[!] Boatnet path: $p"; done

# Installed copies: search for the retained packed-build marker before the appended trailer
for f in /etc/.* /var/cache/.* /var/lib/.* /usr/bin/.* /root/.cache/.* /home/*/.cache/.*; do [ -f "$f" ] && LC_ALL=C grep -aFq -- 'BN4/mG7otq7uVCjF' "$f" && echo "[!] Boatnet binary: $f"; done

# Persistence
grep -rls "boatnet-unit-v2" /etc/systemd/system && echo "[!] Boatnet systemd unit"
grep -rlsE '^\*/5 \* \* \* \* root /[^[:space:]]*/\.[^[:space:]]+ >/dev/null 2>&1$' /etc/cron.d && echo "[!] Suspicious hidden-binary cron entry"

# Fake kworker process: userland PID claiming a kernel worker name
ps -eo pid,ppid,comm,args | awk '$3 == "kworker/1:1" && $2 != 2 { print "[!] Suspicious userland kworker:", $0 }'
