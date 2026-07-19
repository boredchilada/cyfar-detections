#!/bin/sh
# n4d-mcp-worm.sh
# n4d/NadMesh: C2-Coordinated Propagation System Weaponizes MCP
# https://github.com/boredchilada/cyfar-detections
#
# These are hunt commands, not a script to run blindly. Read each one, understand
# what it checks, and run the relevant ones on hosts you suspect are compromised.
# Paths and the SSH key were confirmed during controlled detonation and live capture.

# --- Node-ID files and binary self-copies (high confidence) ---
# The worm writes a 16-char hex node ID triplicated across /tmp, /var/tmp, /dev/shm,
# plus PID/lock files and binary self-copies.
find /dev/shm /tmp /var/tmp -name '.n4d_nid' -o -name '.agent.pid' -o -name '.agent.lock' -o -name '.wd' 2>/dev/null
ls -la /var/tmp/.a /usr/local/lib/.a /tmp/.sys-health-monitor 2>/dev/null

# --- Login-hook persistence ---
# Respawns the worm on user login via profile.d or bashrc.
grep -l 'pgrep.*var/tmp/\.a\|/var/tmp/\.wd' /etc/profile.d/.sys_alias.sh /root/.bashrc 2>/dev/null

# --- SSH persistence key (definitive) ---
# The attacker's ed25519 key appended to authorized_keys.
grep 'AAAAC3NzaC1lZDI1NTE5AAAAIJKH4g/SD6c00i5PzlWWkwXJwIHEac+nlAjg6WeOHUq3' /root/.ssh/authorized_keys ~/.ssh/authorized_keys 2>/dev/null

# --- Cron-based updater ---
# Fetches updates from cdnorigin.net, falls back to the C2 IP on port 9090.
crontab -l 2>/dev/null | grep -E 'sys-health-monitor|cdnorigin'
find /var/spool/cron /etc/cron.d /etc/crontabs -type f -exec grep -l 'sys-health-monitor\|cdnorigin' {} \; 2>/dev/null
