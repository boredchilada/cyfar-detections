# voidlink-ddos-botnet-docker-abuse.sh
# Self-Blocking Docker API Abuse Delivers the VoidLink DDoS-for-Hire Botnet
# https://github.com/boredchilada/cyfar-detections

# --- daemon.json.disabled-by-dockerpwn fallback artifact ---
sudo find /etc/docker -name 'daemon.json*' -ls

# --- docker logs audit for PWN COMPLETE / dockerpwn ---
sudo journalctl --since "30 days ago" | grep -E 'PWN (COMPLETE|INCOMPLETE)|dockerpwn'

# --- dockerpwn managed ssh marker in sshd_config ---
sudo grep -Rln 'dockerpwn managed ssh' /etc/ssh/ /etc/sshd_config /usr/local/etc/ssh/ 2>/dev/null

# --- Docker systemd override audit ---
sudo find /etc/systemd/system/docker.service.d -name 'override.conf*' -ls

# --- ed25519 marker key in authorized_keys ---
# Run host-side, fleet-wide
sudo find / -name authorized_keys -type f -exec \
  grep -l 'AAAAC3NzaC1lZDI1NTE5AAAAIMhfiGeykxXnvdARJXQSCouFsIHeG+H28W03yY2juP00' {} +

# --- LD_PRELOAD rootkit hook in the agent systemd unit ---
sudo grep -rs 'Environment=LD_PRELOAD=/var/cache/systemd-network/' /etc/systemd/system/ 2>/dev/null

# --- /tmp/pwn.sh content signature ---
sudo find / -name 'pwn.sh' -type f 2>/dev/null | xargs -r grep -l 'Universal Docker Pwn Script'

# --- VoidLink on-disk footprint ---
# masqueraded agent + DDoS modules
sudo ls -la /usr/local/bin/.systemd-network-monitor /usr/local/bin/.fleet-* 2>/dev/null
# persistence unit + boot cron
sudo ls -la /etc/systemd/system/systemd-network-monitor.service 2>/dev/null; sudo crontab -l 2>/dev/null | grep -F systemd-network-monitor
# userland rootkit hook + state directory
sudo grep -s LD_PRELOAD /etc/systemd/system/systemd-network-monitor.service; sudo ls -la /var/cache/systemd-network/ 2>/dev/null

