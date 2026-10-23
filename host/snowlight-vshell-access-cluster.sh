# snowlight-vshell-access-cluster.sh
# Highway to VShell: cPanel Cron Jobs, a Docker Upload, and SNOWLIGHT
# https://github.com/boredchilada/cyfar-detections

# --- SNOWLIGHT, VShell 4.9.3, and cPanel CVE-2026-41940 Host Hunt ---
# 1. Check host PID namespace for user-space processes backed by /memfd:a (deleted)
for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null || true)
    case "$exe" in
        /memfd:*)
            cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)
            cwd=$(tr '\0' '\n' < "$p/environ" 2>/dev/null | grep '^CWD=' || true)
            printf "PID=%s EXE=%s CMD=%s %s\n" "${p#/proc/}" "$exe" "$cmd" "$cwd"
            ;;
    esac
done

# 2. Check disk for SNOWLIGHT stage binary, Docker upload, exit guard, dropped slw, and cron output
ls -la /tmp/.sysd /tmp/a19b30acws /usr/local/bin/a19b30acws /usr/libexec/a19b30acws /usr/bin/a19b30acws /tmp/log_de.log /home/*/slw /home/*/public_html/.s.txt 2>/dev/null

# 3. Inspect cPanel raw session files for this cluster's CVE-2026-41940 canary keys or CR-injected lines
grep -rnaE '(nxesec_canary_|^nx=[A-Za-z0-9]{6}=1|(successful_(internal|external)_auth_with_timestamp|hasroot)=.*\r)' /var/cpanel/sessions/raw/ 2>/dev/null

# 4. Check cPanel access_log for post-bypass svc<6> account creation and Cron add_line calls, and inspect user crontabs
grep -aE '(/cpsess[0-9]+/json-api/createacct\?api\.version=1&username=svc[a-z0-9]{6}&|cpanel_jsonapi_module=Cron&cpanel_jsonapi_func=add_line)' /usr/local/cpanel/logs/access_log 2>/dev/null
grep -rnE '(:8988/slw|public_html/\.s\.txt|RCEOK)' /var/spool/cron/ 2>/dev/null
