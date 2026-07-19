// n4d-mcp-worm.yar
// n4d/NadMesh: C2-Coordinated Propagation System Weaponizes MCP
// https://github.com/boredchilada/cyfar-detections
//
// The packed agent is UPX-compressed and garble-obfuscated. On-disk detection of
// the packed form cannot be distinguished from any other UPX-packed Go binary, so
// there is no packed-agent rule here. Detect packing generically, then unpack
// (upx -d) and apply n4d_agent_unpacked, which keys on type metadata that survives
// garble's -literals pass.

rule n4d_persistence_watchdog
{
    meta:
        description = "n4d watchdog script - respawns agent every 25 seconds, re-downloads from C2"
        author      = "boredchilada"
        date        = "2026-07-15"
        tlp         = "CLEAR"
        hash_wd     = "dfe3ff4f58fbc1784858840858bb02fd88a9a003476c24a97e7604b9b9cb3fea"

    strings:
        $pgrep = "pgrep -f '/var/tmp/.a|/tmp/.a|/dev/shm/.a'"
        $c2_dl = "/api/agent/full?arch="
        $sleep = "sleep 25"

    condition:
        filesize < 2KB and
        $pgrep and $c2_dl and $sleep
}

rule n4d_persistence_updater
{
    meta:
        description = "n4d cron updater script - fetches agent updates from cdnorigin.net"
        author      = "boredchilada"
        date        = "2026-07-15"
        tlp         = "CLEAR"
        hash_sm     = "001a23e4a0c7cbdc076db370cfcffbbbd7c86214040f339708ca9b818fba69ab"

    strings:
        $lock = "/tmp/.n4d_lock"
        $cdn = "cdnorigin.net"
        $agent_path = "/api/agent/binary?arch="

    condition:
        filesize < 2KB and
        $lock and $cdn and $agent_path
}

rule n4d_persistence_login_hook
{
    meta:
        description = "n4d shell login hook - respawns agent on user login via profile.d or bashrc"
        author      = "boredchilada"
        date        = "2026-07-15"
        tlp         = "CLEAR"
        hash_sh     = "806381665929b54b2079ed93b464ee660194bb20e294607bdc97ead27e48679e"

    strings:
        $hook = "pgrep -f '/var/tmp/.a|/tmp/.a'"
        $wd   = "/var/tmp/.wd"

    condition:
        filesize < 500 and
        $hook and $wd
}

rule n4d_ssh_key
{
    meta:
        description = "n4d SSH persistence key in authorized_keys"
        author      = "boredchilada"
        date        = "2026-07-15"
        tlp         = "CLEAR"

    strings:
        $key = "AAAAC3NzaC1lZDI1NTE5AAAAIJKH4g/SD6c00i5PzlWWkwXJwIHEac+nlAjg6WeOHUq3"

    condition:
        $key
}

rule n4d_agent_unpacked
{
    meta:
        description = "n4d MCP propagation agent (unpacked, garble-obfuscated)"
        author      = "boredchilada"
        date        = "2026-07-15"
        tlp         = "CLEAR"
        note        = "For use after UPX unpacking. Garble encrypts string literals but Go type metadata survives."

    strings:
        // MCP tool dispatch handler names (Go type metadata, survives garble -literals)
        $h1 = "ExecPy"
        $h2 = "jsCode"
        $h3 = "es_rce"
        $h4 = "pg_rce"

        // MCP endpoint paths (type metadata)
        $m1 = "/mcp"
        $m2 = "/sse"
        $m3 = "jsonrpc"

        // Honeypot/analysis awareness strings (type metadata)
        $hp1 = "cowrie"
        $hp2 = "t-pot"
        $hp3 = "canary"
        $hp4 = "tarpit"
        $hp5 = "ghidra"

        // Go build info
        $go = "Go buildinf:"

    condition:
        uint32(0) == 0x464C457F and
        filesize > 15MB and filesize < 30MB and
        $go and
        (3 of ($h*)) and
        (2 of ($hp*)) and
        (1 of ($m*))
}
