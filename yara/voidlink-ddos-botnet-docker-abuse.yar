// voidlink-ddos-botnet-docker-abuse.yar
// Self-Blocking Docker API Abuse Delivers the VoidLink DDoS-for-Hire Botnet
// https://github.com/boredchilada/cyfar-detections

import "hash"

rule DockerPwn_v2_Universal_Persistence_Script
{
    meta:
        description = "Universal Docker Pwn Script v2 - SSH-key implant + 2375/2376 closure (both builds)"
        author      = "Cyfar / boredchilada"
        date        = "2026-05-28"
        ref         = "Engagement 45.92.1[.]231 against Docker Engine API"
        sha256_v1   = "ae93e852a0a7aba60258582806c4f36885609016954a31ff6ce4fefcbbb14e17"
        sha256_v2   = "a6e8eca1a19d804836968dea1e4e30f9abbc455be7751d10e2b066fc146c7e39"

    strings:
        $marker1 = "Universal Docker Pwn Script v2"
        $marker2 = "by Polly for"
        $marker3 = "BEGIN dockerpwn managed ssh"
        $marker4 = "AAAAC3NzaC1lZDI1NTE5AAAAIMhfiGeykxXnvdARJXQSCouFsIHeG"
        $marker5 = "daemon.json.disabled-by-dockerpwn"
        $marker6 = "strip_tcp_2375_hosts"
        $marker7 = "Install VoidLink botnet agent"

    condition:
        // Exact-file match on either build OR any 2 of the corpus markers (script may be re-tagged).
        hash.sha256(0, filesize) == "ae93e852a0a7aba60258582806c4f36885609016954a31ff6ce4fefcbbb14e17"
        or hash.sha256(0, filesize) == "a6e8eca1a19d804836968dea1e4e30f9abbc455be7751d10e2b066fc146c7e39"
        or 2 of ($marker*)
}

rule VoidLink_FleetAgent
{
    meta:
        author = "cyfar / boredchilada"
        date = "2026-06-10"
        description = "VoidLink (aka Fleet) DDoS-for-hire botnet agent - Go binary, all builds"
        reference = "https://code.cyfar.ca/cyfar/detonation-lab (private)"
        hash_abe412b = "e2f064892cfe10b5856bbf4285de9248d2f8d7e1b6ea21d6db943ade8b20d0ad"
        hash_ad9ce0f = "31f48c774b15"
        tlp = "amber"
        family = "VoidLink"
        actor = "Polly"

    strings:
        // Go module path (stable across all 29 builds - the strongest anchor)
        $mod = "fleet-agent/internal/agent" ascii

        // Source file paths (compiled into every build via pclntab)
        $src_ws      = "fleet-agent/internal/agent/ws_client.go" ascii
        $src_ddos    = "fleet-agent/internal/agent/jobs_ddos.go" ascii
        $src_hide    = "fleet-agent/internal/agent/hidepid_linux.go" ascii
        $src_stealth = "fleet-agent/internal/agent/stealth_linux.go" ascii
        $src_crypto  = "fleet-agent/internal/agent/crypto.go" ascii

        // Function names unique to this family (not in any legit Go project)
        $fn_enroll   = "fleet-agent/internal/agent.EnsureEnrollment" ascii
        $fn_heartbt  = "fleet-agent/internal/agent.(*wsClient).sendHeartbeat" ascii
        $fn_result   = "fleet-agent/internal/agent.(*wsClient).sendResult" ascii
        $fn_hidepid  = "fleet-agent/internal/agent.InitHidePids" ascii
        $fn_memfd    = "fleet-agent/internal/agent.memfdCreateExecutable" ascii
        $fn_hulk     = "fleet-agent/internal/agent.runDdosHulk" ascii
        $fn_l4       = "fleet-agent/internal/agent.runDdosL4" ascii
        $fn_l7       = "fleet-agent/internal/agent.runDdosL7" ascii
        $fn_mtproto  = "fleet-agent/internal/agent.runDdosMtprotoProxy" ascii
        $fn_masked   = "fleet-agent/internal/agent.runMaskedTool" ascii

        // DDoS command key prefixes (stable across builds)
        $cmd_udp     = "ddos-udp" ascii
        $cmd_tcp     = "ddos-tcp" ascii
        $cmd_hulk    = "ddos-hul" ascii
        $cmd_http    = "ddos-htt" ascii
        $cmd_ack     = "ddos-ack" ascii
        $cmd_byp     = "ddos-byp" ascii
        $cmd_aut     = "ddos-aut" ascii

        // Persistence / rootkit paths
        $path_hide   = ".hidepids" ascii
        $path_jenv   = ".journal.env" ascii
        $path_jstat  = ".journal.state" ascii

        // C2 protocol strings
        $proto_ws    = "/ws/agent" ascii
        $proto_enr   = "/api/agents/enroll" ascii
        $proto_hb    = "/api/agents/heartbeat" ascii

        // Env var names unique to this bot
        $env_server  = "FLEET_SERVER_URL" ascii
        $env_token   = "FLEET_ENROLLMENT_TOKEN" ascii
        $env_mode    = "FLEET_AGENT_MODE" ascii
        $env_key     = "FLEET_TRANSPORT_KEY" ascii
        $env_sudo    = "FLEET_ALLOWED_SUDO" ascii


    condition:
        uint32(0) == 0x464C457F  // ELF magic
        and filesize > 4MB and filesize < 12MB
        and $mod
        and (
            // strong match: module path + any 3 source files
            (3 of ($src_*))
            or
            // strong match: module path + any 3 function names
            (3 of ($fn_*))
            or
            // medium match: module path + 4 DDoS command keys + 2 env vars
            (4 of ($cmd_*) and 2 of ($env_*))
            or
            // medium match: module path + C2 protocol + persistence paths
            (2 of ($proto_*) and 2 of ($path_*))
        )
}

rule VoidLink_FleetAgent_Bootstrap
{
    meta:
        author = "cyfar / boredchilada"
        date = "2026-06-10"
        description = "VoidLink bootstrap/dropper script (installs fleet-agent + libhide rootkit)"
        family = "VoidLink"

    strings:
        $svc_name    = "systemd-network-monitor" ascii
        $svc_path    = "/usr/local/bin/.systemd-network-monitor" ascii
        $hide_lib    = "libhide" ascii
        $preload     = "/etc/ld.so.preload" ascii
        $state_dir   = "/var/cache/systemd-network" ascii
        $env_file    = ".journal.env" ascii
        $fleet_url   = "FLEET_SERVER_URL" ascii
        $fleet_token = "FLEET_ENROLLMENT_TOKEN" ascii
        $reset_fail  = "systemctl reset-failed" ascii

    condition:
        filesize < 50KB
        and 4 of them
}

rule VoidLink_LibHide_Rootkit
{
    meta:
        author = "cyfar / boredchilada"
        date = "2026-06-10"
        description = "VoidLink libhide.so LD_PRELOAD rootkit (hides agent PIDs)"
        family = "VoidLink"

    strings:
        $hidepids    = ".hidepids" ascii
        $preload     = "/etc/ld.so.preload" ascii
        $readdir     = "readdir" ascii
        $dlsym       = "dlsym" ascii
        $proc_stat   = "/proc/%s/stat" ascii
        $legacy_pid  = ".hidepid" ascii
        $cache_dir   = "/var/cache/systemd-network" ascii

    condition:
        uint32(0) == 0x464C457F  // ELF
        and filesize < 100KB
        and 5 of them
}

