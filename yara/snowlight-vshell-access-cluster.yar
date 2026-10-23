// snowlight-vshell-access-cluster.yar
// Highway to VShell: cPanel Cron Jobs, a Docker Upload, and SNOWLIGHT
// https://github.com/boredchilada/cyfar-detections

rule SNOWLIGHT_Shell_Loader {
    meta:
        description = "Detects VShell-generated /slw or /slt (linux.sh) multi-architecture SNOWLIGHT shell loader"
        author = "Cyfar"
        date = "2026-10-21"
    strings:
        $w = "writeablex" ascii
        $v = /v="[0-9a-f]{8}(ws|tcp)"/ ascii
        $s1 = "&t=ws&a=" ascii
        $s2 = "&t=tcp&a=" ascii
        $g = "&stage=true" ascii
        $u = "urllib.urlretrieve" ascii
    condition:
        filesize < 5KB and $w and $v and ($s1 or $s2) and $g and $u
}

rule SNOWLIGHT_Loader_ELF {
    meta:
        description = "Detects SNOWLIGHT in-memory ELF loaders across x86-64, x86, ARM64, and ARMv7"
        author = "Cyfar"
        date = "2026-10-21"
    strings:
        $guard = "/tmp/log_de.log" ascii
        $proc  = "[kworker/0:2]" ascii
        $fmt   = "GET /?a=%s&h=%s&t=%s&p=%d HTTP/1.1" ascii
        $ua    = "Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 25KB and all of them
}

rule VShell_4_9_3_Served_ELF {
    meta:
        description = "Detects decoded VShell 4.9.3 ELF builds sharing the 82e64f09... AES-128-CBC configuration blob"
        author = "Cyfar"
        date = "2026-10-21"
    strings:
        $cfg_blob_32 = {
            82 e6 4f 09 30 70 4a bb 57 00 12 fc 70 22 52 2f
            e0 7d 27 5a 9b 1f 86 66 53 35 af 38 4f 16 83 1f
        }
        $ver = "4.9.3" ascii
        $ws1 = "Sec-WebSocket-Key" ascii
        $ws2 = "Upgrade" ascii
    condition:
        uint32(0) == 0x464c457f and filesize > 5MB and filesize < 12MB and $cfg_blob_32 and $ver and $ws1 and $ws2
}
