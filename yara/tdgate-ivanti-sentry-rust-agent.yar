rule TDGate_High_Confidence {
    meta:
        description = "TDGate Rust C2, reverse proxy, and relay (configured build)"
        author = "Cyfar"
        date = "2026-11-02"
        sha256 = "f65b95003379ee8e8a6eaeef1405af5d5d7282ab93567b4622d917a5d9f1335d"
        severity = "critical"
        tlp = "clear"
    strings:
        $c2_domain = "cdn.876553.xyz" ascii
        $gate_token = "ChangeMe_GateToken_9f3K" ascii
        $path_token = "Q1fc8a9OCb7AsC6f" ascii
        $enc_proto = "td-enc-v1" ascii
        $tun_local = "td-tun.local" ascii
        $gate_local = "td-gate.local" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize > 500000 and filesize < 10000000 and
        3 of them
}

rule TDGate_Family_Behavior {
    meta:
        description = "TDGate family protocol, runtime, file, and operator strings"
        author = "Cyfar"
        date = "2026-11-02"
        sha256 = "f65b95003379ee8e8a6eaeef1405af5d5d7282ab93567b4622d917a5d9f1335d"
        severity = "high"
        tlp = "clear"
    strings:
        $p_tunhello = "TUNHELLO" ascii
        $p_tunpingf = "TUNPINGF" ascii
        $p_encstart1 = "ENCSTART1" ascii
        $p_label = ":td-enc-v1" ascii
        $p_encerr1 = "bad enc chunk" ascii
        $p_encerr2 = "enc auth fail" ascii
        $p_cap = "pty,ustall,shsize" ascii
        $p_udp = "udp enc ack timeout" ascii
        $b_hb = "heartbeat timeout" ascii
        $b_stall = "upload stall" ascii
        $b_eof = "eof during upload body" ascii
        $e_nodel = "TD_NODEL" ascii
        $e_nosb = "TD_NOSB" ascii
        $e_proto = "TD_PROTO" ascii
        $e_tunplain = "TD_TUNPLAIN" ascii
        $e_idsalt = "TD_IDSALT" ascii
        $f_id = ".dsync_rs.cache" ascii
        $f_www = ".td-www" ascii
        $f_log = "ag_dbg.log" ascii
        $s_gate = "td-gate.local" ascii
        $s_tun = "td-tun.local" ascii
        $z_node = "节点监听已启动" ascii
        $z_dup = "已复制: 新实例已启动" ascii
        $z_dl = "下载载荷失败" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize > 500000 and filesize < 20000000 and
        10 of them
}

rule TDGate_Build_Environment {
    meta:
        description = "TDGate inspected-build compiler path and crate fingerprint"
        author = "Cyfar"
        date = "2026-11-02"
        sha256 = "f65b95003379ee8e8a6eaeef1405af5d5d7282ab93567b4622d917a5d9f1335d"
        severity = "informational"
        tlp = "clear"
    strings:
        $rustc_hash = "/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea452" ascii
        $builder = "/Users/hackma/.cargo/registry" ascii
        $oxitls = "oxitls-rustcrypto-provider-0.3.0" ascii
        $chacha = "chacha20poly1305-0.10.1" ascii
        $rustls = "rustls-0.23.44" ascii
        $aes_gcm = "aes-gcm-0.10.3" ascii
        $curve = "curve25519-dalek-4.1.3" ascii
        $rsa_crate = "rsa-0.9.10" ascii
        $hmac = "hmac-0.12.1" ascii
    condition:
        uint32(0) == 0x464C457F and
        $rustc_hash and $builder and $oxitls and
        3 of ($chacha, $rustls, $aes_gcm, $curve, $rsa_crate, $hmac)
}
