// boatnet-docker-etherhiding.yar
// Get Boated: Docker-Delivered Mirai-Linked Malware With EtherHiding C2
// https://github.com/boredchilada/cyfar-detections

rule Boatnet_Packed_Suffix
{
    meta:
        description = "Boatnet UPX-packed ELF carrying the shared 16-byte trailing suffix that breaks stock UPX unpacking"
        author = "Cyfar"
        date = "2026-09-25"
        sha256 = "132ce4e05bfb237b59417ef958ad0a4eb753a0084dc827f8d36eb57971b7707f"

    strings:
        $upx = "UPX!" ascii
        $suffix = "BN4/mG7otq7uVCjF" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1MB and
        #upx >= 2 and
        $suffix at (filesize - 16)
}

rule Boatnet_Unpacked_EtherHiding
{
    meta:
        description = "Unpacked Boatnet ELF: family marker or embedded Polygon EtherHiding contract, selector, and RPC providers"
        author = "Cyfar"
        date = "2026-09-25"
        sha256 = "9c47bda7b9ad9aaff10af520fbd2a6a0daa35368d5748d9a1fc3e02cf4efc300"

    strings:
        $family = "boatnet-unit-v2" ascii
        $contract = "0x5D5abC33a4e5C602a002815d93806b204324D1a1" ascii nocase
        $selector = "6d4ce63c" ascii
        $rpc1 = "polygon.drpc.org" ascii
        $rpc2 = "polygon-bor.publicnode.com" ascii
        $rpc3 = "polygon.gateway.tenderly.co" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 4MB and
        ($family or ($contract and $selector and 2 of ($rpc*)))
}
