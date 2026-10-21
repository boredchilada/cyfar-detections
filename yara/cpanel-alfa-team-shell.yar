// cpanel-alfa-team-shell.yar
// cPanel Exploit Attempt Uncovers Alfa Team Shell and AnonSec LPE Chain
// https://github.com/boredchilada/cyfar-detections

rule PHP_ALFA_Team_4_1_Tesla
{
    meta:
        description = "Detects Alfa Team Shell 4.1 Tesla source code or single Base64 wrapper"
        author = "Cyfar"
        date = "2026-09-20"
        sha256 = "2f1f63b7d2fe56fdad569712ecb92e4ffd6099f2f2a6cf7fbdbe76349490a45f"

    strings:
        $entry_plain = "goto tnf0H; X1oql: function alfapwchanger()" ascii
        $entry_b64 = "goto tnf0H; X1oql: function alfapwchanger()" base64
        $post_plain = "q50cF: foreach ($_POST as $key => $value)" ascii
        $post_b64 = "q50cF: foreach ($_POST as $key => $value)" base64
        $mysql_plain = "function alfaMysqlApi(e,t)" ascii
        $mysql_b64 = "function alfaMysqlApi(e,t)" base64

    condition:
        filesize < 2MB and
        ($entry_plain or $entry_b64) and
        ($post_plain or $post_b64) and
        ($mysql_plain or $mysql_b64)
}
