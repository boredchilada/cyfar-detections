# cyfar-detections

Detection rules from [cyfar.ca](https://cyfar.ca) engagement reports. Suricata, YARA, Sigma, and host-level hunt commands, with test fixtures for the network rules.

Each rule traces back to a specific engagement on the blog. The report has the context. The rules here are the deployable artifacts.

## What's in here

```
suricata/          .rules files, one per engagement
yara/              YARA rules for file-level detection
sigma/             Sigma rules for Linux process-creation telemetry
host/              Shell hunt commands for post-compromise triage
tests/
  fixtures/        YAML test cases (positive + negative) per Suricata rule
  benign-corpus/   Normal-traffic specs for false positive testing
  validate.py      Test runner: builds pcaps, replays through Suricata, checks SIDs
  benign_check.py  FP checker: runs all rules against the benign corpus
  craft_pcap.py    Generates pcaps from YAML specs
  Dockerfile       Suricata 7.0 container for the runner
```

## Current rules

### Ivanti Sentry CVE-2026-10520

[Ten Operators, One Ivanti Sentry Command-Injection Endpoint](https://cyfar.ca/engagements/ten-operators-one-ivanti-sentry-command-injection-endpoint)

| File | Type | Rules |
|------|------|-------|
| `suricata/ivanti-sentry-cve-2026-10520.rules` | Suricata | 1 (pre-auth MICS handleMessage POST) |
| `yara/ivanti-sentry-cve-2026-10520.yar` | YARA | 2 (JSP + PHP webshell) |
| `host/ivanti-sentry-cve-2026-10520.sh` | Host | 1 (UID-0 backdoor, webshell, history clearing) |

### TDGate delivered through Ivanti Sentry CVE-2026-10520

[Self-Deleting After C2 Check-In: TDGate Delivery Commands Targeting Ivanti Sentry CVE-2026-10520](https://cyfar.ca/engagements/self-deleting-after-c2-check-in-tdgate-delivery-commands-targeting-ivanti)

| File | Type | Rules |
|------|------|-------|
| `suricata/ivanti-sentry-cve-2026-10520.rules` | Suricata | 1 shared MICS command-execution rule |
| `suricata/tdgate-ivanti-sentry-rust-agent.rules` | Suricata | 5 (WebSocket gate/tunnel, fake local SNI, cleartext handshake, C2/delivery SNI, plain-HTTP delivery Host) |
| `yara/tdgate-ivanti-sentry-rust-agent.yar` | YARA | 3 (configured build, family behavior, build environment) |
| `sigma/tdgate-ivanti-sentry-rust-agent-delivery.yml` | Sigma | 1 (delivery commands or temporary-path launch) |
| `sigma/tdgate-ivanti-sentry-rust-agent-miner.yml` | Sigma | 1 (miner launch, installer, and masquerade commands) |
| `host/tdgate-ivanti-sentry-rust-agent.sh` | Host | 1 fail-loud Linux triage script (refuses to run outside the host PID and mount namespaces) |

The shared MICS rule is counted under the earlier Ivanti Sentry report in the repository totals.

### VoidLink DDoS-for-hire botnet + Docker Engine API abuse

[Self-Blocking Docker API Abuse Delivers the VoidLink DDoS-for-Hire Botnet](https://cyfar.ca/engagements/self-blocking-docker-api-abuse-delivers-the-voidlink-ddos-for-hire-botnet)

| File | Type | Rules |
|------|------|-------|
| `suricata/voidlink-ddos-botnet-docker-abuse.rules` | Suricata | 13 (Docker API abuse, host escape, C2 enrollment, binary download, bootstrap fetch) |
| `yara/voidlink-ddos-botnet-docker-abuse.yar` | YARA | 4 (DockerPwn persistence script, VoidLink fleet agent, bootstrap dropper, libhide rootkit) |
| `host/voidlink-ddos-botnet-docker-abuse.sh` | Host | 8 (SSH markers, systemd overrides, rootkit hooks, on-disk artifacts) |

### Cross-service credential replay

[Cross-Service Credential Replay: Operator Targets Hypervisor Using Harvested LLM Endpoint Secrets](https://cyfar.ca/engagements/cross-service-credential-replay-operator-targets-hypervisor-using-harvested-llm)

| File | Type | Rules |
|------|------|-------|
| `suricata/cross-service-credential-replay.rules` | Suricata | 1 (prompt injection env-var exfil) |

### n4d/NadMesh MCP propagation worm

[n4d/NadMesh: C2-Coordinated Propagation System Weaponizes MCP](https://cyfar.ca/engagements/n4dnadmesh-c2-coordinated-propagation-system-weaponizes-mcp)

| File | Type | Rules |
|------|------|-------|
| `suricata/n4d-mcp-worm.rules` | Suricata | 3 (external MCP initialize, C2 + cdnorigin agent download) |
| `yara/n4d-mcp-worm.yar` | YARA | 5 (unpacked agent, watchdog, updater, login hook, SSH key) |
| `host/n4d-mcp-worm.sh` | Host | 4 (node-ID + binary self-copies, login hook, SSH key, cron updater) |

The packed agent (UPX + garble) has no dedicated rule: on disk it is indistinguishable from any other UPX-packed Go binary. Detect packing generically, unpack with `upx -d`, then apply `n4d_agent_unpacked`.

### cPanel/WHM Alfa Team Shell

[cPanel Exploit Attempt Uncovers Alfa Team Shell and AnonSec LPE Chain](https://cyfar.ca/engagements/cpanel-exploit-attempt-uncovers-alfa-team-shell-and-anonsec-lpe-chain)

| File | Type | Rules |
|------|------|-------|
| `yara/cpanel-alfa-team-shell.yar` | YARA | 1 (Alfa Team Shell 4.1 Tesla source or Base64 wrapper) |

### Boatnet Docker-delivered bot with EtherHiding C2

[Get Boated: Docker-Delivered Mirai-Linked Malware With EtherHiding C2](https://cyfar.ca/engagements/get-boated-docker-delivered-mirai-linked-malware-with-etherhiding-c2)

| File | Type | Rules |
|------|------|-------|
| `suricata/boatnet-docker-etherhiding.rules` | Suricata | 2 (Docker API archive upload into a host-mounted path, Boatnet execution argument in a Docker API request) |
| `yara/boatnet-docker-etherhiding.yar` | YARA | 2 (UPX-packed build with the trailing suffix, unpacked build) |
| `host/boatnet-docker-etherhiding.sh` | Host | 1 (drop and lock paths, installed binaries by marker, systemd and cron persistence, kworker masquerade) |

### Hermes plugin and AdaptixC2 delivered through the Docker API

[A Miner Was Only the First Clue: From Docker to Hermes and AdaptixC2](https://cyfar.ca/engagements/a-miner-was-only-the-first-clue-from-docker-to-hermes-and-adaptixc2)

| File | Type | Rules |
|------|------|-------|
| `host/docker-hermes-adaptixc2.sh` | Host | 1 (hermes-internal binary, unit and plugin directory, kworker miner masquerade, miner placements, credential stealer output, cron) |

The report's Suricata rule is SID 1000231001, listed in the VoidLink section above.

### Citrix NetScaler CVE-2026-88771

[The Pitboss Pipeline: NetScaler Log Poisoning and a FreeBSD Sliver Implant](https://cyfar.ca/engagements/the-pitboss-pipeline-netscaler-log-poisoning-and-a-freebsd-sliver-implant)

| File | Type | Rules |
|------|------|-------|
| `suricata/netscaler-cve-2026-88771.rules` | Suricata | 5 (Pitboss log poisoning in the request body and User-Agent, INDEX log smuggling header, pylrk[.]cc DNS lookup and TLS SNI) |
| `yara/netscaler-cve-2026-88771.yar` | YARA | 2 (FreeBSD Sliver implant, shell loader) |
| `host/netscaler-cve-2026-88771.sh` | Host | 1 (dropped files, web server handler changes, INDEX marker in access logs, loader files and boot entry) |

### SafeNetv2 Go multi-exploit worm

[Scan, Exploit, Spread: Inside SafeNetv2](https://cyfar.ca/engagements/scan-exploit-spread-inside-safenetv2)

| File | Type | Rules |
|------|------|-------|
| `suricata/safenet-multi-exploit-worm.rules` | Suricata | 3 (CVE-2025-55182 RCE oracle request, CVE-2025-55182 Node.js dropper deployment, forged JFrog Artifactory empty-hash-kid JOIN JWT) |
| `yara/safenet-multi-exploit-worm.yar` | YARA | 1 (SafeNetv2 `safenet/client` Go worm ELF across amd64, 386, and arm64) |
| `host/safenet-multi-exploit-worm.sh` | Host | 1 (candidate temporary and process working directories, `SAFENET_*` environment keys, TCP/10001 sockets) |

### cPanel CVE-2026-41940, Docker API upload, SNOWLIGHT, and VShell 4.9.3

[Highway to VShell: cPanel Cron Jobs, a Docker Upload, and SNOWLIGHT](https://cyfar.ca/engagements/highway-to-vshell-cpanel-cron-jobs-a-docker-upload-and-snowlight)

| File | Type | Rules |
|------|------|-------|
| `suricata/snowlight-vshell-access-cluster.rules` | Suricata | 5 (cPanel CVE-2026-41940 Basic Auth CR/LF session injection, cPanel JSON-API Cron `add_line` stager persistence, `/slw` architecture selector request, SNOWLIGHT stage request, Docker API stageless download command) |
| `yara/snowlight-vshell-access-cluster.yar` | YARA | 3 (`/slw` shell loader, SNOWLIGHT ELF loader across amd64/386/arm64/armv7, decoded VShell 4.9.3 builds sharing the 20,480-byte AES-128-CBC configuration blob) |
| `host/snowlight-vshell-access-cluster.sh` | Host | 1 (`/memfd:a (deleted)` `[kworker/0:2]` process check, `/tmp/log_de.log` and `a19b30acws` file check, cPanel raw session and crontab checks) |

**Totals:** 38 Suricata rules, 23 YARA rules, 2 Sigma rules, 19 host hunt commands. More rules land as new engagement reports publish.

## Using the rules

**Suricata:** Copy `.rules` files into your rules directory and reference them in `suricata.yaml`. All rules use standard `$HOME_NET` / `$EXTERNAL_NET` variables.

**YARA:** Point your scanner at `yara/`. The rules are self-contained, no imports or module dependencies.

**Sigma:** The `.yml` rules target Linux `process_creation` events with complete `Image` and `CommandLine` values. Convert them with your SIEM's Sigma backend and map those two fields.

**Host:** The `.sh` files are collections of hunt commands, not scripts to execute blindly. Read them, understand what each command checks for, and run the relevant ones on hosts you suspect may be compromised.

## Running the Suricata tests

The test runner validates every Suricata rule in two passes. First it runs `suricata -T` to confirm the rule parses without syntax errors. Then it generates a synthetic pcap from the fixture's HTTP request spec, replays it through Suricata, and checks `eve.json` for the expected alert SIDs. Positive tests confirm the rule fires on traffic that matches the detection. Negative tests send similar but benign traffic and confirm the rule stays quiet.

Requires Docker. Builds a Suricata 7.0 container with scapy for pcap generation.

```bash
cd tests
docker compose build
docker compose run --rm validator
```

### Fixture format

Each YAML fixture is self-contained: it carries the rule text and one or more test cases. A test case describes an HTTP request (method, URI, host, headers, body) and lists the SIDs that should or should not fire. The runner turns that spec into a full TCP handshake + HTTP exchange pcap, so there's no need to capture or store real traffic.

```yaml
name: "Ivanti Sentry CVE-2026-10520 pre-auth command injection"
rule: >-
  alert http $EXTERNAL_NET any -> $HOME_NET 8443 (msg:"IVANTI SENTRY CVE-2026-10520
  MICS handleMessage POST"; flow:to_server,established; http.method; content:"POST";
  http.uri; content:"/mics/"; content:"/handleMessage"; sid:1000844001; rev:1;)
tests:
  - name: "positive-handlemessage-external-post"
    expected_sids: [1000844001]
    request:
      method: POST
      uri: /mics/api/v2/sentry/mics-config/handleMessage
      host: 198.51.100.10
      port: 8443
      headers:
        Content-Type: application/xml
      body: "<message><command>id</command></message>"
  - name: "negative-get-not-post"
    expected_sids: []
    request:
      method: GET
      uri: /mics/api/v2/sentry/mics-config/handleMessage
      host: 198.51.100.10
      port: 8443
```

Fixtures for protocols other than HTTP replace the request fields with raw client bytes: `raw` for text and `raw_hex` for binary payloads. The NetScaler DNS and TLS fixtures use `raw_hex` to send a DNS query over TCP and a TLS ClientHello.

If you write your own Suricata rules, you can add a fixture and run the same validator to test them.

## Provenance

See [ENGAGEMENTS.md](./ENGAGEMENTS.md) for which rules came from which report.

This repo is the canonical source for all published detection rules. Blog posts embed a version pinned to a commit and link here. Fixes land here first.

## License

Apache 2.0
