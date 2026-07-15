# cyfar-detections

Detection rules from [cyfar.ca](https://cyfar.ca) engagement reports. Suricata, YARA, and host-level hunt commands, with test fixtures for the network rules.

Each rule traces back to a specific engagement on the blog. The report has the context. The rules here are the deployable artifacts.

## What's in here

```
suricata/          .rules files, one per engagement
yara/              YARA rules for file-level detection
host/              Shell hunt commands for post-compromise triage
tests/
  fixtures/        YAML test cases (positive + negative) per Suricata rule
  validate.py      Test runner: builds pcaps, replays through Suricata, checks SIDs
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

**Totals:** 15 Suricata rules, 6 YARA rules, 9 host hunt commands. More rules land as new engagement reports publish.

## Using the rules

**Suricata:** Copy `.rules` files into your rules directory and reference them in `suricata.yaml`. All rules use standard `$HOME_NET` / `$EXTERNAL_NET` variables.

**YARA:** Point your scanner at `yara/`. The rules are self-contained, no imports or module dependencies.

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

If you write your own Suricata rules, you can add a fixture and run the same validator to test them.

## Provenance

See [ENGAGEMENTS.md](./ENGAGEMENTS.md) for which rules came from which report.

This repo is the canonical source for all published detection rules. Blog posts embed a version pinned to a commit and link here. Fixes land here first.

## License

Apache 2.0
