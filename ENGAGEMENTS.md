# Rule provenance

Which rules came from which published engagement.

| Engagement | Suricata | YARA | Host | Total |
|---|---|---|---|---|
| [Ten Operators, One Ivanti Sentry Command-Injection Endpoint](https://cyfar.ca/engagements/ten-operators-one-ivanti-sentry-command-injection-endpoint) | 1 | 2 | 1 | 4 |
| [Self-Blocking Docker API Abuse Delivers the VoidLink DDoS-for-Hire Botnet](https://cyfar.ca/engagements/self-blocking-docker-api-abuse-delivers-the-voidlink-ddos-for-hire-botnet) | 13 | 2 | 8 | 23 |
| [Cross-Service Credential Replay](https://cyfar.ca/engagements/cross-service-credential-replay-operator-targets-hypervisor-using-harvested-llm) | 1 | 0 | 0 | 1 |

Rules are added to this repo when their engagement report publishes on cyfar.ca. Unpublished research stays private.

**Note:** The credential replay engagement's Suricata rule (SID 1000508001) is published in the report's Detection Opportunities section but was not indexed by the `/api/detections` endpoint. This is a known extraction gap on cyfar.ca.
