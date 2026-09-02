# SAF-T1901: Outbound Webhook C2

## Overview

- **Tactic**: ATK-TA0011 — Command and Control
- **Technique ID**: SAF-T1901
- **Research Packet**: [SAF-T1901 research](../../research/techniques/SAF-T1901/)
- **Traceability Ledger**: [source-or-omit ledger](../../research/techniques/SAF-T1901/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Last Updated**: 2026-09-02

This technique describes a research-derived control channel in which an adversary causes an MCP-enabled or agentic tool to make repeated outbound webhook requests to an attacker-controlled service and consumes returned data as tasking or operator control. The complete behavior crosses the tool runtime's outbound network boundary and maps behaviorally to bidirectional web-service C2. <!-- SAF-TRACE: claims=SAF-T1901-C004, SAF-T1901-C018; sources=SRC-mcp-tools-2026-07-28, SRC-mitre-t1102-002-v1-1 -->

The High severity is conditional: confidentiality and integrity exposure scale with the data and authority available to the tool runtime, while availability impact is secondary unless returned tasking causes disruptive action. <!-- SAF-TRACE: claims=SAF-T1901-C014; sources=SRC-ghsa-cmrh-wvq6-wm9r, SRC-aws-cve-2026-15643, SRC-mitre-t1102-002-v1-1 -->

## Scope

The security boundary is the point where a model-controlled tool or agent scheduler turns invocation context into outbound HTTP traffic and then makes a response available to the agent or downstream automation. <!-- SAF-TRACE: claims=SAF-T1901-C001, SAF-T1901-C004; sources=SRC-mcp-tools-2026-07-28, SRC-mitre-t1102-002-v1-1 -->

In scope are repeated attacker-influenced webhook posts, an external destination not approved for the task, response consumption or materially repeated outbound signaling, and an operator-control objective. <!-- SAF-TRACE: claims=SAF-T1901-C004, SAF-T1901-C011; sources=SRC-mitre-t1102-002-v1-1, SRC-otel-http-spans-1.44.0 -->

Out of scope are ordinary approved callbacks, one-off data-only transfer, generic SSRF without an operator-control function, and unauthorized tool invocation that never establishes repeated external webhook communication. <!-- SAF-TRACE: claims=SAF-T1901-C016, SAF-T1901-C017; sources=SRC-mitre-t1102-002-v1-1, SRC-mitre-t1102-003-v1-1, SRC-mcp-tools-2026-07-28 -->

## Description

MCP tools may be invoked by language models and may interact with external systems such as APIs. The current specification describes tools as model-controlled, while its security guidance requires user control and consent but does not enforce those principles at the protocol layer. <!-- SAF-TRACE: claims=SAF-T1901-C001, SAF-T1901-C002; sources=SRC-mcp-tools-2026-07-28, SRC-mcp-architecture-2026-07-28 -->

An adversary can exploit that authority boundary when prompt influence, a vulnerable tool parameter, or compromised automation determines a webhook destination or request content. If the runtime repeatedly posts to that service and consumes returned tasking, the service can function as a web-based operator relay. This is an inference synthesized from protocol behavior, ATT&CK's web-service C2 definition, and disclosed outbound-request primitives; none of the reviewed advisories establishes the complete channel. <!-- SAF-TRACE: claims=SAF-T1901-C004, SAF-T1901-C009; sources=SRC-mcp-tools-2026-07-28, SRC-mitre-t1102-002-v1-1, SRC-ghsa-cmrh-wvq6-wm9r, SRC-cisa-kev-2026-09-01 -->

## Attack Vectors

| Vector | Required condition | Technique relevance |
|---|---|---|
| Prompt-influenced tool arguments | A model-controlled tool can send caller-influenced HTTP requests | A malicious or compromised instruction can steer the destination or content toward an external operator service. <!-- SAF-TRACE: claims=SAF-T1901-C001, SAF-T1901-C004, SAF-T1901-C005; sources=SRC-mcp-tools-2026-07-28, SRC-ghsa-cmrh-wvq6-wm9r --> |
| Unvalidated URL or pagination field | The runtime accepts an attacker-chosen URL across a trusted tool boundary | Disclosed MCP flaws show that arbitrary outbound HTTP requests can arise from tool parameters even though they do not prove C2. <!-- SAF-TRACE: claims=SAF-T1901-C006, SAF-T1901-C007; sources=SRC-aws-cve-2026-15643, SRC-ghsa-mcp-atlassian-7r34 --> |
| Agent callback configuration | A scheduler or automation can post results to a caller-selected callback | An optional agent scheduler vulnerability demonstrates a blind webhook-post primitive, but not response tasking or a complete channel. <!-- SAF-TRACE: claims=SAF-T1901-C008; sources=SRC-ghsa-xqq2-4j46-vwp7, SRC-nvd-token-scope-corpus --> |

## Technical Details

A representative sequence is: the model selects a tool; invocation data reaches an HTTP-capable component; the component sends an HTTPS POST to a non-approved external endpoint; the response or subsequent callback changes agent behavior; and the pattern repeats under a common session, tool, and destination. The same endpoint alone is not sufficient—operator-control behavior and tasking consumption distinguish this technique from simple transfer. <!-- SAF-TRACE: claims=SAF-T1901-C004, SAF-T1901-C016, SAF-T1901-C017; sources=SRC-mcp-tools-2026-07-28, SRC-mitre-t1102-002-v1-1, SRC-mitre-t1102-003-v1-1 -->

The following inert illustration uses a reserved, non-resolving domain and contains no usable secret or live command content. <!-- SAF-TRACE: claims=SAF-T1901-C004; sources=SRC-mcp-tools-2026-07-28, SRC-mitre-t1102-002-v1-1 -->

```text
tool invocation -> HTTPS POST https://hooks.example.invalid/task
                <- bounded response consumed as next-step tasking
repeat under the same agent session and tool context
```

One-way tasking with no returned output on the same channel, or with a separate return path, fits ATT&CK's one-way web-service distinction rather than the complete bidirectional behavior defined here. <!-- SAF-TRACE: claims=SAF-T1901-C016; sources=SRC-mitre-t1102-002-v1-1, SRC-mitre-t1102-003-v1-1 -->

## Evidence and Current State

The evidence status is Research-Derived. Direct authority research identified four high-relevance enabling vulnerabilities, but no qualifying production incident or end-to-end public MCP/agent webhook-C2 demonstration in the bounded corpus reviewed on 2026-09-02. This is not a claim that the behavior has never occurred, and absence from CISA KEV does not prove absence of exploitation. <!-- SAF-TRACE: claims=SAF-T1901-C004, SAF-T1901-C009; sources=SRC-nvd-token-scope-corpus, SRC-cisa-kev-2026-09-01, SRC-mitre-t1102-002-v1-1 -->

### Ranked Enabling Examples

| Rank | Example | What the authority establishes | Boundary |
|---:|---|---|---|
| 1 | CVE-2026-44694, n8n-mcp | Versions 2.18.7 through 2.50.1 allowed authenticated or prompt-influenced activity to drive webhook/API-client requests; 2.50.2 fixed the path. <!-- SAF-TRACE: claims=SAF-T1901-C005; sources=SRC-ghsa-cmrh-wvq6-wm9r, SRC-nvd-token-scope-corpus --> | Enabling SSRF and response exposure, not a C2 observation. |
| 2 | CVE-2026-15643, AWS HealthLake MCP Server | Versions before 0.0.14 could follow attacker-directed pagination URLs with potential temporary credential exposure; 0.0.14 fixed it. <!-- SAF-TRACE: claims=SAF-T1901-C006; sources=SRC-aws-cve-2026-15643, SRC-nvd-token-scope-corpus --> | Enabling outbound request with bounded credential impact, not webhook C2. |
| 3 | CVE-2026-27826, mcp-atlassian | Versions before 0.17.0 allowed an unauthenticated caller, under documented HTTP transport conditions, to force a request to an attacker URL; 0.17.0 fixed it. <!-- SAF-TRACE: claims=SAF-T1901-C007; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-token-scope-corpus --> | Demonstrated SSRF under prerequisites, not C2. |
| 4 | CVE-2026-33619, PinchTab | Version 0.8.3's optional scheduler could POST to an attacker-selected callback URL; 0.8.4 added destination, address-pinning, and redirect controls. <!-- SAF-TRACE: claims=SAF-T1901-C008; sources=SRC-ghsa-xqq2-4j46-vwp7, SRC-nvd-token-scope-corpus --> | Blind callback primitive with important default-off and authorization constraints. |

### Evidence Summary

| Claim ID | Finding | Evidence status | Supporting source IDs |
|---|---|---|---|
| SAF-T1901-C001 | MCP tools are model-controlled and can interact with external APIs. | Research-Derived | SRC-mcp-tools-2026-07-28 |
| SAF-T1901-C002 | MCP guidance requires consent and denial controls but is not protocol-enforced. | Research-Derived | SRC-mcp-architecture-2026-07-28; SRC-mcp-tools-2026-07-28 |
| SAF-T1901-C003 | ATT&CK defines bidirectional web-service C2 as command delivery and returned output over the service. | Research-Derived | SRC-mitre-t1102-002-v1-1 |
| SAF-T1901-C004 | The complete MCP/agent outbound-webhook C2 behavior is an explicit synthesis. | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-mitre-t1102-002-v1-1; SRC-ghsa-cmrh-wvq6-wm9r; SRC-ghsa-xqq2-4j46-vwp7 |
| SAF-T1901-C005 | CVE-2026-44694 establishes a webhook/API outbound-request primitive and fix. | Demonstrated vulnerability | SRC-ghsa-cmrh-wvq6-wm9r; SRC-nvd-token-scope-corpus |
| SAF-T1901-C006 | CVE-2026-15643 establishes an MCP pagination-URL primitive and fix. | Research-Derived advisory evidence | SRC-aws-cve-2026-15643; SRC-nvd-token-scope-corpus |
| SAF-T1901-C007 | CVE-2026-27826 establishes an arbitrary outbound URL primitive under conditions and fix. | Demonstrated vulnerability | SRC-ghsa-mcp-atlassian-7r34; SRC-nvd-token-scope-corpus |
| SAF-T1901-C008 | CVE-2026-33619 establishes an optional scheduler webhook primitive and fix. | Demonstrated vulnerability | SRC-ghsa-xqq2-4j46-vwp7; SRC-nvd-token-scope-corpus |
| SAF-T1901-C009 | The reviewed corpus yielded no direct qualifying incident or complete public demonstration. | Research-Derived bounded finding | SRC-nvd-token-scope-corpus; SRC-cisa-kev-2026-09-01; SRC-mitre-t1102-002-v1-1 |
| SAF-T1901-C010 | OpenTelemetry defines useful outbound HTTP attributes and redaction duties. | Research-Derived | SRC-otel-http-spans-1.44.0 |
| SAF-T1901-C011 | Repeated model-driven POSTs with consumed responses form a suspicious heuristic, not proof. | Research-Derived | SRC-mitre-t1102-002-v1-1; SRC-otel-http-spans-1.44.0; SRC-mcp-tools-2026-07-28 |
| SAF-T1901-C012 | Egress controls, approval, validation, least privilege, and patching constrain the primitive. | Research-Derived | SRC-mcp-security-2026-07-28; SRC-mcp-architecture-2026-07-28; SRC-ghsa-cmrh-wvq6-wm9r; SRC-ghsa-xqq2-4j46-vwp7 |
| SAF-T1901-C013 | Legitimate automation, incomplete correlation, encryption, and low-and-slow behavior limit detection. | Research-Derived | SRC-mitre-t1102-002-v1-1; SRC-otel-http-spans-1.44.0 |
| SAF-T1901-C014 | Impact depends on runtime data and authority. | Research-Derived | SRC-ghsa-cmrh-wvq6-wm9r; SRC-aws-cve-2026-15643; SRC-mitre-t1102-002-v1-1 |
| SAF-T1901-C015 | Investigation requires MCP-to-HTTP correlation with secret redaction. | Research-Derived | SRC-otel-http-spans-1.44.0; SRC-mcp-tools-2026-07-28 |
| SAF-T1901-C016 | One-way or data-only transfer is not the complete bidirectional behavior. | Research-Derived | SRC-mitre-t1102-002-v1-1; SRC-mitre-t1102-003-v1-1 |
| SAF-T1901-C017 | Operator-control webhook behavior distinguishes the technique from data-only transfer and invocation-only abuse. | Research-Derived | SRC-mitre-t1102-002-v1-1; SRC-mcp-tools-2026-07-28 |
| SAF-T1901-C018 | ATT&CK T1102.002 is the direct behavioral mapping. | Research-Derived | SRC-mitre-t1102-002-v1-1; SRC-mcp-tools-2026-07-28 |

## Impact Assessment

Potential confidentiality impact includes disclosure of credentials, tool responses, or task context available to the runtime. Integrity impact includes adversary-directed tool choices or follow-on actions. Availability impact is typically indirect and depends on what returned tasking can cause the runtime to execute. <!-- SAF-TRACE: claims=SAF-T1901-C014; sources=SRC-ghsa-cmrh-wvq6-wm9r, SRC-aws-cve-2026-15643, SRC-mitre-t1102-002-v1-1 -->

These impacts are conditional rather than observed frequency or loss estimates because the reviewed sources do not document a production instance of the complete technique. <!-- SAF-TRACE: claims=SAF-T1901-C009, SAF-T1901-C014; sources=SRC-nvd-token-scope-corpus, SRC-mitre-t1102-002-v1-1 -->

## Detection Methods

Correlate application audit records with outbound HTTP client telemetry. A high-signal record set includes MCP session, tool, invocation, model-driven indicator, approval decision, destination approval state, method, normalized destination, status, request and response sizes, and whether the response affected subsequent agent behavior. Sensitive URL components and headers must be redacted rather than indiscriminately captured. <!-- SAF-TRACE: claims=SAF-T1901-C010, SAF-T1901-C015; sources=SRC-otel-http-spans-1.44.0, SRC-mcp-tools-2026-07-28 -->

The supplied analytic alerts when one session and tool make at least three HTTPS POSTs across at least two invocation IDs to the same unapproved endpoint within ten minutes, with response consumption or nonempty outbound content. This is a tunable suspicious-behavior heuristic and does not by itself establish C2. <!-- SAF-TRACE: claims=SAF-T1901-C011; sources=SRC-mitre-t1102-002-v1-1, SRC-otel-http-spans-1.44.0 -->

- [Detection rule](./detection-rule.yml)
- [Executable detector](../../tests/SAF-T1901/detector.py)
- [Fixtures](../../tests/SAF-T1901/fixtures.json)
- [Detector test](../../tests/SAF-T1901/test_detector.py)

Expected false positives include newly deployed legitimate recurring integrations whose destination-approval metadata has not yet been reconciled. Blind spots include approved-service abuse, slow or one-off signaling, GET-based polling, encryption, missing response-consumption telemetry, and absent joins between tool and HTTP records. <!-- SAF-TRACE: claims=SAF-T1901-C013; sources=SRC-mitre-t1102-002-v1-1, SRC-otel-http-spans-1.44.0 -->

## Mitigation Strategies

Allowlist destinations by tool and task; require explicit approval for first-use or changed destinations; validate scheme, hostname, resolved public address, redirects, and DNS changes; route tool traffic through controlled egress; minimize runtime credentials; and patch affected components. <!-- SAF-TRACE: claims=SAF-T1901-C002, SAF-T1901-C012; sources=SRC-mcp-security-2026-07-28, SRC-mcp-architecture-2026-07-28, SRC-ghsa-cmrh-wvq6-wm9r, SRC-ghsa-xqq2-4j46-vwp7 -->

Controls must also account for an attacker using an otherwise approved public service or account, so destination allowlisting should be paired with invocation review, account-level restrictions, rate and response-consumption monitoring, and least privilege. <!-- SAF-TRACE: claims=SAF-T1901-C012, SAF-T1901-C013; sources=SRC-mcp-architecture-2026-07-28, SRC-mitre-t1102-002-v1-1, SRC-otel-http-spans-1.44.0 -->

## Related Techniques

The independently authored canonical neighbors below preserve the data-transfer and invocation-only boundaries established by the frozen research. <!-- SAF-TRACE: claims=SAF-T1901-C017; sources=SRC-mitre-t1102-002-v1-1, SRC-mcp-tools-2026-07-28 -->

| Canonical neighbor | Distinction |
|---|---|
| [SAF-T1913 — HTTP POST Exfil](../SAF-T1913/README.md) | Data-only egress lacks the repeated returned-tasking or operator-control function required here. <!-- SAF-TRACE: claims=SAF-T1901-C016, SAF-T1901-C017; sources=SRC-mitre-t1102-002-v1-1, SRC-mitre-t1102-003-v1-1 --> |
| [SAF-T1309 — Privileged Tool Invocation via Prompt Manipulation](../SAF-T1309/README.md) | Invocation-only abuse does not establish an external web-service operator channel. <!-- SAF-TRACE: claims=SAF-T1901-C017; sources=SRC-mitre-t1102-002-v1-1, SRC-mcp-tools-2026-07-28 --> |

## MITRE ATT&CK Mapping

| ATT&CK technique | Relationship | Rationale |
|---|---|---|
| [T1102.002 — Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/) | Direct behavioral mapping | Both definitions require command delivery and returned output over an external web-service channel; this technique adds the MCP/agent tool and runtime-egress context. <!-- SAF-TRACE: claims=SAF-T1901-C003, SAF-T1901-C018; sources=SRC-mitre-t1102-002-v1-1, SRC-mcp-tools-2026-07-28 --> |
| [T1102.003 — Web Service: One-Way Communication](https://attack.mitre.org/techniques/T1102/003/) | Boundary mapping | Use this adjacent mapping when tasking is one-way or output returns over a different channel. <!-- SAF-TRACE: claims=SAF-T1901-C016; sources=SRC-mitre-t1102-002-v1-1, SRC-mitre-t1102-003-v1-1 --> |

## References

- **SRC-mcp-tools-2026-07-28** — [Model Context Protocol Specification: Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), Model Context Protocol maintainers, 2026-07-28.
- **SRC-mcp-architecture-2026-07-28** — [Model Context Protocol Specification: Security and Trust & Safety](https://modelcontextprotocol.io/specification/2026-07-28/architecture), Model Context Protocol maintainers, 2026-07-28.
- **SRC-mcp-security-2026-07-28** — [Model Context Protocol Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices), Model Context Protocol maintainers, 2026-07-28.
- **SRC-mitre-t1102-002-v1-1** — [MITRE ATT&CK T1102.002](https://attack.mitre.org/techniques/T1102/002/), MITRE ATT&CK team, version 1.1.
- **SRC-mitre-t1102-003-v1-1** — [MITRE ATT&CK T1102.003](https://attack.mitre.org/techniques/T1102/003/), MITRE ATT&CK team, version 1.1.
- **SRC-otel-http-spans-1.44.0** — [Semantic Conventions for HTTP Spans](https://opentelemetry.io/docs/specs/semconv/http/http-spans/), OpenTelemetry Semantic Conventions maintainers, version 1.44.0.
- **SRC-ghsa-cmrh-wvq6-wm9r** — [Authenticated SSRF in n8n-mcp webhook and API client paths](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-cmrh-wvq6-wm9r), czlonkowski; reported by fg0x0, 2026.
- **SRC-aws-cve-2026-15643** — [CVE-2026-15643 — AWS HealthLake MCP Server](https://aws.amazon.com/security/security-bulletins/2026-054-aws/), AWS Security; Marios Gyftos acknowledged, 2026.
- **SRC-ghsa-mcp-atlassian-7r34** — [SSRF via unvalidated Atlassian URL headers](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-7r34-79r5-rcc9), sooperset; reported by yotampe-pluto and gil-maman-p, 2026.
- **SRC-ghsa-xqq2-4j46-vwp7** — [Unauthenticated Blind SSRF in Task Scheduler](https://github.com/pinchtab/pinchtab/security/advisories/GHSA-xqq2-4j46-vwp7), luigi-agosti; reported by mean3374, 2026.
- **SRC-nvd-token-scope-corpus** — [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0), National Vulnerability Database staff, reviewed 2026-09-02.
- **SRC-cisa-kev-2026-09-01** — [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), Cybersecurity and Infrastructure Security Agency, catalog 2026.09.01.

## Version History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0-draft | 2026-09-02 | OpenAI clean-room research agent | Independent direct-authority research, executable detection, source-or-omit packet, and integration proposals. |
