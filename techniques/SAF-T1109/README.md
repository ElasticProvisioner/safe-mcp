# SAF-T1109: Debugging Tool Exploitation

- **Tactic**: ATK-TA0002 - Execution
- **Technique ID**: SAF-T1109
- **Research Packet**: [research/techniques/SAF-T1109/](../../research/techniques/SAF-T1109/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1109/traceability-ledger.yml)
- **Lifecycle Status**: Deprecated. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)
- **Documentation Status**: Deprecated
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Last Updated**: 2026-09-02

> **Deprecated compatibility ID:** SAF-T1109 described a product-centered procedure. Map the exposed endpoint to [SAF-T1005: Exposed Endpoint Exploit](../SAF-T1005/README.md) and the process-launch boundary failure to [SAF-T1101: Command Injection](../SAF-T1101/README.md). This page and its evidence packet remain available for provenance. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)

## Overview

Debugging Tool Exploitation abuses a privileged inspection, testing, or prototyping control surface so attacker-controlled input is converted into a local process launch under the developer-tool or agent-host identity. <!-- SAF-TRACE: claims=SAF-T1109-C004, SAF-T1109-C014; sources=SRC-oligo-inspector-cve-2025-49596, SRC-microsoft-autojack-2026, SRC-ghsa-inspector-7f8r -->

The evidence is Demonstrated: independent researchers completed browser-or-remote-input-to-local-process chains in MCP Inspector and an AutoGen Studio development branch, but the reviewed corpus did not establish a production compromise. <!-- SAF-TRACE: claims=SAF-T1109-C004, SAF-T1109-C006, SAF-T1109-C008; sources=SRC-oligo-inspector-cve-2025-49596, SRC-microsoft-autojack-2026 -->

## Scope

The security boundary is untrusted web, remote-server, or agent-derived input crossing into a developer-local control plane that is permitted to spawn MCP subprocesses. <!-- SAF-TRACE: claims=SAF-T1109-C004; sources=SRC-oligo-inspector-cve-2025-49596, SRC-microsoft-autojack-2026 -->

This technique excludes prompt or tool-description manipulation without a control-surface exploit, deceptive local-server installation, and post-execution behavior. <!-- SAF-TRACE: claims=SAF-T1109-C011, SAF-T1109-C012; sources=SRC-ms-agt, SRC-mcp-sep-1024 -->

## Description

MCP tools are model-controlled, and the protocol recommends human confirmation and visibility for sensitive operations. <!-- SAF-TRACE: claims=SAF-T1109-C001; sources=SRC-mcp-tools-2026-07-28 -->

The defining failure occurs when an already-running debug control plane accepts attacker-influenced connection parameters or control requests and reaches a process-launch primitive without effective authorization or input restriction. <!-- SAF-TRACE: claims=SAF-T1109-C004; sources=SRC-oligo-inspector-cve-2025-49596, SRC-microsoft-autojack-2026 -->

## Attack Vectors

- A malicious web origin reaches an exposed local Inspector proxy and submits an unauthenticated control request. <!-- SAF-TRACE: claims=SAF-T1109-C005, SAF-T1109-C006; sources=SRC-ghsa-inspector-7f8r, SRC-oligo-inspector-cve-2025-49596 -->
- An untrusted MCP server supplies an unsafe redirect URI that enables direct interaction with the Inspector proxy. <!-- SAF-TRACE: claims=SAF-T1109-C007; sources=SRC-ghsa-inspector-g9hg, SRC-inspector-fix-0166 -->
- Rendered untrusted content reaches a local prototyping socket whose caller-controlled server parameters map to process launch. <!-- SAF-TRACE: claims=SAF-T1109-C008; sources=SRC-microsoft-autojack-2026 -->

## Technical Details

The common sequence is attacker-controlled input, reachable developer control channel, missing or bypassed authorization or parameter validation, and an immediate child-process start. <!-- SAF-TRACE: claims=SAF-T1109-C004, SAF-T1109-C009; sources=SRC-oligo-inspector-cve-2025-49596, SRC-microsoft-autojack-2026, SRC-mitre-t1203 -->

This inert example illustrates only the observable sequence; it is not an exploit recipe. <!-- SAF-TRACE: claims=SAF-T1109-C009; sources=SRC-microsoft-autojack-2026, SRC-mitre-t1203 -->

```json
{"destination":"https://example.invalid","events":["unauthenticated_local_control_request","disallowed_child_process"],"window_seconds":300}
```

## Evidence and Current State

### Evidence Summary

| Claim | Supported proposition | Primary sources |
|---|---|---|
| SAF-T1109-C001 | MCP tool control and human-in-the-loop guidance | SRC-mcp-tools-2026-07-28 |
| SAF-T1109-C002 | Server and client security responsibilities | SRC-mcp-tools-2026-07-28 |
| SAF-T1109-C003 | Origin, local binding, and authentication controls | SRC-mcp-streamable-http-2026-07-28 |
| SAF-T1109-C004 | Independent end-to-end local execution demonstrations | SRC-oligo-inspector-cve-2025-49596; SRC-microsoft-autojack-2026 |
| SAF-T1109-C005 | CVE-2025-49596 affected and fixed states | SRC-ghsa-inspector-7f8r; SRC-inspector-fix-0141 |
| SAF-T1109-C006 | Controlled Inspector demonstration | SRC-oligo-inspector-cve-2025-49596 |
| SAF-T1109-C007 | CVE-2025-58444 affected and fixed states | SRC-ghsa-inspector-g9hg; SRC-inspector-fix-0166 |
| SAF-T1109-C008 | Controlled AutoJack demonstration and release limitation | SRC-microsoft-autojack-2026 |
| SAF-T1109-C009 | Detection telemetry and correlation | SRC-microsoft-autojack-2026; SRC-mitre-t1203 |
| SAF-T1109-C010 | Mechanism-focused hardening | SRC-mcp-streamable-http-2026-07-28; SRC-inspector-fix-0141; SRC-microsoft-autojack-2026 |
| SAF-T1109-C011 | Prompt and tool-poisoning boundary | SRC-ms-agt |
| SAF-T1109-C012 | Local-server installation boundary | SRC-mcp-sep-1024 |
| SAF-T1109-C013 | ATT&CK behavioral mappings | SRC-mitre-t1203; SRC-mitre-attack-t1190-v2.8 |
| SAF-T1109-C014 | Bounded local execution impact | SRC-ghsa-inspector-7f8r; SRC-microsoft-autojack-2026 |

Three examples were selected: CVE-2025-49596, CVE-2025-58444, and AutoJack; their controlled, advisory-only, or pre-release limitations are recorded in the [source coverage](../../research/techniques/SAF-T1109/source-coverage.yml).

No qualifying production breach was identified in the reviewed authority corpus; this is an evidence-gap statement, not a claim that exploitation never occurred, and the searches are recorded in [source coverage](../../research/techniques/SAF-T1109/source-coverage.yml).

Research credit: Rémy Marot and Tenable Research are credited for CVE-2025-49596; Raymond of Veria Labs, Gavin Zhong, and Shuyang Wang are credited for CVE-2025-58444; Avi Lumelsky and Oligo Research documented the first Inspector chain; and Microsoft Defender Security Research Team, Shaked Ilan, and Microsoft Threat Intelligence documented AutoJack. <!-- SAF-TRACE: claims=SAF-T1109-C005, SAF-T1109-C006, SAF-T1109-C007, SAF-T1109-C008; sources=SRC-ghsa-inspector-7f8r, SRC-oligo-inspector-cve-2025-49596, SRC-ghsa-inspector-g9hg, SRC-microsoft-autojack-2026 -->

Technique packet author: Independent clean-room research agent; external researchers and publishers receive source-level attribution and are not represented as packet coauthors. <!-- SAF-TRACE: claims=SAF-T1109-C005, SAF-T1109-C006, SAF-T1109-C007, SAF-T1109-C008; sources=SRC-ghsa-inspector-7f8r, SRC-oligo-inspector-cve-2025-49596, SRC-ghsa-inspector-g9hg, SRC-microsoft-autojack-2026 -->

## Impact Assessment

Successful exploitation provides local process execution under the permissions and isolation of the vulnerable debugging or agent host; credential access, persistence, or wider compromise require separate conditions or follow-on behavior. <!-- SAF-TRACE: claims=SAF-T1109-C014; sources=SRC-ghsa-inspector-7f8r, SRC-microsoft-autojack-2026 -->

Severity rationale: a reachable privileged development control plane can convert a single untrusted interaction into host process execution, while practical consequence remains bounded by host privilege and isolation. <!-- SAF-TRACE: claims=SAF-T1109-C004, SAF-T1109-C014; sources=SRC-oligo-inspector-cve-2025-49596, SRC-microsoft-autojack-2026, SRC-ghsa-inspector-7f8r -->

## Detection Methods

Correlate an unauthenticated or bypassed loopback control request with a disallowed child process from the same Inspector, debug proxy, or agent-prototype session within five minutes. <!-- SAF-TRACE: claims=SAF-T1109-C009; sources=SRC-microsoft-autojack-2026, SRC-mitre-t1203 -->

Required fields include timestamp, device and session identifiers, endpoint kind, authentication result, caller trust, parent role, child image, and executable-allowlist decision; missing control-plane or endpoint telemetry reduces coverage. <!-- SAF-TRACE: claims=SAF-T1109-C009; sources=SRC-microsoft-autojack-2026, SRC-mitre-t1203 -->

The tested analytic and deterministic cases are available in [detection-rule.yml](detection-rule.yml) and [tests/SAF-T1109](../../tests/SAF-T1109/test-cases.json).

## Mitigation Strategies

Require authentication, validate Origin, bind local services to loopback, restrict executable choices, isolate prototyping environments, and apply least privilege. <!-- SAF-TRACE: claims=SAF-T1109-C002, SAF-T1109-C003, SAF-T1109-C010; sources=SRC-mcp-tools-2026-07-28, SRC-mcp-streamable-http-2026-07-28, SRC-inspector-fix-0141, SRC-microsoft-autojack-2026 -->

Show users the requested operation and inputs, require confirmation for sensitive actions, validate tool results, enforce timeouts, and log tool use. <!-- SAF-TRACE: claims=SAF-T1109-C001, SAF-T1109-C002; sources=SRC-mcp-tools-2026-07-28 -->

After a suspected event, isolate the host, preserve control-plane and process telemetry, review child processes, and rotate credentials only when investigation shows they were accessible to the affected identity. <!-- SAF-TRACE: claims=SAF-T1109-C009, SAF-T1109-C014; sources=SRC-microsoft-autojack-2026 -->

## Related Techniques

- [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) changes model instructions without requiring exploitation of a debugging control surface. <!-- SAF-TRACE: claims=SAF-T1109-C011; sources=SRC-ms-agt -->
- [SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md) manipulates model-visible tool metadata without requiring exploitation of a debugging control surface. <!-- SAF-TRACE: claims=SAF-T1109-C011; sources=SRC-ms-agt -->
- [SAF-T1003: Malicious MCP-Server Distribution](../SAF-T1003/README.md) covers deceptive or unsafe local-server installation at the consent boundary. <!-- SAF-TRACE: claims=SAF-T1109-C012; sources=SRC-mcp-sep-1024 -->

## MITRE ATT&CK Mapping

- **T1203 - Exploitation for Client Execution**: Direct behavioral mapping when a vulnerable developer client or control surface produces local execution. <!-- SAF-TRACE: claims=SAF-T1109-C013; sources=SRC-mitre-t1203 -->
- **T1190 - Exploit Public-Facing Application**: Analogous only when a related exploit targets an internet-facing service rather than the bounded local developer control plane. <!-- SAF-TRACE: claims=SAF-T1109-C013; sources=SRC-mitre-attack-t1190-v2.8 -->

## References

1. SRC-mcp-tools-2026-07-28 - Model Context Protocol, “Tools,” 2026-07-28.
2. SRC-mcp-streamable-http-2026-07-28 - Model Context Protocol, “Streamable HTTP,” 2026-07-28.
3. SRC-ghsa-inspector-7f8r - GitHub Security Advisory GHSA-7f8r-222p-6f5g.
4. SRC-oligo-inspector-cve-2025-49596 - Oligo Security, CVE-2025-49596 disclosure.
5. SRC-inspector-fix-0141 - MCP Inspector 0.14.1 security fix commit.
6. SRC-ghsa-inspector-g9hg - GitHub Security Advisory GHSA-g9hg-qhmf-q45m.
7. SRC-inspector-fix-0166 - MCP Inspector 0.16.6 redirect-validation fix.
8. SRC-microsoft-autojack-2026 - Microsoft Defender Security Research Team, AutoJack.
9. SRC-mcp-sep-1024 - MCP SEP-1024.
10. SRC-ms-agt - Microsoft, MCP control-plane guidance.
11. SRC-mitre-t1203 - MITRE ATT&CK T1203.
12. SRC-mitre-attack-t1190-v2.8 - MITRE ATT&CK T1190.

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-01 | Clean-room draft with complete evidence packet and deterministic detection tests. |
