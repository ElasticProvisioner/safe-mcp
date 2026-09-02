# SAF-T1704: Compromised-Server Pivot

- **Tactic**: [ATK-TA0008 — Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- **Technique ID**: SAF-T1704
- **Research Packet**: [research/techniques/SAF-T1704](../../research/techniques/SAF-T1704/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1704/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Last Updated**: 2026-09-02

## Overview

A compromised or adversary-controlled MCP server can abuse server-originated metadata, results, or authorization responses to make a connected host act against a different trust domain. The pivot succeeds when the host applies its own authority—such as access to another server, a local endpoint, or a protected service—to an action the originating server should not control. <!-- SAF-TRACE: claims=SAF-T1704-C003; sources=SRC-invariant-tpa-2025-04-01 -->

The documented defining case is a controlled cross-server demonstration; reviewed vulnerability records also establish implementation-specific paths from an untrusted or hijacked server to client-host code execution or poisoned client responses. No qualifying production incident establishing the complete behavior was found in the reviewed corpus. <!-- SAF-TRACE: claims=SAF-T1704-C003,SAF-T1704-C006,SAF-T1704-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-jfrog-cve-2025-6514,SRC-jfrog-cve-6515-2025 -->

## Scope

This technique begins after the adversary controls the behavior or responses of an MCP server and ends when that influence causes the connected host to cross into a different trust domain with host-held authority. <!-- SAF-TRACE: claims=SAF-T1704-C003; sources=SRC-invariant-tpa-2025-04-01 -->

It excludes the initial server compromise, credential theft without a resulting pivot, ordinary injection confined to the originating server's own data or capabilities, and later persistence or impact after the cross-boundary action. <!-- SAF-TRACE: claims=SAF-T1704-C010; sources=SRC-ms-azure-mcp-security-2026,SRC-mcp-annotations-2026-03-16 -->

## Description

MCP hosts manage one client per server and are responsible for authorization, consent, security boundaries, and cross-server interaction; servers are intended to remain isolated from one another. <!-- SAF-TRACE: claims=SAF-T1704-C001; sources=SRC-mcp-architecture-2026-07-28 -->

Servers nevertheless supply tool definitions and results that a host may expose to a model. Tool annotations are explicitly untrusted hints rather than enforcement, so the host must independently validate and govern the resulting action. <!-- SAF-TRACE: claims=SAF-T1704-C002; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-annotations-2026-03-16 -->

The pivot is complete when server-originated influence becomes a causally linked action in a different trust domain—for example, an untrusted server's description steering a trusted mail tool, or a crafted authorization response reaching client-host execution. <!-- SAF-TRACE: claims=SAF-T1704-C003,SAF-T1704-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jfrog-cve-2025-6514 -->

## Attack Vectors

- **Cross-server metadata influence**: poisoned tool descriptions can influence a model while the user is interacting with another server; independent demonstrations reported cross-server tool use without invoking the malicious tool itself. <!-- SAF-TRACE: claims=SAF-T1704-C003,SAF-T1704-C004; sources=SRC-invariant-tpa-2025-04-01,SRC-trailofbits-line-jumping-2025 -->
- **Client implementation pivot**: CVE-2025-6514 allowed a crafted authorization endpoint from an untrusted MCP server to reach operating-system command execution in vulnerable `mcp-remote` versions. <!-- SAF-TRACE: claims=SAF-T1704-C006,SAF-T1704-C007; sources=SRC-jfrog-cve-2025-6514,SRC-nvd-cve-6514 -->
- **Response-channel hijack**: CVE-2025-6515 used predictable session identifiers in an SSE implementation to let a network attacker inject malicious server responses into a connected client; this is a legacy-transport-specific path, not a property of the current sessionless protocol. <!-- SAF-TRACE: claims=SAF-T1704-C008,SAF-T1704-C009; sources=SRC-jfrog-cve-6515-2025,SRC-nvd-cve-6515,SRC-mcp-release-2026-07-28 -->

## Technical Details

The defining behavioral chain is: server metadata changes or malicious server content enters model context; the model or client selects a different-server action; the host submits that action with authority unavailable to the origin server; and no independent approval or policy boundary breaks the chain. <!-- SAF-TRACE: claims=SAF-T1704-C003,SAF-T1704-C012; sources=SRC-invariant-tpa-2025-04-01,SRC-microsoft-m365-mcp-monitoring-2026 -->

Empirical work across 45 real MCP servers and 353 tools constructed 1,312 malicious cases and measured cross-tool poisoning under 20 model settings, supporting the mechanism while remaining a controlled, single-turn evaluation rather than production incident evidence. <!-- SAF-TRACE: claims=SAF-T1704-C005; sources=SRC-mcptox-2025 -->

OAuth resource binding, audience validation, and prohibitions on token passthrough limit token misuse across services, but they do not by themselves prevent a host from following malicious server-supplied instructions with a separately authorized tool. <!-- SAF-TRACE: claims=SAF-T1704-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-security-2026-07-28 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Evidence status | Summary |
|---|---|---|
| SAF-T1704-C001 | Research-derived | Current MCP architecture assigns cross-server control and consent to the host. |
| SAF-T1704-C002 | Research-derived | Tool metadata and results are server supplied; annotations are untrusted. |
| SAF-T1704-C003 | Demonstrated | A malicious server description caused a trusted-server mail action in a controlled experiment. |
| SAF-T1704-C004 | Demonstrated | Independent client tests reproduced pre-invocation metadata influence. |
| SAF-T1704-C005 | Demonstrated | MCPTox measured cross-tool poisoning across a multi-server benchmark. |
| SAF-T1704-C006 | Demonstrated | CVE-2025-6514 provided an untrusted-server-to-client-host execution path. |
| SAF-T1704-C007 | Research-derived | Affected and fixed `mcp-remote` versions and exploitation status are bounded by advisories. |
| SAF-T1704-C008 | Demonstrated | CVE-2025-6515 enabled malicious response injection through predictable SSE sessions. |
| SAF-T1704-C009 | Research-derived | The session-hijack example applies to a legacy transport model removed in the current protocol. |
| SAF-T1704-C010 | Research-derived | Risk depends on privilege, target sensitivity, and missing independent approval. |
| SAF-T1704-C011 | Research-derived | Gateway and protocol telemetry can identify server and tool invocation context. |
| SAF-T1704-C012 | Research-derived | A behavior analytic can correlate a changed source catalog with a sensitive different-server action. |
| SAF-T1704-C013 | Research-derived | Provenance gaps and legitimate orchestration constrain detector precision and recall. |
| SAF-T1704-C014 | Research-derived | Pinning, reapproval, isolation, validation, least privilege, and logging interrupt the chain. |
| SAF-T1704-C015 | Research-derived | OAuth resource and audience controls address token misuse, not metadata-mediated influence. |
| SAF-T1704-C016 | Research-derived | ATT&CK T1210 is analogous for exploit-based variants but narrower than the defining behavior. |

Three high-impact qualifying examples were retained: the defining Invariant cross-server demonstration and the CVE-2025-6514 and CVE-2025-6515 vulnerability paths. The evidence gap is a direct-authority report of the complete technique in a production compromise. <!-- SAF-TRACE: claims=SAF-T1704-C003,SAF-T1704-C006,SAF-T1704-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-jfrog-cve-2025-6514,SRC-jfrog-cve-6515-2025 -->

## Impact Assessment

Impact is highest when the connected host can call high-consequence tools, reach local execution, or access a more trusted server without transaction-specific approval. The same mechanism is lower impact when capabilities are read-only, credentials are isolated, and policy blocks cross-server dataflow. <!-- SAF-TRACE: claims=SAF-T1704-C010; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-azure-mcp-security-2026,SRC-mcp-annotations-2026-03-16 -->

The severity is High because a low-trust server can potentially convert host-held authority into unauthorized action in another trust domain, while exploitation remains conditional on client behavior, available privileges, and control coverage. <!-- SAF-TRACE: claims=SAF-T1704-C010; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-azure-mcp-security-2026,SRC-ms-rug-pull-catalog-2026 -->

## Detection Methods

Collect gateway or host events that identify the agent, source server, target server, tool name, time, trust state, approval state, metadata fingerprint, and causal trace. Microsoft documents MCP invocation visibility by agent, server, time, and metadata, while the current protocol release adds method/name routing headers and trace-context support. <!-- SAF-TRACE: claims=SAF-T1704-C011; sources=SRC-microsoft-m365-mcp-monitoring-2026,SRC-mcp-release-2026-07-28 -->

The bundled analytic alerts when a changed catalog from an untrusted or compromised server is followed within 600 seconds by an unapproved high-sensitivity call to a different server in the same trace, with the source server present in causal context. <!-- SAF-TRACE: claims=SAF-T1704-C012; sources=SRC-invariant-tpa-2025-04-01,SRC-microsoft-m365-mcp-monitoring-2026 -->

Expect false positives from legitimate multi-server orchestration after catalog rollout; suppress explicitly approved changes and tune trust and sensitivity labels. The analytic misses pivots where provenance, fingerprints, or trace continuity are absent, and it does not cover direct client exploitation without a preceding catalog change. <!-- SAF-TRACE: claims=SAF-T1704-C013; sources=SRC-ms-azure-mcp-security-2026,SRC-mcptox-2025 -->

Validated fixtures and expected outcomes are recorded in [tests/SAF-T1704](../../tests/SAF-T1704/test-logs.json); the checked-in detector and strict-validator transcripts provide the canonical validation proof.

## Mitigation Strategies

- Apply [SAF-M-2](../../mitigations/SAF-M-2/README.md) and [SAF-M-45](../../mitigations/SAF-M-45/README.md): pin reviewed tool schemas and require reapproval when names, descriptions, parameters, publishers, or endpoints change. <!-- SAF-TRACE: claims=SAF-T1704-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-rug-pull-catalog-2026 -->
- Apply [SAF-M-29](../../mitigations/SAF-M-29/README.md), [SAF-M-14](../../mitigations/SAF-M-14/README.md), [SAF-M-69](../../mitigations/SAF-M-69/README.md), and [SAF-M-74](../../mitigations/SAF-M-74/README.md): isolate credentials and execution environments by server; enforce least privilege, target allowlists, and transaction-specific approval for high-impact cross-server actions. <!-- SAF-TRACE: claims=SAF-T1704-C014,SAF-T1704-C015; sources=SRC-ms-azure-mcp-security-2026,SRC-mcp-authorization-2026-07-28 -->
- Apply [SAF-M-21](../../mitigations/SAF-M-21/README.md), [SAF-M-22](../../mitigations/SAF-M-22/README.md), and [SAF-M-12](../../mitigations/SAF-M-12/README.md): treat annotations and model decisions as advisory, validate tool inputs and results independently, and retain lineage-rich audit logs. <!-- SAF-TRACE: claims=SAF-T1704-C002,SAF-T1704-C014; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-annotations-2026-03-16,SRC-ms-azure-mcp-security-2026 -->
- Apply [SAF-M-70](../../mitigations/SAF-M-70/README.md): monitor catalog fingerprints and cross-server sequences with trust, sensitivity, approval, and causal context. <!-- SAF-TRACE: claims=SAF-T1704-C011,SAF-T1704-C012; sources=SRC-microsoft-m365-mcp-monitoring-2026,SRC-invariant-tpa-2025-04-01 -->
- Patch vulnerable clients and transports; `mcp-remote` 0.1.16 corrected CVE-2025-6514, and secure random session identifiers mitigate the legacy CVE-2025-6515 path. <!-- SAF-TRACE: claims=SAF-T1704-C007,SAF-T1704-C008; sources=SRC-jfrog-cve-2025-6514,SRC-jfrog-cve-6515-2025 -->

## Related Techniques

- **[SAF-T1001 — Tool Poisoning Attack](../SAF-T1001/README.md)**: covers malicious instructions embedded in tool metadata; this technique additionally requires a resulting action in another trust domain. <!-- SAF-TRACE: claims=SAF-T1704-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-architecture-2026-07-28 -->
- **[SAF-T1004 — Server Impersonation / Name-Collision](../SAF-T1004/README.md)**: covers acquisition or substitution of a server identity or channel; this technique begins when controlled server behavior is used to pivot through host authority. <!-- SAF-TRACE: claims=SAF-T1704-C016; sources=SRC-mcp-architecture-2026-07-28 -->
- **[SAF-T1703 — Tool-Chaining Pivot](../SAF-T1703/README.md)**: covers the broader induced cross-tool transition; this technique is the specialization in which the adversary controls the originating MCP server or response channel. <!-- SAF-TRACE: claims=SAF-T1704-C003,SAF-T1704-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-architecture-2026-07-28 -->

## MITRE ATT&CK Mapping

- **[T1210 — Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)**: analogous for implementation-exploit variants such as a malicious remote endpoint reaching code execution, but the defining cross-server metadata path need not exploit a software vulnerability in the target service. <!-- SAF-TRACE: claims=SAF-T1704-C016; sources=SRC-mitre-t1210,SRC-invariant-tpa-2025-04-01 -->

## References

- **SRC-mcp-architecture-2026-07-28**: Model Context Protocol, “Architecture,” 2026-07-28.
- **SRC-mcp-tools-2026-07-28**: Model Context Protocol, “Tools,” 2026-07-28.
- **SRC-mcp-authorization-2026-07-28**: Model Context Protocol, “Authorization,” 2026-07-28.
- **SRC-mcp-auth-security-2026-07-28**: Model Context Protocol, “Authorization Security Considerations,” 2026-07-28.
- **SRC-mcp-release-2026-07-28**: David Soria Parra and Den Delimarsky, “MCP 2026-07-28 Specification Release,” 2026-07-28.
- **SRC-mcp-annotations-2026-03-16**: Ola Hungerford, Sam Morrow, and Luca Chang, “Tool annotations: helping clients understand tool behavior,” 2026-03-16.
- **SRC-invariant-tpa-2025-04-01**: Luca Beurer-Kellner and Marc Fischer, “MCP Security Notification: Tool Poisoning Attacks,” 2025-04-01.
- **SRC-trailofbits-line-jumping-2025**: Trail of Bits AI/ML Security Team, “Jumping the line: How MCP servers can attack you before you ever use them,” 2025-04-21.
- **SRC-nvd-cve-6514**: NIST National Vulnerability Database, CVE-2025-6514.
- **SRC-jfrog-cve-2025-6514**: Or Peles, “CVE-2025-6514: Critical mcp-remote RCE Vulnerability,” 2025-07-09.
- **SRC-nvd-cve-6515**: NIST National Vulnerability Database, CVE-2025-6515.
- **SRC-jfrog-cve-6515-2025**: Ori Hollander and Ofri Ouzan, “MCP Prompt Hijacking Vulnerability,” 2025-10-21.
- **SRC-mcptox-2025**: Zhiqiang Wang et al., “MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers,” 2025-08-19.
- **SRC-ms-azure-mcp-security-2026**: Microsoft Azure MCP Server Documentation Team, “Security,” 2026-07-31.
- **SRC-microsoft-m365-mcp-monitoring-2026**: Microsoft 365 Documentation Team, “Manage tools for agents in Microsoft 365 admin center,” reviewed 2026-09-02.
- **SRC-ms-rug-pull-catalog-2026**: Microsoft Zero Trust Documentation Team, “Rug-Pull Attack (Agent / MCP Server),” 2026-08-01.
- **SRC-mitre-t1210**: MITRE ATT&CK, “Exploitation of Remote Services, T1210,” version 1.2, 2026-08-04.

## Version History

| Version | Date | Author / team | Changes |
|---|---|---|---|
| 1.0 | 2026-09-02 | OpenAI Codex clean-room research agent | Initial clean-room technique, evidence packet, and tested behavioral analytic. |
