# SAF-T1505: In-Memory Secret Extraction

## Overview

- **Tactic**: Credential Access (ATK-TA0006)
- **Technique ID**: SAF-T1505
- **Research Packet**: [research/techniques/SAF-T1505](../../research/techniques/SAF-T1505/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1505/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Unauthorized access to live signing keys, database credentials, personal access tokens, or paid API keys can produce high confidentiality impact; integrity or availability impact requires follow-on use. <!-- SAF-TRACE: claims=SAF-T1505-C018; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->
- **First Observed**: Not observed in production in the direct-authority corpus reviewed on 2026-09-01; controlled demonstrations are public. <!-- SAF-TRACE: claims=SAF-T1505-C001,SAF-T1505-C009; sources=SRC-arxiv-2504.03767v2,SRC-cisa-kev-in-memory-secrets-2026-09-01,SRC-nvd-cve-2026-32625,SRC-nvd-cve-2026-29872,SRC-nvd-cve-2026-40159 -->
- **Last Updated**: 2026-09-01

## Scope

In-Memory Secret Extraction is the unauthorized acquisition of authentication material or another secret from live process-wide environment or runtime state held by an MCP host, agent runtime, or server. The crossed boundary separates that state from a user session, tool, child server, extension, or remote destination that is not authorized to receive it. <!-- SAF-TRACE: claims=SAF-T1505-C001,SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007; sources=SRC-arxiv-2504.03767v2,SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->

### In Scope

- Resolving an attacker-controlled reference against a host process environment and returning or transmitting the resulting secret. <!-- SAF-TRACE: claims=SAF-T1505-C005; sources=SRC-ghsa-4pcc-j6m6-wcwx -->
- Reading one user's secret from process-global state through a different, unauthorized session. <!-- SAF-TRACE: claims=SAF-T1505-C006; sources=SRC-pham-minh-cve-2026-29872 -->
- Giving an untrusted MCP subprocess a secret-bearing parent environment that it can read. <!-- SAF-TRACE: claims=SAF-T1505-C007; sources=SRC-ghsa-pj2r-f9mw-vrcq -->

### Out of Scope

- Prompt injection or malicious-package delivery is an entry mechanism; it is outside this technique unless live secret state is actually acquired. <!-- SAF-TRACE: claims=SAF-T1505-C001,SAF-T1505-C007; sources=SRC-arxiv-2504.03767v2,SRC-ghsa-pj2r-f9mw-vrcq -->
- Reads from persistent files, keychains, vaults, databases, and cloud metadata are separate because the source is not live application state. <!-- SAF-TRACE: claims=SAF-T1505-C015; sources=SRC-mitre-t1003 -->
- Code execution that merely creates access and follow-on exfiltration or token replay are adjacent behaviors; the technique ends at unauthorized acquisition. <!-- SAF-TRACE: claims=SAF-T1505-C004,SAF-T1505-C008; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-mp29-fxh8-92px,SRC-nvd-cve-2026-67531 -->

### Distinguishing Characteristics

The defining observable is a join between a live secret-bearing state container and an unauthorized recipient. A file read lacks the live-state source; code execution without a secret read is only enabling; an outbound transfer after acquisition is follow-on activity. <!-- SAF-TRACE: claims=SAF-T1505-C008,SAF-T1505-C010,SAF-T1505-C015; sources=SRC-ghsa-mp29-fxh8-92px,SRC-nvd-cve-2026-67531,SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872,SRC-mitre-t1003 -->

## Description

MCP stdio implementations may legitimately retrieve credentials from the environment. That design choice makes environment presence ordinary; extraction arises only when an implementation lets an unauthorized session, user-controlled configuration, or untrusted child process read the live value. <!-- SAF-TRACE: claims=SAF-T1505-C002,SAF-T1505-C011; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq -->

The behavior is demonstrated rather than observed. Radosevich and Halloran reproduced an MCP tool chain that located API keys in environment variables and disclosed them through Slack, while three product disclosures document different runtime-state boundary failures. No reviewed authority establishes a qualifying production breach. <!-- SAF-TRACE: claims=SAF-T1505-C001,SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007,SAF-T1505-C009; sources=SRC-arxiv-2504.03767v2,SRC-ghsa-4pcc-j6m6-wcwx,SRC-nvd-cve-2026-32625,SRC-pham-minh-cve-2026-29872,SRC-nvd-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq,SRC-nvd-cve-2026-40159,SRC-cisa-kev-in-memory-secrets-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: Untrusted MCP configuration or tool-mediated input reaches logic that resolves, shares, or reads live runtime secret state. <!-- SAF-TRACE: claims=SAF-T1505-C001,SAF-T1505-C005,SAF-T1505-C006; sources=SRC-arxiv-2504.03767v2,SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872 -->
- **Secondary Vectors**: An untrusted local server inherits the host environment, or a sandbox escape enables process access without itself proving extraction. <!-- SAF-TRACE: claims=SAF-T1505-C007,SAF-T1505-C008; sources=SRC-ghsa-pj2r-f9mw-vrcq,SRC-ghsa-mp29-fxh8-92px,SRC-nvd-cve-2026-67531 -->
- **Affected Components**: MCP hosts, agent runtimes, server-configuration validators, local MCP subprocess launchers, multi-user session state, and sandboxed extensions. <!-- SAF-TRACE: claims=SAF-T1505-C003,SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007,SAF-T1505-C008; sources=SRC-mcp-security-2025-11-25,SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq,SRC-ghsa-mp29-fxh8-92px,SRC-nvd-cve-2026-67531 -->
- **Trust Boundary Crossed**: Secret-owner process or session to an unauthorized user, session, subprocess, extension, or remote destination. <!-- SAF-TRACE: claims=SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->

## Technical Details

### Prerequisites

- The MCP or agent process holds a usable secret in environment or runtime state. <!-- SAF-TRACE: claims=SAF-T1505-C002; sources=SRC-mcp-authorization-2025-11-25 -->
- Attacker-controlled input, a different session, or an untrusted child reaches a code path that can reference or inherit that state. <!-- SAF-TRACE: claims=SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->
- Session isolation, input/source separation, or child-environment minimization is absent or ineffective. <!-- SAF-TRACE: claims=SAF-T1505-C012,SAF-T1505-C013,SAF-T1505-C014; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->

### Attack Flow

1. **Setup**: An adversary supplies MCP configuration, controls an untrusted child command, or reaches a session that shares process-global state. <!-- SAF-TRACE: claims=SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->
2. **Trigger**: The runtime validates the configuration, starts the child, or services the cross-session access. <!-- SAF-TRACE: claims=SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->
3. **Boundary Crossing**: A process-wide lookup or inheritance occurs without recipient authorization or session ownership enforcement. <!-- SAF-TRACE: claims=SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->
4. **Objective**: The unauthorized recipient obtains the secret value; later transfer or use is a separate action. <!-- SAF-TRACE: claims=SAF-T1505-C004,SAF-T1505-C018; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->

### Example Scenario

An authenticated low-privilege user submits a remote MCP endpoint configuration containing a placeholder named `SERVICE_API_KEY`. During validation, the host resolves the placeholder from its live environment and contacts `collector.example.invalid`; the example uses no real key or reachable collection service. <!-- SAF-TRACE: claims=SAF-T1505-C005; sources=SRC-ghsa-4pcc-j6m6-wcwx -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1505-C001 | A controlled MCP workflow extracted environment-held API keys and disclosed them through Slack. | Demonstrated | SRC-arxiv-2504.03767v2: [Radosevich and Halloran](https://arxiv.org/pdf/2504.03767) | Controlled evaluation; prompt injection and exfiltration are adjacent. |
| SAF-T1505-C002 | MCP stdio implementations may retrieve credentials from the environment. | Research-Derived | SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/docs/2025-11-25/specification/basic/authorization) | Does not require full environment inheritance. |
| SAF-T1505-C003 | Local MCP servers may have host access and should be sandboxed with restricted resources. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Broad compromise guidance. |
| SAF-T1505-C004 | Obtained tokens can enable apparently legitimate access; storage and lifetime controls limit impact. | Research-Derived | SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/docs/2025-11-25/specification/basic/authorization) | Does not establish extraction mechanics. |
| SAF-T1505-C005 | LibreChat could resolve process environment placeholders from user MCP URLs. | Demonstrated | SRC-ghsa-4pcc-j6m6-wcwx and SRC-nvd-cve-2026-32625: [LibreChat advisory](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-4pcc-j6m6-wcwx) | PoC and vulnerability, not production exploitation. |
| SAF-T1505-C006 | A GitHub MCP Agent exposed process-global tokens across sessions. | Demonstrated | SRC-pham-minh-cve-2026-29872 and SRC-nvd-cve-2026-29872: [Pham Minh disclosure](https://github.com/lilmingwa13/security-research/blob/main/CVE-2026-29872.md) | No fixed release identified; display modification aided observation. |
| SAF-T1505-C007 | PraisonAI passed a secret-bearing parent environment to user-selected MCP children. | Demonstrated | SRC-ghsa-pj2r-f9mw-vrcq and SRC-nvd-cve-2026-40159: [PraisonAI advisory](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-pj2r-f9mw-vrcq) | Affected-range discrepancy; untrusted child and user interaction required. |
| SAF-T1505-C008 | FrontMCP sandbox escape was enabling but did not demonstrate secret acquisition. | Research-Derived | SRC-ghsa-mp29-fxh8-92px and SRC-nvd-cve-2026-67531: [FrontMCP advisory](https://github.com/agentfront/frontmcp/security/advisories/GHSA-mp29-fxh8-92px) | Enables process access only. |
| SAF-T1505-C009 | No qualifying production breach was found in the bounded 2026-09-01 corpus. | Research-Derived | SRC-cisa-kev-in-memory-secrets-2026-09-01 and the reviewed PoC sources | Bounded absence claim; KEV absence is not proof of non-exploitation. |
| SAF-T1505-C010 | A contextual analytic can join untrusted input or recipients with secret-like live-state access. | Research-Derived | SRC-ghsa-4pcc-j6m6-wcwx, SRC-ghsa-pj2r-f9mw-vrcq, and SRC-pham-minh-cve-2026-29872 | Synthetic schema; not independently evaluated. |
| SAF-T1505-C011 | Environment use alone is normal and requires trust and authorization context. | Research-Derived | SRC-mcp-authorization-2025-11-25 and SRC-ghsa-pj2r-f9mw-vrcq | Context may be unavailable. |
| SAF-T1505-C012 | Untrusted configuration should not resolve process environment placeholders. | Demonstrated | SRC-ghsa-4pcc-j6m6-wcwx: [LibreChat advisory](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-4pcc-j6m6-wcwx) | Product-specific. |
| SAF-T1505-C013 | MCP child environments should be sanitized and allowlisted. | Demonstrated | SRC-ghsa-pj2r-f9mw-vrcq: [PraisonAI advisory](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-pj2r-f9mw-vrcq) | Name filters can miss secrets. |
| SAF-T1505-C014 | User secrets should be session-scoped and cleared after use. | Demonstrated | SRC-pham-minh-cve-2026-29872: [Pham Minh disclosure](https://github.com/lilmingwa13/security-research/blob/main/CVE-2026-29872.md) | Multi-user state guidance. |
| SAF-T1505-C015 | ATT&CK T1003 is analogous, not direct. | Research-Derived | SRC-mitre-t1003: [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/) | A memory-scraping variant may overlap more closely. |
| SAF-T1505-C016 | Detection requires actor, session, destination, process, variable-name, trust, and authorization context. | Research-Derived | The three selected vulnerability disclosures | Products may not emit the synthetic fields. |
| SAF-T1505-C017 | Response should contain execution, scope exposed identifiers, and rotate potentially exposed credentials. | Research-Derived | SRC-mcp-authorization-2025-11-25, SRC-ghsa-pj2r-f9mw-vrcq, and SRC-pham-minh-cve-2026-29872 | No universal response playbook was reviewed. |
| SAF-T1505-C018 | Confidentiality can be high; integrity and availability require follow-on use. | Research-Derived | The three selected vulnerability disclosures | Impact depends on secret privilege and lifetime. |
| SAF-T1505-C019 | Model refusal is not a reliable sole control. | Demonstrated | SRC-arxiv-2504.03767v2: [Radosevich and Halloran](https://arxiv.org/pdf/2504.03767) | Specific models and controlled scenarios. |

### Current State

- **Affected Environments**: Multi-user agent services with process-global secret state, user-configurable MCP endpoints, and hosts that start local MCP children with broad inherited environments. <!-- SAF-TRACE: claims=SAF-T1505-C005,SAF-T1505-C006,SAF-T1505-C007; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->
- **Known Exploitation**: Controlled demonstrations and proof-of-concept records exist; no qualifying production incident was found in the reviewed corpus. <!-- SAF-TRACE: claims=SAF-T1505-C001,SAF-T1505-C009; sources=SRC-arxiv-2504.03767v2,SRC-cisa-kev-in-memory-secrets-2026-09-01,SRC-nvd-cve-2026-32625,SRC-nvd-cve-2026-29872,SRC-nvd-cve-2026-40159 -->
- **Available Protections**: Remove environment substitution from untrusted configuration, session-scope secrets, minimize child environments by allowlist, sandbox local servers, and restrict their filesystem and network access. <!-- SAF-TRACE: claims=SAF-T1505-C003,SAF-T1505-C012,SAF-T1505-C013,SAF-T1505-C014; sources=SRC-mcp-security-2025-11-25,SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- **Residual Risk**: Model refusal can vary with prompt wording, and authorized environment use prevents a reliable name-only distinction between normal and malicious behavior. <!-- SAF-TRACE: claims=SAF-T1505-C011,SAF-T1505-C019; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq,SRC-arxiv-2504.03767v2 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Radosevich-Halloran MCP credential-theft evaluation | 2025-04-11; Claude Desktop with multiple MCP servers | Environment-held placeholder API keys were found and posted through Slack; the authors recommend least privilege and avoiding sensitive environment storage. | Direct demonstration by Brandon Radosevich and John T. Halloran. | Controlled evaluation, not a breach. <!-- SAF-TRACE: claims=SAF-T1505-C001,SAF-T1505-C019; sources=SRC-arxiv-2504.03767v2 --> |
| CVE-2026-32625 / GHSA-4pcc-j6m6-wcwx | 2026-06-02; LibreChat through 0.8.3 | MCP URL validation could transmit process secrets; 0.8.4-rc1 is listed as patched. | Direct vulnerability reported by YLChen-007. | NVD marks PoC; no production exploitation established. <!-- SAF-TRACE: claims=SAF-T1505-C005; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-nvd-cve-2026-32625 --> |
| CVE-2026-29872 | 2026-03-30; Streamlit GitHub MCP Agent at tested commit e46690f | Cross-session token retrieval was reproduced; Pham Minh recommends session-scoped storage, but no fixed release was identified in the reviewed records. | Direct vulnerability and controlled reproduction by Pham Minh. | A display modification made the leak observable. <!-- SAF-TRACE: claims=SAF-T1505-C006; sources=SRC-pham-minh-cve-2026-29872,SRC-nvd-cve-2026-29872 --> |
| CVE-2026-40159 / GHSA-pj2r-f9mw-vrcq | 2026-04-09; PraisonAI affected through 4.5.117 per advisory | Untrusted MCP children inherited the host environment; 4.5.128 is patched and an allowlist is recommended. | Direct vulnerability reported by l3tchupkt. | NVD says versions before 4.5.128, leaving 4.5.118-4.5.127 uncertain; PoC, not production exploitation. <!-- SAF-TRACE: claims=SAF-T1505-C007; sources=SRC-ghsa-pj2r-f9mw-vrcq,SRC-nvd-cve-2026-40159 --> |

### Real-World Incidents or Demonstrations

No qualifying production incident was identified. The strongest end-to-end evidence is the controlled Radosevich-Halloran MCP credential-theft workflow; the three selected CVEs are vulnerability and PoC evidence, not breaches. <!-- SAF-TRACE: claims=SAF-T1505-C001,SAF-T1505-C009; sources=SRC-arxiv-2504.03767v2,SRC-cisa-kev-in-memory-secrets-2026-09-01,SRC-nvd-cve-2026-32625,SRC-nvd-cve-2026-29872,SRC-nvd-cve-2026-40159 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Signing keys, database credentials, personal access tokens, and API keys can cross to unauthorized recipients when held in reachable live state. <!-- SAF-TRACE: claims=SAF-T1505-C018; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq --> |
| Integrity | Low | Extraction alone does not alter state; integrity impact depends on later use of a write-capable secret. <!-- SAF-TRACE: claims=SAF-T1505-C018; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq --> |
| Availability | None | The extraction mechanism does not require disruption; later credential use may create separate availability effects. <!-- SAF-TRACE: claims=SAF-T1505-C018; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq --> |
| Scope | Multi-System | A live secret may authorize downstream repositories, databases, model APIs, or other services, subject to its privilege and lifetime. <!-- SAF-TRACE: claims=SAF-T1505-C004,SAF-T1505-C018; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq --> |

### Severity Conditions

- **Severity increases when**: Long-lived or high-privilege secrets share a process with untrusted users, configuration, tools, or child servers. <!-- SAF-TRACE: claims=SAF-T1505-C018; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872,SRC-ghsa-pj2r-f9mw-vrcq -->
- **Severity decreases when**: Secrets are short-lived, session-bound, audience-restricted, absent from broad process state, and passed only through explicit allowlists. <!-- SAF-TRACE: claims=SAF-T1505-C004,SAF-T1505-C013,SAF-T1505-C014; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP configuration audit | Remote server configuration validation | Timestamp, actor, session, transport, destination host and trust, input trust, referenced environment-variable names | Record names only; never values. <!-- SAF-TRACE: claims=SAF-T1505-C016; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 --> |
| MCP process-launch audit | Local server child creation | Timestamp, parent, child, package or command trust, inherited variable names, allowlist decision | Normalize trust and allowlist decisions. <!-- SAF-TRACE: claims=SAF-T1505-C016; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 --> |
| Runtime secret-access audit | Secret identifier access | Owner session, requesting session, secret identifier, authorization result | A missing ownership signal is a blind spot. <!-- SAF-TRACE: claims=SAF-T1505-C016; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC was identified; destination hosts, secret names, and child identities are environment-specific behavioral context. <!-- SAF-TRACE: claims=SAF-T1505-C010,SAF-T1505-C011; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872,SRC-mcp-authorization-2025-11-25 -->

### Behavioral Indicators

- An untrusted MCP server configuration references a secret-like environment name while resolving to an external destination. <!-- SAF-TRACE: claims=SAF-T1505-C005,SAF-T1505-C010; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- An untrusted or unknown MCP child receives a non-allowlisted secret-like environment name. <!-- SAF-TRACE: claims=SAF-T1505-C007,SAF-T1505-C010; sources=SRC-ghsa-pj2r-f9mw-vrcq,SRC-ghsa-4pcc-j6m6-wcwx,SRC-pham-minh-cve-2026-29872 -->
- A requesting session accesses a secret owned by another session without an explicit authorization decision. <!-- SAF-TRACE: claims=SAF-T1505-C006,SAF-T1505-C010; sources=SRC-pham-minh-cve-2026-29872,SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect an unauthorized recipient joined to a secret-like live-state access signal. <!-- SAF-TRACE: claims=SAF-T1505-C010; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- **Rule Status**: Experimental because the normalized event schema is synthetic and no reviewed source evaluates this detector. <!-- SAF-TRACE: claims=SAF-T1505-C010; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- **Detection Logic**: Alert on any of the three reviewed boundary patterns: untrusted remote substitution, untrusted child inheritance, or unauthorized cross-session secret access. <!-- SAF-TRACE: claims=SAF-T1505-C010; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- **Correlation Window**: Single normalized event; implementations may correlate configuration validation to the resulting outbound request in one transaction. <!-- SAF-TRACE: claims=SAF-T1505-C005,SAF-T1505-C010; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- **Known False Positives**: Approved local servers may legitimately receive an explicitly allowlisted minimum environment. <!-- SAF-TRACE: claims=SAF-T1505-C002,SAF-T1505-C011; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq -->
- **Known Limitations**: Existing products may not emit ownership or trust context; secret-name heuristics miss unusual names and must not log values. <!-- SAF-TRACE: claims=SAF-T1505-C010,SAF-T1505-C016; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- **Tuning Guidance**: Maintain local trusted-destination, trusted-child, authorized-sharing, and explicit variable allowlists. <!-- SAF-TRACE: claims=SAF-T1505-C011,SAF-T1505-C013; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1505/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1505/test_detection_rule.py)
- **Expected Result**: Eight of eight cases pass, including three positives and negative, boundary, malformed, and expected false-positive cases. <!-- SAF-TRACE: claims=SAF-T1505-C010,SAF-T1505-C011,SAF-T1505-C016; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872,SRC-mcp-authorization-2025-11-25 -->
- **Last Validated**: 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1505-C010; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- **Feasibility Waiver**: None; the analytic has deterministic synthetic cases. <!-- SAF-TRACE: claims=SAF-T1505-C010; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-52: Input Validation Pipeline](../../mitigations/SAF-M-52/README.md)**: Do not apply environment substitution to user-controlled MCP endpoint configuration. <!-- SAF-TRACE: claims=SAF-T1505-C012; sources=SRC-ghsa-4pcc-j6m6-wcwx -->
2. **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Build a strict allowlist for each MCP child instead of copying the parent environment. <!-- SAF-TRACE: claims=SAF-T1505-C013; sources=SRC-ghsa-pj2r-f9mw-vrcq -->
3. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Keep user credentials in session-scoped storage, bind them to the owner, clear them after use, and avoid process-global state. <!-- SAF-TRACE: claims=SAF-T1505-C014; sources=SRC-pham-minh-cve-2026-29872 -->
4. **[SAF-M-9: Sandboxed Testing](../../mitigations/SAF-M-9/README.md)**: Sandbox local MCP servers with minimal privileges and restrict filesystem and network access. <!-- SAF-TRACE: claims=SAF-T1505-C003; sources=SRC-mcp-security-2025-11-25 -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Record variable names, owners, recipient trust, and allowlist outcomes while redacting values. <!-- SAF-TRACE: claims=SAF-T1505-C016; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
2. **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20/README.md)**: Require an unauthorized or untrusted recipient so legitimate stdio credential use does not alert by itself. <!-- SAF-TRACE: claims=SAF-T1505-C011; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq -->

### Response Procedures

#### Immediate Actions

- Stop the affected session or process and prevent further launches or outbound requests on the implicated configuration. <!-- SAF-TRACE: claims=SAF-T1505-C017; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- **[SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37/README.md)** and **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Rotate each potentially exposed credential according to its issuing service and shorten token lifetime where supported. <!-- SAF-TRACE: claims=SAF-T1505-C004,SAF-T1505-C017; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->

#### Investigation Steps

- Preserve redacted configuration-validation, child-launch, secret-access, and destination telemetry; do not capture secret values. <!-- SAF-TRACE: claims=SAF-T1505-C016,SAF-T1505-C017; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- Identify affected secret names, owner sessions, unauthorized recipients, and any follow-on use in the issuing services. <!-- SAF-TRACE: claims=SAF-T1505-C004,SAF-T1505-C017; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->

#### Remediation

- Patch the affected implementation and enforce input separation, session scoping, or child-environment allowlisting for the relevant variant. <!-- SAF-TRACE: claims=SAF-T1505-C012,SAF-T1505-C013,SAF-T1505-C014; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872 -->
- Re-run positive, negative, boundary, malformed, and expected false-positive tests before restoring the path. <!-- SAF-TRACE: claims=SAF-T1505-C010,SAF-T1505-C011; sources=SRC-ghsa-4pcc-j6m6-wcwx,SRC-ghsa-pj2r-f9mw-vrcq,SRC-pham-minh-cve-2026-29872,SRC-mcp-authorization-2025-11-25 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1502: File-Based Credential Harvest](../SAF-T1502/README.md) | Alternative source | SAF-T1502 reads credential-bearing files rather than live runtime state; vaults and databases remain outside this direct join. See the [contract](../../research/techniques/SAF-T1505/technique-contract.yml). |
| [SAF-T1305: Host OS Priv-Esc (RCE)](../SAF-T1305/README.md) | Prerequisite or enabling | Code execution can create process access but does not establish extraction unless live secret material is actually reached. See the [contract](../../research/techniques/SAF-T1505/technique-contract.yml). |
| [SAF-T1911: Parameter Exfiltration](../SAF-T1911/README.md) | Follow-on | SAF-T1911 begins after acquisition and transfers the value through outbound tool parameters. See the [contract](../../research/techniques/SAF-T1505/technique-contract.yml). |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Analogous | Both concern credential acquisition from memory, but T1003 focuses on operating-system credential material and privileged memory or stores; SAF-T1505 includes application-level environment and session state. <!-- SAF-TRACE: claims=SAF-T1505-C015; sources=SRC-mitre-t1003 --> |

## References

1. **SRC-arxiv-2504.03767v2**: [MCP Safety Audit — Brandon Radosevich and John T. Halloran](https://arxiv.org/pdf/2504.03767), version 2, 2025-04-11.
2. **SRC-mcp-authorization-2025-11-25**: [Model Context Protocol Authorization](https://modelcontextprotocol.io/docs/2025-11-25/specification/basic/authorization), Model Context Protocol maintainers, 2025-11-25.
3. **SRC-mcp-security-2025-11-25**: [Model Context Protocol Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices), Model Context Protocol maintainers, 2025-11-25.
4. **SRC-ghsa-4pcc-j6m6-wcwx**: [LibreChat advisory GHSA-4pcc-j6m6-wcwx](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-4pcc-j6m6-wcwx), reported by YLChen-007 and published by danny-avila, 2026-06-02.
5. **SRC-nvd-cve-2026-32625**: [NVD CVE-2026-32625](https://nvd.nist.gov/vuln/detail/CVE-2026-32625), NIST NVD and the originating CNA.
6. **SRC-pham-minh-cve-2026-29872**: [CVE-2026-29872 disclosure](https://github.com/lilmingwa13/security-research/blob/main/CVE-2026-29872.md), Pham Minh, 2026.
7. **SRC-nvd-cve-2026-29872**: [NVD CVE-2026-29872](https://nvd.nist.gov/vuln/detail/CVE-2026-29872), NIST NVD and the originating CNA.
8. **SRC-ghsa-pj2r-f9mw-vrcq**: [PraisonAI advisory GHSA-pj2r-f9mw-vrcq](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-pj2r-f9mw-vrcq), reported by l3tchupkt and published by MervinPraison, 2026-04-09.
9. **SRC-nvd-cve-2026-40159**: [NVD CVE-2026-40159](https://nvd.nist.gov/vuln/detail/CVE-2026-40159), NIST NVD and the originating CNA.
10. **SRC-ghsa-mp29-fxh8-92px**: [FrontMCP advisory GHSA-mp29-fxh8-92px](https://github.com/agentfront/frontmcp/security/advisories/GHSA-mp29-fxh8-92px), reported by fg0x0 and remediated by frontegg-david, 2026-07-26.
11. **SRC-nvd-cve-2026-67531**: [NVD CVE-2026-67531](https://nvd.nist.gov/vuln/detail/CVE-2026-67531), NIST NVD and the originating CNA.
12. **SRC-cisa-kev-in-memory-secrets-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), catalog version 2026.09.01.
13. **SRC-mitre-t1003**: [MITRE ATT&CK T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003/), MITRE ATT&CK team.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Independent clean-room authoring, evidence packet, and tested analytic | OpenAI Codex clean-room author |
