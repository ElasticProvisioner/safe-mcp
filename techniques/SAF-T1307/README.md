# SAF-T1307: Confused Deputy Attack

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1307
- **Research Packet**: [research/techniques/SAF-T1307](../../research/techniques/SAF-T1307/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1307/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A successful deputy-confusion path can expose the deputy's identity, network reach, or process-launch authority, with impact bounded by the deputy's privileges and the attacker's ability to supply an unbound directive. [CWE-441](https://cwe.mitre.org/data/definitions/441.html) <!-- SAF-TRACE: claims=SAF-T1307-C002,SAF-T1307-C017; sources=SRC-cwe-441-v4.20,SRC-ghsa-inspector-7f8r,SRC-jfrog-cve-2025-6514 -->
- **First Observed**: Not observed in a qualifying production incident; publicly demonstrated against `mcp-remote` on 2025-07-09. [JFrog analysis](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) <!-- SAF-TRACE: claims=SAF-T1307-C007,SAF-T1307-C010; sources=SRC-jfrog-cve-2025-6514,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers an attacker causing an MCP or agentic intermediary to use authority, identity, network reach, or execution capability unavailable to the attacker because the intermediary fails to preserve or enforce the initiating principal's identity, resource, authorization intent, or approved delegation. [CWE-441 definition](https://cwe.mitre.org/data/definitions/441.html) <!-- SAF-TRACE: claims=SAF-T1307-C001; sources=SRC-cwe-441-v4.20 -->

### In Scope

- An MCP proxy, client, host, or agent receives attacker-controlled intent and performs a protected downstream action under a different, more privileged security context without a valid initiating-principal binding. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C011; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
- OAuth proxy confusion, token-audience confusion, unauthenticated proxy-to-process launch, and equivalent agent-to-tool delegation are in scope when the deputy's distinct authority is the boundary-crossing mechanism. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C005,SAF-T1307-C007,SAF-T1307-C008; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r -->

### Out of Scope

- Prompt or instruction injection is delivery behavior, not this technique, unless the injected instruction causes a separately authorized deputy to cross the defined privilege boundary. <!-- SAF-TRACE: claims=SAF-T1307-C009,SAF-T1307-C012; sources=SRC-cve-2025-32711,SRC-cwe-441-v4.20 -->
- SSRF, path traversal, token theft, and command injection remain separate mechanisms when they do not rely on an intermediary's distinct authority or loss of initiator binding. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C016; sources=SRC-cwe-441-v4.20,SRC-cve-2025-53109 -->

### Distinguishing Characteristics

The decisive observable is an authorization asymmetry: the initiator is not permitted to perform the action, the deputy is permitted, and the deputy acts without a valid binding among initiator, approved delegation, target resource, and action. A mere malicious input or vulnerable sink is insufficient without that asymmetric authority. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C011; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->

## Description

A confused deputy attack turns a legitimate intermediary into the apparent source of an attacker's request. The weakness matters when the intermediary has access the attacker lacks and forwards or executes a request outside the authority actually granted to the initiator. [CWE-441](https://cwe.mitre.org/data/definitions/441.html) <!-- SAF-TRACE: claims=SAF-T1307-C001; sources=SRC-cwe-441-v4.20 -->

MCP documents a direct OAuth form of the problem: an MCP proxy using a static third-party client ID can combine dynamic MCP client registration, an existing consent cookie, and missing per-client consent so that an attacker receives an authorization code and accesses a third-party API as the user. This is an authoritative attack model, not evidence of a production incident. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#confused-deputy-problem) <!-- SAF-TRACE: claims=SAF-T1307-C003; sources=SRC-mcp-security-2026-07-28 -->

The same boundary failure can appear below OAuth. JFrog demonstrated that an untrusted MCP server could supply an authorization endpoint that `mcp-remote` passed to a privileged URL-opening path, producing process execution on the client system; the MCP Inspector advisory separately records unauthenticated proxy requests launching MCP commands over `stdio`. [JFrog analysis](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [Inspector advisory](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g) <!-- SAF-TRACE: claims=SAF-T1307-C007,SAF-T1307-C008; sources=SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r -->

## Attack Vectors

- **Primary Vector**: Attacker-controlled authorization metadata, proxy requests, or agent instructions reach a deputy that has stronger downstream authority than the initiator. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C007,SAF-T1307-C008; sources=SRC-mcp-security-2026-07-28,SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r -->
- **Secondary Vectors**: Cross-resource token reuse and dynamically registered redirect targets can detach downstream authority from the intended client or resource. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C005,SAF-T1307-C006; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-rfc9700 -->
- **Affected Components**: MCP proxies, clients, hosts, authorization servers, agent runtimes, tool gateways, and downstream APIs that perform delegated actions. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C003; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
- **Trust Boundary Crossed**: The boundary between attacker-controlled intent and the deputy's separately authorized identity, network position, token audience, or process privileges. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C005; sources=SRC-cwe-441-v4.20,SRC-rfc8707 -->

## Technical Details

### Prerequisites

- The intermediary has authority, reach, or execution capability the initiating attacker does not possess. <!-- SAF-TRACE: claims=SAF-T1307-C001; sources=SRC-cwe-441-v4.20 -->
- The attacker can cause the intermediary to receive a request, directive, authorization value, or target that the intermediary may forward or execute. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C003; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
- The system lacks or fails an enforceable binding among initiating principal, approved client or delegation, target resource, and requested action. <!-- SAF-TRACE: claims=SAF-T1307-C004,SAF-T1307-C005,SAF-T1307-C013; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-rfc9700 -->

### Attack Flow

1. **Setup**: The attacker identifies a deputy whose downstream authority exceeds the attacker's own. <!-- SAF-TRACE: claims=SAF-T1307-C001; sources=SRC-cwe-441-v4.20 -->
2. **Delivery**: The attacker supplies metadata, a request, or instructions that encode an attacker-chosen client, redirect, resource, or operation. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C007,SAF-T1307-C008; sources=SRC-mcp-security-2026-07-28,SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r -->
3. **Trigger**: The intermediary treats the input as eligible for delegated processing and initiates the protected action. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C007; sources=SRC-cwe-441-v4.20,SRC-jfrog-cve-2025-6514 -->
4. **Boundary Crossing**: Initiator identity, per-client consent, audience, target, or delegation binding is absent, stale, or not enforced. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C005,SAF-T1307-C006; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-rfc9700 -->
5. **Objective**: The deputy performs or enables an action that the initiating attacker could not perform directly. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C002; sources=SRC-cwe-441-v4.20 -->
6. **Follow-On Activity**: Consequences can include assumed identity, unauthorized command execution, hidden attribution, or access to data within the deputy's reachable scope. <!-- SAF-TRACE: claims=SAF-T1307-C002,SAF-T1307-C017; sources=SRC-cwe-441-v4.20,SRC-ghsa-inspector-7f8r,SRC-jfrog-cve-2025-6514 -->

### Example Scenario

An untrusted client asks `proxy.example` to invoke `records.read` for `tenant-b`; the proxy's service identity is authorized, but the initiating client is not, and the proxy emits the call without a valid delegation binding. The inert audit shape is `{"initiator":"client-untrusted","deputy":"proxy.example","resource":"tenant-b/records","binding_valid":false}`. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C011; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1307-C001 | A confused deputy fails to preserve the upstream requester's identity and uses different access to forward an unintended request. | Research-Derived | SRC-cwe-441-v4.20: [CWE-441](https://cwe.mitre.org/data/definitions/441.html) | A class-level weakness; each product mapping requires review. |
| SAF-T1307-C002 | Consequences include gained privilege or identity, hidden activity, and unauthorized code or commands. | Research-Derived | SRC-cwe-441-v4.20: [CWE-441 consequences](https://cwe.mitre.org/data/definitions/441.html) | Consequence, not likelihood for any one system. |
| SAF-T1307-C003 | MCP documents a complete OAuth proxy confused-deputy flow and its exact prerequisites. | Research-Derived | SRC-mcp-security-2026-07-28: [MCP security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#confused-deputy-problem) | Authoritative model, not a reported breach or controlled product test. |
| SAF-T1307-C004 | MCP requires per-client consent controls for the documented proxy pattern. | Research-Derived | SRC-mcp-security-2026-07-28: [MCP required protections](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#required-protections) | Applies to the documented OAuth proxy conditions. |
| SAF-T1307-C005 | MCP and RFC 8707 require or recommend resource and audience binding that limits token use across resources. | Research-Derived | SRC-mcp-authorization-2026-07-28 and SRC-rfc8707: [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html#section-3) | Token binding does not validate arbitrary non-OAuth deputy actions. |
| SAF-T1307-C006 | OAuth BCP requires exact redirect matching and recommends least-privilege, audience-restricted tokens. | Research-Derived | SRC-rfc9700: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | General OAuth guidance, not MCP-specific incident evidence. |
| SAF-T1307-C007 | JFrog demonstrated CVE-2025-6514 causing client-side execution from an untrusted MCP server; version 0.1.16 fixes the issue. | Demonstrated | SRC-jfrog-cve-2025-6514, SRC-jfsa-2025-6514, SRC-cve-2025-6514: [research report](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/), [advisory](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/) | Full shell-argument control was proven on Windows; other platforms had narrower demonstrated control. |
| SAF-T1307-C008 | CVE-2025-49596 allowed unauthenticated Inspector proxy requests to launch MCP commands over stdio before 0.14.1. | Research-Derived | SRC-ghsa-inspector-7f8r, SRC-cve-2025-49596: [maintainer advisory](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g) | The reviewed advisory establishes vulnerability, not production exploitation. |
| SAF-T1307-C009 | CVE-2025-32711 is a critical M365 Copilot command-injection information-disclosure vulnerability, but the reviewed record does not establish the deputy-binding mechanism. | Research-Derived | SRC-cve-2025-32711: [CVE record](https://cveawg.mitre.org/api/cve/CVE-2025-32711) | Adjacent agentic evidence only. |
| SAF-T1307-C010 | No selected candidate appeared in the 2026-09-01 KEV snapshot, and no qualifying production incident was found in this corpus. | Research-Derived | SRC-cisa-kev-2026-09-01: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | A dated, bounded search result; not a claim that exploitation has never occurred. |
| SAF-T1307-C011 | A runtime analytic can correlate initiator authorization, deputy authorization, and binding validity to identify suspicious asymmetric delegation. | Research-Derived | SRC-cwe-441-v4.20, SRC-mcp-security-2026-07-28 | Inferred analytic requiring normalized fields not guaranteed by MCP. |
| SAF-T1307-C012 | Legitimate proxying and absent identity context limit behavioral detection and can create false positives. | Research-Derived | SRC-cwe-441-v4.20: [CWE-441](https://cwe.mitre.org/data/definitions/441.html) | Environment-specific delegation policy is still required. |
| SAF-T1307-C013 | Initiator preservation, per-client consent, exact redirects, audience binding, and least privilege constrain the defining mechanism. | Research-Derived | SRC-cwe-441-v4.20, SRC-mcp-security-2026-07-28, SRC-rfc8707, SRC-rfc9700 | Controls must be enforced at every deputy hop. |
| SAF-T1307-C014 | Containment should stop the deputy path, revoke affected authorization material, and reconstruct the initiator-to-target chain. | Research-Derived | SRC-mcp-security-2026-07-28, SRC-rfc9700 | Response synthesis; exact revocation actions depend on the implementation. |
| SAF-T1307-C015 | ATT&CK T1068 is analogous where a deputy vulnerability is exploited to gain higher access, but it does not model delegation confusion. | Research-Derived | SRC-mitre-attack-t1068: [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) | Analogous, not direct. |
| SAF-T1307-C016 | CVE-2025-53109 concerns MCP filesystem symlink/path validation and is not evidence for this authority-binding mechanism. | Research-Derived | SRC-cve-2025-53109: [CVE record](https://cveawg.mitre.org/api/cve/CVE-2025-53109) | Excluded adjacent vulnerability. |
| SAF-T1307-C017 | Realized impact is bounded by the deputy's reachable resources and privileges. | Research-Derived | SRC-cwe-441-v4.20, SRC-ghsa-inspector-7f8r, SRC-jfrog-cve-2025-6514 | Does not predict exploit probability. |

### Current State

- **Affected Environments**: Systems with an MCP or agentic intermediary that accepts less-trusted requests while holding stronger OAuth, network, tool, or process authority. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C003,SAF-T1307-C007,SAF-T1307-C008; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28,SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r -->
- **Known Exploitation**: No qualifying production incident was identified in the reviewed corpus as of 2026-09-01; two direct MCP vulnerabilities and one adjacent agentic vulnerability were selected. <!-- SAF-TRACE: claims=SAF-T1307-C007,SAF-T1307-C008,SAF-T1307-C009,SAF-T1307-C010; sources=SRC-cve-2025-6514,SRC-cve-2025-49596,SRC-cve-2025-32711,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: `mcp-remote` 0.1.16 and MCP Inspector 0.14.1 address the selected product flaws; current MCP guidance also requires per-client consent and token-resource binding. <!-- SAF-TRACE: claims=SAF-T1307-C004,SAF-T1307-C005,SAF-T1307-C007,SAF-T1307-C008; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r -->
- **Residual Risk**: Patches for named products do not eliminate deputy confusion in custom proxies, agents, or multi-hop delegations that still fail to bind initiator, resource, and approval. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C013; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28,SRC-rfc8707,SRC-rfc9700 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-6514 | Published 2025-07-09; `mcp-remote` 0.0.5 through 0.1.15 when connecting to an untrusted MCP server. | Client-side command or executable execution; update to 0.1.16. | Direct vulnerability and direct public demonstration: attacker-supplied authorization metadata reached a more privileged URL-opening deputy. <!-- SAF-TRACE: claims=SAF-T1307-C007; sources=SRC-cve-2025-6514,SRC-jfsa-2025-6514,SRC-jfrog-cve-2025-6514 --> | No reviewed evidence of production exploitation; non-Windows control was more limited. |
| CVE-2025-49596 / GHSA-7f8r-222p-6f5g | Published 2025-06-13; MCP Inspector before 0.14.1. | Unauthenticated proxy requests could launch MCP commands over stdio; update to 0.14.1. | Direct vulnerability: an unauthenticated initiator could exercise the proxy's process-launch authority. <!-- SAF-TRACE: claims=SAF-T1307-C008; sources=SRC-cve-2025-49596,SRC-ghsa-inspector-7f8r --> | Advisory evidence, not a production incident. |
| CVE-2025-32711 | Published 2025-06-11; Microsoft 365 Copilot hosted service. | Network information disclosure from AI command injection; the CNA record links a vendor patch and reports a critical score. | Adjacent agentic vulnerability retained for impact context; the reviewed record does not establish initiator/deputy binding loss. <!-- SAF-TRACE: claims=SAF-T1307-C009; sources=SRC-cve-2025-32711 --> | CISA enrichment reports exploitation as none; affected version and rollout detail are not exposed in the CNA record. |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A deputy can expose resources reachable under its identity, as illustrated by agentic information disclosure and CWE-441 identity abuse. <!-- SAF-TRACE: claims=SAF-T1307-C002,SAF-T1307-C009,SAF-T1307-C017; sources=SRC-cwe-441-v4.20,SRC-cve-2025-32711 --> |
| Integrity | High | A deputy with process or tool authority can execute attacker-chosen actions under the deputy's privilege. <!-- SAF-TRACE: claims=SAF-T1307-C002,SAF-T1307-C007,SAF-T1307-C008,SAF-T1307-C017; sources=SRC-cwe-441-v4.20,SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r --> |
| Availability | High | Demonstrated or advisory-described process execution can affect availability when the deputy can modify or terminate reachable resources. <!-- SAF-TRACE: claims=SAF-T1307-C007,SAF-T1307-C008,SAF-T1307-C017; sources=SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r --> |
| Scope | Multi-System | OAuth proxy and tool-gateway deputies can bridge clients, authorization systems, downstream APIs, and local processes; actual spread is limited to the deputy's reachable scope. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C005,SAF-T1307-C017; sources=SRC-mcp-security-2026-07-28,SRC-rfc8707,SRC-cwe-441-v4.20 --> |

### Severity Conditions

- **Severity increases when**: The deputy has broad tokens, cross-tenant reach, local process-launch capability, or no per-client approval boundary. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C006,SAF-T1307-C007,SAF-T1307-C008,SAF-T1307-C017; sources=SRC-mcp-security-2026-07-28,SRC-rfc9700,SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r -->
- **Severity decreases when**: Tokens are resource- and audience-bound, scopes are minimal, every delegation is bound to the initiator, and high-risk actions require fresh approval. <!-- SAF-TRACE: claims=SAF-T1307-C004,SAF-T1307-C005,SAF-T1307-C006,SAF-T1307-C013; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-rfc9700 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host, proxy, or agent audit log | Authorization initiation, downstream call, tool execution, or process launch | Timestamp, session, initiator ID, deputy ID, action, resource, initiator authorization, deputy authorization, approval or delegation ID, binding result, outcome | Preserve a correlation identifier across every deputy hop. <!-- SAF-TRACE: claims=SAF-T1307-C011,SAF-T1307-C012; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 --> |
| OAuth authorization and resource logs | Client registration, consent, code issuance, token issuance, and resource access | Client ID, resource owner, redirect URI, approved redirect, scopes, resource, audience, state result, token ID, result | Compare client, resource, and audience at issuance and use. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C004,SAF-T1307-C005,SAF-T1307-C006; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-rfc9700 --> |

### Indicators of Compromise (IoCs)

- No universal durable IoC exists; this is an authorization relationship and must be evaluated from event context. <!-- SAF-TRACE: claims=SAF-T1307-C011,SAF-T1307-C012; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
- Product-specific signals can include an untrusted authorization endpoint preceding a process launch or an unauthenticated Inspector proxy request preceding `stdio` command launch. <!-- SAF-TRACE: claims=SAF-T1307-C007,SAF-T1307-C008; sources=SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r -->

### Behavioral Indicators

- Alert when a deputy-authorized action succeeds or is attempted while the initiator is unauthorized and the authorization or delegation binding is invalid. <!-- SAF-TRACE: claims=SAF-T1307-C011; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
- Increase confidence when the same correlation chain contains redirect mismatch, missing per-client consent, resource/audience mismatch, or process launch from remotely supplied metadata. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C005,SAF-T1307-C007,SAF-T1307-C011; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-jfrog-cve-2025-6514 -->
- Suppress only when a validated, current delegation explicitly binds the same initiator, action, and target resource. <!-- SAF-TRACE: claims=SAF-T1307-C012,SAF-T1307-C013; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect asymmetric deputy actions in which the deputy is authorized, the initiator is not, and no valid delegation binding is present. <!-- SAF-TRACE: claims=SAF-T1307-C011; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
- **Rule Status**: [Experimental rule](detection-rule.yml)
- **Detection Logic**: Select normalized deputy-action events with `deputy.allowed=true`, `initiator.allowed=false`, and `binding.valid=false`; exclude an explicitly validated delegation. <!-- SAF-TRACE: claims=SAF-T1307-C011; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
- **Correlation Window**: Correlate the initiating event and downstream action within ten minutes when they are emitted as separate events. <!-- SAF-TRACE: claims=SAF-T1307-C011; sources=SRC-mcp-security-2026-07-28,SRC-cwe-441-v4.20 -->
- **Known False Positives**: Approved service-to-service delegation can look asymmetric if delegation validation is omitted from the normalized event. <!-- SAF-TRACE: claims=SAF-T1307-C012; sources=SRC-cwe-441-v4.20 -->
- **Known Limitations**: Missing initiator or binding fields create a blind spot; the rule does not infer authorization from free-form prompt text. <!-- SAF-TRACE: claims=SAF-T1307-C011,SAF-T1307-C012; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
- **Tuning Guidance**: Normalize explicit policy decisions and approved delegation IDs before applying service-account allowlists. <!-- SAF-TRACE: claims=SAF-T1307-C011,SAF-T1307-C012; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1307/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1307/test_detection_rule.py)
- **Expected Result**: [Three positive and five non-alerting cases pass](../../tests/SAF-T1307/test-logs.json)
- **Last Validated**: [2026-09-01](../../tests/SAF-T1307/test-logs.json)
- **Feasibility Waiver**: [None; deterministic normalized-event tests are present](../../tests/SAF-T1307/test_detection_rule.py)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Preserve an immutable initiator identity and bind each delegation to the approved action and target. <!-- SAF-TRACE: claims=SAF-T1307-C002,SAF-T1307-C013; sources=SRC-cwe-441-v4.20 -->
2. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Restrict deputy tokens and runtime privileges to the smallest resource and action set. <!-- SAF-TRACE: claims=SAF-T1307-C005,SAF-T1307-C006,SAF-T1307-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-rfc9700 -->
3. **Per-client consent and redirect validation**: Bind consent to the requesting client, show scopes and redirect target, match redirects exactly, and validate single-use state. <!-- SAF-TRACE: claims=SAF-T1307-C004,SAF-T1307-C006,SAF-T1307-C013; sources=SRC-mcp-security-2026-07-28,SRC-rfc9700 -->

### Detective Controls

1. Preserve initiator, deputy, resource, authorization decision, delegation, and outcome in one correlation chain. <!-- SAF-TRACE: claims=SAF-T1307-C011,SAF-T1307-C013; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->
2. Monitor redirect, consent, resource, audience, and process-launch mismatches rather than treating the deputy's authenticated identity as sufficient. <!-- SAF-TRACE: claims=SAF-T1307-C003,SAF-T1307-C005,SAF-T1307-C007,SAF-T1307-C011; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-jfrog-cve-2025-6514 -->

### Response Procedures

#### Immediate Actions

- Stop or isolate the deputy path, disable the affected client or proxy, and block further downstream actions under the implicated authorization context. <!-- SAF-TRACE: claims=SAF-T1307-C014; sources=SRC-mcp-security-2026-07-28,SRC-rfc9700 -->
- Revoke affected authorization codes, access or refresh tokens, proxy credentials, and delegations when the reviewed event chain shows possible exposure. <!-- SAF-TRACE: claims=SAF-T1307-C014; sources=SRC-mcp-security-2026-07-28,SRC-rfc9700 -->

#### Investigation Steps

- Reconstruct the initiator-to-deputy-to-target chain and compare registered client, redirect, consent, resource, audience, requested action, and actual outcome. <!-- SAF-TRACE: claims=SAF-T1307-C005,SAF-T1307-C011,SAF-T1307-C014; sources=SRC-mcp-security-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-rfc9700 -->
- Determine whether the issue is deputy confusion or an adjacent injection, SSRF, path-validation, or token-theft mechanism before scoping follow-on activity. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C014,SAF-T1307-C016; sources=SRC-cwe-441-v4.20,SRC-cve-2025-53109,SRC-rfc9700 -->

#### Remediation

- Patch affected products, restore per-client and per-resource authorization binding, and reduce deputy privileges before re-enabling the path. <!-- SAF-TRACE: claims=SAF-T1307-C007,SAF-T1307-C008,SAF-T1307-C013,SAF-T1307-C014; sources=SRC-jfrog-cve-2025-6514,SRC-ghsa-inspector-7f8r,SRC-mcp-security-2026-07-28,SRC-rfc9700 -->
- Add regression cases for unauthorized initiators, target mismatches, stale approvals, missing binding fields, and valid delegated lookalikes. <!-- SAF-TRACE: claims=SAF-T1307-C011,SAF-T1307-C012,SAF-T1307-C014; sources=SRC-cwe-441-v4.20,SRC-mcp-security-2026-07-28 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Possible prerequisite | Injection changes interpreted instructions; confused deputy requires a separate authority asymmetry and invalid delegation binding. <!-- SAF-TRACE: claims=SAF-T1307-C001,SAF-T1307-C009,SAF-T1307-C012; sources=SRC-cwe-441-v4.20,SRC-cve-2025-32711 --> |
| [SAF-T1707: CSRF Token Relay](../SAF-T1707/README.md) | Overlapping deputy behavior | CSRF token relay causes a browser or portal to exercise stored authority, while confused deputy is bounded more generally by an intermediary's distinct authority and loss of initiator context. <!-- SAF-TRACE: claims=SAF-T1307-C001; sources=SRC-cwe-441-v4.20 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Analogous | Both use a software weakness to obtain higher access, but T1068 does not encode the initiator/deputy/target delegation relationship. <!-- SAF-TRACE: claims=SAF-T1307-C015; sources=SRC-mitre-attack-t1068 --> |

## References

1. **SRC-cwe-441-v4.20**: [CWE-441: Unintended Proxy or Intermediary](https://cwe.mitre.org/data/definitions/441.html) — MITRE CWE Content Team; definition, conditions, consequences, mitigation, and detection.
2. **SRC-mcp-security-2026-07-28**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) — Model Context Protocol maintainers; confused deputy, token passthrough, URL validation, and logging guidance.
3. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — Model Context Protocol maintainers; resource parameters and token handling.
4. **SRC-rfc8707**: [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html) — Brian Campbell, John Bradley, and Hannes Tschofenig; resource and audience restriction.
5. **SRC-rfc9700**: [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) — Torsten Lodderstedt, John Bradley, Andrey Labunets, and Daniel Fett; redirect, privilege, audience, and token controls.
6. **SRC-cve-2025-6514**: [CVE-2025-6514 CNA record](https://cveawg.mitre.org/api/cve/CVE-2025-6514) — JFrog CNA and CISA Vulnerability Enrichment Team; affected range, impact, references, and exploitation assessment.
7. **SRC-jfsa-2025-6514**: [JFSA-2025-001290844](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/) — Or Peles and the JFrog Security Research Team; discovery credit and affected versions.
8. **SRC-jfrog-cve-2025-6514**: [Critical RCE Vulnerability in mcp-remote](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) — Or Peles and the JFrog Security Research Team; reproduction, platform limits, and fixed version.
9. **SRC-cve-2025-49596**: [CVE-2025-49596 CNA record](https://cveawg.mitre.org/api/cve/CVE-2025-49596) — GitHub CNA and CISA Vulnerability Enrichment Team; affected range and exploitation assessment.
10. **SRC-ghsa-inspector-7f8r**: [Inspector proxy server vulnerabilities](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g) — publisher handle `petery-ant` and the Model Context Protocol maintainers; credit to Rémy Marot of Tenable; affected and fixed versions.
11. **SRC-cve-2025-32711**: [CVE-2025-32711 CNA record](https://cveawg.mitre.org/api/cve/CVE-2025-32711) — Microsoft Security Response Center, CVE Program, and CISA Vulnerability Enrichment Team; M365 Copilot vulnerability and exploitation assessment.
12. **SRC-cve-2025-53109**: [CVE-2025-53109 CNA record](https://cveawg.mitre.org/api/cve/CVE-2025-53109) — GitHub CNA and CISA Vulnerability Enrichment Team; adjacent filesystem weakness.
13. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Cybersecurity and Infrastructure Security Agency; exact-ID absence check.
14. **SRC-mitre-attack-t1068**: [ATT&CK T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) — MITRE ATT&CK Team and named page contributors; analogous mapping.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft, evidence packet, and tested detection | OpenAI Codex clean-room agent |
