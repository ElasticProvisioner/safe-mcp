# SAF-T1206: Credential Implant in Config

## Overview

- **Tactic**: Persistence (ATK-TA0003)
- **Technique ID**: SAF-T1206
- **Research Packet**: [research/techniques/SAF-T1206](../../research/techniques/SAF-T1206/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1206/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: An implanted credential can make later agent sessions act through an attacker-selected identity, with impact bounded by that identity's privileges and the tools exposed through the configured server. [Microsoft Foundry authentication guidance](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/mcp-authentication) <!-- SAF-TRACE: claims=SAF-T1206-C019; sources=SRC-t1206-foundry-auth -->
- **First Observed**: No direct production instance was identified in the authoritative corpus reviewed through 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1206-C011; sources=SRC-t1206-nvd-cursor,SRC-t1206-nvd-dive,SRC-t1206-nvd-zed,SRC-t1206-ms-config-risk,SRC-t1206-gtig-ai-threats -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers an adversary writing or replacing a credential, credential reference, or client-registration identity in persistent MCP or agent configuration so later connections authenticate with an attacker-selected identity. The crossed boundary is the administrative trust placed in persistent client configuration when it selects authentication material for future server connections. <!-- SAF-TRACE: claims=SAF-T1206-C001,SAF-T1206-C005; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli,SRC-t1206-mcp-client-registration,SRC-t1206-ghsa-cursor -->

### In Scope

- Adding or replacing a literal token, client credential, secret reference, or credential-provider reference in a persistent MCP/agent configuration record. <!-- SAF-TRACE: claims=SAF-T1206-C002; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli,SRC-t1206-foundry-auth -->
- Causing later client or agent sessions to reuse that attacker-selected authentication identity for a configured MCP server. <!-- SAF-TRACE: claims=SAF-T1206-C003,SAF-T1206-C005; sources=SRC-t1206-mcp-client-registration,SRC-t1206-copilot-cli -->

### Out of Scope

- Stealing an existing token without altering persistent configuration; that is credential acquisition, not a credential implant. <!-- SAF-TRACE: claims=SAF-T1206-C020; sources=SRC-mcp-auth-security-2026-07-28 -->
- Injecting a command or MCP server solely to obtain code execution belongs with [SAF-T1006: Malicious MCP Server Distribution](../SAF-T1006/README.md), even when the delivery artifact is the same configuration file. <!-- SAF-TRACE: claims=SAF-T1206-C009,SAF-T1206-C010; sources=SRC-ghsa-zed-68433,SRC-ghsa-dive-66580 -->
- Adding a credential directly to a cloud account or OAuth application; ATT&CK T1098.001 covers that account-side behavior, while this technique covers the agent-client configuration that chooses a credential. <!-- SAF-TRACE: claims=SAF-T1206-C018; sources=SRC-t1206-attack-t1098-001 -->
- Substituting only a server endpoint, or using an already implanted credential, which are separate configuration-redirection and valid-identity behaviors. <!-- SAF-TRACE: claims=SAF-T1206-C001; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->

### Distinguishing Characteristics

[SAF-T1502](../SAF-T1502/README.md) ends when an existing file-based credential is copied; [SAF-T1006](../SAF-T1006/README.md) delivers a configured malicious server; and [SAF-T1407](../SAF-T1407/README.md) changes the apparent destination identity. SAF-T1206 requires a persistent configuration change whose immediate objective is future authentication as an attacker-selected identity. <!-- SAF-TRACE: claims=SAF-T1206-C001,SAF-T1206-C020; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli,SRC-t1206-mcp-client-registration -->

## Description

MCP clients can obtain authentication material from static client registration, stored OAuth state, input variables, environment references, or configured headers. Current MCP authorization rules require persisted registration credentials to remain bound to the issuer that created them, while product configurations may retain the references that supply credentials to later runs. <!-- SAF-TRACE: claims=SAF-T1206-C002,SAF-T1206-C003; sources=SRC-t1206-mcp-client-registration,SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->

An adversary who can modify a trusted persistent configuration can replace that identity selection with an attacker-controlled credential or reference. On the next start or reconnect, the client may authenticate with the implanted identity, creating persistence at the client-to-server trust boundary without changing the victim's primary account. This end-to-end behavior is an explicit synthesis of documented configuration and authorization behaviors; no reviewed source demonstrated the complete credential-implant sequence in production. <!-- SAF-TRACE: claims=SAF-T1206-C001,SAF-T1206-C005,SAF-T1206-C011; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli,SRC-t1206-mcp-client-registration,SRC-t1206-ghsa-cursor,SRC-t1206-ms-config-risk,SRC-t1206-gtig-ai-threats -->

The technique does not assume that every credential-bearing configuration is insecure. Microsoft and MCP guidance instead favor secure storage, issuer and audience binding, workload identities, least privilege, and reference-based secret handling; those controls narrow both implant opportunity and resulting authority. <!-- SAF-TRACE: claims=SAF-T1206-C004,SAF-T1206-C016; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-security-2026-07-28,SRC-ms-azure-mcp-security-2026 -->

## Attack Vectors

- **Primary Vector**: Unauthorized write access to a user, workspace, repository, or centrally managed MCP/agent configuration. <!-- SAF-TRACE: claims=SAF-T1206-C006; sources=SRC-t1206-ghsa-cursor,SRC-vscode-mcp-servers,SRC-t1206-copilot-cli -->
- **Secondary Vectors**: Prompt-injection-assisted file overwrite, a compromised configuration distribution path, or abuse of a legitimate administrative configuration interface. <!-- SAF-TRACE: claims=SAF-T1206-C006,SAF-T1206-C015; sources=SRC-t1206-ghsa-cursor,SRC-vscode-mcp-servers,SRC-t1206-ms-config-risk -->
- **Affected Components**: MCP clients and agent hosts that persist server definitions, credential references, headers, environment mappings, or client-registration state. <!-- SAF-TRACE: claims=SAF-T1206-C002,SAF-T1206-C003; sources=SRC-t1206-mcp-client-registration,SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->
- **Trust Boundary Crossed**: The boundary between authorized configuration administration and the client's later selection of an outbound authentication identity. <!-- SAF-TRACE: claims=SAF-T1206-C001; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->

## Technical Details

### Prerequisites

- The target must persist an MCP or agent configuration that influences authentication on later connections. <!-- SAF-TRACE: claims=SAF-T1206-C002,SAF-T1206-C005; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli,SRC-t1206-mcp-client-registration -->
- The adversary must obtain a write path to that configuration or to a trusted mechanism that produces it. <!-- SAF-TRACE: claims=SAF-T1206-C006; sources=SRC-t1206-ghsa-cursor,SRC-vscode-mcp-servers -->
- The implanted credential must be valid for the selected server and retain enough scope to provide useful access; compliant servers still validate issuer, audience, expiry, and scope. <!-- SAF-TRACE: claims=SAF-T1206-C004,SAF-T1206-C019; sources=SRC-mcp-authorization-2026-07-28,SRC-ms-azure-mcp-security-2026 -->

### Attack Flow

1. **Setup**: The adversary identifies a persistent client configuration and a credential-bearing field or reference that the client resolves. <!-- SAF-TRACE: claims=SAF-T1206-C002; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->
2. **Write**: The adversary creates or changes the configuration through an unauthorized file write, configuration API, or compromised distribution path. <!-- SAF-TRACE: claims=SAF-T1206-C006; sources=SRC-t1206-ghsa-cursor,SRC-ghsa-dive-66580,SRC-t1206-ms-config-risk -->
3. **Persist**: The modified record survives the current process and remains available to a later client or agent session. <!-- SAF-TRACE: claims=SAF-T1206-C005; sources=SRC-vscode-mcp-servers,SRC-t1206-copilot-cli -->
4. **Authenticate**: A later connection resolves the implanted material and presents the resulting credential to the configured server. <!-- SAF-TRACE: claims=SAF-T1206-C004,SAF-T1206-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-t1206-mcp-client-registration,SRC-t1206-copilot-cli -->
5. **Objective**: The agent operates through the attacker-selected identity until the configuration or credential is removed, rejected, expired, or rotated. <!-- SAF-TRACE: claims=SAF-T1206-C005,SAF-T1206-C017; sources=SRC-mcp-auth-security-2026-07-28,SRC-ms-azure-mcp-security-2026 -->
6. **Follow-On Activity**: Any later tool use is constrained by server-side authorization and the privileges carried by that identity. <!-- SAF-TRACE: claims=SAF-T1206-C004,SAF-T1206-C019; sources=SRC-mcp-authorization-2026-07-28,SRC-t1206-foundry-auth -->

### Example Scenario

An attacker-controlled write changes a workspace MCP entry so its authorization field references a placeholder secret owned by the attacker. A later agent start loads the persistent entry and connects using that identity; the synthetic value below is inert and demonstrates only the configuration shape. <!-- SAF-TRACE: claims=SAF-T1206-C001,SAF-T1206-C002,SAF-T1206-C005; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->

```json
{
  "servers": {
    "inventory": {
      "url": "https://mcp.invalid/example",
      "headers": { "Authorization": "Bearer ${env:SAF_SYNTHETIC_TOKEN}" }
    }
  }
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1206-C001 | Persistent credential selection can be attacker-directed after unauthorized configuration modification. | Research-Derived | SRC-t1206-vscode-config; SRC-t1206-copilot-cli; SRC-t1206-ghsa-cursor | Complete credential-implant sequence is inferred, not directly demonstrated. |
| SAF-T1206-C002 | MCP/agent configurations can hold credential-bearing headers, environment mappings, input references, or secret references. | Research-Derived | SRC-t1206-vscode-config; SRC-t1206-copilot-cli; SRC-t1206-foundry-auth | Implementations differ in storage and interpolation. |
| SAF-T1206-C003 | MCP supports static or persisted client credentials and requires issuer binding for persisted registration credentials. | Research-Derived | SRC-t1206-mcp-client-registration | Does not prescribe every client's storage format. |
| SAF-T1206-C004 | Servers must validate token audience; clients send bearer tokens on protected requests. | Research-Derived | SRC-mcp-authorization-2026-07-28; SRC-mcp-auth-security-2026-07-28 | Applies to conformant HTTP authorization implementations. |
| SAF-T1206-C005 | A persistent configuration implant can influence later authentication until removed or invalidated. | Research-Derived | SRC-vscode-mcp-servers; SRC-t1206-copilot-cli; SRC-t1206-mcp-client-registration | Inference from documented persistence and authentication behavior. |
| SAF-T1206-C006 | Unauthorized or compromised config-write paths are a prerequisite; Cursor exposed one such path on Windows. | Demonstrated | SRC-t1206-ghsa-cursor | Advisory demonstrates overwrite, not a credential implant. |
| SAF-T1206-C007 | Impact depends on the authority and tool access carried by the selected identity. | Research-Derived | SRC-t1206-foundry-auth; SRC-ms-azure-mcp-security-2026 | Deployment-specific privileges determine consequences. |
| SAF-T1206-C008 | CVE-2025-64107 allowed approval-bypassing overwrite of sensitive Cursor editor files on Windows before 2.0. | Demonstrated | SRC-t1206-ghsa-cursor; SRC-t1206-nvd-cursor | Requires prompt injection or malicious-model control; no credential implant shown. |
| SAF-T1206-C009 | CVE-2025-68433 used project MCP configuration for code execution in Zed before 0.218.2-pre. | Demonstrated | SRC-ghsa-zed-68433; SRC-zed-secure-default; SRC-t1206-nvd-zed | Adjacent configuration-execution behavior, not credential persistence. |
| SAF-T1206-C010 | CVE-2025-66580 used stored XSS to inject Dive MCP configuration and reach code execution before 0.11.1. | Demonstrated | SRC-ghsa-dive-66580; SRC-t1206-nvd-dive | Adjacent configuration injection with user interaction; no credential implant shown. |
| SAF-T1206-C011 | No direct production credential-implant case was found in the reviewed authoritative corpus through 2026-09-01. | Research-Derived | SRC-t1206-ms-config-risk; SRC-t1206-gtig-ai-threats; SRC-t1206-nvd-cursor; SRC-t1206-nvd-dive; SRC-t1206-nvd-zed | Narrow absence claim limited to recorded searches and sources. |
| SAF-T1206-C012 | File/config change telemetry correlated with later client authentication is a testable analytic for this behavior. | Research-Derived | SRC-t1206-vscode-config; SRC-t1206-copilot-cli; SRC-t1206-attack-t1098-001 | No public accuracy evaluation exists for this synthetic analytic. |
| SAF-T1206-C013 | Legitimate server onboarding and credential rotation can resemble an implant. | Research-Derived | SRC-vscode-mcp-servers; SRC-t1206-foundry-auth | Requires local change-control context to tune. |
| SAF-T1206-C014 | Encrypted stores, absent file auditing, and configuration APIs without change logs create detection blind spots. | Research-Derived | SRC-mcp-auth-security-2026-07-28; SRC-ms-azure-mcp-security-2026 | Product telemetry varies. |
| SAF-T1206-C015 | Trust review and configuration-integrity controls constrain unauthorized MCP configuration changes. | Research-Derived | SRC-vscode-mcp-servers; SRC-zed-secure-default | User approval does not protect already trusted or centrally modified paths. |
| SAF-T1206-C016 | Workload identity, secure storage, rotation, issuer binding, audience binding, and least privilege reduce exposure. | Research-Derived | SRC-mcp-auth-security-2026-07-28; SRC-t1206-mcp-client-registration; SRC-ms-azure-mcp-security-2026 | Availability depends on platform and server. |
| SAF-T1206-C017 | Response should remove the implant, invalidate affected credentials, and verify subsequent identity selection. | Research-Derived | SRC-mcp-auth-security-2026-07-28; SRC-ms-azure-mcp-security-2026 | Exact procedures are platform-specific. |
| SAF-T1206-C018 | ATT&CK T1098.001 is analogous because it adds adversary-controlled credentials for persistence. | Research-Derived | SRC-t1206-attack-t1098-001 | ATT&CK modifies account-side credentials, not client config. |
| SAF-T1206-C019 | Broad credential privileges and autonomous tool availability increase potential impact. | Research-Derived | SRC-t1206-foundry-auth; SRC-ms-azure-mcp-security-2026 | Does not establish a universal severity. |
| SAF-T1206-C020 | Credential theft and configuration execution are adjacent but distinct objectives. | Research-Derived | SRC-mcp-auth-security-2026-07-28; SRC-ghsa-zed-68433; SRC-ghsa-dive-66580 | SAF neighbor IDs are synthetic until integration. |
| SAF-T1206-C021 | Official records list proof-of-concept status for Dive, and no exploitation for the Cursor and Zed CVEs; none appeared in CISA KEV 2026.09.01. | Research-Derived | SRC-t1206-nvd-cursor; SRC-t1206-nvd-dive; SRC-t1206-nvd-zed; SRC-cisa-kev-2026-09-01 | Status can change after publication. |

### Current State

- **Affected Environments**: Clients or agent hosts that load persistent MCP configuration containing credential-bearing headers, environment mappings, secret references, or persisted registration state. <!-- SAF-TRACE: claims=SAF-T1206-C002,SAF-T1206-C003; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli,SRC-t1206-mcp-client-registration -->
- **Known Exploitation**: No direct production case was identified; the reviewed Cursor and Zed records reported no exploitation, while Dive reported proof-of-concept activity, and none of the three appeared in CISA KEV catalog version 2026.09.01. <!-- SAF-TRACE: claims=SAF-T1206-C011,SAF-T1206-C021; sources=SRC-t1206-nvd-cursor,SRC-t1206-nvd-dive,SRC-t1206-nvd-zed,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Configuration trust review, protected write paths, secure secret references, workload identities, credential rotation, issuer binding, audience validation, and least privilege. <!-- SAF-TRACE: claims=SAF-T1206-C015,SAF-T1206-C016; sources=SRC-vscode-mcp-servers,SRC-t1206-mcp-client-registration,SRC-mcp-auth-security-2026-07-28,SRC-ms-azure-mcp-security-2026 -->
- **Residual Risk**: Trusted or centrally distributed configuration changes can still persist, and controls may not expose the resolved identity or changes inside encrypted credential stores. <!-- SAF-TRACE: claims=SAF-T1206-C014,SAF-T1206-C015; sources=SRC-mcp-auth-security-2026-07-28,SRC-vscode-mcp-servers,SRC-ms-azure-mcp-security-2026 -->

### Known Breaches and Vulnerabilities

No qualifying direct production breach was identified. The following highest-impact qualifying vulnerabilities are ordered by relevance and explicitly remain enabling or adjacent evidence rather than proof of the complete technique. <!-- SAF-TRACE: claims=SAF-T1206-C011; sources=SRC-t1206-ms-config-risk,SRC-t1206-gtig-ai-threats,SRC-t1206-nvd-cursor,SRC-t1206-nvd-dive,SRC-t1206-nvd-zed -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-64107 / GHSA-2jr2-8wf5-v6pf | 2025-11-03; Cursor 1.7.52 and earlier on Windows | Sensitive editor files could be overwritten without approval after prompt injection or malicious-model control; fixed in 2.0. | Enabling vulnerability: supplies an unauthorized write path to `mcp.json`. <!-- SAF-TRACE: claims=SAF-T1206-C008,SAF-T1206-C021; sources=SRC-t1206-ghsa-cursor,SRC-t1206-nvd-cursor,SRC-cisa-kev-2026-09-01 --> | Reporter Philts demonstrated config protection bypass, not a credential implant; official status recorded no exploitation. |
| CVE-2025-66580 / GHSA-xv8m-365j-x6h2 | 2025-12-19; Dive through 0.11.0 | A click-triggered stored-XSS path could overwrite MCP server configuration and reach RCE; fixed in 0.11.1. | Adjacent vulnerability: demonstrates MCP configuration injection but pursues execution. <!-- SAF-TRACE: claims=SAF-T1206-C010,SAF-T1206-C021; sources=SRC-ghsa-dive-66580,SRC-t1206-nvd-dive,SRC-cisa-kev-2026-09-01 --> | Reporter c2an1's proof of concept did not implant authentication material; exploitation status was proof-of-concept. |
| CVE-2025-68433 / GHSA-cv6g-cmxc-vw8j | 2025-12-17; Zed before 0.218.2-pre | Project settings could auto-start a malicious MCP server with user privileges; worktree trust in 0.218.2-pre addressed the issue. | Adjacent vulnerability: shares the trusted persistent-config boundary but pursues execution. <!-- SAF-TRACE: claims=SAF-T1206-C009,SAF-T1206-C021; sources=SRC-ghsa-zed-68433,SRC-zed-secure-default,SRC-t1206-nvd-zed,SRC-cisa-kev-2026-09-01 --> | Aaron Portnoy of Mindgard demonstrated command execution, not credential persistence; official status recorded no exploitation. |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A later session can read data exposed to the implanted identity when its server tools and scopes permit retrieval. <!-- SAF-TRACE: claims=SAF-T1206-C007,SAF-T1206-C019; sources=SRC-t1206-foundry-auth,SRC-ms-azure-mcp-security-2026 --> |
| Integrity | High | The identity can invoke state-changing tools only to the extent its authorization and configured tool set allow. <!-- SAF-TRACE: claims=SAF-T1206-C007,SAF-T1206-C019; sources=SRC-t1206-foundry-auth,SRC-ms-azure-mcp-security-2026 --> |
| Availability | Medium | Disruption is conditional on destructive or administrative capabilities exposed to the identity; credential rejection may instead only break the connection. <!-- SAF-TRACE: claims=SAF-T1206-C004,SAF-T1206-C019; sources=SRC-mcp-authorization-2026-07-28,SRC-t1206-foundry-auth --> |
| Scope | Multi-System | A shared, synced, workspace, or centrally distributed configuration can affect more than one agent session, while local-only config limits blast radius. <!-- SAF-TRACE: claims=SAF-T1206-C005,SAF-T1206-C019; sources=SRC-vscode-mcp-servers,SRC-t1206-copilot-cli --> |

### Severity Conditions

- **Severity increases when**: Configuration is shared or synced, the implanted identity is long-lived and highly privileged, and tools run autonomously across sensitive services. <!-- SAF-TRACE: claims=SAF-T1206-C019; sources=SRC-vscode-mcp-servers,SRC-t1206-foundry-auth,SRC-ms-azure-mcp-security-2026 -->
- **Severity decreases when**: Write access is restricted, credentials are short-lived and audience-bound, secrets remain in protected stores, and tools or scopes are narrowly allowlisted. <!-- SAF-TRACE: claims=SAF-T1206-C016; sources=SRC-mcp-auth-security-2026-07-28,SRC-ms-azure-mcp-security-2026,SRC-t1206-copilot-cli -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| File or configuration audit | Create/modify credential-bearing MCP configuration | timestamp, actor, path/object, change type, changed key names, old/new value hashes, process, approval context | Collect user, workspace, and managed configuration paths; hash or redact secret values. <!-- SAF-TRACE: claims=SAF-T1206-C012,SAF-T1206-C014; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli,SRC-mcp-auth-security-2026-07-28 --> |
| MCP client and identity logs | Client start/reload followed by authentication | timestamp, host, workspace, server ID/URL, issuer, client ID or credential-reference fingerprint, result, scopes | Correlate with the preceding change while preserving credential confidentiality. <!-- SAF-TRACE: claims=SAF-T1206-C004,SAF-T1206-C012; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-security-2026-07-28,SRC-ms-azure-mcp-security-2026 --> |

### Indicators of Compromise (IoCs)

- An unapproved new credential-bearing header, environment key, client ID, secret reference, or token-provider reference in a known MCP configuration path. <!-- SAF-TRACE: claims=SAF-T1206-C002,SAF-T1206-C012; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->
- An authentication identity or issuer fingerprint that changes immediately after an unexplained configuration modification. <!-- SAF-TRACE: claims=SAF-T1206-C003,SAF-T1206-C012; sources=SRC-t1206-mcp-client-registration,SRC-mcp-authorization-2026-07-28 -->

### Behavioral Indicators

- A nonadministrative or agent-controlled process modifies a persistent MCP configuration and introduces a credential-bearing key. <!-- SAF-TRACE: claims=SAF-T1206-C006,SAF-T1206-C012; sources=SRC-t1206-ghsa-cursor,SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->
- A later client reload connects under a new issuer, client ID, or credential-reference fingerprint without a corresponding approved onboarding or rotation event. <!-- SAF-TRACE: claims=SAF-T1206-C012,SAF-T1206-C013; sources=SRC-t1206-mcp-client-registration,SRC-vscode-mcp-servers,SRC-t1206-foundry-auth -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Flag creates or modifications to known persistent MCP configuration paths when changed key names indicate authentication material or a credential reference. <!-- SAF-TRACE: claims=SAF-T1206-C012; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1206-C012; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->
- **Detection Logic**: Match a persistent MCP configuration suffix, a create/modify event, and a credential-bearing changed key; use a second-stage correlation with client authentication where available. <!-- SAF-TRACE: claims=SAF-T1206-C012; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli,SRC-mcp-authorization-2026-07-28 -->
- **Correlation Window**: Fifteen minutes is a starting operational window, not an evidence-backed universal threshold. <!-- SAF-TRACE: claims=SAF-T1206-C012; sources=SRC-vscode-mcp-servers,SRC-t1206-copilot-cli -->
- **Known False Positives**: Approved server onboarding, credential rotation, profile migration, and settings synchronization. <!-- SAF-TRACE: claims=SAF-T1206-C013; sources=SRC-vscode-mcp-servers,SRC-t1206-foundry-auth -->
- **Known Limitations**: The rule misses unlogged APIs, encrypted-store-only changes, unknown paths, and replacements whose key names appear benign. <!-- SAF-TRACE: claims=SAF-T1206-C014; sources=SRC-mcp-auth-security-2026-07-28,SRC-ms-azure-mcp-security-2026 -->
- **Tuning Guidance**: Maintain approved path, actor, issuer, and credential-reference baselines; suppress only changes tied to a verified change record. <!-- SAF-TRACE: claims=SAF-T1206-C012,SAF-T1206-C013; sources=SRC-t1206-attack-t1098-001,SRC-vscode-mcp-servers -->

### Validation

- **Test Data**: [test-events.json](../../tests/SAF-T1206/test-events.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1206/test_detection_rule.py)
- **Expected Result**: Eight deterministic cases pass: three malicious positives, one path-normalization boundary positive, three true negatives, and one expected legitimate lookalike that alerts. [quality-review.yml](../../research/techniques/SAF-T1206/quality-review.yml)
- **Last Validated**: 2026-09-01. [quality-review.yml](../../research/techniques/SAF-T1206/quality-review.yml)
- **Feasibility Waiver**: None. [quality-review.yml](../../research/techniques/SAF-T1206/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAF-M-45/README.md)**: Restrict writers, verify managed configuration provenance, and require explicit review when server or credential-bearing fields change. <!-- SAF-TRACE: claims=SAF-T1206-C015; sources=SRC-vscode-mcp-servers,SRC-zed-secure-default -->
2. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Prefer workload identities or protected secret references over plaintext, and keep tokens short-lived, issuer-bound, audience-bound, and least-privileged. <!-- SAF-TRACE: claims=SAF-T1206-C016; sources=SRC-t1206-mcp-client-registration,SRC-mcp-auth-security-2026-07-28,SRC-ms-azure-mcp-security-2026 -->
3. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Record actor, path, changed key names, approval context, and later authentication identity without logging secret values. <!-- SAF-TRACE: claims=SAF-T1206-C012,SAF-T1206-C014; sources=SRC-mcp-auth-security-2026-07-28,SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Alert on new or changed authentication keys in persistent MCP configuration and correlate with client reloads. <!-- SAF-TRACE: claims=SAF-T1206-C012; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli -->
2. **[SAF-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAF-M-45/README.md)**: Compare configuration provenance and value fingerprints against approved baselines before trusting a server. <!-- SAF-TRACE: claims=SAF-T1206-C013,SAF-T1206-C015; sources=SRC-vscode-mcp-servers,SRC-zed-secure-default -->

### Response Procedures

#### Immediate Actions

- Stop or isolate affected agent sessions, disable the suspect server entry, and prevent further configuration distribution. <!-- SAF-TRACE: claims=SAF-T1206-C017; sources=SRC-vscode-mcp-servers,SRC-ms-azure-mcp-security-2026 -->
- Revoke or rotate the implanted and potentially exposed credentials, preserving only redacted identifiers and hashes for investigation. <!-- SAF-TRACE: claims=SAF-T1206-C016,SAF-T1206-C017; sources=SRC-mcp-auth-security-2026-07-28,SRC-ms-azure-mcp-security-2026 -->

#### Investigation Steps

- Preserve configuration change records, client reload events, resolved issuer/client identifiers, approval context, and subsequent tool activity. <!-- SAF-TRACE: claims=SAF-T1206-C012,SAF-T1206-C014; sources=SRC-mcp-authorization-2026-07-28,SRC-vscode-mcp-servers,SRC-ms-azure-mcp-security-2026 -->
- Determine the first unauthorized writer, every distribution or synchronization target, and the privileges exercised through the implanted identity. <!-- SAF-TRACE: claims=SAF-T1206-C019; sources=SRC-vscode-mcp-servers,SRC-t1206-foundry-auth -->

#### Remediation

- Restore configuration from an approved source, remove unauthorized credential references, and validate issuer, audience, scope, and identity on a fresh connection. <!-- SAF-TRACE: claims=SAF-T1206-C004,SAF-T1206-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-t1206-mcp-client-registration,SRC-ms-azure-mcp-security-2026 -->
- Close the write path, re-evaluate trust decisions, and add the observed key and path pattern to regression tests and monitoring. <!-- SAF-TRACE: claims=SAF-T1206-C012,SAF-T1206-C015; sources=SRC-vscode-mcp-servers,SRC-zed-secure-default -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1502: File-Based Credential Harvest](../SAF-T1502/README.md) | Prerequisite or co-occurring | Copies an existing credential; SAF-T1206 persists an attacker-selected credential or reference in client configuration. <!-- SAF-TRACE: claims=SAF-T1206-C020; sources=SRC-mcp-auth-security-2026-07-28,SRC-t1206-mcp-client-registration --> |
| [SAF-T1006: Malicious MCP Server Distribution](../SAF-T1006/README.md) | Overlapping delivery artifact | Uses configuration to deliver and execute a malicious server; SAF-T1206's immediate objective is future authentication identity selection. <!-- SAF-TRACE: claims=SAF-T1206-C009,SAF-T1206-C010,SAF-T1206-C020; sources=SRC-ghsa-zed-68433,SRC-ghsa-dive-66580 --> |
| [SAF-T1407: Server Proxy Masquerade](../SAF-T1407/README.md) | Co-occurring | Changes the apparent connection identity; SAF-T1206 requires a credential or credential reference implant even when the endpoint also changes. <!-- SAF-TRACE: claims=SAF-T1206-C001; sources=SRC-t1206-vscode-config,SRC-t1206-copilot-cli --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Additional Cloud Credentials | Analogous | Both preserve access by introducing adversary-controlled credentials, but ATT&CK changes account-side credentials whereas SAF-T1206 changes an MCP/agent client's persistent credential selection. <!-- SAF-TRACE: claims=SAF-T1206-C018; sources=SRC-t1206-attack-t1098-001 --> |

## References

1. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization, revision 2026-07-28 — Model Context Protocol maintainers](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — bearer-token use, audience validation, and refresh-token handling.
2. **SRC-mcp-auth-security-2026-07-28**: [MCP Authorization Security Considerations — Model Context Protocol maintainers](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) — token theft, storage, audience binding, and redirect protections.
3. **SRC-t1206-mcp-client-registration**: [MCP Client Registration — Model Context Protocol maintainers](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration) — static credentials, persistence, and authorization-server binding.
4. **SRC-t1206-vscode-config**: [MCP configuration reference — Microsoft VS Code documentation team](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) — configuration locations, credential inputs, environment mappings, and reset commands.
5. **SRC-vscode-mcp-servers**: [Add and manage MCP servers in VS Code — Microsoft VS Code documentation team, 2026-08-26](https://code.visualstudio.com/docs/agent-customization/mcp-servers) — trust review, configuration scope, synchronization, and restart behavior.
6. **SRC-t1206-copilot-cli**: [GitHub Copilot CLI command reference — GitHub Docs team](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference) — MCP config priority, persistent locations, environment/header fields, and trust levels.
7. **SRC-t1206-foundry-auth**: [Set up authentication for MCP tools — Microsoft Foundry documentation team](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/mcp-authentication) — shared and individual identities, secret references, token handling, and least privilege.
8. **SRC-ms-azure-mcp-security-2026**: [Secure your Azure MCP Server deployment — Microsoft Azure MCP Server documentation team](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) — workload identity, vault references, audience checks, rotation, and credential isolation.
9. **SRC-t1206-ghsa-cursor**: [GHSA-2jr2-8wf5-v6pf — hmwildermuth; reporter Philts, 2025-11-03](https://github.com/cursor/cursor/security/advisories/GHSA-2jr2-8wf5-v6pf) — Windows config-protection bypass and remediation.
10. **SRC-t1206-nvd-cursor**: [NVD CVE-2025-64107 — NIST NVD with GitHub CNA and CISA ADP data](https://nvd.nist.gov/vuln/detail/CVE-2025-64107) — affected range and exploitation status.
11. **SRC-ghsa-dive-66580**: [GHSA-xv8m-365j-x6h2 — ckaznable; reporter c2an1, 2025-12-19](https://github.com/OpenAgentPlatform/Dive/security/advisories/GHSA-xv8m-365j-x6h2) — stored XSS to MCP configuration injection and RCE.
12. **SRC-t1206-nvd-dive**: [NVD CVE-2025-66580 — NIST NVD with GitHub CNA and CISA ADP data](https://nvd.nist.gov/vuln/detail/CVE-2025-66580) — affected range, fixed version, and proof-of-concept status.
13. **SRC-ghsa-zed-68433**: [GHSA-cv6g-cmxc-vw8j — Zed security team; Aaron Portnoy, Mindgard, 2025-12-17](https://github.com/zed-industries/zed/security/advisories/GHSA-cv6g-cmxc-vw8j) — project MCP configuration execution and affected versions.
14. **SRC-zed-secure-default**: [Zed Moves Toward Secure-by-Default — John Swanson and Kirill Bulatov, 2025-12-17](https://zed.dev/blog/secure-by-default) — worktree-trust remediation and disclosure credit.
15. **SRC-t1206-nvd-zed**: [NVD CVE-2025-68433 — NIST NVD with GitHub CNA and CISA ADP data](https://nvd.nist.gov/vuln/detail/CVE-2025-68433) — affected range, fixed version, and exploitation status.
16. **SRC-cisa-kev-2026-09-01**: [Known Exploited Vulnerabilities Catalog version 2026.09.01 — CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — current catalog cross-check for selected CVEs.
17. **SRC-t1206-attack-t1098-001**: [ATT&CK T1098.001 Additional Cloud Credentials v2.8 — MITRE ATT&CK contributors, 2025-10-24](https://attack.mitre.org/techniques/T1098/001/) — analogous credential-addition persistence and detection concept.
18. **SRC-t1206-ms-config-risk**: [When configuration becomes a vulnerability — Microsoft Defender Security Research Team and Yossi Weizman, 2026-05-14](https://www.microsoft.com/en-us/security/blog/2026/05/14/configuration-becomes-vulnerability-exploitable-misconfigurations-ai-apps/) — observed agentic misconfiguration abuse, used to bound rather than establish this technique.
19. **SRC-t1206-gtig-ai-threats**: [GTIG AI Threat Tracker — Google Threat Intelligence Group, 2026-05-12](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access/) — current agentic threat reporting, used to test for and reject adjacent incidents.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft, evidence packet, and tested detection analytic. | OpenAI Codex clean-room agent `/root/cleanroom_saf_t1206` |
