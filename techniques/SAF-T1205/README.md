# SAF-T1205: Persistent Tool Redefinition

## Overview

- **Tactic**: Persistence (ATK-TA0003)
- **Technique ID**: SAF-T1205
- **Research Packet**: [research/techniques/SAF-T1205](../../research/techniques/SAF-T1205/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1205/traceability-ledger.yml)
- **Lifecycle Status**: Deprecated. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)
- **Documentation Status**: Deprecated
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A retained trust decision can expose sensitive data or privileged tools to a changed definition; reapproval, least privilege, and isolation reduce that impact. <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 -->
- **First Observed**: Not observed in production; directly reproduced in controlled research published in 2025. <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 -->
- **Last Updated**: 2026-09-02

> **Deprecated compatibility ID:** SAF-T1205 is consolidated into [SAF-T1201: Post-Approval Tool Mutation](../SAF-T1201/README.md). This page and its evidence packet remain available for provenance; use SAF-T1201 for new mappings. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)

## Scope

Persistent Tool Redefinition is a post-trust change to security-relevant MCP tool metadata, schema, or behavior that remains available under the apparent server/tool relationship without a fresh security decision. <!-- SAF-TRACE: claims=SAF-T1205-C002,SAF-T1205-C003,SAF-T1205-C005; sources=SRC-mcp-tools-2025-11-25,SRC-song-mcp-attack-v4,SRC-ms-indirect-injection-2025 -->

### In Scope

- A previously accepted server or tool later presents a materially different definition under the same trusted relationship. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C005; sources=SRC-song-mcp-attack-v4,SRC-ms-indirect-injection-2025 -->
- The host accepts that changed definition without approval tied to the current definition, preserving influence over later interactions. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C007; sources=SRC-ms-azure-mcp-security-2026,SRC-ms-visual-studio-mcp-2026 -->

### Out of Scope

- Malicious metadata present on first discovery, unauthorized registration of a different server, or ordinary evolution approved before use. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C006; sources=SRC-song-mcp-attack-v4,SRC-ms-azure-mcp-security-2026 -->
- Prompt injection, command execution, collection, or exfiltration after the changed definition is accepted; those are downstream behaviors. <!-- SAF-TRACE: claims=SAF-T1205-C004,SAF-T1205-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-rug-pull-catalog-2026 -->

### Distinguishing Characteristics

The necessary sequence is benign or approved state, security-relevant change, retained apparent identity, and no matching reapproval. This separates the technique from initial poisoning, server-identity replacement, and unauthorized invocation. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C010,SAF-T1205-C014; sources=SRC-song-mcp-attack-v4,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-ms-rug-pull-catalog-2026 -->

## Description

MCP tools are model-controlled capabilities. A definition can include a name, description, input and output schemas, annotations, and execution metadata; clients discover definitions with `tools/list`, and a capable server can announce later list changes. <!-- SAF-TRACE: claims=SAF-T1205-C001,SAF-T1205-C002; sources=SRC-mcp-tools-2025-11-25 -->

The technique abuses the gap between this legitimate mutability and the host's approval state. A server, update channel, or referenced package first earns trust in a benign state and later substitutes a security-relevant definition. The immediate objective is continued influence under the earlier trust decision, not any particular downstream action. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C005; sources=SRC-song-mcp-attack-v4,SRC-ms-indirect-injection-2025 -->

Song and eight coauthors reproduced the temporal step on three MCP aggregators: they registered benign repositories, later replaced the content with malicious server code, and observed unchanged listing status and continued accessibility for seven days. The controlled work affected no production users and did not separately measure the downstream phase. <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 -->

## Attack Vectors

- **Primary Vector**: An attacker-controlled update path changes a previously accepted tool or server definition. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C005; sources=SRC-song-mcp-attack-v4,SRC-ms-indirect-injection-2025 -->
- **Secondary Vectors**: A protocol change notification refreshes the tool list, or a mutable registry/package reference resolves to changed server content. <!-- SAF-TRACE: claims=SAF-T1205-C002,SAF-T1205-C003; sources=SRC-mcp-tools-2025-11-25,SRC-song-mcp-attack-v4 -->
- **Affected Components**: MCP hosts and clients, servers, tool definitions, approval stores, registries, and update channels. <!-- SAF-TRACE: claims=SAF-T1205-C001,SAF-T1205-C003,SAF-T1205-C007; sources=SRC-mcp-tools-2025-11-25,SRC-song-mcp-attack-v4,SRC-ms-visual-studio-mcp-2026 -->
- **Trust Boundary Crossed**: The boundary between the definition that was approved and the definition later presented for use. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C010; sources=SRC-ms-azure-mcp-security-2026,SRC-ms-visual-studio-mcp-2026,SRC-azure-appservice-mcp-2026 -->

## Technical Details

### Prerequisites

- The adversary can alter the server, its tool-list response, or an update/reference path after the initial trust decision. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C005; sources=SRC-song-mcp-attack-v4,SRC-ms-indirect-injection-2025 -->
- The host lacks an approval bound to the normalized current definition, or a user or policy bypasses reapproval. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C007,SAF-T1205-C010; sources=SRC-ms-azure-mcp-security-2026,SRC-ms-visual-studio-mcp-2026,SRC-azure-appservice-mcp-2026 -->

### Attack Flow

1. **Setup**: Publish or operate a benign definition and obtain listing, trust, or approval. <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 -->
2. **Redefinition**: Change security-relevant definition fields or referenced implementation content. <!-- SAF-TRACE: claims=SAF-T1205-C001,SAF-T1205-C003; sources=SRC-mcp-tools-2025-11-25,SRC-song-mcp-attack-v4 -->
3. **Refresh**: The client refetches, receives a list-change event, or resolves the mutable reference. <!-- SAF-TRACE: claims=SAF-T1205-C002,SAF-T1205-C007; sources=SRC-mcp-tools-2025-11-25,SRC-ms-visual-studio-mcp-2026 -->
4. **Boundary Crossing**: The changed definition becomes usable without approval for its current normalized hash. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C010; sources=SRC-ms-azure-mcp-security-2026,SRC-ms-visual-studio-mcp-2026,SRC-azure-appservice-mcp-2026 -->
5. **Objective**: Preserve influence over later model selection or tool invocation under the earlier trust decision. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C005; sources=SRC-song-mcp-attack-v4,SRC-ms-indirect-injection-2025 -->
6. **Follow-On Activity**: Any later data access or manipulation is classified separately and must be established from invocation evidence. <!-- SAF-TRACE: claims=SAF-T1205-C004,SAF-T1205-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-rug-pull-catalog-2026 -->

### Example Scenario

An approved server at `mcp.example.invalid` changes only a tool description while retaining its identity; the host records a new hash but no approval for that hash. This inert example illustrates the analytic boundary without an exploit payload. <!-- SAF-TRACE: claims=SAF-T1205-C010,SAF-T1205-C011; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-mcp-tools-2025-11-25 -->

```json
{"event":"tools/list_changed","server_id":"mcp.example.invalid","tool":"lookup","current_hash":"b2","approved_hash":"a1","approval_for_current":false}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source | Limitation |
| --- | --- | --- | --- | --- |
| SAF-T1205-C001 | Tool definitions are model-facing structured capabilities. | Research-Derived | SRC-mcp-tools-2025-11-25 | Approval UI is not universal. |
| SAF-T1205-C002 | Tool discovery supports list-change notification. | Research-Derived | SRC-mcp-tools-2025-11-25 | Reapproval is not mandated. |
| SAF-T1205-C003 | Controlled research reproduced post-listing replacement under unchanged listing status. | Demonstrated | SRC-song-mcp-attack-v4 | No production users were affected. |
| SAF-T1205-C004 | An adjacent poisoned-description experiment caused sensitive-file transmission. | Demonstrated | SRC-invariant-tpa-2025-04-01 | The experiment did not reproduce the temporal step. |
| SAF-T1205-C005 | Microsoft describes dynamic post-approval amendment and bounded consequences. | Research-Derived | SRC-ms-indirect-injection-2025 | Guidance, not an incident report. |
| SAF-T1205-C006 | Azure guidance recommends pinning and reapproval. | Research-Derived | SRC-ms-azure-mcp-security-2026 | Adoption is product-specific. |
| SAF-T1205-C007 | Visual Studio resets permissions and refetches changed tools. | Research-Derived | SRC-ms-visual-studio-mcp-2026 | Bypass choices remain. |
| SAF-T1205-C008 | Azure App Service hashes recomputed tool lists before notification. | Research-Derived | SRC-azure-appservice-mcp-2026 | Preview implementation, not a client decision. |
| SAF-T1205-C009 | Google recommends proxy audit fields and fingerprints. | Research-Derived | SRC-google-mcp-security-2025 | Reference architecture, not protocol mandate. |
| SAF-T1205-C010 | Hash-versus-approved-baseline correlation is testable. | Research-Derived | SRC-azure-appservice-mcp-2026; SRC-ms-visual-studio-mcp-2026; SRC-ms-azure-mcp-security-2026 | Detects change, not intent. |
| SAF-T1205-C011 | Legitimate change and unstable identity/canonicalization bound detection. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-azure-appservice-mcp-2026 | Frequency is deployment-specific. |
| SAF-T1205-C012 | CVE-2025-64443 enabled browser-based tool manipulation in affected Docker gateway modes. | Research-Derived | SRC-docker-ghsa-46gc-2025; SRC-nvd-cve-2025-64443 | Enabling vulnerability only. |
| SAF-T1205-C013 | ATT&CK T1554 is a host-binary persistence analog. | Research-Derived | SRC-mitre-t1554 | Not a direct mapping. |
| SAF-T1205-C014 | Microsoft's catalog maps adjacent AI behaviors and notes no dedicated ATLAS entry. | Research-Derived | SRC-ms-rug-pull-catalog-2026 | Mappings may evolve. |
| SAF-T1205-C015 | Disable, preserve, compare, reapprove, and investigate is a defensible response sequence. | Research-Derived | SRC-ms-visual-studio-mcp-2026; SRC-google-mcp-security-2025; SRC-ms-azure-mcp-security-2026 | Rotation depends on exposure evidence. |
| SAF-T1205-C016 | Conditional confidentiality and integrity impact can be high. | Research-Derived | SRC-invariant-tpa-2025-04-01; SRC-ms-indirect-injection-2025; SRC-ms-azure-mcp-security-2026 | No production loss data. |

### Current State

- **Affected Environments**: Deployments that allow mutable tool discovery or mutable package/registry references after a trust decision. <!-- SAF-TRACE: claims=SAF-T1205-C002,SAF-T1205-C003; sources=SRC-mcp-tools-2025-11-25,SRC-song-mcp-attack-v4 -->
- **Known Exploitation**: One controlled direct demonstration was found; no qualifying production incident was verified. <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 -->
- **Available Protections**: Pin definitions, compare normalized hashes, reset permissions, and require reapproval after relevant changes. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C007,SAF-T1205-C008; sources=SRC-ms-azure-mcp-security-2026,SRC-ms-visual-studio-mcp-2026,SRC-azure-appservice-mcp-2026 -->
- **Residual Risk**: Always-trust choices, mutable external references, missing baselines, and weak identity binding can preserve the gap. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C007,SAF-T1205-C011; sources=SRC-song-mcp-attack-v4,SRC-ms-visual-studio-mcp-2026,SRC-mcp-tools-2025-11-25,SRC-azure-appservice-mcp-2026 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Song et al. RQ1 Test 2 <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 --> | 2025; Smithery, MCP.so, and Glama controlled listings <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 --> | Unchanged status after replacement; repositories removed after seven days <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 --> | Direct controlled demonstration <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 --> | No users affected; downstream harm not retested <!-- SAF-TRACE: claims=SAF-T1205-C003; sources=SRC-song-mcp-attack-v4 --> |
| Invariant Cursor experiment <!-- SAF-TRACE: claims=SAF-T1205-C004; sources=SRC-invariant-tpa-2025-04-01 --> | 2025; controlled Cursor environment <!-- SAF-TRACE: claims=SAF-T1205-C004; sources=SRC-invariant-tpa-2025-04-01 --> | Sensitive-file access and transmission; pin/hash definitions <!-- SAF-TRACE: claims=SAF-T1205-C004; sources=SRC-invariant-tpa-2025-04-01 --> | Adjacent impact demonstration <!-- SAF-TRACE: claims=SAF-T1205-C004; sources=SRC-invariant-tpa-2025-04-01 --> | Did not perform post-approval replacement <!-- SAF-TRACE: claims=SAF-T1205-C004; sources=SRC-invariant-tpa-2025-04-01 --> |
| CVE-2025-64443 / GHSA-46gc-mwh4-cc5r <!-- SAF-TRACE: claims=SAF-T1205-C012; sources=SRC-docker-ghsa-46gc-2025,SRC-nvd-cve-2025-64443 --> | Docker MCP Gateway through 0.27.0 in SSE/streaming mode <!-- SAF-TRACE: claims=SAF-T1205-C012; sources=SRC-docker-ghsa-46gc-2025,SRC-nvd-cve-2025-64443 --> | Browser-based tool manipulation; fixed in 0.28.0, with stdio workaround <!-- SAF-TRACE: claims=SAF-T1205-C012; sources=SRC-docker-ghsa-46gc-2025 --> | Enabling vulnerability <!-- SAF-TRACE: claims=SAF-T1205-C012; sources=SRC-docker-ghsa-46gc-2025,SRC-nvd-cve-2025-64443 --> | No CISA-observed exploitation; does not establish retained trust <!-- SAF-TRACE: claims=SAF-T1205-C012; sources=SRC-nvd-cve-2025-64443,SRC-docker-ghsa-46gc-2025 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> | High <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> | Requires reachable sensitive data and a capable downstream tool path. <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> |
| Integrity <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> | High <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> | Requires privileged tool access or consequential model decisions. <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> |
| Availability <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> | Low <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> | Availability harm was not established by the reviewed direct demonstration. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C016; sources=SRC-song-mcp-attack-v4,SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> |
| Scope <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C016; sources=SRC-song-mcp-attack-v4,SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> | Multi-System <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C016; sources=SRC-song-mcp-attack-v4,SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> | A shared listing or server can reach multiple clients, bounded by each client's trust and privileges. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C016; sources=SRC-song-mcp-attack-v4,SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 --> |

### Severity Conditions

- **Severity increases when**: The agent has broad data access, privileged tools, unattended execution, or shared downstream consumers. <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 -->
- **Severity decreases when**: The host binds approval to a current definition, applies least privilege and isolation, and blocks use until reapproval. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C007,SAF-T1205-C016; sources=SRC-ms-azure-mcp-security-2026,SRC-ms-visual-studio-mcp-2026,SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025 -->

## Detection Methods

### Required Telemetry

| Source | Events | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP discovery and approval logs <!-- SAF-TRACE: claims=SAF-T1205-C008,SAF-T1205-C009,SAF-T1205-C010; sources=SRC-azure-appservice-mcp-2026,SRC-google-mcp-security-2025,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 --> | `tools/list`, list change, trust, and approval <!-- SAF-TRACE: claims=SAF-T1205-C002,SAF-T1205-C007; sources=SRC-mcp-tools-2025-11-25,SRC-ms-visual-studio-mcp-2026 --> | Time, server identity, tool, normalized current hash, approved hash, approval status <!-- SAF-TRACE: claims=SAF-T1205-C008,SAF-T1205-C009,SAF-T1205-C010; sources=SRC-azure-appservice-mcp-2026,SRC-google-mcp-security-2025,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 --> | Canonicalize security-relevant fields and retain approval history. <!-- SAF-TRACE: claims=SAF-T1205-C010,SAF-T1205-C011; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-mcp-tools-2025-11-25 --> |
| Invocation or proxy logs <!-- SAF-TRACE: claims=SAF-T1205-C009,SAF-T1205-C015; sources=SRC-google-mcp-security-2025,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 --> | Tool calls after definition change <!-- SAF-TRACE: claims=SAF-T1205-C009,SAF-T1205-C015; sources=SRC-google-mcp-security-2025,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 --> | Agent, session, server, tool, payload fingerprint, result <!-- SAF-TRACE: claims=SAF-T1205-C009; sources=SRC-google-mcp-security-2025 --> | Correlate calls only after a suspicious change and protect sensitive payloads. <!-- SAF-TRACE: claims=SAF-T1205-C009,SAF-T1205-C015; sources=SRC-google-mcp-security-2025,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 --> |

### Indicators of Compromise (IoCs)

- None known: a definition-hash change is behavioral evidence and may be a legitimate update, not a durable compromise artifact. <!-- SAF-TRACE: claims=SAF-T1205-C011; sources=SRC-mcp-tools-2025-11-25,SRC-azure-appservice-mcp-2026 -->

### Behavioral Indicators

- A known server/tool identity presents a normalized definition hash different from the approved hash. <!-- SAF-TRACE: claims=SAF-T1205-C008,SAF-T1205-C010; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 -->
- The changed definition becomes enabled or invoked without an approval event bound to the current hash. <!-- SAF-TRACE: claims=SAF-T1205-C007,SAF-T1205-C010; sources=SRC-ms-visual-studio-mcp-2026,SRC-azure-appservice-mcp-2026,SRC-ms-azure-mcp-security-2026 -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect a definition mismatch that lacks matching current approval. <!-- SAF-TRACE: claims=SAF-T1205-C010; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1205-C010,SAF-T1205-C011; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-mcp-tools-2025-11-25 -->
- **Detection Logic**: Match a stable server/tool identity where current and approved hashes differ and current-hash approval is false. <!-- SAF-TRACE: claims=SAF-T1205-C010; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 -->
- **Correlation Window**: Evaluate at every discovery refresh and retain history through later invocations. <!-- SAF-TRACE: claims=SAF-T1205-C002,SAF-T1205-C009,SAF-T1205-C015; sources=SRC-mcp-tools-2025-11-25,SRC-google-mcp-security-2025,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 -->
- **Known False Positives**: Approved hot reloads, planned schema changes, and hash changes caused by inconsistent canonicalization. <!-- SAF-TRACE: claims=SAF-T1205-C011; sources=SRC-mcp-tools-2025-11-25,SRC-azure-appservice-mcp-2026 -->
- **Known Limitations**: Missing baselines, unstable identities, or semantic behavior changes outside hashed fields defeat the analytic. <!-- SAF-TRACE: claims=SAF-T1205-C011; sources=SRC-mcp-tools-2025-11-25,SRC-azure-appservice-mcp-2026 -->
- **Tuning Guidance**: Normalize only security-relevant fields, bind approval to the normalized hash, and allowlist an update only after review. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C010,SAF-T1205-C011; sources=SRC-ms-azure-mcp-security-2026,SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-mcp-tools-2025-11-25 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Two positive and five negative/boundary cases pass. <!-- SAF-TRACE: claims=SAF-T1205-C010,SAF-T1205-C011; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-mcp-tools-2025-11-25 -->
- **Last Validated**: 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1205-C010,SAF-T1205-C011; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-mcp-tools-2025-11-25 -->
- **Feasibility Waiver**: None; synthetic cases exercise positive, negative, malformed, boundary, and legitimate-change behavior. <!-- SAF-TRACE: claims=SAF-T1205-C010,SAF-T1205-C011; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-mcp-tools-2025-11-25 -->

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-2: Cryptographic Integrity for Tool Descriptions](../../mitigations/SAF-M-2/README.md)**: Pin a reviewed normalized definition hash and block changed definitions until reapproval. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C010; sources=SRC-ms-azure-mcp-security-2026,SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026 -->
2. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Constrain tools, credentials, filesystem, and network reach so a changed definition has less downstream authority. <!-- SAF-TRACE: claims=SAF-T1205-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-indirect-injection-2025,SRC-ms-azure-mcp-security-2026 -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Centralize discovery, approval, and invocation logs with identity and signature fingerprints. <!-- SAF-TRACE: claims=SAF-T1205-C009,SAF-T1205-C010; sources=SRC-google-mcp-security-2025,SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 -->

### Response Procedures

#### Immediate Actions

- Disable the changed tool, preserve discovery and approval state, and prevent invocation pending review. <!-- SAF-TRACE: claims=SAF-T1205-C015; sources=SRC-ms-visual-studio-mcp-2026,SRC-google-mcp-security-2025,SRC-ms-azure-mcp-security-2026 -->

#### Investigation Steps

- Compare the changed definition with the approved baseline and correlate calls made after the first mismatch. <!-- SAF-TRACE: claims=SAF-T1205-C009,SAF-T1205-C015; sources=SRC-google-mcp-security-2025,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026 -->

#### Remediation

- Restore a reviewed definition, issue a fresh approval, and rotate credentials only when the investigation finds plausible exposure. <!-- SAF-TRACE: claims=SAF-T1205-C006,SAF-T1205-C015; sources=SRC-ms-azure-mcp-security-2026,SRC-ms-visual-studio-mcp-2026,SRC-google-mcp-security-2025 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md) <!-- SAF-TRACE: claims=SAF-T1205-C004,SAF-T1205-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-rug-pull-catalog-2026 --> | Alternative <!-- SAF-TRACE: claims=SAF-T1205-C004; sources=SRC-invariant-tpa-2025-04-01 --> | Malicious on first discovery rather than changed after trust. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C004; sources=SRC-song-mcp-attack-v4,SRC-invariant-tpa-2025-04-01 --> |
| [SAF-T1201: Post-Approval Tool Mutation](../SAF-T1201/README.md) <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C014; sources=SRC-song-mcp-attack-v4,SRC-ms-rug-pull-catalog-2026 --> | Broader umbrella <!-- SAF-TRACE: claims=SAF-T1205-C014; sources=SRC-ms-rug-pull-catalog-2026 --> | Rug pull also covers changed delivered implementation or update content; SAF-T1205 is restricted to a security-relevant tool-definition mutation retained across later sessions or invocations. <!-- SAF-TRACE: claims=SAF-T1205-C003,SAF-T1205-C014; sources=SRC-song-mcp-attack-v4,SRC-ms-rug-pull-catalog-2026 --> |
| [SAF-T1407: Server Proxy Masquerade](../SAF-T1407/README.md) <!-- SAF-TRACE: claims=SAF-T1205-C010,SAF-T1205-C011; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-mcp-tools-2025-11-25 --> | Alternative <!-- SAF-TRACE: claims=SAF-T1205-C011; sources=SRC-mcp-tools-2025-11-25,SRC-azure-appservice-mcp-2026 --> | Changes the trusted identity instead of retaining it. <!-- SAF-TRACE: claims=SAF-T1205-C010,SAF-T1205-C011; sources=SRC-azure-appservice-mcp-2026,SRC-ms-visual-studio-mcp-2026,SRC-ms-azure-mcp-security-2026,SRC-mcp-tools-2025-11-25 --> |
| [SAF-T1103: Fake Tool Invocation (Function Spoofing)](../SAF-T1103/README.md) <!-- SAF-TRACE: claims=SAF-T1205-C014; sources=SRC-ms-rug-pull-catalog-2026 --> | Follow-On <!-- SAF-TRACE: claims=SAF-T1205-C014; sources=SRC-ms-rug-pull-catalog-2026 --> | Concerns a call decision, not mutation of the definition that informs it. <!-- SAF-TRACE: claims=SAF-T1205-C014; sources=SRC-ms-rug-pull-catalog-2026 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1554](https://attack.mitre.org/techniques/T1554/) <!-- SAF-TRACE: claims=SAF-T1205-C013; sources=SRC-mitre-t1554 --> | Compromise Host Software Binary <!-- SAF-TRACE: claims=SAF-T1205-C013; sources=SRC-mitre-t1554 --> | Analogous <!-- SAF-TRACE: claims=SAF-T1205-C013; sources=SRC-mitre-t1554 --> | Both preserve access by changing an already trusted artifact, but tool metadata is not a host binary. <!-- SAF-TRACE: claims=SAF-T1205-C013; sources=SRC-mitre-t1554 --> |

### Additional Framework Mappings

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| MITRE ATLAS <!-- SAF-TRACE: claims=SAF-T1205-C014; sources=SRC-ms-rug-pull-catalog-2026 --> | AML.T0010.005, AML.T0051.001, AML.T0053, AML.T0110 <!-- SAF-TRACE: claims=SAF-T1205-C014; sources=SRC-ms-rug-pull-catalog-2026 --> | Closest-fit supply-chain, prompt-injection, tool-invocation, and tool-poisoning mappings <!-- SAF-TRACE: claims=SAF-T1205-C014; sources=SRC-ms-rug-pull-catalog-2026 --> | Microsoft's catalog notes that ATLAS has no dedicated rug-pull technique. <!-- SAF-TRACE: claims=SAF-T1205-C014; sources=SRC-ms-rug-pull-catalog-2026 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — model control, definition fields, discovery, notifications, and security considerations.
2. **SRC-song-mcp-attack-v4**: [Song, Shen, Luo, Guo, Chen, Wang, Li, Zhang, and Chen, “Beyond the Protocol” v4](https://arxiv.org/html/2506.02040v4) — direct controlled post-listing mutation experiment.
3. **SRC-invariant-tpa-2025-04-01**: [Luca Beurer-Kellner and Marc Fischer, “MCP Security Notification”](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — adjacent Cursor experiment and rug-pull discussion.
4. **SRC-ms-indirect-injection-2025**: [Sarah Young and Den Delimarsky, “Protecting against indirect prompt injection attacks in MCP”](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/) — dynamic-amendment guidance.
5. **SRC-ms-azure-mcp-security-2026**: [Microsoft, “Secure your Azure MCP Server deployment”](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) — pinning, reapproval, isolation, and monitoring.
6. **SRC-google-mcp-security-2025**: [Lanre Ogunmola and Biodun Awojobi, “How to secure your remote MCP server on Google Cloud”](https://cloud.google.com/blog/products/identity-security/how-to-secure-your-remote-mcp-server-on-google-cloud/) — proxy logging and audit fields.
7. **SRC-ms-visual-studio-mcp-2026**: [Microsoft, “Use MCP servers in Visual Studio”](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio) — list-change permission reset and trust dialog.
8. **SRC-azure-appservice-mcp-2026**: [Microsoft, “Configure App Service built-in MCP”](https://learn.microsoft.com/en-us/azure/app-service/configure-mcp-built-in) — tool-list hashing and hot reload.
9. **SRC-docker-ghsa-46gc-2025**: [Docker, GHSA-46gc-mwh4-cc5r](https://github.com/docker/mcp-gateway/security/advisories/GHSA-46gc-mwh4-cc5r) — affected gateway modes, patch, workaround, and credit.
10. **SRC-nvd-cve-2025-64443**: [NVD, CVE-2025-64443](https://nvd.nist.gov/vuln/detail/CVE-2025-64443) — vulnerability metadata and exploitation status.
11. **SRC-mitre-t1554**: [MITRE ATT&CK T1554](https://attack.mitre.org/techniques/T1554/) — analogous host-binary persistence behavior and contributors.
12. **SRC-ms-rug-pull-catalog-2026**: [Microsoft, “Rug-Pull Attack”](https://learn.microsoft.com/en-us/security/zero-trust/catalog-ai-attack-techniques/rug-pull-attack) — current closest-fit ATLAS mappings.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Independent clean-room draft with evidence packet and tested analytic | OpenAI Codex clean-room research team |
