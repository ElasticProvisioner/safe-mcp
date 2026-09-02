# SAF-T1606: Directory Listing via File Tool

## Overview

- **Tactic**: Discovery (ATK-TA0007)
- **Technique ID**: SAF-T1606
- **Research Packet**: [research/techniques/SAF-T1606](../../research/techniques/SAF-T1606/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1606/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: Medium
- **Severity Rationale**: Directory metadata can reveal project structure and high-value names that guide later activity, but listing alone does not read file contents or change state. <!-- SAF-TRACE: claims=SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 -->
- **First Observed**: No qualifying direct production incident was identified in the reviewed direct-authority corpus as of 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1606-C016; sources=SRC-anthropic-espionage-2025-11,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-02

## Scope

SAF-T1606 covers a model, client, or actor invoking a file-capable MCP tool to obtain names, entry types, sizes, counts, matching paths, or directory structure from the filesystem namespace available to the server. <!-- SAF-TRACE: claims=SAF-T1606-C004,SAF-T1606-C006; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-mcp-tools-2025-11-25 -->

### In Scope

- A `tools/call` request for a directory listing, recursive tree, file search, or allowed-directory list. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C004; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
- The returned directory metadata and its immediate use to understand filesystem organization or choose later targets. <!-- SAF-TRACE: claims=SAF-T1606-C005,SAF-T1606-C015; sources=SRC-attack-t1083,SRC-mcp-filesystem-reference-2026-09-02 -->

### Out of Scope

- Reading, collecting, uploading, or exfiltrating file contents and modifying filesystem state are separate follow-on behaviors. <!-- SAF-TRACE: claims=SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 -->
- Prompt injection, session theft, malicious server installation, or another mechanism that first obtains tool-call influence is a prerequisite or co-occurring behavior, not directory listing. <!-- SAF-TRACE: claims=SAF-T1606-C006; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
- Path traversal, symlink handling, prefix collisions, and authorization flaws may enlarge reachable paths, but they are boundary-bypass mechanisms rather than the discovery objective. <!-- SAF-TRACE: claims=SAF-T1606-C007,SAF-T1606-C008; sources=SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110 -->

### Distinguishing Characteristics

The immediate output distinguishes this technique: SAF-T1606 ends with directory metadata, the content-acquisition neighbor obtains bytes or text, and the path-boundary neighbor changes which locations a tool can reach. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C015; sources=SRC-mcp-roots-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->

## Description

MCP tools are named, schema-described operations that a model-controlled client can discover and invoke. A file-capable server can therefore place directory enumeration behind a `tools/call` request rather than a shell command, with results returned as tool content or structured data. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C006; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->

The official Filesystem reference server documents listing, recursive-tree, search, and allowed-directory tools. Its configured directories or MCP roots bound intended reach, while the server process identity and implementation determine effective access. The adversary objective is discovery: use returned metadata to understand the environment and select follow-on actions. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C004,SAF-T1606-C005; sources=SRC-mcp-roots-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 -->

The complete adversary path is Research-Derived. The reviewed corpus independently establishes MCP invocation, concrete listing functions, filesystem boundaries, and the discovery purpose, but it does not directly reproduce or observe an adversary using an MCP filesystem listing tool end to end. <!-- SAF-TRACE: claims=SAF-T1606-C018; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083,SRC-anthropic-espionage-2025-11 -->

## Attack Vectors

- **Primary Vector**: A model-controlled MCP client invokes a documented file-server directory-enumeration tool with a path argument. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C004,SAF-T1606-C006; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1606-C004; sources=SRC-mcp-filesystem-reference-2026-09-02 -->
  - Recursive tree or file-search functions enumerate broader structure than a single-directory listing. <!-- SAF-TRACE: claims=SAF-T1606-C004,SAF-T1606-C011; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-mitre-det0370-v1.0 -->
  - A roots or path-validation weakness can increase the namespace reachable by an otherwise ordinary listing request. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C007,SAF-T1606-C008; sources=SRC-mcp-roots-2025-11-25,SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110 -->
- **Affected Components**: MCP client or host, file-capable MCP server, roots and allowed-directory configuration, filesystem namespace, invoking identity, and audit pipeline. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C003,SAF-T1606-C004; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-roots-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
- **Trust Boundary Crossed**: A protocol-level tool request causes the file server to reveal metadata from the filesystem namespace available under its configured roots and process permissions. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C006; sources=SRC-mcp-roots-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->

## Technical Details

### Prerequisites

- The client has discovered a file-capable server and a directory-enumeration tool through its configured or listed tool surface. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C004; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
- The actor can cause or influence a `tools/call` request, whether directly or through a co-occurring behavior outside this technique. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C006; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
- The requested path is reachable under the server's effective roots and permissions, unless a separately classified weakness expands that boundary. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C007,SAF-T1606-C008; sources=SRC-mcp-roots-2025-11-25,SRC-nvd-cve-2025-53109,SRC-nvd-cve-2025-53110 -->

### Attack Flow

1. **Reconnaissance or Setup**: The client discovers a file-capable tool name and schema or already has it configured. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C004; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
2. **Delivery**: Actor-influenced context reaches the model or client that can request the tool; how that influence was obtained is outside SAF-T1606. <!-- SAF-TRACE: claims=SAF-T1606-C006; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
3. **Trigger or Execution**: The client sends `tools/call` with a listing, search, tree, or allowed-directory tool and its arguments. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C004; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
4. **Boundary Crossing**: The server evaluates the path under its configured roots and process identity, then performs the filesystem operation. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C006; sources=SRC-mcp-roots-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02 -->
5. **Objective**: The tool result reveals directory names, types, sizes, counts, matches, or hierarchy. <!-- SAF-TRACE: claims=SAF-T1606-C004,SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 -->
6. **Follow-On Activity**: The actor may use the metadata to select later reading, collection, persistence, or impact actions, which require separate classification. <!-- SAF-TRACE: claims=SAF-T1606-C005,SAF-T1606-C015; sources=SRC-attack-t1083,SRC-mcp-filesystem-reference-2026-09-02 -->

### Example Scenario

An actor-influenced agent asks an approved test Filesystem server for a recursive tree of an inert workspace; the result contains names and types only, illustrating the discovery output without file content or a boundary-bypass payload. <!-- SAF-TRACE: claims=SAF-T1606-C004,SAF-T1606-C006,SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-mcp-tools-2025-11-25,SRC-attack-t1083 -->

```json
{
  "rpc": {"method": "tools/call"},
  "tool": {"name": "directory_tree", "arguments": {"path": "/workspace/example"}},
  "result": {"entries": [{"name": "docs", "type": "directory"}]}
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1606-C001 | MCP tools are discoverable, callable schema-described operations with returned results. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | No standard directory-listing tool name. |
| SAF-T1606-C002 | MCP recommends confirmation, validation, access control, result checks, and audit logging. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Several client controls are SHOULD recommendations. |
| SAF-T1606-C003 | Roots express intended filesystem boundaries and security requirements. | Research-Derived | SRC-mcp-roots-2025-11-25: [MCP Roots specification](https://modelcontextprotocol.io/specification/2025-11-25/client/roots) | Implementation enforcement still matters. |
| SAF-T1606-C004 | The official Filesystem server implements multiple read-only directory-enumeration tools. | Demonstrated | SRC-mcp-filesystem-reference-2026-09-02 and SRC-mcp-example-servers-2026-09-02: [Filesystem reference server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | Capability documentation is not adversary observation. |
| SAF-T1606-C005 | Directory discovery can shape follow-on behavior. | Demonstrated | SRC-attack-t1083: [ATT&CK T1083](https://attack.mitre.org/techniques/T1083/) | Platform-general, not MCP-specific. |
| SAF-T1606-C006 | A model-controlled file-tool call can return directory metadata from the server's reachable namespace. | Research-Derived | SRC-mcp-tools-2025-11-25, SRC-mcp-filesystem-reference-2026-09-02, SRC-attack-t1083 | Explicit synthesis; no direct end-to-end incident or public evaluation. |
| SAF-T1606-C007 | CVE-2025-53109 documents a symlink-based Filesystem boundary bypass reported by Elad Beber of Cymulate. | Research-Derived | SRC-nvd-cve-2025-53109, SRC-ghsa-cve-2025-53109, SRC-mcp-fix-d00c60d | No named listing call or production exploitation. |
| SAF-T1606-C008 | CVE-2025-53110 documents a path-prefix Filesystem boundary bypass reported by Elad Beber of Cymulate. | Research-Derived | SRC-nvd-cve-2025-53110, SRC-ghsa-cve-2025-53110, SRC-mcp-fix-cc99bda | No named listing call or production exploitation. |
| SAF-T1606-C009 | NVD SSVC data recorded exploitation as none and neither selected CVE appeared in CISA KEV 2026.09.01. | Research-Derived | SRC-nvd-cve-2025-53109, SRC-nvd-cve-2025-53110, SRC-cisa-kev-2026-09-01 | SSVC observations are dated; KEV absence is not universal absence. |
| SAF-T1606-C010 | Anthropic documented MCP-enabled agentic discovery in a production campaign but did not name a filesystem listing tool. | Observed | SRC-anthropic-espionage-2025-11: [Anthropic Threat Intelligence report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) | Adjacent, not a direct SAF-T1606 instance. |
| SAF-T1606-C011 | ATT&CK DET0370 correlates enumeration with context, breadth, sensitive locations, allowlists, and time. | Research-Derived | SRC-mitre-det0370-v1.0: [ATT&CK DET0370](https://attack.mitre.org/detectionstrategies/DET0370/) | Not an MCP analytic and no accuracy evaluation. |
| SAF-T1606-C012 | An MCP analytic can adapt those concepts to file-tool calls, paths, recursion, approvals, and allowlists. | Research-Derived | SRC-mcp-tools-2025-11-25, SRC-mcp-filesystem-reference-2026-09-02, SRC-mitre-det0370-v1.0 | Experimental synthesis over normalized audit fields. |
| SAF-T1606-C013 | Legitimate browsing and automation require contextual tuning. | Research-Derived | SRC-mitre-det0370-v1.0, SRC-mcp-filesystem-reference-2026-09-02 | No MCP false-positive rate is available. |
| SAF-T1606-C014 | Roots, least privilege, validation, confirmation, and audit reduce reach or improve accountability. | Research-Derived | SRC-mcp-roots-2025-11-25, SRC-mcp-tools-2025-11-25, SRC-mcp-security-2025-11-25 | Authorized in-scope listing can remain possible. |
| SAF-T1606-C015 | Listing reveals metadata but does not itself prove content disclosure, modification, or disruption. | Research-Derived | SRC-mcp-filesystem-reference-2026-09-02, SRC-attack-t1083 | Impact depends on path sensitivity and follow-on action. |
| SAF-T1606-C016 | No direct production case was found in the reviewed corpus as of 2026-09-02. | Research-Derived | SRC-anthropic-espionage-2025-11, SRC-cisa-kev-2026-09-01 | Bounded search result, not a universal negative. |
| SAF-T1606-C017 | Official 0.6.3/0.6.4 fixed-version fields conflict for both selected CVEs. | Research-Derived | SRC-ghsa-cve-2025-53109, SRC-ghsa-cve-2025-53110, SRC-nvd-cve-2025-53109, SRC-nvd-cve-2025-53110 | No unambiguous 0.6.3-safe claim. |
| SAF-T1606-C018 | The complete technique warrants Research-Derived status. | Research-Derived | SRC-mcp-tools-2025-11-25, SRC-mcp-filesystem-reference-2026-09-02, SRC-attack-t1083, SRC-anthropic-espionage-2025-11 | Raise only with direct end-to-end evidence. |
| SAF-T1606-C019 | ATT&CK T1083 directly matches the directory-enumeration behavior, with MCP as a specialization. | Research-Derived | SRC-attack-t1083, SRC-mcp-tools-2025-11-25 | T1083 does not imply MCP, model control, or roots. |

### Current State

- **Affected Environments**: MCP hosts connected to a file-capable server that exposes listing, recursive-tree, file-search, or allowed-directory operations under usable filesystem permissions. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C004,SAF-T1606-C006; sources=SRC-mcp-roots-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02,SRC-mcp-tools-2025-11-25 -->
- **Known Exploitation**: No direct production instance was identified; one MCP-enabled production campaign is adjacent, and both selected enabling CVEs had exploitation recorded as none in their dated NVD SSVC blocks and were absent from CISA KEV 2026.09.01. <!-- SAF-TRACE: claims=SAF-T1606-C009,SAF-T1606-C010,SAF-T1606-C016; sources=SRC-nvd-cve-2025-53109,SRC-nvd-cve-2025-53110,SRC-cisa-kev-2026-09-01,SRC-anthropic-espionage-2025-11 -->
- **Available Protections**: Bound roots and process privileges, validate paths, require meaningful confirmation for sensitive requests, validate results, and retain complete tool-call audit records. <!-- SAF-TRACE: claims=SAF-T1606-C002,SAF-T1606-C003,SAF-T1606-C014; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-roots-2025-11-25,SRC-mcp-security-2025-11-25 -->
- **Residual Risk**: A permitted request within approved roots can still reveal useful structure, and legitimate browsing makes intent difficult to infer from a single event. <!-- SAF-TRACE: claims=SAF-T1606-C013,SAF-T1606-C014,SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-mitre-det0370-v1.0,SRC-attack-t1083 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-53109 / GHSA-q66q-fx2p-7w4m | Published July 2025; affected official Filesystem server versions. | Symlink handling could expose unintended files. The uncontested guidance is to upgrade to 0.6.4 or 2025.7.01; official 0.6.3 fields conflict. | Enabling vulnerability selected for relevance and impact; reported by Elad Beber of Cymulate. | No directory-listing call or production exploitation is documented. <!-- SAF-TRACE: claims=SAF-T1606-C007,SAF-T1606-C009,SAF-T1606-C017; sources=SRC-nvd-cve-2025-53109,SRC-ghsa-cve-2025-53109,SRC-mcp-fix-d00c60d,SRC-cisa-kev-2026-09-01 --> |
| CVE-2025-53110 / GHSA-hc55-p739-j48w | Published July 2025; affected official Filesystem server versions. | A colliding path prefix could expose unintended files. The uncontested guidance is to upgrade to 0.6.4 or 2025.7.01; official 0.6.3 fields conflict. | Enabling vulnerability selected for relevance and impact; reported by Elad Beber of Cymulate. | No directory-listing call or production exploitation is documented. <!-- SAF-TRACE: claims=SAF-T1606-C008,SAF-T1606-C009,SAF-T1606-C017; sources=SRC-nvd-cve-2025-53110,SRC-ghsa-cve-2025-53110,SRC-mcp-fix-cc99bda,SRC-cisa-kev-2026-09-01 --> |
| GTG-1002 AI-orchestrated espionage campaign | Detected September 2025; roughly 30 entities targeted and a handful of successful intrusions validated. | Anthropic banned identified accounts, notified affected entities, coordinated with authorities, and expanded detection and safety controls. | Adjacent production incident selected for impact: Claude Code and MCP tools supported largely autonomous discovery and intrusion activity. | The report does not identify a filesystem listing tool or call, so it is not a direct SAF-T1606 breach. <!-- SAF-TRACE: claims=SAF-T1606-C010,SAF-T1606-C016; sources=SRC-anthropic-espionage-2025-11 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Medium | Names, entry types, sizes, counts, and hierarchy may expose project structure or high-value targets; content disclosure requires a separate operation. <!-- SAF-TRACE: claims=SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 --> |
| Integrity | None | The documented listing tools are read-only; integrity impact requires a separate write or follow-on behavior. <!-- SAF-TRACE: claims=SAF-T1606-C004,SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 --> |
| Availability | None | Directory listing does not itself disrupt the service; a separate resource-exhaustion or destructive behavior would be required. <!-- SAF-TRACE: claims=SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 --> |
| Scope | Local | Reach is normally bounded by configured roots and the server process identity, although a separately classified weakness can expand it. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C007,SAF-T1606-C008; sources=SRC-mcp-roots-2025-11-25,SRC-nvd-cve-2025-53109,SRC-nvd-cve-2025-53110 --> |

### Severity Conditions

- **Severity increases when**: Broad roots, privileged server identities, recursive operations, sensitive naming, unattended automation, or weak confirmation expose more structure. <!-- SAF-TRACE: claims=SAF-T1606-C002,SAF-T1606-C003,SAF-T1606-C011,SAF-T1606-C015; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-roots-2025-11-25,SRC-mitre-det0370-v1.0,SRC-mcp-filesystem-reference-2026-09-02 -->
- **Severity decreases when**: Narrow read-only roots, minimal process permissions, explicit approvals, and monitored non-recursive access constrain reach and context. <!-- SAF-TRACE: claims=SAF-T1606-C002,SAF-T1606-C003,SAF-T1606-C014; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-roots-2025-11-25,SRC-mcp-security-2025-11-25 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or client tool-audit log | Tool discovery and invocation, approval, and result status | Timestamp, session, actor, server, rpc.method, tool.name, tool.arguments.path, approval state, allowlist state, result status | Preserve enough context to reconstruct the request and distinguish approved automation. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C002,SAF-T1606-C012; sources=SRC-mcp-tools-2025-11-25,SRC-mitre-det0370-v1.0 --> |
| Optional endpoint or filesystem telemetry | Process execution and file-access events associated with the server | Timestamp, process or service identity, normalized path, access type, parent process | Correlate by identity and time; DET0370 uses process, file-access, command, path, and user context. <!-- SAF-TRACE: claims=SAF-T1606-C011,SAF-T1606-C012; sources=SRC-mitre-det0370-v1.0,SRC-mcp-filesystem-reference-2026-09-02 --> |

### Indicators of Compromise (IoCs)

- No reliable durable artifact is inherent to directory listing; treat the tool-call sequence as behavior, not an IoC. <!-- SAF-TRACE: claims=SAF-T1606-C011,SAF-T1606-C013,SAF-T1606-C015; sources=SRC-mitre-det0370-v1.0,SRC-mcp-filesystem-reference-2026-09-02 -->

### Behavioral Indicators

- A `tools/call` event selects a documented directory-enumeration tool and targets a boundary-aware sensitive path without an approved allowlist exception. <!-- SAF-TRACE: claims=SAF-T1606-C004,SAF-T1606-C012; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-mitre-det0370-v1.0 -->
- Recursive tree or search calls outside the actor's normal workflow increase investigative priority. <!-- SAF-TRACE: claims=SAF-T1606-C011,SAF-T1606-C012,SAF-T1606-C013; sources=SRC-mitre-det0370-v1.0,SRC-mcp-filesystem-reference-2026-09-02 -->
- Denied, failed, or successful calls should all be retained because an attempted listing can still show intent or control behavior, while success establishes returned reach. <!-- SAF-TRACE: claims=SAF-T1606-C002,SAF-T1606-C012; sources=SRC-mcp-tools-2025-11-25,SRC-mitre-det0370-v1.0 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Surface unapproved recursive or sensitive-path directory enumeration through documented MCP file-tool names. <!-- SAF-TRACE: claims=SAF-T1606-C012; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-mitre-det0370-v1.0 -->
- **Rule Status**: Experimental; deterministic fixture tests validate implementation logic, not production accuracy. <!-- SAF-TRACE: claims=SAF-T1606-C012,SAF-T1606-C013; sources=SRC-mitre-det0370-v1.0,SRC-mcp-tools-2025-11-25 -->
- **Detection Logic**: Require `tools/call`, a documented listing tool, and either a boundary-aware sensitive path or a recursive function; suppress only sessions that are both approved and allowlisted. <!-- SAF-TRACE: claims=SAF-T1606-C012,SAF-T1606-C013; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-filesystem-reference-2026-09-02,SRC-mitre-det0370-v1.0 -->
- **Correlation Window**: Single-event logic in the frozen analytic; environments may add actor/session baselines or burst correlation after validation. <!-- SAF-TRACE: claims=SAF-T1606-C011,SAF-T1606-C012; sources=SRC-mitre-det0370-v1.0,SRC-mcp-tools-2025-11-25 -->
- **Known False Positives**: IDE indexing, project browsing, build, backup, inventory, and authorized administrative workflows. <!-- SAF-TRACE: claims=SAF-T1606-C013; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-mitre-det0370-v1.0 -->
- **Known Limitations**: Missing or renamed tool fields, custom listing tools, unlogged calls, path-encoding differences, and compromised approvals can evade or mislead the rule. <!-- SAF-TRACE: claims=SAF-T1606-C001,SAF-T1606-C011,SAF-T1606-C012,SAF-T1606-C013; sources=SRC-mcp-tools-2025-11-25,SRC-mitre-det0370-v1.0 -->
- **Tuning Guidance**: Normalize paths, inventory local tool aliases, baseline recursive calls by actor and server, and restrict allowlists to reviewed workflows. <!-- SAF-TRACE: claims=SAF-T1606-C011,SAF-T1606-C012,SAF-T1606-C013; sources=SRC-mitre-det0370-v1.0,SRC-mcp-filesystem-reference-2026-09-02 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1606/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1606/test_detection_rule.py)
- **Expected Result**: [Eleven positive, negative, boundary, malformed, and legitimate-lookalike cases pass](../../research/techniques/SAF-T1606/validation/detection-test.txt).
- **Last Validated**: [2026-09-02](../../research/techniques/SAF-T1606/validation/detection-test.txt)
- **Feasibility Waiver**: None; representative synthetic logic tests are included, while production-effectiveness claims remain excluded. <!-- SAF-TRACE: claims=SAF-T1606-C012,SAF-T1606-C013; sources=SRC-mcp-tools-2025-11-25,SRC-mitre-det0370-v1.0 -->

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)** and **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Expose only required roots, run the server with minimal permissions, and make read-only mounts the default where writes are unnecessary. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C014; sources=SRC-mcp-roots-2025-11-25,SRC-mcp-security-2025-11-25 -->
2. **[SAF-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../../mitigations/SAF-M-69/README.md)**: Show tool inputs, require meaningful confirmation for sensitive paths or recursive operations, and retain approval context. <!-- SAF-TRACE: claims=SAF-T1606-C002,SAF-T1606-C014; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25 -->
3. **Validate filesystem boundaries**: Canonicalize and validate every requested path against permitted roots, monitor root availability, and keep affected Filesystem deployments on an uncontested remediated release. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C007,SAF-T1606-C008,SAF-T1606-C017; sources=SRC-mcp-roots-2025-11-25,SRC-nvd-cve-2025-53109,SRC-nvd-cve-2025-53110,SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110 -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Record tool name, arguments, actor, server, session, approval, result, and time for every call. <!-- SAF-TRACE: claims=SAF-T1606-C002,SAF-T1606-C012; sources=SRC-mcp-tools-2025-11-25,SRC-mitre-det0370-v1.0 -->
2. **[SAF-M-70: Tool-Invocation Anomaly Detection & Baselining](../../mitigations/SAF-M-70/README.md)** and **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20/README.md)**: Correlate recursive breadth or sensitive paths with unusual actors, denied approvals, endpoint access, and environment-owned allowlists. <!-- SAF-TRACE: claims=SAF-T1606-C011,SAF-T1606-C012,SAF-T1606-C013; sources=SRC-mitre-det0370-v1.0,SRC-mcp-tools-2025-11-25 -->

### Response Procedures

#### Immediate Actions

- Suspend the implicated session or tool connection when risk is ongoing, preserve its tool-call records, and narrow exposed roots before re-enabling access. <!-- SAF-TRACE: claims=SAF-T1606-C002,SAF-T1606-C003,SAF-T1606-C014; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-roots-2025-11-25,SRC-mcp-security-2025-11-25 -->
- If a boundary-bypass candidate is present, move the server to the uncontested remediated release and review every reachable root and process permission. <!-- SAF-TRACE: claims=SAF-T1606-C007,SAF-T1606-C008,SAF-T1606-C017; sources=SRC-nvd-cve-2025-53109,SRC-nvd-cve-2025-53110,SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110 -->

#### Investigation Steps

- Reconstruct `tools/call` events by actor, server, session, path, approval, and result; correlate with endpoint file-access telemetry when available. <!-- SAF-TRACE: claims=SAF-T1606-C002,SAF-T1606-C011,SAF-T1606-C012; sources=SRC-mcp-tools-2025-11-25,SRC-mitre-det0370-v1.0 -->
- Separate names and metadata actually returned from later file reads, uploads, writes, or exfiltration so each behavior is classified and contained correctly. <!-- SAF-TRACE: claims=SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 -->

#### Remediation

- Remove unauthorized roots, reduce server process privileges, repair path validation, and require reviewed approvals or policies for sensitive and recursive listing tools. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C014; sources=SRC-mcp-roots-2025-11-25,SRC-mcp-security-2025-11-25,SRC-mcp-tools-2025-11-25 -->
- Add a regression fixture for the observed tool alias, normalized path form, and legitimate allowlist case before restoring automated access. <!-- SAF-TRACE: claims=SAF-T1606-C012,SAF-T1606-C013; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-mitre-det0370-v1.0 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1502: File-Based Credential Harvest](../SAF-T1502/README.md) | Narrower follow-on | SAF-T1606 returns names and directory metadata; SAF-T1502 reads credential-bearing file contents. <!-- SAF-TRACE: claims=SAF-T1606-C015; sources=SRC-mcp-filesystem-reference-2026-09-02,SRC-attack-t1083 --> |
| [SAF-T1105: Path Traversal via File Tool](../SAF-T1105/README.md) | Enabling / co-occurring | SAF-T1606 is the discovery objective; SAF-T1105 uses path-boundary weakness to expand which locations the tool can reach. <!-- SAF-TRACE: claims=SAF-T1606-C003,SAF-T1606-C007,SAF-T1606-C008; sources=SRC-mcp-roots-2025-11-25,SRC-nvd-cve-2025-53109,SRC-nvd-cve-2025-53110 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Direct | Both behaviors enumerate filesystem names or structure to guide follow-on action; MCP adds a model-controlled tool invocation and root boundary not implied by ATT&CK. <!-- SAF-TRACE: claims=SAF-T1606-C005,SAF-T1606-C019; sources=SRC-attack-t1083,SRC-mcp-tools-2025-11-25 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [Model Context Protocol Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — Model Context Protocol project maintainers; version 2025-11-25.
2. **SRC-mcp-roots-2025-11-25**: [Model Context Protocol Roots specification](https://modelcontextprotocol.io/specification/2025-11-25/client/roots) — Model Context Protocol project maintainers; version 2025-11-25.
3. **SRC-mcp-security-2025-11-25**: [Model Context Protocol Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — Model Context Protocol project maintainers; version 2025-11-25.
4. **SRC-mcp-example-servers-2026-09-02**: [Model Context Protocol Example Servers](https://modelcontextprotocol.io/examples) — Model Context Protocol project maintainers; reviewed 2026-09-02.
5. **SRC-mcp-filesystem-reference-2026-09-02**: [Filesystem MCP Server README](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) — Model Context Protocol servers contributors; main reviewed 2026-09-02; exact GitHub URL obtained first from the official Example Servers page.
6. **SRC-nvd-cve-2025-53109**: [NVD CVE-2025-53109 API record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-53109) — NVD team, GitHub Security Advisories source CNA, and CISA Coordinator data; last modified 2026-06-17.
7. **SRC-ghsa-cve-2025-53109**: [GHSA-q66q-fx2p-7w4m](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-q66q-fx2p-7w4m) — published by dsp-ant; issue reported by Elad Beber of Cymulate; exact URL obtained first from NVD.
8. **SRC-mcp-fix-d00c60d**: [Maintainer fix commit d00c60d](https://github.com/modelcontextprotocol/servers/commit/d00c60df9d74dba8a3bb13113f8904407cda594f) — committed by jenn-newton; exact URL obtained first from NVD.
9. **SRC-nvd-cve-2025-53110**: [NVD CVE-2025-53110 API record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-53110) — NVD team, GitHub Security Advisories source CNA, and CISA Coordinator data; last modified 2026-06-17.
10. **SRC-ghsa-cve-2025-53110**: [GHSA-hc55-p739-j48w](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-hc55-p739-j48w) — published by dsp-ant; issue reported by Elad Beber of Cymulate; exact URL obtained first from NVD.
11. **SRC-mcp-fix-cc99bda**: [Maintainer fix commit cc99bda](https://github.com/modelcontextprotocol/servers/commit/cc99bdabdcad93a58877c5f3ab20e21d4394423d) — Model Context Protocol servers contributors; exact URL obtained first from NVD.
12. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — CISA; catalog version 2026.09.01.
13. **SRC-attack-t1083**: [MITRE ATT&CK T1083](https://attack.mitre.org/techniques/T1083/) — MITRE ATT&CK team; contributor Austin Clark (@c2defense); version 1.7, modified 2026-05-12.
14. **SRC-mitre-det0370-v1.0**: [MITRE ATT&CK DET0370](https://attack.mitre.org/detectionstrategies/DET0370/) — MITRE ATT&CK team; version 1.0, modified 2026-05-12.
15. **SRC-anthropic-espionage-2025-11**: [Disrupting the first reported AI-orchestrated cyber espionage campaign](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) — Anthropic Threat Intelligence; November 2025.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-02 | Independent clean-room technique, evidence packet, tested analytic, and framework fragments. | SAF-MCP Research Team; clean-room agent `/root/cleanroom_saf_t1606` |
