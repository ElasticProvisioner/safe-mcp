# SAF-T1914: Tool-to-Tool Exfil

## Overview

- **Tactic**: Exfiltration (ATK-TA0010)
- **Technique ID**: SAF-T1914
- **Research Packet**: [research/techniques/SAF-T1914](../../research/techniques/SAF-T1914/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1914/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Confidentiality impact can be high when a sensitive source tool and an attacker-reachable outbound sink are available in the same agent session. <!-- SAF-TRACE: claims=SAF-T1914-C017; sources=SRC-nvd-cve-2025-34072,SRC-invariant-github-mcp-2025 -->
- **First Observed**: Not observed in production; the earliest directly reviewed controlled demonstration was published 2025-04-01. <!-- SAF-TRACE: claims=SAF-T1914-C005,SAF-T1914-C010; sources=SRC-invariant-tpa-2025-04-01,SRC-nvd-fsp-catalog-queries-2026-09-01,SRC-cisa-kev-fsp-2026-09-01 -->
- **Last Updated**: 2026-09-02

## Scope

Tool-to-Tool Exfil covers an agentic host carrying confidential data returned by one source tool into a distinct outbound-capable sink tool or server under adversary-influenced instructions, causing or attempting unauthorized disclosure. <!-- SAF-TRACE: claims=SAF-T1914-C004,SAF-T1914-C016; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01,SRC-greshake-ipi-2023 -->

The crossed boundary is the host-enforced information-flow boundary between the source tool's data domain and a different recipient, server, account, repository, channel, or service reached through the sink. <!-- SAF-TRACE: claims=SAF-T1914-C001,SAF-T1914-C004; sources=SRC-mcp-architecture-2026,SRC-invariant-github-mcp-2025 -->

### In Scope

- Tool-description poisoning that induces a sensitive read followed by a data-bearing call to a different tool or server. <!-- SAF-TRACE: claims=SAF-T1914-C005,SAF-T1914-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-greshake-ipi-2023 -->
- Indirect injection in a source-tool result that causes source data to be placed into a distinct trusted sink call. <!-- SAF-TRACE: claims=SAF-T1914-C006,SAF-T1914-C016; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-greshake-ipi-2023 -->
- Same-server flows when the read and externally visible write are distinct tools, as well as cross-server flows coordinated by the host. <!-- SAF-TRACE: claims=SAF-T1914-C001,SAF-T1914-C004; sources=SRC-mcp-architecture-2026,SRC-invariant-github-mcp-2025 -->

### Out of Scope

- Injection that changes agent behavior but does not culminate in a sensitive source-to-sink transfer. <!-- SAF-TRACE: claims=SAF-T1914-C016; sources=SRC-greshake-ipi-2023,SRC-invariant-tpa-2025-04-01 -->
- Unauthorized tool invocation whose immediate objective is execution, modification, or disruption rather than disclosure. <!-- SAF-TRACE: claims=SAF-T1914-C016; sources=SRC-greshake-ipi-2023,SRC-invariant-tpa-2025-04-01 -->
- Direct network egress by a compromised server process and a single vulnerable tool that performs both a file read and upload without a distinct tool transition. <!-- SAF-TRACE: claims=SAF-T1914-C009,SAF-T1914-C016; sources=SRC-nvd-cve-2026-46555,SRC-ghsa-7jj9-4qqq-4xc4,SRC-greshake-ipi-2023 -->

### Distinguishing Characteristics

The defining observable is lineage: a sensitive result from a source call reappears, directly or by a stable reference or fingerprint, in a later call to a distinct outbound sink. Injection is the delivery mechanism and unauthorized invocation is a broader action primitive; the data-bearing transition is what distinguishes this technique. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C016; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-greshake-ipi-2023 -->

## Description

MCP hosts can coordinate multiple clients and servers, aggregate context, and present model-controlled tools. Tool results can enter model context or supply state used in later calls, so a hostile instruction in a description or returned result can influence how data from one security domain is passed to another tool. <!-- SAF-TRACE: claims=SAF-T1914-C001,SAF-T1914-C002; sources=SRC-mcp-architecture-2026,SRC-mcp-tools-2026-07-28 -->

The adversary's immediate objective is unauthorized disclosure, not merely gaining control of a tool call. Controlled WhatsApp, GitHub, email, and local-file demonstrations show the complete behavior with different source/sink pairs. <!-- SAF-TRACE: claims=SAF-T1914-C004,SAF-T1914-C005,SAF-T1914-C006,SAF-T1914-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->

MCP guidance assigns hosts and clients consent, input visibility, result validation, and logging duties, but these are implementation responsibilities and mostly SHOULD-level safeguards; the protocol cannot guarantee that every host makes the full flow visible or blocks it. <!-- SAF-TRACE: claims=SAF-T1914-C001,SAF-T1914-C003; sources=SRC-mcp-architecture-2026,SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026 -->

## Attack Vectors

- **Primary Vector**: Malicious instructions embedded in an untrusted source-tool result cause an agent to combine returned confidential data with a later outbound sink call. <!-- SAF-TRACE: claims=SAF-T1914-C006,SAF-T1914-C016; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-greshake-ipi-2023 -->
- **Secondary Vectors**:
  - Poisoned tool descriptions direct the model to obtain local or remote sensitive data and place it in another tool's arguments. <!-- SAF-TRACE: claims=SAF-T1914-C005; sources=SRC-invariant-tpa-2025-04-01 -->
  - Cross-server shadowing changes the apparent semantics, destination, or recipient of a trusted sink tool. <!-- SAF-TRACE: claims=SAF-T1914-C005,SAF-T1914-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Affected Components**: The MCP or agent host, model orchestration layer, one or more clients and servers, tool descriptions and results, call arguments, approval UI, and external sink. <!-- SAF-TRACE: claims=SAF-T1914-C001,SAF-T1914-C002,SAF-T1914-C003; sources=SRC-mcp-architecture-2026,SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026 -->
- **Trust Boundary Crossed**: The host-controlled boundary separating a source tool's sensitive data from a distinct sink recipient or service. <!-- SAF-TRACE: claims=SAF-T1914-C001,SAF-T1914-C004; sources=SRC-mcp-architecture-2026,SRC-invariant-github-mcp-2025 -->

## Technical Details

### Prerequisites

- The agent session can call both a tool that returns sensitive data and a distinct tool capable of sending, publishing, uploading, or otherwise exposing data. <!-- SAF-TRACE: claims=SAF-T1914-C004; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-invariant-tpa-2025-04-01 -->
- Attacker-controlled content or tool metadata reaches the model context and influences a later call. <!-- SAF-TRACE: claims=SAF-T1914-C002,SAF-T1914-C016; sources=SRC-mcp-tools-2026-07-28,SRC-greshake-ipi-2023 -->
- Source permissions, sink permissions, approval behavior, or cross-server policy allow the data-bearing transition to proceed. <!-- SAF-TRACE: claims=SAF-T1914-C003,SAF-T1914-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026,SRC-invariant-github-mcp-2025 -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies an agent workflow with a sensitive source and a reachable outbound sink, or introduces a server whose description can influence a trusted sink. <!-- SAF-TRACE: claims=SAF-T1914-C004,SAF-T1914-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
2. **Delivery**: A malicious instruction arrives in tool metadata, a public issue or document, a message, or another result the agent is asked to process. <!-- SAF-TRACE: claims=SAF-T1914-C005,SAF-T1914-C006,SAF-T1914-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
3. **Trigger or Execution**: The agent calls the source tool and receives confidential data in its context or returned state. <!-- SAF-TRACE: claims=SAF-T1914-C002,SAF-T1914-C004; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07 -->
4. **Boundary Crossing**: The host permits a distinct sink call whose arguments contain the source data, a derived representation, or a reference resolving to it. <!-- SAF-TRACE: claims=SAF-T1914-C004,SAF-T1914-C011; sources=SRC-invariant-github-mcp-2025,SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024 -->
5. **Objective**: The sink publishes, sends, uploads, or otherwise exposes the data to an unauthorized recipient or service. <!-- SAF-TRACE: claims=SAF-T1914-C004,SAF-T1914-C017; sources=SRC-invariant-github-mcp-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2025-34072 -->
6. **Follow-On Activity**: The recipient may use exposed credentials or information, but further access is conditional and not required for classification. <!-- SAF-TRACE: claims=SAF-T1914-C017,SAF-T1914-C018; sources=SRC-nvd-cve-2025-34072,SRC-mcp-tools-2026-07-28,SRC-invariant-github-mcp-2025 -->

### Example Scenario

An agent reads a synthetic restricted record from `records.example`; an untrusted message then directs it to send that record through `messaging.example` to a reserved invalid-domain recipient. The host audit stream records the same inert data reference in the source result and sink arguments. <!-- SAF-TRACE: claims=SAF-T1914-C004,SAF-T1914-C011; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024 -->

The sanitized example contains no live secret, working endpoint, or operational injection payload. <!-- SAF-TRACE: claims=SAF-T1914-C011; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024 -->

```json
{
  "source": {"server": "records.example", "tool": "read_record", "data_ref": "record:synthetic-42", "sensitivity": "restricted"},
  "sink": {"server": "messaging.example", "tool": "send_message", "data_ref": "record:synthetic-42", "destination": "recipient@example.invalid"},
  "authorization": {"approved": false, "destination_allowed": false}
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1914-C001 | MCP host/client architecture places aggregation, policy, and cross-server control at the host. | Research-Derived | SRC-mcp-architecture-2026: [MCP Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture/index) | Allocation of responsibility is not proof of implementation. |
| SAF-T1914-C002 | Model-controlled tools return content or state usable by later calls. | Research-Derived | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Host policy varies. |
| SAF-T1914-C003 | MCP guidance recommends consent, input visibility, result validation, and logging. | Research-Derived | SRC-mcp-overview-2026 and SRC-mcp-tools-2026-07-28: [MCP Specification](https://modelcontextprotocol.io/specification/2026-07-28) | Mostly SHOULD-level safeguards. |
| SAF-T1914-C004 | Multiple controlled examples carry sensitive source data into a distinct sink. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07, SRC-invariant-github-mcp-2025, and SRC-invariant-tpa-2025-04-01: [Invariant WhatsApp study](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | No production compromise established. |
| SAF-T1914-C005 | Tool descriptions induced sensitive reads and malicious or redirected sink calls in Cursor tests. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Product and date specific. |
| SAF-T1914-C006 | WhatsApp source results were transferred through a trusted send-message sink. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07: [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | Controlled experiments only. |
| SAF-T1914-C007 | Private repository data was disclosed in a public pull request. | Demonstrated | SRC-invariant-github-mcp-2025: [Toxic Agent Flow](https://invariantlabs.ai/blog/mcp-github-vulnerability) | Controlled proof of concept only. |
| SAF-T1914-C008 | Slack link unfurling produced a disclosed critical exfiltration vulnerability. | Research-Derived | SRC-nvd-cve-2025-34072 and SRC-cve-34072: [NVD record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-34072) | Proof of concept, not production exploitation. |
| SAF-T1914-C009 | An unauthenticated WhatsApp bridge enabled sibling callers to read and send files before 0.2.1. | Research-Derived | SRC-nvd-cve-2026-46555 and SRC-ghsa-7jj9-4qqq-4xc4: [NVD record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-46555) | Enabling evidence, not a complete demonstrated chain. |
| SAF-T1914-C010 | No verified production breach qualified in the bounded direct-authority corpus. | Research-Derived | SRC-nvd-fsp-catalog-queries-2026-09-01 and SRC-cisa-kev-fsp-2026-09-01: [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol) | Catalog absence cannot prove global absence. |
| SAF-T1914-C011 | Host logs can correlate sensitive source results to unauthorized distinct sinks by lineage. | Research-Derived | SRC-mcp-tools-2026-07-28 and SRC-agentdojo-2024: [AgentDojo](https://arxiv.org/pdf/2406.13352) | Event schema and window are SAF proposals. |
| SAF-T1914-C012 | Transformations, missing logs, timing, and legitimate copying limit correlation. | Research-Derived | SRC-greshake-ipi-2023 and SRC-agentdojo-2024: [Indirect Prompt Injection paper](https://arxiv.org/pdf/2302.12173) | Papers do not evaluate this detector. |
| SAF-T1914-C013 | Layered least-privilege, visibility, destination, flow-policy, validation, and logging controls address the mechanism. | Research-Derived | SRC-mcp-tools-2026-07-28 and SRC-cve-34072: [Slack advisory](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) | No single control is complete. |
| SAF-T1914-C014 | AgentDojo quantifies multi-tool attack and defense performance over 97 tasks and 629 security cases. | Research-Derived | SRC-agentdojo-2024: [AgentDojo](https://arxiv.org/pdf/2406.13352) | Benchmark-specific measurements. |
| SAF-T1914-C015 | The behavior belongs under Exfiltration and is conditionally analogous to ATT&CK T1567. | Research-Derived | SRC-mitre-ta0010 and SRC-mitre-t1567: [ATT&CK Exfiltration](https://attack.mitre.org/tactics/TA0010/) | Not every sink is a web service. |
| SAF-T1914-C016 | Injection and unauthorized invocation alone do not satisfy the disclosure boundary. | Research-Derived | SRC-greshake-ipi-2023 and SRC-invariant-tpa-2025-04-01: [IPI paper](https://arxiv.org/pdf/2302.12173) | Neighbor IDs remain synthetic until integration. |
| SAF-T1914-C017 | Confidentiality is the core impact and severity is conditional. | Research-Derived | SRC-nvd-cve-2025-34072 and SRC-invariant-github-mcp-2025: [NVD record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-34072) | Sensitivity and reachability determine severity. |
| SAF-T1914-C018 | Response should preserve lineage, contain the session and sink, rotate exposed credentials, and narrow permissions. | Research-Derived | SRC-mcp-tools-2026-07-28 and SRC-cve-34072: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Procedure is an operational synthesis. |

### Current State

- **Affected Environments**: Agentic hosts with a sensitive source tool, a distinct outbound sink, attacker-influenced content or metadata, and insufficient cross-tool policy are exposed to the demonstrated pattern. <!-- SAF-TRACE: claims=SAF-T1914-C004,SAF-T1914-C013; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-mcp-tools-2026-07-28 -->
- **Known Exploitation**: Public controlled demonstrations and CVE-2025-34072 proof-of-concept evidence exist; no verified production breach qualified in the reviewed direct-authority corpus. <!-- SAF-TRACE: claims=SAF-T1914-C008,SAF-T1914-C010; sources=SRC-nvd-cve-2025-34072,SRC-cve-34072,SRC-nvd-fsp-catalog-queries-2026-09-01,SRC-cisa-kev-fsp-2026-09-01 -->
- **Available Protections**: Current MCP guidance covers consent, argument visibility, validation, access control, output sanitization, and logging; example-specific mitigations additionally restrict sinks and destinations. <!-- SAF-TRACE: claims=SAF-T1914-C003,SAF-T1914-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026,SRC-cve-34072 -->
- **Residual Risk**: Encoded or transformed data, incomplete telemetry, persistent approvals, and legitimate-looking destinations can bypass or weaken these controls. <!-- SAF-TRACE: claims=SAF-T1914-C012,SAF-T1914-C014; sources=SRC-greshake-ipi-2023,SRC-agentdojo-2024 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-34072 | 2025; deprecated Anthropic Slack MCP server with link unfurling | Private data in a generated link can reach an attacker endpoint; retire the deprecated server, disable unfurling, and constrain destinations. | Direct vulnerability; selected rank 1. | Proof of concept; no production exploitation established. <!-- SAF-TRACE: claims=SAF-T1914-C008; sources=SRC-nvd-cve-2025-34072,SRC-cve-34072 --> |
| GitHub toxic-agent-flow demonstration | 2025; trusted GitHub tools spanning public issues, private repositories, and public pull requests | Private repository information entered a public pull request; apply granular read/write policy and public-sink controls. | Direct demonstration; selected rank 2. | Controlled proof of concept. <!-- SAF-TRACE: claims=SAF-T1914-C007,SAF-T1914-C013; sources=SRC-invariant-github-mcp-2025 --> |
| WhatsApp MCP experiments | 2025; trusted WhatsApp tools plus a malicious server or injected message | Chat or contact data was sent to an attacker-selected number; isolate servers and enforce recipient and cross-server policy. | Direct demonstration; selected rank 3. | Controlled setup; result injection was harder and needed more privilege. <!-- SAF-TRACE: claims=SAF-T1914-C006; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| Tool poisoning and email shadowing | 2025; Cursor with malicious and trusted MCP tools | Local data entered a malicious tool call or trusted email was redirected; pin metadata and show full arguments. | Direct demonstration; selected rank 4. | Product-specific controlled tests. <!-- SAF-TRACE: claims=SAF-T1914-C005; sources=SRC-invariant-tpa-2025-04-01 --> |
| CVE-2026-46555 | Through 0.2.0; unauthenticated local WhatsApp MCP bridge | Local callers could read and send files; upgrade to 0.2.1 for authentication, Host validation, and path confinement. | Enabling vulnerability; not selected. | Does not itself prove a complete host-mediated chain. <!-- SAF-TRACE: claims=SAF-T1914-C009; sources=SRC-nvd-cve-2026-46555,SRC-ghsa-7jj9-4qqq-4xc4 --> |

### Real-World Incidents or Demonstrations

No verified production incident was found. The evidence status rests on controlled demonstrations and disclosed proof-of-concept vulnerability evidence, not on an in-production breach claim. <!-- SAF-TRACE: claims=SAF-T1914-C004,SAF-T1914-C008,SAF-T1914-C010; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-invariant-tpa-2025-04-01,SRC-nvd-cve-2025-34072,SRC-nvd-fsp-catalog-queries-2026-09-01,SRC-cisa-kev-fsp-2026-09-01 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Sensitive source data can reach an attacker-reachable sink when source and sink permissions coexist. <!-- SAF-TRACE: claims=SAF-T1914-C017; sources=SRC-nvd-cve-2025-34072,SRC-invariant-github-mcp-2025 --> |
| Integrity | Low | Argument or recipient manipulation can occur, but integrity impact is conditional and not required for technique classification. <!-- SAF-TRACE: claims=SAF-T1914-C005,SAF-T1914-C017; sources=SRC-invariant-tpa-2025-04-01,SRC-nvd-cve-2025-34072 --> |
| Availability | None | The core documented behavior is disclosure; availability loss is not required or established by the selected examples. <!-- SAF-TRACE: claims=SAF-T1914-C017; sources=SRC-nvd-cve-2025-34072,SRC-invariant-github-mcp-2025 --> |
| Scope | Multi-System | The flow can cross servers, accounts, repositories, messaging recipients, or external preview infrastructure, bounded by the host's connected tools and permissions. <!-- SAF-TRACE: claims=SAF-T1914-C001,SAF-T1914-C004,SAF-T1914-C008; sources=SRC-mcp-architecture-2026,SRC-invariant-github-mcp-2025,SRC-nvd-cve-2025-34072 --> |

### Severity Conditions

- **Severity increases when**: Sources contain credentials or restricted records, sinks are public or attacker-controlled, approvals hide arguments, and automation has broad persistent permissions. <!-- SAF-TRACE: claims=SAF-T1914-C005,SAF-T1914-C007,SAF-T1914-C017; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-github-mcp-2025,SRC-nvd-cve-2025-34072 -->
- **Severity decreases when**: Source and sink scopes are separated, full recipients and arguments require per-call approval, destinations are constrained, and cross-server data-flow policy blocks sensitive lineage. <!-- SAF-TRACE: claims=SAF-T1914-C003,SAF-T1914-C013,SAF-T1914-C017; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026,SRC-invariant-tpa-2025-04-01,SRC-cve-34072,SRC-nvd-cve-2025-34072 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Agent host or client tool audit | Source results, sink calls, approvals, and outcomes | Timestamp, session and call IDs, server and tool IDs, role, sensitivity, data reference or fingerprint, arguments, destination, approval, authorization, allowlist result, and outcome | Create fingerprints or lineage references before redaction and use synchronized timestamps. <!-- SAF-TRACE: claims=SAF-T1914-C001,SAF-T1914-C003,SAF-T1914-C011; sources=SRC-mcp-architecture-2026,SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024 --> |
| Sink application or network audit | Message, upload, publication, repository write, or outbound request | Recipient or destination, actor, time, session correlation, object or request identifier, and disposition | Use for confirmation because a proposed call may be rejected or fail before disclosure. <!-- SAF-TRACE: claims=SAF-T1914-C008,SAF-T1914-C011,SAF-T1914-C012; sources=SRC-nvd-cve-2025-34072,SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-greshake-ipi-2023 --> |

### Indicators of Compromise (IoCs)

- No universal durable IoC is known; recipients, domains, and artifacts depend on the selected sink and adversary-controlled content. <!-- SAF-TRACE: claims=SAF-T1914-C012; sources=SRC-greshake-ipi-2023,SRC-agentdojo-2024,SRC-mcp-tools-2026-07-28 -->
- Treat an unapproved destination or recipient carrying a known sensitive data reference as contextual evidence, not as a globally reusable indicator. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C012; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-greshake-ipi-2023 -->

### Behavioral Indicators

- A sensitivity-labeled source result is followed in the same session by a different outbound tool or server carrying the same lineage reference or fingerprint. <!-- SAF-TRACE: claims=SAF-T1914-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-architecture-2026,SRC-agentdojo-2024 -->
- The sink recipient, public visibility, or destination falls outside the source data's approved policy, especially when approval was absent, incomplete, or rejected. <!-- SAF-TRACE: claims=SAF-T1914-C003,SAF-T1914-C011,SAF-T1914-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026,SRC-invariant-github-mcp-2025 -->
- Confidence increases when the host sequence is confirmed by a sink-side message, publication, upload, or outbound-request record. <!-- SAF-TRACE: claims=SAF-T1914-C008,SAF-T1914-C011; sources=SRC-nvd-cve-2025-34072,SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect an unauthorized, data-bearing transition from a sensitive source result to a distinct outbound sink in one agent session. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C016; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-greshake-ipi-2023 -->
- **Rule Status**: Experimental; the normalized schema and window are SAF proposals tested only with the included inert fixtures. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C012; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-greshake-ipi-2023 -->
- **Detection Logic**: Correlate a sensitivity-labeled source result to a distinct outbound call sharing a data reference or fingerprint, then suppress only a transfer that is approved, explicitly authorized, and destination-allowed. <!-- SAF-TRACE: claims=SAF-T1914-C003,SAF-T1914-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026,SRC-agentdojo-2024 -->
- **Correlation Window**: 120 seconds by default, inclusive; tune it to workflow latency and session semantics. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C012; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-greshake-ipi-2023 -->
- **Known False Positives**: Approved cross-tool business workflows with missing authorization metadata, coarse sensitivity labels, retries, and mirrored calls. <!-- SAF-TRACE: claims=SAF-T1914-C012; sources=SRC-greshake-ipi-2023,SRC-agentdojo-2024,SRC-mcp-tools-2026-07-28 -->
- **Known Limitations**: Transformations, summaries, encoding, cross-session delays, missing lineage, and unlogged tools can evade correlation. <!-- SAF-TRACE: claims=SAF-T1914-C012; sources=SRC-greshake-ipi-2023,SRC-agentdojo-2024,SRC-mcp-tools-2026-07-28 -->
- **Tuning Guidance**: Baseline intended source/sink pairs, require destination identity, preserve privacy-safe lineage, and shorten or extend the window using measured workflow timing. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C012,SAF-T1914-C013; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-greshake-ipi-2023,SRC-invariant-tpa-2025-04-01 -->

### Validation

- **Test Data**: [fixtures.json](../../tests/SAF-T1914/fixtures.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1914/test_detection_rule.py)
- **Reference Detector**: [detect_tool_to_tool_exfil.py](detect_tool_to_tool_exfil.py)
- **Expected Result**: Nine inert fixture classes and a tunable-window assertion pass, covering two positives, the inclusive boundary, late transfer, authorized lookalike, public data, same-tool exclusion, transformed-data blind spot, and malformed input. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C012; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-greshake-ipi-2023 -->
- **Last Validated**: 2026-09-02; result captured in [detection-test-results.txt](../../research/techniques/SAF-T1914/validation/detection-test-results.txt).
- **Feasibility Waiver**: None; synthetic representative validation is executable locally. <!-- SAF-TRACE: claims=SAF-T1914-C011; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024 -->

## Mitigation Strategies

### Preventive Controls

1. **Treat tool metadata and results as untrusted**: Review and pin descriptions, validate results before they enter model context, and sanitize server output. <!-- SAF-TRACE: claims=SAF-T1914-C002,SAF-T1914-C003,SAF-T1914-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026,SRC-invariant-tpa-2025-04-01 -->
2. **Separate source and sink authority**: Minimize credentials and tool sets, avoid broad persistent approval, and require explicit policy for confidential cross-server transfers. <!-- SAF-TRACE: claims=SAF-T1914-C003,SAF-T1914-C013; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-github-mcp-2025,SRC-invariant-tpa-2025-04-01 -->
3. **Constrain the sink**: Show complete arguments and recipients, restrict destinations or public visibility, and disable automatic unfurl or preview behavior where applicable. <!-- SAF-TRACE: claims=SAF-T1914-C008,SAF-T1914-C013; sources=SRC-nvd-cve-2025-34072,SRC-cve-34072,SRC-mcp-tools-2026-07-28 -->

### Detective Controls

1. **Retain host lineage**: Log source results, sink calls, approvals, destinations, and outcomes with a shared session and privacy-preserving lineage token. <!-- SAF-TRACE: claims=SAF-T1914-C003,SAF-T1914-C011,SAF-T1914-C013; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-invariant-tpa-2025-04-01 -->
2. **Confirm at the sink**: Correlate host alerts with application or network records and prioritize unauthorized public or attacker-controlled recipients. <!-- SAF-TRACE: claims=SAF-T1914-C008,SAF-T1914-C011; sources=SRC-nvd-cve-2025-34072,SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024 -->

### Response Procedures

#### Immediate Actions

- Contain the implicated agent session, disable or isolate the sink, and prevent further calls while preserving audit state. <!-- SAF-TRACE: claims=SAF-T1914-C018; sources=SRC-mcp-tools-2026-07-28,SRC-cve-34072,SRC-invariant-github-mcp-2025 -->
- Revoke or rotate credentials and secrets shown by source-to-sink reconstruction to have reached an unauthorized destination. <!-- SAF-TRACE: claims=SAF-T1914-C017,SAF-T1914-C018; sources=SRC-nvd-cve-2025-34072,SRC-mcp-tools-2026-07-28,SRC-invariant-github-mcp-2025 -->

#### Investigation Steps

- Preserve host call, result, approval, and outcome records; reconstruct lineage from the first adversarial instruction through the source and sink calls. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C018; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-cve-34072 -->
- Confirm recipient, visibility, delivery, or outbound request at the sink and identify all data references that crossed the boundary. <!-- SAF-TRACE: claims=SAF-T1914-C008,SAF-T1914-C018; sources=SRC-nvd-cve-2025-34072,SRC-cve-34072,SRC-mcp-tools-2026-07-28 -->

#### Remediation

- Remove or neutralize the injected content or poisoned metadata and update or retire the affected server or integration. <!-- SAF-TRACE: claims=SAF-T1914-C009,SAF-T1914-C013,SAF-T1914-C018; sources=SRC-nvd-cve-2026-46555,SRC-ghsa-7jj9-4qqq-4xc4,SRC-mcp-tools-2026-07-28,SRC-cve-34072 -->
- Narrow source and sink permissions, add destination and cross-server policy, and rerun the inert regression fixtures before restoring automation. <!-- SAF-TRACE: claims=SAF-T1914-C011,SAF-T1914-C013,SAF-T1914-C018; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024,SRC-invariant-github-mcp-2025 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite or co-occurring | Injection delivers adversarial control; Tool-to-Tool Exfil additionally requires sensitive data to cross into a distinct sink. <!-- SAF-TRACE: claims=SAF-T1914-C016; sources=SRC-greshake-ipi-2023,SRC-invariant-tpa-2025-04-01 --> |
| [SAF-T1309: Privileged Tool Invocation via Prompt Manipulation](../SAF-T1309/README.md) | Overlapping | Unauthorized invocation is broader; Tool-to-Tool Exfil requires a data-bearing source-to-sink transition with a disclosure objective. <!-- SAF-TRACE: claims=SAF-T1914-C016; sources=SRC-greshake-ipi-2023,SRC-invariant-tpa-2025-04-01 --> |

Both canonical joins were reconciled only after the immutable clean-room freeze, as recorded in the [integration notes](../../research/techniques/SAF-T1914/integration-notes.yml).

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [TA0010](https://attack.mitre.org/tactics/TA0010/) | Exfiltration | Direct tactic placement | The immediate objective is unauthorized data disclosure from the victim environment. <!-- SAF-TRACE: claims=SAF-T1914-C015; sources=SRC-mitre-ta0010,SRC-mitre-t1567 --> |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Analogous | It is the closest match when the sink is a web service, but SAF requires agent-mediated cross-tool lineage and also covers non-web sink tools. <!-- SAF-TRACE: claims=SAF-T1914-C015; sources=SRC-mitre-ta0010,SRC-mitre-t1567 --> |

## References

1. **SRC-mcp-overview-2026**: [Model Context Protocol Specification, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) — privacy, consent, human control, and untrusted tool metadata.
2. **SRC-mcp-tools-2026-07-28**: [MCP Server Features — Tools, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — model-controlled tools, results, returned state, validation, confirmation, and logging.
3. **SRC-mcp-architecture-2026**: [MCP Architecture, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/architecture/index) — host, client, server, and cross-server responsibilities.
4. **SRC-invariant-tpa-2025-04-01**: [MCP Security Notification — Tool Poisoning Attacks — Luca Beurer-Kellner and Marc Fischer, 2025-04-01](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — controlled description poisoning and cross-server shadowing.
5. **SRC-invariant-whatsapp-mcp-2025-04-07**: [WhatsApp MCP Exploited — Luca Beurer-Kellner and Marc Fischer, 2025-04-07](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) — controlled source-to-send-message experiments.
6. **SRC-invariant-github-mcp-2025**: [MCP GitHub Toxic Agent Flow — Marco Milanta and Luca Beurer-Kellner, 2025-05-26](https://invariantlabs.ai/blog/mcp-github-vulnerability) — controlled private-repository-to-public-pull-request flow.
7. **SRC-cve-34072**: [Anthropic Slack MCP Server Data Leakage — wunderwuzzi, 2025-06-24](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) — link-unfurl walkthrough, timeline, and mitigations.
8. **SRC-nvd-fsp-catalog-queries-2026-09-01**: [NVD CVE 2.0 Model Context Protocol result set](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol) — bounded vulnerability-catalog review.
9. **SRC-nvd-cve-2025-34072**: [NVD CVE-2025-34072 record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-34072) — Slack MCP vulnerability, CVSS, SSVC, and references.
10. **SRC-nvd-cve-2026-46555**: [NVD CVE-2026-46555 record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-46555) — WhatsApp bridge affected and fixed versions, metrics, and advisory provenance.
11. **SRC-ghsa-7jj9-4qqq-4xc4**: [GHSA-7jj9-4qqq-4xc4 — jack-arturo; reported by Paul van der Klooster, 2026-05-16](https://github.com/verygoodplugins/whatsapp-mcp/security/advisories/GHSA-7jj9-4qqq-4xc4) — exact vendor advisory identified by NVD.
12. **SRC-cisa-kev-fsp-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog CSV](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) — exact candidate-ID absence check on 2026-09-02.
13. **SRC-greshake-ipi-2023**: [Not what you've signed up for — Kai Greshake et al., arXiv v2, 2023-05-05](https://arxiv.org/pdf/2302.12173) — indirect prompt injection, API-mediated exfiltration, evasion, and limitations.
14. **SRC-agentdojo-2024**: [AgentDojo — Edoardo Debenedetti et al., NeurIPS 2024 / arXiv v3](https://arxiv.org/pdf/2406.13352) — source/sink benchmark design and defense measurements.
15. **SRC-mitre-ta0010**: [MITRE ATT&CK Exfiltration, TA0010](https://attack.mitre.org/tactics/TA0010/) — tactic definition.
16. **SRC-mitre-t1567**: [MITRE ATT&CK Exfiltration Over Web Service, T1567, version 1.5; contributor William Cain](https://attack.mitre.org/techniques/T1567/) — analogous technique, mitigations, and detection guidance.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Independent clean-room draft, evidence packet, detector, and synthetic validation bundle | OpenAI Codex clean-room agent |
