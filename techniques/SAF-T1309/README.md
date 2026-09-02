# SAF-T1309: Privileged Tool Invocation via Prompt Manipulation

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1309
- **Research Packet**: [research/techniques/SAF-T1309](../../research/techniques/SAF-T1309/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1309/traceability-ledger.yml)
- **Lifecycle Status**: Deprecated. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)
- **Documentation Status**: Deprecated
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Prompt manipulation can turn an agent's delegated identity and high-risk tools into a path to unauthorized state change or code execution when approval and least-privilege controls fail. <!-- SAF-TRACE: claims=SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773 -->
- **First Observed**: Not observed in production in the reviewed direct-authority corpus; controlled agentic demonstrations were published by 2024-06-19. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C008; sources=SRC-agentdojo-2406.13352v3,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-02

> **Deprecated compatibility ID:** SAF-T1309 is normalized into [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) as the enabling manipulation and [SAF-T1302: Agentic Confused Deputy](../SAF-T1302/README.md) as the authority-crossing effect. This page and its evidence packet remain available for provenance. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)

## Scope

This technique covers adversary-controlled natural-language instructions that alter a model's decision so it invokes a sensitive tool, or changes an approval-relevant setting that immediately enables such invocation, under privileges already delegated to the agent or MCP client. The crossed boundary is from untrusted prompt or retrieved content into a privileged action channel. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773 -->

### In Scope

- Direct prompt manipulation and indirect instructions embedded in files, web pages, messages, or tool results that cause a sensitive tool call. <!-- SAF-TRACE: claims=SAF-T1309-C003,SAF-T1309-C004; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->
- Agent or MCP-client execution using the victim's delegated tool permissions when required approval is missing, bypassed, or changed through the manipulated agent. <!-- SAF-TRACE: claims=SAF-T1309-C001,SAF-T1309-C006,SAF-T1309-C007; sources=SRC-mcp-tools-2026-07-28,SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773 -->

### Out of Scope

- Direct API, state-handle, session, or authorization abuse that does not manipulate a model through natural-language instructions. <!-- SAF-TRACE: claims=SAF-T1309-C015; sources=SRC-mcp-security-2026-07-28 -->
- MCP server-definition or configuration replacement performed directly by a repository collaborator without a prompt-manipulation step. <!-- SAF-TRACE: claims=SAF-T1309-C015; sources=SRC-cursor-ghsa-24mc-g4xr-4395 -->
- Prompt manipulation that changes only generated text and never reaches a privileged tool or approval-changing action. <!-- SAF-TRACE: claims=SAF-T1309-C004; sources=SRC-agentdojo-2406.13352v3 -->

### Distinguishing Characteristics

The defining observable is a prompt-derived control-flow change followed by a sensitive tool action in the agent's authority context. Direct transport injection, authorization theft, configuration substitution, and ordinary unsafe tool implementation have different initiating mechanisms even when the eventual impact is similar. <!-- SAF-TRACE: claims=SAF-T1309-C011,SAF-T1309-C015; sources=SRC-ms-prompt-shields-2026-07-31,SRC-mcp-security-2026-07-28,SRC-cursor-ghsa-24mc-g4xr-4395 -->

## Description

MCP tools are model-controlled: the model may discover and invoke them automatically from context and user prompts, while MCP leaves the interaction model to implementations. A manipulated instruction can therefore influence the model's tool-selection or argument-generation decision before the client sends `tools/call`. <!-- SAF-TRACE: claims=SAF-T1309-C001; sources=SRC-mcp-tools-2026-07-28 -->

The behavior becomes privilege escalation in the agentic trust model when the selected tool can mutate protected state, execute code, spend funds, disclose restricted data, or change approval-relevant configuration using authority unavailable to the attacker directly. Public evaluations demonstrate malicious tool actions from untrusted content, and product advisories document prompt-injection chains to host code execution; these are demonstrations and vulnerabilities, not evidence of a production breach. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C006,SAF-T1309-C007,SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773,SRC-rehberger-cve-2025-53773 -->

## Attack Vectors

- **Primary Vector**: Indirect instructions in attacker-controlled content that the agent reads through retrieval or a tool response. <!-- SAF-TRACE: claims=SAF-T1309-C003,SAF-T1309-C004; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1309-C003; sources=SRC-ms-prompt-shields-2026-07-31 -->
  - Direct user-prompt attempts to replace or override higher-priority instructions. <!-- SAF-TRACE: claims=SAF-T1309-C003; sources=SRC-ms-prompt-shields-2026-07-31 -->
  - Prompt-induced edits to agent or workspace settings that remove confirmation before a later tool invocation. <!-- SAF-TRACE: claims=SAF-T1309-C006,SAF-T1309-C007; sources=SRC-ghsa-cursor-4cxx-2025,SRC-rehberger-cve-2025-53773 -->
- **Affected Components**: Agent model, MCP host or client, retrieved content, tool-call broker, approval service, and the external system reached by the tool. <!-- SAF-TRACE: claims=SAF-T1309-C001,SAF-T1309-C004; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2406.13352v3 -->
- **Trust Boundary Crossed**: Untrusted language or tool-returned data influences a tool action executed with the agent user's delegated authority. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-cve-2025-53773 -->

## Technical Details

### Prerequisites

- The attacker can place instructions in a prompt or in content that the agent will process. <!-- SAF-TRACE: claims=SAF-T1309-C003,SAF-T1309-C004; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->
- The agent has a sensitive tool, write capability, or configuration path capable of reaching the adversary's immediate objective. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025 -->
- Human confirmation, capability enforcement, tool isolation, or least-privilege scope control does not prevent the action. <!-- SAF-TRACE: claims=SAF-T1309-C002,SAF-T1309-C009,SAF-T1309-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2026-07-28,SRC-camel-2503.18813v2 -->

### Attack Flow

1. **Reconnaissance or Setup**: The attacker identifies content the agent will ingest and an action reachable through its tools. <!-- SAF-TRACE: claims=SAF-T1309-C004; sources=SRC-agentdojo-2406.13352v3 -->
2. **Delivery**: The attacker embeds an instruction in a user prompt or in untrusted content such as a file, message, web page, or tool result. <!-- SAF-TRACE: claims=SAF-T1309-C003,SAF-T1309-C004; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->
3. **Trigger or Execution**: The model treats the injected text as control input and selects a sensitive tool or an approval-changing file write. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C006,SAF-T1309-C007; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025,SRC-rehberger-cve-2025-53773 -->
4. **Boundary Crossing**: The client executes the action without an effective user denial, policy check, or capability restriction. <!-- SAF-TRACE: claims=SAF-T1309-C002,SAF-T1309-C010; sources=SRC-mcp-tools-2026-07-28,SRC-camel-2503.18813v2 -->
5. **Objective**: The tool performs a privileged operation under the victim's delegated identity or host process. <!-- SAF-TRACE: claims=SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-cve-2025-53773 -->
6. **Follow-On Activity**: Any persistence, collection, exfiltration, or destructive effect depends on the invoked tool and is not part of this technique's defining boundary crossing. <!-- SAF-TRACE: claims=SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025 -->

### Example Scenario

An agent summarizes a document from an untrusted workspace. The document contains an inert instruction asking the agent to call a synthetic administrative tool; the agent attempts the call without a recorded approval, creating the observable sequence used by the example detection analytic. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C011; sources=SRC-agentdojo-2406.13352v3,SRC-ms-prompt-shields-2026-07-31,SRC-mcp-tools-2026-07-28 -->

```json
{
  "content_source": "https://example.invalid/report.txt",
  "synthetic_instruction": "Request the non-deployable tool admin.preview_change",
  "tool_result": "blocked_pending_human_approval"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1309-C001 | MCP models can automatically select tools from context and prompts, then clients send `tools/call`. | Research-Derived | SRC-mcp-tools-2026-07-28: [MCP Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | The protocol does not mandate a client interaction model. |
| SAF-T1309-C002 | MCP guidance calls for confirmation on sensitive operations, visible inputs, access controls, result validation, and tool-use logging. | Research-Derived | SRC-mcp-tools-2026-07-28: [MCP Tools security considerations](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | SHOULD-level client controls vary by implementation. |
| SAF-T1309-C003 | Microsoft's Prompt Shields distinguishes user-prompt and document attacks and exposes detection annotations at input and tool-response points. | Research-Derived | SRC-ms-prompt-shields-2026-07-31: [Prompt Shields](https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/content-filter-prompt-shields) | A product-specific classifier is not a universal detector. |
| SAF-T1309-C004 | AgentDojo demonstrates untrusted tool-returned data causing agents to execute attacker-selected tool actions in controlled environments. | Demonstrated | SRC-agentdojo-2406.13352v3: [AgentDojo](https://arxiv.org/html/2406.13352v3) | Controlled non-production evaluation; not MCP-specific. |
| SAF-T1309-C006 | CVE-2025-54135 chains indirect prompt injection and creation of an MCP settings file to code execution without approval in affected Cursor versions. | Demonstrated | SRC-ghsa-cursor-4cxx-2025: [Cursor advisory](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm) | Vulnerability disclosure and demonstration, not a production incident. |
| SAF-T1309-C007 | CVE-2025-53773 documents and publicly demonstrates prompt-injection-driven local code execution in GitHub Copilot and Visual Studio. | Demonstrated | SRC-cve-2025-53773: [CVE record](https://cveawg.mitre.org/api/cve/CVE-2025-53773); SRC-rehberger-cve-2025-53773: [researcher disclosure](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) | Requires local user interaction according to the CVE vector; no observed exploitation established. |
| SAF-T1309-C008 | No qualifying direct production incident was identified in the bounded reviewed corpus as of 2026-09-01. | Research-Derived | SRC-cisa-kev-2026-09-01: [CISA KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Absence is limited to reviewed direct authorities and exact candidates. |
| SAF-T1309-C009 | Progressive scopes, explicit confirmation, and elevation-event logging constrain prompt-driven tool misuse. | Research-Derived | SRC-mcp-security-2026-07-28: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) | Guidance does not prove resistance to adaptive prompt injection. |
| SAF-T1309-C010 | CaMeL demonstrates a capability and policy design that separates untrusted data processing from privileged tool control. | Demonstrated | SRC-camel-2503.18813v2: [CaMeL paper](https://arxiv.org/html/2503.18813v2) | Requires policy design and ecosystem integration and retains side-channel and usability limits. |
| SAF-T1309-C011 | Correlating an untrusted-input attack marker with an unapproved high-risk tool call is a testable behavioral analytic. | Research-Derived | SRC-ms-prompt-shields-2026-07-31; SRC-mcp-tools-2026-07-28; SRC-agentdojo-2406.13352v3 | SAF inference; correlation does not prove causation. |
| SAF-T1309-C012 | Classifier false positives and false negatives require the analytic to preserve context and support tuning. | Research-Derived | SRC-ms-prompt-shields-2026-07-31; SRC-agentdojo-2406.13352v3 | Product and benchmark behavior may not generalize. |
| SAF-T1309-C013 | Consequence and severity depend on the authority and side effects of the invoked tool. | Research-Derived | SRC-agentdojo-2406.13352v3; SRC-ghsa-cursor-4cxx-2025; SRC-cve-2025-53773 | Environment-dependent synthesis. |
| SAF-T1309-C014 | ATT&CK T1548 is analogous only where prompt manipulation circumvents an elevation-control mechanism. | Research-Derived | SRC-clean-t1301-attack-t1548: [ATT&CK T1548](https://attack.mitre.org/techniques/T1548/) | ATT&CK T1548 does not describe model-mediated prompt manipulation. |
| SAF-T1309-C015 | Direct handle abuse, configuration substitution, and URL command injection have initiating mechanisms distinct from prompt manipulation. | Research-Derived | SRC-mcp-security-2026-07-28; SRC-cursor-ghsa-24mc-g4xr-4395; SRC-jfsa-2025-6514 | Neighbor IDs require repository integration reconciliation. |

### Current State

- **Affected Environments**: Tool-using agents and MCP clients that ingest untrusted language and expose sensitive actions without effective per-action policy or approval. <!-- SAF-TRACE: claims=SAF-T1309-C001,SAF-T1309-C004; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2406.13352v3 -->
- **Known Exploitation**: Controlled demonstrations and disclosed vulnerabilities exist; no qualifying direct production incident was identified in the reviewed direct-authority corpus. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C006,SAF-T1309-C007,SAF-T1309-C008; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Confirmation for sensitive operations, tool-input display, least-privilege scopes, policy enforcement at tool-call time, and prompt-attack scanning at user-input and tool-response points. <!-- SAF-TRACE: claims=SAF-T1309-C002,SAF-T1309-C003,SAF-T1309-C009,SAF-T1309-C010; sources=SRC-mcp-tools-2026-07-28,SRC-ms-prompt-shields-2026-07-31,SRC-mcp-security-2026-07-28,SRC-camel-2503.18813v2 -->
- **Residual Risk**: Classifiers can miss attacks or flag legitimate content, and capability systems require complete policy design and integration. <!-- SAF-TRACE: claims=SAF-T1309-C010,SAF-T1309-C012; sources=SRC-camel-2503.18813v2,SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->

### Known Breaches and Vulnerabilities

No qualifying direct production breach was identified in the bounded direct-authority review; the selected examples below are two disclosed vulnerabilities and one controlled demonstration. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C006,SAF-T1309-C007,SAF-T1309-C008; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773,SRC-cisa-kev-2026-09-01 -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-54135 / GHSA-4cxx-hrm3-49rm | Published 2025-08-02; Cursor. The GHSA lists affected versions through 1.2.1 and a 1.3.9 patch, while the CNA record describes versions before 1.3.9. | Indirect prompt injection could create a sensitive MCP settings file and trigger code execution without approval; Cursor blocked unapproved writes to MCP-sensitive files. | Direct vulnerability. | Version-range wording differs between the CNA and GHSA, and neither establishes production exploitation. <!-- SAF-TRACE: claims=SAF-T1309-C006; sources=SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-54135 --> |
| CVE-2025-53773 | Published 2025-08-12; GitHub Copilot with Visual Studio 2022 17.14 before 17.14.12. | A demonstrated prompt injection changed auto-approval settings and executed a local command; Microsoft fixed the issue in the August 2025 update. | Direct vulnerability. | The disclosed chain is a controlled demonstration and the CVE vector requires user interaction. <!-- SAF-TRACE: claims=SAF-T1309-C007; sources=SRC-cve-2025-53773,SRC-rehberger-cve-2025-53773 --> |
| AgentDojo | Submitted 2024-06-19; controlled Workspace, Slack, Travel, and Banking agent environments. | Untrusted tool-returned data caused attacker-goal tool actions; the benchmark evaluates defensive tradeoffs rather than shipping a product patch. | Direct demonstration. | Non-production and not MCP-specific. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C012; sources=SRC-agentdojo-2406.13352v3 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | High when a manipulated agent can invoke tools that read secrets or transmit protected data; otherwise bounded by tool authorization. <!-- SAF-TRACE: claims=SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-ghsa-cursor-4cxx-2025 --> |
| Integrity | High | High when write, transaction, configuration, or command tools are available under the victim's delegated identity. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C013; sources=SRC-agentdojo-2406.13352v3,SRC-cve-2025-53773 --> |
| Availability | High | High only where invoked tools can stop services, corrupt state, or execute host commands. <!-- SAF-TRACE: claims=SAF-T1309-C006,SAF-T1309-C007,SAF-T1309-C013; sources=SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773 --> |
| Scope | Multi-System | A single agent may bridge content, identity, and external services, but blast radius remains bounded by scopes, approvals, and tool capabilities. <!-- SAF-TRACE: claims=SAF-T1309-C009,SAF-T1309-C013; sources=SRC-mcp-security-2026-07-28,SRC-agentdojo-2406.13352v3 --> |

### Severity Conditions

- **Severity increases when**: Sensitive tools are auto-approved, broad scopes are pre-granted, tool results are treated as trusted instructions, or the agent can edit its own approval configuration. <!-- SAF-TRACE: claims=SAF-T1309-C006,SAF-T1309-C007,SAF-T1309-C009,SAF-T1309-C013; sources=SRC-ghsa-cursor-4cxx-2025,SRC-rehberger-cve-2025-53773,SRC-mcp-security-2026-07-28,SRC-agentdojo-2406.13352v3 -->
- **Severity decreases when**: Per-action approval, narrow scopes, sandboxing, or capability policies independently block high-risk effects. <!-- SAF-TRACE: claims=SAF-T1309-C002,SAF-T1309-C009,SAF-T1309-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2026-07-28,SRC-camel-2503.18813v2 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Prompt or content guardrail | User-input and tool-response attack annotations | timestamp, session_id, source_trust, attack_detected, filtered | Retain annotation mode and intervention point; classifiers can produce false positives and negatives. <!-- SAF-TRACE: claims=SAF-T1309-C003,SAF-T1309-C012; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 --> |
| MCP host or agent tool audit | Sensitive `tools/call`, file-write, configuration, transaction, or command event | timestamp, session_id, actor_id, server_id, tool_name, arguments_digest, risk_tier, approval_state, outcome | Correlate on the same session and actor; preserve redacted arguments and approval provenance. <!-- SAF-TRACE: claims=SAF-T1309-C002,SAF-T1309-C011; sources=SRC-mcp-tools-2026-07-28,SRC-ms-prompt-shields-2026-07-31 --> |

### Indicators of Compromise (IoCs)

- No technique-specific durable IoC is reliable because the same tools and arguments may be legitimate in an approved workflow. <!-- SAF-TRACE: claims=SAF-T1309-C011,SAF-T1309-C012; sources=SRC-agentdojo-2406.13352v3,SRC-ms-prompt-shields-2026-07-31 -->

### Behavioral Indicators

- A prompt-attack or untrusted-document marker followed by a high- or critical-risk tool call in the same session without a granted approval. <!-- SAF-TRACE: claims=SAF-T1309-C011; sources=SRC-ms-prompt-shields-2026-07-31,SRC-mcp-tools-2026-07-28 -->
- A prompt-derived write to an approval, agent, workspace, or MCP configuration file followed by a newly unapproved command-capable tool action. <!-- SAF-TRACE: claims=SAF-T1309-C006,SAF-T1309-C007; sources=SRC-ghsa-cursor-4cxx-2025,SRC-rehberger-cve-2025-53773 -->
- A sensitive tool call that diverges from the user's recorded intent, especially after the agent reads attacker-controlled content. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C011; sources=SRC-agentdojo-2406.13352v3,SRC-ms-prompt-shields-2026-07-31 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml). Do not duplicate the complete rule in this document.

- **Analytic Goal**: Identify a high-risk agent tool call that closely follows a direct or indirect prompt-attack marker and lacks a granted approval. <!-- SAF-TRACE: claims=SAF-T1309-C011; sources=SRC-ms-prompt-shields-2026-07-31,SRC-mcp-tools-2026-07-28,SRC-agentdojo-2406.13352v3 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1309-C011,SAF-T1309-C012; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->
- **Detection Logic**: Correlate an untrusted input with `attack_detected=true` to an attempted or executed high-risk tool call whose approval state is missing, denied, or not requested, keyed by session and actor. <!-- SAF-TRACE: claims=SAF-T1309-C011; sources=SRC-ms-prompt-shields-2026-07-31,SRC-mcp-tools-2026-07-28 -->
- **Correlation Window**: Five minutes in the example rule; tune to the agent's task duration. <!-- SAF-TRACE: claims=SAF-T1309-C011; sources=SRC-agentdojo-2406.13352v3,SRC-mcp-tools-2026-07-28 -->
- **Known False Positives**: Authorized red-team tests, classifier mistakes, and automation whose approval is recorded in a separate system. <!-- SAF-TRACE: claims=SAF-T1309-C012; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->
- **Known Limitations**: The rule misses successful injections without an attack marker, cannot prove causal influence, and depends on consistent risk and approval fields. <!-- SAF-TRACE: claims=SAF-T1309-C011,SAF-T1309-C012; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->
- **Tuning Guidance**: Baseline tool risk, preserve intervention-point context, join the system of record for approval, and suppress labeled exercises without suppressing real production sessions. <!-- SAF-TRACE: claims=SAF-T1309-C011,SAF-T1309-C012; sources=SRC-ms-prompt-shields-2026-07-31,SRC-mcp-tools-2026-07-28 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1309/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1309/test_detection_rule.py)
- **Expected Result**: Four matching cases, including a 300-second boundary and an expected legitimate lookalike, plus six nonmatching cases. <!-- SAF-TRACE: claims=SAF-T1309-C011,SAF-T1309-C012; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->
- **Last Validated**: 2026-09-01 via the [quality review](../../research/techniques/SAF-T1309/quality-review.yml).
- **Feasibility Waiver**: None; deterministic synthetic validation is provided in the [quality review](../../research/techniques/SAF-T1309/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **Per-action authorization**: Require a user-deniable confirmation for sensitive operations, display tool inputs, and keep server-side access controls independent of model output. <!-- SAF-TRACE: claims=SAF-T1309-C002; sources=SRC-mcp-tools-2026-07-28 -->
2. **Least-privilege and step-up scope**: Begin with baseline scopes and grant narrowly challenged scopes only when a privileged operation is attempted. <!-- SAF-TRACE: claims=SAF-T1309-C009; sources=SRC-mcp-security-2026-07-28 -->
3. **Control/data separation**: Prevent untrusted retrieved values from determining privileged control flow, and enforce tool-call policies using provenance-aware capabilities where feasible. <!-- SAF-TRACE: claims=SAF-T1309-C010; sources=SRC-camel-2503.18813v2 -->

### Detective Controls

1. **Guardrail annotations**: Scan user input and tool responses for direct and document attacks, retaining `detected` and `filtered` results for correlation. <!-- SAF-TRACE: claims=SAF-T1309-C003; sources=SRC-ms-prompt-shields-2026-07-31 -->
2. **Tool and elevation audit**: Log tool use, approvals, and scope-elevation events with correlation identifiers. <!-- SAF-TRACE: claims=SAF-T1309-C002,SAF-T1309-C009; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2026-07-28 -->

### Response Procedures

#### Immediate Actions

- Suspend the affected agent session and block pending sensitive tool calls while preserving prompt, tool, approval, and identity telemetry. <!-- SAF-TRACE: claims=SAF-T1309-C011; sources=SRC-mcp-tools-2026-07-28,SRC-ms-prompt-shields-2026-07-31 -->
- Revoke or narrow delegated scopes when an unapproved call reached an external service. <!-- SAF-TRACE: claims=SAF-T1309-C009,SAF-T1309-C013; sources=SRC-mcp-security-2026-07-28,SRC-agentdojo-2406.13352v3 -->

#### Investigation Steps

- Reconstruct the sequence from untrusted content ingestion through model decision, approval handling, `tools/call`, and external side effects. <!-- SAF-TRACE: claims=SAF-T1309-C002,SAF-T1309-C011; sources=SRC-mcp-tools-2026-07-28,SRC-ms-prompt-shields-2026-07-31 -->
- Determine whether any approval or MCP configuration was modified before the privileged action and whether the behavior matches a patched product vulnerability. <!-- SAF-TRACE: claims=SAF-T1309-C006,SAF-T1309-C007; sources=SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773 -->

#### Remediation

- Remove the attacker-controlled content, restore approval configuration, update affected products, and verify that sensitive operations again require explicit authorization. <!-- SAF-TRACE: claims=SAF-T1309-C002,SAF-T1309-C006,SAF-T1309-C007; sources=SRC-mcp-tools-2026-07-28,SRC-ghsa-cursor-4cxx-2025,SRC-cve-2025-53773 -->
- Add a regression case for the entry point and tool sequence, then tune correlation using known legitimate lookalikes. <!-- SAF-TRACE: claims=SAF-T1309-C011,SAF-T1309-C012; sources=SRC-ms-prompt-shields-2026-07-31,SRC-agentdojo-2406.13352v3 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Overlapping | SAF-T1102 covers prompt manipulation that affects text or planning but does not reach a privileged tool or approval-changing action. <!-- SAF-TRACE: claims=SAF-T1309-C004,SAF-T1309-C015; sources=SRC-agentdojo-2406.13352v3,SRC-mcp-security-2026-07-28 --> |
| [SAF-T1302: Agentic Confused Deputy](../SAF-T1302/README.md) | Alternative | SAF-T1302 covers unauthorized or direct privileged tool use caused by an authority or policy failure without prompt-derived model control. <!-- SAF-TRACE: claims=SAF-T1309-C013,SAF-T1309-C015; sources=SRC-agentdojo-2406.13352v3,SRC-mcp-security-2026-07-28 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Analogous | Both involve circumvention of a privilege-control mechanism, but T1548 does not model prompt-derived agent control flow or delegated tool authority. <!-- SAF-TRACE: claims=SAF-T1309-C014; sources=SRC-clean-t1301-attack-t1548 --> |

## References

1. **SRC-mcp-tools-2026-07-28**: [MCP Tools specification, protocol maintainers, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) - model-controlled tools, `tools/call`, security considerations, and audit guidance.
2. **SRC-mcp-security-2026-07-28**: [MCP Security Best Practices, protocol maintainers, 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) - least-privilege scopes, elevation logging, and adjacent mechanisms.
3. **SRC-ms-prompt-shields-2026-07-31**: [Prompt Shields in Microsoft Foundry, Microsoft Learn content team, 2026-07-31](https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/content-filter-prompt-shields) - direct/document attack classes, intervention points, fields, and limits.
4. **SRC-agentdojo-2406.13352v3**: [AgentDojo, Edoardo Debenedetti, Jie Zhang, Mislav Balunović, Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr, 2024](https://arxiv.org/html/2406.13352v3) - controlled agentic prompt-injection evaluation and defense limits.
5. **SRC-camel-2503.18813v2**: [Defeating Prompt Injections by Design, Edoardo Debenedetti, Ilia Shumailov, Tianqi Fan, Jamie Hayes, Nicholas Carlini, Daniel Fabian, Christoph Kern, Chongyang Shi, Andreas Terzis, and Florian Tramèr, 2025](https://arxiv.org/html/2503.18813v2) - capability-based tool-call policy enforcement and limitations.
6. **SRC-ghsa-cursor-4cxx-2025**: [Cursor advisory GHSA-4cxx-hrm3-49rm, published by hmwildermuth; reported by hxofir-a and MaccariTA, 2025](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm) - CVE-2025-54135 impact, affected versions, remediation, and credits.
7. **SRC-cve-2025-54135**: [CVE-2025-54135 record, GitHub CNA and CISA ADP Vulnrichment Team, 2025](https://cveawg.mitre.org/api/cve/CVE-2025-54135) - CNA affected range, CVSS, and exploitation assessment.
8. **SRC-cve-2025-53773**: [CVE-2025-53773 record, Microsoft Security Response Center and CISA ADP Vulnrichment Team, updated 2026](https://cveawg.mitre.org/api/cve/CVE-2025-53773) - affected Visual Studio versions, impact, patch reference, and exploitation assessment.
9. **SRC-rehberger-cve-2025-53773**: [GitHub Copilot: Remote Code Execution via Prompt Injection, wunderwuzzi, 2025](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) - controlled exploit chain and responsible-disclosure timeline.
10. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog JSON, CISA, 2026-09-01](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) - exact-candidate exploitation-catalog check.
11. **SRC-clean-t1301-attack-t1548**: [ATT&CK T1548 Abuse Elevation Control Mechanism, MITRE ATT&CK Team, version 2.0, 2026](https://attack.mitre.org/techniques/T1548/) - analogous privilege-control behavior and mapping limits.
12. **SRC-cursor-ghsa-24mc-g4xr-4395**: [Cursor advisory GHSA-24mc-g4xr-4395, published by hmwildermuth; reported by chaandrey, 2025](https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395) - adjacent direct configuration-substitution mechanism.
13. **SRC-jfsa-2025-6514**: [JFSA-2025-001290844, Or Peles and the JFrog Security Research Team, 2025](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/) - adjacent authorization-URL command injection mechanism.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft and evidence packet | Clean-room authoring agent |
