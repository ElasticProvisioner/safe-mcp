# SAF-T1301: Cross-Server Tool Shadowing

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1301
- **Research Packet**: [research/techniques/SAF-T1301](../../research/techniques/SAF-T1301/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1301/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Observed
- **Severity**: High
- **Severity Rationale**: A hostile server can influence use of a separately trusted tool, so impact can inherit that tool's data and action authority when the host does not isolate descriptor provenance. <!-- SAF-TRACE: claims=SAF-T1301-C005,SAF-T1301-C006; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01 -->
- **First Observed**: 2026, in an anonymized enterprise-agent pattern reported by Microsoft Incident Response. <!-- SAF-TRACE: claims=SAF-T1301-C002; sources=SRC-microsoft-tool-poisoning-2026-06-30 -->
- **Last Updated**: 2026-09-01

## Scope

Cross-Server Tool Shadowing occurs when an attacker-controlled or compromised server supplies semantic instructions in a tool descriptor that influence a model to invoke a different, trusted server's tool contrary to user or owner intent. The crossed boundary is the host's separation between untrusted descriptor provenance and trusted tool authority. <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

### In Scope

- A descriptor from one server refers to or behaviorally redirects a tool exposed by another server in the same model context. <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C004; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- The immediate outcome is unauthorized use or altered use of the trusted server's tool authority. <!-- SAF-TRACE: claims=SAF-T1301-C002,SAF-T1301-C003; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01 -->

### Out of Scope

- Poisoning that changes only selection or use of the malicious server's own tool is [SAF-T1001: Tool Poisoning Attack (TPA)](../SAF-T1001/README.md). <!-- SAF-TRACE: claims=SAF-T1301-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- Changing metadata after approval is [SAF-T1205: Persistent Tool Redefinition](../SAF-T1205/README.md); identical or similar tool-name registration is also separate, but no exact SAF catalog neighbor currently represents that collision-only boundary. <!-- SAF-TRACE: claims=SAF-T1301-C014; sources=SRC-clean-t1301-mcp-tools-draft,SRC-clean-t1301-unit42-shadowing -->
- Indirect prompt injection delivered in tool output or external content, and any later collection or exfiltration, are separate mechanisms or follow-on activity. <!-- SAF-TRACE: claims=SAF-T1301-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

### Distinguishing Characteristics

The defining observable is a provenance crossing: one server's descriptor semantically targets another server's tool. Neither a shared name nor invocation of the malicious tool is required. <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-clean-t1301-mcp-tools-draft -->

## Description

MCP tools are model-controlled, and a tool definition includes human-readable descriptive metadata. A host commonly lists available tools and supplies their definitions to the model before executing a selected call. <!-- SAF-TRACE: claims=SAF-T1301-C001; sources=SRC-mcp-tools-2025-11-25 -->

An adversarial descriptor can therefore act on the shared decision context rather than only describe its own implementation. In the documented shadowing demonstration, a malicious server's descriptor imposed additional behavior on a trusted email tool, redirecting the trusted tool's action even though the malicious tool itself did not need to run. <!-- SAF-TRACE: claims=SAF-T1301-C003; sources=SRC-invariant-tpa-2025-04-01 -->

Microsoft Incident Response later reported observing the pattern in 2026 enterprise-agent activity involving a third-party enrichment server and trusted finance and messaging tools. The report withholds affected organizations and detailed indicators, so it establishes production observation but not prevalence. <!-- SAF-TRACE: claims=SAF-T1301-C002; sources=SRC-microsoft-tool-poisoning-2026-06-30 -->

## Attack Vectors

- **Primary Vector**: Registration of an attacker-controlled server whose tool descriptor embeds a semantic reference to a trusted server's tool. <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Secondary Vectors**: Compromise of an already configured server, or a supply-chain change that gives an adversary control of its descriptors. <!-- SAF-TRACE: claims=SAF-T1301-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Affected Components**: MCP host or client, model context, malicious server descriptor, trusted server tool, and the trusted tool's downstream service. <!-- SAF-TRACE: claims=SAF-T1301-C001,SAF-T1301-C005; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->
- **Trust Boundary Crossed**: Untrusted server metadata influences a call authorized through a separately trusted server. <!-- SAF-TRACE: claims=SAF-T1301-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

## Technical Details

### Prerequisites

- The adversary controls descriptor text for a server visible to the host. <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C004; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- A trusted tool with useful authority is simultaneously visible in the model context. <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-microsoft-tool-poisoning-2026-06-30 -->
- The host permits the model to interpret cross-server descriptor semantics without deterministic provenance isolation or an effective approval boundary. <!-- SAF-TRACE: claims=SAF-T1301-C007; sources=SRC-clean-t1301-openai-mcp-guide -->

### Attack Flow

1. **Setup**: The adversary makes a server and its crafted descriptor available to a multi-server agent session. <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C004; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
2. **Delivery**: The host lists the server's tool definition into the model-visible tool context. <!-- SAF-TRACE: claims=SAF-T1301-C001; sources=SRC-mcp-tools-2025-11-25 -->
3. **Trigger**: A user request makes a trusted tool relevant, while the malicious descriptor adds instructions about that tool's selection or arguments. <!-- SAF-TRACE: claims=SAF-T1301-C003; sources=SRC-invariant-tpa-2025-04-01 -->
4. **Boundary Crossing**: The model treats instructions from the untrusted descriptor as applicable to the separately trusted tool. <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
5. **Objective**: The trusted tool is invoked with behavior or arguments inconsistent with the user's request or the owner's policy. <!-- SAF-TRACE: claims=SAF-T1301-C002,SAF-T1301-C003; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01 -->
6. **Follow-On Activity**: Consequences depend on the trusted tool and can include unauthorized disclosure or state change. <!-- SAF-TRACE: claims=SAF-T1301-C006; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01 -->

### Example Scenario

An organization connects an untrusted enrichment server and a trusted mail server to one agent. The enrichment descriptor refers to the trusted mail tool and attempts to alter its recipient behavior; a provenance-aware host quarantines the reference before either tool is called. <!-- SAF-TRACE: claims=SAF-T1301-C002,SAF-T1301-C010; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-mcp-scan-2025 -->

```json
{"source_server":"untrusted-enrichment","descriptor_reference":"trusted-mail/send_email","requested_recipient":"user@example.invalid","policy":"quarantine cross-server reference"}
```
<!-- SAF-TRACE: claims=SAF-T1301-C010; sources=SRC-invariant-mcp-scan-2025 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1301-C002 | Microsoft Incident Response reported observing cross-server instruction override in 2026 enterprise-agent activity. | Observed | SRC-microsoft-tool-poisoning-2026-06-30: Microsoft Incident Response | Organizations, exact event dates, and indicators are withheld. |
| SAF-T1301-C003 | Invariant demonstrated a malicious descriptor changing a trusted email tool's behavior in Cursor. | Demonstrated | SRC-invariant-tpa-2025-04-01: Invariant Labs | A controlled demonstration does not establish prevalence. |
| SAF-T1301-C004 | A controlled study evaluated shadowing in shared MCP context across multiple models. | Demonstrated | SRC-jamshidi-2026-arxiv-2512-06556: Jamshidi et al. | The study used synthetic scenarios rather than a production deployment. |
| SAF-T1301-C005 | The technique is the cross-provenance application of one server's descriptor instructions to another server's trusted tool. | Research-Derived | SRC-invariant-tpa-2025-04-01; SRC-jamshidi-2026-arxiv-2512-06556 | This is a framework boundary synthesized from direct evidence. |

### Current State

- **Affected Environments**: Multi-server agent sessions where model-visible descriptors from one trust domain coexist with tools from another. <!-- SAF-TRACE: claims=SAF-T1301-C004,SAF-T1301-C005; sources=SRC-jamshidi-2026-arxiv-2512-06556,SRC-invariant-tpa-2025-04-01 -->
- **Known Exploitation**: One anonymized 2026 production pattern is reported, alongside public demonstrations and controlled evaluation. <!-- SAF-TRACE: claims=SAF-T1301-C002,SAF-T1301-C003,SAF-T1301-C004; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Available Protections**: Server allowlisting, descriptor review and pinning, per-call approvals, least privilege, and correlation of server, tool, and approval logs. <!-- SAF-TRACE: claims=SAF-T1301-C007; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-clean-t1301-openai-mcp-guide,SRC-invariant-tpa-2025-04-01 -->
- **Residual Risk**: Soft metadata and annotations are not enforcement; compromised trusted servers and implicit references can evade simple trust or text checks. <!-- SAF-TRACE: claims=SAF-T1301-C009; sources=SRC-mcp-annotations-2026-03-16,SRC-invariant-mcp-scan-2025 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Microsoft enterprise-agent pattern | Reported 2026; finance workflow with trusted business-data and messaging tools plus a third-party enrichment server | Sensitive finance data was collected and exfiltrated; Microsoft recommends allowlists, metadata inspection, DLP, approvals, and correlated logging. | Direct production incident | The source anonymizes organizations and detailed telemetry. | <!-- SAF-TRACE: claims=SAF-T1301-C002,SAF-T1301-C007; sources=SRC-microsoft-tool-poisoning-2026-06-30 -->
| Invariant Cursor shadowing demonstration | 2025; Cursor with a malicious server and trusted email tool | Trusted email behavior was redirected; suggested controls include visible descriptors, pinning, and cross-server guardrails. | Direct demonstration | Lab evidence does not show a production victim. | <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C007; sources=SRC-invariant-tpa-2025-04-01 -->
| Descriptor-level manipulation study | Revised 2026; synthetic shared-context scenarios across three model families | Unsafe tool calls bypassed baseline defenses in controlled tests; layered semantic vetting and runtime guardrails were evaluated. | Direct demonstration | Results are model- and prompt-dependent and not a production incidence rate. | <!-- SAF-TRACE: claims=SAF-T1301-C004; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A trusted read or communication tool can disclose sensitive data when its invocation is redirected. | <!-- SAF-TRACE: claims=SAF-T1301-C002,SAF-T1301-C006; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01 -->
| Integrity | High | A trusted action tool can receive attacker-influenced arguments when approvals do not expose the provenance crossing. | <!-- SAF-TRACE: claims=SAF-T1301-C003,SAF-T1301-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-microsoft-tool-poisoning-2026-06-30 -->
| Availability | Low | Availability effects are possible only when the shadowed tool can alter or disrupt resources; direct public evidence reviewed here emphasizes disclosure and redirection. | <!-- SAF-TRACE: claims=SAF-T1301-C006; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01 -->
| Scope | Multi-System | The malicious descriptor, trusted tool, and downstream service can span separate trust domains, while the blast radius remains bounded by exposed tool authorities. | <!-- SAF-TRACE: claims=SAF-T1301-C006; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01 -->

### Severity Conditions

- **Severity increases when** trusted tools can read sensitive data, send externally, or modify state without specific approval. <!-- SAF-TRACE: claims=SAF-T1301-C006,SAF-T1301-C007; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-clean-t1301-openai-mcp-guide -->
- **Severity decreases when** tools are narrowly scoped, descriptors are pinned and reviewed, cross-server references are isolated, and calls require informed approval. <!-- SAF-TRACE: claims=SAF-T1301-C007; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01,SRC-clean-t1301-openai-mcp-guide -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host tool inventory | Descriptor registration or change | timestamp, session, source server ID and trust, tool name, descriptor hash, referenced server and tool names, review state | Preserve raw descriptors under appropriate access controls and normalize cross-server references. | <!-- SAF-TRACE: claims=SAF-T1301-C008; sources=SRC-invariant-mcp-scan-2025,SRC-microsoft-tool-poisoning-2026-06-30 -->
| MCP call and approval audit | Tool selection, approval, and execution | session, server, tool, arguments, approval decision, actor, result | Correlate the descriptor's provenance with subsequent trusted-tool calls. | <!-- SAF-TRACE: claims=SAF-T1301-C008,SAF-T1301-C009; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-clean-t1301-openai-mcp-guide -->

### Indicators of Compromise (IoCs)

- No durable universal IoC is known; the relevant signal is behavioral and deployment-specific. <!-- SAF-TRACE: claims=SAF-T1301-C009; sources=SRC-invariant-mcp-scan-2025,SRC-mcp-annotations-2026-03-16 -->

### Behavioral Indicators

- An untrusted descriptor explicitly names a server or tool outside its own provenance domain without an approved orchestration purpose. <!-- SAF-TRACE: claims=SAF-T1301-C010; sources=SRC-invariant-mcp-scan-2025 -->
- A trusted tool call follows registration or change of a foreign descriptor that refers to it, especially when arguments differ from the user's stated request. <!-- SAF-TRACE: claims=SAF-T1301-C008,SAF-T1301-C009; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-mcp-scan-2025 -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Flag unreviewed explicit cross-server references in descriptors from untrusted servers. <!-- SAF-TRACE: claims=SAF-T1301-C010; sources=SRC-invariant-mcp-scan-2025 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1301-C010; sources=SRC-invariant-mcp-scan-2025 -->
- **Detection Logic**: Match descriptor-registration events where the source is untrusted, another server is referenced, and that reference lacks approval. <!-- SAF-TRACE: claims=SAF-T1301-C010; sources=SRC-invariant-mcp-scan-2025 -->
- **Known False Positives**: Reviewed orchestration tools and documentation descriptors may legitimately reference other servers. <!-- SAF-TRACE: claims=SAF-T1301-C009; sources=SRC-invariant-mcp-scan-2025 -->
- **Known Limitations**: Implicit, obfuscated, or dynamically assembled references and compromised servers still labeled trusted can evade this static heuristic. <!-- SAF-TRACE: claims=SAF-T1301-C009; sources=SRC-invariant-mcp-scan-2025,SRC-mcp-annotations-2026-03-16 -->
- **Tuning Guidance**: Maintain an explicit review record for permitted source-to-target server relationships and correlate alerts with trusted-tool calls. <!-- SAF-TRACE: claims=SAF-T1301-C008,SAF-T1301-C010; sources=SRC-invariant-mcp-scan-2025,SRC-microsoft-tool-poisoning-2026-06-30 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1301/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1301/test_detection_rule.py)
- **Expected Result**: Eight deterministic cases pass, including two alerts and six non-alerts, as defined in [test-logs.json](../../tests/SAF-T1301/test-logs.json).
- **Last Validated**: 2026-09-01, recorded in the [quality review](../../research/techniques/SAF-T1301/quality-review.yml).
- **Feasibility Waiver**: None; see the [quality review](../../research/techniques/SAF-T1301/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)**: Admit only reviewed servers and prefer official provider-operated endpoints for sensitive integrations. <!-- SAF-TRACE: claims=SAF-T1301-C007; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-clean-t1301-openai-mcp-guide -->
2. **[SAF-M-2: Cryptographic Integrity for Tool Descriptions](../../mitigations/SAF-M-2/README.md)**: Pin reviewed descriptors and prevent one server's metadata from silently governing another server's tool. <!-- SAF-TRACE: claims=SAF-T1301-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-ms-redteam-update-2026 -->
3. **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Restrict allowed tools and require approvals that show server, tool, arguments, and relevant descriptor provenance. <!-- SAF-TRACE: claims=SAF-T1301-C007; sources=SRC-clean-t1301-openai-mcp-guide,SRC-microsoft-tool-poisoning-2026-06-30 -->

### Detective Controls

1. Scan new and changed descriptors for cross-server references and review them before exposure to the model. <!-- SAF-TRACE: claims=SAF-T1301-C008,SAF-T1301-C010; sources=SRC-invariant-mcp-scan-2025,SRC-microsoft-tool-poisoning-2026-06-30 -->
2. Correlate descriptor versions, server identity, approvals, and trusted-tool invocations within each session. <!-- SAF-TRACE: claims=SAF-T1301-C008; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-clean-t1301-openai-mcp-guide -->

### Response Procedures

- Disable the suspect server, preserve descriptor and call logs, and suspend affected agent sessions. <!-- SAF-TRACE: claims=SAF-T1301-C011; sources=SRC-microsoft-tool-poisoning-2026-06-30 -->
- Review trusted-tool calls made after the descriptor appeared; contain downstream actions and rotate credentials if exposure is confirmed. <!-- SAF-TRACE: claims=SAF-T1301-C011; sources=SRC-microsoft-tool-poisoning-2026-06-30 -->
- Restore only reviewed descriptor versions and add explicit source-to-target policy before re-enabling the integration. <!-- SAF-TRACE: claims=SAF-T1301-C007,SAF-T1301-C011; sources=SRC-microsoft-tool-poisoning-2026-06-30,SRC-invariant-tpa-2025-04-01 -->

## Related Techniques

- **[SAF-T1001: Tool Poisoning Attack (TPA)](../SAF-T1001/README.md)**: The malicious descriptor governs its own tool rather than a different trusted server's tool. <!-- SAF-TRACE: claims=SAF-T1301-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **[SAF-T1205: Persistent Tool Redefinition](../SAF-T1205/README.md)**: The defining event is a descriptor change after approval rather than cross-server semantic influence. <!-- SAF-TRACE: claims=SAF-T1301-C005; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->

Tool Name Collision is another adjacent boundary: its ambiguity arises from identical or similar registered names, while SAF-T1301 does not require a collision. No exact SAF catalog neighbor currently represents that collision-only behavior. <!-- SAF-TRACE: claims=SAF-T1301-C014; sources=SRC-clean-t1301-mcp-tools-draft,SRC-clean-t1301-unit42-shadowing -->

## MITRE ATT&CK Mapping

- **T1548, Abuse Elevation Control Mechanism — Analogous**: Both concern obtaining or exercising higher authority, but T1548 describes abuse of operating-system elevation controls, whereas this technique crosses semantic provenance and tool-authority boundaries in an agent host. <!-- SAF-TRACE: claims=SAF-T1301-C012; sources=SRC-clean-t1301-attack-t1548 -->

## References

- **SRC-mcp-tools-2025-11-25**: Model Context Protocol contributors, [Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
- **SRC-clean-t1301-mcp-tools-draft**: Model Context Protocol contributors, [Draft Tools specification](https://modelcontextprotocol.io/specification/draft/server/tools).
- **SRC-mcp-annotations-2026-03-16**: Ola Hungerford, Sam Morrow, and Luca Chang, [Tool Annotations as Risk Vocabulary](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/).
- **SRC-invariant-tpa-2025-04-01**: Luca Beurer-Kellner and Marc Fischer, [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks).
- **SRC-invariant-mcp-scan-2025**: Luca Beurer-Kellner and Marc Fischer, [Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan).
- **SRC-jamshidi-2026-arxiv-2512-06556**: Saeid Jamshidi, Arghavan Moradi Dakhel, Kawser Wazed Nafi, and Foutse Khomh, [Semantic Attacks on Tool-Augmented LLMs](https://arxiv.org/abs/2512.06556).
- **SRC-microsoft-tool-poisoning-2026-06-30**: Microsoft Defender Experts Cybersecurity Incident Response, [Securing AI agents as AI tools move from reading to acting](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/).
- **SRC-ms-redteam-update-2026**: Microsoft AI Red Team, [Updating our taxonomy of failure modes in agentic AI systems](https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/).
- **SRC-clean-t1301-openai-mcp-guide**: OpenAI, [MCP and Connectors guide](https://developers.openai.com/api/docs/guides/tools-connectors-mcp).
- **SRC-clean-t1301-unit42-shadowing**: Palo Alto Networks Unit 42, [Agent Session Smuggling in Agent2Agent Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/).
- **SRC-clean-t1301-attack-t1548**: MITRE, [T1548: Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/).

## Version History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | OpenAI Codex clean-room authoring agent | Initial independently researched technique and evidence packet. |
