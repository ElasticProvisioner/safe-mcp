# SAF-T1102: Prompt Injection (Multiple Vectors)

## Overview

- **Tactic**: Execution (ATK-TA0002)
- **Technique ID**: SAF-T1102
- **Research Packet**: [research/techniques/SAF-T1102](../../research/techniques/SAF-T1102/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1102/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: High when model-facing content can influence an agent that can call consequential tools or access data across trust boundaries; impact remains bounded by the agent's effective authority and approval controls. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C011,SAF-T1102-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025,SRC-owasp-llm01-2025 -->
- **First Observed**: Not observed in a qualifying production incident; publicly demonstrated in MCP tool-description poisoning research published 2025-04-01. <!-- SAF-TRACE: claims=SAF-T1102-C006; sources=SRC-invariant-tpa-2025-04-01 -->
- **Last Updated**: 2026-09-01

## Scope

Prompt Injection (Multiple Vectors) covers attacker-controlled natural-language or multimodal instructions that enter model context and cause the model to treat untrusted content as authoritative directions. The defining boundary is crossed when content supplied through a user prompt, MCP prompt, resource, tool description, tool result, or external object returned by a tool redirects model-selected behavior. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C002,SAF-T1102-C003,SAF-T1102-C004,SAF-T1102-C005,SAF-T1102-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-mcp-prompts-2026,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025,SRC-greshake-ipi-2023 -->

### In Scope

- Direct injection through the user's instruction channel and indirect injection embedded in websites, files, messages, retrieved resources, or other external data processed by an agent. <!-- SAF-TRACE: claims=SAF-T1102-C005; sources=SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025,SRC-greshake-ipi-2023 -->
- Injection delivered through MCP prompt content, resources, tool descriptions, tool results, or external content reached by a tool. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C002,SAF-T1102-C003,SAF-T1102-C004; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-mcp-prompts-2026,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28 -->

### Out of Scope

- Training-time data poisoning, covered by [SAF-T2107](../SAF-T2107/README.md); this technique begins when attacker-controlled content is processed at inference time. <!-- SAF-TRACE: claims=SAF-T1102-C005; sources=SRC-nist-ai-100-2e2025,SRC-owasp-llm01-2025 -->
- Malicious server or tool code that performs harmful actions without redirecting model behavior, including software introduced through [SAF-T1006](../SAF-T1006/README.md). <!-- SAF-TRACE: claims=SAF-T1102-C001; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- Downstream collection, exfiltration, persistence, or command execution as separate behaviors; those outcomes are follow-on activity unless the injection itself is the behavior under analysis. <!-- SAF-TRACE: claims=SAF-T1102-C011,SAF-T1102-C017; sources=SRC-nist-ai-100-2e2025,SRC-mitre-t1059-current -->
- Safety-only jailbreaks that alter content policy compliance but do not cross an application authority or tool boundary. <!-- SAF-TRACE: claims=SAF-T1102-C005,SAF-T1102-C011; sources=SRC-nist-ai-100-2e2025,SRC-owasp-llm01-2025 -->

### Distinguishing Characteristics

The technique is distinguished by the model interpreting adversary-controlled content as instructions and then changing model-selected behavior. Merely connecting an untrusted server, returning false data, or running malicious code is insufficient unless the model's instruction authority is manipulated; the formal boundary is recorded in the [technique contract](../../research/techniques/SAF-T1102/technique-contract.yml). <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025 -->

## Description

An adversary places instructions where an MCP-enabled model will process them. Delivery can be direct, through a user-controlled prompt, or indirect, through content the system labels or intends as data. MCP supplies several model-facing paths: server-authored prompts, application-managed resources, model-visible tool descriptions, and tool results. <!-- SAF-TRACE: claims=SAF-T1102-C002,SAF-T1102-C003,SAF-T1102-C004,SAF-T1102-C005; sources=SRC-mcp-prompts-2026,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025,SRC-greshake-ipi-2023 -->

Execution occurs when the model gives the injected content greater practical authority than the intended task and changes its reasoning, tool selection, arguments, or data handling. Controlled MCP demonstrations have redirected agents through tool metadata, trusted tool results, and third-party platform content; their consequences included cross-server manipulation and disclosure of synthetic test data. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C006,SAF-T1102-C007,SAF-T1102-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->

The evidence supports an end-to-end demonstrated classification, not an observed-production classification. The public examples selected here are controlled demonstrations or a disclosed vulnerability, and the reviewed advisories report no known exploitation for the direct vulnerability. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C009; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-cve-2025-54135,SRC-ghsa-cursor-4cxx-2025 -->

## Attack Vectors

- **Primary Vector**: Indirect instructions embedded in external content that an MCP tool or resource returns to the model. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C003,SAF-T1102-C004,SAF-T1102-C005; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-nist-ai-100-2e2025 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1102-C002,SAF-T1102-C005,SAF-T1102-C006,SAF-T1102-C016; sources=SRC-mcp-prompts-2026,SRC-invariant-tpa-2025-04-01,SRC-owasp-llm01-2025,SRC-greshake-ipi-2023 -->
  - Direct user-prompt instructions that conflict with the application's intended authority. <!-- SAF-TRACE: claims=SAF-T1102-C005; sources=SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025 -->
  - Instructions hidden in MCP tool descriptions or server-authored prompt content. <!-- SAF-TRACE: claims=SAF-T1102-C002,SAF-T1102-C006; sources=SRC-mcp-prompts-2026,SRC-invariant-tpa-2025-04-01 -->
  - Visible, encoded, multilingual, visually hidden, or multimodal instructions in model-facing content. <!-- SAF-TRACE: claims=SAF-T1102-C016; sources=SRC-greshake-ipi-2023,SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025 -->
- **Affected Components**: MCP host, client, server-provided prompt, resource, tool metadata, tool result, model, and connected external service. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C002,SAF-T1102-C003,SAF-T1102-C004; sources=SRC-mcp-overview-2026,SRC-mcp-prompts-2026,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- **Trust Boundary Crossed**: Untrusted content is treated as an instruction authorized to influence model-selected activity. <!-- SAF-TRACE: claims=SAF-T1102-C005,SAF-T1102-C011; sources=SRC-nist-ai-100-2e2025 -->

## Technical Details

### Prerequisites

- The adversary can influence a user prompt, prompt template input, resource, tool description, tool result, or external object the agent will process. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C002,SAF-T1102-C003,SAF-T1102-C004,SAF-T1102-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-mcp-prompts-2026,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-nist-ai-100-2e2025 -->
- The host or model combines that content with an instruction-bearing context and lacks a deterministic policy that prevents the requested action. <!-- SAF-TRACE: claims=SAF-T1102-C011,SAF-T1102-C014,SAF-T1102-C015; sources=SRC-nist-ai-100-2e2025,SRC-camel-2025,SRC-ncsc-prompt-injection-2025 -->
- Consequential impact additionally requires effective tool, credential, data, or network authority and either no approval gate or an approval decision that does not surface the risk. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C011,SAF-T1102-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025,SRC-owasp-llm01-2025 -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies model-facing content and a reachable action or data boundary. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C011; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025 -->
2. **Delivery**: The adversary places an instruction in a direct prompt, prompt input, resource, tool description, tool result, or external object. <!-- SAF-TRACE: claims=SAF-T1102-C002,SAF-T1102-C003,SAF-T1102-C004,SAF-T1102-C005; sources=SRC-mcp-prompts-2026,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025 -->
3. **Trigger or Execution**: The host supplies the content to the model, which interprets the injected text or media as instructions. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-greshake-ipi-2023 -->
4. **Boundary Crossing**: The model selects or attempts an action outside the user's intended task or the content source's authority. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C011; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025 -->
5. **Objective**: The immediate result is redirected model behavior, potentially including unauthorized retrieval, disclosure, modification, or tool use. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C011; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025 -->
6. **Follow-On Activity**: Separate downstream behaviors can include data exfiltration or command execution and should be mapped independently when their definitions are met. <!-- SAF-TRACE: claims=SAF-T1102-C011,SAF-T1102-C017; sources=SRC-nist-ai-100-2e2025,SRC-mitre-t1059-current -->

### Example Scenario

An attacker posts a support message containing hidden instructions. A helpdesk agent asks an MCP-enabled assistant to summarize new messages. The trusted messaging tool returns the attacker's content, the model attempts an unapproved high-risk export tool call in the same session, and the host records the untrusted source, detector verdict, approval state, and denied action. This inert scenario adapts the documented tool-result mechanism without claiming a real incident. <!-- SAF-TRACE: claims=SAF-T1102-C007,SAF-T1102-C012,SAF-T1102-C013; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28 -->

```json
{
  "event_type": "model_content_received",
  "session_id": "demo-001",
  "channel": "mcp_tool_result",
  "trust_label": "untrusted",
  "detector_verdict": "suspicious",
  "content": "[inert test instruction omitted]"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1102-C001 | Multiple MCP content paths redirected model-selected actions in controlled demonstrations. | Demonstrated | SRC-invariant-tpa-2025-04-01, SRC-invariant-whatsapp-mcp-2025-04-07, SRC-invariant-github-mcp-2025 | Controlled tests, not production compromises. | <!-- SAF-TRACE: claims=SAF-T1102-C001; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
| SAF-T1102-C002 | MCP prompts are server-authored structured messages subject to injection validation. | Research-Derived | SRC-mcp-prompts-2026 | No prescribed detector. | <!-- SAF-TRACE: claims=SAF-T1102-C002; sources=SRC-mcp-prompts-2026 -->
| SAF-T1102-C003 | MCP resources can supply text or binary context, including optional automatic inclusion. | Research-Derived | SRC-mcp-resources-2026 | Automatic inclusion is optional. | <!-- SAF-TRACE: claims=SAF-T1102-C003; sources=SRC-mcp-resources-2026 -->
| SAF-T1102-C004 | MCP tools expose model-visible metadata and results, with validation and audit guidance. | Research-Derived | SRC-mcp-tools-2026-07-28, SRC-mcp-overview-2026 | Guidance does not prove semantic detection. | <!-- SAF-TRACE: claims=SAF-T1102-C004; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026 -->
| SAF-T1102-C005 | Direct injection uses the user channel; indirect injection arrives through external data. | Research-Derived | SRC-owasp-llm01-2025, SRC-nist-ai-100-2e2025, SRC-greshake-ipi-2023 | Labels vary by product. | <!-- SAF-TRACE: claims=SAF-T1102-C005; sources=SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025,SRC-greshake-ipi-2023 -->
| SAF-T1102-C006 | Tool-description poisoning and cross-server shadowing were demonstrated in Cursor. | Demonstrated | SRC-invariant-tpa-2025-04-01 | Specific controlled configuration. | <!-- SAF-TRACE: claims=SAF-T1102-C006; sources=SRC-invariant-tpa-2025-04-01 -->
| SAF-T1102-C007 | A trusted WhatsApp MCP result carrying an injected message disclosed synthetic contacts in a lab test. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07 | No production victim. | <!-- SAF-TRACE: claims=SAF-T1102-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07 -->
| SAF-T1102-C008 | A public issue redirected a GitHub MCP agent to expose private-repository test data through a public pull request. | Demonstrated | SRC-invariant-github-mcp-2025 | Demonstration repositories; not a GitHub server-code defect. | <!-- SAF-TRACE: claims=SAF-T1102-C008; sources=SRC-invariant-github-mcp-2025 -->
| SAF-T1102-C009 | CVE-2025-54135 chained prompt injection with an MCP-sensitive file to reach code execution before Cursor 1.3.9. | Demonstrated | SRC-cve-2025-54135, SRC-ghsa-cursor-4cxx-2025 | Separate injection opportunity required; no known exploitation. | <!-- SAF-TRACE: claims=SAF-T1102-C009; sources=SRC-cve-2025-54135,SRC-ghsa-cursor-4cxx-2025 -->
| SAF-T1102-C010 | InjecAgent measured configuration-specific attack success across a large tool-agent benchmark. | Demonstrated | SRC-injecagent-acl-2024 | Not a production incidence rate. | <!-- SAF-TRACE: claims=SAF-T1102-C010; sources=SRC-injecagent-acl-2024 -->
| SAF-T1102-C011 | NIST documents indirect injection through combined data/instruction channels and CIA outcomes. | Research-Derived | SRC-nist-ai-100-2e2025 | Concrete cases need independent support. | <!-- SAF-TRACE: claims=SAF-T1102-C011; sources=SRC-nist-ai-100-2e2025 -->
| SAF-T1102-C012 | Detection needs source-labeled model, tool, approval, and failed-action telemetry. | Research-Derived | SRC-ncsc-prompt-injection-2025, SRC-mcp-tools-2026-07-28 | Logging creates privacy and retention risk. | <!-- SAF-TRACE: claims=SAF-T1102-C012; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28 -->
| SAF-T1102-C013 | A bounded source-to-action correlation is a practical behavioral analytic. | Research-Derived | SRC-ncsc-prompt-injection-2025, SRC-invariant-github-mcp-2025, SRC-invariant-whatsapp-mcp-2025-04-07 | Keyword signals are bypassable and incomplete. | <!-- SAF-TRACE: claims=SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-invariant-github-mcp-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
| SAF-T1102-C014 | Least privilege, approvals, isolation, trust labeling, and deterministic enforcement constrain impact. | Research-Derived | SRC-owasp-llm01-2025, SRC-anthropic-pi-defenses-2025, SRC-camel-2025, SRC-mcp-tools-2026-07-28 | Controls can reduce utility and do not close every path. | <!-- SAF-TRACE: claims=SAF-T1102-C014; sources=SRC-owasp-llm01-2025,SRC-anthropic-pi-defenses-2025,SRC-camel-2025,SRC-mcp-tools-2026-07-28 -->
| SAF-T1102-C015 | Model-level and detector defenses retain material adaptive residual risk. | Research-Derived | SRC-nist-ai-100-2e2025, SRC-anthropic-pi-defenses-2025, SRC-adaptive-pi-defenses-2025, SRC-ncsc-prompt-injection-2025 | Results vary by model and threat model. | <!-- SAF-TRACE: claims=SAF-T1102-C015; sources=SRC-nist-ai-100-2e2025,SRC-anthropic-pi-defenses-2025,SRC-adaptive-pi-defenses-2025,SRC-ncsc-prompt-injection-2025 -->
| SAF-T1102-C016 | Injections can be hidden, encoded, multilingual, or multimodal. | Research-Derived | SRC-greshake-ipi-2023, SRC-owasp-llm01-2025, SRC-nist-ai-100-2e2025 | Obfuscation alone does not prove intent. | <!-- SAF-TRACE: claims=SAF-T1102-C016; sources=SRC-greshake-ipi-2023,SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025 -->
| SAF-T1102-C017 | ATT&CK T1059 is analogous only when the injection causes command-interpreter execution. | Research-Derived | SRC-mitre-t1059-current, SRC-nist-ai-100-2e2025 | Prompt interpretation alone is not T1059. | <!-- SAF-TRACE: claims=SAF-T1102-C017; sources=SRC-mitre-t1059-current,SRC-nist-ai-100-2e2025 -->

### Current State

- **Affected Environments**: MCP hosts and agents that place untrusted prompts, resources, tool metadata, tool results, or retrieved content into model context, especially when the model can invoke consequential tools. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C002,SAF-T1102-C003,SAF-T1102-C004,SAF-T1102-C011; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-mcp-prompts-2026,SRC-mcp-resources-2026,SRC-mcp-tools-2026-07-28,SRC-nist-ai-100-2e2025 -->
- **Known Exploitation**: Controlled end-to-end demonstrations and one direct disclosed vulnerability were identified; no qualifying production compromise or known exploitation of CVE-2025-54135 was established by the reviewed sources. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C009; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-cve-2025-54135,SRC-ghsa-cursor-4cxx-2025 -->
- **Available Protections**: MCP recommends validation, result sanitization, confirmation, and audit logging; additional controls include least privilege, isolation, trust labeling, and deterministic capability enforcement. <!-- SAF-TRACE: claims=SAF-T1102-C004,SAF-T1102-C014; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-overview-2026,SRC-owasp-llm01-2025,SRC-anthropic-pi-defenses-2025,SRC-camel-2025 -->
- **Residual Risk**: Semantic detection remains incomplete and adaptive attacks can bypass model-level defenses, so high-authority deployments must assume non-zero failure. <!-- SAF-TRACE: claims=SAF-T1102-C015; sources=SRC-nist-ai-100-2e2025,SRC-anthropic-pi-defenses-2025,SRC-adaptive-pi-defenses-2025,SRC-ncsc-prompt-injection-2025 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Invariant MCP tool poisoning | 2025-04-01; controlled Cursor setup | Tool-description poisoning and cross-server shadowing; constrain trust and show tool descriptions. | Direct demonstration | No production victim. | <!-- SAF-TRACE: claims=SAF-T1102-C006; sources=SRC-invariant-tpa-2025-04-01 -->
| Invariant WhatsApp MCP experiments | 2025-04-07; controlled WhatsApp and filesystem MCP setup | Redirected agent and exposed synthetic contacts; isolate tools and require approvals. | Direct demonstration | Synthetic data and lab setup. | <!-- SAF-TRACE: claims=SAF-T1102-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07 -->
| Invariant GitHub MCP demonstration | 2025-05-26; demonstration repositories | Public issue led to private test-data retrieval and public pull request; reduce token scope, approvals, and public/private mixing. | Direct demonstration | Authors identify an agent-architecture issue, not a GitHub MCP code defect. | <!-- SAF-TRACE: claims=SAF-T1102-C008; sources=SRC-invariant-github-mcp-2025 -->
| CVE-2025-54135 / GHSA-4cxx-hrm3-49rm | 2025-08; Cursor versions before 1.3.9 | Chained injection and MCP-sensitive file creation could enable code execution; fixed in 1.3.9. | Direct vulnerability | Separate injection opportunity required; reviewed enrichment reports no known exploitation. | <!-- SAF-TRACE: claims=SAF-T1102-C009; sources=SRC-cve-2025-54135,SRC-ghsa-cursor-4cxx-2025 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Controlled demonstrations disclosed synthetic private data when agents could read across trust boundaries. | <!-- SAF-TRACE: claims=SAF-T1102-C007,SAF-T1102-C008,SAF-T1102-C011; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025 -->
| Integrity | High | Injection can redirect tool selection, arguments, and state-changing actions when approval or deterministic policy is absent. | <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C011; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025 -->
| Availability | Medium | NIST includes availability violations, but the selected MCP examples primarily demonstrate confidentiality and integrity effects. | <!-- SAF-TRACE: claims=SAF-T1102-C011; sources=SRC-nist-ai-100-2e2025 -->
| Scope | Multi-System | A host can bridge multiple MCP servers and external services, but credentials, network reach, and approval controls limit the blast radius. | <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C006,SAF-T1102-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-owasp-llm01-2025 -->

### Severity Conditions

- **Severity increases when**: The agent has broad tokens, sensitive context, network reach, state-changing tools, automatic execution, or weak source/approval telemetry. <!-- SAF-TRACE: claims=SAF-T1102-C011,SAF-T1102-C012,SAF-T1102-C014; sources=SRC-nist-ai-100-2e2025,SRC-ncsc-prompt-injection-2025,SRC-owasp-llm01-2025 -->
- **Severity decreases when**: Credentials and tool scopes are narrow, untrusted content is isolated, consequential actions require informed approval, and deterministic policy blocks cross-boundary flows. <!-- SAF-TRACE: claims=SAF-T1102-C014; sources=SRC-owasp-llm01-2025,SRC-anthropic-pi-defenses-2025,SRC-camel-2025,SRC-mcp-tools-2026-07-28 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or client audit log | Prompt/resource ingestion, tool discovery, tool call, approval, result | timestamp, session_id, actor, server_id, tool_name, channel, trust_label, arguments_digest, approval_state, outcome | Preserve ordering and source provenance; protect or minimize content. | <!-- SAF-TRACE: claims=SAF-T1102-C012; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28 -->
| Model-security or application log | Detector verdict, instruction indicator, policy decision | timestamp, session_id, content_id, source_id, detector_verdict, indicator_type, policy_action | Record verdict version and distinguish detections from ground truth. | <!-- SAF-TRACE: claims=SAF-T1102-C012,SAF-T1102-C013,SAF-T1102-C015; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28,SRC-anthropic-pi-defenses-2025 -->

### Indicators of Compromise (IoCs)

- None known: prompt injection does not require a stable file, domain, account, or literal phrase, and hidden or encoded forms make content strings unsuitable as durable IoCs. <!-- SAF-TRACE: claims=SAF-T1102-C016; sources=SRC-greshake-ipi-2023,SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025 -->

### Behavioral Indicators

- Untrusted model-facing content with a suspicious detector verdict or instruction-like indicator followed by an unapproved high-risk tool attempt in the same session. <!-- SAF-TRACE: claims=SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- A tool call crosses from a public or low-trust content source into private data or a state-changing destination without an explicit user request. <!-- SAF-TRACE: claims=SAF-T1102-C007,SAF-T1102-C008,SAF-T1102-C013; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- Repeated denied or failed tool/API calls after new external content enters context can raise confidence but do not prove compromise. <!-- SAF-TRACE: claims=SAF-T1102-C012; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect a source-to-action sequence in which untrusted, suspicious model-facing content precedes an unapproved high-risk or cross-boundary tool call. <!-- SAF-TRACE: claims=SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- **Rule Status**: Experimental; synthetic validation passed. <!-- SAF-TRACE: claims=SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- **Detection Logic**: Correlate an untrusted content event carrying a detector signal with a later tool-call event in the same session when the action is high-risk or crosses a boundary and approval is missing or bypassed. <!-- SAF-TRACE: claims=SAF-T1102-C012,SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- **Correlation Window**: Five minutes, tunable to the host's normal agent-turn duration. <!-- SAF-TRACE: claims=SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- **Known False Positives**: Authorized red-team tests, security evaluation prompts, administrative workflows, and benign text that resembles instructions. <!-- SAF-TRACE: claims=SAF-T1102-C013,SAF-T1102-C016; sources=SRC-ncsc-prompt-injection-2025,SRC-greshake-ipi-2023,SRC-owasp-llm01-2025 -->
- **Known Limitations**: The rule misses injections without detector signals, text-only redirection, approved harmful actions, and events whose provenance or session identity is absent. <!-- SAF-TRACE: claims=SAF-T1102-C012,SAF-T1102-C013,SAF-T1102-C015,SAF-T1102-C016; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28,SRC-nist-ai-100-2e2025,SRC-adaptive-pi-defenses-2025 -->
- **Tuning Guidance**: Baseline high-risk tools, maintain source trust labels, exclude approved test sessions, and shorten or lengthen the window using observed turn duration. <!-- SAF-TRACE: claims=SAF-T1102-C012,SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28 -->

### Validation

- **Test Data**: [detection-fixtures.json](../../tests/SAF-T1102/detection-fixtures.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1102/test_detection_rule.py)
- **Expected Result**: [Three positive and four negative cases](../../tests/SAF-T1102/expected-results.json)
- **Last Validated**: 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- **Feasibility Waiver**: None; representative synthetic validation is feasible for this correlation analytic. <!-- SAF-TRACE: claims=SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->

## Mitigation Strategies

### Preventive Controls

1. **Constrain effective authority**: Give each session only the credentials, tools, data, and network access required for the current task. <!-- SAF-TRACE: claims=SAF-T1102-C014; sources=SRC-owasp-llm01-2025,SRC-anthropic-pi-defenses-2025,SRC-camel-2025 -->
2. **Enforce consequential-action approval**: Show the selected tool and material arguments, and require informed confirmation before state-changing or cross-boundary actions. <!-- SAF-TRACE: claims=SAF-T1102-C004,SAF-T1102-C014; sources=SRC-mcp-tools-2026-07-28,SRC-owasp-llm01-2025 -->
3. **Separate data from authority deterministically**: Label untrusted provenance and enforce policy outside the model so content cannot grant itself capabilities. <!-- SAF-TRACE: claims=SAF-T1102-C014,SAF-T1102-C015; sources=SRC-camel-2025,SRC-ncsc-prompt-injection-2025,SRC-nist-ai-100-2e2025 -->
4. **Validate model-facing MCP content**: Validate prompt input/output, tool results, and server metadata, while treating detection as risk reduction rather than proof of safety. <!-- SAF-TRACE: claims=SAF-T1102-C002,SAF-T1102-C004,SAF-T1102-C015; sources=SRC-mcp-prompts-2026,SRC-mcp-tools-2026-07-28,SRC-anthropic-pi-defenses-2025,SRC-adaptive-pi-defenses-2025 -->

### Detective Controls

1. **Source-to-action correlation**: Retain source labels, model-security verdicts, tool calls, approvals, outcomes, and failed actions under a common session identifier. <!-- SAF-TRACE: claims=SAF-T1102-C012,SAF-T1102-C013; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28 -->
2. **Review trust-boundary anomalies**: Alert when low-trust content is followed by access to higher-trust data or a consequential destination without a matching user request. <!-- SAF-TRACE: claims=SAF-T1102-C007,SAF-T1102-C008,SAF-T1102-C013; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-ncsc-prompt-injection-2025 -->

### Response Procedures

#### Immediate Actions

- Suspend the affected agent session and high-risk tool execution while preserving the content-to-action event chain. <!-- SAF-TRACE: claims=SAF-T1102-C012,SAF-T1102-C014; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28,SRC-owasp-llm01-2025 -->
- Revoke or rotate credentials if logs show attempted or successful access outside the intended task. <!-- SAF-TRACE: claims=SAF-T1102-C011,SAF-T1102-C014; sources=SRC-nist-ai-100-2e2025,SRC-owasp-llm01-2025 -->

#### Investigation Steps

- Reconstruct model inputs and outputs, source provenance, tool discovery, calls, arguments, approvals, results, and failed actions in timestamp order. <!-- SAF-TRACE: claims=SAF-T1102-C012; sources=SRC-ncsc-prompt-injection-2025,SRC-mcp-tools-2026-07-28 -->
- Identify the first attacker-controlled content object and determine which credentials, data, systems, or state-changing tools were reachable. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C011,SAF-T1102-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-nist-ai-100-2e2025,SRC-owasp-llm01-2025 -->

#### Remediation

- Remove or quarantine the injected object, unsafe server metadata, or vulnerable workflow and invalidate cached model context derived from it. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-owasp-llm01-2025 -->
- Reduce privileges, add deterministic source-to-capability policy and informed approvals, then replay the synthetic regression cases before restoration. <!-- SAF-TRACE: claims=SAF-T1102-C013,SAF-T1102-C014; sources=SRC-camel-2025,SRC-owasp-llm01-2025,SRC-mcp-tools-2026-07-28 -->
- For CVE-2025-54135, update Cursor to version 1.3.9 or later. <!-- SAF-TRACE: claims=SAF-T1102-C009; sources=SRC-cve-2025-54135,SRC-ghsa-cursor-4cxx-2025 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T2107: AI Model Poisoning via MCP Tool Training Data Contamination](../SAF-T2107/README.md) | Alternative | Changes learned behavior before inference; SAF-T1102 manipulates inference-time context. | <!-- SAF-TRACE: claims=SAF-T1102-C005; sources=SRC-nist-ai-100-2e2025,SRC-owasp-llm01-2025 -->
| [SAF-T1006: Malicious MCP-Server Installation](../SAF-T1006/README.md) | Co-occurring | Harm originates in installed server or tool code without requiring model redirection; SAF-T1102 requires instruction-authority manipulation. | <!-- SAF-TRACE: claims=SAF-T1102-C001; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Analogous | Apply only to follow-on command or script execution; natural-language prompt interpretation does not meet T1059 by itself. | <!-- SAF-TRACE: claims=SAF-T1102-C017; sources=SRC-mitre-t1059-current,SRC-nist-ai-100-2e2025 -->

### Additional Framework Mappings

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| OWASP Top 10 for LLM Applications 2025 | LLM01 | Prompt Injection | Supplies the direct/indirect taxonomy, common vectors, impacts, and layered mitigations used here. | <!-- SAF-TRACE: claims=SAF-T1102-C005,SAF-T1102-C014,SAF-T1102-C016; sources=SRC-owasp-llm01-2025 -->
| NIST AI 100-2e2025 | Sections 3.4-3.5 | Direct and Indirect Prompt Injection; Security of Agents | Supplies the combined data/instruction channel model and agent consequence taxonomy. | <!-- SAF-TRACE: claims=SAF-T1102-C005,SAF-T1102-C011; sources=SRC-nist-ai-100-2e2025 -->

## References

1. **SRC-mcp-overview-2026**: [Model Context Protocol Specification](https://modelcontextprotocol.io/specification/2026-07-28) - protocol roles, trust, and authorization guidance. <!-- SAF-TRACE: claims=SAF-T1102-C004; sources=SRC-mcp-overview-2026 -->
2. **SRC-mcp-prompts-2026**: [MCP Server Features - Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts) - prompt content and injection validation. <!-- SAF-TRACE: claims=SAF-T1102-C002; sources=SRC-mcp-prompts-2026 -->
3. **SRC-mcp-resources-2026**: [MCP Server Features - Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources) - resource context paths. <!-- SAF-TRACE: claims=SAF-T1102-C003; sources=SRC-mcp-resources-2026 -->
4. **SRC-mcp-tools-2026-07-28**: [MCP Server Features - Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) - model-visible tool metadata, results, and security guidance. <!-- SAF-TRACE: claims=SAF-T1102-C004,SAF-T1102-C012,SAF-T1102-C014; sources=SRC-mcp-tools-2026-07-28 -->
5. **SRC-invariant-tpa-2025-04-01**: [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) - controlled tool-description and shadowing demonstrations. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C006; sources=SRC-invariant-tpa-2025-04-01 -->
6. **SRC-invariant-whatsapp-mcp-2025-04-07**: [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) - controlled tool-result and cross-server demonstrations. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C007,SAF-T1102-C013; sources=SRC-invariant-whatsapp-mcp-2025-04-07 -->
7. **SRC-invariant-github-mcp-2025**: [MCP GitHub Vulnerability](https://invariantlabs.ai/blog/mcp-github-vulnerability) - controlled public-issue injection demonstration. <!-- SAF-TRACE: claims=SAF-T1102-C001,SAF-T1102-C008,SAF-T1102-C013; sources=SRC-invariant-github-mcp-2025 -->
8. **SRC-greshake-ipi-2023**: [Not what you've signed up for](https://arxiv.org/pdf/2302.12173.pdf) - indirect-injection mechanisms and representations. <!-- SAF-TRACE: claims=SAF-T1102-C005,SAF-T1102-C016; sources=SRC-greshake-ipi-2023 -->
9. **SRC-injecagent-acl-2024**: [InjecAgent](https://aclanthology.org/2024.findings-acl.624/) - benchmark composition and evaluated attack success. <!-- SAF-TRACE: claims=SAF-T1102-C010; sources=SRC-injecagent-acl-2024 -->
10. **SRC-nist-ai-100-2e2025**: [NIST AI 100-2e2025](https://doi.org/10.6028/NIST.AI.100-2e2025) - injection taxonomy, outcomes, agents, and mitigation limits. <!-- SAF-TRACE: claims=SAF-T1102-C005,SAF-T1102-C011,SAF-T1102-C015,SAF-T1102-C016,SAF-T1102-C017; sources=SRC-nist-ai-100-2e2025 -->
11. **SRC-owasp-llm01-2025**: [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) - vectors and mitigations. <!-- SAF-TRACE: claims=SAF-T1102-C005,SAF-T1102-C014,SAF-T1102-C016; sources=SRC-owasp-llm01-2025 -->
12. **SRC-cve-2025-54135**: [CVE-2025-54135](https://cveawg.mitre.org/api/cve/CVE-2025-54135) - official vulnerability record and exploitation enrichment. <!-- SAF-TRACE: claims=SAF-T1102-C009; sources=SRC-cve-2025-54135 -->
13. **SRC-ghsa-cursor-4cxx-2025**: [GHSA-4cxx-hrm3-49rm](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm) - maintainer advisory, remediation, and credits. <!-- SAF-TRACE: claims=SAF-T1102-C009; sources=SRC-ghsa-cursor-4cxx-2025 -->
14. **SRC-anthropic-pi-defenses-2025**: [Mitigating the risk of prompt injections in browser use](https://www.anthropic.com/research/prompt-injection-defenses) - layered safeguards and residual risk. <!-- SAF-TRACE: claims=SAF-T1102-C014,SAF-T1102-C015; sources=SRC-anthropic-pi-defenses-2025 -->
15. **SRC-camel-2025**: [Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813) - deterministic control/data-flow and capability enforcement. <!-- SAF-TRACE: claims=SAF-T1102-C014; sources=SRC-camel-2025 -->
16. **SRC-adaptive-pi-defenses-2025**: [The Attacker Moves Second](https://arxiv.org/abs/2510.09023) - adaptive evaluation of prompt-injection defenses. <!-- SAF-TRACE: claims=SAF-T1102-C015; sources=SRC-adaptive-pi-defenses-2025 -->
17. **SRC-ncsc-prompt-injection-2025**: [Prompt injection is not SQL injection](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection) - deterministic design, monitoring, and residual-risk guidance. <!-- SAF-TRACE: claims=SAF-T1102-C012,SAF-T1102-C013,SAF-T1102-C015; sources=SRC-ncsc-prompt-injection-2025 -->
18. **SRC-mitre-t1059-current**: [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/) - analogous follow-on command-interpreter mapping. <!-- SAF-TRACE: claims=SAF-T1102-C017; sources=SRC-mitre-t1059-current -->

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft, evidence packet, and tested analytic. | OpenAI Codex clean-room authoring agent |
