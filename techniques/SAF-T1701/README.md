# SAF-T1701: Cross-Tool Contamination

- **Tactic**: Lateral Movement (ATK-TA0008)
- **Technique ID**: SAF-T1701
- **Evidence Status**: Demonstrated
- **Documentation Status**: Draft
- **Severity**: High
- **First Observed**: Controlled agent-tool evaluations published in 2024 <!-- SAF-TRACE: claims=SAF-T1701-C002; sources=SRC-injecagent-2024 -->
- **Last Updated**: 2026-09-02
- **Research Packet**: [source-or-omit evidence](../../research/techniques/SAF-T1701/source-coverage.yml)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1701/traceability-ledger.yml)

## Overview

Cross-Tool Contamination occurs when adversary-controlled content returned by one tool is interpreted as instruction-bearing context and causes the host or model to invoke a different tool across a capability, server, data, or authorization boundary. <!-- SAF-TRACE: claims=SAF-T1701-C002; sources=SRC-injecagent-2024 -->

The immediate adversary objective is to pivot from a data channel exposed by one tool into capabilities held by another tool without a matching, explicit user request. <!-- SAF-TRACE: claims=SAF-T1701-C002,SAF-T1701-C003; sources=SRC-injecagent-2024,SRC-invariant-github-mcp-2025 -->

## Scope

This technique requires a source-tool result influenced by an adversary, a later call to a distinct tool or server in the same execution context, and a causal link between the untrusted result and that later call. <!-- SAF-TRACE: claims=SAF-T1701-C002; sources=SRC-injecagent-2024 -->

Tool-description poisoning before invocation, a direct malicious user prompt, and a single-tool input-validation flaw are neighboring mechanisms rather than instances of this technique. <!-- SAF-TRACE: claims=SAF-T1701-C012; sources=SRC-invariant-tpa-2025-04-01 -->

The technique ends at the cross-tool pivot; collection, exfiltration, modification, or execution performed afterward is a downstream impact. <!-- SAF-TRACE: claims=SAF-T1701-C002; sources=SRC-injecagent-2024 -->

## Description

MCP hosts can assemble tools from multiple servers, and tool results can contain structured or unstructured content that the model consumes. The specification labels tools model-controlled and requires servers to validate inputs, enforce access controls, rate-limit calls, and sanitize outputs; clients are advised to show tool inputs, confirm sensitive operations, validate results, and log usage. <!-- SAF-TRACE: claims=SAF-T1701-C001; sources=SRC-mcp-tools-2025-11-25 -->

The security risk is a property of the combined session: a tool that exposes untrusted data can taint the execution path before a separate tool with sensitive or outward-facing capability is selected. Static annotations may inform host policy, but they neither make the model resist injection nor enforce isolation. <!-- SAF-TRACE: claims=SAF-T1701-C008; sources=SRC-mcp-annotations-2026-03-16 -->

## Attack Vectors

- **Collaborative content**: an issue, review, message, document, or similar record is returned by a source tool and embeds instructions that redirect later tool use. <!-- SAF-TRACE: claims=SAF-T1701-C002,SAF-T1701-C003,SAF-T1701-C004; sources=SRC-injecagent-2024,SRC-invariant-github-mcp-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Cross-server pivot**: content obtained through one server induces a call to another server that can read sensitive data, write externally, or execute an action. <!-- SAF-TRACE: claims=SAF-T1701-C004,SAF-T1701-C005; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invisible-prompts-2025 -->
- **Over-broad tool grants**: an authorization defect can amplify the pivot by making tools available to low-privilege users or prompt-injected content that should not be authorized to call them. <!-- SAF-TRACE: claims=SAF-T1701-C006; sources=SRC-vulncheck-cve-2026-58168,SRC-nvd-cve-2026-58168 -->

## Technical Details

The defining sequence is: a source tool returns adversary-influenced data; the host places that result in model context; the result changes planning; and a distinct target tool is called with sensitive arguments or effect. The cross-tool edge, not a particular payload phrase, is the stable behavioral invariant. <!-- SAF-TRACE: claims=SAF-T1701-C002,SAF-T1701-C007; sources=SRC-injecagent-2024,SRC-invariant-toxic-flow-2025 -->

In a controlled GitHub MCP demonstration, content in a public issue redirected an agent that had private-repository access and caused private material to be placed in a public pull request. The researchers described this as an architectural agent/tool-flow problem rather than a defect in the server code. <!-- SAF-TRACE: claims=SAF-T1701-C003; sources=SRC-invariant-github-mcp-2025 -->

In a controlled WhatsApp MCP demonstration, an attacker message surfaced through a listing tool and induced subsequent use of other capabilities to disclose contact information. A separate experiment on the same page used malicious tool metadata and is excluded from this technique. <!-- SAF-TRACE: claims=SAF-T1701-C004,SAF-T1701-C012; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01 -->

An ACL 2025 controlled demonstration placed a hidden instruction in external content returned to an agent and observed an MCP email tool being used to transmit protected data. <!-- SAF-TRACE: claims=SAF-T1701-C005; sources=SRC-invisible-prompts-2025 -->

DeepTutor before 1.4.10 omitted a deny result when an MCP-tool grant was absent, allowing low-privilege users or prompt-injected content to enumerate and invoke configured tools. The vendor advisory record and NVD identify 1.4.10 as the fixed version; this is an enabling authorization vulnerability, not by itself proof of a production cross-tool incident. <!-- SAF-TRACE: claims=SAF-T1701-C006; sources=SRC-vulncheck-cve-2026-58168,SRC-nvd-cve-2026-58168 -->

## Evidence and Current State

Controlled demonstrations in an academic benchmark and independent MCP case studies establish the end-to-end source-result-to-different-tool mechanism. <!-- SAF-TRACE: claims=SAF-T1701-C002,SAF-T1701-C003,SAF-T1701-C004,SAF-T1701-C005; sources=SRC-injecagent-2024,SRC-invariant-github-mcp-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invisible-prompts-2025 -->

The reviewed incident and vulnerability corpus did not yield a directly documented production incident; the evidence label therefore remains Demonstrated rather than Observed. Search scope and exclusions are recorded in the [source coverage ledger](../../research/techniques/SAF-T1701/source-coverage.yml).

### Evidence Summary

| Claim | Summary | Evidence |
|---|---|---|
| SAF-T1701-C001 | MCP tool results enter model-controlled workflows, while the protocol assigns result validation, confirmation, access control, sanitization, and logging duties to implementations. | SRC-mcp-tools-2025-11-25 |
| SAF-T1701-C002 | Empirical research formalizes and tests indirect instructions arriving through one tool result and triggering a different tool. | SRC-injecagent-2024 |
| SAF-T1701-C003 | A controlled GitHub MCP demonstration crossed from public issue content to private-repository access and a public write. | SRC-invariant-github-mcp-2025 |
| SAF-T1701-C004 | A controlled WhatsApp MCP demonstration crossed from an attacker-controlled message returned by one operation into use of another capability. | SRC-invariant-whatsapp-mcp-2025-04-07 |
| SAF-T1701-C005 | A controlled MCP experiment crossed from untrusted external content to an email tool with sensitive data. | SRC-invisible-prompts-2025 |
| SAF-T1701-C006 | CVE-2026-58168 removed an authorization boundary around configured MCP tools before DeepTutor 1.4.10. | SRC-vulncheck-cve-2026-58168, SRC-nvd-cve-2026-58168 |
| SAF-T1701-C007 | Cross-tool dataflow is a more durable detection basis than prompt-text matching alone. | SRC-invariant-toxic-flow-2025, SRC-adaptive-attacks-2025 |
| SAF-T1701-C008 | Session taint and host-enforced approval or blocking are appropriate controls when untrusted-data and impact-capable tools coexist. | SRC-mcp-annotations-2026-03-16 |
| SAF-T1701-C009 | Correlation needs a session identifier plus tool-call identity, arguments, result, trust, approval, and effect fields. | SRC-otel-genai-2026, SRC-otel-session-2026, SRC-mcp-tools-2025-11-25 |
| SAF-T1701-C010 | Proposed detection is behavioral and testable but does not establish universal accuracy; content-only defenses are bypassable and may have false positives or negatives. | SRC-adaptive-attacks-2025, SRC-formal-security-2024 |
| SAF-T1701-C011 | Confirmation, least privilege, result validation, output sanitization, isolation, and cross-tool flow policy reduce the defining pivot. | SRC-mcp-tools-2025-11-25, SRC-mcp-annotations-2026-03-16 |
| SAF-T1701-C012 | Tool-description poisoning can shadow a trusted tool but precedes invocation and is a neighboring mechanism. | SRC-invariant-tpa-2025-04-01 |
| SAF-T1701-C013 | ATT&CK T1080 is an analogy for adversary-controlled shared content affecting another execution context, not an exact protocol mapping. | SRC-mitre-t1080-2025 |

## Impact Assessment

Severity is High because the pivot can combine a low-trust content source with otherwise legitimate tools that read private data, publish externally, modify state, or execute code; realized impact remains bounded by the target tool's effective permissions and approval path. <!-- SAF-TRACE: claims=SAF-T1701-C003,SAF-T1701-C004,SAF-T1701-C005,SAF-T1701-C006; sources=SRC-invariant-github-mcp-2025,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invisible-prompts-2025,SRC-vulncheck-cve-2026-58168 -->

## Detection Methods

Correlate an untrusted source-tool result with a later high-impact call to a different tool or server in the same session, especially when the call lacks explicit user intent or approval and carries values derived from the earlier result. <!-- SAF-TRACE: claims=SAF-T1701-C007,SAF-T1701-C009; sources=SRC-invariant-toxic-flow-2025,SRC-otel-genai-2026,SRC-otel-session-2026 -->

The repository analytic uses a ten-minute window and requires an instruction-like untrusted result followed by a distinct high-impact tool call. Its executable fixtures cover positive sequences, same-tool activity, different sessions, expired windows, trusted content, low-impact calls, and explicitly approved user workflows. See the [detection rule](detection-rule.yml), [test cases](../../tests/SAF-T1701/test-cases.yml), and [validation proof](../../research/techniques/SAF-T1701/validation/detector-test.txt). <!-- SAF-TRACE: claims=SAF-T1701-C007,SAF-T1701-C009,SAF-T1701-C010; sources=SRC-invariant-toxic-flow-2025,SRC-otel-genai-2026,SRC-adaptive-attacks-2025 -->

Tune instruction indicators, impact classes, trust labels, and the correlation window to the deployment. The rule can miss paraphrased contamination, incomplete telemetry, long-delay pivots, or same-tool abuse, and it can alert on legitimate automation that lacks auditable approval. <!-- SAF-TRACE: claims=SAF-T1701-C010; sources=SRC-adaptive-attacks-2025,SRC-formal-security-2024 -->

## Mitigation Strategies

- **[SAF-M-21: Output Context Isolation](../../mitigations/SAF-M-21/README.md)** and **[SAF-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../../mitigations/SAF-M-69/README.md)**: Mark results from tools that expose adversary-controlled data as untrusted and carry that taint through the session; block or require explicit approval before later sensitive or outward-facing calls. <!-- SAF-TRACE: claims=SAF-T1701-C008,SAF-T1701-C011; sources=SRC-mcp-annotations-2026-03-16,SRC-mcp-tools-2025-11-25 -->
- **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)** and **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Give each user and workflow only the tools and resource scopes required, and enforce authorization at the server rather than relying on model judgment or descriptive annotations. <!-- SAF-TRACE: claims=SAF-T1701-C006,SAF-T1701-C011; sources=SRC-vulncheck-cve-2026-58168,SRC-mcp-tools-2025-11-25 -->
- **[SAF-M-22: Semantic Output Validation](../../mitigations/SAF-M-22/README.md)**, **[SAF-M-5: Content Sanitization](../../mitigations/SAF-M-5/README.md)**, and **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Validate tool results against declared schemas, sanitize untrusted output, display sensitive call inputs, and retain session-level call/result/approval audit records. <!-- SAF-TRACE: claims=SAF-T1701-C001,SAF-T1701-C009,SAF-T1701-C011; sources=SRC-mcp-tools-2025-11-25,SRC-otel-genai-2026,SRC-otel-session-2026 -->
- **[SAF-M-1: Control/Data Flow Separation](../../mitigations/SAF-M-1/README.md)**: Isolate high-impact tools and destinations with sandbox, filesystem, network, and write controls because annotations are advisory rather than enforcement. <!-- SAF-TRACE: claims=SAF-T1701-C008,SAF-T1701-C011; sources=SRC-mcp-annotations-2026-03-16,SRC-mcp-tools-2025-11-25 -->
- **[SAF-M-70: Tool-Invocation Anomaly Detection & Baselining](../../mitigations/SAF-M-70/README.md)**: Monitor same-session transitions from untrusted source results to distinct high-impact tools, retaining intent and approval context for investigation. <!-- SAF-TRACE: claims=SAF-T1701-C007,SAF-T1701-C009,SAF-T1701-C011; sources=SRC-invariant-toxic-flow-2025,SRC-otel-genai-2026,SRC-otel-session-2026 -->

## Related Techniques

- **[SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md)**: malicious instructions reside in tool definitions or annotations before a result is returned; this technique instead begins with adversary-controlled result content. <!-- SAF-TRACE: claims=SAF-T1701-C012; sources=SRC-invariant-tpa-2025-04-01 -->
- **[SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md)**: prompt injection establishes adversarial instruction influence; this technique additionally requires an indirect source-tool result followed by a call to a distinct target tool. <!-- SAF-TRACE: claims=SAF-T1701-C002; sources=SRC-injecagent-2024 -->

## MITRE ATT&CK Mapping

- **ATK-TA0008 — Lateral Movement**: the technique pivots between tool trust or capability domains in a shared agent execution context. <!-- SAF-TRACE: claims=SAF-T1701-C013; sources=SRC-mitre-t1080-2025 -->
- **T1080 — Taint Shared Content (analogous)**: both mechanisms seed adversary-controlled shared content that affects another execution context, but T1080 describes executable content in shared storage, whereas this technique describes instruction-bearing tool output driving another tool. <!-- SAF-TRACE: claims=SAF-T1701-C013; sources=SRC-mitre-t1080-2025 -->

## References

- [SRC-mcp-tools-2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — Model Context Protocol, “Tools,” 2025-11-25.
- [SRC-mcp-annotations-2026-03-16](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/) — MCP Blog, “Tool Annotations as Risk Vocabulary,” 2026-03-16.
- [SRC-injecagent-2024](https://aclanthology.org/2024.findings-acl.624.pdf) — Zhan et al., “InjecAgent,” Findings of ACL 2024.
- [SRC-adaptive-attacks-2025](https://aclanthology.org/anthology-files/pdf/naacl/2025.naacl-findings.395.pdf) — Zhan et al., adaptive indirect prompt-injection attacks, Findings of NAACL 2025.
- [SRC-invisible-prompts-2025](https://aclanthology.org/2025.findings-emnlp.376.pdf) — Xiong et al., “Invisible Prompts, Visible Threats,” Findings of EMNLP 2025.
- [SRC-invariant-github-mcp-2025](https://invariantlabs.ai/blog/mcp-github-vulnerability) — Invariant Labs GitHub MCP controlled demonstration.
- [SRC-invariant-whatsapp-mcp-2025-04-07](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) — Invariant Labs WhatsApp MCP controlled demonstrations.
- [SRC-invariant-tpa-2025-04-01](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — Invariant Labs tool-poisoning research.
- [SRC-invariant-toxic-flow-2025](https://invariantlabs.ai/blog/toxic-flow-analysis) — Invariant Labs toxic-flow analysis.
- [SRC-formal-security-2024](https://invariantlabs.ai/theme/research/ai_agents_with_formal_security.pdf) — Beurer-Kellner et al., “AI Agents with Formal Security Guarantees,” 2024.
- [SRC-vulncheck-cve-2026-58168](https://www.vulncheck.com/advisories/deeptutor-insecure-default-grants-unrestricted-mcp-tool-access-to-non-admin-users) — VulnCheck advisory for CVE-2026-58168.
- [SRC-nvd-cve-2026-58168](https://nvd.nist.gov/vuln/detail/CVE-2026-58168) — NVD record for CVE-2026-58168.
- [SRC-otel-genai-2026](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/) — OpenTelemetry generative-AI attribute registry.
- [SRC-otel-session-2026](https://opentelemetry.io/docs/specs/semconv/general/session/) — OpenTelemetry session semantic conventions.
- [SRC-mitre-t1080-2025](https://attack.mitre.org/techniques/T1080/) — MITRE ATT&CK T1080, Taint Shared Content.

## Version History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-09-02 | Frank Kautz, SAF Technique Author; OpenAI Codex, Research and Drafting | Clean-room initial publication candidate with tested behavioral detection. |
