# SAF-T1405: Tool Obfuscation/Renaming

## Overview

- **Tactic**: Defense Evasion (ATK-TA0005)
- **Technique ID**: SAF-T1405
- **Research Packet**: [research/techniques/SAF-T1405](../../research/techniques/SAF-T1405/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1405/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Impact is conditional on the selected tool's permissions and behavior; controlled MCP evaluations show that manipulated names or descriptions can redirect tool selection, but not that every selection produces compromise. <!-- SAF-TRACE: claims=SAF-T1405-C010; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->
- **First Observed**: Not observed in production in the reviewed direct-authority corpus as of 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1405-C005; sources=SRC-nvd-mcp-tool-identity-corpus-2026,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-01

## Scope

Tool Obfuscation/Renaming covers attacker control of a tool's machine name, human-facing title, or description so that an MCP host, model, operator, or name-based control confuses the tool with an expected capability, prefers it over a competitor, or overlooks a material identity change. The crossed boundary is untrusted tool metadata entering discovery, review, and selection decisions. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C002; sources=SRC-mcp-tools-2026-07-28,SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->

### In Scope

- A malicious or compromised tool provider publishes or updates a misleading machine name, title, or description and the metadata changes discovery, trust, or selection. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->
- Name collision, trusted-looking renaming, promotional name modifiers, and descriptor wording are included when the immediate objective is tool misidentification or preferential selection. <!-- SAF-TRACE: claims=SAF-T1405-C003,SAF-T1405-C004; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->

### Out of Scope

- Instructions delivered only in tool results or user content, where the tool identity and discovery metadata remain accurate. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->
- Backend behavior changes with unchanged metadata, registry or package compromise by itself, and authorization bypass that invokes a known tool directly. <!-- SAF-TRACE: claims=SAF-T1405-C002,SAF-T1405-C006,SAF-T1405-C007; sources=SRC-etdi-2025,SRC-ghsa-cr22-wjx7-2w6m -->

### Distinguishing Characteristics

The defining observable is a misleading or unexpected tool-identity presentation at discovery or update time, followed by review or selection. SAF-T1001 covers instruction-bearing definition semantics, while SAF-T1201 covers post-approval behavior or definition mutation under a stable identity. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->

## Description

MCP tool definitions expose a case-sensitive machine name plus optional title and description, and clients call a tool by its name. Names must be unique within one server, while collisions can occur across servers; the specification advises clients and aggregators to disambiguate them and warns that a server-reported name is not a verified global identity. <!-- SAF-TRACE: claims=SAF-T1405-C001; sources=SRC-mcp-tools-2026-07-28 -->

An attacker who controls registration or update metadata can exploit that presentation layer. Two controlled evaluations demonstrate the mechanism: MPMA changed names or descriptions to bias competitive tool choice, and MCP Security Bench added a similar-name tool and measured selection-linked attack success in live MCP execution. These demonstrations support the technique label; they do not establish production exploitation. <!-- SAF-TRACE: claims=SAF-T1405-C002,SAF-T1405-C003,SAF-T1405-C004; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->

## Attack Vectors

- **Primary Vector**: Attacker-operated MCP server supplies a deceptive tool definition during discovery. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->
- **Secondary Vectors**: A compromised update path changes an approved descriptor; an aggregator exposes colliding names without stable origin disambiguation. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C007; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025 -->
- **Affected Components**: MCP server, client or host, tool registry or aggregator, model, and approval interface. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C002; sources=SRC-mcp-tools-2026-07-28,SRC-mpma-2025 -->
- **Trust Boundary Crossed**: Provider-controlled metadata crosses into client, model, and operator identity and selection decisions. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->

## Technical Details

### Prerequisites

- The adversary can publish, register, aggregate, or update a tool definition visible to the target host. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->
- The host, model, operator, or policy relies on mutable presentation metadata without a trusted origin-and-definition baseline. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025 -->
- A competing trusted or expected capability exists, or the deceptive wording can otherwise influence selection. <!-- SAF-TRACE: claims=SAF-T1405-C003,SAF-T1405-C004; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->

### Attack Flow

1. **Setup**: The adversary identifies an expected capability or competitive tool context. <!-- SAF-TRACE: claims=SAF-T1405-C003,SAF-T1405-C004; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->
2. **Delivery**: An attacker-controlled server advertises a colliding, trusted-looking, or preferentially worded tool definition. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->
3. **Trigger**: Discovery exposes the definition and the model, host, or operator chooses among tools. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C002; sources=SRC-mcp-tools-2026-07-28,SRC-mpma-2025 -->
4. **Boundary Crossing**: Mutable presentation metadata is treated as identity or trust evidence without stable provider binding. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025 -->
5. **Objective**: The attacker-controlled tool is selected, or a material definition change avoids expected review. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 -->
6. **Follow-On Activity**: Consequences depend on the selected tool's permissions, implementation, and subsequent authorization checks. <!-- SAF-TRACE: claims=SAF-T1405-C006,SAF-T1405-C010; sources=SRC-mcp-security-bench-2510.15994,SRC-ghsa-cr22-wjx7-2w6m -->

### Example Scenario

In an inert test tenant, an operator approves a document-search tool from provider A. A test server later advertises a similar display identity with a changed definition hash. The host logs the new provider binding and hash, the model selects the changed entry, and the analytic alerts before any non-test action; this scenario exercises identity drift without credentials, sensitive data, or destructive behavior. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-etdi-2025,SRC-mcp-tools-2026-07-28 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1405-C001 | MCP tool discovery and invocation rely on tool-definition names and metadata, with only per-server name uniqueness. | Research-Derived | SRC-mcp-tools-2026-07-28: MCP Tools specification | The specification defines protocol behavior, not exploitation prevalence. |
| SAF-T1405-C002 | Deceptive names or descriptors can redirect selection at the untrusted-metadata boundary. | Demonstrated | SRC-mpma-2025; SRC-mcp-security-bench-2510.15994 | Both are controlled evaluations, not incident reports. |
| SAF-T1405-C003 | MPMA's direct name and description manipulations strongly biased tool selection across its test matrix. | Demonstrated | SRC-mpma-2025 | Results depend on the tested models, prompts, servers, and competitive setup. |
| SAF-T1405-C004 | MCP Security Bench measured a 14.62% average ASR for its name-collision-plus-false-error condition across ten model backbones. | Demonstrated | SRC-mcp-security-bench-2510.15994 | The benchmark couples name collision with a response-stage false error. |
| SAF-T1405-C005 | No direct production incident or direct renaming vulnerability was identified in the reviewed NVD and CISA KEV corpus. | Research-Derived | SRC-nvd-mcp-tool-identity-corpus-2026; SRC-cisa-kev-2026-09-01 | This is a bounded corpus finding, not proof of absence. |
| SAF-T1405-C006 | CVE-2026-46519 is an enabling authorization flaw, not a renaming vulnerability. | Research-Derived | SRC-ghsa-cr22-wjx7-2w6m; SRC-nvd-cve-2026-46519 | It demonstrates direct invocation of filtered known names, not deceptive metadata. |
| SAF-T1405-C007 | Stable provider binding plus approved definition hashes and change review provide a basis for detecting identity drift. | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-etdi-2025 | ETDI is a proposed architecture, not field-effectiveness evidence. |
| SAF-T1405-C008 | Metadata scanners and semantic defenses have blind spots and measurable false positives. | Demonstrated | SRC-mpma-2025; SRC-jamshidi-2026-arxiv-2512-06556 | Evaluations use controlled corpora and different defensive designs. |
| SAF-T1405-C009 | Origin disambiguation, definition integrity, reapproval, least privilege, and execution-time authorization constrain the technique and its consequences. | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-etdi-2025; SRC-ghsa-cr22-wjx7-2w6m | No cited source proves that the combined stack eliminates the technique. |
| SAF-T1405-C010 | Impact is conditional on the selected tool's privileges and downstream behavior. | Demonstrated | SRC-mpma-2025; SRC-mcp-security-bench-2510.15994 | Selection bias alone is not equivalent to compromise. |
| SAF-T1405-C011 | ATT&CK T1036 is an analogous, not direct, mapping. | Research-Derived | SRC-mitre-attack-t1036 | T1036 documents operating-system and artifact masquerading, not MCP tool metadata. |
| SAF-T1405-C012 | A layered semantic-defense experiment reduced unsafe invocation from 0.36 to 0.15 while producing a 0.22 false-positive rate. | Demonstrated | SRC-jamshidi-2026-arxiv-2512-06556 | The study used a controlled synthetic testbed with three models. |

### Current State

- **Affected Environments**: MCP hosts that aggregate untrusted or mutable tool definitions and use names, titles, or descriptions in selection or review. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C002; sources=SRC-mcp-tools-2026-07-28,SRC-mpma-2025 -->
- **Known Exploitation**: Public controlled demonstrations exist; no qualifying production breach was found in the reviewed direct-authority corpus. <!-- SAF-TRACE: claims=SAF-T1405-C003,SAF-T1405-C004,SAF-T1405-C005; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994,SRC-nvd-mcp-tool-identity-corpus-2026,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Origin disambiguation, immutable or signed definition baselines, review on change, scoped permissions, and authorization at invocation. <!-- SAF-TRACE: claims=SAF-T1405-C009; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025,SRC-ghsa-cr22-wjx7-2w6m -->
- **Residual Risk**: First-seen deceptive definitions and subtle semantic wording can evade baseline-change rules or classifiers, while stricter semantic defenses can reject benign tools. <!-- SAF-TRACE: claims=SAF-T1405-C008,SAF-T1405-C012; sources=SRC-mpma-2025,SRC-jamshidi-2026-arxiv-2512-06556 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| MPMA controlled evaluation | 2025; eight MCP servers, five models, Cline host | Manipulated names and descriptions biased tool choice; authors evaluated detector behavior. | Direct demonstration | No production victim or breach. <!-- SAF-TRACE: claims=SAF-T1405-C003,SAF-T1405-C008; sources=SRC-mpma-2025 --> |
| MCP Security Bench | 2026; live MCP execution across ten domains and 405 attack tools | Name-collision-plus-false-error averaged 14.62% ASR; MCIP reduced aggregate attack success with utility tradeoffs. | Direct demonstration | The result does not isolate renaming from the coupled false-error stage. <!-- SAF-TRACE: claims=SAF-T1405-C004; sources=SRC-mcp-security-bench-2510.15994 --> |
| CVE-2026-46519 / GHSA-cr22-wjx7-2w6m | 2026; mcp-server-kubernetes before 3.6.0 | Filtered tools could still be called by known name; 3.6.0 enforces the allowed set at invocation. | Enabling vulnerability | No deceptive name or descriptor was required. <!-- SAF-TRACE: claims=SAF-T1405-C006; sources=SRC-ghsa-cr22-wjx7-2w6m,SRC-nvd-cve-2026-46519 --> |

No direct production breach or direct renaming vulnerability qualified; the evidence gap is preserved rather than filled with adjacent incidents. <!-- SAF-TRACE: claims=SAF-T1405-C005; sources=SRC-nvd-mcp-tool-identity-corpus-2026,SRC-cisa-kev-2026-09-01 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A selected malicious tool can expose data only if its granted inputs, credentials, or environment permit access. <!-- SAF-TRACE: claims=SAF-T1405-C010; sources=SRC-mcp-security-bench-2510.15994 --> |
| Integrity | High | Selection can redirect an intended operation to attacker-controlled behavior, bounded by execution authorization and tool privilege. <!-- SAF-TRACE: claims=SAF-T1405-C010; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 --> |
| Availability | Medium | Disruption is possible when the selected tool can fail or alter workflows, but availability impact is not intrinsic to metadata manipulation. <!-- SAF-TRACE: claims=SAF-T1405-C004,SAF-T1405-C010; sources=SRC-mcp-security-bench-2510.15994 --> |
| Scope | Multi-System | Aggregators may present tools from multiple servers, while per-call permissions and server isolation limit blast radius. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-bench-2510.15994 --> |

### Severity Conditions

- **Severity increases when**: The host auto-selects among untrusted tools, definitions are mutable, and tools receive broad credentials or sensitive context. <!-- SAF-TRACE: claims=SAF-T1405-C007,SAF-T1405-C010; sources=SRC-etdi-2025,SRC-mcp-security-bench-2510.15994 -->
- **Severity decreases when**: Provider identity is bound to the definition, changes require reapproval, and invocation is least-privileged and independently authorized. <!-- SAF-TRACE: claims=SAF-T1405-C009; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025,SRC-ghsa-cr22-wjx7-2w6m -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP discovery and registry audit | Tool first-seen and update events | timestamp, event_type, server_identity, provider_identity, tool_name, title, description_hash, schema_hash, approved_definition_hash, approval_state | Preserve stable provider identifiers and normalized hashes across sessions. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025 --> |
| MCP invocation audit | Tool selection and call | session_id, server_identity, tool_name, definition_hash, approval_state, result | Correlate the selected definition with the version reviewed by the operator. <!-- SAF-TRACE: claims=SAF-T1405-C007,SAF-T1405-C009; sources=SRC-etdi-2025,SRC-ghsa-cr22-wjx7-2w6m --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC is known; names and descriptor text are attacker-chosen and environment-specific. <!-- SAF-TRACE: claims=SAF-T1405-C008; sources=SRC-mpma-2025,SRC-jamshidi-2026-arxiv-2512-06556 -->

### Behavioral Indicators

- An existing provider-and-tool binding appears with an unapproved machine-name or descriptor hash change. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-etdi-2025 -->
- A newly seen server advertises a name colliding with an approved tool, particularly when selection immediately shifts to the new binding. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C004; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-bench-2510.15994 -->
- A changed or colliding definition is invoked without a matching approval record. <!-- SAF-TRACE: claims=SAF-T1405-C007,SAF-T1405-C009; sources=SRC-etdi-2025,SRC-ghsa-cr22-wjx7-2w6m -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect unapproved tool-name or definition-hash drift for a stable provider binding, and flag a cross-server name collision when one binding is already approved. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-etdi-2025 -->
- **Detection Logic**: Match registry or discovery events marked as unapproved when the machine name changed, the current definition hash differs from the approved hash, or the name collides with another approved server binding. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C007; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025 -->
- **Correlation Window**: Evaluate each discovery snapshot and retain the approved binding baseline across updates. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-etdi-2025 -->
- **Known False Positives**: Legitimate provider migrations, planned renames, schema revisions, and duplicate generic names across unrelated servers. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C008; sources=SRC-mcp-tools-2026-07-28,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Known Limitations**: The rule cannot judge a first-seen deceptive definition, subtle semantic manipulation with unchanged hashes, or a baseline approved under a compromised identity. <!-- SAF-TRACE: claims=SAF-T1405-C008; sources=SRC-mpma-2025,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Tuning Guidance**: Bind baselines to a stable provider identity and review allowlisted migrations rather than suppressing a tool name globally. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C007; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1405/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1405/test_detection_rule.py)
- **Expected Result**: [Three positives and three negatives, with exact case classification](../../tests/SAF-T1405/expected-results.json)
- **Last Validated**: [2026-09-01 validation record](../../tests/SAF-T1405/validation-output.txt)
- **Feasibility Waiver**: None; the deterministic analytic is exercised with synthetic discovery events in the [passing validation record](../../tests/SAF-T1405/validation-output.txt).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-2: Cryptographic Integrity for Tool Descriptions](../../mitigations/SAF-M-2/README.md)**: Bind server or provider identity to the complete tool definition, compare it with the approved version, and require review for name, descriptor, schema, or permission changes. <!-- SAF-TRACE: claims=SAF-T1405-C007,SAF-T1405-C009; sources=SRC-etdi-2025 -->
2. **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Enforce the allowed tool set at `tools/call`, not only at discovery, and apply least privilege to the selected tool. <!-- SAF-TRACE: claims=SAF-T1405-C006,SAF-T1405-C009; sources=SRC-ghsa-cr22-wjx7-2w6m,SRC-mcp-tools-2026-07-28 -->
3. **Origin-aware display and routing**: Present and route tools by a stable origin-qualified identity because tool names and server-reported names are not globally unique identities. <!-- SAF-TRACE: claims=SAF-T1405-C001,SAF-T1405-C009; sources=SRC-mcp-tools-2026-07-28 -->

### Detective Controls

1. Compare each discovery snapshot with the approved provider, name, and full-definition hashes; alert on unapproved drift and cross-origin collision. <!-- SAF-TRACE: claims=SAF-T1405-C007; sources=SRC-mcp-tools-2026-07-28,SRC-etdi-2025 -->
2. Correlate definition-change alerts with approval and invocation events, while retaining human review because semantic defenses have false negatives and false positives. <!-- SAF-TRACE: claims=SAF-T1405-C008,SAF-T1405-C012; sources=SRC-mpma-2025,SRC-jamshidi-2026-arxiv-2512-06556 -->

### Response Procedures

- Quarantine the changed binding, preserve discovery, approval, and invocation records, and revoke only credentials exposed to the suspect tool. <!-- SAF-TRACE: claims=SAF-T1405-C007,SAF-T1405-C010; sources=SRC-etdi-2025,SRC-mcp-security-bench-2510.15994 -->
- Re-establish the provider and definition baseline, enforce authorization at invocation, and review downstream actions taken after the first unapproved change. <!-- SAF-TRACE: claims=SAF-T1405-C006,SAF-T1405-C009; sources=SRC-etdi-2025,SRC-ghsa-cr22-wjx7-2w6m -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md) | Alternative or co-occurring | It changes instruction-bearing definition semantics; this technique changes the presented tool identity or descriptor used for selection. <!-- SAF-TRACE: claims=SAF-T1405-C002; sources=SRC-mpma-2025,SRC-mcp-security-bench-2510.15994 --> |
| [SAF-T1201: MCP Rug Pull Attack](../SAF-T1201/README.md) | Alternative or follow-on | It changes behavior or definition content after approval under a stable identity; this technique is defined by deceptive name or descriptor metadata. <!-- SAF-TRACE: claims=SAF-T1405-C002,SAF-T1405-C007; sources=SRC-etdi-2025,SRC-mpma-2025 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Analogous | Both manipulate names or metadata so an object appears legitimate and evades observation, but ATT&CK T1036 does not define MCP tool discovery or model selection. <!-- SAF-TRACE: claims=SAF-T1405-C011; sources=SRC-mitre-attack-t1036 --> |

## References

1. **SRC-mcp-tools-2026-07-28**: [Model Context Protocol — Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — normative tool discovery, naming, invocation, disambiguation, and logging guidance.
2. **SRC-mpma-2025**: [MPMA: Preference Manipulation Attack Against Model Context Protocol](https://arxiv.org/abs/2505.11154) — controlled name and description manipulation evaluation.
3. **SRC-mcp-security-bench-2510.15994**: [MCP Security Bench](https://arxiv.org/abs/2510.15994) — controlled name-collision evaluation with live MCP execution.
4. **SRC-jamshidi-2026-arxiv-2512-06556**: [Semantic Attacks on Tool-Augmented LLMs](https://arxiv.org/abs/2512.06556) — controlled descriptor manipulation and layered-defense evaluation.
5. **SRC-etdi-2025**: [Building a Secure and Trustworthy Tool Ecosystem for MCP](https://arxiv.org/abs/2506.01333) — proposed signed, versioned tool-definition controls.
6. **SRC-nvd-mcp-tool-identity-corpus-2026**: [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) — bounded vulnerability-catalog queries.
7. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — exploitation-catalog coverage check.
8. **SRC-nvd-cve-2026-46519**: [NVD CVE-2026-46519](https://nvd.nist.gov/vuln/detail/CVE-2026-46519) — affected versions, weakness, and advisory references.
9. **SRC-ghsa-cr22-wjx7-2w6m**: [GHSA-cr22-wjx7-2w6m](https://github.com/Flux159/mcp-server-kubernetes/security/advisories/GHSA-cr22-wjx7-2w6m) — maintainer advisory for discovery-only filtering bypass.
10. **SRC-mitre-attack-t1036**: [MITRE ATT&CK T1036: Masquerading](https://attack.mitre.org/techniques/T1036/) — analogous framework behavior.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Initial clean-room draft | OpenAI Codex |
