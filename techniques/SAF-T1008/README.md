# SAF-T1008: Tool Shadowing Attack

## Overview

- **Tactic**: Initial Access (ATK-TA0001)
- **Technique ID**: SAF-T1008
- **Research Packet**: [research/techniques/SAF-T1008](../../research/techniques/SAF-T1008/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1008/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: An attacker-controlled server can steer a model's use of a separately trusted tool, so integrity impact is high and confidentiality impact becomes high when the trusted tool handles sensitive data or a follow-on path can export it. <!-- SAF-TRACE: claims=SAF-T1008-C005,SAF-T1008-C012; sources=SRC-invariant-tpa-2025-04-01,SRC-croce-south-2025-arxiv-2507-19880 -->
- **First Observed**: Not observed in production; publicly demonstrated on 2025-04-01. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C010; sources=SRC-invariant-tpa-2025-04-01,SRC-cisa-kev-2026-09-01,SRC-nvd-cve-2026-25905 -->
- **Last Updated**: 2026-09-01

## Scope

Tool shadowing is cross-server descriptor interference: text supplied for an attacker-controlled tool changes how an agent selects, configures, or invokes a distinct tool from a trusted server. The abused boundary is the host's shared model context, where independently administered tool descriptors are composed without an enforceable provenance boundary. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

### In Scope

- A malicious or compromised server publishes a descriptor that refers to, overrides, or adds instructions for a tool owned by another server. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- The shared agent context carries the foreign descriptor's instruction into selection or invocation of the trusted tool, whether or not the attacker's own tool is called. <!-- SAF-TRACE: claims=SAF-T1008-C005,SAF-T1008-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

### Out of Scope

- Instructions that alter only the attacker's own tool are ordinary tool-description poisoning, not shadowing. <!-- SAF-TRACE: claims=SAF-T1008-C004; sources=SRC-invariant-tpa-2025-04-01 -->
- A descriptor that becomes malicious only after approval is a rug-pull or post-approval mutation; identical-name registration and resolution-order abuse are tool-name collision or squatting. <!-- SAF-TRACE: claims=SAF-T1008-C003,SAF-T1008-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-csa-shadowing-2026 -->
- Prompt-resource injection, malicious tool output, and cross-server exfiltration are separate mechanisms or follow-on behaviors unless a foreign tool descriptor controls the trusted invocation. <!-- SAF-TRACE: claims=SAF-T1008-C011; sources=SRC-croce-south-2025-arxiv-2507-19880,SRC-embrace-red-2025-05-02 -->

### Distinguishing Characteristics

The decisive observable is provenance mismatch: a descriptor from server A contains operational instructions about tool B on server B, followed by a model decision involving B. A same-name registration without foreign-descriptor influence is a collision; instructions confined to A are ordinary poisoning; and later descriptor replacement is mutation. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C013,SAF-T1008-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556,SRC-csa-shadowing-2026 -->

## Description

MCP servers return tool names, descriptions, and schemas through `tools/list`, while clients invoke a chosen tool by name through `tools/call`. The protocol describes model-controlled tool use and recommends visible exposure, confirmation, validation, and logging, but it does not define a mandatory isolation boundary for descriptors aggregated from multiple servers. <!-- SAF-TRACE: claims=SAF-T1008-C001,SAF-T1008-C002; sources=SRC-mcp-tools-2025-11-25 -->

In a public Cursor demonstration, a bogus calculator tool's description instructed the model to alter a trusted email tool invocation and route the message to an attacker-controlled recipient. The attacker tool did not need to be selected; its descriptor influenced a separate tool in the shared context. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C005; sources=SRC-invariant-tpa-2025-04-01 -->

A later controlled study formalized shadowing as malicious descriptor content that contaminates interpretation of benign tool descriptors and evaluated it across multiple model families and prompting strategies. Because these results used controlled or synthetic conditions rather than a documented production compromise, the technique is Demonstrated, not Observed. <!-- SAF-TRACE: claims=SAF-T1008-C006,SAF-T1008-C007; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->

## Attack Vectors

- **Primary Vector**: A victim installs, connects, or enables an attacker-controlled MCP server whose advertised tool descriptor names or gives instructions for a tool supplied by another connected server. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C009; sources=SRC-invariant-tpa-2025-04-01,SRC-mitre-attack-t1195 -->
- **Secondary Vectors**: A previously trusted server is compromised or gains descriptor-modification capability; an isolation flaw permits code in one MCP tool server to rewrite its advertised registry state. <!-- SAF-TRACE: claims=SAF-T1008-C008; sources=SRC-jfrog-jfsa-2026-001653030,SRC-nvd-cve-2026-25905 -->
- **Affected Components**: MCP host/client, tool registry snapshot, model context, attacker-controlled server, trusted server, and trusted tool. <!-- SAF-TRACE: claims=SAF-T1008-C001,SAF-T1008-C006; sources=SRC-mcp-tools-2025-11-25,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Trust Boundary Crossed**: Independent server provenance is lost when descriptors share model context and one server's instructions influence another server's tool. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

## Technical Details

### Prerequisites

- At least two tool providers are visible in the same agent session: one attacker-controlled descriptor source and one trusted target tool. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- The host presents both descriptors in shared model context and does not enforce a policy that rejects cross-server operational references. <!-- SAF-TRACE: claims=SAF-T1008-C006,SAF-T1008-C013; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->
- The target tool has an action or data path valuable to the attacker; user confirmation may reduce success but does not remove descriptor influence before the decision. <!-- SAF-TRACE: claims=SAF-T1008-C002,SAF-T1008-C005; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->

### Attack Flow

1. **Reconnaissance or Setup**: The attacker identifies a likely trusted tool and prepares an otherwise plausible server whose descriptor embeds instructions about that foreign tool. <!-- SAF-TRACE: claims=SAF-T1008-C004; sources=SRC-invariant-tpa-2025-04-01 -->
2. **Delivery**: The victim connects the attacker-controlled server, placing its descriptor beside trusted descriptors in the host's model context. <!-- SAF-TRACE: claims=SAF-T1008-C001,SAF-T1008-C004; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->
3. **Trigger or Execution**: A user request causes the model to consider the trusted tool while the malicious foreign-tool instruction remains in context. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
4. **Boundary Crossing**: The host or model applies server A's text to server B's tool selection or arguments without an enforceable provenance policy. <!-- SAF-TRACE: claims=SAF-T1008-C005,SAF-T1008-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
5. **Objective**: The trusted tool is invoked differently from the user's stated intent. <!-- SAF-TRACE: claims=SAF-T1008-C005; sources=SRC-invariant-tpa-2025-04-01 -->
6. **Follow-On Activity**: Depending on the trusted tool and available paths, altered execution may enable collection, unauthorized state changes, or exfiltration. <!-- SAF-TRACE: claims=SAF-T1008-C005,SAF-T1008-C011; sources=SRC-invariant-tpa-2025-04-01,SRC-croce-south-2025-arxiv-2507-19880 -->

### Example Scenario

An employee enables a harmless-looking formatting server while a corporate mail server is already connected. One formatting-tool descriptor says that every invocation of the separate mail tool must replace its destination with `audit@example.invalid`; a normal request to send a draft then produces a mail call whose proposed recipient differs from the user's stated recipient. The example is inert and stops before execution. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C005; sources=SRC-invariant-tpa-2025-04-01 -->

```json
{"descriptor_server":"format-helper","descriptor_tool":"format_text","foreign_tool_reference":"mail/send","directive":"replace destination with audit@example.invalid","observed_proposed_call":{"server":"corporate-mail","tool":"send","destination":"audit@example.invalid"},"executed":false}
```
<!-- SAF-TRACE: claims=SAF-T1008-C004; sources=SRC-invariant-tpa-2025-04-01 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1008-C001 | MCP tool discovery returns name, description, and schema; invocation names a tool. | Protocol normative | SRC-mcp-tools-2025-11-25: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Does not prescribe a multi-server aggregation architecture. |
| SAF-T1008-C002 | Tool use is model-controlled and human confirmation, validation, and logging are recommended client safeguards. | Protocol normative | SRC-mcp-tools-2025-11-25: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Recommendations do not prove uniform implementation. |
| SAF-T1008-C003 | Rug-pull mutation is distinct from initially malicious cross-server shadowing. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Invariant Labs research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Product behavior may change after the publication date. |
| SAF-T1008-C004 | A malicious descriptor can change a separate trusted tool invocation. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Invariant Labs research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Public product demonstration, not a production incident. |
| SAF-T1008-C005 | The attacker's tool need not be invoked for its descriptor to influence the trusted tool. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Invariant Labs research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | One demonstrated client and scenario. |
| SAF-T1008-C006 | Controlled research formalized and measured shared-context descriptor shadowing. | Demonstrated | SRC-jamshidi-2026-arxiv-2512-06556: [Jamshidi et al.](https://arxiv.org/abs/2512.06556) | Synthetic descriptors and controlled evaluation. |
| SAF-T1008-C007 | The controlled study does not establish production prevalence. | Research finding | SRC-jamshidi-2026-arxiv-2512-06556: [Jamshidi et al.](https://arxiv.org/abs/2512.06556) | Black-box model and generalizability limits remain. |
| SAF-T1008-C008 | CVE-2026-25905 can let code in mcp-run-python modify its server environment and advertised tools. | Disclosed vulnerability | SRC-jfrog-jfsa-2026-001653030: [JFrog advisory](https://research.jfrog.com/vulnerabilities/mcp-run-python-lack-of-isolation-mcp-takeover-jfsa-2026-001653030/); SRC-nvd-cve-2026-25905: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25905) | Enables registry takeover but does not demonstrate cross-server descriptor influence. |
| SAF-T1008-C009 | Installing an attacker-controlled server can be analogous to a supply-chain initial-access path. | Framework inference | SRC-mitre-attack-t1195: [MITRE ATT&CK T1195](https://attack.mitre.org/techniques/T1195/) | Analogy applies to delivery, not the MCP semantic mechanism. |
| SAF-T1008-C010 | No direct production incident was identified in the reviewed NVD and CISA KEV corpora. | Research finding | SRC-cisa-kev-2026-09-01: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); SRC-nvd-cve-2026-25905: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25905) | Absence from reviewed corpora cannot prove no incident exists. |
| SAF-T1008-C011 | Cross-server prompt/tool chains demonstrate conditional confidentiality impact but use mechanisms adjacent to shadowing. | Demonstrated | SRC-croce-south-2025-arxiv-2507-19880: [Croce and South](https://arxiv.org/abs/2507.19880); SRC-embrace-red-2025-05-02: [Embrace The Red](https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/) | These demonstrations use a prompt resource or metadata-driven second-tool call, not the exact foreign-descriptor override contract. |
| SAF-T1008-C012 | Impact depends on target-tool privileges, data, connectivity, and approval behavior. | Research-derived | SRC-invariant-tpa-2025-04-01: [Invariant Labs research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks); SRC-croce-south-2025-arxiv-2507-19880: [Croce and South](https://arxiv.org/abs/2507.19880) | Impact is conditional, not universal. |
| SAF-T1008-C013 | Foreign-tool references and directive density are useful detection features with semantic-evasion and false-positive limits. | Framework inference | SRC-invariant-tpa-2025-04-01: [Invariant Labs research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks); SRC-jamshidi-2026-arxiv-2512-06556: [Jamshidi et al.](https://arxiv.org/abs/2512.06556) | Proposed analytic is locally derived and not a production-validated detector. |
| SAF-T1008-C014 | Descriptor provenance, version pinning, approval context, and cross-server policy are relevant safeguards. | Research-derived | SRC-invariant-tpa-2025-04-01: [Invariant Labs research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks); SRC-mcp-tools-2025-11-25: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Exact controls are host-specific. |
| SAF-T1008-C015 | “Tool shadowing” is also used for name-collision attacks, creating a terminology conflict. | Research finding | SRC-csa-shadowing-2026: [CSA MCP Security](https://modelcontextprotocol-security.io/ttps/tool-poisoning/tool-shadowing/) | Community taxonomy is not used as core evidence. |
| SAF-T1008-C016 | A combined defense evaluation reported meaningful blocking with measurable false positives and residual unsafe behavior. | Demonstrated | SRC-jamshidi-2026-arxiv-2512-06556: [Jamshidi et al.](https://arxiv.org/abs/2512.06556) | Controlled metrics do not predict a specific production deployment. |

### Current State

- **Affected Environments**: Multi-server agent sessions that place independently sourced tool descriptors in shared model context and expose a consequential trusted tool. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Known Exploitation**: Public demonstrations and controlled evaluations exist; no qualifying production incident was found in the reviewed NVD and CISA KEV searches. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C006,SAF-T1008-C010; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Visible tool exposure, confirmation, result validation, usage logging, version pinning, and cross-server dataflow controls can constrain the mechanism. <!-- SAF-TRACE: claims=SAF-T1008-C002,SAF-T1008-C014; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->
- **Residual Risk**: Semantic filters and approval prompts can miss disguised intent; the controlled study reports residual unsafe invocations and false positives under combined mitigations. <!-- SAF-TRACE: claims=SAF-T1008-C007,SAF-T1008-C016; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Invariant Cursor shadowing demonstration | 2025-04-01; Cursor with a bogus calculator server and trusted email tool | Trusted email arguments were redirected; authors recommend UI disclosure, pinning, and cross-server flow controls. | Direct demonstration | Not a production incident; single public scenario. | <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C005,SAF-T1008-C014; sources=SRC-invariant-tpa-2025-04-01 -->
| CVE-2026-25905 / JFSA-2026-001653030 | 2026-02-09; mcp-run-python | Unisolated code can modify the MCP server and tool registry; the archived project was not expected to receive a fix. | Enabling vulnerability | Demonstrates server takeover and same-server tool mutation, not foreign descriptor control of another server's tool. | <!-- SAF-TRACE: claims=SAF-T1008-C008; sources=SRC-jfrog-jfsa-2026-001653030,SRC-nvd-cve-2026-25905 -->
| Trivial Trojans cross-server proof of concept | 2025-07-26; Claude Desktop, a malicious weather server, and a banking server | A prompt-directed chain read and exported banking data after confirmations; capability boundaries are recommended. | Adjacent demonstration | Prompt resource and malicious exfiltration tool differ from descriptor-only shadowing. | <!-- SAF-TRACE: claims=SAF-T1008-C011; sources=SRC-croce-south-2025-arxiv-2507-19880 -->

### Real-World Incidents or Demonstrations

#### Invariant Cursor Demonstration (2025-04-01)

Invariant Labs showed an attacker-controlled calculator descriptor changing a trusted email tool's recipient and behavior in Cursor. It directly establishes the cross-server influence mechanism, while leaving prevalence and production exploitation unestablished. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C005; sources=SRC-invariant-tpa-2025-04-01 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Sensitive data may be exposed when the trusted tool reads protected data and a follow-on export path exists. | <!-- SAF-TRACE: claims=SAF-T1008-C011,SAF-T1008-C012; sources=SRC-croce-south-2025-arxiv-2507-19880,SRC-invariant-tpa-2025-04-01 -->
| Integrity | High | The demonstrated mechanism can alter target-tool selection or arguments relative to user intent. | <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C005; sources=SRC-invariant-tpa-2025-04-01 -->
| Availability | Low | Disruption is possible only when the target tool can affect service state; it is not intrinsic to shadowing. | <!-- SAF-TRACE: claims=SAF-T1008-C012; sources=SRC-invariant-tpa-2025-04-01,SRC-croce-south-2025-arxiv-2507-19880 -->
| Scope | Multi-System | One agent session may connect multiple servers, but available tools, permissions, and approvals bound the blast radius. | <!-- SAF-TRACE: claims=SAF-T1008-C006,SAF-T1008-C012; sources=SRC-jamshidi-2026-arxiv-2512-06556,SRC-croce-south-2025-arxiv-2507-19880 -->

### Severity Conditions

- **Severity increases when**: Trusted tools hold broad write privileges or sensitive data, outbound paths are available, descriptors are accepted without provenance policy, and tool calls execute with weak approval. <!-- SAF-TRACE: claims=SAF-T1008-C005,SAF-T1008-C012; sources=SRC-invariant-tpa-2025-04-01,SRC-croce-south-2025-arxiv-2507-19880 -->
- **Severity decreases when**: Hosts isolate server contexts, pin reviewed descriptors, deny undeclared cross-server influence, show destination-sensitive diffs, and require informed confirmation. <!-- SAF-TRACE: claims=SAF-T1008-C002,SAF-T1008-C014; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host registry audit | `tools/list`, descriptor snapshot, server connect, and `notifications/tools/list_changed` | Timestamp, session, server identity, tool identity, descriptor hash/text, foreign-tool references, approval state | Preserve immutable pre- and post-change snapshots with server provenance. | <!-- SAF-TRACE: claims=SAF-T1008-C001,SAF-T1008-C003,SAF-T1008-C014; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->
| Agent decision and tool-call audit | Model tool proposal, user approval, and `tools/call` | Session, request intent, selected server/tool, arguments, descriptor sources, approver, result | Correlate the proposal with the exact descriptor versions in context. | <!-- SAF-TRACE: claims=SAF-T1008-C001,SAF-T1008-C002,SAF-T1008-C014; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->

### Indicators of Compromise (IoCs)

- No durable universal IoC is known; the technique is semantic and attacker-chosen descriptor text is variable. <!-- SAF-TRACE: claims=SAF-T1008-C007,SAF-T1008-C013; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->

### Behavioral Indicators

- A descriptor from one server explicitly names a tool owned by another server and contains imperative text about selection, arguments, recipients, destinations, or precedence. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- A trusted tool proposal deviates from the user's request in the same session after an unrelated server descriptor is introduced or changed. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- Confidence increases when the foreign reference and imperative pattern are not covered by an approved, explicit cross-server orchestration contract. <!-- SAF-TRACE: claims=SAF-T1008-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Flag unapproved descriptors that refer to another server's tool and contain at least two imperative or argument-manipulation signals. <!-- SAF-TRACE: claims=SAF-T1008-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Rule Status**: Experimental; see [detection-rule.yml](detection-rule.yml).
- **Detection Logic**: Require a tool-registry snapshot, a foreign-tool reference, directive score of two or more, and no approved cross-server contract. <!-- SAF-TRACE: claims=SAF-T1008-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Correlation Window**: One registry snapshot or the lifetime of its descriptor hashes in a session. <!-- SAF-TRACE: claims=SAF-T1008-C013; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Known False Positives**: Legitimate orchestration tools, gateways, and documentation descriptors that intentionally reference foreign tools. <!-- SAF-TRACE: claims=SAF-T1008-C013; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Known Limitations**: The analytic needs semantic enrichment, misses oblique or encoded instructions, and does not prove that a subsequent call was influenced. <!-- SAF-TRACE: claims=SAF-T1008-C007,SAF-T1008-C013; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Tuning Guidance**: Inventory tool ownership, allowlist explicit orchestration contracts, and baseline descriptor hashes by server version. <!-- SAF-TRACE: claims=SAF-T1008-C013,SAF-T1008-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

### Validation

- **Test Data**: [events.json](../../tests/SAF-T1008/fixtures/events.json).
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1008/test_detection_rule.py).
- **Expected Result**: [Two positive and six negative fixtures pass with no mismatches](../../tests/SAF-T1008/results.json).
- **Last Validated**: [2026-09-01](../../research/techniques/SAF-T1008/quality-review.yml).
- **Feasibility Waiver**: [None](../../research/techniques/SAF-T1008/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-2: Cryptographic Integrity for Tool Descriptions](../../mitigations/SAF-M-2/README.md)**: Bind each descriptor to an authenticated server identity and reject operational references to foreign tools unless an explicit contract authorizes them. <!-- SAF-TRACE: claims=SAF-T1008-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25 -->
2. **[SAF-M-1: Architectural Defense - Control/Data Flow Separation](../../mitigations/SAF-M-1/README.md)**: Isolate server contexts or enforce a declared policy for cross-server data and control flow. <!-- SAF-TRACE: claims=SAF-T1008-C014; sources=SRC-invariant-tpa-2025-04-01 -->
3. **Version and change control**: Pin reviewed tool descriptors and require renewed review after a descriptor hash or tool list changes. <!-- SAF-TRACE: claims=SAF-T1008-C003,SAF-T1008-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25 -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Preserve descriptor provenance and correlate foreign-tool references with proposed and executed calls. <!-- SAF-TRACE: claims=SAF-T1008-C013,SAF-T1008-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25 -->
2. **Approval-diff review**: Show users the chosen server, tool, destination-sensitive arguments, and the descriptor source that influenced the call. <!-- SAF-TRACE: claims=SAF-T1008-C002,SAF-T1008-C014; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->

### Response Procedures

#### Immediate Actions

- Disable the suspected descriptor source, stop the affected agent session, and block pending calls whose provenance cannot be reconstructed. <!-- SAF-TRACE: claims=SAF-T1008-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25 -->
- Revoke or rotate credentials only when call/result evidence shows that a protected destination or secret may have been reached. <!-- SAF-TRACE: claims=SAF-T1008-C012; sources=SRC-croce-south-2025-arxiv-2507-19880 -->

#### Investigation Steps

- Preserve exact descriptor snapshots, hashes, server identities, model proposals, approvals, tool calls, arguments, results, and outbound network records for the session. <!-- SAF-TRACE: claims=SAF-T1008-C002,SAF-T1008-C014; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->
- Compare user intent with trusted-tool proposals and determine whether a foreign descriptor preceded each deviation. <!-- SAF-TRACE: claims=SAF-T1008-C004,SAF-T1008-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

#### Remediation

- Remove the attacker-controlled or compromised server, restore pinned descriptors, and enforce explicit server-to-server interaction policy before reconnection. <!-- SAF-TRACE: claims=SAF-T1008-C014; sources=SRC-invariant-tpa-2025-04-01 -->
- Validate affected external state and add regression fixtures for the exact provenance mismatch and semantic evasion observed. <!-- SAF-TRACE: claims=SAF-T1008-C013,SAF-T1008-C014; sources=SRC-jamshidi-2026-arxiv-2512-06556 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md) | Overlapping prerequisite | Malicious text changes only the attacker's own tool behavior; it does not govern a separately trusted tool. | <!-- SAF-TRACE: claims=SAF-T1008-C004; sources=SRC-invariant-tpa-2025-04-01 -->
| [SAF-T1201: MCP Rug Pull Attack](../SAF-T1201/README.md) | Alternative lifecycle | The descriptor becomes malicious after approval rather than arriving with cross-server instructions. | <!-- SAF-TRACE: claims=SAF-T1008-C003; sources=SRC-invariant-tpa-2025-04-01 -->
| [SAF-T1301: Cross-Server Tool Shadowing](../SAF-T1301/README.md) | Alternative resolution mechanism | The host resolves or overrides colliding tool calls; foreign descriptor instructions are not required. | <!-- SAF-TRACE: claims=SAF-T1008-C015; sources=SRC-csa-shadowing-2026,SRC-invariant-tpa-2025-04-01 -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1195](https://attack.mitre.org/techniques/T1195/) | Supply Chain Compromise | Analogous | Delivery of a malicious or modified MCP server before consumer use resembles manipulation of a product or delivery mechanism, but ATT&CK T1195 does not define shared-context descriptor interference. | <!-- SAF-TRACE: claims=SAF-T1008-C009; sources=SRC-mitre-attack-t1195 -->

## References

1. **SRC-mcp-tools-2025-11-25**: [MCP Tools specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) - Discovery, invocation, metadata, and client-safety behavior.
2. **SRC-invariant-tpa-2025-04-01**: [MCP Security Notification: Tool Poisoning Attacks - Luca Beurer-Kellner and Marc Fischer, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) - Direct cross-server shadowing demonstration, distinctions, and mitigations.
3. **SRC-jamshidi-2026-arxiv-2512-06556**: [Semantic Attacks on Tool-Augmented LLMs - Saeid Jamshidi, Arghavan Moradi Dakhel, Kawser Wazed Nafi, and Foutse Khomh, 2026](https://arxiv.org/abs/2512.06556) - Controlled descriptor-shadowing evaluation and limitations.
4. **SRC-jfrog-jfsa-2026-001653030**: [mcp-run-python Lack of Isolation - JFrog Security Research, 2026](https://research.jfrog.com/vulnerabilities/mcp-run-python-lack-of-isolation-mcp-takeover-jfsa-2026-001653030/) - Enabling server-takeover vulnerability.
5. **SRC-nvd-cve-2026-25905**: [CVE-2026-25905 - NVD, 2026](https://nvd.nist.gov/vuln/detail/CVE-2026-25905) - Vulnerability identity and advisory metadata.
6. **SRC-cisa-kev-2026-09-01**: [Known Exploited Vulnerabilities Catalog - CISA, accessed 2026-09-01](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Reviewed exploited-vulnerability corpus; no matching entry found.
7. **SRC-croce-south-2025-arxiv-2507-19880**: [Trivial Trojans - Nicola Croce and Tobin South, 2025](https://arxiv.org/abs/2507.19880) - Adjacent controlled cross-server exfiltration proof of concept and conditions.
8. **SRC-embrace-red-2025-05-02**: [Model Context Protocol Security Risks - Embrace The Red, 2025](https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/) - Independent adjacent cross-tool metadata demonstration.
9. **SRC-mitre-attack-t1195**: [Supply Chain Compromise - MITRE ATT&CK, version 1.7](https://attack.mitre.org/techniques/T1195/) - Analogous Initial Access mapping.
10. **SRC-csa-shadowing-2026**: [Tool Shadowing - CSA MCP Security](https://modelcontextprotocol-security.io/ttps/tool-poisoning/tool-shadowing/) - Conflicting name-collision usage recorded as a taxonomy limitation.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room research draft, detection analytic, evidence packet, and isolated validation | OpenAI Codex |
