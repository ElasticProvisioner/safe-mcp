# SAF-T1302: Agentic Confused Deputy

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Framework Profiles**: SAF Core; MCP. [Framework Model v2](../../research/framework-model.yml)
- **Lifecycle Status**: Active. [Framework Model v2](../../research/framework-model.yml)
- **Technique ID**: SAF-T1302
- **Research Packet**: [research/techniques/SAF-T1302](../../research/techniques/SAF-T1302/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1302/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A low-trust principal can obtain the confidentiality, integrity, or availability reach of an elevated tool or process when requestor authorization or action-bound approval fails. <!-- SAF-TRACE: claims=SAF-T1302-C013; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h,SRC-nvd-cve-2026-41378 -->
- **First Observed**: Not observed in production; the defining behavior is supported by controlled demonstrations and disclosed vulnerabilities. [Research coverage](../../research/techniques/SAF-T1302/source-coverage.yml)
- **Last Updated**: 2026-09-02

## Scope

Agentic Confused Deputy covers a low-trust requestor or untrusted input causing an agent to exercise a legitimate tool, service identity, or approved process with authority unavailable to that principal because requestor authorization, scope binding, or action-bound approval is absent or ineffective. <!-- SAF-TRACE: claims=SAF-T1302-C004; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h,SRC-elastic-esa-2026-83 -->

### In Scope

- A low-trust requestor reaches an elevated or cross-tenant tool through an agent endpoint that fails to recheck the requestor's authority. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C009; sources=SRC-elastic-esa-2026-83 -->
- Untrusted content steers a model-controlled tool call that runs under an already-approved higher-privilege process without a new action-bound approval. <!-- SAF-TRACE: claims=SAF-T1302-C001,SAF-T1302-C007; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-codewhale-g29h -->
- A trusted tool sequence crosses from attacker-writable data into resources available only to the agent's user or service identity. <!-- SAF-TRACE: claims=SAF-T1302-C005; sources=SRC-invariant-github-mcp-2025 -->

### Out of Scope

- Prompt or tool-description manipulation without a resulting higher-authority tool effect belongs to [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md). <!-- SAF-TRACE: claims=SAF-T1302-C004; sources=SRC-invariant-github-mcp-2025 -->
- Direct theft or use of a delegated credential is separate from abusing the agent or tool as the privileged deputy. <!-- SAF-TRACE: claims=SAF-T1302-C004; sources=SRC-elastic-esa-2026-83 -->
- Unsafe argument handling that creates arbitrary code execution is separate unless a legitimate tool's authorization or approval gap is the defining boundary failure. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C007; sources=SRC-ghsa-codewhale-g29h -->
- Overbroad permissions alone are a precondition, not this technique, until adversary influence causes those permissions to be exercised. <!-- SAF-TRACE: claims=SAF-T1302-C003,SAF-T1302-C004; sources=SRC-mcp-authorization-2025-11-25,SRC-invariant-github-mcp-2025 -->

### Distinguishing Characteristics

The analyst should identify both sides of the authority mismatch: the principal that supplied or controlled the triggering request or content, and the effective identity or process used by the tool. [SAF-T1102](../SAF-T1102/README.md) ends at instruction manipulation, [SAF-T1304](../SAF-T1304/README.md) centers on credential propagation or direct use, and [SAF-T1303](../SAF-T1303/README.md) centers on code-execution mechanics. <!-- SAF-TRACE: claims=SAF-T1302-C004; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h,SRC-elastic-esa-2026-83 -->

## Description

MCP tools are model-controlled: a model can discover and invoke them from context and user prompts, while the client chooses its interaction model. The current Tools specification therefore couples automatic invocation with recommended human denial, sensitive-operation confirmation, visible tool inputs, and audit logging. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1302-C001,SAF-T1302-C002; sources=SRC-mcp-tools-2025-11-25 -->

The technique is a deputy failure, not merely a bad prompt. The attacker begins with less authority than the agent-side tool and gets a privileged result because the system validates only the agent or service identity, treats earlier approval as reusable, or omits a requestor-to-action authorization check. Controlled GitHub MCP research and current CodeWhale and Kibana disclosures demonstrate these variants. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C005,SAF-T1302-C007,SAF-T1302-C009; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h,SRC-elastic-esa-2026-83 -->

The behavior is classified as Demonstrated, not Observed: the reviewed corpus contains a complete controlled MCP sequence and direct vulnerabilities, but no qualifying production compromise. [Research coverage](../../research/techniques/SAF-T1302/source-coverage.yml)

## Attack Vectors

- **Primary Vector**: Attacker-controlled content or a low-privilege agent request reaches a model or gateway that can invoke a higher-authority tool. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C005,SAF-T1302-C008; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-openclaw-gjm7 -->
- **Secondary Vectors**: Reuse of a prior broad approval, missing per-feature requestor authorization, or cross-resource operations under one agent identity. <!-- SAF-TRACE: claims=SAF-T1302-C005,SAF-T1302-C007,SAF-T1302-C009; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h,SRC-elastic-esa-2026-83 -->
- **Affected Components**: MCP hosts and clients, agent gateways, tool brokers, approval services, downstream APIs, service identities, and privileged interactive processes. <!-- SAF-TRACE: claims=SAF-T1302-C001,SAF-T1302-C004; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-codewhale-g29h -->
- **Trust Boundary Crossed**: Requestor or content authority to agent/tool effective authority. <!-- SAF-TRACE: claims=SAF-T1302-C004; sources=SRC-elastic-esa-2026-83 -->

## Technical Details

### Prerequisites

- The agent or gateway can invoke a tool with elevated, administrative, root, cross-resource, or cross-tenant reach. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C008,SAF-T1302-C013; sources=SRC-ghsa-openclaw-gjm7,SRC-nvd-cve-2026-41378 -->
- An attacker can submit a low-privilege request or place untrusted content where the agent will process it. <!-- SAF-TRACE: claims=SAF-T1302-C005,SAF-T1302-C007; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h -->
- The system lacks effective requestor authorization, narrow scope binding, or a valid parameter-bound approval at execution time. <!-- SAF-TRACE: claims=SAF-T1302-C003,SAF-T1302-C004,SAF-T1302-C009; sources=SRC-mcp-authorization-2025-11-25,SRC-elastic-esa-2026-83 -->

### Attack Flow

1. **Setup**: The adversary identifies attacker-writable content or a low-privilege agent endpoint whose workflow can reach a high-risk tool. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C005; sources=SRC-invariant-github-mcp-2025 -->
2. **Delivery**: The adversary supplies content or a request that the agent treats as task context or an actionable event. <!-- SAF-TRACE: claims=SAF-T1302-C005,SAF-T1302-C007; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h -->
3. **Trigger**: The model or gateway selects and invokes the legitimate tool. <!-- SAF-TRACE: claims=SAF-T1302-C001,SAF-T1302-C004; sources=SRC-mcp-tools-2025-11-25,SRC-elastic-esa-2026-83 -->
4. **Boundary Crossing**: Authorization is evaluated for the agent identity instead of the originating principal, or an earlier approval is reused for materially different input. <!-- SAF-TRACE: claims=SAF-T1302-C007,SAF-T1302-C008,SAF-T1302-C009; sources=SRC-ghsa-codewhale-g29h,SRC-ghsa-openclaw-gjm7,SRC-elastic-esa-2026-83 -->
5. **Objective**: The tool returns or performs an elevated action unavailable to the adversary directly. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C013; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h -->
6. **Follow-On Activity**: The result may expose private data or enable code execution within the bounded authority of the tool or process. <!-- SAF-TRACE: claims=SAF-T1302-C013; sources=SRC-invariant-github-mcp-2025,SRC-ghsa-codewhale-g29h,SRC-nvd-cve-2026-41378 -->

### Example Scenario

An external contributor places an inert instruction marker in `public.example/issues/42`. A repository assistant later reviews the issue using a session that can read `private.example/reports` and publish to the public project; absent a repository-bound policy and valid approval for the publish action, the assistant copies a placeholder classification label into a public draft. This synthetic scenario mirrors the demonstrated authority flow without reproducing payloads or private data. <!-- SAF-TRACE: claims=SAF-T1302-C005; sources=SRC-invariant-github-mcp-2025 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1302-C001 | MCP tools are model-controlled. | Demonstrated | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Interaction model is implementation-specific. |
| SAF-T1302-C002 | Tool access control, confirmation, visibility, validation, and logging are specified safeguards. | Demonstrated | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Some client safeguards are SHOULD-level. |
| SAF-T1302-C003 | MCP authorization calls for least-privilege scopes. | Demonstrated | SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Scope alone does not bind intent. |
| SAF-T1302-C004 | A low-trust principal can obtain a higher-authority tool effect through an authorization or approval gap. | Demonstrated | SRC-invariant-github-mcp-2025, SRC-ghsa-codewhale-g29h, SRC-elastic-esa-2026-83 | Public evidence is not a production intrusion. |
| SAF-T1302-C005 | GitHub MCP research completed the defining tool-abuse sequence. | Demonstrated | SRC-invariant-github-mcp-2025: [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability) | Demo repositories and one client configuration. |
| SAF-T1302-C006 | Structured decision, approval, tool, and outcome fields support monitoring. | Research-Derived | SRC-owasp-agent-security: [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) | Guidance is not a universal schema. |
| SAF-T1302-C007 | CodeWhale reused an approved process without reapproval and was fixed in 0.8.64. | Demonstrated | SRC-ghsa-codewhale-g29h, SRC-nvd-cve-2026-75857 | Prior approved process required. |
| SAF-T1302-C008 | OpenClaw paired nodes could reach broader gateway tools and was fixed in 2026.3.31. | Demonstrated | SRC-ghsa-openclaw-gjm7, SRC-nvd-cve-2026-41378 | Trusted paired-node foothold required. |
| SAF-T1302-C009 | Kibana Agent Builder omitted a feature-privilege check and was fixed in 9.4.4. | Demonstrated | SRC-elastic-esa-2026-83, SRC-nvd-cve-2026-72681 | Affected data set is not specified. |
| SAF-T1302-C010 | The provided correlation is an evidence-backed SAF analytic synthesis. | Research-Derived | SRC-owasp-agent-security, SRC-mcp-tools-2025-11-25 | Requires local risk labels. |
| SAF-T1302-C011 | Missing authorization fields and legitimate emergency access create blind spots and lookalikes. | Research-Derived | SRC-owasp-agent-security, SRC-elastic-esa-2026-83 | False-positive rate is unmeasured. |
| SAF-T1302-C012 | Least privilege and parameter-bound approval constrain the mechanism. | Research-Derived | SRC-owasp-agent-security, SRC-mcp-authorization-2025-11-25 | Controls do not prove model resistance. |
| SAF-T1302-C013 | Consequences inherit the tool's bounded CIA reach. | Demonstrated | SRC-invariant-github-mcp-2025, SRC-ghsa-codewhale-g29h, SRC-nvd-cve-2026-41378 | Deployment controls bound impact. |
| SAF-T1302-C014 | ATT&CK T1078.004 is analogous, not direct. | Research-Derived | SRC-mitre-t1078-004: [MITRE ATT&CK](https://attack.mitre.org/techniques/T1078/004/) | ATT&CK lacks agent approval semantics. |
| SAF-T1302-C015 | Containment, telemetry preservation, scope analysis, policy repair, and regression tests form a supported response sequence. | Research-Derived | SRC-owasp-agent-security, SRC-mcp-tools-2025-11-25 | Credential rotation is conditional. |

### Current State

- **Affected Environments**: Agentic and MCP systems in which tools, service identities, or approved processes hold more authority than the influencing requestor or content. <!-- SAF-TRACE: claims=SAF-T1302-C004; sources=SRC-invariant-github-mcp-2025,SRC-elastic-esa-2026-83 -->
- **Known Exploitation**: Controlled demonstrations and proof-of-concept status exist; no qualifying production compromise was identified in the reviewed corpus. [Research coverage](../../research/techniques/SAF-T1302/source-coverage.yml)
- **Available Protections**: Fixed product versions, requestor-aware authorization, least-privilege scopes, explicit action approval, visible inputs, and structured audit logging. <!-- SAF-TRACE: claims=SAF-T1302-C002,SAF-T1302-C003,SAF-T1302-C007,SAF-T1302-C008,SAF-T1302-C009,SAF-T1302-C012; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-authorization-2025-11-25,SRC-ghsa-codewhale-g29h,SRC-ghsa-openclaw-gjm7,SRC-elastic-esa-2026-83,SRC-owasp-agent-security -->
- **Residual Risk**: Approval fatigue, lost provenance, incomplete field joins, and intentionally broad automation can leave the authority mismatch detectable only through contextual correlation. <!-- SAF-TRACE: claims=SAF-T1302-C005,SAF-T1302-C011; sources=SRC-invariant-github-mcp-2025,SRC-owasp-agent-security -->

### Known Breaches and Vulnerabilities

No qualifying production breach was identified in the directly reviewed corpus as of 2026-09-01. [Search and exclusion record](../../research/techniques/SAF-T1302/source-coverage.yml)

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-41378 / GHSA-gjm7-hw8f-73rq | 2026; OpenClaw through 2026.3.28 | Broader gateway tool access and possible gateway code execution; fixed in 2026.3.31. | Direct vulnerability: low-privilege paired node reached higher-authority agent dispatch. | Trusted paired-node foothold required; CISA SSVC reports no exploitation. <!-- SAF-TRACE: claims=SAF-T1302-C008; sources=SRC-ghsa-openclaw-gjm7,SRC-nvd-cve-2026-41378 --> |
| CVE-2026-75857 / GHSA-g29h-pfmp-qp9r | 2026; CodeWhale 0.8.41 to before 0.8.64 | Commands could execute inside a prior-approved process at its privilege; fixed in 0.8.64. | Direct vulnerability: model-controlled input bypassed action reapproval. | Prior interactive-process approval required; CISA SSVC reports proof of concept, not production use. <!-- SAF-TRACE: claims=SAF-T1302-C007; sources=SRC-ghsa-codewhale-g29h,SRC-nvd-cve-2026-75857 --> |
| CVE-2026-72681 / ESA-2026-83 | 2026; Kibana Agent Builder 9.4.0-9.4.3 | Possible unauthorized sensitive-information disclosure; fixed in 9.4.4 with no workaround. | Direct vulnerability: missing requestor privilege check before tool creation and execution. | Elastic names no specific IoC and NVD's CISA data reports no exploitation. <!-- SAF-TRACE: claims=SAF-T1302-C009,SAF-T1302-C011; sources=SRC-elastic-esa-2026-83,SRC-nvd-cve-2026-72681 --> |
| GitHub MCP private-repository demonstration | 2025; Claude Desktop, GitHub MCP, demo repositories | Private data was read and placed in a public pull request; granular repository and data-flow controls were recommended. | Direct demonstration: attacker-writable public content drove trusted higher-authority tools. | Controlled experiment, not a production incident or server-code vulnerability. <!-- SAF-TRACE: claims=SAF-T1302-C005; sources=SRC-invariant-github-mcp-2025 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Private repository and product disclosures show access can extend to sensitive data available to the abused identity or process. <!-- SAF-TRACE: claims=SAF-T1302-C005,SAF-T1302-C008,SAF-T1302-C009,SAF-T1302-C013; sources=SRC-invariant-github-mcp-2025,SRC-nvd-cve-2026-41378,SRC-elastic-esa-2026-83 --> |
| Integrity | High | A privileged interactive process or gateway tool can perform state-changing actions within its granted authority. <!-- SAF-TRACE: claims=SAF-T1302-C007,SAF-T1302-C008,SAF-T1302-C013; sources=SRC-ghsa-codewhale-g29h,SRC-nvd-cve-2026-41378 --> |
| Availability | High | Code execution under a privileged process or gateway can affect availability, but only within reachable systems and downstream controls. <!-- SAF-TRACE: claims=SAF-T1302-C007,SAF-T1302-C008,SAF-T1302-C013; sources=SRC-ghsa-codewhale-g29h,SRC-nvd-cve-2026-41378 --> |
| Scope | Multi-System | Cross-repository, gateway, or downstream-service reach is possible when one agent identity spans resources; narrow scopes limit the blast radius. <!-- SAF-TRACE: claims=SAF-T1302-C003,SAF-T1302-C005,SAF-T1302-C008,SAF-T1302-C013; sources=SRC-mcp-authorization-2025-11-25,SRC-invariant-github-mcp-2025,SRC-ghsa-openclaw-gjm7 --> |

### Severity Conditions

- **Severity increases when**: The tool can reach administrative, root, cross-tenant, production, or sensitive-data operations and approval is absent or reusable. <!-- SAF-TRACE: claims=SAF-T1302-C007,SAF-T1302-C008,SAF-T1302-C013; sources=SRC-ghsa-codewhale-g29h,SRC-nvd-cve-2026-41378 -->
- **Severity decreases when**: Tool functionality, identities, resources, and scopes are narrow and each high-impact action requires a fresh parameter-bound authorization. <!-- SAF-TRACE: claims=SAF-T1302-C003,SAF-T1302-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-owasp-agent-security -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP client, agent gateway, and tool broker | Tool selection, authorization decision, approval, invocation, and result | Timestamp, session, requestor, server, tool, risk, effective privilege, argument digest, approval state and ID, policy version, outcome | Preserve causal ordering and redact secrets while retaining stable digests. <!-- SAF-TRACE: claims=SAF-T1302-C006; sources=SRC-owasp-agent-security --> |
| Identity and downstream service logs | Token or service identity use and privileged resource action | Principal, resource, action, scope or role, decision, source session, result | Join to the originating agent session; missing joins are a documented blind spot. <!-- SAF-TRACE: claims=SAF-T1302-C006,SAF-T1302-C011; sources=SRC-owasp-agent-security --> |

### Indicators of Compromise (IoCs)

- No technique-wide durable IoC is known; Elastic likewise identified no specific IoC for CVE-2026-72681, so detection should focus on authorization and behavior. <!-- SAF-TRACE: claims=SAF-T1302-C011; sources=SRC-elastic-esa-2026-83,SRC-owasp-agent-security -->

### Behavioral Indicators

- A successful high-risk tool call where the effective tool privilege exceeds the originating requestor's trust or privilege. <!-- SAF-TRACE: claims=SAF-T1302-C010; sources=SRC-owasp-agent-security -->
- A missing, bypassed, expired, or non-parameter-bound approval immediately before an elevated action. <!-- SAF-TRACE: claims=SAF-T1302-C002,SAF-T1302-C007,SAF-T1302-C010; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-codewhale-g29h,SRC-owasp-agent-security -->
- Cross-resource access or a privileged action inconsistent with the session's stated task and requestor authorization. <!-- SAF-TRACE: claims=SAF-T1302-C005,SAF-T1302-C006,SAF-T1302-C010; sources=SRC-invariant-github-mcp-2025,SRC-owasp-agent-security -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify successful elevated tool effects initiated by low-trust principals without valid action approval. <!-- SAF-TRACE: claims=SAF-T1302-C010; sources=SRC-owasp-agent-security,SRC-mcp-tools-2025-11-25 -->
- **Rule Status**: Experimental; deterministic synthetic tests pass. [Quality review](../../research/techniques/SAF-T1302/quality-review.yml)
- **Detection Logic**: Correlate a high-risk successful tool call with a low-trust requestor, elevated effective privilege, and missing, bypassed, or unnecessary approval; suppress explicitly authorized break-glass use. <!-- SAF-TRACE: claims=SAF-T1302-C010,SAF-T1302-C011; sources=SRC-owasp-agent-security,SRC-mcp-tools-2025-11-25 -->
- **Correlation Window**: One normalized tool-call decision and execution transaction, with platform-specific session joins. <!-- SAF-TRACE: claims=SAF-T1302-C006,SAF-T1302-C010; sources=SRC-owasp-agent-security -->
- **Known False Positives**: Emergency access with lost approval context and intentionally elevated unattended automation mislabeled as low trust. <!-- SAF-TRACE: claims=SAF-T1302-C011; sources=SRC-owasp-agent-security -->
- **Known Limitations**: Missing requestor, tool privilege, approval, policy, or outcome fields prevent evaluation; the rule does not detect a blocked attempt or prove malicious intent. <!-- SAF-TRACE: claims=SAF-T1302-C011; sources=SRC-owasp-agent-security,SRC-elastic-esa-2026-83 -->
- **Tuning Guidance**: Maintain reviewed tool-risk and effective-privilege labels, bind approvals to argument digests, and tightly govern break-glass suppression. <!-- SAF-TRACE: claims=SAF-T1302-C006,SAF-T1302-C010,SAF-T1302-C012; sources=SRC-owasp-agent-security -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1302/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1302/test_detection_rule.py)
- **Expected Result**: Nine cases pass: three positive, two negative, two boundary, one malformed, and one expected legitimate lookalike. [Recorded test log](../../tests/SAF-T1302/test-logs.json)
- **Last Validated**: 2026-09-01. [Quality review](../../research/techniques/SAF-T1302/quality-review.yml)
- **Feasibility Waiver**: None. [Technique contract](../../research/techniques/SAF-T1302/technique-contract.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Expose only required tools and operations, and bind scopes and resources to the task and requestor. <!-- SAF-TRACE: claims=SAF-T1302-C003,SAF-T1302-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-owasp-agent-security -->
2. **[SAF-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../../mitigations/SAF-M-69/README.md)**: Require fresh approval for high-impact calls and bind it to the displayed tool, parameters, resource, principal, and expiry. <!-- SAF-TRACE: claims=SAF-T1302-C002,SAF-T1302-C007,SAF-T1302-C012; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-codewhale-g29h,SRC-owasp-agent-security -->
3. **Patch direct vulnerabilities**: Upgrade CodeWhale to 0.8.64 or later, OpenClaw to 2026.3.31 or later, and Kibana to 9.4.4 or later for the selected affected lines. <!-- SAF-TRACE: claims=SAF-T1302-C007,SAF-T1302-C008,SAF-T1302-C009; sources=SRC-ghsa-codewhale-g29h,SRC-ghsa-openclaw-gjm7,SRC-elastic-esa-2026-83 -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Log requestor identity, tool privilege, approval, arguments digest, policy version, and outcome, then alert on authority mismatches. <!-- SAF-TRACE: claims=SAF-T1302-C006,SAF-T1302-C010; sources=SRC-owasp-agent-security,SRC-mcp-tools-2025-11-25 -->
2. **Cross-source review**: Join agent traces to identity and downstream service logs so the originating principal and final privileged action remain attributable. <!-- SAF-TRACE: claims=SAF-T1302-C006,SAF-T1302-C011; sources=SRC-owasp-agent-security -->

### Response Procedures

#### Immediate Actions

- Contain the affected agent session, tool connection, and privileged identity; disable only the implicated high-risk route while preserving evidence. <!-- SAF-TRACE: claims=SAF-T1302-C015; sources=SRC-owasp-agent-security,SRC-mcp-tools-2025-11-25 -->
- Revoke or rotate credentials only when telemetry shows exposure, unauthorized use, or loss of control. <!-- SAF-TRACE: claims=SAF-T1302-C015; sources=SRC-owasp-agent-security -->

#### Investigation Steps

- Preserve the model decision, tool arguments digest, approval record, policy version, result, and matching downstream service events. <!-- SAF-TRACE: claims=SAF-T1302-C006,SAF-T1302-C015; sources=SRC-owasp-agent-security -->
- Reconstruct the originating principal, untrusted input path, effective tool identity, accessed resources, and follow-on actions. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C015; sources=SRC-invariant-github-mcp-2025,SRC-owasp-agent-security -->

#### Remediation

- Upgrade affected software and replace reusable or agent-only authorization with requestor-aware, resource-scoped, parameter-bound checks. <!-- SAF-TRACE: claims=SAF-T1302-C007,SAF-T1302-C008,SAF-T1302-C009,SAF-T1302-C012,SAF-T1302-C015; sources=SRC-ghsa-codewhale-g29h,SRC-ghsa-openclaw-gjm7,SRC-elastic-esa-2026-83,SRC-owasp-agent-security -->
- Restore altered state, validate access boundaries, and add the incident path to repeatable tool-abuse and approval-bypass regression tests. <!-- SAF-TRACE: claims=SAF-T1302-C012,SAF-T1302-C015; sources=SRC-owasp-agent-security -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite or co-occurring | Covers adversarial influence; SAF-T1302 requires a higher-authority legitimate tool effect. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C005; sources=SRC-invariant-github-mcp-2025 --> |
| [SAF-T1304: Credential Relay Chain](../SAF-T1304/README.md) | Alternative or co-occurring | Covers credential propagation or direct credential use; SAF-T1302 keeps the agent or tool as deputy. <!-- SAF-TRACE: claims=SAF-T1302-C004; sources=SRC-elastic-esa-2026-83 --> |
| [SAF-T1303: Sandbox Escape via Server Exec](../SAF-T1303/README.md) | Follow-on or overlapping | Covers the execution primitive; SAF-T1302 covers missing authorization or approval for a legitimate tool. <!-- SAF-TRACE: claims=SAF-T1302-C004,SAF-T1302-C007; sources=SRC-ghsa-codewhale-g29h --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | Analogous | Both can turn a high-privilege service or cloud identity into elevated access, but ATT&CK centers on valid-account use and does not model agent tool selection or action approval. <!-- SAF-TRACE: claims=SAF-T1302-C014; sources=SRC-mitre-t1078-004 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [MCP Tools specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) - Model Context Protocol specification contributors; invocation and security considerations.
2. **SRC-mcp-authorization-2025-11-25**: [MCP Authorization specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) - Model Context Protocol specification contributors; scope selection.
3. **SRC-owasp-agent-security**: [AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) - OWASP Cheat Sheet Series project team; controls, telemetry, and testing.
4. **SRC-invariant-github-mcp-2025**: [GitHub MCP Exploited](https://invariantlabs.ai/blog/mcp-github-vulnerability) - Marco Milanta and Luca Beurer-Kellner, 2025; controlled demonstration and limits.
5. **SRC-ghsa-codewhale-g29h**: [GHSA-g29h-pfmp-qp9r](https://github.com/Hmbown/CodeWhale/security/advisories/GHSA-g29h-pfmp-qp9r) - reporter sai-sh and CodeWhale maintainers, 2026; approval bypass and fix.
6. **SRC-nvd-cve-2026-75857**: [CVE-2026-75857](https://nvd.nist.gov/vuln/detail/CVE-2026-75857) - NVD, VulnCheck CNA, and CISA Coordinator; severity and exploitation status.
7. **SRC-ghsa-openclaw-gjm7**: [GHSA-gjm7-hw8f-73rq](https://github.com/openclaw/openclaw/security/advisories/GHSA-gjm7-hw8f-73rq) - AntAISecurityLab and OpenClaw maintainers, 2026; boundary, affected versions, and fix.
8. **SRC-nvd-cve-2026-41378**: [CVE-2026-41378](https://nvd.nist.gov/vuln/detail/CVE-2026-41378) - NVD, VulnCheck CNA, and CISA Coordinator; impact and exploitation status.
9. **SRC-elastic-esa-2026-83**: [Kibana 9.4.4 Security Update](https://discuss.elastic.co/t/kibana-9-4-4-security-update-esa-2026-83/389534) - Ioannis Kakavas and Elastic Product Security, 2026; missing authorization and remediation.
10. **SRC-nvd-cve-2026-72681**: [CVE-2026-72681](https://nvd.nist.gov/vuln/detail/CVE-2026-72681) - NVD, Elastic, and CISA Coordinator; impact and exploitation status.
11. **SRC-mitre-t1078-004**: [Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) - MITRE ATT&CK and named contributors; analogous mapping.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Clean-room initial publication candidate with independent evidence packet and tested detection. | OpenAI Codex clean-room research agent |
