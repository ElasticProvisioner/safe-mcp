# SAF-T1603: System Prompt Disclosure

## Overview

- **Tactic**: Discovery (ATK-TA0007) <!-- SAF-TRACE: claims=SAF-T1603-C005; sources=SRC-atlas-2026-08 -->
- **Technique ID**: SAF-T1603
- **Research Packet**: [research/techniques/SAF-T1603](../../research/techniques/SAF-T1603/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1603/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Demonstrated
- **Severity**: High <!-- SAF-TRACE: claims=SAF-T1603-C016; sources=SRC-owasp-llm07,SRC-ghsa-weknora,SRC-ghsa-praisonai -->
- **Severity Rationale**: Unauthorized disclosure can expose privileged application logic or control assumptions, but actual harm depends on prompt content and surrounding privileges. <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C016; sources=SRC-owasp-llm07,SRC-ghsa-weknora,SRC-ghsa-praisonai -->
- **First Observed**: Not observed in a qualifying production breach; publicly demonstrated no later than the 2026-01-25 ClawdBot exercise. <!-- SAF-TRACE: claims=SAF-T1603-C006,SAF-T1603-C014; sources=SRC-atlas-2026-08,SRC-nvd-audit -->
- **Last Updated**: 2026-09-02

## Scope

This technique covers unauthorized recovery of the whole or a substantial portion of hidden system, developer, or agent instructions across the boundary separating privileged instruction context from an untrusted requester, remote peer, or tool-mediated recipient. <!-- SAF-TRACE: claims=SAF-T1603-C001,SAF-T1603-C003,SAF-T1603-C005; sources=SRC-mcp-architecture,SRC-openai-model-spec,SRC-atlas-2026-08 -->

### In Scope

- A model or agent response that reveals hidden instruction content to an unauthorized requester. <!-- SAF-TRACE: claims=SAF-T1603-C003,SAF-T1603-C005,SAF-T1603-C007; sources=SRC-openai-model-spec,SRC-atlas-2026-08,SRC-arxiv-justask -->
- An application, configuration, or agent interface that returns hidden instructions across an authorization boundary. <!-- SAF-TRACE: claims=SAF-T1603-C009,SAF-T1603-C010; sources=SRC-ghsa-open-webui,SRC-ghsa-praisonai -->
- Tool-mediated exfiltration when obtaining privileged instructions is the immediate objective. <!-- SAF-TRACE: claims=SAF-T1603-C008; sources=SRC-ghsa-weknora -->

### Out of Scope

- Prompt injection or jailbreak activity that changes behavior without disclosing hidden instructions. <!-- SAF-TRACE: claims=SAF-T1603-C005; sources=SRC-atlas-2026-08 -->
- Authorized MCP `prompts/list` or `prompts/get` access to server-declared, user-controlled prompt templates. <!-- SAF-TRACE: claims=SAF-T1603-C002; sources=SRC-mcp-prompts -->
- Exposure limited to user data, training data, credentials, operating-system memory, or logs without hidden instruction content. <!-- SAF-TRACE: claims=SAF-T1603-C004; sources=SRC-owasp-llm07 -->

### Distinguishing Characteristics

The defining observable is unauthorized recovery of privileged instruction content. Prompt injection may be a delivery mechanism, and sensitive-data disclosure may co-occur, but neither is this technique unless the immediate recovered object is the hidden instruction itself. <!-- SAF-TRACE: claims=SAF-T1603-C005,SAF-T1603-C008; sources=SRC-atlas-2026-08,SRC-ghsa-weknora -->

## Description

System Prompt Disclosure occurs when an adversary obtains hidden instructions intended to govern a model or agent session. The disclosure can arise from model output, a misconfigured application API, a prompt/configuration store, or a tool-mediated path. <!-- SAF-TRACE: claims=SAF-T1603-C005,SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-atlas-2026-08,SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->

MCP separates host context from servers: the host retains conversation history and enforces the security boundary, while servers should not receive the whole conversation. Server-declared MCP prompt templates are deliberately discoverable and therefore require separate authorization analysis from hidden host or builder instructions. <!-- SAF-TRACE: claims=SAF-T1603-C001,SAF-T1603-C002; sources=SRC-mcp-architecture,SRC-mcp-prompts -->

The technique is Demonstrated. Public research reports controlled extraction, ATLAS records an exercise, and current advisories document direct application and MCP-connected disclosure paths. None of those authorities establishes a qualifying malicious production breach. <!-- SAF-TRACE: claims=SAF-T1603-C006,SAF-T1603-C007,SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010,SAF-T1603-C014; sources=SRC-atlas-2026-08,SRC-arxiv-justask,SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai,SRC-nvd-audit -->

## Attack Vectors

- **Primary Vector**: An untrusted requester induces a model or agent to return hidden instructions in its output. <!-- SAF-TRACE: claims=SAF-T1603-C006,SAF-T1603-C007; sources=SRC-atlas-2026-08,SRC-arxiv-justask -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->
  - An under-protected application or configuration endpoint returns stored prompts. <!-- SAF-TRACE: claims=SAF-T1603-C009,SAF-T1603-C010; sources=SRC-ghsa-open-webui,SRC-ghsa-praisonai -->
  - A malicious MCP server influences tool selection or model context and receives prompt content. <!-- SAF-TRACE: claims=SAF-T1603-C008; sources=SRC-ghsa-weknora -->
- **Affected Components**: MCP host and client, agent application, model gateway, prompt/configuration store, and model response pipeline. <!-- SAF-TRACE: claims=SAF-T1603-C001,SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-mcp-architecture,SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->
- **Trust Boundary Crossed**: Privileged host- or builder-controlled instruction context becomes visible to an unauthorized requester or remote peer. <!-- SAF-TRACE: claims=SAF-T1603-C001,SAF-T1603-C003; sources=SRC-mcp-architecture,SRC-openai-model-spec -->

## Technical Details

### Prerequisites

- The target uses hidden system, developer, or agent instructions that are reachable by the model or an application interface. <!-- SAF-TRACE: claims=SAF-T1603-C003,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-openai-model-spec,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->
- The adversary can submit input, reach an exposed interface, or influence an attached MCP server. <!-- SAF-TRACE: claims=SAF-T1603-C006,SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-atlas-2026-08,SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->
- Output handling or access control fails to preserve the instruction boundary. <!-- SAF-TRACE: claims=SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies an agent, model conversation, prompt API, or attached MCP server that may reach privileged instructions. <!-- SAF-TRACE: claims=SAF-T1603-C005,SAF-T1603-C008,SAF-T1603-C009; sources=SRC-atlas-2026-08,SRC-ghsa-weknora,SRC-ghsa-open-webui -->
2. **Delivery**: The adversary sends a request, reaches the exposed interface, or supplies server-controlled context. <!-- SAF-TRACE: claims=SAF-T1603-C006,SAF-T1603-C008,SAF-T1603-C010; sources=SRC-atlas-2026-08,SRC-ghsa-weknora,SRC-ghsa-praisonai -->
3. **Trigger or Execution**: The model generates revealing output or the application returns stored instruction fields. <!-- SAF-TRACE: claims=SAF-T1603-C006,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-atlas-2026-08,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->
4. **Boundary Crossing**: Hidden instruction content leaves the privileged context without required authorization. <!-- SAF-TRACE: claims=SAF-T1603-C001,SAF-T1603-C003,SAF-T1603-C009; sources=SRC-mcp-architecture,SRC-openai-model-spec,SRC-ghsa-open-webui -->
5. **Objective**: The adversary receives the whole or a substantial portion of the hidden instruction content. <!-- SAF-TRACE: claims=SAF-T1603-C005,SAF-T1603-C006; sources=SRC-atlas-2026-08 -->
6. **Follow-On Activity**: The disclosure may support later evasion or exploitation, which must be classified separately. <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C005,SAF-T1603-C016; sources=SRC-owasp-llm07,SRC-atlas-2026-08,SRC-ghsa-weknora,SRC-ghsa-praisonai -->

### Example Scenario

An organization exposes an agent inventory endpoint to a remote network without authentication. A peer requests one synthetic agent record, and the response includes the instruction string that should have remained host-controlled; the defender correlates the API response with a protected-prompt overlap alert. <!-- SAF-TRACE: claims=SAF-T1603-C010,SAF-T1603-C011,SAF-T1603-C012; sources=SRC-ghsa-praisonai,SRC-arxiv-spe-llm,SRC-otel-genai-events -->

```json
{
  "event.name": "gen_ai.client.inference.operation.details",
  "gen_ai.conversation.id": "conv-synthetic-001",
  "saf.system_prompt.overlap_count": 2,
  "saf.disclosure.authorized": false
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1603-C006 | An exposed ClawdBot interface returned its system prompt in an ATLAS-recorded exercise. | Demonstrated | SRC-atlas-2026-08: [MITRE ATLAS 2026.08](https://atlas.mitre.org/atlas-data/dist/v6/ATLAS-2026.08.yaml) | Exercise, not a confirmed malicious production breach. |
| SAF-T1603-C007 | Controlled black-box research extracted prompts across commercial models and evaluated production assistants. | Demonstrated | SRC-arxiv-justask: [JustAsk](https://arxiv.org/html/2601.21233) | Some black-box ground truth depends on an oracle or consistency measure. |
| SAF-T1603-C008 | WeKnora permitted MCP-mediated system-context exfiltration before version 0.3.0. | Demonstrated vulnerability | SRC-ghsa-weknora: [GHSA-67q9-58vj-32qx](https://github.com/Tencent/WeKnora/security/advisories/GHSA-67q9-58vj-32qx) | Proof of concept; no confirmed malicious exploitation. |
| SAF-T1603-C009 | Open WebUI exposed administrator-configured prompts to regular users before version 0.8.9. | Demonstrated vulnerability | SRC-ghsa-open-webui: [GHSA-jh9g-8jqw-m2qx](https://github.com/open-webui/open-webui/security/advisories/GHSA-jh9g-8jqw-m2qx) | Proof of concept; no confirmed malicious exploitation. |
| SAF-T1603-C010 | PraisonAI insecure defaults exposed prompts to unauthenticated peers before version 1.7.3. | Demonstrated vulnerability | SRC-ghsa-praisonai: [GHSA-6wjp-v33h-5cvq](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-6wjp-v33h-5cvq) | Runtime-confirmed vulnerability; no confirmed malicious exploitation. |

### Current State

- **Affected Environments**: Agentic or LLM applications that retain privileged instructions in model context or expose them through under-protected application, configuration, or MCP-connected paths. <!-- SAF-TRACE: claims=SAF-T1603-C003,SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-openai-model-spec,SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->
- **Known Exploitation**: Public exercises, controlled research, and proofs of concept are documented; the reviewed authorities do not establish a qualifying malicious production breach. <!-- SAF-TRACE: claims=SAF-T1603-C006,SAF-T1603-C007,SAF-T1603-C014; sources=SRC-atlas-2026-08,SRC-arxiv-justask,SRC-nvd-audit -->
- **Available Protections**: Patched product versions, access controls for prompt stores and configuration interfaces, external authorization, and output monitoring reduce exposure. <!-- SAF-TRACE: claims=SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010,SAF-T1603-C015; sources=SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai,SRC-owasp-llm07,SRC-atlas-2026-08 -->
- **Residual Risk**: Output filters and instruction-only defenses can miss paraphrase or transformed disclosure, so prompt secrecy cannot substitute for external controls. <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C011,SAF-T1603-C015; sources=SRC-owasp-llm07,SRC-arxiv-spe-llm,SRC-atlas-2026-08 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| ClawdBot control-interface exercise | 2026-01-25; exposed agent control interface | Returned the SOUL.md system prompt; restrict interface exposure and access. | Direct demonstration | ATLAS classifies it as an exercise, not a production breach. | <!-- SAF-TRACE: claims=SAF-T1603-C006; sources=SRC-atlas-2026-08 -->
| CVE-2026-61426 / GHSA-6wjp-v33h-5cvq | 2026-06-25; PraisonAI before 1.7.3 with insecure defaults | Unauthenticated peers could read agent instructions; upgrade to 1.7.3 or later. | Direct vulnerability | Runtime-confirmed; malicious production exploitation not established. | <!-- SAF-TRACE: claims=SAF-T1603-C010; sources=SRC-ghsa-praisonai -->
| CVE-2026-30856 / GHSA-67q9-58vj-32qx | 2026-03-06; WeKnora through 0.2.14 with a malicious remote MCP server | Tool collision and indirect injection could exfiltrate system context; upgrade to 0.3.0 or later. | Direct vulnerability | Controlled proof of concept; production exploitation not established. | <!-- SAF-TRACE: claims=SAF-T1603-C008; sources=SRC-ghsa-weknora -->
| CVE-2026-45351 / GHSA-jh9g-8jqw-m2qx | 2026-05-09; Open WebUI through 0.8.8 | Regular users could retrieve administrator-configured prompts; upgrade to 0.8.9 or later. | Direct vulnerability | Proof of concept; production exploitation not established. | <!-- SAF-TRACE: claims=SAF-T1603-C009; sources=SRC-ghsa-open-webui -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Privileged instruction content crosses to an unauthorized party; materiality depends on whether the prompt contains proprietary logic, control assumptions, or improperly embedded secrets. | <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C016; sources=SRC-owasp-llm07,SRC-ghsa-weknora,SRC-ghsa-praisonai -->
| Integrity | Low | Disclosure alone does not alter state, but recovered control logic may assist separately classified evasion or manipulation. | <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C016; sources=SRC-owasp-llm07 -->
| Availability | None | No availability effect is inherent to disclosure. | <!-- SAF-TRACE: claims=SAF-T1603-C016; sources=SRC-owasp-llm07,SRC-ghsa-weknora,SRC-ghsa-praisonai -->
| Scope | Adjacent | The immediate exposure is bounded to reachable prompts and sessions; follow-on impact depends on connected privileges and systems. | <!-- SAF-TRACE: claims=SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010,SAF-T1603-C016; sources=SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->

### Severity Conditions

- **Severity increases when** prompts contain secrets, authorization logic, high-value proprietary instructions, or details of privileged tool access. <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C016; sources=SRC-owasp-llm07,SRC-ghsa-weknora,SRC-ghsa-praisonai -->
- **Severity decreases when** prompts exclude sensitive data, authorization is external and deterministic, access is scoped, and disclosed text does not enable additional capability. <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C015; sources=SRC-owasp-llm07,SRC-atlas-2026-08 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Model or agent response events | Response emission | operation name, conversation ID, actor, model, output, authorization state | Capture content only when permitted; protect and minimize sensitive telemetry. | <!-- SAF-TRACE: claims=SAF-T1603-C012; sources=SRC-otel-genai-events -->
| Secure prompt-protection service | Prompt overlap or canary match | overlap count, canary match, prompt version, authorized-disclosure flag | Keep protected prompt text out of ordinary logs; emit derived metadata. | <!-- SAF-TRACE: claims=SAF-T1603-C011,SAF-T1603-C015; sources=SRC-arxiv-spe-llm,SRC-owasp-llm07 -->

### Indicators of Compromise (IoCs)

- None known. The technique is behavioral and does not inherently create a durable artifact. <!-- SAF-TRACE: claims=SAF-T1603-C006,SAF-T1603-C007,SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-atlas-2026-08,SRC-arxiv-justask,SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->

### Behavioral Indicators

- A response contains multiple protected instruction chunks or a purpose-built synthetic canary not expected in ordinary output. <!-- SAF-TRACE: claims=SAF-T1603-C011; sources=SRC-arxiv-spe-llm -->
- The alert is stronger when the response is tied to an untrusted requester or remote peer and lacks an authorized-disclosure flag. <!-- SAF-TRACE: claims=SAF-T1603-C009,SAF-T1603-C010,SAF-T1603-C012; sources=SRC-ghsa-open-webui,SRC-ghsa-praisonai,SRC-otel-genai-events -->
- Authorized diagnostics and deliberately public prompt material must be allowlisted to reduce false positives. <!-- SAF-TRACE: claims=SAF-T1603-C002,SAF-T1603-C011; sources=SRC-mcp-prompts,SRC-arxiv-spe-llm -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect unauthorized response events with derived evidence that protected instruction content was emitted. <!-- SAF-TRACE: claims=SAF-T1603-C011,SAF-T1603-C012; sources=SRC-arxiv-spe-llm,SRC-otel-genai-events -->
- **Rule Status**: [Experimental](detection-rule.yml)
- **Detection Logic**: Require a model-response event plus either two protected-prompt chunk overlaps or a canary match, then suppress explicitly authorized disclosure. <!-- SAF-TRACE: claims=SAF-T1603-C011; sources=SRC-arxiv-spe-llm -->
- **Correlation Window**: One response event; upstream enrichment may aggregate chunks within that response. <!-- SAF-TRACE: claims=SAF-T1603-C011; sources=SRC-arxiv-spe-llm -->
- **Known False Positives**: Authorized debugging, deliberate public-prompt publication, and defensive evaluations. <!-- SAF-TRACE: claims=SAF-T1603-C002,SAF-T1603-C011; sources=SRC-mcp-prompts,SRC-arxiv-spe-llm -->
- **Known Limitations**: Paraphrase, translation, encoding, partial one-chunk disclosure, disabled content capture, or missing authorization context can evade or weaken the analytic. <!-- SAF-TRACE: claims=SAF-T1603-C011,SAF-T1603-C012; sources=SRC-arxiv-spe-llm,SRC-otel-genai-events -->
- **Tuning Guidance**: Select chunks that are distinctive, rotate canaries on prompt changes, and keep authorized actors and public templates in narrow allowlists. <!-- SAF-TRACE: claims=SAF-T1603-C002,SAF-T1603-C011; sources=SRC-mcp-prompts,SRC-arxiv-spe-llm -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1603/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1603/test_detection_rule.py)
- **Expected Result**: [Two synthetic positive cases alert and six negative or boundary cases do not](../../tests/SAF-T1603/test-logs.json).
- **Last Validated**: [2026-09-02](../../research/techniques/SAF-T1603/quality-review.yml). [Recorded detector output](../../research/techniques/SAF-T1603/validation/detection-test.txt) [Strict validation](../../research/techniques/SAF-T1603/validation/strict-validator.txt)
- **Feasibility Waiver**: [None](../../research/techniques/SAF-T1603/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-1: Control/Data Flow Separation](../../mitigations/SAF-M-1/README.md)**: Keep credentials and authorization logic outside system prompts and enforce them in deterministic controls. <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C015; sources=SRC-owasp-llm07,SRC-atlas-2026-08 -->
2. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Authenticate and authorize prompt-store, model-configuration, and agent-administration access; apply **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)** to minimize exposed authority. <!-- SAF-TRACE: claims=SAF-T1603-C009,SAF-T1603-C010,SAF-T1603-C015; sources=SRC-ghsa-open-webui,SRC-ghsa-praisonai,SRC-atlas-2026-08 -->
3. **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)**: Apply host-controlled server authorization and preserve client isolation so a remote server cannot inherit unrelated conversation context. <!-- SAF-TRACE: claims=SAF-T1603-C001,SAF-T1603-C008; sources=SRC-mcp-architecture,SRC-ghsa-weknora -->
4. **Patch affected products**: Use WeKnora 0.3.0 or later, Open WebUI 0.8.9 or later, and PraisonAI 1.7.3 or later where applicable. <!-- SAF-TRACE: claims=SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010; sources=SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai -->

### Detective Controls

1. **[SAF-M-36: Model Behavior Monitoring](../../mitigations/SAF-M-36/README.md)**: Monitor model outputs for protected-prompt overlap or synthetic canaries, treating filters as a defense layer rather than proof of secrecy. <!-- SAF-TRACE: claims=SAF-T1603-C011,SAF-T1603-C015; sources=SRC-arxiv-spe-llm,SRC-owasp-llm07 -->
2. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Correlate output alerts with actor, conversation, interface, server, model, prompt version, and authorization state. <!-- SAF-TRACE: claims=SAF-T1603-C012,SAF-T1603-C015; sources=SRC-otel-genai-events,SRC-atlas-2026-08 -->

### Response Procedures

#### Immediate Actions

- Contain the affected session or interface, preserve evidence, and revoke unauthorized access to prompt/configuration stores. <!-- SAF-TRACE: claims=SAF-T1603-C009,SAF-T1603-C010,SAF-T1603-C015; sources=SRC-ghsa-open-webui,SRC-ghsa-praisonai,SRC-atlas-2026-08 -->
- Apply **[SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37/README.md)** to any credential improperly embedded in the prompt and move the security decision outside model instructions. <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C015; sources=SRC-owasp-llm07 -->

#### Investigation Steps

- Determine which prompt version and sessions were exposed, who received the output, and whether tool or configuration access followed. <!-- SAF-TRACE: claims=SAF-T1603-C012,SAF-T1603-C016; sources=SRC-otel-genai-events,SRC-ghsa-weknora,SRC-ghsa-praisonai -->
- Separate authorized MCP prompt discovery from hidden host-instruction disclosure before escalating. <!-- SAF-TRACE: claims=SAF-T1603-C001,SAF-T1603-C002; sources=SRC-mcp-architecture,SRC-mcp-prompts -->

#### Remediation

- Patch or reconfigure the exposed interface, restrict prompt-store access, and add regression tests for authorization and output monitoring. <!-- SAF-TRACE: claims=SAF-T1603-C008,SAF-T1603-C009,SAF-T1603-C010,SAF-T1603-C015; sources=SRC-ghsa-weknora,SRC-ghsa-open-webui,SRC-ghsa-praisonai,SRC-atlas-2026-08 -->
- Review disclosed instructions for embedded secrets or control logic and migrate those controls to protected external services. <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C015; sources=SRC-owasp-llm07 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite or co-occurring | Injection changes instruction processing; this technique requires recovery of hidden instruction content. | <!-- SAF-TRACE: claims=SAF-T1603-C005,SAF-T1603-C008; sources=SRC-atlas-2026-08,SRC-ghsa-weknora -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Analogous | Both collect system information for follow-on activity under Discovery, but T1082 concerns operating-system and hardware data rather than LLM instructions. | <!-- SAF-TRACE: claims=SAF-T1603-C013; sources=SRC-mitre-attack-t1082-current -->

### Additional Framework Mappings

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| MITRE ATLAS | AML.T0069.002 | System Prompt | Directly describes discovery of hidden LLM system instructions. | <!-- SAF-TRACE: claims=SAF-T1603-C005; sources=SRC-atlas-2026-08 -->
| MITRE ATLAS | AML.T0056 | Extract LLM System Prompt | Directly describes extraction through prompt injection or configuration access. | <!-- SAF-TRACE: claims=SAF-T1603-C005; sources=SRC-atlas-2026-08 -->
| OWASP GenAI | LLM07:2025 | System Prompt Leakage | Directly describes unintended disclosure risk and bounded prevention guidance. | <!-- SAF-TRACE: claims=SAF-T1603-C004,SAF-T1603-C015; sources=SRC-owasp-llm07 -->

## References

1. **SRC-mcp-architecture**: [MCP Architecture, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/architecture) — host and server context boundaries.
2. **SRC-mcp-prompts**: [MCP Prompts, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/prompts) — intended user-controlled prompt discovery.
3. **SRC-owasp-llm07**: [OWASP LLM07:2025 System Prompt Leakage](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/) — risk and prevention guidance.
4. **SRC-openai-model-spec**: [OpenAI Model Spec, 2025-12-18](https://model-spec.openai.com/2025-12-18.html) — privileged-information treatment.
5. **SRC-atlas-2026-08**: [MITRE ATLAS 2026.08 data release](https://atlas.mitre.org/atlas-data/dist/v6/ATLAS-2026.08.yaml) — technique definitions, exercise, and mitigations.
6. **SRC-mitre-attack-t1082-current**: [MITRE ATT&CK T1082](https://attack.mitre.org/techniques/T1082/) — analogous Discovery behavior.
7. **SRC-nvd-audit**: [NVD CVE API keyword audit](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=system%20prompt%20leakage) — bounded vulnerability-search record.
8. **SRC-ghsa-weknora**: [GHSA-67q9-58vj-32qx](https://github.com/Tencent/WeKnora/security/advisories/GHSA-67q9-58vj-32qx) — WeKnora MCP-mediated exfiltration vulnerability and patch.
9. **SRC-ghsa-open-webui**: [GHSA-jh9g-8jqw-m2qx](https://github.com/open-webui/open-webui/security/advisories/GHSA-jh9g-8jqw-m2qx) — Open WebUI prompt-access vulnerability and patch.
10. **SRC-ghsa-praisonai**: [GHSA-6wjp-v33h-5cvq](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-6wjp-v33h-5cvq) — PraisonAI prompt exposure and patch.
11. **SRC-arxiv-justask**: [JustAsk, ICML 2026](https://arxiv.org/html/2601.21233) — controlled extraction evaluation and limitations.
12. **SRC-arxiv-spe-llm**: [SPE-LLM, 2025](https://arxiv.org/html/2505.23817) — output-match defense evaluation and limitations.
13. **SRC-otel-genai-events**: [OpenTelemetry GenAI events](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-events.md) — developing telemetry conventions and sensitive-content cautions.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial clean-room draft | OpenAI Codex clean-room research agent |
