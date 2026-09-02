# SAF-T1110: Multimodal Prompt Injection via Images/Audio

## Overview

- **Tactic**: Execution (ATK-TA0002)
- **Technique ID**: SAF-T1110
- **Research Packet**: [research/techniques/SAF-T1110](../../research/techniques/SAF-T1110/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1110/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: High when a model can convert attacker-influenced image or audio content into an unapproved privileged action or sensitive transmission; isolation, least privilege, and approval gates reduce consequence. <!-- SAF-TRACE: claims=SAF-T1110-C012; sources=SRC-nist-ai-100-2e2025,SRC-mcp-tools-2025-11-25 -->
- **First Observed**: Publicly demonstrated in July 2023; no qualifying production breach was identified in the completed current search. <!-- SAF-TRACE: claims=SAF-T1110-C002; sources=SRC-bagdasaryan-multimodal-injection-2023 -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers attacker-controlled instructions carried by image or audio data that a multimodal model treats as executable guidance, crossing the boundary between untrusted media and trusted agent decisions. <!-- SAF-TRACE: claims=SAF-T1110-C001,SAF-T1110-C002; sources=SRC-owasp-llm01-2025,SRC-bagdasaryan-multimodal-injection-2023 -->

### In Scope

- An image, screenshot, rendered interface, recording, or ambient sound conveys an instruction that conflicts with the user's intended task. <!-- SAF-TRACE: claims=SAF-T1110-C001; sources=SRC-owasp-llm01-2025 -->
- A multimodal model consumes the media and changes a response, plan, tool call, or agent action because of the embedded instruction. <!-- SAF-TRACE: claims=SAF-T1110-C002,SAF-T1110-C005; sources=SRC-bagdasaryan-multimodal-injection-2023,SRC-cao-vpi-bench-2025 -->
- An MCP host is in scope when media arrives through a resource, tool result, user attachment, or external interface and influences model-controlled tool use. <!-- SAF-TRACE: claims=SAF-T1110-C006; sources=SRC-mcp-tools-2025-11-25 -->

### Out of Scope

- Text-only indirect prompt injection is a neighboring delivery mechanism, even if its downstream action is identical. <!-- SAF-TRACE: claims=SAF-T1110-C014; sources=SRC-owasp-llm01-2025 -->
- A user deliberately supplying a multimodal jailbreak to bypass content policy is direct adversarial use, not third-party media crossing a trust boundary. <!-- SAF-TRACE: claims=SAF-T1110-C014; sources=SRC-figstep-2025,SRC-owasp-llm01-2025 -->
- Training-data poisoning, persistent model backdoors, ordinary speech-command spoofing, and malicious tool output without an image or audio carrier use different mechanisms. <!-- SAF-TRACE: claims=SAF-T1110-C014; sources=SRC-nist-ai-100-2e2025 -->

### Distinguishing Characteristics

The defining observable is a causal chain from untrusted image or audio content to model interpretation and then to behavior outside the user's stated intent. The carrier modality distinguishes it from [SAF-T1102 text-only prompt injection](../SAF-T1102/README.md), the third-party trust boundary distinguishes it from direct multimodal jailbreaking, and the inference-time trigger distinguishes it from [SAF-T2107 model poisoning](../SAF-T2107/README.md). <!-- SAF-TRACE: claims=SAF-T1110-C014; sources=SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025 -->

## Description

An adversary places an instruction in media that a victim or agent is expected to inspect. The instruction may be visible, blended into a scene, rendered in a user interface, or encoded as an adversarial perturbation. When the model jointly processes trusted task context and the attacker-influenced modality, it may follow the media-borne instruction instead of the user's intent. <!-- SAF-TRACE: claims=SAF-T1110-C001,SAF-T1110-C002,SAF-T1110-C005; sources=SRC-owasp-llm01-2025,SRC-bagdasaryan-multimodal-injection-2023,SRC-cao-vpi-bench-2025 -->

The MCP-specific risk arises when a host exposes model-controlled tools and accepts image or audio content in tool results or other context. The protocol can transport those modalities, while authorization and safety remain deployment responsibilities; a media trigger can therefore become consequential when the host permits sensitive follow-on actions. <!-- SAF-TRACE: claims=SAF-T1110-C006,SAF-T1110-C012; sources=SRC-mcp-tools-2025-11-25,SRC-nist-ai-100-2e2025 -->

Public studies have demonstrated the defining chain in controlled image and audio settings, including browser/computer agents and voice agents. They do not establish a widespread production breach, universal transfer across models, or reliable imperceptibility in every environment. <!-- SAF-TRACE: claims=SAF-T1110-C002,SAF-T1110-C003,SAF-T1110-C004,SAF-T1110-C005,SAF-T1110-C013; sources=SRC-bagdasaryan-multimodal-injection-2023,SRC-liu-piggybacking-2026,SRC-chen-audiohijack-2026,SRC-cao-vpi-bench-2025,SRC-bailey-image-hijacks-2024 -->

## Attack Vectors

- **Primary Vector**: Attacker-influenced image or audio reaches a multimodal agent during an otherwise benign task. <!-- SAF-TRACE: claims=SAF-T1110-C001; sources=SRC-owasp-llm01-2025 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1110-C003,SAF-T1110-C005; sources=SRC-liu-piggybacking-2026,SRC-cao-vpi-bench-2025 -->
  - Rendered web or application content contains visual instructions that the agent observes while navigating. <!-- SAF-TRACE: claims=SAF-T1110-C005; sources=SRC-cao-vpi-bench-2025 -->
  - Environmental or concurrently played audio overlaps a legitimate voice interaction. <!-- SAF-TRACE: claims=SAF-T1110-C003; sources=SRC-liu-piggybacking-2026 -->
  - Adversarially modified media steers model output or subsequent dialogue. <!-- SAF-TRACE: claims=SAF-T1110-C002,SAF-T1110-C004; sources=SRC-bagdasaryan-multimodal-injection-2023,SRC-chen-audiohijack-2026 -->
- **Affected Components**: MCP host, multimodal model, media ingestion pipeline, tool-result handler, approval service, and connected tools. <!-- SAF-TRACE: claims=SAF-T1110-C006; sources=SRC-mcp-tools-2025-11-25 -->
- **Trust Boundary Crossed**: Untrusted media is promoted into trusted model instructions or privileged action context. <!-- SAF-TRACE: claims=SAF-T1110-C001,SAF-T1110-C007; sources=SRC-nist-ai-100-2e2025,SRC-openai-agent-pi-defense-2026 -->

## Technical Details

### Prerequisites

- The adversary can influence image or audio that the target model will process. <!-- SAF-TRACE: claims=SAF-T1110-C001; sources=SRC-owasp-llm01-2025 -->
- The model or surrounding agent does not reliably separate media-derived content from higher-trust instructions. <!-- SAF-TRACE: claims=SAF-T1110-C007; sources=SRC-nist-ai-100-2e2025 -->
- A harmful outcome additionally requires a dangerous sink, such as a sensitive transmission or tool action, and insufficient confirmation or policy enforcement. <!-- SAF-TRACE: claims=SAF-T1110-C007,SAF-T1110-C012; sources=SRC-openai-agent-pi-defense-2026,SRC-mcp-tools-2025-11-25 -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies media the agent is likely to inspect and an available action that could advance the adversary's objective. <!-- SAF-TRACE: claims=SAF-T1110-C007; sources=SRC-openai-agent-pi-defense-2026 -->
2. **Delivery**: The adversary places a benign-looking but instruction-bearing image or audio item in that path. <!-- SAF-TRACE: claims=SAF-T1110-C002,SAF-T1110-C003; sources=SRC-bagdasaryan-multimodal-injection-2023,SRC-liu-piggybacking-2026 -->
3. **Trigger or Execution**: The multimodal model processes the media during the victim's task and incorporates the embedded instruction. <!-- SAF-TRACE: claims=SAF-T1110-C002,SAF-T1110-C005; sources=SRC-bagdasaryan-multimodal-injection-2023,SRC-cao-vpi-bench-2025 -->
4. **Boundary Crossing**: Media-derived content is treated as authority for a response or tool decision without sufficient provenance enforcement. <!-- SAF-TRACE: claims=SAF-T1110-C007; sources=SRC-nist-ai-100-2e2025 -->
5. **Objective**: The agent produces attacker-selected output or proposes or executes an unauthorized action. <!-- SAF-TRACE: claims=SAF-T1110-C003,SAF-T1110-C004,SAF-T1110-C005; sources=SRC-liu-piggybacking-2026,SRC-chen-audiohijack-2026,SRC-cao-vpi-bench-2025 -->
6. **Follow-On Activity**: Consequences depend on tool permissions and may include external transmission, state change, or disclosure; these are not automatic properties of the carrier. <!-- SAF-TRACE: claims=SAF-T1110-C012; sources=SRC-nist-ai-100-2e2025,SRC-mcp-tools-2025-11-25 -->

### Example Scenario

An analyst asks an MCP-enabled assistant to summarize a vendor-provided screenshot. The screenshot contains an instruction to send a placeholder note to an inert domain; the assistant proposes the send action without approval. The scenario is non-destructive and illustrates the media-to-action correlation used by the analytic. <!-- SAF-TRACE: claims=SAF-T1110-C005,SAF-T1110-C011; sources=SRC-cao-vpi-bench-2025,SRC-openai-agent-pi-defense-2026 -->

The sanitized event representation contains no live credential or executable payload. <!-- SAF-TRACE: claims=SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026 -->

```json
{
  "media_type": "image",
  "media_source_trust": "untrusted",
  "instruction_detected": true,
  "proposed_action": "external_send",
  "destination": "https://example.invalid/notice",
  "approval_state": "not_requested"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1110-C001 | Images and audio can carry prompt-injection instructions across an untrusted-content boundary. | Research-Derived | SRC-owasp-llm01-2025; SRC-nist-ai-100-2e2025 | General authorities do not establish product-specific exploitability. |
| SAF-T1110-C002 | Adversarially modified images and audio steered open multimodal systems in a controlled proof of concept. | Demonstrated | SRC-bagdasaryan-multimodal-injection-2023 | White-box, early systems; no production incident. |
| SAF-T1110-C003 | Concurrent environmental audio induced agent actions in an eleven-agent controlled evaluation and a bounded device study. | Demonstrated | SRC-liu-piggybacking-2026 | Selected devices, scenarios, and small human study. |
| SAF-T1110-C004 | AudioHijack induced unauthorized actions in controlled commercial-agent experiments. | Demonstrated | SRC-chen-audiohijack-2026 | White-box generation, preselected successful inputs, mutable APIs. |
| SAF-T1110-C005 | VPI-Bench demonstrated visually embedded instructions causing unauthorized agent behavior in controlled browser and computer environments. | Demonstrated | SRC-cao-vpi-bench-2025 | Simulated platforms and identities; not a production breach. |
| SAF-T1110-C006 | MCP tools are model-controlled and tool results can contain image or audio content. | Protocol-Normative | SRC-mcp-tools-2025-11-25 | The specification does not define this attack or guarantee deployment controls. |
| SAF-T1110-C007 | Risk requires an influence source and a consequential sink; separating trust and constraining actions limits impact. | Research-Derived | SRC-nist-ai-100-2e2025; SRC-openai-agent-pi-defense-2026 | Architectural guidance does not guarantee detection. |
| SAF-T1110-C008 | Media-aware screening can inspect OCR, visual context, source separation, or cross-modal consistency. | Research-Finding | SRC-openai-gpt4v-system-card; SRC-liu-piggybacking-2026 | Reported methods remain model- and setting-dependent. |
| SAF-T1110-C009 | Prompt-only and generic guard approaches can miss developed or distribution-shifted attacks. | Research-Finding | SRC-openai-agent-pi-defense-2026; SRC-webagentguard-2026 | Results are not a universal comparison of all guards. |
| SAF-T1110-C010 | Dedicated multimodal guards and action gateways can improve evaluated detection while retaining false-positive and adaptive-evasion risk. | Research-Finding | SRC-webagentguard-2026; SRC-chen-audiohijack-2026; SRC-promptshield-home-2026 | Mostly synthetic or controlled evaluations. |
| SAF-T1110-C011 | Correlating an untrusted multimodal instruction signal with an unapproved sensitive action is a defensible behavioral analytic. | Framework-Inference | SRC-openai-agent-pi-defense-2026; SRC-mcp-tools-2025-11-25 | Requires instrumentation and can alert on benign overlap. |
| SAF-T1110-C012 | Consequence grows with data access, tool privileges, connectivity, and absent human approval. | Research-Derived | SRC-nist-ai-100-2e2025; SRC-mcp-tools-2025-11-25 | Severity remains deployment-specific. |
| SAF-T1110-C013 | Demonstrated attacks do not establish universal cross-model transfer or imperceptibility. | Research-Finding | SRC-bailey-image-hijacks-2024; SRC-chen-audiohijack-2026 | Transfer behavior changes with model and optimization access. |
| SAF-T1110-C014 | Text-only injection, direct jailbreak, poisoning, and non-media tool-output attacks are neighboring but distinct. | Framework-Inference | SRC-owasp-llm01-2025; SRC-figstep-2025; SRC-nist-ai-100-2e2025 | Boundaries may co-occur in a single campaign. |
| SAF-T1110-C015 | ATT&CK User Execution is analogous because victim activity can enable execution, but it does not describe model instruction parsing. | Historical-Analogy | SRC-mitre-attack-t1204 | No direct enterprise ATT&CK equivalent was identified. |
| SAF-T1110-C016 | ATT&CK Malicious Image concerns virtual machine or container images, not visual-media pixels. | Protocol-Normative | SRC-mitre-attack-t1204-003 | Name similarity can mislead mapping. |
| SAF-T1110-C017 | Reviewed CVEs described adjacent prompt-injection or content-injection paths, not direct image/audio input injection. | Disclosed-Vulnerability | SRC-nvd-cve-2024-45989; SRC-nvd-cve-2025-58357 | Neither advisory establishes this technique. |

### Current State

- **Affected Environments**: Multimodal assistants and agents that ingest third-party image or audio and can produce tool calls or sensitive outputs. <!-- SAF-TRACE: claims=SAF-T1110-C001,SAF-T1110-C012; sources=SRC-owasp-llm01-2025,SRC-nist-ai-100-2e2025 -->
- **Known Exploitation**: Multiple controlled demonstrations qualify; the completed incident and advisory search found no direct production breach or direct modality-specific CVE. See [source-coverage.yml](../../research/techniques/SAF-T1110/source-coverage.yml).
- **Available Protections**: Least privilege, trust separation, media-aware screening, sandboxing, action gateways, and explicit approval for consequential operations. <!-- SAF-TRACE: claims=SAF-T1110-C006,SAF-T1110-C007,SAF-T1110-C008,SAF-T1110-C010; sources=SRC-nist-ai-100-2e2025,SRC-mcp-tools-2025-11-25,SRC-webagentguard-2026 -->
- **Residual Risk**: Input classifiers can miss contextual attacks, and evaluated defenses remain sensitive to distribution shift, adaptive attack, and legitimate ambient overlap. <!-- SAF-TRACE: claims=SAF-T1110-C009,SAF-T1110-C010; sources=SRC-openai-agent-pi-defense-2026,SRC-chen-audiohijack-2026,SRC-promptshield-home-2026 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| VPI-Bench | 2025; controlled browser and computer agents | Unauthorized actions and exfiltration scenarios; system-prompt defense had limited overall effect. | Direct demonstration | Simulated test platforms; not production. <!-- SAF-TRACE: claims=SAF-T1110-C005; sources=SRC-cao-vpi-bench-2025 --> |
| AudioHijack | 2026; controlled open and commercial audio-language agents | Six behavior categories including tool misuse; paper evaluates several detector designs. | Direct demonstration | White-box generation and controlled trials. <!-- SAF-TRACE: claims=SAF-T1110-C004,SAF-T1110-C010; sources=SRC-chen-audiohijack-2026 --> |
| Piggybacking on Perception | 2026; eleven agents plus bounded physical/device experiments | Concurrent audio changed agent behavior; CADV evaluated as mitigation. | Direct demonstration | Selected scenarios and devices; not a reported breach. <!-- SAF-TRACE: claims=SAF-T1110-C003,SAF-T1110-C008; sources=SRC-liu-piggybacking-2026 --> |
| Images and Sounds Indirect Injection | 2023; LLaVA and PandaGPT proof of concept | Attacker-chosen output and dialogue steering; no production remediation assessed. | Direct demonstration | White-box initial proof of concept. <!-- SAF-TRACE: claims=SAF-T1110-C002; sources=SRC-bagdasaryan-multimodal-injection-2023 --> |

### Real-World Incidents or Demonstrations (Optional)

#### Highest-impact qualifying demonstrations (2023–2026)

The selected examples cover both modalities and prioritize demonstrations that connect the carrier to agent behavior or tools. Piggybacking includes a bounded physical/device study; AudioHijack includes controlled commercial-agent trials; VPI-Bench exercises browser/computer agents; and the 2023 work establishes the foundational image-and-audio mechanism. None is represented as a production breach. <!-- SAF-TRACE: claims=SAF-T1110-C002,SAF-T1110-C003,SAF-T1110-C004,SAF-T1110-C005; sources=SRC-bagdasaryan-multimodal-injection-2023,SRC-liu-piggybacking-2026,SRC-chen-audiohijack-2026,SRC-cao-vpi-bench-2025 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Sensitive context can be disclosed when the agent has access and an external-send sink; access scoping and confirmation constrain the outcome. <!-- SAF-TRACE: claims=SAF-T1110-C005,SAF-T1110-C012; sources=SRC-cao-vpi-bench-2025,SRC-nist-ai-100-2e2025 --> |
| Integrity | High | Connected tools can alter state when the model converts media instructions into unauthorized action. <!-- SAF-TRACE: claims=SAF-T1110-C003,SAF-T1110-C004,SAF-T1110-C012; sources=SRC-liu-piggybacking-2026,SRC-chen-audiohijack-2026,SRC-nist-ai-100-2e2025 --> |
| Availability | Medium | Disruption is plausible through connected actions but is not the principal outcome in the selected evidence. <!-- SAF-TRACE: claims=SAF-T1110-C012; sources=SRC-nist-ai-100-2e2025 --> |
| Scope | Multi-System | A host plus connected tools can cross application boundaries, but credentials, network policy, and approvals limit blast radius. <!-- SAF-TRACE: claims=SAF-T1110-C006,SAF-T1110-C012; sources=SRC-mcp-tools-2025-11-25,SRC-nist-ai-100-2e2025 --> |

### Severity Conditions

- **Severity increases when**: The agent has broad credentials, sensitive context, unattended autonomy, external connectivity, or state-changing tools. <!-- SAF-TRACE: claims=SAF-T1110-C012; sources=SRC-nist-ai-100-2e2025,SRC-mcp-tools-2025-11-25 -->
- **Severity decreases when**: Media is isolated from instructions, tools are least-privileged and sandboxed, and consequential actions require informed approval. <!-- SAF-TRACE: claims=SAF-T1110-C007,SAF-T1110-C012; sources=SRC-nist-ai-100-2e2025,SRC-openai-agent-pi-defense-2026,SRC-mcp-tools-2025-11-25 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Media-ingestion and classifier log | Image/audio receipt and instruction-risk decision | timestamp, session_id, event_type, media_type, media_source_trust, instruction_detected | Preserve provenance and normalize timestamps. <!-- SAF-TRACE: claims=SAF-T1110-C008,SAF-T1110-C011; sources=SRC-openai-gpt4v-system-card,SRC-openai-agent-pi-defense-2026 --> |
| MCP host or agent action log | Tool proposals, executions, denials, and approvals | timestamp, session_id, event_type, action_type, approval_state, action_source | Correlate before execution where possible. <!-- SAF-TRACE: claims=SAF-T1110-C006,SAF-T1110-C011; sources=SRC-mcp-tools-2025-11-25,SRC-openai-agent-pi-defense-2026 --> |

### Indicators of Compromise (IoCs)

- None known: the technique has no stable payload string, file hash, or endpoint across modalities and models. <!-- SAF-TRACE: claims=SAF-T1110-C013; sources=SRC-bailey-image-hijacks-2024,SRC-chen-audiohijack-2026 -->

### Behavioral Indicators

- An untrusted image or audio item receives an instruction-risk signal shortly before a sensitive tool proposal in the same session. <!-- SAF-TRACE: claims=SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026,SRC-mcp-tools-2025-11-25 -->
- The proposed action is not entailed by the user's task or crosses a new destination, identity, or permission boundary. <!-- SAF-TRACE: claims=SAF-T1110-C007,SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026 -->
- No explicit approval exists for the sensitive action, increasing confidence that the media-to-action transition is unsafe. <!-- SAF-TRACE: claims=SAF-T1110-C011; sources=SRC-mcp-tools-2025-11-25,SRC-openai-agent-pi-defense-2026 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect an untrusted image/audio instruction signal followed within 120 seconds by an unapproved sensitive action in the same session. <!-- SAF-TRACE: claims=SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026,SRC-mcp-tools-2025-11-25 -->
- **Rule Status**: Test. <!-- SAF-TRACE: claims=SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026 -->
- **Detection Logic**: Correlate media provenance and instruction classification with a later external-send, state-change, credential-access, or file-write action; suppress when explicit approval is recorded. <!-- SAF-TRACE: claims=SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026,SRC-mcp-tools-2025-11-25 -->
- **Correlation Window**: Inclusive 120-second sequence in one session. <!-- SAF-TRACE: claims=SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026 -->
- **Known False Positives**: Benign media that discusses an instruction while a legitimate but unapproved action occurs in the same session. <!-- SAF-TRACE: claims=SAF-T1110-C010,SAF-T1110-C011; sources=SRC-promptshield-home-2026,SRC-openai-agent-pi-defense-2026 -->
- **Known Limitations**: Misses unlogged media, absent or bypassed classifiers, actionless response manipulation, cross-session delays, and actions outside the enumerated sensitive set. <!-- SAF-TRACE: claims=SAF-T1110-C009,SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026,SRC-webagentguard-2026 -->
- **Tuning Guidance**: Tune the action set, provenance labels, approval semantics, and correlation interval against local workflows; do not treat the instruction classifier alone as proof. <!-- SAF-TRACE: claims=SAF-T1110-C009,SAF-T1110-C011; sources=SRC-openai-agent-pi-defense-2026,SRC-webagentguard-2026 -->

### Validation

- **Test Data**: [test-logs.json](../../research/techniques/SAF-T1110/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../research/techniques/SAF-T1110/test_detection_rule.py)
- **Expected Result**: Nine deterministic cases pass, including image/audio positives, approved and text-only negatives, time boundaries, missing fields, and one documented expected false positive; see [detection-test.txt](../../research/techniques/SAF-T1110/validation/detection-test.txt).
- **Last Validated**: 2026-09-01; see [strict-validator.txt](../../research/techniques/SAF-T1110/validation/strict-validator.txt).
- **Feasibility Waiver**: None; the completed test is recorded in [quality-review.yml](../../research/techniques/SAF-T1110/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-21: Output Context Isolation](../../mitigations/SAF-M-21/README.md)**: Preserve media provenance, label extracted content as untrusted data, and keep it below user or system authority. <!-- SAF-TRACE: claims=SAF-T1110-C007; sources=SRC-nist-ai-100-2e2025 -->
2. **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Scope credentials and block sensitive sinks that are unnecessary for the task. <!-- SAF-TRACE: claims=SAF-T1110-C007,SAF-T1110-C012; sources=SRC-nist-ai-100-2e2025,SRC-openai-agent-pi-defense-2026 -->
3. **Media-aware preprocessing and screening**: Apply OCR or transcription-aware analysis, source separation where relevant, and cross-modal consistency checks before action authorization. <!-- SAF-TRACE: claims=SAF-T1110-C008; sources=SRC-openai-gpt4v-system-card,SRC-liu-piggybacking-2026 -->
4. **Consequential-action approval**: Show the user normalized action inputs and require informed confirmation before external transmission or state change. <!-- SAF-TRACE: claims=SAF-T1110-C006,SAF-T1110-C007; sources=SRC-mcp-tools-2025-11-25,SRC-openai-agent-pi-defense-2026 -->

### Detective Controls

1. **[SAF-M-36: Model Behavior Monitoring](../../mitigations/SAF-M-36/README.md)**: Retain media provenance, classifier decisions, tool arguments, results, and approval state for sequence correlation. <!-- SAF-TRACE: claims=SAF-T1110-C006,SAF-T1110-C011; sources=SRC-mcp-tools-2025-11-25,SRC-openai-agent-pi-defense-2026 -->
2. **Independent action gateway**: Evaluate proposed actions with a guard or deterministic policy that is separate from task reasoning, and escalate denials for explicit human review. <!-- SAF-TRACE: claims=SAF-T1110-C010; sources=SRC-webagentguard-2026 -->

### Response Procedures

#### Immediate Actions

- Pause the affected agent session and deny pending sensitive actions while preserving the media and decision trail. <!-- SAF-TRACE: claims=SAF-T1110-C006,SAF-T1110-C011; sources=SRC-mcp-tools-2025-11-25,SRC-openai-agent-pi-defense-2026 -->
- Revoke or rotate scoped credentials only when logs show exposure or unauthorized use. <!-- SAF-TRACE: claims=SAF-T1110-C012; sources=SRC-nist-ai-100-2e2025 -->

#### Investigation Steps

- Correlate the original media, provenance, model/classifier decisions, tool proposals, tool results, and approval events by session and time. <!-- SAF-TRACE: claims=SAF-T1110-C006,SAF-T1110-C011; sources=SRC-mcp-tools-2025-11-25,SRC-openai-agent-pi-defense-2026 -->
- Determine whether the media influenced only output or reached a sensitive sink, then bound data and systems touched. <!-- SAF-TRACE: claims=SAF-T1110-C007,SAF-T1110-C012; sources=SRC-openai-agent-pi-defense-2026,SRC-nist-ai-100-2e2025 -->

#### Remediation

- Remove or quarantine the trigger, correct any unauthorized state, and narrow the tool or data authorization that enabled consequence. <!-- SAF-TRACE: claims=SAF-T1110-C007,SAF-T1110-C012; sources=SRC-nist-ai-100-2e2025,SRC-openai-agent-pi-defense-2026 -->
- Add the sanitized trigger class to regression tests, evaluate classifier and gateway behavior, and retune with false-positive review. <!-- SAF-TRACE: claims=SAF-T1110-C009,SAF-T1110-C010; sources=SRC-webagentguard-2026,SRC-promptshield-home-2026 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Alternative | Uses textual data rather than an image/audio carrier. <!-- SAF-TRACE: claims=SAF-T1110-C014; sources=SRC-owasp-llm01-2025 --> |
| [SAF-T2107: AI Model Poisoning via MCP Tool Training Data Contamination](../SAF-T2107/README.md) | Alternative | Alters training or model state rather than supplying an inference-time media instruction. <!-- SAF-TRACE: claims=SAF-T1110-C014; sources=SRC-nist-ai-100-2e2025 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Analogous | Both may depend on victim activity enabling execution, but ATT&CK T1204 does not model multimodal instruction parsing or an agent trust boundary. <!-- SAF-TRACE: claims=SAF-T1110-C015; sources=SRC-mitre-attack-t1204 --> |

### Additional Framework Mappings (Optional)

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| OWASP GenAI | LLM01:2025 | Prompt Injection | Explicitly includes hidden multimodal instructions and emphasizes impact dependence on model agency. <!-- SAF-TRACE: claims=SAF-T1110-C001,SAF-T1110-C012; sources=SRC-owasp-llm01-2025 --> |
| NIST AI 100-2e2025 | Indirect Prompt Injection | Adversarial Machine Learning Taxonomy | Describes third-party instruction channels, agent hijacking, trust separation, and incomplete mitigations. <!-- SAF-TRACE: claims=SAF-T1110-C007; sources=SRC-nist-ai-100-2e2025 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [Model Context Protocol Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) - model-controlled tools, multimodal results, authorization and logging guidance.
2. **SRC-owasp-llm01-2025**: [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) - multimodal injection definition, impacts, and mitigations.
3. **SRC-nist-ai-100-2e2025**: [NIST AI 100-2e2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf) - indirect injection taxonomy, agent consequences, and mitigation limits.
4. **SRC-openai-gpt4v-system-card**: [GPT-4V System Card](https://cdn.openai.com/papers/GPTV_System_Card.pdf) - image-jailbreak and OCR/moderation considerations.
5. **SRC-openai-agent-pi-defense-2026**: [Designing AI agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/) - source-sink framing, confirmations, sandboxing, and classifier limits.
6. **SRC-bagdasaryan-multimodal-injection-2023**: [Abusing Images and Sounds for Indirect Instruction Injection in Multi-Modal LLMs](https://arxiv.org/abs/2307.10490) - foundational image/audio demonstration.
7. **SRC-liu-piggybacking-2026**: [Piggybacking on Perception](https://arxiv.org/abs/2607.28165) - concurrent audio attacks and CADV evaluation.
8. **SRC-chen-audiohijack-2026**: [AudioHijack](https://arxiv.org/abs/2604.14604) - audio injection, tool misuse, and defense evaluation.
9. **SRC-cao-vpi-bench-2025**: [VPI-Bench](https://arxiv.org/abs/2506.02456) - visual injection benchmark for computer/browser agents.
10. **SRC-bailey-image-hijacks-2024**: [Image Hijacks](https://arxiv.org/abs/2309.00236) - image-based behavior matching and transfer limits.
11. **SRC-webagentguard-2026**: [WebAgentGuard](https://arxiv.org/abs/2604.12284) - multimodal guard and action-gateway evaluation.
12. **SRC-promptshield-home-2026**: [PromptShield Home](https://arxiv.org/abs/2608.05495) - ambient multimodal detection and over-refusal challenge.
13. **SRC-figstep-2025**: [FigStep](https://arxiv.org/abs/2311.05608) - direct visual jailbreak boundary.
14. **SRC-mitre-attack-t1204**: [MITRE ATT&CK T1204 User Execution](https://attack.mitre.org/techniques/T1204/) - analogous execution behavior.
15. **SRC-mitre-attack-t1204-003**: [MITRE ATT&CK T1204.003 Malicious Image](https://attack.mitre.org/techniques/T1204/003/) - virtual machine/container image distinction.
16. **SRC-nvd-cve-2024-45989**: [NVD CVE-2024-45989](https://nvd.nist.gov/vuln/detail/CVE-2024-45989) - adjacent output-rendering exfiltration path.
17. **SRC-nvd-cve-2025-58357**: [NVD CVE-2025-58357](https://nvd.nist.gov/vuln/detail/CVE-2025-58357) - adjacent MCP client content-injection path.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Clean-room research draft, analytic, and evidence packet | OpenAI Codex clean-room research agent |
