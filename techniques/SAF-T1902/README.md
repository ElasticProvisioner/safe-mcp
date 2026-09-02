# SAF-T1902: Covert Channel in Responses

## Overview

- **Tactic**: Command and Control (ATK-TA0011)
- **Technique ID**: SAF-T1902
- **Research Packet**: [research/techniques/SAF-T1902](../../research/techniques/SAF-T1902/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1902/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: High applies when an attacker can influence response content and the host renders, follows, or relays that content across an external boundary with access to sensitive context; isolation, confirmation, and egress controls reduce the rating. <!-- SAF-TRACE: claims=SAF-T1902-C020; sources=SRC-openai-url,SRC-rehberger-spaiware,SRC-cursor-cve-2025-54132 -->
- **First Observed**: No qualifying production breach was identified; the earliest selected public demonstration was published on 2023-05-16. <!-- SAF-TRACE: claims=SAF-T1902-C009; sources=SRC-rehberger-webpilot -->
- **Last Updated**: 2026-09-02

## Scope

SAF-T1902 covers an adversary concealing control data, collected data, or a callback trigger inside an MCP or agent response so that a cooperating receiver obtains it through response processing, rendering, or relay outside the intended review path. The crossed boundary is the point where untrusted response content becomes trusted display, model context, or outbound network activity. <!-- SAF-TRACE: claims=SAF-T1902-C001,SAF-T1902-C010; sources=SRC-nist-covert-channel,SRC-mcp-tools-2025-11-25,SRC-openai-url -->

### In Scope

- Encoded, visually suppressed, steganographic, or renderer-active content carried in tool results, resource-derived context, or agent-facing responses for command, callback, or data transfer. <!-- SAF-TRACE: claims=SAF-T1902-C001,SAF-T1902-C002,SAF-T1902-C004,SAF-T1902-C005; sources=SRC-nist-covert-channel,SRC-mcp-tools-2025-11-25,SRC-unicode-tr51-17,SRC-rfc4648 -->
- Automatic or user-mediated retrieval of an attacker-selected response URL when the URL carries session data or collected context. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C021; sources=SRC-openai-url,SRC-rehberger-webpilot,SRC-rehberger-m365-ascii -->

### Out of Scope

- Plain response injection that changes model instructions but does not use the response as a concealed communication carrier; that behavior is assigned to the proposed neighbor [SAF-T1102: Response Injection](../SAF-T1102/README.md). <!-- SAF-TRACE: claims=SAF-T1902-C001; sources=SRC-nist-covert-channel -->
- Tool-description poisoning, ordinary approved tool calls, transport tunneling below response semantics, and follow-on execution are separate mechanisms even when they coexist with this technique. <!-- SAF-TRACE: claims=SAF-T1902-C010; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2026-07-28 -->

### Distinguishing Characteristics

The defining observable is concealed or dual-use information in a response plus a receiver path: decoding by a collaborator, reuse by the model, user activation, or an automatic network fetch. Mere malicious prose is insufficient, and explicit authorized export is not covert. <!-- SAF-TRACE: claims=SAF-T1902-C001,SAF-T1902-C003,SAF-T1902-C021; sources=SRC-nist-covert-channel,SRC-openai-url,SRC-rehberger-m365-ascii -->

## Description

A covert response channel repurposes a legitimate result or answer field as an unintended communication path. MCP tool results can contain text, images, audio, links, embedded resources, and structured content; a host may then expose that material to a model or renderer. <!-- SAF-TRACE: claims=SAF-T1902-C001,SAF-T1902-C002; sources=SRC-nist-covert-channel,SRC-mcp-tools-2025-11-25 -->

The carrier can be an encoded substring, Unicode tag characters that some implementations render invisibly, a crafted link, or an external-resource reference. If the host automatically retrieves the reference, the request itself can transmit attacker-chosen data; if user action is required, the channel is weaker but remains possible after activation. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C004,SAF-T1902-C005,SAF-T1902-C021; sources=SRC-openai-url,SRC-unicode-tr51-17,SRC-rfc4648,SRC-rehberger-m365-ascii -->

Public demonstrations establish the end-to-end behavior in agent products, including persistent response-driven callbacks, response-rendered external images, hidden Unicode placed in response links, and Markdown image retrieval. These demonstrations justify a Demonstrated rating, but they do not establish a production compromise campaign. <!-- SAF-TRACE: claims=SAF-T1902-C006,SAF-T1902-C007,SAF-T1902-C008,SAF-T1902-C009,SAF-T1902-C019; sources=SRC-rehberger-spaiware,SRC-nassi-promptware-kill-chain,SRC-cursor-cve-2025-54132,SRC-cursor-cve-research,SRC-rehberger-m365-ascii,SRC-rehberger-webpilot -->

## Attack Vectors

- **Primary Vector**: Attacker-influenced content enters a tool result or retrieved context, and the model or host places a concealed carrier in a response. <!-- SAF-TRACE: claims=SAF-T1902-C010; sources=SRC-mcp-tools-2025-11-25,SRC-openai-url -->
- **Secondary Vectors**: Persistent memory instructions can recreate a callback carrier in later responses; rendered Markdown, Mermaid, or equivalent rich content can initiate retrieval; a user can activate a concealed link. <!-- SAF-TRACE: claims=SAF-T1902-C006,SAF-T1902-C007,SAF-T1902-C008,SAF-T1902-C021; sources=SRC-rehberger-spaiware,SRC-cursor-cve-research,SRC-cursor-cve-2025-54132,SRC-rehberger-m365-ascii -->
- **Affected Components**: MCP hosts and clients, models, tool-result handlers, rich-content renderers, memory stores, and outbound network controls. <!-- SAF-TRACE: claims=SAF-T1902-C002,SAF-T1902-C010; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2026-07-28 -->
- **Trust Boundary Crossed**: Untrusted response data crosses into trusted rendering, model context, or an external request without an equivalent content and destination decision. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C010; sources=SRC-openai-url,SRC-mcp-tools-2025-11-25 -->

## Technical Details

### Prerequisites

- The adversary must influence content that can reach an MCP result, retrieved resource, model response, or persistent context. <!-- SAF-TRACE: claims=SAF-T1902-C010; sources=SRC-mcp-tools-2025-11-25,SRC-openai-url -->
- A cooperating receiver or callback destination must be reachable, and the carrier must survive normalization, policy checks, and rendering. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C005; sources=SRC-openai-url,SRC-rfc4648 -->
- Automatic rendering removes the click prerequisite; otherwise a user must activate the link or the model must later decode or relay the carrier. <!-- SAF-TRACE: claims=SAF-T1902-C021; sources=SRC-rehberger-webpilot,SRC-rehberger-m365-ascii,SRC-openai-url -->

### Attack Flow

1. **Setup**: The adversary prepares response content whose ordinary appearance masks an encoded token, hidden character sequence, or external-resource locator. <!-- SAF-TRACE: claims=SAF-T1902-C004,SAF-T1902-C005; sources=SRC-unicode-tr51-17,SRC-rfc4648 -->
2. **Delivery**: Attacker-controlled content reaches a tool result, retrieved context, memory, or another input that can affect the response. <!-- SAF-TRACE: claims=SAF-T1902-C010; sources=SRC-mcp-tools-2025-11-25 -->
3. **Trigger**: The model reproduces the carrier or the host renders a response object containing it. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C006,SAF-T1902-C007; sources=SRC-openai-url,SRC-rehberger-spaiware,SRC-cursor-cve-research -->
4. **Boundary Crossing**: A decoder, user action, or automatic fetch transfers the concealed material to the cooperating receiver. <!-- SAF-TRACE: claims=SAF-T1902-C001,SAF-T1902-C021; sources=SRC-nist-covert-channel,SRC-rehberger-webpilot,SRC-rehberger-m365-ascii -->
5. **Objective**: The adversary receives data or sends control state while the carrier resembles normal response content. <!-- SAF-TRACE: claims=SAF-T1902-C001,SAF-T1902-C006; sources=SRC-nist-covert-channel,SRC-rehberger-spaiware -->
6. **Follow-On Activity**: The channel can be repeated while its prerequisite instruction or rendering behavior remains, but capabilities remain bounded by accessible context and network policy. <!-- SAF-TRACE: claims=SAF-T1902-C006,SAF-T1902-C014; sources=SRC-rehberger-spaiware,SRC-openai-url -->

### Example Scenario

An inert test server returns ordinary help text containing an image locator at `https://collector.invalid/pixel?id=TEST_VALUE`. A test host records that the renderer requested the locator in the same session; no credential, routable destination, or destructive instruction is used. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C013; sources=SRC-openai-url,SRC-attack-det0108 -->

```json
{"event_type":"agent_response","session_id":"demo-1","response_text":"Status: ready ![](https://collector.invalid/pixel?id=TEST_VALUE)"}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1902-C001 | An unintended response field can carry concealed communication across a policy boundary. | Research-Derived | SRC-nist-covert-channel; SRC-mcp-tools-2025-11-25 | NIST defines the general mechanism; MCP does not define this attack. |
| SAF-T1902-C002 | MCP tool results support multiple rich and structured response content forms. | Research-Derived | SRC-mcp-tools-2025-11-25 | Capability alone is not exploitation. |
| SAF-T1902-C003 | A response-contained URL can transmit data when rendered or retrieved. | Demonstrated | SRC-openai-url; SRC-rehberger-webpilot | Retrieval behavior varies by product and policy. |
| SAF-T1902-C004 | Unicode tag characters can be invisible in tag-unaware rendering. | Research-Derived | SRC-unicode-tr51-17 | Legitimate emoji tag sequences exist. |
| SAF-T1902-C005 | Encoding and permissive decoding can hide data or create a covert subchannel. | Research-Derived | SRC-rfc4648 | Base encoding alone is common and benign. |
| SAF-T1902-C006 | SpAIware demonstrated persistent response-driven data transfer and a control path. | Demonstrated | SRC-rehberger-spaiware; SRC-nassi-promptware-kill-chain | Controlled research, not a reported production breach. |
| SAF-T1902-C007 | Cursor versions around 1.1.3 rendered external Mermaid images in responses, enabling data exfiltration; version 1.3 removed remote images. | Demonstrated | SRC-cursor-cve-2025-54132; SRC-cursor-cve-research | Advisory rates the issue Moderate and requires attacker influence. |
| SAF-T1902-C008 | A Microsoft 365 Copilot demonstration hid data-bearing response link content with Unicode tags. | Demonstrated | SRC-rehberger-m365-ascii | User activation was required and the reported path was fixed. |
| SAF-T1902-C009 | A WebPilot demonstration caused a response-rendered Markdown image to request an attacker destination. | Demonstrated | SRC-rehberger-webpilot | The demonstration predates MCP and is product-specific. |
| SAF-T1902-C010 | Exploitation requires attacker influence over response-relevant content plus a surviving receiver path. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-openai-url | Exact prerequisites differ by host and renderer. |
| SAF-T1902-C011 | Confidentiality is the primary impact; persistent control state can also affect integrity. | Demonstrated | SRC-rehberger-spaiware; SRC-cursor-cve-2025-54132 | Accessible context and permissions cap impact. |
| SAF-T1902-C012 | Detection needs response content, session identity, renderer decisions, and outbound request telemetry. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-mcp-security-2026-07-28 | Many deployments do not retain all fields. |
| SAF-T1902-C013 | Correlating suspicious response carriers with near-time outbound requests improves analytic confidence. | Research-Derived | SRC-attack-det0108; SRC-openai-url | Thresholds and timing are local design choices. |
| SAF-T1902-C014 | Carrier-only detection has false positives and cannot prove adversary intent. | Research-Derived | SRC-unicode-tr51-17; SRC-rfc4648; SRC-openai-url | Behavioral correlation still permits legitimate matches. |
| SAF-T1902-C015 | Output validation, restricted rendering, destination controls, and least-privilege egress constrain the technique. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-mcp-security-2026-07-28; SRC-openai-url | No single control covers every carrier or side channel. |
| SAF-T1902-C016 | Response should preserve correlated evidence and rotate exposed credentials after containment. | Research-Derived | SRC-mcp-security-2026-07-28; SRC-cursor-cve-2025-54132 | Incident scope determines exact actions. |
| SAF-T1902-C017 | ATT&CK Data Encoding is an analogous mapping for encoded C2 content. | Research-Derived | SRC-attack-t1132 | Not every covert response carrier is a standard encoding. |
| SAF-T1902-C018 | ATT&CK Data Obfuscation is an analogous mapping for hidden C2 traffic. | Research-Derived | SRC-attack-t1001 | SAF-T1902 is bounded to response semantics. |
| SAF-T1902-C019 | Public controlled demonstrations support the Demonstrated evidence label. | Demonstrated | SRC-rehberger-spaiware; SRC-cursor-cve-2025-54132; SRC-rehberger-m365-ascii; SRC-rehberger-webpilot | No selected source establishes production exploitation. |
| SAF-T1902-C020 | Severity rises with automatic egress, persistence, sensitive context, and broad permissions. | Demonstrated | SRC-openai-url; SRC-rehberger-spaiware; SRC-cursor-cve-2025-54132 | These are conditional, not universal, impacts. |
| SAF-T1902-C021 | Automatic rendering and user-mediated links have materially different activation requirements. | Demonstrated | SRC-rehberger-webpilot; SRC-rehberger-m365-ascii; SRC-openai-url | Product behavior can change after patches. |
| SAF-T1902-C022 | MCP guidance calls for result validation, output sanitization, confirmation, logging, and constrained privileges. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-mcp-security-2026-07-28 | Guidance is not evidence that every implementation complies. |

### Current State

- **Affected Environments**: Agent or MCP deployments that ingest attacker-influenced results and expose rich response content to a renderer, model, link handler, or network-capable client. <!-- SAF-TRACE: claims=SAF-T1902-C002,SAF-T1902-C010; sources=SRC-mcp-tools-2025-11-25,SRC-openai-url -->
- **Known Exploitation**: Four selected public demonstrations or disclosed vulnerability records establish the mechanism; the research packet records no qualifying production breach. <!-- SAF-TRACE: claims=SAF-T1902-C006,SAF-T1902-C007,SAF-T1902-C008,SAF-T1902-C009,SAF-T1902-C019; sources=SRC-rehberger-spaiware,SRC-cursor-cve-2025-54132,SRC-rehberger-m365-ascii,SRC-rehberger-webpilot -->
- **Available Protections**: Validate and sanitize results, constrain rich rendering and outbound destinations, require context-appropriate confirmation, log result use, and isolate server privileges. <!-- SAF-TRACE: claims=SAF-T1902-C015,SAF-T1902-C022; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2026-07-28,SRC-openai-url -->
- **Residual Risk**: Static domain allowlists do not address every dynamic URL, open redirect, non-URL carrier, or later-discovered side channel. <!-- SAF-TRACE: claims=SAF-T1902-C014,SAF-T1902-C015; sources=SRC-openai-url -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| SpAIware persistent exfiltration | 2024-09-20; ChatGPT macOS app | Repeated response image callbacks could carry conversation data; fixed in app version 1.2024.247. | Direct demonstration <!-- SAF-TRACE: claims=SAF-T1902-C006; sources=SRC-rehberger-spaiware,SRC-nassi-promptware-kill-chain --> | Controlled demonstration; no production victim evidence. |
| CVE-2025-54132 / GHSA-43wj-mwcc-x93p | 2025-08-01 advisory; Cursor 1.1.3, patched in 1.3 | Response Mermaid remote images could transmit sensitive context; remote images were removed. | Direct vulnerability <!-- SAF-TRACE: claims=SAF-T1902-C007; sources=SRC-cursor-cve-2025-54132,SRC-cursor-cve-research --> | Moderate CVSS 4.4; requires attacker influence and relevant context. |
| Microsoft 365 Copilot ASCII-smuggling chain | 2024-08-26; Microsoft 365 Copilot | Invisible Unicode staged data in a response link; the researcher reported the path fixed by July 2024. | Direct demonstration <!-- SAF-TRACE: claims=SAF-T1902-C008,SAF-T1902-C021; sources=SRC-rehberger-m365-ascii --> | Required a user click and was not assigned a vulnerability identifier. |
| ChatGPT WebPilot Markdown-image chain | 2023-05-16; ChatGPT Plugins/WebPilot | A response image URL could carry chat content to an attacker endpoint. | Direct demonstration <!-- SAF-TRACE: claims=SAF-T1902-C009,SAF-T1902-C021; sources=SRC-rehberger-webpilot --> | Product-specific controlled demonstration, not a production incident. |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Data visible to the agent can leave through the concealed carrier when rendering or activation reaches the receiver. <!-- SAF-TRACE: claims=SAF-T1902-C011,SAF-T1902-C020; sources=SRC-rehberger-spaiware,SRC-cursor-cve-2025-54132 --> |
| Integrity | Medium | Persistent control material can influence later response behavior, but this requires retained instructions or equivalent state. <!-- SAF-TRACE: claims=SAF-T1902-C006,SAF-T1902-C011; sources=SRC-rehberger-spaiware,SRC-nassi-promptware-kill-chain --> |
| Availability | Low | The selected evidence does not establish availability impact as the primary objective. <!-- SAF-TRACE: claims=SAF-T1902-C011; sources=SRC-rehberger-spaiware,SRC-cursor-cve-2025-54132 --> |
| Scope | Multi-System | The path can connect an agent host, renderer, external service, and attacker endpoint, while permissions and egress policy bound the blast radius. <!-- SAF-TRACE: claims=SAF-T1902-C010,SAF-T1902-C020; sources=SRC-openai-url,SRC-mcp-security-2026-07-28 --> |

### Severity Conditions

- **Severity increases when** rendering is automatic, persistent context recreates the carrier, broad sensitive data is available, or unrestricted network egress exists. <!-- SAF-TRACE: claims=SAF-T1902-C020; sources=SRC-openai-url,SRC-rehberger-spaiware,SRC-cursor-cve-2025-54132 -->
- **Severity decreases when** response content is normalized, destinations are constrained, remote rendering is disabled, user confirmation is meaningful, and the process has minimal privileges. <!-- SAF-TRACE: claims=SAF-T1902-C015,SAF-T1902-C022; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2026-07-28 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or agent audit log | Tool result ingestion and response creation | timestamp, session_id, event_type, response_text, server or tool identity | Preserve the pre-render response with access controls appropriate to potentially sensitive content. <!-- SAF-TRACE: claims=SAF-T1902-C012; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2026-07-28 --> |
| Renderer and network log | External-resource decision and request | timestamp, session_id, destination_url, auto_fetched, response correlation identifier | Normalize URLs and synchronize clocks before correlation. <!-- SAF-TRACE: claims=SAF-T1902-C012,SAF-T1902-C013; sources=SRC-openai-url,SRC-attack-det0108 --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC is known; attacker destinations and carrier encodings are changeable. <!-- SAF-TRACE: claims=SAF-T1902-C014; sources=SRC-openai-url,SRC-rfc4648 -->

### Behavioral Indicators

- Unicode tag characters outside a valid expected emoji workflow, especially a run embedded in model-generated prose or links. <!-- SAF-TRACE: claims=SAF-T1902-C004,SAF-T1902-C014; sources=SRC-unicode-tr51-17 -->
- A response contains an external URL with a long encoded or high-entropy value, followed by a matching request from the same session. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C013; sources=SRC-openai-url,SRC-attack-det0108 -->
- Repeated callbacks to a previously unseen destination after unrelated prompts can increase confidence when correlated with persistent context. <!-- SAF-TRACE: claims=SAF-T1902-C006,SAF-T1902-C013; sources=SRC-rehberger-spaiware,SRC-attack-det0108 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify invisible tag carriers or suspicious response URLs that correlate with same-session outbound retrieval. <!-- SAF-TRACE: claims=SAF-T1902-C013; sources=SRC-attack-det0108,SRC-openai-url -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1902-C014; sources=SRC-openai-url -->
- **Detection Logic**: Alert on four or more Unicode tag characters, or on a response URL with a long encoded value when a matching network request occurs within 120 seconds. <!-- SAF-TRACE: claims=SAF-T1902-C004,SAF-T1902-C013; sources=SRC-unicode-tr51-17,SRC-attack-det0108 -->
- **Correlation Window**: Same session, no more than 120 seconds; this is a locally tested analytic parameter rather than an externally asserted universal threshold. <!-- SAF-TRACE: claims=SAF-T1902-C013; sources=SRC-attack-det0108 -->
- **Known False Positives**: Legitimate emoji tag sequences, signed URLs, cache busters, telemetry beacons, and content-delivery tokens. <!-- SAF-TRACE: claims=SAF-T1902-C014; sources=SRC-unicode-tr51-17,SRC-rfc4648 -->
- **Known Limitations**: The analytic misses low-entropy carriers, encrypted bodies, uncaptured rendering, trusted-domain redirects, user relays outside the window, and non-URL covert encodings other than Unicode tags. <!-- SAF-TRACE: claims=SAF-T1902-C014; sources=SRC-openai-url,SRC-rfc4648 -->
- **Tuning Guidance**: Baseline expected renderer destinations, validate signed-resource paths, retain full URL components under privacy controls, and lower thresholds only with corroborating context. <!-- SAF-TRACE: claims=SAF-T1902-C013,SAF-T1902-C014; sources=SRC-attack-det0108,SRC-openai-url -->

### Validation

- **Test Data**: [events.jsonl](../../tests/SAF-T1902/fixtures/events.jsonl)
- **Validation Script**: [test_detection.py](../../tests/SAF-T1902/test_detection.py)
- **Expected Result**: Three malicious fixtures alert and five benign or boundary fixtures do not alert; see the [recorded test output](../../research/techniques/SAF-T1902/validation/detector-test-output.txt).
- **Last Validated**: 2026-09-02 in the [recorded test output](../../research/techniques/SAF-T1902/validation/detector-test-output.txt).
- **Feasibility Waiver**: None, as recorded in [quality-review.yml](../../research/techniques/SAF-T1902/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-22: Semantic Output Validation](../../mitigations/SAF-M-22/README.md)**: Treat tool results and model responses as untrusted; normalize Unicode and URLs, validate structured outputs, and reject unsupported rich-content forms before rendering. <!-- SAF-TRACE: claims=SAF-T1902-C015,SAF-T1902-C022; sources=SRC-mcp-tools-2025-11-25,SRC-unicode-tr51-17,SRC-rfc4648 -->
2. **Destination and renderer policy**: Disable automatic remote-resource retrieval where unnecessary, apply exact URL or dynamically approved-resource policy, validate redirects, and prevent sensitive values from entering request paths or queries. <!-- SAF-TRACE: claims=SAF-T1902-C015; sources=SRC-openai-url,SRC-mcp-security-2026-07-28 -->
3. **Least privilege**: Restrict MCP server filesystem and network access, minimize accessible context, and require confirmation for consequential operations. <!-- SAF-TRACE: claims=SAF-T1902-C015,SAF-T1902-C022; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2026-07-28 -->

### Detective Controls

1. **Response-to-egress correlation**: Join the pre-render response, renderer decision, and outbound request under one session identifier. <!-- SAF-TRACE: claims=SAF-T1902-C012,SAF-T1902-C013; sources=SRC-attack-det0108,SRC-openai-url -->
2. **Carrier normalization**: Decode or expose Unicode tags and canonicalize supported encodings before content review, while retaining original bytes for investigation. <!-- SAF-TRACE: claims=SAF-T1902-C004,SAF-T1902-C005,SAF-T1902-C014; sources=SRC-unicode-tr51-17,SRC-rfc4648 -->

### Response Procedures

#### Immediate Actions

- Stop remote response rendering or isolate the affected session, server, renderer, and destination while preserving evidence. <!-- SAF-TRACE: claims=SAF-T1902-C016; sources=SRC-mcp-security-2026-07-28,SRC-cursor-cve-2025-54132 -->
- Revoke or rotate credentials and tokens that were present in accessible context or observed in correlated requests. <!-- SAF-TRACE: claims=SAF-T1902-C011,SAF-T1902-C016; sources=SRC-cursor-cve-2025-54132,SRC-mcp-security-2026-07-28 -->

#### Investigation Steps

- Preserve original and normalized response content, tool-result provenance, model/session identifiers, rendering decisions, destination requests, redirect chains, and persistent memory state. <!-- SAF-TRACE: claims=SAF-T1902-C012,SAF-T1902-C016; sources=SRC-mcp-security-2026-07-28,SRC-rehberger-spaiware -->
- Determine the first attacker-influenced input, every response containing the carrier, data available to each response, and any follow-on commands or callbacks. <!-- SAF-TRACE: claims=SAF-T1902-C006,SAF-T1902-C010,SAF-T1902-C016; sources=SRC-rehberger-spaiware,SRC-nassi-promptware-kill-chain -->

#### Remediation

- Patch the affected product or disable the unsafe response feature, remove persistent malicious state, constrain egress, and retest the original carrier under regression coverage. <!-- SAF-TRACE: claims=SAF-T1902-C007,SAF-T1902-C015,SAF-T1902-C016; sources=SRC-cursor-cve-2025-54132,SRC-rehberger-spaiware,SRC-openai-url -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Response Injection](../SAF-T1102/README.md) | Prerequisite or co-occurring | Injection changes agent interpretation; SAF-T1902 additionally requires a concealed response carrier and receiver path. <!-- SAF-TRACE: claims=SAF-T1902-C001,SAF-T1902-C010; sources=SRC-nist-covert-channel,SRC-mcp-tools-2025-11-25 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1132](https://attack.mitre.org/techniques/T1132/) | Data Encoding | Analogous | Both encode information to make command-and-control traffic harder to inspect; SAF-T1902 is limited to response carriers and may use non-encoding mechanisms. <!-- SAF-TRACE: claims=SAF-T1902-C017; sources=SRC-attack-t1132 --> |
| [T1001](https://attack.mitre.org/techniques/T1001/) | Data Obfuscation | Analogous | Both conceal C2 within otherwise plausible traffic; SAF-T1902 requires concealment in response semantics. <!-- SAF-TRACE: claims=SAF-T1902-C018; sources=SRC-attack-t1001 --> |

## References

1. **SRC-nist-covert-channel**: [NIST CSRC Glossary: Covert Channel](https://csrc.nist.gov/glossary/term/covert_channel) — NIST, current glossary entry; general security definition. <!-- SAF-TRACE: claims=SAF-T1902-C001; sources=SRC-nist-covert-channel -->
2. **SRC-mcp-tools-2025-11-25**: [MCP Server Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — Model Context Protocol project; result forms, validation, confirmation, sanitization, and logging guidance. <!-- SAF-TRACE: claims=SAF-T1902-C002,SAF-T1902-C010,SAF-T1902-C012,SAF-T1902-C015,SAF-T1902-C022; sources=SRC-mcp-tools-2025-11-25 -->
3. **SRC-mcp-security-2026-07-28**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) — Model Context Protocol project; restricted network access, sandboxing, URL validation, and logging guidance. <!-- SAF-TRACE: claims=SAF-T1902-C010,SAF-T1902-C012,SAF-T1902-C015,SAF-T1902-C016,SAF-T1902-C022; sources=SRC-mcp-security-2026-07-28 -->
4. **SRC-openai-url**: [Preventing URL-Based Data Exfiltration in Language-Model Agents](https://cdn.openai.com/pdf/dd8e7875-e606-42b4-80a1-f824e4e11cf4/prevent-url-data-exfil.pdf) — Adrian Spânu and Thomas Shadwell, 2025; mechanism, controls, and limitations. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C010,SAF-T1902-C013,SAF-T1902-C014,SAF-T1902-C015,SAF-T1902-C020,SAF-T1902-C021; sources=SRC-openai-url -->
5. **SRC-unicode-tr51-17**: [Unicode Technical Standard #51, Version 17.0](https://unicode.org/reports/tr51/) — editors Mark Davis and Ned Holbrook, 2025; tag ranges, valid sequences, and invisible tag-unaware rendering. <!-- SAF-TRACE: claims=SAF-T1902-C004,SAF-T1902-C014,SAF-T1902-C015; sources=SRC-unicode-tr51-17 -->
6. **SRC-rfc4648**: [RFC 4648: The Base16, Base32, and Base64 Data Encodings](https://datatracker.ietf.org/doc/html/rfc4648) — Simon Josefsson, 2006; covert-channel and canonical-decoding considerations. <!-- SAF-TRACE: claims=SAF-T1902-C005,SAF-T1902-C014,SAF-T1902-C015; sources=SRC-rfc4648 -->
7. **SRC-rehberger-spaiware**: [ChatGPT macOS App: Persistent Data Exfiltration](https://embracethered.com/blog/posts/2024/chatgpt-macos-app-persistent-data-exfiltration/) — Johann Rehberger, 2024; end-to-end demonstration and remediation timeline. <!-- SAF-TRACE: claims=SAF-T1902-C006,SAF-T1902-C011,SAF-T1902-C019,SAF-T1902-C020; sources=SRC-rehberger-spaiware -->
8. **SRC-nassi-promptware-kill-chain**: [Promptware Kill Chain](https://arxiv.org/html/2601.09625v1) — Ben Nassi, Bruce Schneier, and Oleg Brodt, 2026; persistence and C2 analysis of agent promptware. <!-- SAF-TRACE: claims=SAF-T1902-C006; sources=SRC-nassi-promptware-kill-chain -->
9. **SRC-cursor-cve-2025-54132**: [GHSA-43wj-mwcc-x93p / CVE-2025-54132](https://github.com/cursor/cursor/security/advisories/GHSA-43wj-mwcc-x93p) — Cursor maintainer advisory by hmwildermuth; credits Johann Rehberger and MaccariTA; affected and patched versions. <!-- SAF-TRACE: claims=SAF-T1902-C007,SAF-T1902-C011,SAF-T1902-C016,SAF-T1902-C019,SAF-T1902-C020; sources=SRC-cursor-cve-2025-54132 -->
10. **SRC-cursor-cve-research**: [Cursor Data Exfiltration with Mermaid](https://embracethered.com/blog/posts/2025/cursor-data-exfiltration-with-mermaid/) — Johann Rehberger, 2025; demonstration and direct provenance for the exact GitHub advisory. <!-- SAF-TRACE: claims=SAF-T1902-C007; sources=SRC-cursor-cve-research -->
11. **SRC-rehberger-m365-ascii**: [Microsoft 365 Copilot Prompt Injection and ASCII Smuggling](https://embracethered.com/blog/posts/2024/m365-copilot-prompt-injection-tool-invocation-and-data-exfil-using-ascii-smuggling/) — Johann Rehberger, 2024; controlled hidden-response link demonstration and disclosure timeline. <!-- SAF-TRACE: claims=SAF-T1902-C008,SAF-T1902-C019,SAF-T1902-C021; sources=SRC-rehberger-m365-ascii -->
12. **SRC-rehberger-webpilot**: [ChatGPT WebPilot Data Exfiltration via Markdown Injection](https://embracethered.com/blog/posts/2023/chatgpt-webpilot-data-exfil-via-markdown-injection/) — Johann Rehberger, 2023; controlled automatic image-fetch demonstration. <!-- SAF-TRACE: claims=SAF-T1902-C003,SAF-T1902-C009,SAF-T1902-C019,SAF-T1902-C021; sources=SRC-rehberger-webpilot -->
13. **SRC-attack-det0108**: [MITRE ATT&CK DET0108: Detection Strategy for Data Encoding](https://attack.mitre.org/detectionstrategies/DET0108/) — MITRE ATT&CK, 2026; encoded-content and entropy-based detection guidance. <!-- SAF-TRACE: claims=SAF-T1902-C013; sources=SRC-attack-det0108 -->
14. **SRC-attack-t1132**: [MITRE ATT&CK T1132: Data Encoding](https://attack.mitre.org/techniques/T1132/) — MITRE ATT&CK, contributor Itzik Kotler, version 1.3; analogous mapping. <!-- SAF-TRACE: claims=SAF-T1902-C017; sources=SRC-attack-t1132 -->
15. **SRC-attack-t1001**: [MITRE ATT&CK T1001: Data Obfuscation](https://attack.mitre.org/techniques/T1001/) — MITRE ATT&CK, version 1.2; analogous mapping. <!-- SAF-TRACE: claims=SAF-T1902-C018; sources=SRC-attack-t1001 -->

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial clean-room draft | OpenAI Codex clean-room generator |
