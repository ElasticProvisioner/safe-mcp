# SAF-T1911: Parameter Exfiltration

## Overview

- **Tactic**: Exfiltration (ATK-TA0010)
- **Technique ID**: SAF-T1911
- **Research Packet**: [research/techniques/SAF-T1911](../../research/techniques/SAF-T1911/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1911/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Controlled experiments transmitted configuration, private-key, chat-history, and contact data; realized impact still depends on the agent's access and successful dispatch. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) and [WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **First Observed**: Not observed in production; publicly demonstrated on 2025-04-01. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C004; sources=SRC-invariant-tpa-2025-04-01 -->
- **Last Updated**: 2026-09-02

## Scope

Parameter Exfiltration is the unauthorized transmission of sensitive data by placing it in the argument values of an MCP tool call. The security boundary is crossed when data available inside the host or a trusted source becomes part of the `arguments` object sent by an MCP client to an attacker-controlled server or unauthorized external destination. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C001,SAF-T1911-C004; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->

### In Scope

- Sensitive host, model-context, or trusted-tool data is materialized in a `tools/call` argument and sent to an unauthorized recipient. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C001,SAF-T1911-C004,SAF-T1911-C006; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- The receiving field may belong to a malicious MCP server or to a trusted tool whose destination or content parameter has been subverted. [WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->

### Out of Scope

- Prompt, context, or tool-description injection without sensitive data in an outbound tool parameter is a delivery behavior covered by SAF-T1102. [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) <!-- SAF-TRACE: claims=SAF-T1911-C010; sources=SRC-owasp-mcp-top10-v0.1 -->
- Reading or collecting sensitive data without transmitting it is collection behavior covered by SAF-T1801. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C004; sources=SRC-invariant-tpa-2025-04-01 -->
- Startup-command exfiltration by a malicious local server is outside this parameter-specific boundary because the data leaves through server process behavior rather than a host-issued tool argument. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1911-C009; sources=SRC-mcp-security-2025-11-25 -->

### Distinguishing Characteristics

The decisive observable is sensitive content or data lineage in the outbound argument object. Instruction injection explains why a model may attempt the call, and collection explains how the data became available; neither is Parameter Exfiltration until the sensitive value crosses the client-to-server or client-to-service boundary as an argument. [MCP Architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture/index) and [Invariant WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C003,SAF-T1911-C006,SAF-T1911-C010; sources=SRC-mcp-architecture-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-owasp-mcp-top10-v0.1 -->

## Description

MCP clients send a `tools/call` request containing a tool name and an `arguments` object. Parameter Exfiltration abuses that ordinary data path: an agent inserts sensitive values it can access into one or more arguments, and the client sends them to a server or external tool destination that is not authorized to receive them. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C001,SAF-T1911-C004; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->

The behavior is demonstrated, not merely inferred. Luca Beurer-Kellner and Marc Fischer of Invariant Labs reported a controlled Cursor experiment that sent sensitive local-file contents in an unrelated parameter, and a separate study that placed chat or contact data into WhatsApp tool-call fields. Neither report establishes a production breach or present-day susceptibility of every named client. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) and [WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C006,SAF-T1911-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->

MCP architecture assigns the host responsibility for consent and security boundaries, and current tool guidance recommends showing inputs before dispatch. Those controls can interrupt the technique, but an approval interface that hides or truncates argument values can fail to expose the actual data transfer. [MCP Architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture/index), [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), and [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C002,SAF-T1911-C003,SAF-T1911-C005,SAF-T1911-C008; sources=SRC-mcp-architecture-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->

## Attack Vectors

- **Primary Vector**: A malicious or compromised instruction source induces the model to place sensitive data in a tool argument bound for an unauthorized destination. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Secondary Vector**: An injected tool result or message supplies the instruction without requiring an attacker-controlled MCP server. [WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Affected Components**: MCP host, model orchestration layer, client router, receiving server, and external service. [MCP Architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture/index) <!-- SAF-TRACE: claims=SAF-T1911-C001,SAF-T1911-C003; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-architecture-2025-11-25 -->
- **Trust Boundary Crossed**: Sensitive host or trusted-source data crosses into a server-specific client session or external service request through tool arguments. [MCP Architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture/index) <!-- SAF-TRACE: claims=SAF-T1911-C003,SAF-T1911-C006; sources=SRC-mcp-architecture-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07 -->

## Technical Details

### Prerequisites

- The agent or host can obtain sensitive data from local files, model context, or a trusted tool result. [Invariant controlled demonstrations](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C006,SAF-T1911-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- An attacker-controlled instruction, poisoned description, or injected result influences argument construction. [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C007,SAF-T1911-C010; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-owasp-mcp-top10-v0.1 -->
- The host dispatches the call without an effective data-flow block or informed denial of the complete arguments. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C005,SAF-T1911-C008,SAF-T1911-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25 -->

### Attack Flow

1. **Setup**: The adversary controls an instruction source that the agent processes, such as a tool description or retrieved message. [Invariant controlled demonstrations](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
2. **Collection**: The agent reads or receives sensitive content available through its host or another connected tool. [WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
3. **Argument Construction**: The model places the sensitive value in a field that appears plausible for the selected tool. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
4. **Dispatch**: The client serializes the tool name and arguments into `tools/call`; an incomplete approval view may not reveal the embedded data. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C001,SAF-T1911-C005; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->
5. **Boundary Crossing**: The unauthorized server or service receives the sensitive argument. [Invariant WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
6. **Follow-On Activity**: Any later credential use or data abuse is outside this technique and depends on what was transmitted. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C015,SAF-T1911-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07 -->

### Example Scenario

An agent reads a document labeled `confidential`, then a poisoned instruction causes it to populate an optional `notes` argument for an untrusted summarization tool. The host-side audit event records only the label and data-flow match in this inert example; no document contents or reusable payload are reproduced. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C011; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07 -->

The client would transmit the normalized structure below to the server; the placeholder is intentionally non-sensitive. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C001; sources=SRC-mcp-tools-2025-11-25 -->

```json
{
  "method": "tools/call",
  "params": {
    "name": "summarize",
    "arguments": {"notes": "[REDACTED-SENSITIVE-VALUE]"}
  }
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1911-C001 | `tools/call` carries a name and arguments object. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Structure does not establish authorization. |
| SAF-T1911-C002 | Tools may be model-controlled; human denial and confirmation are recommended. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | SHOULD-level client guidance. |
| SAF-T1911-C003 | The host manages consent and server isolation. | Research-Derived | SRC-mcp-architecture-2025-11-25: [MCP Architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture/index) | Implementation effectiveness is not established. |
| SAF-T1911-C004 | A controlled tool-poisoning experiment transmitted sensitive files in a parameter. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Invariant](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Lab result, not a production breach or current-client assessment. |
| SAF-T1911-C005 | The tested confirmation UI hid complete inputs; encoding could reduce visibility. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Invariant](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | One tested interface and date. |
| SAF-T1911-C006 | A controlled cross-server experiment sent chat history in message fields. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07: [Invariant](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | Lab result; delivery behavior is separate. |
| SAF-T1911-C007 | An injected-message variant sent contact data after context adaptation. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07: [Invariant](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | Context-dependent lab result. |
| SAF-T1911-C008 | Current guidance recommends complete-input review, confirmation, and logging. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | No standard log schema. |
| SAF-T1911-C009 | Current guidance recommends restricted filesystem and network access for local servers. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP Security](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Does not stop already-authorized remote calls. |
| SAF-T1911-C010 | OWASP separates poisoning, audit, and over-sharing risks. | Research-Derived | SRC-owasp-mcp-top10-v0.1: [OWASP](https://owasp.org/www-project-mcp-top-10/) | Beta guidance, not incident evidence. |
| SAF-T1911-C011 | Sensitive-lineage plus untrusted-call correlation is a bounded analytic. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-invariant-tpa-2025-04-01; SRC-invariant-whatsapp-mcp-2025-04-07 | Requires non-standard host enrichment. |
| SAF-T1911-C012 | Redaction, missing lineage, encoding, and non-MCP paths are blind spots. | Research-Derived | SRC-invariant-tpa-2025-04-01; SRC-mcp-tools-2025-11-25 | Evasion coverage is not measured. |
| SAF-T1911-C013 | Legitimate external transfers require policy and trust tuning. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-mitre-attack-t1020-v1.3 | No universal allowlist or threshold. |
| SAF-T1911-C014 | Visibility, approval, logging, and privilege restriction cover different stages. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-mcp-security-2025-11-25 | Human approval and sandboxing have limits. |
| SAF-T1911-C015 | Response should contain the path, preserve evidence, and rotate transmitted credentials. | Research-Derived | SRC-invariant-tpa-2025-04-01; SRC-mcp-tools-2025-11-25; SRC-mcp-security-2025-11-25 | Scope depends on received values. |
| SAF-T1911-C016 | ATT&CK T1020 is analogous but not MCP-specific. | Research-Derived | SRC-mitre-attack-t1020-v1.3: [ATT&CK](https://attack.mitre.org/techniques/T1020/) | A separate transfer behavior normally also applies. |
| SAF-T1911-C017 | Description-only scanning cannot prove runtime parameter transmission. | Research-Derived | SRC-invariant-mcp-scan-2025: [Invariant MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) | Does not assess later versions. |
| SAF-T1911-C018 | The stable observable is a source-to-argument-to-destination sequence. | Research-Derived | SRC-invariant-tpa-2025-04-01; SRC-invariant-whatsapp-mcp-2025-04-07 | Product-specific artifacts may exist. |
| SAF-T1911-C019 | Confidentiality impact can be high under demonstrated access and dispatch conditions. | Demonstrated | SRC-invariant-tpa-2025-04-01; SRC-invariant-whatsapp-mcp-2025-04-07 | Prevalence and production loss are not established. |

### Current State

- **Affected Environments**: Agentic hosts that can access sensitive data and dispatch MCP tool arguments to an unauthorized server or service. [MCP Architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture/index) <!-- SAF-TRACE: claims=SAF-T1911-C003,SAF-T1911-C004,SAF-T1911-C006; sources=SRC-mcp-architecture-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Known Exploitation**: Controlled demonstrations qualify; no qualifying production incident or direct vulnerability was identified in the [reviewed coverage](../../research/techniques/SAF-T1911/source-coverage.yml).
- **Available Protections**: Complete argument display, meaningful confirmation, tool-usage logging, server isolation, and least-privilege filesystem and network access. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C008,SAF-T1911-C009,SAF-T1911-C014; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25 -->
- **Residual Risk**: Encoded values, redacted logs, absent lineage, user-approved lookalikes, and non-MCP channels can evade the bounded analytic. [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C012,SAF-T1911-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-mitre-attack-t1020-v1.3 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Reviewed-corpus production/CVE gap | Searched 2026-09-02 | No qualifying direct production breach or direct CVE was identified; continue authoritative-catalog review during integration. | Evidence gap documented in the [coverage audit](../../research/techniques/SAF-T1911/source-coverage.yml). | NVD filtered API access was rejected and the CISA KEV feed returned 403 during this run. |
| Invariant Tool Poisoning experiment | Published 2025-04-01; controlled Cursor setup | Sensitive configuration and private-key data were sent in a side parameter; current MCP guidance recommends full-input review and logging. | Direct demonstration of Parameter Exfiltration. [Research report](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C005,SAF-T1911-C008; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25 --> | No production exploitation or current client status. |
| Invariant WhatsApp MCP experiments | Published 2025-04-07 and updated 2025-04-09; controlled Cursor and WhatsApp MCP setups | Chat or contact data was placed in message fields directed to an attacker; remediation guidance was precautionary rather than a vendor patch record. | Direct demonstrations using malicious-description and injected-message delivery. [Research report](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C006,SAF-T1911-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> | No documented production victim or CVE. |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Demonstrated data classes include configuration, private keys, chat history, and contacts; impact is bounded by accessible data and dispatch. [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| Integrity | Low | Argument manipulation is a means to transmit data; material state change belongs to a different objective unless the tool also alters a recipient or action. [WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C006; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| Availability | None | The defining behavior transmits data and does not require service disruption. [ATT&CK Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) <!-- SAF-TRACE: claims=SAF-T1911-C016; sources=SRC-mitre-attack-t1020-v1.3 --> |
| Scope | Multi-System | The data may originate from the host or one trusted server and be sent to a different MCP server or external messaging service. [MCP Architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture/index) <!-- SAF-TRACE: claims=SAF-T1911-C003,SAF-T1911-C006; sources=SRC-mcp-architecture-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07 --> |

### Severity Conditions

- **Severity increases when**: The host exposes credentials, private data, broad cross-server context, or opaque approval views. [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C005,SAF-T1911-C019; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Severity decreases when**: The host restricts accessible data and server privileges, blocks sensitive data flow, and presents complete arguments for meaningful approval. [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1911-C008,SAF-T1911-C009,SAF-T1911-C014; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or client audit | `tools/call` dispatch and approval | timestamp, session, server identity and trust, tool name, normalized argument metadata, approval visibility, policy exception | Collect before dispatch; protect raw values and prefer classifications or keyed fingerprints. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C001,SAF-T1911-C008,SAF-T1911-C011; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| Host data-lineage or DLP enrichment | Sensitive source content mapped into tool arguments | source classification, argument data-flow match, authorized workflow or exception | Without lineage or equivalent content classification, the rule cannot distinguish a secret from an ordinary argument. [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C011,SAF-T1911-C012; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 --> |

### Indicators of Compromise (IoCs)

- No universal durable IoC was identified; different demonstrations used different data, parameters, and destinations. [Invariant controlled demonstrations](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C018; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->

### Behavioral Indicators

- Sensitive source access or lineage is followed by a `tools/call` whose arguments contain the same classified content and whose destination is untrusted. [Invariant controlled demonstrations](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C011,SAF-T1911-C018; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- The approval view omits complete arguments, or the call falls outside an authorized data-transfer workflow. [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C005,SAF-T1911-C013; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-mitre-attack-t1020-v1.3 -->
- Tool-description scanning alone is not runtime confirmation because the documented scanner does not retain tool-call contents or results. [Invariant MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) <!-- SAF-TRACE: claims=SAF-T1911-C017; sources=SRC-invariant-mcp-scan-2025 -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify enriched MCP tool calls that carry sensitive source data to an untrusted destination without an approved policy exception. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C011; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Rule Status**: Experimental because sensitive data lineage and destination trust are deployment-specific enrichments. [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C011,SAF-T1911-C012; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Detection Logic**: Match a dispatched `tools/call` with `dataflow.sensitive_to_arguments=true` and `destination.trust=untrusted`, excluding explicitly approved policy exceptions. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C011,SAF-T1911-C013; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mitre-attack-t1020-v1.3 -->
- **Correlation Window**: No time threshold is used; data-lineage evidence must be attached to the same normalized tool-call event. [Invariant controlled demonstrations](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C011,SAF-T1911-C018; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Known False Positives**: Authorized support, backup, or analysis workflows may intentionally send classified data externally; use explicit scoped exceptions rather than suppressing all such traffic. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C013; sources=SRC-mcp-tools-2025-11-25,SRC-mitre-attack-t1020-v1.3 -->
- **Known Limitations**: Missing lineage, redacted values, encoding, unknown destination trust, and non-MCP channels are blind spots. [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C012; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25 -->
- **Tuning Guidance**: Maintain narrow workflow exceptions keyed by tool, destination, data class, and owner; review unknown destinations instead of treating them as confirmed malicious. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C013; sources=SRC-mcp-tools-2025-11-25,SRC-mitre-attack-t1020-v1.3 -->

### Validation

- **Test Data**: [events.json](../../tests/SAF-T1911/events.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1911/test_detection_rule.py)
- **Expected Result**: [test-logs.json](../../tests/SAF-T1911/test-logs.json)
- **Last Validated**: 2026-09-02; see [quality-review.yml](../../research/techniques/SAF-T1911/quality-review.yml).
- **Canonical Validation Proof**: The destination-repository detector and strict validator results are recorded in [canonical-validation.txt](../../research/techniques/SAF-T1911/validation/canonical-validation.txt).
- **Feasibility Waiver**: None; deterministic positive, negative, boundary, malformed, authorized, and expected-lookalike cases are included in the [test log](../../tests/SAF-T1911/test-logs.json).

## Mitigation Strategies

### Preventive Controls

1. **Pre-dispatch data control**: Show complete arguments and block sensitive classifications from unauthorized destinations before `tools/call` leaves the host. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C008,SAF-T1911-C014; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25 -->
2. **Server isolation**: Restrict local MCP server filesystem and network privileges and grant additional access explicitly. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1911-C009,SAF-T1911-C014; sources=SRC-mcp-security-2025-11-25,SRC-mcp-tools-2025-11-25 -->
3. **Meaningful confirmation**: Require user approval for sensitive operations only after presenting the destination and complete, non-truncated argument values. [Invariant research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C005,SAF-T1911-C008,SAF-T1911-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25 -->

### Detective Controls

1. **Tool-call audit**: Log the server identity, tool, argument classifications, approval visibility, and policy decision before dispatch. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C008,SAF-T1911-C011; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
2. **Data-flow correlation**: Alert when sensitive source content maps into arguments for an untrusted destination and no scoped exception applies. [Invariant controlled demonstrations](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C011,SAF-T1911-C013; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mitre-attack-t1020-v1.3 -->

### Response Procedures

#### Immediate Actions

- Deny a pending call or disconnect the implicated server and contain the affected session when dispatch already occurred. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25 -->
- Rotate only credentials whose values were transmitted or whose compromise is otherwise established. [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) <!-- SAF-TRACE: claims=SAF-T1911-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25 -->

#### Investigation Steps

- Preserve tool-call arguments or privacy-preserving fingerprints, server identity, approval presentation, and the sensitive source-access trail. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1911-C008,SAF-T1911-C015; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-mcp-security-2025-11-25 -->
- Determine which values reached which destination; do not infer exposure from tool-description scanning alone. [Invariant MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) <!-- SAF-TRACE: claims=SAF-T1911-C015,SAF-T1911-C017; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2025-11-25,SRC-mcp-security-2025-11-25,SRC-invariant-mcp-scan-2025 -->

#### Remediation

- Remove or distrust the inducing instruction source, close the approval-visibility gap, and constrain data and server privileges before reconnecting. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1911-C009,SAF-T1911-C014,SAF-T1911-C015; sources=SRC-mcp-security-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01 -->
- Add the confirmed source-to-argument sequence as a regression case without retaining raw exposed secrets. [Invariant controlled demonstrations](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) <!-- SAF-TRACE: claims=SAF-T1911-C011,SAF-T1911-C015; sources=SRC-mcp-tools-2025-11-25,SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-security-2025-11-25 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite or co-occurring | Injection supplies adversary influence; Parameter Exfiltration requires sensitive content in an outbound argument. [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C007,SAF-T1911-C010; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-owasp-mcp-top10-v0.1 --> |
| [SAF-T1801: Automated Data Harvesting](../SAF-T1801/README.md) | Prerequisite | Collection obtains data; Parameter Exfiltration transmits it in a tool parameter. [ATT&CK Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) <!-- SAF-TRACE: claims=SAF-T1911-C004,SAF-T1911-C016; sources=SRC-invariant-tpa-2025-04-01,SRC-mitre-attack-t1020-v1.3 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Analogous | Both use automated processing to transmit gathered data; T1020 is not MCP-specific and normally pairs with a separate transfer technique. <!-- SAF-TRACE: claims=SAF-T1911-C016; sources=SRC-mitre-attack-t1020-v1.3 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [Tools - Model Context Protocol Specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) - Tool invocation, arguments, confirmation, input visibility, and logging.
2. **SRC-mcp-architecture-2025-11-25**: [Architecture - Model Context Protocol Specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/architecture/index) - Host, client, server, and isolation responsibilities.
3. **SRC-mcp-security-2025-11-25**: [Security Best Practices - Model Context Protocol, 2025-11-25](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) - Server isolation, access restriction, logging, and scope minimization.
4. **SRC-invariant-tpa-2025-04-01**: [MCP Security Notification: Tool Poisoning Attacks - Luca Beurer-Kellner and Marc Fischer, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) - Controlled parameter-exfiltration experiment and interface limitations.
5. **SRC-invariant-whatsapp-mcp-2025-04-07**: [WhatsApp MCP Exploited - Luca Beurer-Kellner and Marc Fischer, 2025](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) - Controlled cross-server and injected-message parameter-exfiltration experiments.
6. **SRC-invariant-mcp-scan-2025**: [Introducing MCP-Scan - Luca Beurer-Kellner and Marc Fischer, 2025](https://invariantlabs.ai/blog/introducing-mcp-scan) - Tool-description scanner scope and runtime-logging limitation.
7. **SRC-owasp-mcp-top10-v0.1**: [OWASP MCP Top 10, v0.1 beta](https://owasp.org/www-project-mcp-top-10/) - Neighboring risk categories, telemetry guidance, project status, and attribution.
8. **SRC-mitre-attack-t1020-v1.3**: [MITRE ATT&CK T1020: Automated Exfiltration, v1.3](https://attack.mitre.org/techniques/T1020/) - Analogous framework behavior and limits.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Independent clean-room draft with evidence packet and tested analytic. | OpenAI Codex clean-room author |
