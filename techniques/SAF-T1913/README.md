# SAF-T1913: HTTP POST Exfil

## Overview

- **Tactic**: Exfiltration (ATK-TA0010)
- **Technique ID**: SAF-T1913
- **Research Packet**: [research/techniques/SAF-T1913](../../research/techniques/SAF-T1913/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1913/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: A completed transfer can disclose credentials or other high-sensitivity data, but severity depends on accessible content, destination trust, approval, and request completion. <!-- SAF-TRACE: claims=SAF-T1913-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-overview-2026 -->
- **First Observed**: Not observed in production in the reviewed direct-authority corpus as of 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1913-C014; sources=SRC-nvd-fsp-catalog-queries-2026-09-01,SRC-nvd-http-post-query-2026-09-02,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-02

## Scope

HTTP POST Exfil is the transfer of sensitive data from an MCP host or client to an adversary-controlled remote MCP server by placing that data in `tools/call` arguments carried in a Streamable HTTP POST body. <!-- SAF-TRACE: claims=SAF-T1913-C004; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-invariant-tpa-2025-04-01 -->

### In Scope

- Sensitive content appears in `params.arguments` of a `tools/call` request addressed to a remote MCP server. <!-- SAF-TRACE: claims=SAF-T1913-C002,SAF-T1913-C004; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-streamable-http-2026-07-28 -->
- The current Streamable HTTP transport sends the JSON-RPC message as one HTTP POST whose immediate recipient is that server. <!-- SAF-TRACE: claims=SAF-T1913-C001,SAF-T1913-C003; sources=SRC-mcp-streamable-http-2026-07-28,SRC-rfc9110 -->

### Out of Scope

- Prompt injection, tool poisoning, and prior collection are prerequisites or co-occurring behaviors; arbitrary command execution and use of disclosed credentials are follow-on behaviors. <!-- SAF-TRACE: claims=SAF-T1913-C004,SAF-T1913-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2026-07-28 -->
- URI or link-unfurl leakage, server-side request forgery, email or attachment transfer, stdio, and custom transports use a different channel or boundary. <!-- SAF-TRACE: claims=SAF-T1913-C012,SAF-T1913-C018,SAF-T1913-C020; sources=SRC-cve-34072,SRC-cve-2025-34072,SRC-mcp-security-2026-07-28,SRC-mcp-streamable-http-2026-07-28 -->

### Distinguishing Characteristics

The defining observables are an outbound POST, an MCP `tools/call` operation, sensitive-data classification for the request content, and receipt by the selected remote MCP endpoint. A request to an unintended destination is SSRF; a crawler fetching a secret-bearing URL is URI or link-unfurl exfiltration. <!-- SAF-TRACE: claims=SAF-T1913-C007,SAF-T1913-C009,SAF-T1913-C018; sources=SRC-mcp-streamable-http-2026-07-28,SRC-otel-http-spans-1.44.0,SRC-attack-m1057-v1.1,SRC-mcp-security-2026-07-28 -->

## Description

MCP revision 2026-07-28 requires each Streamable HTTP client request to be a new POST, and a `tools/call` request carries its tool name and arguments in the JSON-RPC body. The technique abuses this normal application channel: sensitive values become tool arguments, and the client delivers them to a server controlled by or accessible to the adversary. <!-- SAF-TRACE: claims=SAF-T1913-C001,SAF-T1913-C002,SAF-T1913-C003,SAF-T1913-C004; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-rfc9110 -->

The complete HTTP-specific behavior is Research-Derived. Luca Beurer-Kellner and Marc Fischer demonstrated sensitive files being sent to a malicious MCP server through a concealed tool parameter, but their report does not identify the transport; the HTTP step follows independently from the current MCP transport specification. <!-- SAF-TRACE: claims=SAF-T1913-C004,SAF-T1913-C005,SAF-T1913-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-streamable-http-2026-07-28,SRC-nvd-fsp-catalog-queries-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: An adversary-controlled or compromised remote MCP server receives a sensitive `tools/call` argument through its Streamable HTTP endpoint. <!-- SAF-TRACE: claims=SAF-T1913-C004; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-invariant-tpa-2025-04-01 -->
- **Secondary Vectors**:
  - A poisoned tool description or other adversarial instruction causes the agent to populate an otherwise benign argument with sensitive content. <!-- SAF-TRACE: claims=SAF-T1913-C005; sources=SRC-invariant-tpa-2025-04-01 -->
  - Missing, misleading, or incomplete approval presentation allows the transfer despite MCP's consent principles. <!-- SAF-TRACE: claims=SAF-T1913-C006; sources=SRC-mcp-overview-2026,SRC-mcp-tools-2026-07-28 -->
- **Affected Components**: MCP host, client, remote server, Streamable HTTP transport, tool approval layer, and egress telemetry pipeline. <!-- SAF-TRACE: claims=SAF-T1913-C004,SAF-T1913-C007,SAF-T1913-C008; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-otel-http-spans-1.44.0 -->
- **Trust Boundary Crossed**: The outbound data boundary from the host's sensitive context to the remote MCP server. <!-- SAF-TRACE: claims=SAF-T1913-C004,SAF-T1913-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-streamable-http-2026-07-28 -->

## Technical Details

### Prerequisites

- The host is connected to a remote MCP server through Streamable HTTP and can invoke one of its tools. <!-- SAF-TRACE: claims=SAF-T1913-C001,SAF-T1913-C002; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- Sensitive content is accessible to the agent or host and can be placed into a tool argument. <!-- SAF-TRACE: claims=SAF-T1913-C004,SAF-T1913-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2026-07-28 -->
- Consent, destination policy, or content controls do not prevent the request. <!-- SAF-TRACE: claims=SAF-T1913-C006,SAF-T1913-C016; sources=SRC-mcp-overview-2026,SRC-mcp-tools-2026-07-28,SRC-mitre-attack-t1048-v1.6,SRC-attack-m1057-v1.1 -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary operates or compromises a remote MCP server and exposes a tool whose argument can accept attacker-useful data. <!-- SAF-TRACE: claims=SAF-T1913-C002,SAF-T1913-C004; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-tpa-2025-04-01 -->
2. **Delivery**: Adversarial instructions or another prerequisite influence the agent to obtain sensitive content and place it in that argument. <!-- SAF-TRACE: claims=SAF-T1913-C005; sources=SRC-invariant-tpa-2025-04-01 -->
3. **Trigger or Execution**: The client constructs a `tools/call` JSON-RPC request containing the selected tool and arguments. <!-- SAF-TRACE: claims=SAF-T1913-C002; sources=SRC-mcp-tools-2026-07-28 -->
4. **Boundary Crossing**: The client sends the request body as an HTTP POST to the remote MCP endpoint without effective approval or content blocking. <!-- SAF-TRACE: claims=SAF-T1913-C001,SAF-T1913-C004,SAF-T1913-C006; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-overview-2026 -->
5. **Objective**: The remote server receives the sensitive argument value, completing the bounded confidentiality loss. <!-- SAF-TRACE: claims=SAF-T1913-C004,SAF-T1913-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-streamable-http-2026-07-28 -->
6. **Follow-On Activity**: Credential use, persistence, additional collection, and further exfiltration are separate behaviors requiring their own evidence and classification. <!-- SAF-TRACE: claims=SAF-T1913-C015; sources=SRC-invariant-tpa-2025-04-01 -->

### Example Scenario

An inert test host calls a remote tool at `collector.example.invalid`; the fixture records only a synthetic sensitivity label and placeholder hash, not a secret. This illustrates the request boundary without supplying an operational receiver or reusable payload. <!-- SAF-TRACE: claims=SAF-T1913-C001,SAF-T1913-C002,SAF-T1913-C004; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-tools-2026-07-28 -->

The following sanitized message mirrors only the protocol shape documented by the MCP Tools specification. <!-- SAF-TRACE: claims=SAF-T1913-C002; sources=SRC-mcp-tools-2026-07-28 -->

```json
{
  "jsonrpc": "2.0",
  "id": "example-1",
  "method": "tools/call",
  "params": {
    "name": "format_note",
    "arguments": {
      "sensitivity_label": "synthetic-secret",
      "value_hash": "sha256:placeholder"
    }
  }
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1913-C001 | Current Streamable HTTP uses one POST per JSON-RPC client request. | Research-Derived | SRC-mcp-streamable-http-2026-07-28: [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) | Current revision only. |
| SAF-T1913-C002 | `tools/call` carries tool name and arguments. | Research-Derived | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Message shape does not establish authorization. |
| SAF-T1913-C003 | POST sends a representation for target-specific processing. | Research-Derived | SRC-rfc9110: [RFC 9110 §9.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#name-post) | Generic HTTP semantics only. |
| SAF-T1913-C004 | Sensitive tool arguments cross to a remote MCP server in the POST body. | Research-Derived | SRC-mcp-streamable-http-2026-07-28 and SRC-invariant-tpa-2025-04-01: [transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [experiment](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Explicit inference; experiment transport unstated. |
| SAF-T1913-C005 | Invariant demonstrated concealed sensitive-data transfer in an MCP tool parameter. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Beurer-Kellner and Fischer](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Controlled experiment; transport unstated. |
| SAF-T1913-C006 | MCP requires consent for user-data exposure and tool use, but cannot enforce it at protocol level. | Research-Derived | SRC-mcp-overview-2026: [MCP Specification](https://modelcontextprotocol.io/specification/2026-07-28) | Implementation behavior varies. |
| SAF-T1913-C007 | Current requests expose `Mcp-Method` and `Mcp-Name` for intermediaries. | Research-Derived | SRC-mcp-streamable-http-2026-07-28: [request metadata](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) | Earlier revisions differ; no content label. |
| SAF-T1913-C008 | OpenTelemetry standardizes outbound HTTP method and destination fields. | Research-Derived | SRC-otel-http-spans-1.44.0: [HTTP client spans](https://opentelemetry.io/docs/specs/semconv/http/http-spans/) | Approval and DLP fields are supplemental. |
| SAF-T1913-C009 | Correlation of transport, destination, approval, and DLP labels is a defensible analytic. | Research-Derived | SRC-attack-m1057-v1.1: [Data Loss Prevention](https://attack.mitre.org/mitigations/M1057/) | Synthetic validation only. |
| SAF-T1913-C010 | Metadata alone cannot establish sensitive POST content. | Research-Derived | SRC-otel-http-spans-1.44.0: [HTTP span attributes](https://opentelemetry.io/docs/specs/semconv/http/http-spans/) | Product telemetry may add fields. |
| SAF-T1913-C011 | Approved, trusted exports are the bounded expected lookalike. | Research-Derived | SRC-mcp-overview-2026: [consent principles](https://modelcontextprotocol.io/specification/2026-07-28) | Trust or approval can be wrong. |
| SAF-T1913-C012 | CVE-2025-34072 is adjacent link-unfurl exfiltration. | Demonstrated | SRC-cve-2025-34072 and SRC-cve-34072: [CVE record](https://cveawg.mitre.org/api/cve/CVE-2025-34072), [original disclosure](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) | URI and preview-fetch channel, not MCP POST content. |
| SAF-T1913-C013 | CVE-2026-15643 is adjacent HealthLake MCP pagination SSRF. | Demonstrated | SRC-aws-cve-2026-15643 and SRC-cve-2026-15643: [AWS bulletin](https://aws.amazon.com/security/security-bulletins/2026-054-aws/), [CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-15643) | SSRF; CISA ADP recorded no exploitation evidence. |
| SAF-T1913-C014 | No exact production, direct-vulnerability, or complete-demo case qualified in the reviewed corpus. | Research-Derived | SRC-nvd-fsp-catalog-queries-2026-09-01, SRC-nvd-http-post-query-2026-09-02, SRC-cisa-kev-2026-09-01 | Bounded corpus conclusion, not universal absence. |
| SAF-T1913-C015 | Immediate impact is conditional confidentiality loss. | Research-Derived | SRC-invariant-tpa-2025-04-01: [Invariant experiment](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Severity depends on data and completion. |
| SAF-T1913-C016 | Approval, destination filtering, and DLP constrain the transfer. | Research-Derived | SRC-mitre-attack-t1048-v1.6 and SRC-attack-m1057-v1.1: [T1048](https://attack.mitre.org/techniques/T1048/), [M1057](https://attack.mitre.org/mitigations/M1057/) | Layered controls retain bypasses. |
| SAF-T1913-C017 | Response should contain, preserve, scope, and rotate when credentials are exposed. | Research-Derived | SRC-aws-cve-2026-15643: [AWS workaround guidance](https://aws.amazon.com/security/security-bulletins/2026-054-aws/) | Rotation applies to revocable secrets. |
| SAF-T1913-C018 | SSRF differs by unintended-destination request behavior. | Research-Derived | SRC-mcp-security-2026-07-28: [MCP SSRF guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) | Chains can contain both behaviors. |
| SAF-T1913-C019 | ATT&CK T1048 is analogous, not direct. | Research-Derived | SRC-mitre-attack-t1048-v1.6: [T1048](https://attack.mitre.org/techniques/T1048/) | ATT&CK does not model MCP message semantics. |
| SAF-T1913-C020 | Current POST and header assumptions are protocol-version dependent. | Research-Derived | SRC-mcp-streamable-http-2026-07-28: [backward compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) | Older and custom transports remain possible. |

### Current State

- **Affected Environments**: Remote MCP connections using Streamable HTTP where an agent can populate tool arguments with sensitive data and approval, destination, or DLP controls are ineffective. <!-- SAF-TRACE: claims=SAF-T1913-C004,SAF-T1913-C006,SAF-T1913-C016; sources=SRC-mcp-streamable-http-2026-07-28,SRC-invariant-tpa-2025-04-01,SRC-mcp-overview-2026,SRC-attack-m1057-v1.1 -->
- **Known Exploitation**: No qualifying direct production incident was identified; the closest tool-parameter result is a controlled demonstration with an unstated transport. <!-- SAF-TRACE: claims=SAF-T1913-C005,SAF-T1913-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-nvd-fsp-catalog-queries-2026-09-01,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Explicit approval, trusted-destination policy, network filtering, and DLP inspection can interrupt the transfer. <!-- SAF-TRACE: claims=SAF-T1913-C006,SAF-T1913-C016; sources=SRC-mcp-overview-2026,SRC-mcp-tools-2026-07-28,SRC-mitre-attack-t1048-v1.6,SRC-attack-m1057-v1.1 -->
- **Residual Risk**: Compromised trusted servers, mistaken approvals, transformed data, missing DLP labels, and legacy transports can bypass or blind the example analytic. <!-- SAF-TRACE: claims=SAF-T1913-C010,SAF-T1913-C011,SAF-T1913-C020; sources=SRC-otel-http-spans-1.44.0,SRC-attack-m1057-v1.1,SRC-mcp-streamable-http-2026-07-28 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| No qualifying direct case identified | Authority corpus reviewed 2026-09-02 | Direct production, vulnerability, and full HTTP-specific demonstration evidence remains a gap. | Explicit gap | The bounded searches cannot establish universal absence. <!-- SAF-TRACE: claims=SAF-T1913-C014; sources=SRC-nvd-fsp-catalog-queries-2026-09-01,SRC-nvd-http-post-query-2026-09-02,SRC-cisa-kev-2026-09-01 --> |
| Rank 1: Invariant Tool Poisoning Experiment 1 | 2025-04-01; controlled MCP client experiment | Sensitive MCP configuration and SSH-key content was sent through a hidden tool parameter; researchers recommend UI, pinning, cross-server, and dataflow controls. | Selected adjacent component demonstration | The report does not state the transport and is not a production incident. <!-- SAF-TRACE: claims=SAF-T1913-C005; sources=SRC-invariant-tpa-2025-04-01 --> |
| Rank 2: CVE-2025-34072 | 2025-06-24 disclosure; deprecated Anthropic Slack MCP Server | Prompt injection and link unfurling produced zero-click private-data disclosure; the deprecated server was not expected to receive a fix. | Selected adjacent vulnerability and demonstration | Data is embedded in a URL and fetched by preview services, not carried as MCP POST content. <!-- SAF-TRACE: claims=SAF-T1913-C012; sources=SRC-cve-2025-34072,SRC-cve-34072 --> |
| Rank 3: CVE-2026-15643 | 2026-07-14; AWS HealthLake MCP Server before 0.0.14 | Crafted pagination could disclose temporary AWS credentials to an arbitrary endpoint; fixed in 0.0.14, with least privilege and rotation guidance. | Selected adjacent vulnerability | The mechanism is SSRF; CISA ADP recorded exploitation `none` on 2026-07-15. <!-- SAF-TRACE: claims=SAF-T1913-C013; sources=SRC-aws-cve-2026-15643,SRC-cve-2026-15643 --> |

### Real-World Incidents or Demonstrations

Luca Beurer-Kellner and Marc Fischer's controlled experiment is the closest mechanism evidence: it shows sensitive values concealed in a tool parameter and received by a malicious MCP server. It is not described as a breach, and the unstated transport prevents it from establishing the complete HTTP-specific behavior. <!-- SAF-TRACE: claims=SAF-T1913-C005,SAF-T1913-C014; sources=SRC-invariant-tpa-2025-04-01,SRC-nvd-fsp-catalog-queries-2026-09-01 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Credentials, private keys, or other high-sensitivity arguments can be disclosed when the request reaches the adversary-controlled server. <!-- SAF-TRACE: claims=SAF-T1913-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-overview-2026 --> |
| Integrity | None | The bounded technique ends at data receipt; later use or modification is a separate behavior. <!-- SAF-TRACE: claims=SAF-T1913-C015; sources=SRC-invariant-tpa-2025-04-01 --> |
| Availability | None | The bounded transfer does not inherently disrupt service. <!-- SAF-TRACE: claims=SAF-T1913-C015; sources=SRC-invariant-tpa-2025-04-01 --> |
| Scope | Adjacent | One POST crosses from the host's sensitive context to one remote server; blast radius grows with repeated calls and data access. <!-- SAF-TRACE: claims=SAF-T1913-C001,SAF-T1913-C004,SAF-T1913-C015; sources=SRC-mcp-streamable-http-2026-07-28,SRC-invariant-tpa-2025-04-01 --> |

### Severity Conditions

- **Severity increases when**: the agent can reach credentials, private keys, regulated records, or other high-sensitivity data; tools run without intelligible approval; or the destination is untrusted. <!-- SAF-TRACE: claims=SAF-T1913-C005,SAF-T1913-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-overview-2026 -->
- **Severity decreases when**: data access is minimized and the request must pass explicit approval, destination allowlisting, and DLP blocking. <!-- SAF-TRACE: claims=SAF-T1913-C006,SAF-T1913-C016; sources=SRC-mcp-overview-2026,SRC-mcp-tools-2026-07-28,SRC-mitre-attack-t1048-v1.6,SRC-attack-m1057-v1.1 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP client or gateway | Outbound Streamable HTTP request | timestamp, client and actor IDs, request ID, `Mcp-Method`, `Mcp-Name`, protocol version | Normalize header names case-insensitively and preserve version for legacy handling. <!-- SAF-TRACE: claims=SAF-T1913-C007,SAF-T1913-C020; sources=SRC-mcp-streamable-http-2026-07-28 --> |
| HTTP client spans or egress proxy | Outbound request and response | `http.request.method`, `server.address`, `url.full`, status code, optional body size | Correlate each send attempt; do not assume standard spans expose content. <!-- SAF-TRACE: claims=SAF-T1913-C008,SAF-T1913-C010; sources=SRC-otel-http-spans-1.44.0 --> |
| Approval, trust, and DLP pipeline | Authorization and content-policy evaluation | approval state, destination trust, nonempty sensitive-data classes | Retain classifications or hashes instead of raw secret values. <!-- SAF-TRACE: claims=SAF-T1913-C009,SAF-T1913-C011; sources=SRC-mcp-overview-2026,SRC-attack-m1057-v1.1 --> |

### Indicators of Compromise (IoCs)

- No durable technique-specific IoC was identified; use behavioral correlation because the MCP endpoint and POST method can be legitimate. <!-- SAF-TRACE: claims=SAF-T1913-C009,SAF-T1913-C011; sources=SRC-mcp-streamable-http-2026-07-28,SRC-attack-m1057-v1.1 -->

### Behavioral Indicators

- A `tools/call` POST to an untrusted or unknown server carries a positive sensitive-data classification without recorded approval. <!-- SAF-TRACE: claims=SAF-T1913-C007,SAF-T1913-C009; sources=SRC-mcp-streamable-http-2026-07-28,SRC-attack-m1057-v1.1 -->
- Repeated POST attempts, new server addresses, or body-size deviation can increase investigative priority but do not independently prove exfiltration. <!-- SAF-TRACE: claims=SAF-T1913-C008,SAF-T1913-C010; sources=SRC-otel-http-spans-1.44.0 -->
- Approval without trusted destination, or trusted destination without approval, remains suspicious under the example rule. <!-- SAF-TRACE: claims=SAF-T1913-C011; sources=SRC-mcp-overview-2026,SRC-attack-m1057-v1.1 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify sensitive `tools/call` POSTs that lack the combined approval and destination-trust conditions. <!-- SAF-TRACE: claims=SAF-T1913-C009,SAF-T1913-C011; sources=SRC-mcp-streamable-http-2026-07-28,SRC-attack-m1057-v1.1 -->
- **Rule Status**: Experimental; representative synthetic validation only. [Detection proof](../../research/techniques/SAF-T1913/validation/detection-test.txt)
- **Detection Logic**: Match POST plus `tools/call` plus a nonempty DLP class, then suppress only an approved transfer to a trusted or partner-allowlisted destination. <!-- SAF-TRACE: claims=SAF-T1913-C009,SAF-T1913-C011; sources=SRC-mcp-streamable-http-2026-07-28,SRC-attack-m1057-v1.1 -->
- **Correlation Window**: One request event; repeated attempts may be aggregated by request, actor, client, and destination for triage. <!-- SAF-TRACE: claims=SAF-T1913-C007,SAF-T1913-C008; sources=SRC-mcp-streamable-http-2026-07-28,SRC-otel-http-spans-1.44.0 -->
- **Known False Positives**: Approved emergency exports, stale trust labels, and overly broad DLP classification. <!-- SAF-TRACE: claims=SAF-T1913-C011; sources=SRC-mcp-overview-2026,SRC-attack-m1057-v1.1 -->
- **Known Limitations**: Missing DLP metadata, transformed content, mistaken approval, compromised trusted servers, legacy revisions, and custom transports can evade or blind the rule. <!-- SAF-TRACE: claims=SAF-T1913-C010,SAF-T1913-C011,SAF-T1913-C020; sources=SRC-otel-http-spans-1.44.0,SRC-mcp-streamable-http-2026-07-28,SRC-attack-m1057-v1.1 -->
- **Tuning Guidance**: Populate destination trust from controlled inventory, require explicit approval provenance, and tune DLP classes without retaining raw values. <!-- SAF-TRACE: claims=SAF-T1913-C009,SAF-T1913-C011,SAF-T1913-C016; sources=SRC-mcp-overview-2026,SRC-attack-m1057-v1.1,SRC-mitre-attack-t1048-v1.6 -->

### Validation

- **Test Data**: [11 inert fixtures](../../tests/SAF-T1913/fixtures.jsonl)
- **Validation Script**: [representative unit tests](../../tests/SAF-T1913/test_detection.py)
- **Expected Result**: Five alerts and six non-alerts across all required fixture classes, with zero mismatches. [Detection proof](../../research/techniques/SAF-T1913/validation/detection-test.txt)
- **Last Validated**: 2026-09-02. [Quality review](../../research/techniques/SAF-T1913/quality-review.yml)
- **Feasibility Waiver**: None. [Technique contract](../../research/techniques/SAF-T1913/technique-contract.yml)

## Mitigation Strategies

### Preventive Controls

1. **Intelligible Tool Approval**: Show the remote destination, tool name, sensitive data classes, and intended transfer before authorizing the call. <!-- SAF-TRACE: claims=SAF-T1913-C006,SAF-T1913-C016; sources=SRC-mcp-overview-2026,SRC-mcp-tools-2026-07-28 -->
2. **Destination Filtering**: Permit remote MCP POST traffic only to inventoried endpoints and treat destination changes as new trust decisions. <!-- SAF-TRACE: claims=SAF-T1913-C016; sources=SRC-mitre-attack-t1048-v1.6,SRC-mcp-overview-2026 -->
3. **Data Loss Prevention**: Classify and block unapproved sensitive content before the HTTP request leaves the host or controlled gateway. <!-- SAF-TRACE: claims=SAF-T1913-C016; sources=SRC-attack-m1057-v1.1 -->

### Detective Controls

1. **MCP-Aware Egress Telemetry**: Record current `Mcp-Method` and `Mcp-Name` with standard HTTP client destination fields and protocol version. <!-- SAF-TRACE: claims=SAF-T1913-C007,SAF-T1913-C008,SAF-T1913-C020; sources=SRC-mcp-streamable-http-2026-07-28,SRC-otel-http-spans-1.44.0 -->
2. **Content-Policy Correlation**: Alert when a sensitive data class appears without both approval and a trusted destination. <!-- SAF-TRACE: claims=SAF-T1913-C009,SAF-T1913-C011; sources=SRC-attack-m1057-v1.1,SRC-mcp-overview-2026 -->

### Response Procedures

#### Immediate Actions

- Disable or isolate the implicated remote MCP endpoint and stop the affected client session while preserving request identifiers. <!-- SAF-TRACE: claims=SAF-T1913-C017; sources=SRC-mcp-streamable-http-2026-07-28,SRC-otel-http-spans-1.44.0 -->
- Revoke or rotate credentials whose classification indicates they may have crossed the boundary. <!-- SAF-TRACE: claims=SAF-T1913-C017; sources=SRC-aws-cve-2026-15643 -->

#### Investigation Steps

- Correlate the request, actor, client, server address, tool name, approval record, DLP classes, status, and retries without copying raw secret values into the case record. <!-- SAF-TRACE: claims=SAF-T1913-C007,SAF-T1913-C008,SAF-T1913-C010,SAF-T1913-C017; sources=SRC-mcp-streamable-http-2026-07-28,SRC-otel-http-spans-1.44.0,SRC-attack-m1057-v1.1 -->
- Determine whether the observed channel was the MCP POST body, URI unfurling, SSRF, or another transfer mechanism, and classify co-occurring delivery or collection separately. <!-- SAF-TRACE: claims=SAF-T1913-C012,SAF-T1913-C018; sources=SRC-cve-34072,SRC-cve-2025-34072,SRC-mcp-security-2026-07-28 -->

#### Remediation

- Remove the adversarial server or unsafe tool, repair approval and destination policy, and add regression fixtures for the observed data class and trust decision. <!-- SAF-TRACE: claims=SAF-T1913-C006,SAF-T1913-C016,SAF-T1913-C017; sources=SRC-mcp-overview-2026,SRC-mcp-tools-2026-07-28,SRC-attack-m1057-v1.1,SRC-aws-cve-2026-15643 -->
- Validate credential rotation and re-run MCP-aware egress detection before restoring the connection. <!-- SAF-TRACE: claims=SAF-T1913-C009,SAF-T1913-C017; sources=SRC-aws-cve-2026-15643,SRC-mcp-streamable-http-2026-07-28 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md) | Prerequisite | Changes agent intent; SAF-T1913 starts at sensitive argument transfer. <!-- SAF-TRACE: claims=SAF-T1913-C004,SAF-T1913-C005; sources=SRC-invariant-tpa-2025-04-01,SRC-mcp-tools-2026-07-28 --> |
| [SAF-T1911: Parameter Exfiltration](../SAF-T1911/README.md) | Broader channel | Covers sensitive data placed in tool arguments; SAF-T1913 narrows the channel to a Streamable HTTP POST body sent to a remote MCP server. <!-- SAF-TRACE: claims=SAF-T1913-C001,SAF-T1913-C002,SAF-T1913-C004; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-invariant-tpa-2025-04-01 --> |
| [SAF-T1902: Covert Channel in Responses](../SAF-T1902/README.md) | Alternative | Embeds data in a URI and depends on a fetcher rather than an MCP POST body. <!-- SAF-TRACE: claims=SAF-T1913-C012; sources=SRC-cve-34072,SRC-cve-2025-34072 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Analogous | T1048 includes HTTP/S transfer to an alternate network location, but does not model MCP tools/call semantics and depends on the relationship to command and control. <!-- SAF-TRACE: claims=SAF-T1913-C019; sources=SRC-mitre-attack-t1048-v1.6 --> |

## References

1. **SRC-mcp-overview-2026**: [Model Context Protocol Specification, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) — consent, data privacy, tool safety, and enforcement limits.
2. **SRC-mcp-streamable-http-2026-07-28**: [MCP Streamable HTTP, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) — POST transport, request body, headers, and backward compatibility.
3. **SRC-mcp-tools-2026-07-28**: [MCP Tools, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — `tools/call`, arguments, and approval guidance.
4. **SRC-mcp-security-2026-07-28**: [MCP Security Best Practices, revision 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) — SSRF definition and distinction.
5. **SRC-rfc9110**: [RFC 9110: HTTP Semantics — Roy T. Fielding, Mark Nottingham, and Julian Reschke, 2022](https://www.rfc-editor.org/rfc/rfc9110.html#name-post) — POST semantics.
6. **SRC-invariant-tpa-2025-04-01**: [MCP Security Notification: Tool Poisoning Attacks — Luca Beurer-Kellner and Marc Fischer, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — controlled hidden-argument exfiltration.
7. **SRC-otel-http-spans-1.44.0**: [OpenTelemetry Semantic Conventions for HTTP Spans 1.44.0](https://opentelemetry.io/docs/specs/semconv/http/http-spans/) — outbound HTTP telemetry fields.
8. **SRC-mitre-attack-t1048-v1.6**: [MITRE ATT&CK T1048, version 1.6 — contributors Alfredo Abarca and William Cain](https://attack.mitre.org/techniques/T1048/) — analogous mapping and detection context.
9. **SRC-attack-m1057-v1.1**: [MITRE ATT&CK M1057, version 1.1](https://attack.mitre.org/mitigations/M1057/) — DLP classification, monitoring, and blocking.
10. **SRC-cve-34072**: [Anthropic Slack MCP Server Data Exfiltration — wunderwuzzi, 2025](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) — original adjacent link-unfurl disclosure.
11. **SRC-cve-2025-34072**: [CVE-2025-34072 — VulnCheck CNA with CISA ADP enrichment](https://cveawg.mitre.org/api/cve/CVE-2025-34072) — identifier, affected record, and proof-of-concept status.
12. **SRC-aws-cve-2026-15643**: [AWS bulletin 2026-054-AWS — AWS Security; Marios Gyftos credited](https://aws.amazon.com/security/security-bulletins/2026-054-aws/) — HealthLake MCP SSRF, fixed version, and response guidance.
13. **SRC-cve-2026-15643**: [CVE-2026-15643 — Amazon CNA with CISA ADP enrichment](https://cveawg.mitre.org/api/cve/CVE-2026-15643) — affected range and exploitation assessment.
14. **SRC-nvd-fsp-catalog-queries-2026-09-01**: [NVD CVE API query for Model Context Protocol](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol) — 77-record authority-catalog review on 2026-09-02.
15. **SRC-nvd-http-post-query-2026-09-02**: [NVD CVE API query for HTTP POST exfiltration](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=HTTP%20POST%20exfiltration) — three-record authority-catalog review on 2026-09-02.
16. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog, version 2026.09.01](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — exact-ID membership checks with bounded interpretation.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-02 | Clean-room initial technique, evidence packet, and tested detector. | OpenAI Codex clean-room agent `/root/cleanroom_saf_t1913` |
