# SAF-T1504: Token Theft via API Response

## Overview

- **Tactic**: Credential Access (ATK-TA0006)
- **Technique ID**: SAF-T1504
- **Research Packet**: [research/techniques/SAF-T1504](../../research/techniques/SAF-T1504/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1504/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Severity is highest when an unauthenticated or low-privilege recipient receives a long-lived, broadly scoped token that can be replayed outside MCP; short lifetime, narrow scope, sender constraint, redaction, and rapid revocation reduce impact. [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) <!-- SAF-TRACE: claims=SAF-T1504-C022; sources=SRC-rfc6750,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
- **First Observed**: Not observed in production in the reviewed corpus; publicly demonstrated with an inert token on 2026-05-20. [Meta Ads MCP advisory](https://github.com/pipeboard-co/meta-ads-mcp/security/advisories/GHSA-9gw6-46qc-99vr) <!-- SAF-TRACE: claims=SAF-T1504-C006,SAF-T1504-C010; sources=SRC-ghsa-meta-ads,SRC-cisa-kev-token-response-2026-09-01,SRC-cve-2026-48039,SRC-cve-2026-39974 -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers an adversary obtaining a reusable access, bearer, refresh, or session token because an MCP tool or agentic API response delivers that token to a recipient not authorized to possess it. The crossed boundary is the server-to-client response boundary, including result data later placed into model context. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) <!-- SAF-TRACE: claims=SAF-T1504-C001,SAF-T1504-C003,SAF-T1504-C004; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-ghsa-meta-ads -->

### In Scope

- A successful or error result contains reusable token material in text, structured content, an embedded resource, or response detail and releases it to an unauthorized caller, tenant, user, or model context. [MCP Tool Result](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#tool-result) <!-- SAF-TRACE: claims=SAF-T1504-C001,SAF-T1504-C004; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads -->
- A server fetches credential-bearing upstream data and reflects that data through JSON-RPC to a less-trusted caller. [n8n-MCP advisory](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-4ggg-h7ph-26qr) <!-- SAF-TRACE: claims=SAF-T1504-C008,SAF-T1504-C009; sources=SRC-ghsa-n8n-mcp,SRC-cve-2026-39974 -->

### Out of Scope

- Token theft from logs, repositories, browser storage, process memory, authorization redirects, or intercepted traffic is outside this technique when an API response is not the disclosure channel. [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) <!-- SAF-TRACE: claims=SAF-T1504-C004,SAF-T1504-C017; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-ghsa-meta-ads,SRC-mitre-t1528 -->
- Token passthrough and SSRF are neighboring mechanisms; each is in scope only when the resulting response itself gives a token to an unauthorized recipient. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1504-C012,SAF-T1504-C013; sources=SRC-mcp-security-2025-11-25 -->
- Subsequent replay, privilege escalation, persistence, and data access are follow-on behavior, although they determine impact. [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C017,SAF-T1504-C022; sources=SRC-rfc6750,SRC-mitre-t1528,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->

### Distinguishing Characteristics

Analysts distinguish this technique by proving three facts in the same event chain: a response result crossed from server to client, it contained a reusable token, and the recipient was not authorized to possess that token. A vulnerable fetch or missing authentication alone does not satisfy the contract. <!-- SAF-TRACE: claims=SAF-T1504-C004,SAF-T1504-C014,SAF-T1504-C019,SAF-T1504-C020; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-ghsa-meta-ads,SRC-cve-2026-27826,SRC-ghsa-mcp-atlassian-7r34,SRC-cve-2026-25650,SRC-ghsa-mcp-salesforce -->

## Description

MCP tool results may contain unstructured content, structured content, resource links, or embedded resources, and clients may provide execution-error content to a model. Those features create a legitimate server-to-client data path; SAF-T1504 occurs when application error handling, response composition, reflection, or another server path places a reusable token on that path for an unauthorized recipient. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) <!-- SAF-TRACE: claims=SAF-T1504-C001,SAF-T1504-C004; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads -->

The behavior is security-relevant because bearer-token possession is sufficient for use without separate proof-of-possession key material. The practical consequence depends on token audience, scope, lifetime, sender constraint, revocation, and the downstream service's controls. [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C011,SAF-T1504-C022; sources=SRC-rfc6750,SRC-mcp-authorization-2025-11-25,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->

The evidence status is Demonstrated because the Meta Ads MCP advisory reproduced an unauthenticated tool call returning an inert placeholder access token in a JSON-RPC response. The reviewed corpus did not establish the same behavior in a production incident. [Meta Ads MCP advisory](https://github.com/pipeboard-co/meta-ads-mcp/security/advisories/GHSA-9gw6-46qc-99vr) <!-- SAF-TRACE: claims=SAF-T1504-C006,SAF-T1504-C010; sources=SRC-ghsa-meta-ads,SRC-cve-2026-48039,SRC-cve-2026-39974,SRC-cisa-kev-token-response-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: Invoke a reachable tool or API path whose success or error serialization includes server-held token material. [CVE-2026-48039 record](https://cveawg.mitre.org/api/cve/CVE-2026-48039) <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C006; sources=SRC-cve-2026-48039,SRC-ghsa-meta-ads -->
- **Secondary Vectors**:
  - Cause an MCP server to fetch a credential-bearing internal endpoint and reflect the upstream body to the caller. [CVE-2026-39974 record](https://cveawg.mitre.org/api/cve/CVE-2026-39974) <!-- SAF-TRACE: claims=SAF-T1504-C008,SAF-T1504-C009; sources=SRC-cve-2026-39974,SRC-ghsa-n8n-mcp -->
  - Trigger an error path that serializes a token-bearing URL, request object, configuration object, or upstream response. [Meta Ads MCP advisory](https://github.com/pipeboard-co/meta-ads-mcp/security/advisories/GHSA-9gw6-46qc-99vr) [Elastic ESA-2026-24](https://discuss.elastic.co/t/kibana-8-19-14-9-2-8-9-3-3-security-update-esa-2026-24/385812) <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C018; sources=SRC-ghsa-meta-ads,SRC-elastic-esa-2026-24 -->
- **Affected Components**: MCP server tool handlers, upstream API adapters, JSON-RPC serialization, MCP client result processing, and model-context construction. <!-- SAF-TRACE: claims=SAF-T1504-C001,SAF-T1504-C004; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads -->
- **Trust Boundary Crossed**: Server-held or upstream credential material crosses into a response recipient that lacks authorization to possess it. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C004; sources=SRC-rfc6750,SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads -->

## Technical Details

### Prerequisites

- A tool or API response path can reach token-bearing server state, upstream response data, request metadata, or configuration. <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C008; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
- The response path fails to remove the token before serialization or forwarding. <!-- SAF-TRACE: claims=SAF-T1504-C002,SAF-T1504-C005; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads -->
- The caller, tenant, user, or model context can receive the result without authorization to possess the token. <!-- SAF-TRACE: claims=SAF-T1504-C004,SAF-T1504-C009; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies a reachable response path that uses a server credential or can reach credential-bearing upstream content. <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C008; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
2. **Delivery**: The adversary supplies a tool invocation, tenant-specific URL, or input that reaches the vulnerable handler. <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C008,SAF-T1504-C009; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
3. **Trigger or Execution**: The server calls an upstream service or constructs an error or success result using token-bearing state. <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C008; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
4. **Boundary Crossing**: The server serializes or reflects the token in result content without effective redaction or recipient authorization. <!-- SAF-TRACE: claims=SAF-T1504-C004,SAF-T1504-C006,SAF-T1504-C008; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
5. **Objective**: The unauthorized recipient obtains the reusable token value. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C004; sources=SRC-rfc6750,SRC-ghsa-meta-ads -->
6. **Follow-On Activity**: The recipient may replay the token within its remaining audience, scope, lifetime, and issuer constraints. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C007,SAF-T1504-C017,SAF-T1504-C022; sources=SRC-rfc6750,SRC-ghsa-meta-ads,SRC-mitre-t1528 -->

### Example Scenario

An unauthenticated caller invokes an inert account-listing tool. The upstream service returns an error, and the adapter mistakenly includes a request URL containing a fake test token in the tool result; a response guard classifies and redacts the value before delivery. This sanitized scenario models the demonstrated boundary without providing a working credential or exploit. <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C006,SAF-T1504-C023; sources=SRC-ghsa-meta-ads,SRC-cve-2026-48039 -->

```json
{
  "result_channel": "error_detail",
  "secret_finding": "access_token",
  "token_value": "[REDACTED-INERT-DEMO]",
  "recipient_authorized": false,
  "delivery": "blocked"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1504-C001 | MCP result and error channels can carry server-produced content to clients and models. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | The protocol does not state that compliant servers return tokens. <!-- SAF-TRACE: claims=SAF-T1504-C001; sources=SRC-mcp-tools-2025-11-25 --> |
| SAF-T1504-C002 | Servers must sanitize outputs; clients should validate results and log tool use. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | No universal secret-classifier schema is prescribed. <!-- SAF-TRACE: claims=SAF-T1504-C002; sources=SRC-mcp-tools-2025-11-25 --> |
| SAF-T1504-C003 | Bearer possession permits use without a separate proof key. | Research-Derived | SRC-rfc6750: [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) | Sender-constrained, expired, or revoked tokens may not be replayable. <!-- SAF-TRACE: claims=SAF-T1504-C003; sources=SRC-rfc6750 --> |
| SAF-T1504-C004 | Unauthorized delivery of a reusable token in result data is the defining response-boundary crossing. | Research-Derived | SRC-mcp-tools-2025-11-25, SRC-rfc6750, SRC-ghsa-meta-ads | This is the SAF synthesis. <!-- SAF-TRACE: claims=SAF-T1504-C004; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-ghsa-meta-ads --> |
| SAF-T1504-C005 | CVE-2026-48039 returned a Meta operator token in JSON-RPC before fixed version 1.0.109. | Demonstrated | SRC-cve-2026-48039, SRC-ghsa-meta-ads | Advisory narrative contains an older affected-range note. <!-- SAF-TRACE: claims=SAF-T1504-C005; sources=SRC-cve-2026-48039,SRC-ghsa-meta-ads --> |
| SAF-T1504-C006 | The Meta Ads advisory reproduced the complete behavior with a fake token. | Demonstrated | SRC-ghsa-meta-ads | Controlled demonstration, not production exploitation. <!-- SAF-TRACE: claims=SAF-T1504-C006; sources=SRC-ghsa-meta-ads --> |
| SAF-T1504-C007 | The Meta token could be reused outside MCP subject to its privileges and validity. | Demonstrated | SRC-ghsa-meta-ads | Realized impact depends on token properties. <!-- SAF-TRACE: claims=SAF-T1504-C007; sources=SRC-ghsa-meta-ads --> |
| SAF-T1504-C008 | CVE-2026-39974 reflected reachable response bodies through JSON-RPC before fixed version 2.47.4. | Demonstrated | SRC-cve-2026-39974, SRC-ghsa-n8n-mcp | No live token theft or production exploitation is documented. <!-- SAF-TRACE: claims=SAF-T1504-C008; sources=SRC-cve-2026-39974,SRC-ghsa-n8n-mcp --> |
| SAF-T1504-C009 | The n8n-MCP issue required specific multi-tenant HTTP conditions. | Demonstrated | SRC-ghsa-n8n-mcp | Other topology controls were not exhaustively evaluated. <!-- SAF-TRACE: claims=SAF-T1504-C009; sources=SRC-ghsa-n8n-mcp --> |
| SAF-T1504-C010 | No selected record states production exploitation, and neither selected CVE was in the dated CISA KEV snapshot. | Research-Derived | SRC-cve-2026-48039, SRC-cve-2026-39974, SRC-cisa-kev-token-response-2026-09-01 | This bounded corpus finding does not prove exploitation never occurred. <!-- SAF-TRACE: claims=SAF-T1504-C010; sources=SRC-cve-2026-48039,SRC-cve-2026-39974,SRC-cisa-kev-token-response-2026-09-01 --> |
| SAF-T1504-C011 | MCP authorization requires intended-audience validation and treats token theft as a security concern. | Research-Derived | SRC-mcp-authorization-2025-11-25 | Audience validation does not sanitize application responses. <!-- SAF-TRACE: claims=SAF-T1504-C011; sources=SRC-mcp-authorization-2025-11-25 --> |
| SAF-T1504-C012 | Token passthrough is a distinct anti-pattern; separate, narrow downstream authorization is preferred. | Research-Derived | SRC-mcp-security-2025-11-25 | Passthrough does not itself prove response disclosure. <!-- SAF-TRACE: claims=SAF-T1504-C012; sources=SRC-mcp-security-2025-11-25 --> |
| SAF-T1504-C013 | URL, redirect, address, and egress controls reduce SSRF-fed response disclosures. | Research-Derived | SRC-mcp-security-2025-11-25 | These controls do not cover non-SSRF error serialization. <!-- SAF-TRACE: claims=SAF-T1504-C013; sources=SRC-mcp-security-2025-11-25 --> |
| SAF-T1504-C014 | Authorization-aware response-secret correlation is a testable detection inference. | Research-Derived | SRC-mcp-tools-2025-11-25, SRC-rfc6750, SRC-elastic-esa-2026-24 | It depends on classifier and authorization telemetry. <!-- SAF-TRACE: claims=SAF-T1504-C014; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 --> |
| SAF-T1504-C015 | Token classifiers cannot assume a universal token size or syntax. | Research-Derived | SRC-rfc6750 | Issuer-specific formats can still be detected. <!-- SAF-TRACE: claims=SAF-T1504-C015; sources=SRC-rfc6750 --> |
| SAF-T1504-C016 | Response requires containment, revocation or rotation, and follow-on access investigation. | Research-Derived | SRC-ghsa-meta-ads, SRC-ghsa-n8n-mcp, SRC-elastic-esa-2026-24 | Issuer procedures and retained telemetry vary. <!-- SAF-TRACE: claims=SAF-T1504-C016; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-elastic-esa-2026-24 --> |
| SAF-T1504-C017 | ATT&CK T1528 behaviorally covers stealing application access tokens. | Research-Derived | SRC-mitre-t1528: [MITRE ATT&CK](https://attack.mitre.org/techniques/T1528/) | T1528 is not response-channel specific. <!-- SAF-TRACE: claims=SAF-T1504-C017; sources=SRC-mitre-t1528 --> |
| SAF-T1504-C018 | Elastic ESA-2026-24 is a non-agentic API-response historical analogy. | Research-Derived | SRC-elastic-esa-2026-24 | Kibana cannot set the MCP evidence status. <!-- SAF-TRACE: claims=SAF-T1504-C018; sources=SRC-elastic-esa-2026-24 --> |
| SAF-T1504-C019 | CVE-2026-27826 is enabling, not direct, under this response-boundary contract. | Research-Derived | SRC-cve-2026-27826, SRC-ghsa-mcp-atlassian-7r34 | A future complete reproduction could change classification. <!-- SAF-TRACE: claims=SAF-T1504-C019; sources=SRC-cve-2026-27826,SRC-ghsa-mcp-atlassian-7r34 --> |
| SAF-T1504-C020 | CVE-2026-25650 discloses an MCP Salesforce token but does not identify the disclosure channel. | Research-Derived | SRC-cve-2026-25650, SRC-ghsa-mcp-salesforce | It cannot establish response delivery. <!-- SAF-TRACE: claims=SAF-T1504-C020; sources=SRC-cve-2026-25650,SRC-ghsa-mcp-salesforce --> |
| SAF-T1504-C021 | CVE-2026-33461 is excluded from direct evidence because Kibana is not agentic or MCP. | Research-Derived | SRC-cve-2026-33461, SRC-elastic-esa-2026-24 | It remains a useful analogy. <!-- SAF-TRACE: claims=SAF-T1504-C021; sources=SRC-cve-2026-33461,SRC-elastic-esa-2026-24 --> |
| SAF-T1504-C022 | Severity rises with reachability, scope, lifetime, and replayability. | Research-Derived | SRC-ghsa-meta-ads, SRC-ghsa-n8n-mcp, SRC-rfc6750 | No universal severity score fits all tokens. <!-- SAF-TRACE: claims=SAF-T1504-C022; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-rfc6750 --> |
| SAF-T1504-C023 | Authentication enforcement and token-safe error serialization fix the Meta Ads path. | Demonstrated | SRC-ghsa-meta-ads | This does not cover every response leak. <!-- SAF-TRACE: claims=SAF-T1504-C023; sources=SRC-ghsa-meta-ads --> |
| SAF-T1504-C024 | Upgrade and bounded egress and tenant controls address the n8n-MCP path. | Demonstrated | SRC-ghsa-n8n-mcp | Workarounds do not prove all response leaks are blocked. <!-- SAF-TRACE: claims=SAF-T1504-C024; sources=SRC-ghsa-n8n-mcp --> |

### Current State

- **Affected Environments**: MCP HTTP deployments are exposed when result construction can reach server or upstream credentials and response authorization or redaction fails; the exact prerequisites are product-specific. <!-- SAF-TRACE: claims=SAF-T1504-C004,SAF-T1504-C005,SAF-T1504-C008,SAF-T1504-C009; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
- **Known Exploitation**: None identified in the reviewed authoritative corpus as of 2026-09-01; one controlled direct demonstration and one direct disclosed vulnerability were selected. <!-- SAF-TRACE: claims=SAF-T1504-C006,SAF-T1504-C008,SAF-T1504-C010; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-cve-2026-48039,SRC-cve-2026-39974,SRC-cisa-kev-token-response-2026-09-01 -->
- **Available Protections**: Authenticate callers, sanitize and validate results, keep tokens out of URLs and error objects, constrain upstream destinations and redirects, restrict egress, and minimize token scope and lifetime. <!-- SAF-TRACE: claims=SAF-T1504-C002,SAF-T1504-C011,SAF-T1504-C012,SAF-T1504-C013,SAF-T1504-C023,SAF-T1504-C024; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
- **Residual Risk**: Opaque or novel tokens can evade classification, application-specific serializers can introduce new response paths, and a token already delivered may remain usable until it expires or is revoked. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C015,SAF-T1504-C016; sources=SRC-rfc6750,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-elastic-esa-2026-24 -->

### Known Breaches and Vulnerabilities

No qualifying production breach was identified in the reviewed corpus; the following are the two highest-impact qualifying vulnerability examples and must not be described as breaches. <!-- SAF-TRACE: claims=SAF-T1504-C006,SAF-T1504-C008,SAF-T1504-C010; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-cve-2026-48039,SRC-cve-2026-39974,SRC-cisa-kev-token-response-2026-09-01 -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-48039 / GHSA-9gw6-46qc-99vr | Published 2026-08-07; Meta Ads MCP before 1.0.109 on reachable Streamable HTTP | An unauthenticated caller could receive the operator token and invoke tools; fixed in 1.0.109 by enforcing authentication and preventing token-bearing error serialization. | Direct vulnerability and direct controlled demonstration; reported by 232-323 and published by nictuku. | The proof used an inert token, production exploitation is not stated, and advisory affected-range wording contains a disclosed inconsistency. <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C006,SAF-T1504-C007,SAF-T1504-C023; sources=SRC-cve-2026-48039,SRC-ghsa-meta-ads --> |
| CVE-2026-39974 / GHSA-4ggg-h7ph-26qr | Published 2026-04-09; n8n-MCP through 2.47.3 in multi-tenant HTTP mode with a caller AUTH_TOKEN | A less-trusted caller could receive reflected internal or metadata response bodies; fixed in 2.47.4, with egress and tenant restrictions as interim controls. | Direct vulnerability selected from work credited to the Eresus Security Research Team and ibrahmsql. | No production exploitation or live-token theft is documented; single-tenant stdio and HTTP without multi-tenant headers are not affected. <!-- SAF-TRACE: claims=SAF-T1504-C008,SAF-T1504-C009,SAF-T1504-C024; sources=SRC-cve-2026-39974,SRC-ghsa-n8n-mcp --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | The recipient gains secret token material; realized access depends on audience, validity, scope, and downstream authorization. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C007,SAF-T1504-C022; sources=SRC-rfc6750,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp --> |
| Integrity | High | A replayable token may permit API actions within its permissions, as the Meta Ads advisory states for operator tool and Graph API access. <!-- SAF-TRACE: claims=SAF-T1504-C007,SAF-T1504-C022; sources=SRC-ghsa-meta-ads,SRC-rfc6750 --> |
| Availability | Low | Availability loss is not intrinsic; it depends on permitted follow-on API actions and quota consumption. <!-- SAF-TRACE: claims=SAF-T1504-C007,SAF-T1504-C022; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp --> |
| Scope | Multi-System | A reusable token can cross from the MCP deployment to the separate resource server for which it remains valid. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C007,SAF-T1504-C017; sources=SRC-rfc6750,SRC-ghsa-meta-ads,SRC-mitre-t1528 --> |

### Severity Conditions

- **Severity increases when**: The service is remotely reachable, caller authentication is absent or weak, tokens are long-lived or broadly scoped, and the recipient can replay them outside the MCP service. <!-- SAF-TRACE: claims=SAF-T1504-C007,SAF-T1504-C009,SAF-T1504-C022; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-rfc6750 -->
- **Severity decreases when**: The response is redacted or blocked, the recipient is authorized, the token is short-lived or narrowly scoped, or rapid revocation and sender constraint prevent replay. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C011,SAF-T1504-C014,SAF-T1504-C022; sources=SRC-rfc6750,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP response-security audit log | Tool result and tool execution error before client delivery | Timestamp, session and request IDs, caller and tenant, server, tool, result channel, secret classifications and count, authorization decision, redaction state | Store classifications or non-reversible fingerprints, not raw token values; correlate before result release. <!-- SAF-TRACE: claims=SAF-T1504-C001,SAF-T1504-C002,SAF-T1504-C014,SAF-T1504-C015; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 --> |
| Identity and downstream API logs | Token revocation and later API use | Issuer, client or application, audience, scopes, non-reversible token fingerprint, source address, action, revocation time | Use only where the issuer safely exposes these fields; token values must not enter logs. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C016,SAF-T1504-C017; sources=SRC-rfc6750,SRC-elastic-esa-2026-24,SRC-mitre-t1528 --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC is known; tokens can be opaque and product-specific, so use issuer or product identifiers only when independently validated. <!-- SAF-TRACE: claims=SAF-T1504-C015; sources=SRC-rfc6750 -->

### Behavioral Indicators

- A tool result or error has one or more classified token findings, is not redacted, and is addressed to a recipient whose authorization decision is false. <!-- SAF-TRACE: claims=SAF-T1504-C014; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->
- An unauthorized response is followed by use of the same non-reversible token fingerprint from a new client, application, address, or tenant. <!-- SAF-TRACE: claims=SAF-T1504-C016,SAF-T1504-C017; sources=SRC-elastic-esa-2026-24,SRC-mitre-t1528 -->
- Repeated calls intentionally produce upstream errors or select internal destinations immediately before response secret findings. <!-- SAF-TRACE: claims=SAF-T1504-C005,SAF-T1504-C008,SAF-T1504-C013; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-mcp-security-2025-11-25 -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify unredacted MCP results containing classifier-identified token material before release to an unauthorized response recipient. <!-- SAF-TRACE: claims=SAF-T1504-C014; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1504-C014,SAF-T1504-C015; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->
- **Detection Logic**: Require a tool result or error, a supported result channel, a token-classifier count of at least one, a recognized token class, a false recipient-authorization decision, and no true redaction flag. <!-- SAF-TRACE: claims=SAF-T1504-C014,SAF-T1504-C015; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->
- **Correlation Window**: Evaluate synchronously before release; correlate any later issuer use until token expiry or revocation when a safe fingerprint exists. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C014,SAF-T1504-C016; sources=SRC-rfc6750,SRC-elastic-esa-2026-24,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
- **Known False Positives**: Inert security tests, token-shaped documentation, and incorrect authorization decisions. <!-- SAF-TRACE: claims=SAF-T1504-C014,SAF-T1504-C015; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->
- **Known Limitations**: Novel opaque tokens, missing classifier coverage, missing recipient decisions, and results outside instrumented paths can evade the analytic. <!-- SAF-TRACE: claims=SAF-T1504-C014,SAF-T1504-C015; sources=SRC-rfc6750,SRC-mcp-tools-2025-11-25,SRC-elastic-esa-2026-24 -->
- **Tuning Guidance**: Maintain issuer-specific classifier patterns, authorize explicit test tenants, fail closed on positive findings, and investigate missing redaction state without logging raw tokens. <!-- SAF-TRACE: claims=SAF-T1504-C002,SAF-T1504-C014,SAF-T1504-C015; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->

### Validation

- **Test Data**: [cases.json](../../tests/SAF-T1504/cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1504/test_detection_rule.py)
- **Expected Result**: [Ten cases pass: four alerts and six non-alerts](../../research/techniques/SAF-T1504/validation/detection-test-output.txt)
- **Last Validated**: [2026-09-01](../../research/techniques/SAF-T1504/validation/detection-test-output.txt)
- **Feasibility Waiver**: None; deterministic representative cases are included. [Detection proof](../../research/techniques/SAF-T1504/validation/detection-test-output.txt)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Authenticate every exposed MCP request and reject unauthorized requests before tool execution; keep access tokens out of URI query strings and serialized error objects. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) [Meta Ads remediation](https://github.com/pipeboard-co/meta-ads-mcp/security/advisories/GHSA-9gw6-46qc-99vr) <!-- SAF-TRACE: claims=SAF-T1504-C011,SAF-T1504-C023; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-meta-ads -->
2. **[SAF-M-72: Data Loss Prevention on Tool Outputs](../../mitigations/SAF-M-72/README.md)**: Sanitize server outputs and validate tool results before giving them to the client or model; block delivery when secret findings remain. [MCP Tools security considerations](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#security-considerations) <!-- SAF-TRACE: claims=SAF-T1504-C002,SAF-T1504-C014; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->
3. When an upstream fetch is involved, validate full URLs and redirects, block private and link-local destinations, and constrain egress. [MCP SSRF guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices#server-side-request-forgery-ssrf) <!-- SAF-TRACE: claims=SAF-T1504-C013,SAF-T1504-C024; sources=SRC-mcp-security-2025-11-25,SRC-ghsa-n8n-mcp -->
4. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Issue short-lived, narrowly scoped, audience-bound tokens and avoid token passthrough so a disclosure has less reach. [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C011,SAF-T1504-C012,SAF-T1504-C022; sources=SRC-rfc6750,SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25 -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Inspect response-security events before delivery and alert when an unredacted token finding is addressed to an unauthorized recipient. <!-- SAF-TRACE: claims=SAF-T1504-C002,SAF-T1504-C014; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->
2. **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20/README.md)**: Correlate the safe fingerprint of an exposed token with later use from unexpected clients, addresses, or tenants when issuer telemetry permits. <!-- SAF-TRACE: claims=SAF-T1504-C016,SAF-T1504-C017; sources=SRC-elastic-esa-2026-24,SRC-mitre-t1528 -->

### Response Procedures

#### Immediate Actions

- Block the response path or disable the vulnerable tool, contain the caller session, and preserve metadata without retaining the raw token. <!-- SAF-TRACE: claims=SAF-T1504-C002,SAF-T1504-C016; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-elastic-esa-2026-24 -->
- **[SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37/README.md)**: Revoke or rotate the exposed token through its issuer and reduce related scopes until investigation is complete. <!-- SAF-TRACE: claims=SAF-T1504-C011,SAF-T1504-C016,SAF-T1504-C022; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-elastic-esa-2026-24 -->

#### Investigation Steps

- Determine the first response containing the token, every recipient and model context that received it, and whether copies entered downstream logs or traces. <!-- SAF-TRACE: claims=SAF-T1504-C001,SAF-T1504-C002,SAF-T1504-C016; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp,SRC-elastic-esa-2026-24 -->
- Review issuer and resource-server activity for the safe token fingerprint, unexpected client identity, source address, tenant, scope use, and actions after disclosure. <!-- SAF-TRACE: claims=SAF-T1504-C003,SAF-T1504-C016,SAF-T1504-C017; sources=SRC-rfc6750,SRC-elastic-esa-2026-24,SRC-mitre-t1528 -->

#### Remediation

- Upgrade the affected product or correct authentication, upstream destination validation, and token-safe serialization at the root response path. <!-- SAF-TRACE: claims=SAF-T1504-C023,SAF-T1504-C024; sources=SRC-ghsa-meta-ads,SRC-ghsa-n8n-mcp -->
- Add a regression case for the exact success or error channel and verify that redaction occurs before client or model delivery. <!-- SAF-TRACE: claims=SAF-T1504-C002,SAF-T1504-C014; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-elastic-esa-2026-24 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1307: Confused Deputy Attack](../SAF-T1307/README.md) | Prerequisite or alternative authority path | SAF-T1307 requires use of a deputy's distinct downstream authority; SAF-T1504 additionally requires a token to be delivered across the response boundary. SSRF without a distinct deputy authority remains outside the neighbor join. <!-- SAF-TRACE: claims=SAF-T1504-C013,SAF-T1504-C019; sources=SRC-mcp-security-2025-11-25,SRC-cve-2026-27826,SRC-ghsa-mcp-atlassian-7r34 --> |
| [SAF-T1304: Credential Relay Chain](../SAF-T1304/README.md) | Overlapping credential-boundary failure | SAF-T1304 sends an improperly accepted client credential downstream; SAF-T1504 returns a server-held or upstream token to an unauthorized recipient. <!-- SAF-TRACE: claims=SAF-T1504-C004,SAF-T1504-C012; sources=SRC-mcp-tools-2025-11-25,SRC-rfc6750,SRC-ghsa-meta-ads,SRC-mcp-security-2025-11-25 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Direct | Both behaviors obtain application access tokens for possible resource access; SAF-T1504 is narrower because the acquisition channel is an MCP or agentic API response. <!-- SAF-TRACE: claims=SAF-T1504-C017; sources=SRC-mitre-t1528 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [Model Context Protocol Specification - Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) - Model Context Protocol contributors, version 2025-11-25.
2. **SRC-mcp-authorization-2025-11-25**: [Model Context Protocol Specification - Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) - Model Context Protocol contributors, version 2025-11-25.
3. **SRC-mcp-security-2025-11-25**: [Model Context Protocol Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) - Model Context Protocol contributors, version 2025-11-25.
4. **SRC-rfc6750**: [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) - Michael B. Jones and Dick Hardt, October 2012.
5. **SRC-cve-2026-48039**: [CVE-2026-48039 record](https://cveawg.mitre.org/api/cve/CVE-2026-48039) - CVE Program and GitHub CNA, updated 2026-08-07.
6. **SRC-ghsa-meta-ads**: [GHSA-9gw6-46qc-99vr](https://github.com/pipeboard-co/meta-ads-mcp/security/advisories/GHSA-9gw6-46qc-99vr) - published by nictuku; 232-323 credited as reporter, 2026-05-20.
7. **SRC-cve-2026-39974**: [CVE-2026-39974 record](https://cveawg.mitre.org/api/cve/CVE-2026-39974) - CVE Program and GitHub CNA, updated 2026-04-13.
8. **SRC-ghsa-n8n-mcp**: [GHSA-4ggg-h7ph-26qr](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-4ggg-h7ph-26qr) - czlonkowski; reported by the Eresus Security Research Team and ibrahmsql, 2026-04-08.
9. **SRC-cisa-kev-token-response-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) - CISA Cybersecurity Division, snapshot reviewed 2026-09-01.
10. **SRC-elastic-esa-2026-24**: [Elastic ESA-2026-24](https://discuss.elastic.co/t/kibana-8-19-14-9-2-8-9-3-3-security-update-esa-2026-24/385812) - Paul (ismisepaul) and Elastic Product Security Team, 2026-04-08.
11. **SRC-cve-2026-33461**: [CVE-2026-33461 record](https://cveawg.mitre.org/api/cve/CVE-2026-33461) - CVE Program and Elastic Product Security Team, updated 2026-04-09.
12. **SRC-cve-2026-27826**: [CVE-2026-27826 record](https://cveawg.mitre.org/api/cve/CVE-2026-27826) - CVE Program and GitHub CNA, 2026-03-10.
13. **SRC-ghsa-mcp-atlassian-7r34**: [GHSA-7r34-79r5-rcc9](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-7r34-79r5-rcc9) - sooperset; yotampe-pluto and gil-maman-p credited as reporters, 2026-02-24.
14. **SRC-cve-2026-25650**: [CVE-2026-25650 record](https://cveawg.mitre.org/api/cve/CVE-2026-25650) - CVE Program and GitHub CNA, updated 2026-02-09.
15. **SRC-ghsa-mcp-salesforce**: [GHSA-vf6j-c56p-cq58](https://github.com/smn2gnt/MCP-Salesforce/security/advisories/GHSA-vf6j-c56p-cq58) - smn2gnt; nirhaas credited as reporter, 2026-02-06.
16. **SRC-mitre-t1528**: [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) - MITRE ATT&CK team and named contributors, version 1.5, modified 2026-05-12.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft, evidence packet, and tested detector | OpenAI Codex clean-room research agent /root/cleanroom_saf_t1504 |
