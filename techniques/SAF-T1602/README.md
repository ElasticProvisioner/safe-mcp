# SAF-T1602: Tool Enumeration

## Overview

- **Tactic**: Discovery (ATK-TA0007)
- **Technique ID**: SAF-T1602
- **Research Packet**: [research/techniques/SAF-T1602](../../research/techniques/SAF-T1602/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1602/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: Medium
- **Severity Rationale**: Enumeration reveals the authorized catalog's operational interfaces but does not itself invoke a tool; severity rises when a broad catalog exposes sensitive names, descriptions, or schemas. <!-- SAF-TRACE: claims=SAF-T1602-C003,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
- **First Observed**: No malicious production use was identified in the [reviewed direct-authority corpus](../../research/techniques/SAF-T1602/source-coverage.yml).
- **Last Updated**: 2026-09-02

## Scope

Tool Enumeration is an actor's use of `tools/list`, including pagination, to obtain the tool definitions an MCP server makes available to that requesting principal. The crossed boundary is the server's authorization- and policy-filtered tool catalog. [MCP Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C002,SAF-T1602-C003; sources=SRC-mcp-tools-2026-07-28 -->

### In Scope

- Sending `tools/list` and following `nextCursor` values to inventory the available catalog. <!-- SAF-TRACE: claims=SAF-T1602-C002; sources=SRC-mcp-tools-2026-07-28 -->
- Collecting returned names, descriptions, schemas, annotations, and related tool metadata to select a possible follow-on operation. <!-- SAF-TRACE: claims=SAF-T1602-C003,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

### Out of Scope

- `server/discover`, which returns server identity, supported versions, and capability categories rather than individual tool definitions. [Server Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1602-C005; sources=SRC-mcp-discovery-2026-07-28 -->
- `resources/list`, `resources/read`, `prompts/list`, and `prompts/get`, which inventory or retrieve context and prompt templates. [Resources specification](https://modelcontextprotocol.io/specification/2026-07-28/server/resources) [Prompts specification](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts) <!-- SAF-TRACE: claims=SAF-T1602-C006,SAF-T1602-C007; sources=SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
- Tool invocation, tool-definition manipulation, or exploitation of a discovered operation; `tools/call` is a separate request. <!-- SAF-TRACE: claims=SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

### Distinguishing Characteristics

The defining observable is a `tools/list` request and its returned tool-definition metadata. Capability discovery stops before individual definitions, resource enumeration centers on URI-addressed context, prompt enumeration centers on user-controlled templates, and execution begins only with a separate tool call. <!-- SAF-TRACE: claims=SAF-T1602-C002,SAF-T1602-C005,SAF-T1602-C006,SAF-T1602-C007,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-discovery-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

## Description

MCP servers declaring the `tools` capability must return the tools currently available to the requesting client. The result may vary with authorization on the request, so enumeration observes the catalog after the server's access policy has been applied. [MCP Tools capability requirements](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#capabilities) <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C008; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28 -->

The request can disclose names, descriptions, input and output schemas, and annotations. That metadata can reveal which operations are exposed and how later calls would be structured, but enumeration alone does not execute an operation or retrieve resource or prompt content. <!-- SAF-TRACE: claims=SAF-T1602-C003,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

The behavior is Demonstrated because the first-party MCP Inspector documents an end-to-end CLI method for listing a server's tools. This evidence establishes the operation, not malicious use or a production incident. [MCP Inspector quickstart](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector) <!-- SAF-TRACE: claims=SAF-T1602-C004,SAF-T1602-C016; sources=SRC-mcp-inspector-2026,SRC-mcp-tools-2026-07-28 -->

## Attack Vectors

- **Primary Vector**: An actor able to send MCP requests issues `tools/list` to a reachable server. <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C002; sources=SRC-mcp-tools-2026-07-28 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1602-C002; sources=SRC-mcp-tools-2026-07-28 -->
  - Pagination retrieves later catalog pages when the first response includes `nextCursor`. <!-- SAF-TRACE: claims=SAF-T1602-C002; sources=SRC-mcp-tools-2026-07-28 -->
  - A compromised valid principal enumerates only the set exposed to its authorization unless server policy is overbroad or incorrectly enforced. <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C008,SAF-T1602-C009; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->
- **Affected Components**: MCP client, MCP server catalog, authorization layer, and JSON-RPC observability pipeline. <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C008,SAF-T1602-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0 -->
- **Trust Boundary Crossed**: The requesting principal receives the server's authorization-filtered tool interface metadata. <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C003; sources=SRC-mcp-tools-2026-07-28 -->

## Technical Details

### Prerequisites

- The actor can reach an MCP endpoint and send a conforming JSON-RPC request. <!-- SAF-TRACE: claims=SAF-T1602-C002,SAF-T1602-C010; sources=SRC-mcp-tools-2026-07-28,SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0 -->
- When HTTP authorization is used, the request carries a token accepted for that server; authorization is optional in MCP and differs for stdio. <!-- SAF-TRACE: claims=SAF-T1602-C008; sources=SRC-mcp-authorization-2026-07-28 -->
- The server declares tools and exposes at least one definition to the request's authorization context. <!-- SAF-TRACE: claims=SAF-T1602-C001; sources=SRC-mcp-tools-2026-07-28 -->

### Attack Flow

1. **Reconnaissance or Setup**: The actor identifies a reachable MCP server or learns from `server/discover` that it supports tools. <!-- SAF-TRACE: claims=SAF-T1602-C005; sources=SRC-mcp-discovery-2026-07-28 -->
2. **Delivery**: The actor sends a JSON-RPC `tools/list` request with the required request metadata and, when applicable, authorization. <!-- SAF-TRACE: claims=SAF-T1602-C002,SAF-T1602-C008,SAF-T1602-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0 -->
3. **Trigger or Execution**: The server resolves the catalog available to the requesting principal and returns tool definitions. <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C003; sources=SRC-mcp-tools-2026-07-28 -->
4. **Boundary Crossing**: The response crosses the catalog boundary with names, descriptions, schemas, and optional annotations. <!-- SAF-TRACE: claims=SAF-T1602-C003; sources=SRC-mcp-tools-2026-07-28 -->
5. **Objective**: The actor inventories possible operations and their interfaces without invoking them. <!-- SAF-TRACE: claims=SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
6. **Follow-On Activity**: Any later tool call or exploitation is a separate behavior and must be analyzed independently. <!-- SAF-TRACE: claims=SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

### Example Scenario

A synthetic client at `client.example` lists an inert weather server's tool catalog; the example stops at the metadata response and performs no tool call. <!-- SAF-TRACE: claims=SAF-T1602-C002,SAF-T1602-C003,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

```json
{
  "request": {"jsonrpc": "2.0", "id": "inventory-1", "method": "tools/list", "params": {"cursor": null}},
  "response_summary": {"tools": [{"name": "weather.lookup", "inputSchema": {"type": "object"}}]}
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1602-C001 | Tool catalogs are returned for the requesting client and may vary by authorization. | Demonstrated | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Does not identify intent. |
| SAF-T1602-C002 | `tools/list` is paginated JSON-RPC and returns tool records. | Demonstrated | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Does not prescribe logging fields. |
| SAF-T1602-C003 | Tool definitions expose interface metadata. | Demonstrated | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Optional fields vary. |
| SAF-T1602-C004 | MCP Inspector implements a tool-listing CLI workflow. | Demonstrated | SRC-mcp-inspector-2026: [MCP Inspector](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector) | Controlled workflow, not a malicious incident. |
| SAF-T1602-C005 | Server discovery returns capabilities, not tool definitions. | Demonstrated | SRC-mcp-discovery-2026-07-28: [Server Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) | Instructions can contain other text. |
| SAF-T1602-C006 | Resource operations inventory URI-addressed context. | Demonstrated | SRC-mcp-resources-2026: [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources) | Tools may return resource links. |
| SAF-T1602-C007 | Prompt operations inventory user-controlled templates. | Demonstrated | SRC-mcp-prompts-2026: [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts) | Interface presentation is implementation-specific. |
| SAF-T1602-C008 | HTTP authorization is per request and invalid tokens must be rejected. | Demonstrated | SRC-mcp-authorization-2026-07-28: [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Does not apply to stdio. |
| SAF-T1602-C009 | Least privilege and catalog filtering constrain enumeration. | Research-Derived | SRC-mcp-authorization-2026-07-28; SRC-mcp-security-2026-07-28; SRC-mcp-tools-2026-07-28 | Scope policy is implementation-specific. |
| SAF-T1602-C010 | JSON-RPC and OpenTelemetry expose correlation fields for telemetry. | Demonstrated | SRC-jsonrpc-2.0; SRC-opentelemetry-jsonrpc-1.44.0 | Method capture is opt-in; authorization context is not standardized. |
| SAF-T1602-C011 | A list event alone is ambiguous because legitimate clients list tools. | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-mcp-inspector-2026 | Requires local behavioral context. |
| SAF-T1602-C012 | Authorization and burst-pagination correlation is testable local logic. | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-opentelemetry-jsonrpc-1.44.0 | Threshold is proposed and tunable. |
| SAF-T1602-C013 | Listing exposes metadata but does not itself invoke or read content. | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-mcp-resources-2026; SRC-mcp-prompts-2026 | Metadata can still be sensitive. |
| SAF-T1602-C014 | ATT&CK T1046 is analogous, not direct. | Research-Derived | SRC-mitre-attack-t1046-v3.2; SRC-mcp-tools-2026-07-28 | Different discovery layer. |
| SAF-T1602-C015 | Response should verify identity, preserve correlated records, and reduce catalog exposure. | Research-Derived | SRC-mcp-authorization-2026-07-28; SRC-mcp-tools-2026-07-28; SRC-jsonrpc-2.0 | Operational details vary. |
| SAF-T1602-C016 | Public evidence demonstrates listing but not malicious production use. | Demonstrated | SRC-mcp-inspector-2026; SRC-mcp-tools-2026-07-28 | Corpus-bounded conclusion. |

### Current State

- **Affected Environments**: Any MCP server that declares tools can answer `tools/list`; the visible set can be authorization-dependent. <!-- SAF-TRACE: claims=SAF-T1602-C001; sources=SRC-mcp-tools-2026-07-28 -->
- **Known Exploitation**: The complete operation is publicly demonstrated by MCP Inspector, but no malicious production use was identified in the [reviewed corpus](../../research/techniques/SAF-T1602/source-coverage.yml).
- **Available Protections**: Per-request authorization, least-privilege scopes, catalog filtering, and tool-usage audit records can constrain or expose enumeration. <!-- SAF-TRACE: claims=SAF-T1602-C008,SAF-T1602-C009,SAF-T1602-C011; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026 -->
- **Residual Risk**: Legitimate clients also list tools, so intent cannot be established from the method alone. <!-- SAF-TRACE: claims=SAF-T1602-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| No qualifying direct example in the reviewed corpus | Reviewed 2026-09-02 across current MCP authority pages, CVE records, maintainer advisories, and CISA exploitation assessments | No direct remediation claim; preserve the evidence gap and enforce ordinary authorization and audit controls | The [coverage audit](../../research/techniques/SAF-T1602/source-coverage.yml) classifies three high-impact MCP vulnerability families as adjacent or rejected, not Tool Enumeration | The conclusion is bounded to the direct-authority corpus and date. |

### Real-World Incidents or Demonstrations

#### MCP Inspector controlled listing (2026-07-28 documentation)

The MCP project documents a CLI invocation that lists a server's tools and exits. It demonstrates the end-to-end enumeration operation in a controlled developer context; it does not establish adversarial use. [MCP Inspector](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector) <!-- SAF-TRACE: claims=SAF-T1602-C004,SAF-T1602-C016; sources=SRC-mcp-inspector-2026,SRC-mcp-tools-2026-07-28 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Low | The operation returns authorized interface metadata; sensitivity rises when names, descriptions, or schemas expose operational detail. <!-- SAF-TRACE: claims=SAF-T1602-C003,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 --> |
| Integrity | None | `tools/list` does not itself invoke a tool or modify server state. <!-- SAF-TRACE: claims=SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 --> |
| Availability | None | Enumeration alone is a listing operation; availability effects from abusive volume require separate rate or resource-exhaustion analysis. <!-- SAF-TRACE: claims=SAF-T1602-C002,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 --> |
| Scope | Local | The response covers one server's catalog as filtered for one request authorization; aggregation across servers requires additional access. <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C003; sources=SRC-mcp-tools-2026-07-28 --> |

### Severity Conditions

- **Severity increases when**: The requester has broad scopes or the catalog includes sensitive operational vocabulary and rich schemas. <!-- SAF-TRACE: claims=SAF-T1602-C003,SAF-T1602-C009; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->
- **Severity decreases when**: The server returns only authorization-filtered, least-privilege tool definitions and audits requests. <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C009,SAF-T1602-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28,SRC-mcp-inspector-2026 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host, server, or proxy audit | JSON-RPC request and response | timestamp, `rpc.method`, request ID, actor/client identity, target server, authorization decision, cursor, returned tool count | Preserve request/response correlation and record `tools/list` explicitly rather than `_OTHER`. <!-- SAF-TRACE: claims=SAF-T1602-C010,SAF-T1602-C011,SAF-T1602-C012; sources=SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0,SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026 --> |
| Authorization and policy decision log | Token validation, scope check, and catalog filtering | principal, audience, scopes, server, decision, policy version, correlation ID | Actor, authorization, cursor, and result-count fields are local extensions beyond generic JSON-RPC telemetry. <!-- SAF-TRACE: claims=SAF-T1602-C008,SAF-T1602-C009,SAF-T1602-C010; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0 --> |

### Indicators of Compromise (IoCs)

- No durable artifact is inherent to `tools/list`; treat it as behavior and policy context, not a standalone IoC. <!-- SAF-TRACE: claims=SAF-T1602-C011,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

### Behavioral Indicators

- `tools/list` from a principal not authorized or expected to inventory the target server. <!-- SAF-TRACE: claims=SAF-T1602-C008,SAF-T1602-C012; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-opentelemetry-jsonrpc-1.44.0 -->
- Three or more cursor-bearing list pages from the same actor and server within sixty seconds, after excluding approved inventory jobs. <!-- SAF-TRACE: claims=SAF-T1602-C012; sources=SRC-mcp-tools-2026-07-28,SRC-opentelemetry-jsonrpc-1.44.0 -->
- Enumeration followed by a separate `tools/call` can increase investigative priority, but the invocation is not part of this technique. <!-- SAF-TRACE: claims=SAF-T1602-C002,SAF-T1602-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify tool listing by an unauthorized principal or burst pagination that exceeds a local inventory baseline. <!-- SAF-TRACE: claims=SAF-T1602-C012; sources=SRC-mcp-tools-2026-07-28,SRC-opentelemetry-jsonrpc-1.44.0 -->
- **Rule Status**: Experimental because the protocol does not label adversarial intent and generic telemetry omits some required context. <!-- SAF-TRACE: claims=SAF-T1602-C010,SAF-T1602-C011; sources=SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0,SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026 -->
- **Detection Logic**: Match `tools/list`, then alert if authorization is denied/unapproved or if one actor and server produce at least three cursor-bearing pages within sixty seconds. <!-- SAF-TRACE: claims=SAF-T1602-C012; sources=SRC-mcp-tools-2026-07-28,SRC-opentelemetry-jsonrpc-1.44.0 -->
- **Correlation Window**: Sixty seconds for the burst branch. <!-- SAF-TRACE: claims=SAF-T1602-C012; sources=SRC-mcp-tools-2026-07-28,SRC-opentelemetry-jsonrpc-1.44.0 -->
- **Known False Positives**: Approved inventory, administration, testing, and client cache refreshes can legitimately list tools. <!-- SAF-TRACE: claims=SAF-T1602-C004,SAF-T1602-C011,SAF-T1602-C012; sources=SRC-mcp-inspector-2026,SRC-mcp-tools-2026-07-28,SRC-opentelemetry-jsonrpc-1.44.0 -->
- **Known Limitations**: Missing actor, authorization, method, cursor, or server fields prevents reliable correlation; a single approved request is intentionally not alerted. <!-- SAF-TRACE: claims=SAF-T1602-C010,SAF-T1602-C011,SAF-T1602-C012; sources=SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0,SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026 -->
- **Tuning Guidance**: Maintain server-specific inventory allowlists and replace the three-page threshold with a measured local baseline where available. <!-- SAF-TRACE: claims=SAF-T1602-C011,SAF-T1602-C012; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026,SRC-opentelemetry-jsonrpc-1.44.0 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Nine cases cover positive, negative, threshold boundary, malformed-field, and legitimate-lookalike behavior. [Recorded results](../../research/techniques/SAF-T1602/validation/detection-test.txt) [Strict validation](../../research/techniques/SAF-T1602/validation/strict-validator.txt)
- **Last Validated**: 2026-09-02. [Quality review](../../research/techniques/SAF-T1602/quality-review.yml)
- **Feasibility Waiver**: None. [Technique contract](../../research/techniques/SAF-T1602/technique-contract.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13.md)**: Validate token audience and validity before returning a catalog; reject invalid tokens. [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) <!-- SAF-TRACE: claims=SAF-T1602-C008,SAF-T1602-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-jsonrpc-2.0 -->
2. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29.md)**: Return only tools permitted by the authorization presented on the request. <!-- SAF-TRACE: claims=SAF-T1602-C001,SAF-T1602-C009; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->
3. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16.md)**: Start with baseline scopes and elevate only for the current operation; avoid publishing an entire scope catalog. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#scope-minimization) <!-- SAF-TRACE: claims=SAF-T1602-C009; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28,SRC-mcp-tools-2026-07-28 -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12.md)**: Record the JSON-RPC method and request ID together with actor, server, authorization decision, cursor, and result count. <!-- SAF-TRACE: claims=SAF-T1602-C010,SAF-T1602-C011; sources=SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0,SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026 -->
2. **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20.md)**: Allowlist approved inventory jobs and alert on denied principals or unusual pagination bursts. <!-- SAF-TRACE: claims=SAF-T1602-C011,SAF-T1602-C012; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026,SRC-opentelemetry-jsonrpc-1.44.0 -->

### Response Procedures

#### Immediate Actions

- Verify the principal, target server, token audience, scopes, and authorization decision; block access and apply **[SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37.md)** when local evidence shows it is unauthorized. <!-- SAF-TRACE: claims=SAF-T1602-C008,SAF-T1602-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-jsonrpc-2.0 -->
- Preserve correlated list requests and responses before changing catalog or access policy. <!-- SAF-TRACE: claims=SAF-T1602-C010,SAF-T1602-C015; sources=SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0,SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28 -->

#### Investigation Steps

- Reconstruct pages by actor, server, request ID, cursor, time, authorization decision, and returned tool count. <!-- SAF-TRACE: claims=SAF-T1602-C010,SAF-T1602-C012,SAF-T1602-C015; sources=SRC-jsonrpc-2.0,SRC-opentelemetry-jsonrpc-1.44.0,SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28 -->
- Determine whether a later `tools/call` or another technique followed enumeration, without conflating that activity with the listing itself. <!-- SAF-TRACE: claims=SAF-T1602-C013,SAF-T1602-C015; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026,SRC-mcp-authorization-2026-07-28,SRC-jsonrpc-2.0 -->

#### Remediation

- Correct authorization or catalog-filtering policy and reduce broad scopes before restoring access. <!-- SAF-TRACE: claims=SAF-T1602-C009,SAF-T1602-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-jsonrpc-2.0 -->
- Add a regression case for the affected principal, server, and catalog policy and retune the pagination baseline if the alert was a legitimate lookalike. <!-- SAF-TRACE: claims=SAF-T1602-C011,SAF-T1602-C012; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-inspector-2026,SRC-opentelemetry-jsonrpc-1.44.0 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1601: MCP Server Enumeration](../SAF-T1601/README.md) | Prerequisite or alternative | Returns configured or reachable server identity and capability metadata, not individual tool definitions. <!-- SAF-TRACE: claims=SAF-T1602-C005; sources=SRC-mcp-discovery-2026-07-28 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Analogous | Both inventory exposed functionality for later selection, but T1046 concerns services on hosts or network infrastructure while this technique reads an MCP application-protocol catalog. <!-- SAF-TRACE: claims=SAF-T1602-C014; sources=SRC-mitre-attack-t1046-v3.2,SRC-mcp-tools-2026-07-28 --> |

## References

1. **SRC-mcp-tools-2026-07-28**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — Model Context Protocol contributors; capabilities, listing, tool metadata, and security considerations.
2. **SRC-mcp-inspector-2026**: [MCP Inspector](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector) — Model Context Protocol documentation team; controlled CLI listing workflow.
3. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — Model Context Protocol contributors; per-request authorization and scope handling.
4. **SRC-mcp-security-2026-07-28**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) — Model Context Protocol security contributors; scope minimization and audit guidance.
5. **SRC-mcp-discovery-2026-07-28**: [MCP Server Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) — Model Context Protocol contributors; identity, version, and capability discovery.
6. **SRC-mcp-resources-2026**: [MCP Resources specification](https://modelcontextprotocol.io/specification/2026-07-28/server/resources) — Model Context Protocol contributors; resource listing and reading.
7. **SRC-mcp-prompts-2026**: [MCP Prompts specification](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts) — Model Context Protocol contributors; prompt listing and retrieval.
8. **SRC-jsonrpc-2.0**: [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification) — JSON-RPC Working Group; request, method, identifier, and response correlation.
9. **SRC-opentelemetry-jsonrpc-1.44.0**: [OpenTelemetry JSON-RPC semantic conventions](https://opentelemetry.io/docs/specs/semconv/rpc/json-rpc/) — OpenTelemetry Semantic Conventions maintainers; JSON-RPC span attributes and limitations.
10. **SRC-mitre-attack-t1046-v3.2**: [MITRE ATT&CK T1046, Network Service Discovery](https://attack.mitre.org/techniques/T1046/) — MITRE ATT&CK team; contributors Aaron Sullivan (ZerkerEOD) and Praetorian; version 3.2.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial clean-room technique, research packet, tested analytic, and framework fragments | OpenAI Codex clean-room research agent |
