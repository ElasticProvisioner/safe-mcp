# SAF-T1005: Exposed Endpoint Exploit

## Overview

- **Tactic**: Initial Access (ATK-TA0001)
- **Technique ID**: SAF-T1005
- **Research Packet**: [research/techniques/SAF-T1005](../../research/techniques/SAF-T1005/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1005/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Reachable endpoints can expose every enabled capability with the server's own downstream privileges; impact is bounded by endpoint reachability, enabled operations, and the privileges of server-side credentials. <!-- SAF-TRACE: claims=SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r -->
- **First Observed**: No qualifying production compromise was identified in the reviewed corpus as of 2026-09-01; controlled demonstrations and disclosed vulnerabilities establish the behavior. <!-- SAF-TRACE: claims=SAF-T1005-C004,SAF-T1005-C010; sources=SRC-oligo-inspector-cve-2025-49596,SRC-ghsa-mcp-pinot-73cv,SRC-horizon3-litellm-chain -->
- **Last Updated**: 2026-09-01

## Scope

Exposed Endpoint Exploit covers an untrusted network client or browser origin reaching an MCP endpoint, proxy, or management endpoint whose exposure and missing or bypassed access controls permit an unauthorized capability invocation. The crossed boundary is the untrusted network or web origin into a server that can act on local processes, tools, resources, or downstream services. <!-- SAF-TRACE: claims=SAF-T1005-C001,SAF-T1005-C003; sources=SRC-mcp-streamable-http-2026-07-28,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r -->

### In Scope

- Internet- or network-reachable MCP HTTP interfaces that accept sensitive operations without effective authentication or authorization. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C006; sources=SRC-ghsa-mcp-pinot-73cv,SRC-mcp-authorization-2026-07-28 -->
- Browser-reachable local listeners exposed through missing Origin validation, DNS rebinding protection, or equivalent host controls. <!-- SAF-TRACE: claims=SAF-T1005-C001,SAF-T1005-C004,SAF-T1005-C007; sources=SRC-mcp-streamable-http-2026-07-28,SRC-oligo-inspector-cve-2025-49596,SRC-ghsa-go-sdk-xw59 -->
- Support, inspection, or test endpoints that can invoke tools or spawn backend processes after a missing or bypassed access decision. <!-- SAF-TRACE: claims=SAF-T1005-C005,SAF-T1005-C008,SAF-T1005-C009; sources=SRC-ghsa-inspector-7f8r,SRC-ghsa-litellm-v4p8,SRC-horizon3-litellm-chain -->

### Out of Scope

- Impersonating or name-colliding with a trusted server; that changes server identity rather than exploiting endpoint exposure. See the [scope contract](../../research/techniques/SAF-T1005/technique-contract.yml).
- Phishing a user through an OAuth authorization flow; that abuses user authorization rather than direct endpoint reachability. See the [scope contract](../../research/techniques/SAF-T1005/technique-contract.yml).
- Injecting commands into the arguments of a tool already reached through an authorized session; that is unsafe input handling after access. See the [scope contract](../../research/techniques/SAF-T1005/technique-contract.yml).
- Downstream persistence, privilege escalation, collection, or exfiltration after the initial unauthorized invocation. See the [scope contract](../../research/techniques/SAF-T1005/technique-contract.yml).

### Distinguishing Characteristics

The defining observable is a sensitive MCP or support operation accepted from an untrusted source despite missing, invalid, or bypassed access-control context. A merely reachable health endpoint, an intentionally public read-only capability, or malicious arguments supplied after valid authorization is not sufficient on its own. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-owasp-logging-cheat-sheet -->

## Description

Streamable HTTP exposes a single MCP endpoint and sends every request as an HTTP POST. The current protocol requires Origin validation, recommends localhost-only binding for local servers, and recommends authentication for all connections because missing protections can let remote websites interact with local servers. <!-- SAF-TRACE: claims=SAF-T1005-C001; sources=SRC-mcp-streamable-http-2026-07-28 -->

The technique occurs when deployment exposure and an absent or bypassed access decision combine so an untrusted caller reaches a sensitive operation. The immediate objective is unauthorized initial access to an MCP capability or privileged backend action, not the later impact performed with that access. <!-- SAF-TRACE: claims=SAF-T1005-C003; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r,SRC-horizon3-litellm-chain -->

Public disclosures demonstrate several realizations: a browser reaching an unauthenticated local inspection proxy, an all-interface database MCP server exposing every tool, an SDK omitting DNS-rebinding protection by default, and a test endpoint that starts a supplied local process under insufficient authorization. <!-- SAF-TRACE: claims=SAF-T1005-C004,SAF-T1005-C006,SAF-T1005-C007,SAF-T1005-C008; sources=SRC-oligo-inspector-cve-2025-49596,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-go-sdk-xw59,SRC-ghsa-litellm-v4p8 -->

## Attack Vectors

- **Primary Vector**: Direct HTTP reachability to a sensitive MCP endpoint with missing or ineffective authentication or authorization. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C006; sources=SRC-ghsa-mcp-pinot-73cv,SRC-mcp-authorization-2026-07-28 -->
- **Secondary Vectors**:
  - A malicious website reaches a local listener through absent Origin or DNS-rebinding protection. <!-- SAF-TRACE: claims=SAF-T1005-C001,SAF-T1005-C007; sources=SRC-mcp-streamable-http-2026-07-28,SRC-ghsa-go-sdk-xw59 -->
  - A support or test route exposes privileged backend behavior to a low-privilege or unauthenticated caller. <!-- SAF-TRACE: claims=SAF-T1005-C008,SAF-T1005-C009; sources=SRC-ghsa-litellm-v4p8,SRC-horizon3-litellm-chain -->
- **Affected Components**: Streamable HTTP endpoints, legacy SSE endpoints, local inspection proxies, test or management routes, tool and resource handlers, edge gateways, and authentication middleware. <!-- SAF-TRACE: claims=SAF-T1005-C001,SAF-T1005-C005,SAF-T1005-C008; sources=SRC-mcp-streamable-http-2026-07-28,SRC-ghsa-inspector-7f8r,SRC-ghsa-litellm-v4p8 -->
- **Trust Boundary Crossed**: Untrusted network client or browser origin to a server-side capability and any downstream authority the server holds. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r -->

## Technical Details

### Prerequisites

- The adversary can route a request to an MCP, proxy, support, or test endpoint, directly or from a browser. <!-- SAF-TRACE: claims=SAF-T1005-C001,SAF-T1005-C004; sources=SRC-mcp-streamable-http-2026-07-28,SRC-oligo-inspector-cve-2025-49596 -->
- Authentication, authorization, Origin validation, or host validation is absent, disabled, or bypassable for the targeted operation. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C006,SAF-T1005-C007,SAF-T1005-C009; sources=SRC-mcp-authorization-2026-07-28,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-go-sdk-xw59,SRC-horizon3-litellm-chain -->
- The endpoint exposes an operation whose result is material, such as a tool call, resource read, configuration mutation, or backend process start. <!-- SAF-TRACE: claims=SAF-T1005-C005,SAF-T1005-C006,SAF-T1005-C008; sources=SRC-ghsa-inspector-7f8r,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-litellm-v4p8 -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies a reachable MCP or companion endpoint, or prepares a website able to reach a local listener. <!-- SAF-TRACE: claims=SAF-T1005-C004,SAF-T1005-C006; sources=SRC-oligo-inspector-cve-2025-49596,SRC-ghsa-mcp-pinot-73cv -->
2. **Delivery**: An HTTP request crosses from an untrusted network zone or browser origin to that endpoint. <!-- SAF-TRACE: claims=SAF-T1005-C001; sources=SRC-mcp-streamable-http-2026-07-28 -->
3. **Trigger or Execution**: The request names a sensitive method such as a tool call or resource read, or reaches a support route that starts a backend action. <!-- SAF-TRACE: claims=SAF-T1005-C002,SAF-T1005-C008; sources=SRC-mcp-streamable-http-2026-07-28,SRC-ghsa-litellm-v4p8 -->
4. **Boundary Crossing**: The server accepts the operation even though access-control or origin context is missing, invalid, or bypassed. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C009; sources=SRC-mcp-authorization-2026-07-28,SRC-horizon3-litellm-chain -->
5. **Objective**: The adversary gains unauthorized use of an MCP capability or privileged backend behavior. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r -->
6. **Follow-On Activity**: Any subsequent data access, state change, process execution, or service disruption depends on the exposed operation and server privileges. <!-- SAF-TRACE: claims=SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r -->

### Example Scenario

An internet-facing server accepts a request with no valid authentication and then records a successful sensitive tool invocation under the same correlation identifier. The following synthetic events are inert and illustrate the minimum correlation fields, not an exploit payload. <!-- SAF-TRACE: claims=SAF-T1005-C011,SAF-T1005-C012; sources=SRC-otel-http-spans-1.44.0,SRC-mitre-attack-t1190-v2.8 -->

```json
[
  {
    "correlation_id": "demo-001",
    "source_zone": "internet",
    "endpoint": "/mcp",
    "http_status": 200,
    "auth_result": "missing",
    "action_class": "endpoint_access"
  },
  {
    "correlation_id": "demo-001",
    "rpc_method": "tools/call",
    "action_class": "tool_invoke",
    "outcome": "success"
  }
]
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1005-C001 | Current Streamable HTTP endpoint and security requirements | Demonstrated | SRC-mcp-streamable-http-2026-07-28: [Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) | Normative guidance does not establish deployment compliance. |
| SAF-T1005-C002 | Current request metadata exposes method and operation names to HTTP intermediaries | Demonstrated | SRC-mcp-streamable-http-2026-07-28: [Request Metadata](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#request-metadata) | Older protocol revisions may not emit these headers. |
| SAF-T1005-C003 | Missing or bypassed endpoint controls can yield unauthorized capability access | Demonstrated | SRC-ghsa-mcp-pinot-73cv: [MCP-Pinot advisory](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6) | Outcome depends on exposed tools and downstream privileges. |
| SAF-T1005-C004 | A browser-to-local-proxy exploit path was publicly demonstrated | Demonstrated | SRC-oligo-inspector-cve-2025-49596: [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) | Controlled research, not a documented production compromise. |
| SAF-T1005-C005 | MCP Inspector before 0.14.1 lacked client-to-proxy authentication | Demonstrated | SRC-ghsa-inspector-7f8r: [GHSA-7f8r-222p-6f5g](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g) | Specific to affected Inspector versions and launch context. |
| SAF-T1005-C006 | MCP-Pinot through 3.0.1 exposed tools on all interfaces without authentication by default | Demonstrated | SRC-ghsa-mcp-pinot-73cv: [GHSA-73cv-556c-w3g6](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6) | Advisory and proof of concept do not establish production abuse. |
| SAF-T1005-C007 | Go SDK before 1.4.0 omitted default DNS-rebinding protection for localhost HTTP handlers | Demonstrated | SRC-ghsa-go-sdk-xw59: [GHSA-xw59-hvm2-8pj6](https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-xw59-hvm2-8pj6) | Applies to affected SDK deployments using HTTP without authentication. |
| SAF-T1005-C008 | LiteLLM MCP test endpoints permitted low-privilege process spawning before 1.83.7 | Demonstrated | SRC-ghsa-litellm-v4p8: [GHSA-v4p8-mg3p-g94g](https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g) | The direct advisory requires a low-privilege API key. |
| SAF-T1005-C009 | A path-based authorization bypass was chained with the LiteLLM endpoint for unauthenticated code execution | Demonstrated | SRC-horizon3-litellm-chain: [Horizon3.ai research](https://horizon3.ai/attack-research/vulnerabilities/cve-2026-42271-chained-with-cve-2026-48710/) | Controlled validation, not confirmed production exploitation. |
| SAF-T1005-C010 | Reviewed direct sources describe vulnerabilities and demonstrations, not qualifying production compromises | Research-Derived | SRC-ghsa-mcp-pinot-73cv and SRC-horizon3-litellm-chain | This is a bounded corpus finding, not proof of global absence. |
| SAF-T1005-C011 | HTTP telemetry can capture client, server, route, method, path, and status fields | Research-Derived | SRC-otel-http-spans-1.44.0: [HTTP semantic conventions](https://opentelemetry.io/docs/specs/semconv/http/http-spans/) | Authentication and MCP method fields need application enrichment. |
| SAF-T1005-C012 | Correlating anomalous public-endpoint requests with child-process or sensitive server behavior raises confidence | Research-Derived | SRC-mitre-attack-t1190-v2.8: [ATT&CK T1190](https://attack.mitre.org/techniques/T1190/) | The analytic is behavioral and not MCP-exclusive. |
| SAF-T1005-C013 | Authentication, authorization, unexpected-method, and high-risk-function events are priority security logs | Research-Derived | SRC-owasp-logging-cheat-sheet: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Logging recommendations do not guarantee product support. |
| SAF-T1005-C014 | Origin validation, loopback binding, authentication, least privilege, and patched versions constrain the mechanism | Demonstrated | SRC-mcp-streamable-http-2026-07-28 and selected advisories | No single control covers every exposure variant. |
| SAF-T1005-C015 | Impact is conditional on enabled operations and server-side authority | Demonstrated | SRC-ghsa-mcp-pinot-73cv and SRC-ghsa-inspector-7f8r | Product-specific examples do not define every deployment's blast radius. |
| SAF-T1005-C016 | Public-facing endpoint exploitation aligns with ATT&CK T1190; local browser reach is only analogous | Research-Derived | SRC-mitre-attack-t1190-v2.8: [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | T1190 does not specifically model MCP or localhost browser access. |
| SAF-T1005-C017 | Intentionally public capabilities and benign scanners can resemble missing-auth exposure | Research-Derived | SRC-mcp-authorization-2026-07-28 and SRC-owasp-logging-cheat-sheet | Requires local inventory and policy to distinguish intent. |

### Current State

- **Affected Environments**: Network-exposed MCP servers, browser-reachable local listeners, and companion test or inspection routes are affected when sensitive operations lack effective access controls. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C005,SAF-T1005-C006,SAF-T1005-C007,SAF-T1005-C008; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r,SRC-ghsa-go-sdk-xw59,SRC-ghsa-litellm-v4p8 -->
- **Known Exploitation**: Controlled demonstrations and proof-of-concept disclosures establish the behavior; no qualifying production compromise was identified in the reviewed corpus. <!-- SAF-TRACE: claims=SAF-T1005-C004,SAF-T1005-C009,SAF-T1005-C010; sources=SRC-oligo-inspector-cve-2025-49596,SRC-horizon3-litellm-chain,SRC-ghsa-mcp-pinot-73cv -->
- **Available Protections**: Apply current protocol Origin and authentication guidance and upgrade affected MCP-Pinot, Inspector, Go SDK, LiteLLM, and Starlette versions. <!-- SAF-TRACE: claims=SAF-T1005-C014; sources=SRC-mcp-streamable-http-2026-07-28,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r,SRC-ghsa-go-sdk-xw59,SRC-ghsa-litellm-v4p8,SRC-ostif-badhost-starlette -->
- **Residual Risk**: A correctly authenticated primary MCP route does not protect undocumented support routes, mis-scoped operations, or edge middleware whose decision can be bypassed. <!-- SAF-TRACE: claims=SAF-T1005-C008,SAF-T1005-C009,SAF-T1005-C014; sources=SRC-ghsa-litellm-v4p8,SRC-horizon3-litellm-chain,SRC-ostif-badhost-starlette -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-49257 / GHSA-73cv-556c-w3g6 | 2026-05-25; MCP-Pinot through 3.0.1 using default HTTP configuration | Unauthenticated network callers could invoke all tools with server-side Pinot credentials; 3.1.0 binds locally by default and refuses unauthenticated non-loopback exposure. | Direct vulnerability | Advisory and proof of concept do not establish production exploitation. <!-- SAF-TRACE: claims=SAF-T1005-C006; sources=SRC-ghsa-mcp-pinot-73cv --> |
| CVE-2025-49596 / GHSA-7f8r-222p-6f5g | 2025-06-13; MCP Inspector before 0.14.1 | Unauthenticated proxy requests could launch MCP commands over stdio; 0.14.1 added a session token and Origin validation. | Direct vulnerability and demonstration | The public report is a controlled demonstration. <!-- SAF-TRACE: claims=SAF-T1005-C004,SAF-T1005-C005; sources=SRC-oligo-inspector-cve-2025-49596,SRC-ghsa-inspector-7f8r --> |
| CVE-2026-34742 / GHSA-xw59-hvm2-8pj6 | 2026-03-30; MCP Go SDK before 1.4.0 using unauthenticated localhost HTTP handlers | A malicious website could reach tools and resources through DNS rebinding; 1.4.0 enables protection by default. | Enabling vulnerability | Requires a browser victim and affected HTTP configuration. <!-- SAF-TRACE: claims=SAF-T1005-C007; sources=SRC-ghsa-go-sdk-xw59 --> |
| CVE-2026-42271 chained with CVE-2026-48710 | 2026; LiteLLM 1.74.2-1.83.6 with affected Starlette | Controlled validation reached unauthenticated process execution; upgrade LiteLLM to 1.83.7+ and Starlette to 1.0.1+. | Direct demonstration | No production exploitation was established by the reviewed report. <!-- SAF-TRACE: claims=SAF-T1005-C008,SAF-T1005-C009; sources=SRC-ghsa-litellm-v4p8,SRC-horizon3-litellm-chain,SRC-ostif-badhost-starlette --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Exposed read operations can disclose data reachable with server-side credentials. <!-- SAF-TRACE: claims=SAF-T1005-C006,SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv --> |
| Integrity | High | Exposed write tools or process-start routes can change downstream state or execute under the server account. <!-- SAF-TRACE: claims=SAF-T1005-C005,SAF-T1005-C006,SAF-T1005-C008; sources=SRC-ghsa-inspector-7f8r,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-litellm-v4p8 --> |
| Availability | High | Heavy operations, configuration changes, or arbitrary processes can degrade the endpoint or downstream service. <!-- SAF-TRACE: claims=SAF-T1005-C006,SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r --> |
| Scope | Multi-System | The blast radius can cross into downstream services when the MCP server acts with separate service credentials. <!-- SAF-TRACE: claims=SAF-T1005-C006,SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv --> |

### Severity Conditions

- **Severity increases when**: The listener is internet reachable, exposes mutating or process-backed tools, and holds broad downstream credentials. <!-- SAF-TRACE: claims=SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r -->
- **Severity decreases when**: The listener is loopback-only, Origin and authentication checks fail closed, operations are least-privileged, and affected components are patched. <!-- SAF-TRACE: claims=SAF-T1005-C014; sources=SRC-mcp-streamable-http-2026-07-28,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-go-sdk-xw59 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| HTTP gateway or server span | Requests and responses to MCP, SSE, test, proxy, and management routes | timestamp, correlation ID, client address or source zone, server address, route/path, method, status, user agent | Normalize edge and application clocks and preserve a common correlation identifier. <!-- SAF-TRACE: claims=SAF-T1005-C011; sources=SRC-otel-http-spans-1.44.0 --> |
| MCP application and identity log | Authentication, authorization, Origin decision, RPC method, tool/resource name, outcome | auth result, principal, scope, Origin verdict, RPC method, action class, outcome | Record decisions without logging bearer tokens or sensitive arguments. <!-- SAF-TRACE: claims=SAF-T1005-C002,SAF-T1005-C013; sources=SRC-mcp-streamable-http-2026-07-28,SRC-owasp-logging-cheat-sheet --> |
| Endpoint process telemetry | Server child processes and privileged backend actions | timestamp, parent process, process name, correlation or trace ID, destination | Correlate within the request window and preserve privacy-appropriate command summaries. <!-- SAF-TRACE: claims=SAF-T1005-C012; sources=SRC-mitre-attack-t1190-v2.8 --> |

### Indicators of Compromise (IoCs)

- No universal durable artifact exists; affected-product advisory identifiers and exposed route inventory are investigation pivots rather than proof of compromise. <!-- SAF-TRACE: claims=SAF-T1005-C010,SAF-T1005-C012; sources=SRC-ghsa-mcp-pinot-73cv,SRC-mitre-attack-t1190-v2.8 -->

### Behavioral Indicators

- A successful request from an internet or untrusted-browser zone with missing or invalid authentication or Origin context. <!-- SAF-TRACE: claims=SAF-T1005-C011,SAF-T1005-C013; sources=SRC-otel-http-spans-1.44.0,SRC-owasp-logging-cheat-sheet -->
- A sensitive tool call, resource read, configuration action, or child process sharing the request's trace or correlation identifier. <!-- SAF-TRACE: claims=SAF-T1005-C012; sources=SRC-mitre-attack-t1190-v2.8 -->
- Repeated 401/403 responses followed by a successful operation on a different route or Host value, which can indicate an access-control-path mismatch. <!-- SAF-TRACE: claims=SAF-T1005-C009,SAF-T1005-C013; sources=SRC-ostif-badhost-starlette,SRC-owasp-logging-cheat-sheet -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect an accepted untrusted request with missing or invalid access context followed within the same correlation window by a successful sensitive action. <!-- SAF-TRACE: claims=SAF-T1005-C011,SAF-T1005-C012; sources=SRC-otel-http-spans-1.44.0,SRC-mitre-attack-t1190-v2.8 -->
- **Rule Status**: Experimental. See [detection-rule.yml](detection-rule.yml).
- **Detection Logic**: Correlate accepted public or browser-origin endpoint access with successful tool, resource, or process activity under one correlation identifier. <!-- SAF-TRACE: claims=SAF-T1005-C012; sources=SRC-mitre-attack-t1190-v2.8 -->
- **Correlation Window**: 120 seconds, inclusive. See [detection-rule.yml](detection-rule.yml).
- **Known False Positives**: Intentionally public read-only capabilities, authorized traffic whose identity fields were dropped by an intermediary, and approved security scanning. <!-- SAF-TRACE: claims=SAF-T1005-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-owasp-logging-cheat-sheet -->
- **Known Limitations**: The rule cannot detect unlogged operations, distinguish public intent without inventory, or join events when trace identifiers are absent. <!-- SAF-TRACE: claims=SAF-T1005-C011,SAF-T1005-C017; sources=SRC-otel-http-spans-1.44.0,SRC-owasp-logging-cheat-sheet -->
- **Tuning Guidance**: Maintain an allowlist of intentionally public routes and operation classes, require action sensitivity labels, and validate edge-to-application field propagation. <!-- SAF-TRACE: claims=SAF-T1005-C011,SAF-T1005-C017; sources=SRC-otel-http-spans-1.44.0,SRC-owasp-logging-cheat-sheet -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Nine deterministic cases pass: two positive, four negative, two time boundaries, and one expected false positive. See [test-results.json](test-results.json).
- **Last Validated**: 2026-09-01. See [test-results.json](test-results.json).
- **Feasibility Waiver**: None. See [quality-review.yml](../../research/techniques/SAF-T1005/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **Constrain network exposure**: Bind local servers only to loopback; place remote endpoints behind an authenticated gateway; deny direct access to support and test routes. <!-- SAF-TRACE: claims=SAF-T1005-C014; sources=SRC-mcp-streamable-http-2026-07-28,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-litellm-v4p8 -->
2. **Validate every access boundary**: Reject invalid Origin values, enforce authentication and per-operation authorization, and validate the audience of bearer tokens for protected endpoints. <!-- SAF-TRACE: claims=SAF-T1005-C001,SAF-T1005-C003,SAF-T1005-C014; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-authorization-2026-07-28 -->
3. **Patch affected components**: Use MCP-Pinot 3.1.0+, Inspector 0.14.1+, Go SDK 1.4.0+, LiteLLM 1.83.7+, and Starlette 1.0.1+ where applicable. <!-- SAF-TRACE: claims=SAF-T1005-C005,SAF-T1005-C006,SAF-T1005-C007,SAF-T1005-C008,SAF-T1005-C009; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-inspector-7f8r,SRC-ghsa-go-sdk-xw59,SRC-ghsa-litellm-v4p8,SRC-ostif-badhost-starlette -->
4. **Limit server authority**: Give the endpoint only the downstream privileges and operations needed for its intended callers. <!-- SAF-TRACE: claims=SAF-T1005-C014,SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv,SRC-mitre-attack-t1190-v2.8 -->

### Detective Controls

1. **Monitor access decisions**: Alert on authentication failures, authorization failures, invalid Origins, unexpected methods, and accepted sensitive operations without a principal. <!-- SAF-TRACE: claims=SAF-T1005-C013; sources=SRC-owasp-logging-cheat-sheet -->
2. **Correlate endpoint and process activity**: Join public request telemetry to sensitive backend actions or server child processes. <!-- SAF-TRACE: claims=SAF-T1005-C011,SAF-T1005-C012; sources=SRC-otel-http-spans-1.44.0,SRC-mitre-attack-t1190-v2.8 -->

### Response Procedures

#### Immediate Actions

- Remove the endpoint from untrusted networks or restrict it to a known gateway while preserving relevant logs. <!-- SAF-TRACE: claims=SAF-T1005-C014; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mitre-attack-t1190-v2.8 -->
- Revoke or rotate server-side credentials if the exposed operation could have used them. <!-- SAF-TRACE: claims=SAF-T1005-C006,SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv -->

#### Investigation Steps

- Correlate HTTP, identity, MCP operation, downstream service, and endpoint process telemetry for the exposure window. <!-- SAF-TRACE: claims=SAF-T1005-C011,SAF-T1005-C012,SAF-T1005-C013; sources=SRC-otel-http-spans-1.44.0,SRC-mitre-attack-t1190-v2.8,SRC-owasp-logging-cheat-sheet -->
- Determine the first reachable route, failed access decision, invoked operations, credentials used, and downstream effects. <!-- SAF-TRACE: claims=SAF-T1005-C003,SAF-T1005-C015; sources=SRC-ghsa-mcp-pinot-73cv,SRC-horizon3-litellm-chain -->

#### Remediation

- Patch the affected component, remove unauthenticated non-loopback exposure, and add fail-closed Origin, authentication, authorization, and Host validation. <!-- SAF-TRACE: claims=SAF-T1005-C014; sources=SRC-mcp-streamable-http-2026-07-28,SRC-ghsa-mcp-pinot-73cv,SRC-ostif-badhost-starlette -->
- Validate restored service with a blocked unauthenticated request, a blocked invalid-Origin request, and an authorized least-privilege operation. <!-- SAF-TRACE: claims=SAF-T1005-C001,SAF-T1005-C003,SAF-T1005-C014; sources=SRC-mcp-streamable-http-2026-07-28,SRC-mcp-authorization-2026-07-28 -->
- Add regression tests and monitoring for every MCP, legacy, test, support, and management route. <!-- SAF-TRACE: claims=SAF-T1005-C008,SAF-T1005-C013; sources=SRC-ghsa-litellm-v4p8,SRC-owasp-logging-cheat-sheet -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1004: Server Impersonation / Name-Collision](../SAF-T1004/README.md) | Alternative | SAF-T1004 changes which server is trusted; SAF-T1005 reaches an actual endpoint through exposure or failed access control. See the [scope contract](../../research/techniques/SAF-T1005/technique-contract.yml). |
| [SAF-T1007: OAuth Authorization Phishing](../SAF-T1007/README.md) | Alternative | SAF-T1007 induces a user to authorize; SAF-T1005 obtains direct endpoint access without a valid authorization decision. See the [scope contract](../../research/techniques/SAF-T1005/technique-contract.yml). |
| [SAF-T1101: Command Injection](../SAF-T1101/README.md) | Possible Follow-On | SAF-T1101 abuses command parsing after a tool is reached; SAF-T1005 is complete when unauthorized endpoint access yields a sensitive invocation. See the [scope contract](../../research/techniques/SAF-T1005/technique-contract.yml). |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Analogous | Internet-facing MCP exploitation matches T1190's public-application path, but SAF-T1005 also includes browser-to-local endpoint reach that is not public-facing in ATT&CK's sense. <!-- SAF-TRACE: claims=SAF-T1005-C016; sources=SRC-mitre-attack-t1190-v2.8 --> |

## References

1. **SRC-mcp-streamable-http-2026-07-28**: [MCP Streamable HTTP, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) - endpoint, Origin, binding, request, and metadata requirements.
2. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) - optional authorization profile and protected-resource token requirements.
3. **SRC-ghsa-mcp-pinot-73cv**: [GHSA-73cv-556c-w3g6](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6) - MCP-Pinot exposure, impact, and remediation; published by xiangfu0 with raysabee and PeledTomer1 credited as reporters.
4. **SRC-ghsa-inspector-7f8r**: [GHSA-7f8r-222p-6f5g](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g) - MCP Inspector missing-authentication advisory; published by petery-ant with Rémy Marot of Tenable BugHunters credited.
5. **SRC-oligo-inspector-cve-2025-49596**: [Critical RCE in MCP Inspector](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) - Avi Lumelsky and Oligo Security Research controlled demonstration and fix analysis.
6. **SRC-ghsa-go-sdk-xw59**: [GHSA-xw59-hvm2-8pj6](https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-xw59-hvm2-8pj6) - MCP Go SDK DNS-rebinding advisory, published by maciej-kisiel.
7. **SRC-ghsa-litellm-v4p8**: [GHSA-v4p8-mg3p-g94g](https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g) - LiteLLM MCP test-endpoint authorization advisory, published by jaydns.
8. **SRC-horizon3-litellm-chain**: [CVE-2026-42271 chained with CVE-2026-48710](https://horizon3.ai/attack-research/vulnerabilities/cve-2026-42271-chained-with-cve-2026-48710/) - Horizon3 Attack Research controlled chain and indicators.
9. **SRC-ostif-badhost-starlette**: [Disclosing the BadHost Vulnerability in Starlette](https://ostif.org/disclosing-the-badhost-vulnerability-in-starlette/) - OSTIF, X41 D-Sec, Persistent Security Industries, and Bintech analysis and remediation.
10. **SRC-otel-http-spans-1.44.0**: [OpenTelemetry HTTP semantic conventions 1.44.0](https://opentelemetry.io/docs/specs/semconv/http/http-spans/) - HTTP server telemetry fields.
11. **SRC-mitre-attack-t1190-v2.8**: [ATT&CK T1190, version 2.8](https://attack.mitre.org/techniques/T1190/) - public-facing application behavior, mitigations, and detection strategy.
12. **SRC-owasp-logging-cheat-sheet**: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) - security event logging guidance.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft with evidence packet and tested analytic | Clean-room authoring agent |
