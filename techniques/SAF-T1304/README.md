# SAF-T1304: Credential Relay Chain

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1304
- **Research Packet**: [research/techniques/SAF-T1304](../../research/techniques/SAF-T1304/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1304/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A relayed bearer credential can give a receiving MCP component the credential holder's tool or data authority; impact depends on that credential's privileges and the receiver's reachable resources. <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->
- **First Observed**: Not observed in production; publicly demonstrated no later than 2026-03-15. <!-- SAF-TRACE: claims=SAF-T1304-C006; sources=SRC-fastmcp-ghsa,SRC-nvd-cve-2025-69196 -->
- **Last Updated**: 2026-09-01

## Scope

Credential Relay Chain covers an MCP or agent intermediary causing a credential to cross a resource, principal, or hop boundary without independent issuance and validation for the current caller and target, so the receiving component authorizes greater access than the caller otherwise has. <!-- SAF-TRACE: claims=SAF-T1304-C001,SAF-T1304-C002,SAF-T1304-C005; sources=SRC-fastmcp-ghsa,SRC-mcp-authorization-2026-07-28,SRC-rfc9728 -->

### In Scope

- Reuse of a token at a resource outside its intended audience, including a malicious resource server inducing authorization for another resource. <!-- SAF-TRACE: claims=SAF-T1304-C005,SAF-T1304-C006; sources=SRC-rfc9728,SRC-fastmcp-ghsa -->
- Forwarding a caller's bearer token to a downstream MCP server or substituting one user's cached credential into another user's request. <!-- SAF-TRACE: claims=SAF-T1304-C003,SAF-T1304-C009,SAF-T1304-C011; sources=SRC-mcp-security,SRC-github-mcp-ghsa,SRC-foundry-local-gap02 -->

### Out of Scope

- Initial token theft, phishing, or secret extraction without the defining cross-boundary authorization step; [SAF-T1504: Token Theft via API Response](../SAF-T1504/README.md) is one acquisition neighbor. <!-- SAF-TRACE: claims=SAF-T1304-C019; sources=SRC-ms-oauth-redirection-2026,SRC-microsoft-ai-gateway-incident -->
- Legitimate scope enlargement through consent or policy, rather than acceptance of a wrong-bound credential; treat that as [SAF-T1308: Token Scope Substitution](../SAF-T1308/README.md). <!-- SAF-TRACE: claims=SAF-T1304-C019; sources=SRC-mcp-security,SRC-rfc8707 -->
- Actions performed after the receiving component has accepted the relayed credential; classify those actions separately by their immediate mechanism and objective. <!-- SAF-TRACE: claims=SAF-T1304-C001; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->

### Distinguishing Characteristics

The decisive signal is authorization with a credential whose audience, upstream principal, or request ownership does not match the current resource and caller. Credential Acquisition ends when credential material is obtained; Authorization Scope Escalation changes legitimate authority; Credential Relay Chain begins when existing authority is replayed, forwarded, or substituted across the trust boundary. <!-- SAF-TRACE: claims=SAF-T1304-C013,SAF-T1304-C019; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security,SRC-github-mcp-ghsa -->

## Description

An adversary arranges for an MCP client, server, gateway, or agent runtime to carry a bearer credential from one security context into another. The receiving resource then treats that credential as authority for its tools or data even though it was not independently issued and validated for that resource, principal, and request. <!-- SAF-TRACE: claims=SAF-T1304-C001,SAF-T1304-C002; sources=SRC-fastmcp-ghsa,SRC-mcp-authorization-2026-07-28 -->

The mechanism includes cross-resource token replay, downstream token passthrough, and cross-user credential-cache contamination. MCP authorization requires servers to accept only tokens intended for them, while MCP security guidance explicitly forbids token passthrough because it bypasses audience and other controls. <!-- SAF-TRACE: claims=SAF-T1304-C002,SAF-T1304-C003; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security -->

The end-to-end behavior is demonstrated by the FastMCP advisory's proof of concept. Separate 2026 advisories document audience-validation omission in Google MCP Toolbox and cross-user credential reuse in GitHub MCP Server; a Microsoft preview known issue documents unvalidated caller-token forwarding to external MCP servers. These establish vulnerable implementations, not confirmed production exploitation. <!-- SAF-TRACE: claims=SAF-T1304-C006,SAF-T1304-C007,SAF-T1304-C009,SAF-T1304-C011; sources=SRC-fastmcp-ghsa,SRC-nvd-cve-2026-14541,SRC-github-mcp-ghsa,SRC-foundry-local-gap02 -->

## Attack Vectors

- **Primary Vector**: An attacker-controlled or confused MCP resource server induces an authorization flow for a different resource, then replays the resulting token at that resource. <!-- SAF-TRACE: claims=SAF-T1304-C005,SAF-T1304-C006; sources=SRC-rfc9728,SRC-fastmcp-ghsa -->
- **Secondary Vectors**:
  - A gateway forwards its caller's bearer token to an external MCP server without revalidation. <!-- SAF-TRACE: claims=SAF-T1304-C003,SAF-T1304-C011; sources=SRC-mcp-security,SRC-foundry-local-gap02 -->
  - A long-lived process caches one request's credential-bearing client and reuses it for another principal. <!-- SAF-TRACE: claims=SAF-T1304-C009; sources=SRC-github-mcp-ghsa -->
- **Affected Components**: MCP clients, servers, gateways, authorization middleware, credential stores, and external resource servers. <!-- SAF-TRACE: claims=SAF-T1304-C003,SAF-T1304-C006,SAF-T1304-C009; sources=SRC-mcp-security,SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->
- **Trust Boundary Crossed**: Resource audience, caller principal, or intermediary-to-downstream authorization boundary. <!-- SAF-TRACE: claims=SAF-T1304-C001,SAF-T1304-C002; sources=SRC-fastmcp-ghsa,SRC-mcp-authorization-2026-07-28 -->

## Technical Details

### Prerequisites

- A reusable credential reaches an MCP or agent component that can contact another protected resource. <!-- SAF-TRACE: claims=SAF-T1304-C004,SAF-T1304-C005; sources=SRC-rfc9700,SRC-rfc9728 -->
- Audience validation, token exchange, or per-request credential isolation is absent or defective. <!-- SAF-TRACE: claims=SAF-T1304-C006,SAF-T1304-C007,SAF-T1304-C009; sources=SRC-fastmcp-ghsa,SRC-nvd-cve-2026-14541,SRC-github-mcp-ghsa -->
- The relayed credential grants authority meaningful to the receiving resource. <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies a component that accepts a foreign audience, forwards bearer tokens, or retains credential state across requests. <!-- SAF-TRACE: claims=SAF-T1304-C006,SAF-T1304-C007,SAF-T1304-C009,SAF-T1304-C011; sources=SRC-fastmcp-ghsa,SRC-nvd-cve-2026-14541,SRC-github-mcp-ghsa,SRC-foundry-local-gap02 -->
2. **Delivery**: A victim authorization flow or ordinary authenticated request supplies the reusable credential to that component. <!-- SAF-TRACE: claims=SAF-T1304-C005,SAF-T1304-C006,SAF-T1304-C009; sources=SRC-rfc9728,SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->
3. **Trigger or Execution**: The component presents the credential to a different resource or on a different principal's request. <!-- SAF-TRACE: claims=SAF-T1304-C001,SAF-T1304-C009; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->
4. **Boundary Crossing**: The receiver accepts the credential without verifying the intended resource and current caller or without a valid token exchange. <!-- SAF-TRACE: claims=SAF-T1304-C002,SAF-T1304-C003; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security -->
5. **Objective**: The request obtains tool or data authority belonging to the credential's original security context. <!-- SAF-TRACE: claims=SAF-T1304-C001,SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->
6. **Follow-On Activity**: The actor can invoke only the operations and access only the resources allowed by the accepted credential and receiving service. <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->

### Example Scenario

A malicious server at `relay.invalid` advertises authorization metadata for `records.invalid`. A user authorizes what appears to be the malicious server; because the client fails to bind the token to the requested resource, the malicious server receives a bearer token usable at `records.invalid` and presents it there. This is an inert adaptation of the published FastMCP proof of concept. <!-- SAF-TRACE: claims=SAF-T1304-C006; sources=SRC-fastmcp-ghsa -->

The safe example event shape is: <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-attack-det0185 -->

```json
{
  "request_id": "req-example",
  "principal_id": "user-current",
  "upstream_principal_id": "user-origin",
  "expected_resource": "https://records.invalid/mcp",
  "token_audience": "https://other.invalid/mcp",
  "token_fingerprint": "sha256:placeholder-not-a-token",
  "token_exchange_validated": false
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1304-C001 | A credential relayed across resource or principal boundaries can be accepted as another context's authority. | Demonstrated | SRC-fastmcp-ghsa: [FastMCP advisory](https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-5h2m-4q8j-pqpj); SRC-github-mcp-ghsa: [GitHub MCP advisory](https://github.com/github/github-mcp-server/security/advisories/GHSA-pjp5-fpmr-3349) | Public demonstrations and vulnerable behavior do not establish production exploitation. |
| SAF-T1304-C002 | MCP servers must validate token audience and accept only tokens intended for their resource. | Research-Derived | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | A normative requirement does not prove implementation compliance. |
| SAF-T1304-C003 | MCP token passthrough creates audience and control-bypass risks and is prohibited. | Research-Derived | SRC-mcp-security: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices) | Guidance describes the risk class, not exploitation prevalence. |
| SAF-T1304-C004 | OAuth replay defenses include sender constraint plus audience and scope restriction. | Research-Derived | SRC-rfc9700: [OAuth 2.0 Security BCP](https://www.rfc-editor.org/info/rfc9700/) | General OAuth guidance is not MCP incident evidence. |
| SAF-T1304-C005 | A malicious resource server can induce a token for a different resource and reuse it there. | Research-Derived | SRC-rfc9728: [OAuth Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html) | The RFC presents a threat model, not an MCP incident. |
| SAF-T1304-C006 | FastMCP before 2.14.2 lacked resource binding; its advisory gives a successful cross-resource replay proof of concept. | Demonstrated | SRC-fastmcp-ghsa: [GHSA-5h2m-4q8j-pqpj](https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-5h2m-4q8j-pqpj); SRC-nvd-cve-2025-69196: [CVE-2025-69196](https://nvd.nist.gov/vuln/detail/CVE-2025-69196) | NVD records proof-of-concept exploitation, not production abuse. |
| SAF-T1304-C007 | Google MCP Toolbox 1.4.0 could accept a valid Google token minted for an unrelated application when audience configuration was omitted. | Demonstrated | SRC-nvd-cve-2026-14541: [CVE-2026-14541](https://nvd.nist.gov/vuln/detail/CVE-2026-14541) | The record reports no known exploitation. |
| SAF-T1304-C008 | Google made audience validation mandatory and released the correction in 1.5.0. | Research-Derived | SRC-google-pr3450: [mcp-toolbox pull request 3450](https://github.com/googleapis/mcp-toolbox/pull/3450) | A maintainer fix record does not measure deployed patch uptake. |
| SAF-T1304-C009 | GitHub MCP Server's global GraphQL-client cache could reuse the first HTTP caller's token for later callers. | Demonstrated | SRC-github-mcp-ghsa: [GHSA-pjp5-fpmr-3349](https://github.com/github/github-mcp-server/security/advisories/GHSA-pjp5-fpmr-3349) | The proof of concept is controlled, not a production incident. |
| SAF-T1304-C010 | GitHub MCP Server fixed the cache isolation flaw in 1.1.2; NVD records public proof-of-concept exploitation. | Demonstrated | SRC-github-mcp-ghsa: [GHSA-pjp5-fpmr-3349](https://github.com/github/github-mcp-server/security/advisories/GHSA-pjp5-fpmr-3349); SRC-nvd-cve-2026-48529: [CVE-2026-48529](https://nvd.nist.gov/vuln/detail/CVE-2026-48529) | The sources do not report production compromise. |
| SAF-T1304-C011 | A Microsoft Foundry Local preview issue forwards a caller bearer token to an external MCP server without revalidation, enabling capture and replay by a malicious server. | Research-Derived | SRC-foundry-local-gap02: [Known issues](https://learn.microsoft.com/en-us/azure/azure-arc/agents-tools-foundry-local/known-issues) | This is a documented preview exposure, not evidence of exploitation. |
| SAF-T1304-C012 | Multi-user remote MCP implementations should validate identity, permissions, audience, and scope on each operation. | Research-Derived | SRC-github-secure-mcp: [Secure remote MCP servers](https://github.blog/ai-and-ml/generative-ai/how-to-build-secure-and-scalable-remote-mcp-servers/) | Architecture guidance is not a product guarantee. |
| SAF-T1304-C013 | Correlating audience mismatch, principal mismatch, and short-window cross-resource token-fingerprint reuse can expose relay behavior. | Demonstrated | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); SRC-attack-det0185: [DET0185](https://attack.mitre.org/detectionstrategies/DET0185/); SRC-github-mcp-ghsa: [GitHub MCP advisory](https://github.com/github/github-mcp-server/security/advisories/GHSA-pjp5-fpmr-3349) | Detection is validated only against synthetic events. |
| SAF-T1304-C014 | Shared gateways, opaque tokens, missing fingerprints, and absent identity fields can create false positives or blind spots. | Research-Derived | SRC-attack-det0185: [DET0185](https://attack.mitre.org/detectionstrategies/DET0185/); SRC-mcp-security: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices) | Environment-specific rates are not publicly measured. |
| SAF-T1304-C015 | Resource-bound tokens, explicit token exchange, and per-request credential isolation constrain relay paths. | Research-Derived | SRC-rfc8707: [Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html); SRC-mcp-security: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices); SRC-github-secure-mcp: [Secure remote MCP servers](https://github.blog/ai-and-ml/generative-ai/how-to-build-secure-and-scalable-remote-mcp-servers/) | Correct configuration and implementation remain required. |
| SAF-T1304-C016 | ATT&CK T1550.001 is an analogous mapping because it covers use of stolen application access tokens. | Research-Derived | SRC-mitre-t1550-001: [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | ATT&CK does not encode MCP hop, audience, or principal boundaries and assigns a different tactic. |
| SAF-T1304-C017 | Consequence is bounded by the relayed credential's privileges and the receiving resource's capabilities. | Research-Derived | SRC-fastmcp-ghsa: [FastMCP advisory](https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-5h2m-4q8j-pqpj); SRC-github-mcp-ghsa: [GitHub MCP advisory](https://github.com/github/github-mcp-server/security/advisories/GHSA-pjp5-fpmr-3349) | Deployment-specific impact requires local assessment. |
| SAF-T1304-C018 | Response should revoke exposed tokens, correct audience or cache isolation, and preserve identity/resource correlation telemetry. | Research-Derived | SRC-rfc9700: [OAuth 2.0 Security BCP](https://www.rfc-editor.org/info/rfc9700/); SRC-github-mcp-ghsa: [GitHub MCP advisory](https://github.com/github/github-mcp-server/security/advisories/GHSA-pjp5-fpmr-3349) | Operational procedures vary by identity provider and resource. |
| SAF-T1304-C019 | Token acquisition and legitimate scope escalation are neighboring but distinct mechanisms. | Research-Derived | SRC-mcp-security: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices); SRC-rfc8707: [Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html); SRC-ms-oauth-redirection-2026: [OAuth redirection abuse](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/) | Synthetic SAF neighbor identifiers require later catalog reconciliation. |

### Current State

- **Affected Environments**: Deployments with missing audience validation, caller-token passthrough, or process-global credential caches are directly represented by the reviewed advisories and known issue. <!-- SAF-TRACE: claims=SAF-T1304-C006,SAF-T1304-C007,SAF-T1304-C009,SAF-T1304-C011; sources=SRC-fastmcp-ghsa,SRC-nvd-cve-2026-14541,SRC-github-mcp-ghsa,SRC-foundry-local-gap02 -->
- **Known Exploitation**: Public proofs of concept exist for FastMCP and GitHub MCP Server; the [source-coverage audit](../../research/techniques/SAF-T1304/source-coverage.yml) found no qualifying direct production breach.
- **Available Protections**: FastMCP 2.14.2, Google MCP Toolbox 1.5.0, and GitHub MCP Server 1.1.2 contain the cited corrections; protocol guidance requires audience validation and forbids token passthrough. <!-- SAF-TRACE: claims=SAF-T1304-C002,SAF-T1304-C003,SAF-T1304-C006,SAF-T1304-C008,SAF-T1304-C010; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security,SRC-fastmcp-ghsa,SRC-google-pr3450,SRC-github-mcp-ghsa -->
- **Residual Risk**: Custom gateways and integrations remain exposed when they validate token signature but not resource, principal, and per-request ownership. <!-- SAF-TRACE: claims=SAF-T1304-C012,SAF-T1304-C015; sources=SRC-github-secure-mcp,SRC-mcp-security -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-69196 / GHSA-5h2m-4q8j-pqpj <!-- SAF-TRACE: claims=SAF-T1304-C006; sources=SRC-fastmcp-ghsa,SRC-nvd-cve-2025-69196 --> | Published 2026-03-15; FastMCP before 2.14.2 <!-- SAF-TRACE: claims=SAF-T1304-C006; sources=SRC-fastmcp-ghsa --> | Cross-resource bearer-token replay to protected tools or resources; update to 2.14.2 <!-- SAF-TRACE: claims=SAF-T1304-C006; sources=SRC-fastmcp-ghsa --> | Direct vulnerability and direct demonstration <!-- SAF-TRACE: claims=SAF-T1304-C001,SAF-T1304-C006; sources=SRC-fastmcp-ghsa --> | Proof of concept only; no production exploitation established <!-- SAF-TRACE: claims=SAF-T1304-C006; sources=SRC-nvd-cve-2025-69196 --> |
| CVE-2026-14541 <!-- SAF-TRACE: claims=SAF-T1304-C007,SAF-T1304-C008; sources=SRC-nvd-cve-2026-14541,SRC-google-pr3450 --> | Published 2026-06-22; Google MCP Toolbox 1.4.0 with Google OAuth and omitted audience configuration <!-- SAF-TRACE: claims=SAF-T1304-C007; sources=SRC-nvd-cve-2026-14541 --> | Acceptance of unrelated-app Google tokens; update to 1.5.0 <!-- SAF-TRACE: claims=SAF-T1304-C007,SAF-T1304-C008; sources=SRC-nvd-cve-2026-14541,SRC-google-pr3450 --> | Direct vulnerability <!-- SAF-TRACE: claims=SAF-T1304-C007; sources=SRC-nvd-cve-2026-14541 --> | NVD records no known exploitation <!-- SAF-TRACE: claims=SAF-T1304-C007; sources=SRC-nvd-cve-2026-14541 --> |
| CVE-2026-48529 / GHSA-pjp5-fpmr-3349 <!-- SAF-TRACE: claims=SAF-T1304-C009,SAF-T1304-C010; sources=SRC-github-mcp-ghsa,SRC-nvd-cve-2026-48529 --> | Published 2026-07-24; GitHub MCP Server 0.22.0 through 1.1.1 using HTTP lockdown mode <!-- SAF-TRACE: claims=SAF-T1304-C009,SAF-T1304-C010; sources=SRC-github-mcp-ghsa --> | Later callers could execute with the first caller's credential; update to 1.1.2 <!-- SAF-TRACE: claims=SAF-T1304-C009,SAF-T1304-C010; sources=SRC-github-mcp-ghsa --> | Direct vulnerability and direct demonstration component <!-- SAF-TRACE: claims=SAF-T1304-C001,SAF-T1304-C009; sources=SRC-github-mcp-ghsa --> | Controlled proof of concept; no production compromise reported <!-- SAF-TRACE: claims=SAF-T1304-C010; sources=SRC-nvd-cve-2026-48529 --> |
| Foundry Local GAP-02 <!-- SAF-TRACE: claims=SAF-T1304-C011; sources=SRC-foundry-local-gap02 --> | Documentation reviewed 2026-09-01; preview `microsoft_entra_id` integration <!-- SAF-TRACE: claims=SAF-T1304-C011; sources=SRC-foundry-local-gap02 --> | Caller token can reach an external MCP server without revalidation; restrict use to trusted servers while under review <!-- SAF-TRACE: claims=SAF-T1304-C011; sources=SRC-foundry-local-gap02 --> | Enabling vulnerability / implementation exposure <!-- SAF-TRACE: claims=SAF-T1304-C011; sources=SRC-foundry-local-gap02 --> | Known issue, not a reported attack or CVE <!-- SAF-TRACE: claims=SAF-T1304-C011; sources=SRC-foundry-local-gap02 --> |

### Real-World Incidents or Demonstrations

#### FastMCP Cross-Resource Proof of Concept (2026)

The FastMCP advisory documents a malicious MCP server advertising a benign server's authorization service, extraction of the resulting token, and a successful protected-resource request returning HTTP 200. It demonstrates the defining cross-resource relay chain, but not a production breach. <!-- SAF-TRACE: claims=SAF-T1304-C001,SAF-T1304-C006; sources=SRC-fastmcp-ghsa,SRC-nvd-cve-2025-69196 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa --> | High <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa --> | Relayed authority can expose private tools and resource data when the accepted credential permits reads. <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa --> |
| Integrity <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-github-mcp-ghsa --> | High <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-github-mcp-ghsa --> | A credential with write permissions can allow state-changing tool calls under the wrong principal. <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-github-mcp-ghsa --> |
| Availability <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-github-mcp-ghsa --> | Medium <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-github-mcp-ghsa --> | Availability effects require a relayed credential that can modify or exhaust the receiving resource. <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-github-mcp-ghsa --> |
| Scope <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa --> | Multi-System <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa --> | The chain crosses at least an intermediary and protected resource but remains bounded by token and service permissions. <!-- SAF-TRACE: claims=SAF-T1304-C017; sources=SRC-fastmcp-ghsa,SRC-github-mcp-ghsa --> |

### Severity Conditions

- **Severity increases when**: Tokens are long-lived or broadly privileged and the receiving MCP server exposes sensitive data or state-changing tools. <!-- SAF-TRACE: claims=SAF-T1304-C004,SAF-T1304-C017; sources=SRC-rfc9700,SRC-fastmcp-ghsa,SRC-github-mcp-ghsa -->
- **Severity decreases when**: Tokens are resource-bound and short-lived, per-request credential isolation is enforced, and high-impact tools require independent approval. <!-- SAF-TRACE: claims=SAF-T1304-C012,SAF-T1304-C015; sources=SRC-rfc8707,SRC-github-secure-mcp -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP gateway or server authorization log <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-github-secure-mcp --> | Authentication decision and protected-resource request <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-github-secure-mcp --> | Timestamp, request/session, current principal, upstream principal, expected resource, token audience, one-way token fingerprint, token-exchange result <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-attack-det0185 --> | Never record raw bearer tokens; retain enough normalized data for a ten-minute correlation window. <!-- SAF-TRACE: claims=SAF-T1304-C013,SAF-T1304-C014; sources=SRC-attack-det0185,SRC-mcp-security --> |
| Identity provider token log <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-attack-det0185 --> | Token issuance or exchange and resource indicator <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-rfc8707,SRC-attack-det0185 --> | Subject, client, audience/resource, scopes, issuance and expiration times, exchange identifier <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-rfc8707,SRC-attack-det0185 --> | Normalize identifiers without exporting token material. <!-- SAF-TRACE: claims=SAF-T1304-C014; sources=SRC-attack-det0185 --> |

### Indicators of Compromise (IoCs)

- None known; the reviewed evidence provides behavior and affected-version indicators rather than a durable adversary artifact. <!-- SAF-TRACE: claims=SAF-T1304-C006,SAF-T1304-C007,SAF-T1304-C009,SAF-T1304-C011; sources=SRC-fastmcp-ghsa,SRC-nvd-cve-2026-14541,SRC-github-mcp-ghsa,SRC-foundry-local-gap02 -->

### Behavioral Indicators

- A protected-resource request whose expected resource differs from the token audience. <!-- SAF-TRACE: claims=SAF-T1304-C002,SAF-T1304-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9728 -->
- A current request principal that differs from the principal attached to the upstream credential. <!-- SAF-TRACE: claims=SAF-T1304-C009,SAF-T1304-C013; sources=SRC-github-mcp-ghsa -->
- The same token fingerprint appearing at different resources within ten minutes without a validated exchange. <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-attack-det0185,SRC-mcp-authorization-2026-07-28 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect wrong-audience use, cross-principal substitution, and short-window cross-resource bearer-token reuse. <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-attack-det0185,SRC-github-mcp-ghsa -->
- **Rule Status**: Test <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-attack-det0185 -->
- **Detection Logic**: Alert on any audience mismatch, any principal mismatch, or reuse of one token fingerprint at two resources within 600 seconds unless a validated token exchange is recorded. <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-attack-det0185,SRC-github-mcp-ghsa -->
- **Correlation Window**: 600 seconds, including the boundary. <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-attack-det0185 -->
- **Known False Positives**: Approved shared-service gateways that intentionally use one service credential for several resources may alert until allowlisted. <!-- SAF-TRACE: claims=SAF-T1304-C014; sources=SRC-attack-det0185 -->
- **Known Limitations**: Opaque tokens, absent fingerprints, missing principal fields, and reuse outside the window can evade this analytic. <!-- SAF-TRACE: claims=SAF-T1304-C014; sources=SRC-attack-det0185,SRC-mcp-security -->
- **Tuning Guidance**: Allowlist only documented exchange services, keep resource identifiers canonical, and baseline legitimate shared-service principals. <!-- SAF-TRACE: claims=SAF-T1304-C014,SAF-T1304-C015; sources=SRC-attack-det0185,SRC-rfc8707 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1304/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1304/test_detection_rule.py)
- **Expected Result**: [Ten synthetic cases: six alerts, including one expected false positive, and four non-alerts.](../../tests/SAF-T1304/validation-results.json)
- **Last Validated**: [2026-09-01](../../tests/SAF-T1304/validation-results.json)
- **Feasibility Waiver**: [None](../../research/techniques/SAF-T1304/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Require the intended resource during authorization and validate it at each protected resource; reject foreign audiences. <!-- SAF-TRACE: claims=SAF-T1304-C002,SAF-T1304-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707 -->
2. **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Construct authorization context per request and never retain a credential-bearing client in process-global state. <!-- SAF-TRACE: claims=SAF-T1304-C009,SAF-T1304-C012,SAF-T1304-C015; sources=SRC-github-mcp-ghsa,SRC-github-secure-mcp -->
3. **Validated Token Exchange**: Mint a new downstream token bound to the receiving resource instead of forwarding the inbound bearer token. <!-- SAF-TRACE: claims=SAF-T1304-C003,SAF-T1304-C015; sources=SRC-mcp-security,SRC-rfc8707 -->

### Detective Controls

1. **[SAF-M-19: Token Usage Tracking](../../mitigations/SAF-M-19/README.md)**: Correlate one-way token fingerprints across resources and callers within a bounded window. <!-- SAF-TRACE: claims=SAF-T1304-C013,SAF-T1304-C015; sources=SRC-attack-det0185,SRC-mcp-authorization-2026-07-28 -->
2. **Authorization Decision Review**: Alert on audience and principal mismatches before tool execution and retain denial reasons for investigation. <!-- SAF-TRACE: claims=SAF-T1304-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-github-secure-mcp -->

### Response Procedures

#### Immediate Actions

- Disable the affected relay path, invalidate active sessions, and revoke the exposed credential at its issuer. <!-- SAF-TRACE: claims=SAF-T1304-C018; sources=SRC-rfc9700,SRC-github-mcp-ghsa -->
- Block the vulnerable client/server version or configuration until audience and per-request isolation controls are verified. <!-- SAF-TRACE: claims=SAF-T1304-C006,SAF-T1304-C008,SAF-T1304-C010,SAF-T1304-C018; sources=SRC-fastmcp-ghsa,SRC-google-pr3450,SRC-github-mcp-ghsa -->

#### Investigation Steps

- Correlate token issuance, exchange, resource access, principal, and tool-call records without collecting raw tokens. <!-- SAF-TRACE: claims=SAF-T1304-C013,SAF-T1304-C018; sources=SRC-attack-det0185,SRC-mcp-authorization-2026-07-28 -->
- Determine every resource and caller for which the fingerprint appeared, then review resulting operations against the credential's allowed scope. <!-- SAF-TRACE: claims=SAF-T1304-C017,SAF-T1304-C018; sources=SRC-rfc9700,SRC-github-mcp-ghsa -->

#### Remediation

- Patch the affected component and enforce explicit audience validation or downstream token exchange. <!-- SAF-TRACE: claims=SAF-T1304-C006,SAF-T1304-C008,SAF-T1304-C010,SAF-T1304-C015; sources=SRC-fastmcp-ghsa,SRC-google-pr3450,SRC-github-mcp-ghsa,SRC-rfc8707 -->
- Remove shared credential-bearing clients and add request-isolation regression tests. <!-- SAF-TRACE: claims=SAF-T1304-C009,SAF-T1304-C015; sources=SRC-github-mcp-ghsa,SRC-github-secure-mcp -->
- Re-run the [synthetic detection tests](../../tests/SAF-T1304/test_detection_rule.py) and preserve the resulting [validation record](../../tests/SAF-T1304/validation-results.json).

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1504: Token Theft via API Response](../SAF-T1504/README.md) <!-- SAF-TRACE: claims=SAF-T1304-C019; sources=SRC-ms-oauth-redirection-2026,SRC-microsoft-ai-gateway-incident --> | Prerequisite <!-- SAF-TRACE: claims=SAF-T1304-C019; sources=SRC-ms-oauth-redirection-2026,SRC-microsoft-ai-gateway-incident --> | Acquires token material through an API response; Credential Relay Chain uses or propagates a credential across an authorization boundary. <!-- SAF-TRACE: claims=SAF-T1304-C019; sources=SRC-ms-oauth-redirection-2026,SRC-microsoft-ai-gateway-incident --> |
| [SAF-T1308: Token Scope Substitution](../SAF-T1308/README.md) <!-- SAF-TRACE: claims=SAF-T1304-C019; sources=SRC-mcp-security,SRC-rfc8707 --> | Alternative <!-- SAF-TRACE: claims=SAF-T1304-C019; sources=SRC-mcp-security,SRC-rfc8707 --> | Enlarges or substitutes legitimate scope; Credential Relay Chain exploits a credential not bound to the current boundary. <!-- SAF-TRACE: claims=SAF-T1304-C019; sources=SRC-mcp-security,SRC-rfc8707 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1550.001](https://attack.mitre.org/techniques/T1550/001/) <!-- SAF-TRACE: claims=SAF-T1304-C016; sources=SRC-mitre-t1550-001 --> | Use Alternate Authentication Material: Application Access Token <!-- SAF-TRACE: claims=SAF-T1304-C016; sources=SRC-mitre-t1550-001 --> | Analogous <!-- SAF-TRACE: claims=SAF-T1304-C016; sources=SRC-mitre-t1550-001 --> | Both use an application token as authority, but ATT&CK does not require an MCP audience, hop, or cross-principal relay and maps it to Lateral Movement. <!-- SAF-TRACE: claims=SAF-T1304-C016; sources=SRC-mitre-t1550-001 --> |

## References

1. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization Specification, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) - Resource indicators, token audience validation, and rejection behavior.
2. **SRC-mcp-security**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices) - Token passthrough, scope, and confused-deputy guidance.
3. **SRC-rfc9700**: [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/info/rfc9700/) - Replay countermeasures and audience restriction.
4. **SRC-rfc8707**: [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html) - Resource-bound authorization and downscoping.
5. **SRC-rfc9728**: [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html) - Malicious-resource token redirection threat.
6. **SRC-fastmcp-ghsa**: [FastMCP GHSA-5h2m-4q8j-pqpj](https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-5h2m-4q8j-pqpj) - Cross-resource proof of concept, impact, affected versions, and fix.
7. **SRC-nvd-cve-2025-69196**: [NVD CVE-2025-69196](https://nvd.nist.gov/vuln/detail/CVE-2025-69196) - Government vulnerability and exploitation-status record.
8. **SRC-nvd-cve-2026-14541**: [NVD CVE-2026-14541](https://nvd.nist.gov/vuln/detail/CVE-2026-14541) - Google MCP Toolbox audience-validation vulnerability.
9. **SRC-google-pr3450**: [Google MCP Toolbox PR 3450](https://github.com/googleapis/mcp-toolbox/pull/3450) - Maintainer correction and release linkage.
10. **SRC-github-mcp-ghsa**: [GitHub MCP Server GHSA-pjp5-fpmr-3349](https://github.com/github/github-mcp-server/security/advisories/GHSA-pjp5-fpmr-3349) - Cross-user credential cache behavior and remediation.
11. **SRC-nvd-cve-2026-48529**: [NVD CVE-2026-48529](https://nvd.nist.gov/vuln/detail/CVE-2026-48529) - Government vulnerability and exploitation-status record.
12. **SRC-foundry-local-gap02**: [Microsoft Foundry Local Known Issues](https://learn.microsoft.com/en-us/azure/azure-arc/agents-tools-foundry-local/known-issues) - GAP-02 caller-token forwarding exposure.
13. **SRC-github-secure-mcp**: [How to build secure and scalable remote MCP servers](https://github.blog/ai-and-ml/generative-ai/how-to-build-secure-and-scalable-remote-mcp-servers/) - Per-operation identity, audience, and scope validation.
14. **SRC-attack-det0185**: [MITRE ATT&CK DET0185](https://attack.mitre.org/detectionstrategies/DET0185/) - Token-reuse correlation strategy.
15. **SRC-mitre-t1550-001**: [MITRE ATT&CK T1550.001](https://attack.mitre.org/techniques/T1550/001/) - Application access-token analogy.
16. **SRC-ms-oauth-redirection-2026**: [Microsoft OAuth redirection abuse research](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/) - Neighbor-boundary evidence for phishing without token relay.
17. **SRC-microsoft-ai-gateway-incident**: [Microsoft AI gateway incident research](https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/) - Neighbor-boundary evidence for credential extraction and later use.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Initial clean-room research draft | OpenAI Codex clean-room agent |
