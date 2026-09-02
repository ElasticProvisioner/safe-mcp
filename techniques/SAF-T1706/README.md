# SAF-T1706: OAuth Token Pivot Replay

## Overview

- **Tactic**: Lateral Movement (ATK-TA0008)
- **Technique ID**: SAF-T1706
- **Research Packet**: [research/techniques/SAF-T1706](../../research/techniques/SAF-T1706/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1706/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: A replayed bearer token can expose every operation and data set allowed by its subject, audience, scope, validity, and resource, but those same constraints bound the consequence. <!-- SAF-TRACE: claims=SAF-T1706-C015; sources=SRC-rfc6750,SRC-rfc9700 -->
- **First Observed**: No direct production OAuth-MCP incident was identified in the reviewed authoritative corpus through 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1706-C009; sources=SRC-nvd-search-corpus,SRC-cisa-kev-catalog-page-2026-09-01 -->
- **Last Updated**: 2026-09-02

## Scope

This technique covers an adversary presenting a captured OAuth bearer access token from an MCP or agent-connected component to a reachable protected resource, where acceptance moves the adversary across that resource boundary as the token subject. <!-- SAF-TRACE: claims=SAF-T1706-C001,SAF-T1706-C004; sources=SRC-rfc6750,SRC-mcp-authorization-2025-11-25 -->

### In Scope

- Replay by a different presenter, including cross-resource reuse when audience validation is missing or incorrect. <!-- SAF-TRACE: claims=SAF-T1706-C002,SAF-T1706-C004; sources=SRC-rfc6750,SRC-rfc9700 -->
- Authentication with the captured token's existing subject and scopes at an MCP or agent-connected protected resource. <!-- SAF-TRACE: claims=SAF-T1706-C004,SAF-T1706-C015; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc6750 -->

### Out of Scope

- Theft or minting of the token, authorization-code replay, refresh-token replay, client-assertion replay, token forgery, and session-cookie replay. <!-- SAF-TRACE: claims=SAF-T1706-C014; sources=SRC-mitre-t1528 -->
- Normal or unsafe token passthrough by an intermediary; MCP explicitly treats passthrough as a separate prohibited behavior. <!-- SAF-TRACE: claims=SAF-T1706-C003; sources=SRC-mcp-security-2025-11-25 -->
- Collection, exfiltration, persistence, or impact actions taken after lateral authentication. <!-- SAF-TRACE: claims=SAF-T1706-C014; sources=SRC-mitre-t1550-001,SRC-mitre-t1528 -->

### Distinguishing Characteristics

[SAF-T1504](../SAF-T1504/README.md) and [SAF-T1506](../SAF-T1506/README.md) end when token material is acquired through an API response or infrastructure path; this technique begins when a captured OAuth access token is presented. [SAF-T1304](../SAF-T1304/README.md) covers the broader credential-relay boundary, while [SAF-T1308](../SAF-T1308/README.md) covers scope or audience substitution without necessarily requiring replay by a different presenter. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C014; sources=SRC-mcp-security-2025-11-25,SRC-mitre-t1528 -->

## Description

OAuth bearer semantics make possession sufficient to use a token; unlike sender-constrained credentials, the bearer need not prove possession of a separate key. The token still carries constraints such as audience, scope, subject, and validity. <!-- SAF-TRACE: claims=SAF-T1706-C001,SAF-T1706-C015; sources=SRC-rfc6750,SRC-rfc9700 -->

In the defining flow, an adversary who has already captured a token presents it to a protected resource from a different workload or context. Lateral access succeeds only if the resource accepts the token for its existing authority. The full OAuth-MCP flow is an evidence-backed inference, not a documented direct production incident. <!-- SAF-TRACE: claims=SAF-T1706-C004,SAF-T1706-C009; sources=SRC-rfc6750,SRC-mcp-authorization-2025-11-25,SRC-nvd-search-corpus -->

MCP requires clients to request resource-bound tokens and servers to validate that tokens were issued for them. CVE-2026-14541 provides direct implementation evidence that omitting the audience or client guard in Google mcp-toolbox 1.4.0 could allow OAuth tokens minted for unrelated applications to reach protected tools and data. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C006,SAF-T1706-C017; sources=SRC-mcp-authorization-2025-11-25,SRC-nvd-cve-2026-14541,SRC-google-pr3450 -->

## Attack Vectors

- **Primary Vector**: Present a previously captured OAuth access token to an MCP or agent-connected protected resource that accepts it. <!-- SAF-TRACE: claims=SAF-T1706-C004; sources=SRC-rfc6750,SRC-mcp-authorization-2025-11-25 -->
- **Secondary Vector**: Reuse the token at a different resource when audience restriction or validation is absent. <!-- SAF-TRACE: claims=SAF-T1706-C002,SAF-T1706-C011; sources=SRC-rfc9700,SRC-rfc8707 -->
- **Affected Components**: MCP clients, hosts, and servers; authorization servers; agent-connected SaaS, cloud, database, and administrative APIs. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C004; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc6750 -->
- **Trust Boundary Crossed**: The boundary between the component authorized to hold the token and the resource that treats possession as authority. <!-- SAF-TRACE: claims=SAF-T1706-C001,SAF-T1706-C004; sources=SRC-rfc6750 -->

## Technical Details

### Prerequisites

- The adversary already possesses a valid OAuth bearer access token; how it was acquired is outside this technique. <!-- SAF-TRACE: claims=SAF-T1706-C001,SAF-T1706-C014; sources=SRC-rfc6750,SRC-mitre-t1528 -->
- A reachable protected resource accepts the token for the target audience, or fails to enforce the correct audience. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-nvd-cve-2026-14541 -->
- The token remains valid and provides useful subject privileges and scopes; sender constraint does not prevent the new presenter. <!-- SAF-TRACE: claims=SAF-T1706-C010,SAF-T1706-C015; sources=SRC-rfc9449,SRC-rfc6750 -->

### Attack Flow

1. **Setup**: Identify a protected resource reachable from the adversary's context and a captured access token whose authority may be accepted there. <!-- SAF-TRACE: claims=SAF-T1706-C004,SAF-T1706-C015; sources=SRC-rfc6750,SRC-mcp-authorization-2025-11-25 -->
2. **Presentation**: Send the captured bearer token as authentication material; possession, not a separate key proof, authorizes bearer use. <!-- SAF-TRACE: claims=SAF-T1706-C001; sources=SRC-rfc6750 -->
3. **Validation**: The resource accepts the token for its intended audience or incorrectly omits the audience check. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-nvd-cve-2026-14541 -->
4. **Boundary Crossing**: Authentication moves from the original token-holding component to the adversary-controlled presenter at the protected resource. <!-- SAF-TRACE: claims=SAF-T1706-C004; sources=SRC-rfc6750,SRC-rfc9700 -->
5. **Objective**: The adversary receives the token subject's existing resource access; follow-on activity is outside this contract. <!-- SAF-TRACE: claims=SAF-T1706-C004,SAF-T1706-C015; sources=SRC-rfc6750 -->

### Safe Example Scenario

A synthetic workload labeled `workload-b` presents only the irreversible fingerprint `sha256:synthetic-a` to `resource-b`. An accepted event with `audience_match=false`, or the same fingerprint from distinct presenters within the analytic window, illustrates the observable without publishing a token, endpoint, payload, or follow-on command. <!-- SAF-TRACE: claims=SAF-T1706-C012; sources=SRC-rfc7662,SRC-mitre-t1550-001 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitation |
| --- | --- | --- | --- | --- |
| SAF-T1706-C001 | Bearer possession is sufficient for token use without a separate key proof. | Research-Derived | SRC-rfc6750: RFC 6750 | Authority remains bounded by token constraints. |
| SAF-T1706-C002 | OAuth identifies redirect and replay threats and recommends audience and sender constraints. | Research-Derived | SRC-rfc6750; SRC-rfc9700 | Standards are not incident evidence. |
| SAF-T1706-C003 | MCP requires resource-bound token requests, audience validation, and no token passthrough. | Research-Derived | SRC-mcp-authorization-2025-11-25; SRC-mcp-security-2025-11-25 | Implementations may be nonconformant. |
| SAF-T1706-C004 | Cross-presenter replay can move an adversary into a resource that accepts the token. | Research-Derived | SRC-rfc6750; SRC-rfc9700; SRC-mcp-authorization-2025-11-25 | Explicit inference; no direct production OAuth-MCP incident. |
| SAF-T1706-C005 | A controlled MCP demonstration replayed a Kubernetes bearer token to its API. | Demonstrated | SRC-ghsa-6mx4-4h42-r8vh; SRC-nvd-cve-2026-47250 | Credential was not established as OAuth. |
| SAF-T1706-C006 | mcp-toolbox 1.4.0 could accept Google OAuth tokens for unrelated applications. | Research-Derived | SRC-nvd-cve-2026-14541; SRC-google-pr3450 | No reported production exploitation or end-to-end transcript. |
| SAF-T1706-C007 | UNC6395 used stolen Drift OAuth tokens against connected Salesforce and Workspace resources. | Observed | SRC-google-gtig-drift; SRC-salesloft-drift-update | SaaS integration incident, not MCP. |
| SAF-T1706-C008 | Stolen Heroku and Travis CI OAuth tokens authenticated to GitHub and exposed repositories. | Observed | SRC-github-oauth-incident-2022 | Predates MCP. |
| SAF-T1706-C009 | No direct production OAuth-MCP replay incident was found in the bounded corpus. | Research-Derived | SRC-nvd-search-corpus; SRC-cisa-kev-catalog-page-2026-09-01 | Bounded absence, not proof of nonoccurrence. |
| SAF-T1706-C010 | DPoP binds token use to a key and request proof, reducing token-only replay. | Research-Derived | SRC-rfc9449; SRC-rfc9700 | Does not help if token and key or client context are both compromised. |
| SAF-T1706-C011 | Resource indicators constrain audience; multi-audience bearer tokens require high trust. | Research-Derived | SRC-rfc8707; SRC-rfc9068 | Same-resource replay remains possible. |
| SAF-T1706-C012 | Fingerprint, audience, resource, presenter, and time correlation can detect suspicious reuse. | Research-Derived | SRC-rfc7662; SRC-mitre-t1550-001; SRC-mcp-authorization-2025-11-25 | Behavior-based and telemetry-dependent. |
| SAF-T1706-C013 | Revocation can invalidate an access token, subject to enforcement propagation and server policy. | Research-Derived | SRC-rfc7009 | Deployment behavior varies. |
| SAF-T1706-C014 | Token use maps directly to ATT&CK T1550.001; acquisition is adjacent T1528. | Research-Derived | SRC-mitre-t1550-001; SRC-mitre-t1528 | ATT&CK is broader than MCP. |
| SAF-T1706-C015 | Impact is bounded by token and resource constraints. | Research-Derived | SRC-rfc6750; SRC-rfc9700; SRC-ghsa-6mx4-4h42-r8vh | Severity is deployment-specific. |
| SAF-T1706-C016 | Response combines containment, revocation, evidence preservation, connected-resource review, and secret rotation. | Research-Derived | SRC-google-gtig-drift; SRC-github-oauth-incident-2022; SRC-rfc7009 | Exact procedure is deployment-specific. |
| SAF-T1706-C017 | Direct and adjacent vulnerabilities have documented fixed versions. | Research-Derived | SRC-nvd-cve-2026-14541; SRC-google-pr3450; SRC-ghsa-6mx4-4h42-r8vh; SRC-release-mcp-k8s-3.7.0 | Downstream patch state is unknown. |
| SAF-T1706-C018 | Selected CVEs were absent from the reviewed KEV version; NVD recorded none versus PoC exploitation. | Research-Derived | SRC-cisa-kev-catalog-page-2026-09-01; SRC-nvd-cve-2026-14541; SRC-nvd-cve-2026-47250 | Status can change after review. |

### Current State

- **Affected Environments**: OAuth-enabled MCP and agent-connected resources that accept bearer tokens and lack correct resource, audience, or presenter constraints. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-nvd-cve-2026-14541 -->
- **Known Exploitation**: The direct MCP CVE had no reported exploitation; the adjacent Kubernetes record had a controlled proof of concept. Neither selected CVE appeared in CISA KEV version 2026.09.01. <!-- SAF-TRACE: claims=SAF-T1706-C018; sources=SRC-cisa-kev-catalog-page-2026-09-01,SRC-nvd-cve-2026-14541,SRC-nvd-cve-2026-47250 -->
- **Available Protections**: Correct audience validation, resource indicators, sender-constrained tokens, patched implementations, and token revocation. <!-- SAF-TRACE: claims=SAF-T1706-C010,SAF-T1706-C011,SAF-T1706-C013,SAF-T1706-C017; sources=SRC-rfc9449,SRC-rfc8707,SRC-rfc7009,SRC-google-pr3450 -->
- **Residual Risk**: Bearer replay can remain possible at the intended resource, and sender constraint fails if the proof key or legitimate execution context is also compromised. <!-- SAF-TRACE: claims=SAF-T1706-C010,SAF-T1706-C011; sources=SRC-rfc9449,SRC-rfc8707 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-14541 | 2026; Google mcp-toolbox 1.4.0 without audience or client configuration | Unrelated-app OAuth tokens could reach protected tools and data; guard merged for 1.5.0. | Direct vulnerability | No production exploitation or end-to-end replay transcript was reported. | <!-- SAF-TRACE: claims=SAF-T1706-C006,SAF-T1706-C017,SAF-T1706-C018; sources=SRC-nvd-cve-2026-14541,SRC-google-pr3450 -->
| CVE-2026-47250 / GHSA-6mx4-4h42-r8vh | 2026; mcp-server-kubernetes before 3.7.0 | Controlled token exposure and API replay; fixed in 3.7.0. | Adjacent demonstration and vulnerability | Kubernetes bearer credential was not established as OAuth. | <!-- SAF-TRACE: claims=SAF-T1706-C005,SAF-T1706-C017; sources=SRC-ghsa-6mx4-4h42-r8vh,SRC-nvd-cve-2026-47250,SRC-release-mcp-k8s-3.7.0 -->
| UNC6395 Salesloft Drift compromise | 2025; connected Salesforce and limited Workspace accounts | Stolen OAuth tokens enabled data access; revocation, rotation, and connected-app investigation were advised. | Historical analogy | Sources did not establish MCP; Salesloft AI agents were not implicated. | <!-- SAF-TRACE: claims=SAF-T1706-C007,SAF-T1706-C016; sources=SRC-google-gtig-drift,SRC-salesloft-drift-update -->
| Heroku and Travis CI OAuth token theft | 2022; GitHub and downstream npm infrastructure | Stolen tokens exposed private repositories; GitHub revoked tokens and supported investigation and rotation. | Historical analogy | Predates MCP and agentic authorization flows. | <!-- SAF-TRACE: claims=SAF-T1706-C008,SAF-T1706-C016; sources=SRC-github-oauth-incident-2022 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Data readable by the token subject and scopes can be exposed when the resource accepts replay. | <!-- SAF-TRACE: claims=SAF-T1706-C007,SAF-T1706-C008,SAF-T1706-C015; sources=SRC-google-gtig-drift,SRC-github-oauth-incident-2022,SRC-rfc6750 -->
| Integrity | High | Write-capable tokens can alter protected resource state, but read-only scopes bound this consequence. | <!-- SAF-TRACE: claims=SAF-T1706-C015; sources=SRC-rfc6750,SRC-rfc9700 -->
| Availability | Low | Replay alone does not require disruption; availability impact depends on token-enabled operations and follow-on actions. | <!-- SAF-TRACE: claims=SAF-T1706-C015; sources=SRC-rfc6750 -->
| Scope | Multi-System | Multi-audience or broadly connected tokens can cross resources, while audience, scope, expiration, and sender constraint limit blast radius. | <!-- SAF-TRACE: claims=SAF-T1706-C011,SAF-T1706-C015; sources=SRC-rfc8707,SRC-rfc9700 -->

### Severity Conditions

- **Severity increases when**: Tokens are long-lived, broadly scoped, multi-audience, or accepted by sensitive connected resources without sender constraint. <!-- SAF-TRACE: claims=SAF-T1706-C010,SAF-T1706-C011,SAF-T1706-C015; sources=SRC-rfc9449,SRC-rfc8707,SRC-rfc6750 -->
- **Severity decreases when**: Tokens are short-lived, single-resource, least-privileged, sender-constrained, promptly revocable, and continuously monitored. <!-- SAF-TRACE: claims=SAF-T1706-C010,SAF-T1706-C011,SAF-T1706-C013; sources=SRC-rfc9449,SRC-rfc8707,SRC-rfc7009 -->

## Detection Methods

### Required Telemetry

| Source | Events | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Protected-resource authentication logs | Accepted and rejected OAuth token presentations | Timestamp, resource, audience-match result, non-reversible token fingerprint, presenter, result | Derive fingerprints consistently without retaining bearer material. | <!-- SAF-TRACE: claims=SAF-T1706-C012; sources=SRC-rfc7662,SRC-mitre-t1550-001 -->
| Authorization and workload identity logs | Token issuance or introspection and presenter identity | Subject, client, audience, issue/expiry time, token identifier or fingerprint, sender-constraint state | Normalize clocks and client-instance groups before correlation. | <!-- SAF-TRACE: claims=SAF-T1706-C010,SAF-T1706-C012; sources=SRC-rfc9449,SRC-rfc7662 -->

### Behavioral Indicators

- A resource accepts a token whose audience does not match that resource. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7662 -->
- The same non-reversible token fingerprint succeeds from distinct presenters or resources within a short window. <!-- SAF-TRACE: claims=SAF-T1706-C012; sources=SRC-mitre-t1550-001,SRC-rfc7662 -->
- Confidence increases when reuse lacks an approved handoff or shared logical client group and crosses resource or workload boundaries. <!-- SAF-TRACE: claims=SAF-T1706-C012,SAF-T1706-C015; sources=SRC-mitre-t1550-001,SRC-rfc6750 -->

### Detection Analytic

The standalone normalized analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect accepted audience mismatch or reuse of one token fingerprint across distinct presenters or resources. <!-- SAF-TRACE: claims=SAF-T1706-C012; sources=SRC-mitre-t1550-001,SRC-rfc7662 -->
- **Rule Status**: Experimental; the local test suite passes, but thresholds and identity grouping require deployment tuning. <!-- SAF-TRACE: claims=SAF-T1706-C012; sources=SRC-mitre-t1550-001 -->
- **Correlation Window**: Ten minutes inclusive, with a 601-second negative boundary test. <!-- SAF-TRACE: claims=SAF-T1706-C012; sources=SRC-mitre-t1550-001 -->
- **Known False Positives**: Approved handoffs, gateway failover, horizontally scaled client instances, clock skew, and inconsistent fingerprint derivation. <!-- SAF-TRACE: claims=SAF-T1706-C012; sources=SRC-rfc7662,SRC-mitre-t1550-001 -->
- **Known Limitations**: Missing audience or presenter telemetry, opaque tokens without stable fingerprints, incomplete resource logs, and attacker use inside the legitimate client context reduce visibility. <!-- SAF-TRACE: claims=SAF-T1706-C010,SAF-T1706-C012; sources=SRC-rfc9449,SRC-rfc7662 -->

### Validation

- **Test Cases**: [test-cases.json](../../tests/SAF-T1706/test-cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1706/test_detection_rule.py)
- **Test Result**: [test-logs.json](../../tests/SAF-T1706/test-logs.json)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Require the OAuth resource indicator and validate that every token was issued for the receiving protected resource. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C011; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc8707 -->
2. **[SAF-M-31: Proof of Possession Tokens](../../mitigations/SAF-M-31/README.md)**: Use DPoP or another supported sender constraint so token possession alone is insufficient. <!-- SAF-TRACE: claims=SAF-T1706-C010; sources=SRC-rfc9449,SRC-rfc9700 -->
3. **Patch affected implementations**: Upgrade mcp-toolbox to 1.5.0 or later and mcp-server-kubernetes to 3.7.0 or later where applicable. <!-- SAF-TRACE: claims=SAF-T1706-C017; sources=SRC-google-pr3450,SRC-release-mcp-k8s-3.7.0 -->

### Detective Controls

1. **[SAF-M-19: Token Usage Tracking](../../mitigations/SAF-M-19/README.md)**: Retain privacy-preserving token fingerprints and correlate accepted uses across audiences, resources, presenters, and time. <!-- SAF-TRACE: claims=SAF-T1706-C012; sources=SRC-rfc7662,SRC-mitre-t1550-001 -->
2. **Validate and alert at the protected resource**: Treat any accepted audience mismatch as a control failure and tune cross-presenter reuse against approved handoffs and logical client groups. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-mitre-t1550-001 -->

### Response Procedures

- Apply [SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37/README.md): contain the presenting workload, revoke affected tokens and grants, and account for authorization-server propagation delay. <!-- SAF-TRACE: claims=SAF-T1706-C013,SAF-T1706-C016; sources=SRC-rfc7009,SRC-google-gtig-drift -->
- Preserve authentication and API logs, investigate every connected resource reached by the identity, and rotate secrets exposed through accessed data. <!-- SAF-TRACE: claims=SAF-T1706-C016; sources=SRC-google-gtig-drift,SRC-github-oauth-incident-2022 -->

## Related Techniques

- **[SAF-T1504 — Token Theft via API Response](../SAF-T1504/README.md)**: supplies an API-response acquisition prerequisite; SAF-T1706 begins at token presentation. <!-- SAF-TRACE: claims=SAF-T1706-C014; sources=SRC-mitre-t1528 -->
- **[SAF-T1506 — Infrastructure Token Theft](../SAF-T1506/README.md)**: supplies an infrastructure-token acquisition prerequisite; SAF-T1706 requires an OAuth access token and ends at lateral authentication. <!-- SAF-TRACE: claims=SAF-T1706-C014; sources=SRC-mitre-t1528 -->
- **[SAF-T1304 — Credential Relay Chain](../SAF-T1304/README.md)**: covers broader propagation or substitution of credentials across an authorization boundary; SAF-T1706 specifically requires replay of a captured OAuth access token by a different presenter. <!-- SAF-TRACE: claims=SAF-T1706-C003; sources=SRC-mcp-security-2025-11-25 -->
- **[SAF-T1308 — Token Scope Substitution](../SAF-T1308/README.md)**: covers grant, scope, or audience misbinding; SAF-T1706 additionally requires adversarial presentation of a captured token as authentication material. <!-- SAF-TRACE: claims=SAF-T1706-C003,SAF-T1706-C004,SAF-T1706-C011; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc8707 -->

## MITRE ATT&CK Mapping

- **T1550.001 – Use Alternate Authentication Material: Application Access Token**: Direct mapping because the defining behavior uses an application access token for authentication. <!-- SAF-TRACE: claims=SAF-T1706-C014; sources=SRC-mitre-t1550-001 -->
- **T1528 – Steal Application Access Token**: Adjacent prerequisite mapping only; acquisition is outside SAF-T1706. <!-- SAF-TRACE: claims=SAF-T1706-C014; sources=SRC-mitre-t1528 -->

## References

- SRC-rfc6750: [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html)
- SRC-rfc9700: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- SRC-rfc8707: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)
- SRC-rfc9449: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)
- SRC-rfc7662: [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)
- SRC-rfc9068: [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)
- SRC-rfc7009: [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html)
- SRC-mcp-authorization-2025-11-25: [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- SRC-mcp-security-2025-11-25: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)
- SRC-nvd-cve-2026-14541: [NVD CVE-2026-14541](https://nvd.nist.gov/vuln/detail/CVE-2026-14541)
- SRC-google-pr3450: [Google mcp-toolbox PR 3450](https://github.com/googleapis/mcp-toolbox/pull/3450)
- SRC-nvd-cve-2026-47250: [NVD CVE-2026-47250](https://nvd.nist.gov/vuln/detail/CVE-2026-47250)
- SRC-ghsa-6mx4-4h42-r8vh: [GHSA-6mx4-4h42-r8vh](https://github.com/Flux159/mcp-server-kubernetes/security/advisories/GHSA-6mx4-4h42-r8vh)
- SRC-release-mcp-k8s-3.7.0: [mcp-server-kubernetes v3.7.0](https://github.com/Flux159/mcp-server-kubernetes/releases/tag/v3.7.0)
- SRC-google-gtig-drift: [Google Threat Intelligence Group Drift report](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift/)
- SRC-salesloft-drift-update: [Salesloft Drift incident updates](https://trust.salesloft.com/?uid=Drift%2FSalesforce+Security+Notification)
- SRC-github-oauth-incident-2022: [GitHub OAuth token incident](https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/)
- SRC-mitre-t1550-001: [MITRE ATT&CK T1550.001](https://attack.mitre.org/techniques/T1550/001/)
- SRC-mitre-t1528: [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
- SRC-cisa-kev-catalog-page-2026-09-01: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- SRC-nvd-search-corpus: [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0/)

## Version History

| Version | Date | Changes |
| --- | --- | --- |
| 1.0 | 2026-09-02 | Clean-room research-derived technique, detector, and evidence packet prepared for mechanical integration. |
