# SAF-T1202: OAuth Token Persistence

## Overview

- **Tactic**: Persistence (ATK-TA0003) <!-- SAF-TRACE: claims=SAF-T1202-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700 -->
- **Technique ID**: SAF-T1202
- **Research Packet**: [research/techniques/SAF-T1202](../../research/techniques/SAF-T1202/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1202/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: High <!-- SAF-TRACE: claims=SAF-T1202-C019; sources=SRC-rfc9700,SRC-ghsa-pw9m-5jxm-xr6h -->
- **Severity Rationale**: A renewed token can preserve the original grant's authorized reach; consequence depends on scope, resource capabilities, and approval controls. <!-- SAF-TRACE: claims=SAF-T1202-C019; sources=SRC-rfc9700,SRC-ghsa-pw9m-5jxm-xr6h -->
- **First Observed**: Not observed end-to-end in an MCP production incident as of 2026-09-01; see the [source-coverage assessment](../../research/techniques/SAF-T1202/source-coverage.yml).
- **Last Updated**: 2026-09-01

## Scope

This technique covers an adversary using an attacker-controlled OAuth refresh token to obtain replacement access tokens for an MCP protected resource, preserving the existing client, subject, scope, and resource grant across access-token lifetimes. <!-- SAF-TRACE: claims=SAF-T1202-C004,SAF-T1202-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700,SRC-google-oauth-token-mitigation -->

### In Scope

- Replay or reuse of an already issued refresh token at the authorization server's token endpoint. <!-- SAF-TRACE: claims=SAF-T1202-C004,SAF-T1202-C005; sources=SRC-rfc9700,SRC-mcp-authorization-2026-07-28 -->
- Continued authorized-looking access after an access token expires or the originally compromised endpoint is contained. <!-- SAF-TRACE: claims=SAF-T1202-C005,SAF-T1202-C017; sources=SRC-rfc9700,SRC-google-oauth-token-mitigation -->

### Out of Scope

- Theft, phishing, logging, or exfiltration that initially acquires the token. <!-- SAF-TRACE: claims=SAF-T1202-C014; sources=SRC-mitre-t1550-001 -->
- Registering or consenting to a malicious OAuth application, which creates or changes an integration. <!-- SAF-TRACE: claims=SAF-T1202-C015; sources=SRC-mitre-ta0003,SRC-ms-app-consent-playbook -->
- Subsequent MCP tool actions, collection, or exfiltration performed with a renewed access token. <!-- SAF-TRACE: claims=SAF-T1202-C019; sources=SRC-rfc9700,SRC-ghsa-pw9m-5jxm-xr6h -->

### Distinguishing Characteristics

The defining observable is a refresh grant that renews access under an existing authorization. Token acquisition ends before that exchange, while malicious application persistence changes the integration or consent state; the exact boundaries are documented in the [contract](../../research/techniques/SAF-T1202/technique-contract.yml). <!-- SAF-TRACE: claims=SAF-T1202-C014,SAF-T1202-C015; sources=SRC-mitre-t1550-001,SRC-mitre-ta0003,SRC-ms-app-consent-playbook -->

## Description

MCP HTTP authorization places the client, authorization server, and protected MCP resource in separate roles. The client presents an access token to the MCP resource, while refresh-token issuance remains an authorization-server decision. <!-- SAF-TRACE: claims=SAF-T1202-C001,SAF-T1202-C002; sources=SRC-mcp-authorization-2026-07-28 -->

If an attacker can successfully replay an unrevoked refresh token, OAuth permits the attacker to mint replacement access tokens on behalf of the resource owner. Applied to MCP, that renewal can preserve access without repeating the interactive authorization flow, subject to client binding, resource, scope, expiry, and revocation controls. <!-- SAF-TRACE: claims=SAF-T1202-C004,SAF-T1202-C005,SAF-T1202-C013; sources=SRC-rfc9700,SRC-mcp-authorization-2026-07-28,SRC-google-oauth-token-mitigation -->

This end-to-end MCP behavior is classified as Research-Derived. A disclosed Better Auth flaw directly affected an MCP plugin, controlled research demonstrated refresh-token injection in a non-MCP SDK, and cloud guidance documents renewal persistence; reviewed production incidents did not expose the full MCP refresh sequence. <!-- SAF-TRACE: claims=SAF-T1202-C006,SAF-T1202-C017,SAF-T1202-C020; sources=SRC-ghsa-pw9m-5jxm-xr6h,SRC-google-oauth-token-mitigation,SRC-usenix-s3kvetter-2018 -->

## Attack Vectors

- **Primary Vector**: Present an attacker-controlled, still-valid refresh token to the authorization server and receive a replacement access token. <!-- SAF-TRACE: claims=SAF-T1202-C004,SAF-T1202-C005; sources=SRC-rfc9700,SRC-mcp-authorization-2026-07-28 -->
- **Secondary Vectors**: Abuse missing confidential-client authentication or an incomplete account-deactivation revocation path. <!-- SAF-TRACE: claims=SAF-T1202-C006,SAF-T1202-C007; sources=SRC-ghsa-pw9m-5jxm-xr6h,SRC-nvd-cve-2026-9571 -->
- **Affected Components**: MCP client token store, OAuth authorization-server token endpoint and grant records, and MCP resource server. <!-- SAF-TRACE: claims=SAF-T1202-C001,SAF-T1202-C003; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-auth-security-2026-07-28 -->
- **Trust Boundary Crossed**: The authorization server accepts possession of refresh material, plus any required client proof, as authority to continue the existing grant. <!-- SAF-TRACE: claims=SAF-T1202-C004,SAF-T1202-C016; sources=SRC-rfc9700,SRC-rfc9449 -->

## Technical Details

### Prerequisites

- The deployment issued a refresh token and the token remains valid for the original client, subject, scope, and resource. <!-- SAF-TRACE: claims=SAF-T1202-C002,SAF-T1202-C004; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700 -->
- The attacker possesses any client authentication or proof material required to redeem it, or the deployment fails to require that proof. <!-- SAF-TRACE: claims=SAF-T1202-C006,SAF-T1202-C016; sources=SRC-ghsa-pw9m-5jxm-xr6h,SRC-rfc9449 -->
- Expiration, revocation, rotation, or identity-lifecycle controls have not already terminated the grant. <!-- SAF-TRACE: claims=SAF-T1202-C007,SAF-T1202-C016; sources=SRC-nvd-cve-2026-9571,SRC-rfc9700 -->

### Attack Flow

1. **Setup**: The adversary obtains control of refresh material through an out-of-scope acquisition path. <!-- SAF-TRACE: claims=SAF-T1202-C014; sources=SRC-mitre-t1550-001 -->
2. **Renewal**: The adversary submits a refresh grant for the existing client and resource. <!-- SAF-TRACE: claims=SAF-T1202-C004,SAF-T1202-C005; sources=SRC-rfc9700,SRC-mcp-authorization-2026-07-28 -->
3. **Authorization Decision**: The authorization server accepts the grant and issues a new access token, and may rotate the refresh token. <!-- SAF-TRACE: claims=SAF-T1202-C004,SAF-T1202-C010; sources=SRC-rfc9700 -->
4. **Resource Access**: The adversary presents the access token to the intended MCP resource under the original subject and scope. <!-- SAF-TRACE: claims=SAF-T1202-C001,SAF-T1202-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700 -->
5. **Persistence**: The adversary repeats renewal while the token family or grant remains valid. <!-- SAF-TRACE: claims=SAF-T1202-C005,SAF-T1202-C017; sources=SRC-rfc9700,SRC-google-oauth-token-mitigation -->

### Example Scenario

An authorization server records a successful refresh for placeholder family `family-example-002` after `subject-example-002` has become deactivated. The event contains no credential value and uses only inert identifiers; it is one of the deterministic cases in [test-logs.json](../../tests/SAF-T1202/test-logs.json). <!-- SAF-TRACE: claims=SAF-T1202-C007,SAF-T1202-C011; sources=SRC-nvd-cve-2026-9571,SRC-rfc9700 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1202-C001 | MCP HTTP authorization separates client, authorization server, and protected resource roles. | Research-Derived | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Authorization is optional. | <!-- SAF-TRACE: claims=SAF-T1202-C001; sources=SRC-mcp-authorization-2026-07-28 -->
| SAF-T1202-C002 | Refresh tokens are confidential and issuance is discretionary. | Research-Derived | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Issuance policy is provider-specific. | <!-- SAF-TRACE: claims=SAF-T1202-C002; sources=SRC-mcp-authorization-2026-07-28 -->
| SAF-T1202-C003 | Stolen tokens can produce apparently legitimate requests; public clients require rotation. | Research-Derived | SRC-mcp-auth-security-2026-07-28: [MCP Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) | Contextual telemetry may still distinguish use. | <!-- SAF-TRACE: claims=SAF-T1202-C003; sources=SRC-mcp-auth-security-2026-07-28 -->
| SAF-T1202-C004 | Successful refresh-token replay mints access tokens for the resource owner's grant. | Research-Derived | SRC-rfc9700: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Access remains bounded by policy and token controls. | <!-- SAF-TRACE: claims=SAF-T1202-C004; sources=SRC-rfc9700 -->
| SAF-T1202-C005 | Replayable refresh material can preserve MCP access across access-token lifetimes. | Research-Derived | SRC-mcp-authorization-2026-07-28; SRC-rfc9700; SRC-google-oauth-token-mitigation | The end-to-end MCP behavior was not observed in a reviewed production incident. | <!-- SAF-TRACE: claims=SAF-T1202-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700,SRC-google-oauth-token-mitigation -->
| SAF-T1202-C006 | Better Auth before 1.6.11 omitted confidential-client authentication on affected MCP and OIDC refresh grants. | Demonstrated | SRC-ghsa-pw9m-5jxm-xr6h: [GHSA-pw9m-5jxm-xr6h](https://github.com/better-auth/better-auth/security/advisories/GHSA-pw9m-5jxm-xr6h) | The advisory does not establish production exploitation. | <!-- SAF-TRACE: claims=SAF-T1202-C006; sources=SRC-ghsa-pw9m-5jxm-xr6h -->
| SAF-T1202-C007 | A Mattermost deactivation flaw left refresh tokens capable of minting access tokens. | Demonstrated | SRC-nvd-cve-2026-9571: [CVE-2026-9571](https://nvd.nist.gov/vuln/detail/CVE-2026-9571) | Non-MCP; production exploitation was not established. | <!-- SAF-TRACE: claims=SAF-T1202-C007; sources=SRC-nvd-cve-2026-9571 -->
| SAF-T1202-C008 | UNC6395 used compromised Drift-associated OAuth tokens and responders revoked both token types. | Observed | SRC-gtig-drift-2025; SRC-salesloft-drift-2026 | The sources do not identify a refresh exchange. | <!-- SAF-TRACE: claims=SAF-T1202-C008; sources=SRC-gtig-drift-2025,SRC-salesloft-drift-2026 -->
| SAF-T1202-C009 | Attackers used stolen Heroku and Travis CI OAuth user tokens against GitHub organizations. | Observed | SRC-github-oauth-incident-2022 | The report does not identify MCP or refresh exchange. | <!-- SAF-TRACE: claims=SAF-T1202-C009; sources=SRC-github-oauth-incident-2022 -->
| SAF-T1202-C010 | Rotation detects competing reuse but cannot identify which party submitted the invalidated token. | Research-Derived | SRC-rfc9700 | Detection requires family state and competing use. | <!-- SAF-TRACE: claims=SAF-T1202-C010; sources=SRC-rfc9700 -->
| SAF-T1202-C011 | Successful refresh after disablement or with detected family reuse is a high-confidence signal. | Research-Derived | SRC-rfc9700; SRC-nvd-cve-2026-9571; SRC-mitre-t1550-001; SRC-ms-entra-risk-detections-2026 | Lifecycle errors and retries can resemble abuse. | <!-- SAF-TRACE: claims=SAF-T1202-C011; sources=SRC-rfc9700,SRC-nvd-cve-2026-9571,SRC-mitre-t1550-001,SRC-ms-entra-risk-detections-2026 -->
| SAF-T1202-C012 | Response must revoke affected grants or families and account for residual access-token validity. | Research-Derived | SRC-google-oauth-token-mitigation; SRC-ms-token-tactics-2022; SRC-rfc7009 | Provider behavior varies. | <!-- SAF-TRACE: claims=SAF-T1202-C012; sources=SRC-google-oauth-token-mitigation,SRC-ms-token-tactics-2022,SRC-rfc7009 -->
| SAF-T1202-C013 | Audience and scope restriction constrain blast radius but do not stop use at the intended resource. | Research-Derived | SRC-mcp-authorization-2026-07-28; SRC-rfc9700 | These controls are not proof of possession. | <!-- SAF-TRACE: claims=SAF-T1202-C013; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700 -->
| SAF-T1202-C014 | ATT&CK T1550.001 includes long-term access through OAuth refresh tokens. | Research-Derived | SRC-mitre-t1550-001 | ATT&CK is broader and maps the behavior outside Persistence. | <!-- SAF-TRACE: claims=SAF-T1202-C014; sources=SRC-mitre-t1550-001 -->
| SAF-T1202-C015 | Creating an OAuth integration is distinct from reusing an existing refresh grant. | Research-Derived | SRC-mitre-ta0003; SRC-ms-app-consent-playbook | The behaviors may co-occur. | <!-- SAF-TRACE: claims=SAF-T1202-C015; sources=SRC-mitre-ta0003,SRC-ms-app-consent-playbook -->
| SAF-T1202-C016 | Sender constraint, rotation, expiry, and revocation reduce replay or duration. | Research-Derived | SRC-rfc9700; SRC-rfc9449 | Rotation needs competing use; sender constraint depends on key protection. | <!-- SAF-TRACE: claims=SAF-T1202-C016; sources=SRC-rfc9700,SRC-rfc9449 -->
| SAF-T1202-C017 | Google Cloud documents persistence from copied refresh tokens and victim-attributed logging. | Demonstrated | SRC-google-oauth-token-mitigation | Product guidance, not an MCP incident. | <!-- SAF-TRACE: claims=SAF-T1202-C017; sources=SRC-google-oauth-token-mitigation -->
| SAF-T1202-C018 | An attacker solely controlling the latest token may evade rotation-reuse detection. | Research-Derived | SRC-rfc9700; SRC-rfc10017; SRC-mitre-t1550-001 | Provider risk engines may expose other signals. | <!-- SAF-TRACE: claims=SAF-T1202-C018; sources=SRC-rfc9700,SRC-rfc10017,SRC-mitre-t1550-001 -->
| SAF-T1202-C019 | Impact is bounded by the renewed token's permissions and available resource actions. | Research-Derived | SRC-rfc9700; SRC-ghsa-pw9m-5jxm-xr6h | Scope and server controls determine consequence. | <!-- SAF-TRACE: claims=SAF-T1202-C019; sources=SRC-rfc9700,SRC-ghsa-pw9m-5jxm-xr6h -->
| SAF-T1202-C020 | Peer-reviewed research demonstrated refresh-token injection and post-expiry renewal. | Demonstrated | SRC-usenix-s3kvetter-2018: [USENIX Security 2018 paper](https://www.usenix.org/conference/usenixsecurity18/presentation/yang) | Non-MCP and dependent on stated identity-provider or acquisition prerequisites. | <!-- SAF-TRACE: claims=SAF-T1202-C020; sources=SRC-usenix-s3kvetter-2018 -->

### Current State

- **Affected Environments**: MCP deployments that issue bearer refresh tokens and authorization systems with replayable, insufficiently bound, or incompletely revoked grants. <!-- SAF-TRACE: claims=SAF-T1202-C002,SAF-T1202-C006,SAF-T1202-C007; sources=SRC-mcp-authorization-2026-07-28,SRC-ghsa-pw9m-5jxm-xr6h,SRC-nvd-cve-2026-9571 -->
- **Known Exploitation**: Controlled and vulnerability evidence establishes renewal behavior; reviewed production incidents establish adjacent token abuse but not the complete MCP renewal sequence. <!-- SAF-TRACE: claims=SAF-T1202-C006,SAF-T1202-C008,SAF-T1202-C020; sources=SRC-ghsa-pw9m-5jxm-xr6h,SRC-gtig-drift-2025,SRC-usenix-s3kvetter-2018 -->
- **Available Protections**: Sender constraint, rotation, bounded lifetime, revocation, and resource/scope restriction. <!-- SAF-TRACE: claims=SAF-T1202-C013,SAF-T1202-C016; sources=SRC-rfc9700,SRC-rfc9449 -->
- **Residual Risk**: Rotation may not alert when the legitimate client never presents an older family member. <!-- SAF-TRACE: claims=SAF-T1202-C018; sources=SRC-rfc9700,SRC-rfc10017 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| GHSA-pw9m-5jxm-xr6h / CVE-2026-53512 | 2026; Better Auth before 1.6.11, including the legacy MCP plugin | Valid refresh material could mint access and rotated refresh tokens; fixed in 1.6.11. | Direct vulnerability | No production exploitation reported by the reviewed advisory. | <!-- SAF-TRACE: claims=SAF-T1202-C006; sources=SRC-ghsa-pw9m-5jxm-xr6h -->
| CVE-2026-9571 | 2026; affected Mattermost releases | Deactivated users retained renewal capability; fixed versions begin at 10.11.20, 11.6.5, 11.7.3, and 11.8.0. | Direct vulnerability | Non-MCP and no production exploitation established. | <!-- SAF-TRACE: claims=SAF-T1202-C007; sources=SRC-nvd-cve-2026-9571 -->
| Refresh-token injection study | 2018; evaluated SSO SDK | Injected refresh material renewed access after expiry under stated prerequisites. | Direct demonstration | Non-MCP controlled research. | <!-- SAF-TRACE: claims=SAF-T1202-C020; sources=SRC-usenix-s3kvetter-2018 -->
| UNC6395 Drift compromise | August 2025; Salesforce and Google Workspace integrations | Stolen OAuth tokens enabled data access; responders revoked access and refresh tokens. | Adjacent production incident | No refresh exchange identified. | <!-- SAF-TRACE: claims=SAF-T1202-C008; sources=SRC-gtig-drift-2025,SRC-salesloft-drift-2026 -->

### Research and Incident Attribution

- Clean-room technique author and analytic implementer: OpenAI Codex research agent, recorded in the [quality review](../../research/techniques/SAF-T1202/quality-review.yml).
- Refresh-token injection research: Ronghai Yang, Wing Cheong Lau, Jiongyi Chen, and Kehuan Zhang. <!-- SAF-TRACE: claims=SAF-T1202-C020; sources=SRC-usenix-s3kvetter-2018 -->
- UNC6395 reporting: Google Threat Intelligence Group and Mandiant authors Austin Larsen, Matt Lin, Tyler McLellan, and Omar ElAhdan, corroborated by Salesloft's incident team. <!-- SAF-TRACE: claims=SAF-T1202-C008; sources=SRC-gtig-drift-2025,SRC-salesloft-drift-2026 -->
- Better Auth advisory credit: Gustavo Valverde, with discovery reported by subhanUmer. <!-- SAF-TRACE: claims=SAF-T1202-C006; sources=SRC-ghsa-pw9m-5jxm-xr6h -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Renewed access can expose data reachable within the existing token's scope. | <!-- SAF-TRACE: claims=SAF-T1202-C019; sources=SRC-rfc9700,SRC-ghsa-pw9m-5jxm-xr6h -->
| Integrity | High | Renewed access can alter state only where the grant and MCP resource authorize write actions. | <!-- SAF-TRACE: claims=SAF-T1202-C019; sources=SRC-rfc9700,SRC-ghsa-pw9m-5jxm-xr6h -->
| Availability | Medium | Disruption requires an authorized destructive or resource-intensive action. | <!-- SAF-TRACE: claims=SAF-T1202-C019; sources=SRC-rfc9700,SRC-ghsa-pw9m-5jxm-xr6h -->
| Scope | Adjacent | Audience, resource, and scope binding limit reach to the intended grant and resource. | <!-- SAF-TRACE: claims=SAF-T1202-C013,SAF-T1202-C019; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700 -->

### Severity Conditions

- **Severity increases when** broad scopes, sensitive MCP resources, long refresh lifetimes, weak sender binding, and incomplete lifecycle revocation coincide. <!-- SAF-TRACE: claims=SAF-T1202-C016,SAF-T1202-C019; sources=SRC-rfc9700,SRC-rfc9449 -->
- **Severity decreases when** scopes and audiences are narrow, refresh tokens are sender-constrained and short-lived, and grants are revoked on security events. <!-- SAF-TRACE: claims=SAF-T1202-C013,SAF-T1202-C016; sources=SRC-rfc9700,SRC-rfc9449 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| OAuth authorization server | Token refresh and family-reuse decision | timestamp, action, outcome, grant type, client ID, subject ID, token-family ID, reuse flag | Preserve family state and normalized success/failure results. | <!-- SAF-TRACE: claims=SAF-T1202-C010,SAF-T1202-C011; sources=SRC-rfc9700,SRC-mitre-t1550-001 -->
| Identity lifecycle system | Disable, deactivate, revoke, and restore | subject ID, account status, effective time, grant status | Correlate status as it existed when the refresh was evaluated. | <!-- SAF-TRACE: claims=SAF-T1202-C007,SAF-T1202-C011; sources=SRC-nvd-cve-2026-9571,SRC-ms-entra-risk-detections-2026 -->

### Indicators of Compromise (IoCs)

- No universal durable artifact identifies this behavior; provider-specific token-family identifiers are sensitive correlation keys rather than portable indicators. <!-- SAF-TRACE: claims=SAF-T1202-C003,SAF-T1202-C011; sources=SRC-mcp-auth-security-2026-07-28,SRC-ms-entra-risk-detections-2026 -->

### Behavioral Indicators

- A successful refresh grant after the subject or grant became disabled or revoked. <!-- SAF-TRACE: claims=SAF-T1202-C007,SAF-T1202-C011; sources=SRC-nvd-cve-2026-9571,SRC-rfc9700 -->
- Server-detected use of an invalidated member of a refresh-token family, correlated with a successful renewal event. <!-- SAF-TRACE: claims=SAF-T1202-C010,SAF-T1202-C011; sources=SRC-rfc9700,SRC-mitre-t1550-001 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Alert on successful OAuth renewal after identity disablement or with detected family reuse. <!-- SAF-TRACE: claims=SAF-T1202-C011; sources=SRC-rfc9700,SRC-nvd-cve-2026-9571 -->
- **Rule Status**: Experimental; see [detection-rule.yml](detection-rule.yml).
- **Detection Logic**: Require a successful refresh grant and either disabled/deactivated subject state or a true reuse signal. <!-- SAF-TRACE: claims=SAF-T1202-C010,SAF-T1202-C011; sources=SRC-rfc9700,SRC-nvd-cve-2026-9571 -->
- **Correlation Window**: Evaluate identity state and family state at the authorization decision time. <!-- SAF-TRACE: claims=SAF-T1202-C011; sources=SRC-rfc9700,SRC-ms-entra-risk-detections-2026 -->
- **Known False Positives**: Lifecycle synchronization lag, recovery testing, or concurrency misclassified as reuse. <!-- SAF-TRACE: claims=SAF-T1202-C011; sources=SRC-rfc9700,SRC-ms-entra-risk-detections-2026 -->
- **Known Limitations**: The analytic misses sole use of a still-valid latest refresh token without lifecycle or contextual evidence. <!-- SAF-TRACE: claims=SAF-T1202-C018; sources=SRC-rfc9700,SRC-rfc10017,SRC-mitre-t1550-001 -->
- **Tuning Guidance**: Suppress documented test clients only after validating lifecycle synchronization; keep family-reuse alerts high priority. <!-- SAF-TRACE: claims=SAF-T1202-C010,SAF-T1202-C011; sources=SRC-rfc9700,SRC-ms-entra-risk-detections-2026 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1202/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1202/test_detection_rule.py)
- **Expected Result**: Eight deterministic cases pass, with three expected alerts and five expected non-alerts; see the [quality review](../../research/techniques/SAF-T1202/quality-review.yml).
- **Last Validated**: 2026-09-01; see the [quality review](../../research/techniques/SAF-T1202/quality-review.yml).
- **Feasibility Waiver**: None; see the [quality review](../../research/techniques/SAF-T1202/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **Sender-constrain or rotate refresh tokens**: Bind tokens to a client key where feasible; otherwise rotate while retaining family state for replay detection. <!-- SAF-TRACE: claims=SAF-T1202-C010,SAF-T1202-C016; sources=SRC-rfc9700,SRC-rfc9449 -->
2. **Bound grants**: Restrict scope, audience, resource, inactivity, and maximum lifetime. <!-- SAF-TRACE: claims=SAF-T1202-C013,SAF-T1202-C016; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700 -->
3. **Synchronize lifecycle revocation**: Terminate refresh grants when subjects are disabled and after security events. <!-- SAF-TRACE: claims=SAF-T1202-C007,SAF-T1202-C012,SAF-T1202-C016; sources=SRC-nvd-cve-2026-9571,SRC-rfc9700,SRC-rfc7009 -->

### Detective Controls

1. **Retain token-family state**: Preserve invalidated-family reuse decisions and correlate them with refresh outcomes. <!-- SAF-TRACE: claims=SAF-T1202-C010,SAF-T1202-C011; sources=SRC-rfc9700,SRC-mitre-t1550-001 -->
2. **Correlate identity context**: Compare refresh events with effective subject status and provider risk signals. <!-- SAF-TRACE: claims=SAF-T1202-C011; sources=SRC-nvd-cve-2026-9571,SRC-ms-entra-risk-detections-2026 -->

### Response Procedures

#### Immediate Actions

- Revoke the affected grant or complete token family, and invalidate or wait out still-valid access tokens according to provider behavior. <!-- SAF-TRACE: claims=SAF-T1202-C012; sources=SRC-google-oauth-token-mitigation,SRC-ms-token-tactics-2022,SRC-rfc7009 -->
- Disable the affected client or integration when its authentication material may also be compromised. <!-- SAF-TRACE: claims=SAF-T1202-C006,SAF-T1202-C012; sources=SRC-ghsa-pw9m-5jxm-xr6h,SRC-google-oauth-token-mitigation -->

#### Investigation Steps

- Correlate token endpoint, identity lifecycle, MCP resource access, and follow-on activity by subject, client, resource, and family identifier. <!-- SAF-TRACE: claims=SAF-T1202-C011,SAF-T1202-C019; sources=SRC-mitre-t1550-001,SRC-ms-entra-risk-detections-2026 -->
- Determine whether the attacker controlled the newest rotated token and whether the legitimate client ever caused a reuse signal. <!-- SAF-TRACE: claims=SAF-T1202-C010,SAF-T1202-C018; sources=SRC-rfc9700,SRC-rfc10017 -->

#### Remediation

- Patch the authorization component, correct lifecycle revocation, and require confidential-client authentication or proof of possession as applicable. <!-- SAF-TRACE: claims=SAF-T1202-C006,SAF-T1202-C007,SAF-T1202-C016; sources=SRC-ghsa-pw9m-5jxm-xr6h,SRC-nvd-cve-2026-9571,SRC-rfc9449 -->
- Re-authorize only after the affected token family and client credentials are invalidated, then verify renewal and revocation regression tests. <!-- SAF-TRACE: claims=SAF-T1202-C012,SAF-T1202-C016; sources=SRC-rfc7009,SRC-rfc9700 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1504: Token Theft via API Response](../SAF-T1504/README.md) | Prerequisite | Acquisition of token material through an API response ends at possession; this technique starts when a refresh token renews access. | <!-- SAF-TRACE: claims=SAF-T1202-C014; sources=SRC-mitre-t1550-001 -->

Malicious OAuth application registration or consent is outside this technique, but no exact SAF catalog neighbor currently represents that boundary. <!-- SAF-TRACE: claims=SAF-T1202-C015; sources=SRC-mitre-ta0003,SRC-ms-app-consent-playbook -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | Use Alternate Authentication Material: Application Access Token | Analogous | It covers stolen application tokens and notes long-term access through refresh tokens, but it is broader than MCP and is assigned to Lateral Movement. | <!-- SAF-TRACE: claims=SAF-T1202-C014; sources=SRC-mitre-t1550-001 -->

## References

1. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — roles, resource binding, token use, and refresh guidance.
2. **SRC-mcp-auth-security-2026-07-28**: [MCP Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) — token theft and rotation requirements.
3. **SRC-rfc9700**: [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) — refresh replay consequences and protections.
4. **SRC-rfc7009**: [RFC 7009: OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html) — revocation semantics.
5. **SRC-rfc9449**: [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449.html) — sender-constrained tokens.
6. **SRC-rfc10017**: [RFC 10017: OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017.html) — persistent token theft and rotation blind spots.
7. **SRC-google-oauth-token-mitigation**: [Google Cloud best practices for mitigating compromised OAuth tokens](https://docs.cloud.google.com/architecture/bps-for-mitigating-gcloud-oauth-tokens) — persistence and remediation.
8. **SRC-ghsa-pw9m-5jxm-xr6h**: [Better Auth advisory GHSA-pw9m-5jxm-xr6h](https://github.com/better-auth/better-auth/security/advisories/GHSA-pw9m-5jxm-xr6h) — affected MCP refresh-grant behavior and patch.
9. **SRC-nvd-cve-2026-9571**: [NVD CVE-2026-9571](https://nvd.nist.gov/vuln/detail/CVE-2026-9571) — account deactivation and refresh-token invalidation flaw.
10. **SRC-gtig-drift-2025**: [Google Threat Intelligence: UNC6395 Drift compromise](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift) — production token abuse and response.
11. **SRC-salesloft-drift-2026**: [Salesloft incident updates](https://trust.salesloft.com/?uid=Update+on+Mandiant+Drift+and+Salesloft+Application+Investigations) — corroborating incident and revocation details.
12. **SRC-github-oauth-incident-2022**: [GitHub security alert: stolen OAuth user tokens](https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/) — adjacent production token abuse.
13. **SRC-ms-token-tactics-2022**: [Microsoft: token tactics](https://www.microsoft.com/en-us/security/blog/2022/11/22/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/) — investigation and response.
14. **SRC-ms-app-consent-playbook**: [Microsoft Learn: application consent grant investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent) — malicious integration boundary.
15. **SRC-ms-entra-risk-detections-2026**: [Microsoft Entra ID Protection risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks) — token anomaly context and false-positive cautions.
16. **SRC-mitre-t1550-001**: [MITRE ATT&CK T1550.001](https://attack.mitre.org/techniques/T1550/001/) — application access-token behavior and detection.
17. **SRC-mitre-ta0003**: [MITRE ATT&CK Persistence tactic](https://attack.mitre.org/tactics/TA0003/) — cloud application integration boundary.
18. **SRC-usenix-s3kvetter-2018**: [Vetting Single Sign-On SDK Implementations via Symbolic Reasoning](https://www.usenix.org/conference/usenixsecurity18/presentation/yang) — controlled refresh-token injection research.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft, evidence packet, and tested analytic. | OpenAI Codex research agent |
