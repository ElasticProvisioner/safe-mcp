# SAF-T1007: OAuth Authorization Phishing

## Overview

- **Tactic**: Initial Access (ATK-TA0001)
- **Technique ID**: SAF-T1007
- **Research Packet**: [research/techniques/SAF-T1007](../../research/techniques/SAF-T1007/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1007/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A successful flow can bind a victim's third-party OAuth access to an attacker-controlled MCP session, with impact bounded by the granted scopes. <!-- SAF-TRACE: claims=SAF-T1007-C004; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
- **First Observed**: Not observed as a qualifying MCP production incident; publicly demonstrated by CVE-2026-31944 on 2026-03-13. <!-- SAF-TRACE: claims=SAF-T1007-C002,SAF-T1007-C011; sources=SRC-nvd-cve-2026-31944,SRC-cisa-kev-catalog-page-2026-09-01 -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers forwarding an MCP-generated third-party OAuth authorization URL to a different user so that the victim completes authorization while the MCP server binds the resulting tokens to the attacker's initiating session. <!-- SAF-TRACE: claims=SAF-T1007-C002,SAF-T1007-C003; sources=SRC-mcp-elicitation-2026-07-28,SRC-ghsa-vf7j-7mrx-hp7g -->

### In Scope

- URL-mode elicitation or an equivalent MCP integration flow in which the server acts as an OAuth client to a third-party service. <!-- SAF-TRACE: claims=SAF-T1007-C001; sources=SRC-mcp-elicitation-2026-07-28 -->
- Failure to verify that the user completing the browser flow is the authenticated user who initiated it, followed by cross-user token binding. <!-- SAF-TRACE: claims=SAF-T1007-C003; sources=SRC-mcp-elicitation-2026-07-28,SRC-ghsa-vf7j-7mrx-hp7g -->

### Out of Scope

- Malicious OAuth applications that obtain tokens granted directly to an attacker-owned client; those are ordinary consent phishing unless the MCP cross-user binding failure is also present. <!-- SAF-TRACE: claims=SAF-T1007-C012; sources=SRC-ms-shinyhunters-oauth-2026 -->
- Authorization-endpoint open redirects that send a user to a phishing page without binding the victim's token to the initiator. <!-- SAF-TRACE: claims=SAF-T1007-C010,SAF-T1007-C017; sources=SRC-ghsa-f6x8-65q6-j9m9,SRC-rfc9700 -->
- Token passthrough, counterfeit resource servers, callback script injection, and authorization-server mix-up attacks, which cross different OAuth boundaries. <!-- SAF-TRACE: claims=SAF-T1007-C017; sources=SRC-mcp-security-2026-07-28,SRC-rfc9700 -->

### Distinguishing Characteristics

The defining observable is an identity mismatch: one authenticated MCP subject starts the external authorization, a different browser subject completes it, and the server stores the resulting tokens under the initiator. Open-redirect phishing changes the browser destination; consent phishing grants an attacker-owned app; this technique instead misbinds an honest third-party grant across two users. <!-- SAF-TRACE: claims=SAF-T1007-C003,SAF-T1007-C010,SAF-T1007-C012; sources=SRC-ghsa-vf7j-7mrx-hp7g,SRC-ghsa-f6x8-65q6-j9m9,SRC-ms-shinyhunters-oauth-2026 -->

## Description

MCP URL-mode elicitation permits a server to direct a user to an external browser flow for third-party authorization while keeping those credentials outside the MCP client. The server remains responsible for associating the request and resulting tokens with the correct user. <!-- SAF-TRACE: claims=SAF-T1007-C001; sources=SRC-mcp-elicitation-2026-07-28 -->

An attacker who can initiate such a flow copies its authorization URL and induces another user of the same integration to open it. If the callback trusts only state recorded for the initiator and does not authenticate the browser user, the victim's successful grant is stored for the attacker. <!-- SAF-TRACE: claims=SAF-T1007-C002,SAF-T1007-C003; sources=SRC-mcp-elicitation-2026-07-28,SRC-ghsa-vf7j-7mrx-hp7g -->

CVE-2026-31944 publicly documents this end-to-end behavior in LibreChat and includes a proof of concept, so the evidence status is Demonstrated rather than Observed; no reviewed source established exploitation in a production victim environment. <!-- SAF-TRACE: claims=SAF-T1007-C002,SAF-T1007-C011; sources=SRC-nvd-cve-2026-31944,SRC-ghsa-vf7j-7mrx-hp7g,SRC-cisa-kev-catalog-page-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: A forwarded third-party OAuth authorization URL generated for the attacker's active MCP integration flow. <!-- SAF-TRACE: claims=SAF-T1007-C002; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
- **Secondary Vectors**: Team-integration pretexts, reused browser consent, or messages that present the grant as a shared administrative task. <!-- SAF-TRACE: claims=SAF-T1007-C002,SAF-T1007-C013; sources=SRC-ghsa-vf7j-7mrx-hp7g,SRC-ms-consent-phishing-2021 -->
- **Affected Components**: MCP host/client, MCP integration server, browser, third-party authorization server, callback handler, and token store. <!-- SAF-TRACE: claims=SAF-T1007-C003; sources=SRC-mcp-elicitation-2026-07-28,SRC-ghsa-vf7j-7mrx-hp7g -->
- **Trust Boundary Crossed**: The authenticated identity that initiated an elicitation versus the authenticated browser identity that completed third-party authorization. <!-- SAF-TRACE: claims=SAF-T1007-C005; sources=SRC-mcp-elicitation-2026-07-28 -->

## Technical Details

### Prerequisites

- The attacker can start a third-party OAuth flow through an MCP-enabled application and obtain the browser authorization URL. <!-- SAF-TRACE: claims=SAF-T1007-C003; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
- A victim can be induced to open that URL and authorize a third-party account. <!-- SAF-TRACE: claims=SAF-T1007-C002; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
- The callback does not authenticate the browser user or compare that subject with the flow initiator before storing tokens. <!-- SAF-TRACE: claims=SAF-T1007-C003; sources=SRC-ghsa-vf7j-7mrx-hp7g -->

### Attack Flow

1. **Setup**: The attacker starts an OAuth-backed MCP integration and preserves the generated authorization URL. <!-- SAF-TRACE: claims=SAF-T1007-C002; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
2. **Delivery**: The attacker sends the URL to a victim under a plausible integration or approval pretext. <!-- SAF-TRACE: claims=SAF-T1007-C002; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
3. **Authorization**: The victim authenticates to the third-party provider and approves the requested scopes. <!-- SAF-TRACE: claims=SAF-T1007-C002; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
4. **Boundary Crossing**: The MCP callback accepts the authorization response without proving that the browser subject matches the initiator. <!-- SAF-TRACE: claims=SAF-T1007-C003; sources=SRC-mcp-elicitation-2026-07-28,SRC-ghsa-vf7j-7mrx-hp7g -->
5. **Objective**: The server stores the victim's third-party tokens for the attacker's MCP account or session. <!-- SAF-TRACE: claims=SAF-T1007-C002; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
6. **Follow-On Activity**: The attacker uses the MCP integration within the scopes authorized by the victim. <!-- SAF-TRACE: claims=SAF-T1007-C004; sources=SRC-ghsa-vf7j-7mrx-hp7g -->

### Example Scenario

The following inert event sequence illustrates the identity mismatch without including a live authorization URL or credential. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->

```json
{"event":"oauth_callback","request_id":"demo-42","initiator_subject":"user-a","callback_subject":"user-b","token_value":"REDACTED"}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1007-C001 | URL-mode elicitation supports external OAuth while the server owns token storage and user binding. | Research-Derived | SRC-mcp-elicitation-2026-07-28: [MCP Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation) | Protocol behavior does not prove a deployment is vulnerable. |
| SAF-T1007-C002 | CVE-2026-31944 demonstrates cross-user token binding after a forwarded MCP OAuth URL. | Demonstrated | SRC-ghsa-vf7j-7mrx-hp7g: [LibreChat advisory](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-vf7j-7mrx-hp7g) | Public proof of concept is not evidence of production exploitation. |
| SAF-T1007-C003 | Missing callback authentication and subject comparison enable the technique. | Demonstrated | SRC-ghsa-vf7j-7mrx-hp7g: [LibreChat advisory](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-vf7j-7mrx-hp7g) | Implementation-specific route details are not universal. |
| SAF-T1007-C005 | MCP requires the initiating and completing user to be the same. | Research-Derived | SRC-mcp-elicitation-2026-07-28: [Phishing security consideration](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation#phishing) | The specification leaves the implementation mechanism open. |
| SAF-T1007-C011 | No qualifying direct production incident was identified in the reviewed corpus. | Research-Derived | SRC-cisa-kev-catalog-page-2026-09-01: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | This is a bounded corpus finding, not a claim that exploitation never occurred. |

### Current State

- **Affected Environments**: MCP-enabled applications that broker third-party OAuth and key callback state only to the initiator without authenticating the browser completer. <!-- SAF-TRACE: claims=SAF-T1007-C003; sources=SRC-ghsa-vf7j-7mrx-hp7g -->
- **Known Exploitation**: A public proof of concept exists for CVE-2026-31944; no qualifying production exploitation was identified. <!-- SAF-TRACE: claims=SAF-T1007-C002,SAF-T1007-C011; sources=SRC-nvd-cve-2026-31944,SRC-cisa-kev-catalog-page-2026-09-01 -->
- **Available Protections**: Authenticate the browser at a server-owned connect URL, compare its authoritative subject with the flow initiator, and reject mismatches before exchange or storage. <!-- SAF-TRACE: claims=SAF-T1007-C005; sources=SRC-mcp-elicitation-2026-07-28 -->
- **Residual Risk**: Weak or mutable subject identifiers, unlogged callback paths, and broad third-party scopes can preserve exposure even when ordinary OAuth state and PKCE checks succeed. <!-- SAF-TRACE: claims=SAF-T1007-C007,SAF-T1007-C009; sources=SRC-mcp-elicitation-2026-07-28,SRC-rfc9700 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-31944 / GHSA-vf7j-7mrx-hp7g | 2026-03-13; LibreChat 0.8.2 through 0.8.2-rc3 with MCP OAuth | Victim third-party tokens could be stored for the initiator; fixed in 0.8.3-rc1. | Direct vulnerability and public demonstration. | No qualifying production incident was identified. <!-- SAF-TRACE: claims=SAF-T1007-C002,SAF-T1007-C004; sources=SRC-nvd-cve-2026-31944,SRC-ghsa-vf7j-7mrx-hp7g --> |
| CVE-2026-42230 / GHSA-f6x8-65q6-j9m9 | 2026-04-22; affected n8n versions before 1.123.32, 2.17.4, and 2.18.1 | Denying MCP OAuth consent could redirect the user to an attacker site; fixed in the listed versions. | Adjacent open-redirect phishing vulnerability. | It did not bind a victim's OAuth tokens to an attacker session, and CISA SSVC recorded no exploitation. <!-- SAF-TRACE: claims=SAF-T1007-C010; sources=SRC-ghsa-f6x8-65q6-j9m9,SRC-nvd-cve-2026-42230 --> |

### Real-World Incidents or Demonstrations

Microsoft observed OAuth redirection phishing campaigns in 2026 and vishing-driven OAuth consent abuse from 2025 to 2026, but neither report described the MCP cross-user token-binding failure, so both remain adjacent historical context and do not raise this technique's evidence status. <!-- SAF-TRACE: claims=SAF-T1007-C012; sources=SRC-ms-oauth-redirection-2026,SRC-ms-shinyhunters-oauth-2026 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A demonstrated implementation exposed third-party service access within the permissions granted to the victim. <!-- SAF-TRACE: claims=SAF-T1007-C004; sources=SRC-ghsa-vf7j-7mrx-hp7g --> |
| Integrity | Medium | Write impact is possible only where the granted integration scopes permit state-changing operations. <!-- SAF-TRACE: claims=SAF-T1007-C004; sources=SRC-ghsa-vf7j-7mrx-hp7g --> |
| Availability | None | The demonstrated vulnerability did not claim an availability consequence. <!-- SAF-TRACE: claims=SAF-T1007-C004; sources=SRC-ghsa-vf7j-7mrx-hp7g --> |
| Scope | Adjacent | Impact crosses from the MCP application into the victim's linked third-party service. <!-- SAF-TRACE: claims=SAF-T1007-C004; sources=SRC-ghsa-vf7j-7mrx-hp7g --> |

### Severity Conditions

- **Severity increases when** broad read/write scopes, long-lived refresh access, or sensitive collaboration services are linked. <!-- SAF-TRACE: claims=SAF-T1007-C004,SAF-T1007-C007; sources=SRC-ghsa-vf7j-7mrx-hp7g,SRC-rfc9700 -->
- **Severity decreases when** the server enforces same-subject completion, uses minimal scopes, and rejects unverifiable callbacks before token exchange or storage. <!-- SAF-TRACE: claims=SAF-T1007-C005,SAF-T1007-C007; sources=SRC-mcp-elicitation-2026-07-28,SRC-rfc9700 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP integration server | OAuth flow creation and callback | timestamp, request_id, server_id, initiator_subject, callback_subject, outcome | Subjects must come from authenticated server-side identity, not client text. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 --> |
| Token store audit log | Token binding, rejection, or revocation | request_id, bound_subject, provider, scope_set, reason | Retain enough correlation to prove which subject received the grant. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 --> |

### Indicators of Compromise (IoCs)

- No durable technique-wide IoC is known; authorization URLs and state values are transaction-specific. <!-- SAF-TRACE: claims=SAF-T1007-C009; sources=SRC-mcp-elicitation-2026-07-28 -->

### Behavioral Indicators

- An OAuth callback whose authoritative `callback_subject` differs from the stored `initiator_subject`. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->
- Token storage when the callback subject is missing, unauthenticated, or different from the subject bound to the request. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->
- Repeated flow creation followed by callbacks completed from unrelated authenticated subjects. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect or prevent cross-user OAuth completion and token binding. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->
- **Rule Status**: Test. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->
- **Detection Logic**: Match completed callbacks when the initiator and callback subjects differ, or when a token is stored without an authoritative callback subject. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->
- **Correlation Window**: The configured OAuth flow lifetime, modeled as 10 minutes in the example analytic. <!-- SAF-TRACE: claims=SAF-T1007-C009; sources=SRC-mcp-elicitation-2026-07-28 -->
- **Known False Positives**: Subject aliases or account-migration identifiers that are not normalized to the same stable principal. <!-- SAF-TRACE: claims=SAF-T1007-C009; sources=SRC-mcp-elicitation-2026-07-28 -->
- **Known Limitations**: A server that never authenticates or logs the browser completer cannot evaluate the mismatch. <!-- SAF-TRACE: claims=SAF-T1007-C009; sources=SRC-mcp-elicitation-2026-07-28 -->
- **Tuning Guidance**: Normalize only issuer-qualified stable subject identifiers and do not allow display names or email text to establish identity. <!-- SAF-TRACE: claims=SAF-T1007-C005,SAF-T1007-C009; sources=SRC-mcp-elicitation-2026-07-28 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Six deterministic cases cover true positive, true negative, missing subject, boundary time, expected alias false positive, and ignored incomplete flow. <!-- SAF-TRACE: claims=SAF-T1007-C008,SAF-T1007-C009; sources=SRC-mcp-elicitation-2026-07-28 -->
- **Last Validated**: 2026-09-01 ([quality review](../../research/techniques/SAF-T1007/quality-review.yml))
- **Feasibility Waiver**: None. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->

## Mitigation Strategies

### Preventive Controls

1. Route the elicitation to a server-owned connect page that authenticates the browser and compares its authoritative subject with the flow initiator before redirecting to the third-party authorization server. <!-- SAF-TRACE: claims=SAF-T1007-C005; sources=SRC-mcp-elicitation-2026-07-28 -->
2. Bind flow state and token storage to an issuer-qualified stable subject; reject missing, mutable, or mismatched identity before exchanging or storing a code. <!-- SAF-TRACE: claims=SAF-T1007-C005; sources=SRC-mcp-elicitation-2026-07-28 -->
3. Minimize requested scopes and use exact redirect matching and standard OAuth protections; those controls limit impact but do not replace same-user verification. <!-- SAF-TRACE: claims=SAF-T1007-C007; sources=SRC-rfc9700,SRC-mcp-authorization-2026-07-28 -->
4. Clients should show the complete elicitation URL, identify the requesting server, require explicit consent, and avoid exposing browser interaction contents to the client or model. <!-- SAF-TRACE: claims=SAF-T1007-C006; sources=SRC-mcp-elicitation-2026-07-28 -->

### Detective Controls

1. Correlate flow creation, authenticated callback, code exchange, and token storage by request ID and compare the subjects at each boundary. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->
2. Alert on mismatches, unauthenticated callbacks, repeated abandoned initiations, and tokens stored after an identity-verification failure. <!-- SAF-TRACE: claims=SAF-T1007-C008; sources=SRC-mcp-elicitation-2026-07-28 -->

### Response Procedures

#### Immediate Actions

- Disable the affected integration path, revoke the misbound third-party grant, and invalidate the initiating MCP session. <!-- SAF-TRACE: claims=SAF-T1007-C014; sources=SRC-mslearn-protect-consent-phishing -->
- Preserve flow, callback, token-store, and third-party API audit records before removing the binding. <!-- SAF-TRACE: claims=SAF-T1007-C014; sources=SRC-mslearn-protect-consent-phishing -->

#### Investigation Steps

- Identify the initiating and completing subjects, the granted scopes, all API calls made through the misbound token, and any additional linked accounts. <!-- SAF-TRACE: claims=SAF-T1007-C014; sources=SRC-mslearn-protect-consent-phishing -->
- Determine whether the flow was merely tested or used against a production victim; do not infer exploitation from advisory publication or a proof of concept. <!-- SAF-TRACE: claims=SAF-T1007-C011; sources=SRC-nvd-cve-2026-31944,SRC-cisa-kev-catalog-page-2026-09-01 -->

#### Remediation

- Add callback authentication and same-subject verification, rotate or revoke affected grants, and retest with cross-user and unauthenticated callback cases. <!-- SAF-TRACE: claims=SAF-T1007-C005,SAF-T1007-C014; sources=SRC-mcp-elicitation-2026-07-28,SRC-mslearn-protect-consent-phishing -->
- Upgrade LibreChat to 0.8.3-rc1 or later when CVE-2026-31944 is the affected implementation. <!-- SAF-TRACE: claims=SAF-T1007-C004; sources=SRC-ghsa-vf7j-7mrx-hp7g -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1009: Authorization Server Mix-up](../../research/techniques/SAF-T1007/technique-contract.yml) | Adjacent | Selects or accepts the wrong authorization issuer; SAF-T1007 preserves the intended external service but misbinds the user completing its OAuth flow. |
| [SAF-T1706: OAuth Token Pivot Replay](../../research/techniques/SAF-T1007/technique-contract.yml) | Adjacent | Reuses an issued token across an agent or service context; SAF-T1007 stores a victim-authorized token under another MCP subject during authorization. |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | Direct | The adversary sends an OAuth authorization link and requires the victim to follow it; the MCP-specific distinction is the callback identity misbinding. <!-- SAF-TRACE: claims=SAF-T1007-C015; sources=SRC-mitre-t1566-002 --> |

### Additional Framework Mappings

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| MITRE ATT&CK | [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Analogous because the attacker gains usable third-party OAuth access, although the token is misbound by the MCP server rather than extracted from storage. <!-- SAF-TRACE: claims=SAF-T1007-C016; sources=SRC-mitre-t1528 --> |

## References

1. **SRC-mcp-elicitation-2026-07-28**: [MCP Elicitation specification, version 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation) — URL-mode OAuth pattern, user binding, phishing scenario, and safe URL handling.
2. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization specification, version 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — OAuth roles, flow, scopes, and token requirements.
3. **SRC-mcp-security-2026-07-28**: [MCP Security Best Practices, version 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) — token passthrough and adjacent OAuth boundaries.
4. **SRC-rfc9700**: [RFC 9700, OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html) — exact redirect validation, least privilege, phishing, and open-redirection controls; Torsten Lodderstedt, John Bradley, Andrey Labunets, and Daniel Fett.
5. **SRC-nvd-cve-2026-31944**: [NVD record for CVE-2026-31944](https://nvd.nist.gov/vuln/detail/CVE-2026-31944) — affected range, CVSS, PoC status, and advisory reference.
6. **SRC-ghsa-vf7j-7mrx-hp7g**: [LibreChat advisory GHSA-vf7j-7mrx-hp7g](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-vf7j-7mrx-hp7g) — Danny Avila; root cause, proof of concept, impact, and fixed version.
7. **SRC-nvd-cve-2026-42230**: [NVD record for CVE-2026-42230](https://nvd.nist.gov/vuln/detail/CVE-2026-42230) — adjacent MCP OAuth open redirect and CISA SSVC exploitation state.
8. **SRC-ghsa-f6x8-65q6-j9m9**: [n8n advisory GHSA-f6x8-65q6-j9m9](https://github.com/n8n-io/n8n/security/advisories/GHSA-f6x8-65q6-j9m9) — Jubke and reporter ori-ron; affected and fixed versions.
9. **SRC-cisa-kev-catalog-page-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — checked for the selected CVEs on 2026-09-01.
10. **SRC-ms-oauth-redirection-2026**: [OAuth redirection abuse enables phishing and malware delivery](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/) — Microsoft Defender Security Research Team with Jonathan Armer, Fernando Dantes, Sagar Patil, Bharat Vaghela, Krithika Ramakrishnan, Sean Reynolds, and Shivas Raina.
11. **SRC-ms-shinyhunters-oauth-2026**: [Defending SaaS-based applications against ShinyHunters OAuth abuse](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/) — Microsoft Security Research and Microsoft Defender Security Research Team, Shruti Ranjit, Doug Cranston, Anand Deshpande, and Ronen Rafaeli.
12. **SRC-ms-consent-phishing-2021**: [Microsoft consent-phishing research](https://www.microsoft.com/en-us/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/) — Microsoft Threat Intelligence.
13. **SRC-mslearn-protect-consent-phishing**: [Protect against consent phishing](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/protect-against-consent-phishing) — Microsoft Learn.
14. **SRC-mitre-t1566-002**: [ATT&CK T1566.002](https://attack.mitre.org/techniques/T1566/002/) — MITRE ATT&CK.
15. **SRC-mitre-t1528**: [ATT&CK T1528](https://attack.mitre.org/techniques/T1528/) — MITRE ATT&CK.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft | OpenAI Codex clean-room agent |
