# SAF-T1507: Authorization Code Interception

## Overview

- **Tactic**: Credential Access (ATK-TA0006)
- **Technique ID**: SAF-T1507
- **Research Packet**: [research/techniques/SAF-T1507](../../research/techniques/SAF-T1507/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1507/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: Successful code redemption can expose data and permit actions within the resulting token's MCP scopes; scope, audience, lifetime, and server capabilities bound the outcome. <!-- SAF-TRACE: claims=SAF-T1507-C016,SAF-T1507-C019; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2025-4143,SRC-cve-2026-67336 -->
- **First Observed**: No qualifying production MCP incident was identified in the reviewed corpus through 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1507-C011; sources=SRC-nvd-cleanroom-queries,SRC-cisa-kev-authorization-code-2026-09-01,SRC-cve-2025-4143,SRC-cve-2025-4144,SRC-cve-2026-67336 -->
- **Last Updated**: 2026-09-01

## Scope

Authorization Code Interception covers an adversary obtaining an OAuth authorization code from the redirect-to-client path used by an HTTP MCP authorization flow, then redeeming or attempting to redeem it when transaction binding or validation is absent or defeated. The crossed boundary spans the authorization server, user agent or local URI dispatcher, MCP client callback, and token endpoint. [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C002; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc6749 -->

### In Scope

- Interception, misdirection, or attacker receipt of a code issued for a legitimate MCP authorization transaction. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc6749,SRC-rfc8252 -->
- Redemption or attempted redemption when S256 PKCE, exact redirect matching, state correlation, or single-use enforcement is missing, downgraded, bypassed, or jointly compromised. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C003,SAF-T1507-C004,SAF-T1507-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700 -->
- Browser, private-use scheme, claimed HTTPS, and loopback callback paths used by an MCP client. <!-- SAF-TRACE: claims=SAF-T1507-C007; sources=SRC-rfc8252,SRC-rfc7636 -->

### Out of Scope

- Authorization-code injection substitutes an attacker-controlled code into another client session; it is a separate neighbor unless the adversary first intercepted a victim-issued code. <!-- SAF-TRACE: claims=SAF-T1507-C018; sources=SRC-rfc9700,SRC-rfc7636 -->
- Theft of an access or refresh token after issuance, token audience confusion, and downstream token misuse occur after the authorization-code boundary. <!-- SAF-TRACE: claims=SAF-T1507-C018,SAF-T1507-C019; sources=SRC-rfc9700,SRC-rfc7636,SRC-mcp-authorization-2025-11-25 -->
- Malicious-client registration, deceptive consent, authorization-server mix-up, phishing without code receipt, and generic open redirection are excluded unless they produce the defining intercepted-code sequence. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C018; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700 -->

### Distinguishing Characteristics

The decisive observable is a code issued for a legitimate authorization transaction reaching or being redeemed by an unintended party before token issuance. Code injection instead changes which code a client processes, while access-token theft begins after the token exists. [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html) <!-- SAF-TRACE: claims=SAF-T1507-C018; sources=SRC-rfc9700,SRC-rfc7636 -->

## Description

The OAuth authorization-code grant sends a short-lived code through a user agent to the client's redirect endpoint; the client then presents that code to the token endpoint. MCP's HTTP authorization specification adopts this role structure for clients accessing protected MCP servers. [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749.html) [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) <!-- SAF-TRACE: claims=SAF-T1507-C002,SAF-T1507-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc6749,SRC-rfc8252 -->

An adversary can target the callback path by claiming a colliding private-use scheme, racing a loopback listener, causing an authorization server to accept an attacker-controlled redirect, or otherwise obtaining the response. If the adversary can redeem the code without the legitimate transaction's verifier, the token endpoint may issue a token to the unintended party. [RFC 8252 native-app guidance](https://www.rfc-editor.org/rfc/rfc8252.html) <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc8252 -->

PKCE normally prevents that redemption: the client commits to a challenge in the authorization request and later proves possession of the transaction-specific verifier. The current MCP specification requires clients to implement PKCE, verify server support, and use S256 when technically capable; exact redirect validation and state checking provide separate protections. [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html) <!-- SAF-TRACE: claims=SAF-T1507-C003,SAF-T1507-C004,SAF-T1507-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc7636 -->

The complete MCP technique is Research-Derived. Three directly relevant MCP-related vulnerabilities establish real control failures, but the reviewed authorities do not establish a production MCP interception incident or a public end-to-end MCP demonstration. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C008,SAF-T1507-C009,SAF-T1507-C010,SAF-T1507-C011; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-cve-2025-4143,SRC-cloudflare-pr26,SRC-cve-2025-4144,SRC-cloudflare-pr27,SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4,SRC-nvd-cleanroom-queries,SRC-cisa-kev-authorization-code-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: Obtain the authorization response through a misdirected redirect URI, colliding local callback handler, or exposed callback path, then race or replace the client's token exchange. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc8252 -->
- **Secondary Vectors**: Defeat PKCE by forcing a no-challenge downgrade, accepting `plain`, or bypassing verifier enforcement. <!-- SAF-TRACE: claims=SAF-T1507-C006,SAF-T1507-C009,SAF-T1507-C010; sources=SRC-rfc7636,SRC-rfc9700,SRC-cve-2025-4144,SRC-cloudflare-pr27,SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4 -->
- **Affected Components**: MCP client, authorization server, browser or operating-system dispatcher, loopback listener, token endpoint, and intended MCP protected resource. <!-- SAF-TRACE: claims=SAF-T1507-C002,SAF-T1507-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc6749,SRC-rfc8252,SRC-rfc7636 -->
- **Trust Boundary Crossed**: Authorization-server response to MCP-client callback, followed by authorization-code proof at the token endpoint. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc6749,SRC-rfc8252 -->

## Technical Details

### Prerequisites

- The deployment uses an HTTP MCP OAuth authorization-code flow. <!-- SAF-TRACE: claims=SAF-T1507-C002,SAF-T1507-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc6749,SRC-rfc8252 -->
- The adversary can influence or observe the redirect path, register or race a local handler, exploit weak redirect validation, or otherwise receive the code. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C007,SAF-T1507-C008; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc8252,SRC-cve-2025-4143,SRC-cloudflare-pr26 -->
- PKCE, redirect binding, state checking, or single-use enforcement is absent, weak, downgraded, bypassed, or compromised together with the verifier. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C003,SAF-T1507-C004,SAF-T1507-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700 -->
- The code remains valid and the attacker can reach the token endpoint before or instead of the intended redemption. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc6749,SRC-rfc8252 -->

### Attack Flow

1. **Setup**: The adversary identifies a callback path it can receive, redirect, observe, or race. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc8252 -->
2. **Authorization**: A legitimate MCP client initiates an authorization request for an MCP protected resource. <!-- SAF-TRACE: claims=SAF-T1507-C002,SAF-T1507-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc6749,SRC-rfc8252 -->
3. **Interception**: The authorization response carrying the code reaches the unintended handler or attacker-controlled redirect. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc8252 -->
4. **Control Failure**: The authorization server accepted an invalid redirect, or the token endpoint accepts a missing, weak, downgraded, or mismatched PKCE relationship. <!-- SAF-TRACE: claims=SAF-T1507-C008,SAF-T1507-C009,SAF-T1507-C010; sources=SRC-cve-2025-4143,SRC-cloudflare-pr26,SRC-cve-2025-4144,SRC-cloudflare-pr27,SRC-rfc9700,SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc7636 -->
5. **Redemption**: The adversary or attacker-influenced flow presents the code to the token endpoint before it expires or is consumed. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc6749,SRC-rfc8252 -->
6. **Objective**: A resulting token can authorize requests to the intended MCP server within its audience, scopes, and lifetime; further token use is follow-on activity. <!-- SAF-TRACE: claims=SAF-T1507-C016,SAF-T1507-C019; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2025-4143,SRC-cve-2026-67336 -->

### Example Scenario

A desktop MCP client opens a browser authorization flow and listens on a local callback. A second local process receives the response first, but the authorization server rejects redemption because the opaque code is bound to the legitimate client's S256 verifier. This inert example shows both the interception point and the expected control outcome. <!-- SAF-TRACE: claims=SAF-T1507-C006,SAF-T1507-C007,SAF-T1507-C014; sources=SRC-rfc7636,SRC-rfc9700,SRC-rfc8252,SRC-mcp-authorization-2025-11-25,SRC-rfc6749 -->

```json
{
  "redirect_uri": "http://127.0.0.1:51004/callback",
  "authorization_code": "opaque-redacted",
  "code_challenge_method": "S256",
  "attacker_has_verifier": false,
  "token_exchange_outcome": "invalid_grant"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1507-C001 | The MCP end-to-end technique follows when an intercepted code is redeemable because binding controls fail. | Research-Derived | SRC-mcp-authorization-2025-11-25: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); SRC-rfc7636: [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html); SRC-rfc9700: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Explicit SAF synthesis; no production MCP incident. |
| SAF-T1507-C002 | MCP HTTP authorization assigns OAuth roles and obtains access tokens for a protected MCP server. | Research-Derived | SRC-mcp-authorization-2025-11-25; SRC-rfc6749 | Applies only to deployments using MCP HTTP authorization. |
| SAF-T1507-C003 | MCP clients must implement PKCE, verify support, and use S256 when technically capable. | Research-Derived | SRC-mcp-authorization-2025-11-25; SRC-rfc9700 | Weak compatibility behavior can remain in nonconforming implementations. |
| SAF-T1507-C004 | Exact redirect validation and state checking are required or recommended MCP protections. | Research-Derived | SRC-mcp-authorization-2025-11-25; SRC-rfc9700 | State does not replace PKCE for stolen public-client codes. |
| SAF-T1507-C005 | The authorization-code flow sends a code through the user agent and exchanges it at the token endpoint. | Research-Derived | SRC-rfc6749; SRC-rfc8252 | Flow mechanics do not establish exploitation. |
| SAF-T1507-C006 | PKCE binds the code to a transaction-specific verifier and derived challenge. | Research-Derived | SRC-rfc7636; SRC-rfc9700 | Fails if the verifier is disclosed, weak, or not enforced. |
| SAF-T1507-C007 | Private-use and loopback callbacks can permit local interception; claimed HTTPS reduces risk. | Research-Derived | SRC-rfc8252; SRC-rfc7636 | Platform and redirect-mechanism dependent. |
| SAF-T1507-C008 | CVE-2025-4143 was an MCP OAuth redirect-validation failure fixed by Cloudflare. | Research-Derived | SRC-cve-2025-4143; SRC-cloudflare-pr26 | Vulnerability, not production breach. |
| SAF-T1507-C009 | CVE-2025-4144 bypassed PKCE through downgrade and was fixed by Cloudflare. | Research-Derived | SRC-cve-2025-4144; SRC-cloudflare-pr27; SRC-rfc9700 | Vulnerability, not observed exploitation. |
| SAF-T1507-C010 | CVE-2026-67336 accepted plain PKCE in Better Auth's legacy MCP plugin before 1.6.11. | Research-Derived | SRC-cve-2026-67336; SRC-ghsa-9h47-pqcx-hjr4; SRC-rfc7636 | Advisory also covers a separate unsigned-token defect. |
| SAF-T1507-C011 | No production MCP incident was found in the named official corpus through 2026-09-01. | Research-Derived | SRC-nvd-cleanroom-queries; SRC-cisa-kev-authorization-code-2026-09-01; three selected CVE records | Bounded absence finding, not proof of never occurring. |
| SAF-T1507-C012 | Endpoint invariant failures and code reuse support an experimental correlation analytic. | Research-Derived | SRC-rfc6749; SRC-rfc7636; SRC-rfc9700 | Normalized fields are not a standard log schema. |
| SAF-T1507-C013 | Retries, join errors, missing events, and attacker-first redemption create false positives or blind spots. | Research-Derived | SRC-rfc6749; SRC-rfc9700 | No detector accuracy study was found. |
| SAF-T1507-C014 | Exact redirects, S256 PKCE, state, single-use codes, and protected callbacks are complementary controls. | Research-Derived | SRC-mcp-authorization-2025-11-25; SRC-rfc6749; SRC-rfc9700; SRC-rfc8252 | Joint code-and-verifier compromise remains possible. |
| SAF-T1507-C015 | Response should contain the transaction, revoke related tokens, preserve evidence, fix configuration, and patch. | Research-Derived | SRC-rfc6749; SRC-cloudflare-pr26; SRC-cloudflare-pr27; SRC-ghsa-9h47-pqcx-hjr4 | Platform-specific revocation and logging vary. |
| SAF-T1507-C016 | Redeemed tokens can affect confidentiality and integrity within their authorization bounds. | Research-Derived | SRC-mcp-authorization-2025-11-25; SRC-cve-2025-4143; SRC-cve-2026-67336 | Impact depends on audience, scopes, lifetime, and server functions. |
| SAF-T1507-C017 | ATT&CK T1528 is analogous because the code is a precursor to obtaining an application access token. | Research-Derived | SRC-mitre-t1528; SRC-rfc7636 | T1528 does not specifically describe redirect interception. |
| SAF-T1507-C018 | Code injection and post-issuance token theft are distinct neighbors. | Research-Derived | SRC-rfc9700; SRC-rfc7636 | Canonical SAF neighbors are reconciled by boundary rather than treated as exact protocol labels. |
| SAF-T1507-C019 | MCP resource indicators and audience validation constrain a token to its intended resource. | Research-Derived | SRC-mcp-authorization-2025-11-25 | Does not prevent use against the intended MCP server. |

### Current State

- **Affected Environments**: HTTP MCP deployments using authorization-code redirects where a callback can be observed, raced, or misdirected and one or more binding controls fail. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C002,SAF-T1507-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc7636,SRC-rfc9700,SRC-rfc6749,SRC-rfc8252 -->
- **Known Exploitation**: No qualifying production MCP incident was identified; three direct vulnerabilities and first-party fixes qualify as implementation evidence. <!-- SAF-TRACE: claims=SAF-T1507-C008,SAF-T1507-C009,SAF-T1507-C010,SAF-T1507-C011; sources=SRC-cve-2025-4143,SRC-cloudflare-pr26,SRC-cve-2025-4144,SRC-cloudflare-pr27,SRC-rfc9700,SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc7636,SRC-nvd-cleanroom-queries,SRC-cisa-kev-authorization-code-2026-09-01 -->
- **Available Protections**: Current MCP guidance requires PKCE-support verification, S256 when technically capable, exact registered redirects, and token audience validation; current OAuth guidance adds downgrade rejection and single-use handling. <!-- SAF-TRACE: claims=SAF-T1507-C003,SAF-T1507-C004,SAF-T1507-C014,SAF-T1507-C019; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc6749,SRC-rfc8252 -->
- **Residual Risk**: Local callback races, disclosed verifiers, nonconforming servers, legacy plain-PKCE compatibility, incomplete logging, and attacker-first redemption can leave exposure or visibility gaps. <!-- SAF-TRACE: claims=SAF-T1507-C006,SAF-T1507-C007,SAF-T1507-C013; sources=SRC-rfc7636,SRC-rfc9700,SRC-rfc8252,SRC-rfc6749 -->

### Known Breaches and Vulnerabilities

No qualifying production MCP breach was identified in the reviewed official corpus. The selected examples are direct vulnerabilities, ordered by recency and MCP-specific relevance; none is presented as observed exploitation. <!-- SAF-TRACE: claims=SAF-T1507-C011; sources=SRC-nvd-cleanroom-queries,SRC-cisa-kev-authorization-code-2026-09-01,SRC-cve-2025-4143,SRC-cve-2025-4144,SRC-cve-2026-67336 -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| [CVE-2026-67336](https://nvd.nist.gov/vuln/detail/CVE-2026-67336) / [GHSA-9h47-pqcx-hjr4](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) | Published 2026-08-01; Better Auth before 1.6.11 using legacy `oidcProvider` or `mcp` plugins | Plain PKCE could allow interception when the authorization URL leaked; upgrade to 1.6.11, disable plain PKCE, and migrate from the deprecated plugin. Reporter: Subhan Umer; advisory publisher: Gustavo Valverde and Better Auth Security. | Direct vulnerability | The advisory also covers a separate unsigned-token defect; CISA ADP recorded exploitation as none, and no breach is established. <!-- SAF-TRACE: claims=SAF-T1507-C010; sources=SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc7636 --> |
| [CVE-2025-4143](https://nvd.nist.gov/vuln/detail/CVE-2025-4143) | Published 2025-05-01; Cloudflare workers-oauth-provider before 0.0.5 | Authorization-time redirect allowlist failure could expose a code under the CNA's prior-authorization, automatic-reauthorization, and user-navigation conditions; pull request 26 added validation and a regression test. Patch author: Glen Maddern; reviewer: Kenton Varda. | Direct vulnerability | The CNA describes bounded potential impact, not a production incident; CISA ADP recorded exploitation as none. <!-- SAF-TRACE: claims=SAF-T1507-C008; sources=SRC-cve-2025-4143,SRC-cloudflare-pr26 --> |
| [CVE-2025-4144](https://nvd.nist.gov/vuln/detail/CVE-2025-4144) | Published 2025-05-01; Cloudflare workers-oauth-provider before 0.0.5 | A verifier could be accepted for a flow without a challenge, bypassing PKCE through downgrade; pull request 27 added the RFC 9700 rejection and a regression test. Patch author: Glen Maddern; reviewer: Kenton Varda. | Direct vulnerability | No end-to-end exploitation is documented; CISA ADP recorded exploitation as none. <!-- SAF-TRACE: claims=SAF-T1507-C009; sources=SRC-cve-2025-4144,SRC-cloudflare-pr27,SRC-rfc9700 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A redeemed token can expose MCP-accessible data within its audience, scopes, lifetime, and server authorization. <!-- SAF-TRACE: claims=SAF-T1507-C016,SAF-T1507-C019; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2025-4143,SRC-cve-2026-67336 --> |
| Integrity | High | The token can permit actions the MCP server authorizes for its scopes; exact consequences depend on available tools and downstream controls. <!-- SAF-TRACE: claims=SAF-T1507-C016; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2025-4143,SRC-cve-2026-67336 --> |
| Availability | Low | Interception does not inherently disrupt service, although authorized operations reached with the token may have separate availability effects. <!-- SAF-TRACE: claims=SAF-T1507-C016; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2025-4143,SRC-cve-2026-67336 --> |
| Scope | Adjacent | Correct resource indicators and audience validation constrain cross-resource replay, but the intended MCP server remains exposed to the token's permissions. <!-- SAF-TRACE: claims=SAF-T1507-C019; sources=SRC-mcp-authorization-2025-11-25 --> |

### Severity Conditions

- **Severity increases when**: Tokens carry broad scopes, long lifetimes, sensitive-data access, write-capable tools, or downstream authority, and when authorization is silently reused. <!-- SAF-TRACE: claims=SAF-T1507-C016; sources=SRC-mcp-authorization-2025-11-25,SRC-cve-2025-4143,SRC-cve-2026-67336 -->
- **Severity decreases when**: S256 PKCE is transaction-specific and enforced, redirects match exactly, codes are short-lived and single-use, tokens are audience-restricted and narrow, and user approval is required. <!-- SAF-TRACE: claims=SAF-T1507-C014,SAF-T1507-C019; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc6749,SRC-rfc9700,SRC-rfc8252 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Authorization endpoint | Authorization request validation and response issuance | Timestamp, transaction ID, privacy-preserving code fingerprint, `client_id`, redirect URI, redirect-match result, PKCE-required state, challenge method, outcome, and error | Retain enough state to join authorization and token decisions without logging raw codes or verifiers. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 --> |
| Token endpoint | Code exchange, verifier validation, reuse rejection, and token issuance | Timestamp, code fingerprint, client ID, verifier-valid result, exchange count, source context, outcome, error, and known-retry classification | Correlate within the code lifetime and normalize client retries; protect logs as sensitive security telemetry. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 --> |

### Indicators of Compromise (IoCs)

- No incident-specific durable IoC is supported by the reviewed corpus; use endpoint behavior and transaction correlation instead. <!-- SAF-TRACE: claims=SAF-T1507-C011,SAF-T1507-C013; sources=SRC-nvd-cleanroom-queries,SRC-cisa-kev-authorization-code-2026-09-01,SRC-cve-2025-4143,SRC-cve-2025-4144,SRC-cve-2026-67336,SRC-rfc6749,SRC-rfc9700 -->

### Behavioral Indicators

- An authorization request fails exact redirect validation or uses a missing or non-S256 challenge method where PKCE is required. <!-- SAF-TRACE: claims=SAF-T1507-C003,SAF-T1507-C004,SAF-T1507-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc6749,SRC-rfc7636 -->
- A token request fails verifier validation, presents a verifier for a code created without a challenge, or reuses a code fingerprint. <!-- SAF-TRACE: claims=SAF-T1507-C006,SAF-T1507-C009,SAF-T1507-C012; sources=SRC-rfc7636,SRC-rfc9700,SRC-cve-2025-4144,SRC-cloudflare-pr27,SRC-rfc6749 -->
- Source, client, redirect, or user-agent context changes between authorization and token exchange for the same transaction. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Surface redirect, PKCE, verifier, or code-reuse conditions consistent with attempted interception or a protective-control failure. <!-- SAF-TRACE: claims=SAF-T1507-C012; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 -->
- **Rule Status**: Experimental; validated against synthetic representative cases, not production accuracy data. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 -->
- **Detection Logic**: Alert on redirect mismatch, required PKCE that is missing or not S256, failed verifier validation, or a second exchange of the same code fingerprint; suppress explicitly classified known retries. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 -->
- **Correlation Window**: The authorization code's configured lifetime, keyed by a privacy-preserving stable fingerprint and transaction context. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 -->
- **Known False Positives**: A client retry after losing a token response and an incorrect join caused by truncated or unstable fingerprints. <!-- SAF-TRACE: claims=SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc9700 -->
- **Known Limitations**: Successful attacker-first redemption may look normal when no later legitimate exchange occurs; missing authorization logs, verifier disclosure, and unlogged local callback races reduce visibility. <!-- SAF-TRACE: claims=SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc9700 -->
- **Tuning Guidance**: Baseline retry behavior per client, mark verified retries, retain full-entropy keyed fingerprints, and require complete endpoint joins before escalating a code-reuse alert. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 -->

### Validation

- **Test Data**: [test-cases.json](../../tests/SAF-T1507/test-cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1507/test_detection_rule.py)
- **Expected Result**: [Ten cases pass across positive, negative, boundary, malformed, and expected-false-positive categories](../../research/techniques/SAF-T1507/validation/detection-test-results.txt)
- **Last Validated**: [2026-09-01](../../research/techniques/SAF-T1507/validation/detection-test-results.txt)
- **Feasibility Waiver**: None; synthetic deterministic validation passed, while production accuracy remains unmeasured. <!-- SAF-TRACE: claims=SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc9700 -->

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-17: Callback URL Restrictions](../../mitigations/SAF-M-17/README.md)** and **[SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13/README.md)**: Register complete redirect URIs, compare them exactly except for the documented native loopback-port case, and never redirect an invalid authorization request to the supplied URI. <!-- SAF-TRACE: claims=SAF-T1507-C004,SAF-T1507-C014; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc6749,SRC-rfc8252 -->
2. **[SAF-M-38: PKCE Enforcement](../../mitigations/SAF-M-38/README.md)**: Refuse authorization when support is absent, reject `plain` for MCP flows, bind each challenge to its code, validate the verifier, and reject verifier-without-challenge downgrade patterns. <!-- SAF-TRACE: claims=SAF-T1507-C003,SAF-T1507-C006,SAF-T1507-C014; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc7636,SRC-rfc6749,SRC-rfc8252 -->
3. **Harden callback handling** with [SAF-M-13](../../mitigations/SAF-M-13/README.md) and [SAF-M-17](../../mitigations/SAF-M-17/README.md): Prefer claimed HTTPS callbacks where available, bind loopback listeners only while needed, avoid reusable local sockets, and verify state against the initiating transaction. <!-- SAF-TRACE: claims=SAF-T1507-C004,SAF-T1507-C007,SAF-T1507-C014; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc8252,SRC-rfc7636,SRC-rfc6749 -->
4. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Include the MCP resource indicator and validate token audience so a redeemed token is not accepted by an unintended service. <!-- SAF-TRACE: claims=SAF-T1507-C019; sources=SRC-mcp-authorization-2025-11-25 -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Log privacy-preserving authorization and token-endpoint decisions with stable transaction and code joins. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 -->
2. **[SAF-M-18: OAuth Flow Monitoring](../../mitigations/SAF-M-18/README.md)** and **[SAF-M-19: Token Usage Tracking](../../mitigations/SAF-M-19/README.md)**: Alert on redirect mismatch, weak PKCE, verifier failure, and repeated exchange, then investigate expected retry behavior before declaring compromise. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C013; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700 -->

### Response Procedures

#### Immediate Actions

- Stop or invalidate the affected authorization transaction and contain the implicated client registration or callback while preserving relevant logs. <!-- SAF-TRACE: claims=SAF-T1507-C015; sources=SRC-rfc6749,SRC-cloudflare-pr26,SRC-cloudflare-pr27,SRC-ghsa-9h47-pqcx-hjr4 -->
- Use **[SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37/README.md)** to revoke tokens derived from a repeatedly exchanged or suspected-compromised code where the authorization server supports that action. <!-- SAF-TRACE: claims=SAF-T1507-C015; sources=SRC-rfc6749,SRC-cloudflare-pr26,SRC-cloudflare-pr27,SRC-ghsa-9h47-pqcx-hjr4 -->

#### Investigation Steps

- Join authorization and token events by transaction and code fingerprint; compare client, redirect, PKCE method, verifier result, source context, outcome, and sequence. <!-- SAF-TRACE: claims=SAF-T1507-C012,SAF-T1507-C015; sources=SRC-rfc6749,SRC-rfc7636,SRC-rfc9700,SRC-cloudflare-pr26,SRC-cloudflare-pr27,SRC-ghsa-9h47-pqcx-hjr4 -->
- Determine whether a local callback race, malicious redirect, leaked URL, weak verifier, PKCE downgrade, implementation bypass, or legitimate retry best explains the event. <!-- SAF-TRACE: claims=SAF-T1507-C007,SAF-T1507-C008,SAF-T1507-C009,SAF-T1507-C010,SAF-T1507-C013; sources=SRC-rfc8252,SRC-rfc7636,SRC-cve-2025-4143,SRC-cloudflare-pr26,SRC-cve-2025-4144,SRC-cloudflare-pr27,SRC-rfc9700,SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc6749 -->

#### Remediation

- Correct redirect registration and comparison, require S256 PKCE, reject downgrade conditions, and add regression tests for the failed invariant. <!-- SAF-TRACE: claims=SAF-T1507-C014,SAF-T1507-C015; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc6749,SRC-rfc9700,SRC-rfc8252,SRC-cloudflare-pr26,SRC-cloudflare-pr27,SRC-ghsa-9h47-pqcx-hjr4 -->
- Apply the affected product's fixed release and verify authorization metadata and runtime enforcement agree before restoring service. <!-- SAF-TRACE: claims=SAF-T1507-C008,SAF-T1507-C009,SAF-T1507-C010,SAF-T1507-C015; sources=SRC-cve-2025-4143,SRC-cloudflare-pr26,SRC-cve-2025-4144,SRC-cloudflare-pr27,SRC-rfc9700,SRC-cve-2026-67336,SRC-ghsa-9h47-pqcx-hjr4,SRC-rfc7636,SRC-rfc6749 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1009: Authorization Server Mix-up](../SAF-T1009/README.md) | Nearest authorization-flow neighbor | Authorization-server mix-up is excluded unless it produces the defining intercepted-code sequence; SAF-T1507 begins when a victim-issued code reaches an unintended party. <!-- SAF-TRACE: claims=SAF-T1507-C001,SAF-T1507-C018; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc7636 --> |
| [SAF-T1504: Token Theft via API Response](../SAF-T1504/README.md) | Follow-on credential-access neighbor | Response-channel token theft targets an already issued token; this technique targets the authorization code before token issuance. <!-- SAF-TRACE: claims=SAF-T1507-C018; sources=SRC-rfc9700,SRC-rfc7636 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Analogous | The intended outcome is an application access token under Credential Access, but SAF-T1507 acts on the authorization-code precursor and redirect/PKCE boundary rather than stealing an already issued token. <!-- SAF-TRACE: claims=SAF-T1507-C017; sources=SRC-mitre-t1528,SRC-rfc7636 --> |

## References

1. **SRC-mcp-authorization-2025-11-25**: [Model Context Protocol Authorization, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) — Model Context Protocol contributors; OAuth roles, PKCE, redirects, state, resource, and audience requirements.
2. **SRC-rfc6749**: [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html) — Dick Hardt and the OAuth Working Group; authorization-code flow, redirects, single use, and response guidance.
3. **SRC-rfc7636**: [RFC 7636: Proof Key for Code Exchange by OAuth Public Clients](https://www.rfc-editor.org/rfc/rfc7636.html) — Nat Sakimura, John Bradley, Naveen Agarwal, and the OAuth Working Group; interception attack and PKCE.
4. **SRC-rfc8252**: [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252.html) — William Denniss and John Bradley; native, claimed-HTTPS, and loopback callback risks.
5. **SRC-rfc9700**: [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) — Torsten Lodderstedt, John Bradley, Andrey Labunets, and Daniel Fett; exact redirects, code injection, PKCE downgrade, and limitations.
6. **SRC-cve-2026-67336**: [CVE-2026-67336 official record](https://cveawg.mitre.org/api/cve/CVE-2026-67336) — CVE Program and VulnCheck CNA; Better Auth affected and fixed versions and PKCE defect.
7. **SRC-ghsa-9h47-pqcx-hjr4**: [Better Auth GHSA-9h47-pqcx-hjr4](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) — published by Gustavo Valverde and Better Auth Security; reported by Subhan Umer; conditions, impact, fixes, and credit.
8. **SRC-cve-2025-4143**: [CVE-2025-4143 official record](https://cveawg.mitre.org/api/cve/CVE-2025-4143) — Cloudflare Product Security and the CVE Program; redirect-validation vulnerability.
9. **SRC-cloudflare-pr26**: [Cloudflare pull request 26](https://github.com/cloudflare/workers-oauth-provider/pull/26) — Glen Maddern, reviewed by Kenton Varda; redirect validation fix and regression test. Exact URL provenance: SRC-cve-2025-4143;
10. **SRC-cve-2025-4144**: [CVE-2025-4144 official record](https://cveawg.mitre.org/api/cve/CVE-2025-4144) — Cloudflare Product Security and the CVE Program; PKCE downgrade bypass.
11. **SRC-cloudflare-pr27**: [Cloudflare pull request 27](https://github.com/cloudflare/workers-oauth-provider/pull/27) — Glen Maddern, reviewed by Kenton Varda; downgrade rejection and regression test. Exact URL provenance: SRC-cve-2025-4144;
12. **SRC-nvd-cleanroom-queries**: [NVD CVE API](https://services.nvd.nist.gov/developers/vulnerabilities) — NIST NVD Team; official-catalog discovery, exclusion, and bounded saturation evidence only.
13. **SRC-cisa-kev-authorization-code-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — CISA KEV Team; catalog version 2026.09.01 exact-ID review only.
14. **SRC-mitre-t1528**: [MITRE ATT&CK T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) — MITRE ATT&CK Team and named version 1.5 contributors; analogous mapping.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Initial independent clean-room draft with evidence packet and tested detection | OpenAI Codex clean-room research agent (`/root/cleanroom_saf_t1507`) |
