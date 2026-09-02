# SAF-T1707: CSRF Token Relay

- **Tactic**: ATK-TA0008
- **Technique ID**: SAF-T1707
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: Medium
- **Last Updated**: 2026-09-02
- **Research Packet**: [research/techniques/SAF-T1707/](../../research/techniques/SAF-T1707/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1707/traceability-ledger.yml)

## Overview

CSRF Token Relay abuses an otherwise valid OAuth anti-CSRF value outside the browser session that initiated it, causing an authorization callback to complete or bind an attacker-controlled authorization result in a victim context. <!-- SAF-TRACE: claims=SAF-T1707-C007; sources=SRC-rfc9700-state-relay,SRC-mcp-authorization-2026-07-28 -->

The defining failure is not that `state` is absent or invalid; it is that acceptance proves only token validity or equality and not continuity with the initiating user-agent session. <!-- SAF-TRACE: claims=SAF-T1707-C004,SAF-T1707-C007; sources=SRC-rfc9700-state-relay,SRC-fastapi-advisory,SRC-authlib-advisory -->

## Scope

- **In scope**:
  - A valid, attacker-obtained `state` value is accepted from a different browser or session, and the callback completes an attacker-originated authorization flow or misbinds an account. <!-- SAF-TRACE: claims=SAF-T1707-C007; sources=SRC-rfc9700-state-relay,SRC-fastapi-advisory,SRC-authlib-advisory -->
  - Weak client-side binding, including a cookie an attacker-controlled sibling origin can plant, permits the relayed state and callback context to match. <!-- SAF-TRACE: claims=SAF-T1707-C010; sources=SRC-fastify-advisory,SRC-nvd-2026-18165 -->
- **Out of scope**:
  - Callbacks that omit or fail to validate `state`; those are ordinary OAuth CSRF rather than relay of a valid anti-CSRF token. <!-- SAF-TRACE: claims=SAF-T1707-C012; sources=SRC-openclaw-advisory,SRC-nvd-saturation-1 -->
  - Authorization-code interception or injection where PKCE or issuer binding is the defining failed boundary. <!-- SAF-TRACE: claims=SAF-T1707-C005; sources=SRC-rfc9700-state-relay,SRC-rfc7636-state-relay -->
  - Bearer-token theft, token passthrough, open redirects, phishing, and downstream actions after authentication. <!-- SAF-TRACE: claims=SAF-T1707-C001; sources=SRC-mcp-authorization-2026-07-28 -->

## Description

In MCP over HTTP, the MCP client is the OAuth client and the MCP server is the resource server; the authorization server authenticates the user and issues tokens. <!-- SAF-TRACE: claims=SAF-T1707-C001; sources=SRC-mcp-authorization-2026-07-28 -->

The current MCP authorization specification requires clients to associate the authorization-server issuer with the same per-request record used for PKCE and, when present, `state`; the MCP security guidance separately requires a fresh state value, storage in the callback session, exact matching, short expiry, and single use. <!-- SAF-TRACE: claims=SAF-T1707-C002,SAF-T1707-C003; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-spec-2026-07-28 -->

OAuth security guidance requires CSRF protection to be bound to the user agent. It also explains that an attacker who learns `state` may replay it with a forged response, while PKCE provides a stronger authorization-response binding against that attacker model. <!-- SAF-TRACE: claims=SAF-T1707-C004,SAF-T1707-C005; sources=SRC-rfc9700-state-relay,SRC-oauth21-draft13 -->

## Attack Vectors

1. The attacker initiates an OAuth authorization request and obtains a valid per-flow `state` value plus an attacker-owned authorization response. <!-- SAF-TRACE: claims=SAF-T1707-C007; sources=SRC-rfc9700-state-relay,SRC-fastapi-advisory,SRC-authlib-advisory -->
2. The attacker causes a victim browser to reach the client callback with the attacker-controlled response and the still-valid state value. <!-- SAF-TRACE: claims=SAF-T1707-C006,SAF-T1707-C007; sources=SRC-fett-oauth-state-leak,SRC-fastapi-advisory -->
3. The client validates signature, expiry, or a plantable cookie but does not verify that the callback session is the session that created the authorization request. <!-- SAF-TRACE: claims=SAF-T1707-C008,SAF-T1707-C009,SAF-T1707-C010; sources=SRC-fastapi-advisory,SRC-authlib-advisory,SRC-fastify-advisory -->
4. The callback succeeds and authenticates the victim context as the attacker or links an attacker-controlled provider identity, with consequences determined by application account-linking logic. <!-- SAF-TRACE: claims=SAF-T1707-C008,SAF-T1707-C009,SAF-T1707-C017; sources=SRC-fastapi-advisory,SRC-authlib-advisory -->

## Technical Details

The formal OAuth State Leak Attack demonstrates the mechanism outside MCP: a leaked state value and authorization result can be replayed through a victim browser and violate login-session integrity. <!-- SAF-TRACE: claims=SAF-T1707-C006; sources=SRC-fett-oauth-state-leak -->

FastAPI Users accepted a signed, unexpired state JWT that lacked per-request entropy and browser correlation; Authlib accepted cache-backed state that was not tied to the initiating browser; and `@fastify/oauth2` compared state and a PKCE verifier with cookies a related host could plant. <!-- SAF-TRACE: claims=SAF-T1707-C008,SAF-T1707-C009,SAF-T1707-C010; sources=SRC-fastapi-advisory,SRC-authlib-advisory,SRC-fastify-advisory -->

These disclosures establish the relay primitive in OAuth clients, but they do not establish exploitation of an MCP deployment. Applying the primitive to the MCP client boundary is therefore an explicit inference. <!-- SAF-TRACE: claims=SAF-T1707-C007,SAF-T1707-C011; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700-state-relay,SRC-cisa-kev-2026-09-01 -->

## Evidence and Current State

The evidence status is **Research-Derived** because direct standards, formal analysis, and disclosed vulnerabilities support the mechanism, while no reviewed authority documented an end-to-end production MCP or agentic incident using a relayed valid CSRF token as of 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1707-C011,SAF-T1707-C019; sources=SRC-mcp-doc-index-2026,SRC-nvd-state-query,SRC-cisa-kev-2026-09-01 -->

The three selected vulnerability examples were chosen for directness and bounded impact: FastAPI Users and Authlib permit attacker-originated login or account-link flows to complete in a victim browser, while the Fastify case demonstrates that matching state and PKCE cookies can still fail when the cookie boundary is attacker-writable. <!-- SAF-TRACE: claims=SAF-T1707-C008,SAF-T1707-C009,SAF-T1707-C010; sources=SRC-fastapi-advisory,SRC-authlib-advisory,SRC-fastify-advisory -->

The CISA Known Exploited Vulnerabilities catalog did not list the selected CVEs at review time; absence from that catalog is not evidence that exploitation has not occurred. <!-- SAF-TRACE: claims=SAF-T1707-C011; sources=SRC-cisa-kev-2026-09-01 -->

### Evidence Summary

| Claim | Summary | Evidence |
|---|---|---|
| SAF-T1707-C001 | MCP OAuth roles and token boundary | SRC-mcp-authorization-2026-07-28 |
| SAF-T1707-C002 | MCP per-request response record | SRC-mcp-authorization-2026-07-28 |
| SAF-T1707-C003 | MCP state-validation requirements | SRC-mcp-security-spec-2026-07-28 |
| SAF-T1707-C004 | User-agent binding requirement | SRC-rfc9700-state-relay |
| SAF-T1707-C005 | State replay and PKCE distinction | SRC-rfc9700-state-relay, SRC-rfc7636-state-relay |
| SAF-T1707-C006 | Formal State Leak Attack | SRC-fett-oauth-state-leak |
| SAF-T1707-C007 | MCP application of the relay primitive | SRC-mcp-authorization-2026-07-28, SRC-rfc9700-state-relay |
| SAF-T1707-C008 | FastAPI Users disclosure | SRC-fastapi-advisory, SRC-nvd-2025-68481 |
| SAF-T1707-C009 | Authlib disclosure | SRC-authlib-advisory, SRC-nvd-2025-68158 |
| SAF-T1707-C010 | Fastify disclosure | SRC-fastify-advisory, SRC-nvd-2026-18165 |
| SAF-T1707-C011 | Production-evidence gap | SRC-cisa-kev-2026-09-01, SRC-nvd-state-query |
| SAF-T1707-C012 | OpenClaw adjacent-case boundary | SRC-openclaw-advisory, SRC-nvd-2026-28477 |
| SAF-T1707-C013 | Detection telemetry design | SRC-owasp-logging-cheat-sheet |
| SAF-T1707-C014 | Cross-session correlation analytic | SRC-owasp-logging-cheat-sheet, LOCAL-detection-rule |
| SAF-T1707-C015 | Preventive transaction binding | SRC-mcp-security-spec-2026-07-28, SRC-rfc9700-state-relay |
| SAF-T1707-C016 | Detection limitations | SRC-owasp-logging-cheat-sheet, LOCAL-detection-rule |
| SAF-T1707-C017 | Conditional impact | SRC-fastapi-advisory, SRC-authlib-advisory |
| SAF-T1707-C018 | ATT&CK delivery analogy | SRC-mitre-t1204-001 |
| SAF-T1707-C019 | Research-derived classification | SRC-mcp-doc-index-2026, SRC-rfc9700-state-relay |

## Impact Assessment

The immediate result is session swapping or account misbinding; account takeover is possible only when the application automatically links an attacker-controlled provider identity to a victim account or exposes an equivalent account-management transition. <!-- SAF-TRACE: claims=SAF-T1707-C017; sources=SRC-fastapi-advisory,SRC-authlib-advisory -->

The technique does not by itself disclose the victim's credentials or tokens, as the Fastify advisory expressly bounds its login-CSRF outcome. <!-- SAF-TRACE: claims=SAF-T1707-C010,SAF-T1707-C017; sources=SRC-fastify-advisory -->

## Detection Methods

Log authorization-request creation, callback validation, and successful token or account-binding completion with a stable interaction identifier, a keyed digest of `state`, client and redirect identifiers, timestamps, and a privacy-preserving session-binding identifier. Do not record raw state, access tokens, or session identifiers. <!-- SAF-TRACE: claims=SAF-T1707-C013; sources=SRC-owasp-logging-cheat-sheet -->

Correlate successful callbacks to the request that created the same state digest. Alert when the initiating and callback session bindings differ, or when one state digest is accepted more than once within its validity window. <!-- SAF-TRACE: claims=SAF-T1707-C014; sources=SRC-owasp-logging-cheat-sheet -->

The repository analytic and deterministic tests are available in [detection-rule.yml](detection-rule.yml) and [test_detection.py](../../tests/SAF-T1707/test_detection.py).

Canonical validation evidence is retained in the [detector transcript](../../research/techniques/SAF-T1707/validation/detection-test.txt) and [strict-validator transcript](../../research/techniques/SAF-T1707/validation/strict-validator.txt).

Architectures that intentionally broker callbacks across browser processes must normalize the legitimate binding before applying this analytic; missing request-start logs and clock or identifier drift can otherwise create false positives or false negatives. <!-- SAF-TRACE: claims=SAF-T1707-C016; sources=SRC-owasp-logging-cheat-sheet -->

## Mitigation Strategies

Apply [SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13/README.md): generate a cryptographically random state value per authorization request, store it in a server-side or protected session record bound to the initiating user agent, require exact callback-session matching, expire it quickly, and consume it once. <!-- SAF-TRACE: claims=SAF-T1707-C003,SAF-T1707-C015; sources=SRC-mcp-security-spec-2026-07-28,SRC-rfc9700-state-relay -->

Apply [SAF-M-38: PKCE Enforcement](../../mitigations/SAF-M-38/README.md) alongside SAF-M-13: use PKCE and authorization-response issuer validation as independent transaction bindings; do not treat a signed state value or query-to-cookie equality as proof that the same browser initiated the flow. <!-- SAF-TRACE: claims=SAF-T1707-C002,SAF-T1707-C005,SAF-T1707-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700-state-relay,SRC-rfc7636-state-relay -->

Apply [SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md) and [SAF-M-18: OAuth Flow Monitoring](../../mitigations/SAF-M-18/README.md) to retain the privacy-preserving request, callback, duplicate-acceptance, and completion events required by the analytic. <!-- SAF-TRACE: claims=SAF-T1707-C013,SAF-T1707-C014; sources=SRC-owasp-logging-cheat-sheet -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1009: Authorization Server Mix-up](../SAF-T1009/README.md) | Neighbor | Mix-up misbinds the authorization-server issuer; SAF-T1707 accepts a valid state outside the user-agent session that created it. <!-- SAF-TRACE: claims=SAF-T1707-C002,SAF-T1707-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-spec-2026-07-28,SRC-rfc9700-state-relay,SRC-rfc7636-state-relay --> |
| [SAF-T1507: Authorization Code Interception](../SAF-T1507/README.md) | Neighbor | Interception steals or injects an authorization code; SAF-T1707 relays valid anti-CSRF state across browser-session boundaries. <!-- SAF-TRACE: claims=SAF-T1707-C005; sources=SRC-rfc9700-state-relay,SRC-rfc7636-state-relay --> |
| [SAF-T1706: OAuth Token Pivot Replay](../SAF-T1706/README.md) | Neighbor | Token pivot replay presents an issued access token at a protected resource; SAF-T1707 occurs while the callback transaction or account binding is being completed. <!-- SAF-TRACE: claims=SAF-T1707-C001,SAF-T1707-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc9700-state-relay,SRC-rfc7636-state-relay --> |

## MITRE ATT&CK Mapping

**T1204.001 User Execution: Malicious Link — Analogous (delivery only).** A malicious link can deliver the relayed callback to a victim, but this ATT&CK technique does not describe the OAuth session-binding failure and is not a direct mapping. <!-- SAF-TRACE: claims=SAF-T1707-C018; sources=SRC-mitre-t1204-001 -->

## References

- [SRC-mcp-authorization-2026-07-28] Model Context Protocol, “Authorization,” protocol revision 2026-07-28.
- [SRC-mcp-security-spec-2026-07-28] Model Context Protocol, “Security Best Practices,” protocol revision 2026-07-28.
- [SRC-mcp-doc-index-2026] Model Context Protocol, official documentation index, accessed 2026-09-02.
- [SRC-rfc9700-state-relay] Lodderstedt, Bradley, Labunets, and Fett, RFC 9700, January 2025.
- [SRC-rfc7636-state-relay] Sakimura, Bradley, and Agarwal, RFC 7636, September 2015.
- [SRC-oauth21-draft13] Parecki and Lodderstedt, OAuth 2.1 draft 13, May 2024.
- [SRC-fett-oauth-state-leak] Fett, Küsters, and Schmitz, “A Comprehensive Formal Security Analysis of OAuth 2.0,” 2016.
- [SRC-fastapi-advisory] FastAPI Users advisory GHSA-5j53-63w8-8625, 2025.
- [SRC-nvd-2025-68481] NVD record CVE-2025-68481.
- [SRC-authlib-advisory] Authlib advisory GHSA-fg6f-75jq-6523, 2025.
- [SRC-nvd-2025-68158] NVD record CVE-2025-68158.
- [SRC-fastify-advisory] `@fastify/oauth2` advisory GHSA-p8h8-rj28-m8q9, 2026.
- [SRC-nvd-2026-18165] NVD record CVE-2026-18165.
- [SRC-openclaw-advisory] OpenClaw advisory GHSA-7rcp-mxpq-72pj, 2026.
- [SRC-nvd-2026-28477] NVD record CVE-2026-28477.
- [SRC-nvd-state-query] NVD keyword-query result set, accessed 2026-09-02.
- [SRC-nvd-saturation-1] NVD authority-only saturation query, accessed 2026-09-02.
- [SRC-cisa-kev-2026-09-01] CISA Known Exploited Vulnerabilities catalog, accessed 2026-09-02.
- [SRC-owasp-logging-cheat-sheet] OWASP Logging Cheat Sheet, accessed 2026-09-02.
- [SRC-mitre-t1204-001] MITRE ATT&CK T1204.001, version 1.2.

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-02 | Independent clean-room research, tested analytic, and evidence packet completed. |
