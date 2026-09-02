# SAF-T1506: Infrastructure Token Theft

- **Author**: [OpenAI Codex](../../research/techniques/SAF-T1506/clean-room-attestation.yml)
- **Team**: [SAF-MCP Technique Authoring](../../research/techniques/SAF-T1506/quality-review.yml)

- **Technique ID**: SAF-T1506
- **Tactic**: Credential Access (`ATK-TA0006`)
- **Evidence Status**: Observed
- **Documentation Status**: Stable
- **Research Packet**: [Evidence packet](../../research/techniques/SAF-T1506/)

## Overview

Infrastructure Token Theft is the acquisition or exfiltration of bearer credentials issued to an infrastructure workload, such as cloud instance-role credentials or Kubernetes service-account tokens, from the workload boundary into an attacker-controlled context. Possession of a bearer token is generally sufficient for use within the token's validity and authorization constraints, so disclosure creates a replay risk without proof of a separate cryptographic key. <!-- SAF-TRACE: claims=SAF-T1506-C001; sources=SRC-rfc6750 -->

This technique is assigned to Credential Access (`ATK-TA0006`). It covers token theft, not initial code execution, authorization-code interception, token minting, static developer-secret theft, or subsequent use of the stolen token. <!-- SAF-TRACE: claims=SAF-T1506-C019; sources=SRC-rfc6750,SRC-mcp-authorization-2026-07-28 -->

## Scope

The technique applies when an MCP, agent, gateway, tool, plugin, or adjacent workload can reach a token-bearing source such as a process environment, projected service-account volume, or cloud metadata service and transfers the resulting credential outside its intended trust boundary. Kubernetes projects short-lived service-account tokens into Pods, AWS exposes temporary role credentials through instance metadata, and Google Compute Engine exposes OAuth access tokens through its metadata server. <!-- SAF-TRACE: claims=SAF-T1506-C002; sources=SRC-k8s-service-accounts,SRC-aws-imds-credentials,SRC-gcp-metadata -->

The scope ends once the credential has been acquired. Initial compromise and later API activity belong in adjacent techniques; a deployment without a reachable token source is not presumed vulnerable. <!-- SAF-TRACE: claims=SAF-T1506-C019; sources=SRC-k8s-service-accounts,SRC-rfc9700 -->

## Description

An attacker first obtains an execution or request primitive inside an infrastructure-connected workload. The primitive may be malicious package code, a compromised local server, or a server-side request path. It then reads a token-bearing environment or file, or queries a link-local metadata endpoint, and sends the credential to an attacker-controlled destination. <!-- SAF-TRACE: claims=SAF-T1506-C003,SAF-T1506-C004,SAF-T1506-C006; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28,SRC-fbi-teampcp-2026 -->

MCP makes the boundary relevant because HTTP authorization uses bearer access tokens, STDIO implementations are expected to obtain credentials from the environment, and current MCP security guidance describes malicious authorization metadata and redirects reaching link-local cloud metadata services. <!-- SAF-TRACE: claims=SAF-T1506-C003,SAF-T1506-C004,SAF-T1506-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->

## Attack Vectors

- A malicious MCP authorization response supplies discovery or endpoint URLs that induce a client to request a link-local or private metadata service and follow a redirect that returns credentials. <!-- SAF-TRACE: claims=SAF-T1506-C004; sources=SRC-mcp-security-2026-07-28 -->
- Code executing in an agentic gateway or dependency reads cloud credential environment variables, metadata credentials, or Kubernetes service-account token files and exfiltrates them. <!-- SAF-TRACE: claims=SAF-T1506-C002,SAF-T1506-C006; sources=SRC-litellm-incident-2026,SRC-fbi-teampcp-2026 -->
- A compromised local MCP component inherits credentials from its host environment and transfers them beyond the intended process boundary. <!-- SAF-TRACE: claims=SAF-T1506-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->

## Technical Details

High-value sources include `169.254.169.254` metadata endpoints, AWS role-credential responses containing access key, secret key, and session token values, Google service-account OAuth token responses, and projected Kubernetes service-account token volumes. <!-- SAF-TRACE: claims=SAF-T1506-C002; sources=SRC-aws-imds,SRC-aws-imds-credentials,SRC-gcp-metadata,SRC-k8s-service-account-admin -->

The theft becomes consequential when the token remains valid for a resource the attacker can reach. Audience restriction, sender-constrained tokens, short lifetimes, narrow scopes, and prompt revocation reduce the opportunity and authority available to a thief; they do not retroactively prevent disclosure. <!-- SAF-TRACE: claims=SAF-T1506-C010,SAF-T1506-C015; sources=SRC-rfc6750,SRC-rfc9700,SRC-mcp-authorization-2026-07-28 -->

## Evidence and Current State

### Known Breaches and Vulnerabilities

**Evidence status: Observed.** LiteLLM reported that malicious PyPI releases `1.82.7` and `1.82.8` were live for approximately forty minutes on March 24, 2026 and executed a credential stealer that targeted environment secrets, cloud credentials, and Kubernetes service-account tokens; its official Docker images were unaffected. <!-- SAF-TRACE: claims=SAF-T1506-C006,SAF-T1506-C018; sources=SRC-litellm-incident-2026 -->

The FBI later described the same TeamPCP campaign as extracting AWS credentials and Kubernetes service-account tokens through SANDCLOCK, while Aqua documented a related Trivy supply-chain compromise in which an automation token was extracted and malicious releases targeted cloud and CI/CD credentials. <!-- SAF-TRACE: claims=SAF-T1506-C007; sources=SRC-fbi-teampcp-2026,SRC-aqua-trivy-2026 -->

Two 2025 MCP vulnerabilities establish enabling primitives but not observed infrastructure-token theft: `mcp-remote` versions `0.0.5` through `0.1.15` permitted command execution from a malicious authorization endpoint and were fixed in `0.1.16`; MCP Inspector versions before `0.14.1` exposed an unauthenticated proxy leading to remote code execution and were fixed in `0.14.1`. Their CVE records reported no known exploitation at publication, so neither is treated as a theft incident here. <!-- SAF-TRACE: claims=SAF-T1506-C008,SAF-T1506-C009; sources=SRC-cve-2025-6514,SRC-jfrog-cve-2025-6514,SRC-cve-2025-49596,SRC-oligo-inspector-cve-2025-49596 -->

## Impact Assessment

An acquired bearer token can authorize cloud or cluster operations up to the token's audience, scope, role, validity period, and reachable resource. Potential consequences therefore range from failed replay to access to workload data, secrets, compute, or administrative APIs. <!-- SAF-TRACE: claims=SAF-T1506-C010; sources=SRC-rfc6750,SRC-rfc9700,SRC-mcp-authorization-2026-07-28 -->

Severity is **High** when a production workload exposes broadly privileged, replayable infrastructure tokens to an MCP or agent process with outbound network access. Severity is lower when sender constraints, resource binding, short lifetimes, least privilege, or egress controls prevent useful replay. <!-- SAF-TRACE: claims=SAF-T1506-C011; sources=SRC-rfc9700,SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->

## Detection Methods

Monitor MCP authorization and HTTP client telemetry for discovery, token, or metadata requests whose resolved destination or redirect target is loopback, private, reserved, or link-local, especially `169.254.169.254`. OpenTelemetry HTTP client spans can expose method, full URL, server address, peer address, status, and response size for this analytic. <!-- SAF-TRACE: claims=SAF-T1506-C012; sources=SRC-mcp-security-2026-07-28,SRC-otel-http-spans-1.44.0 -->

Correlate those network events with the initiating MCP client or gateway identity, unexpected reads of projected service-account token paths or credential environment variables, new outbound destinations, and subsequent cloud or Kubernetes API calls from an unfamiliar source. The supplied detector deliberately recognizes only the network path and needs process and cloud audit correlation for higher confidence. <!-- SAF-TRACE: claims=SAF-T1506-C013; sources=SRC-fbi-teampcp-2026,SRC-litellm-incident-2026,SRC-otel-http-spans-1.44.0 -->

Legitimate cloud SDKs, node agents, and metadata-aware health tooling can contact metadata endpoints; missing DNS, redirect, or process context can also conceal the behavior. Preventive egress blocking can remove the very network event being sought, and ephemeral indicators should be treated as contextual rather than durable signatures. <!-- SAF-TRACE: claims=SAF-T1506-C014,SAF-T1506-C021; sources=SRC-mcp-security-2026-07-28,SRC-fbi-teampcp-2026 -->

### Validation

- **Rule**: [detection-rule.yml](detection-rule.yml)
- **Fixtures**: [fixtures.jsonl](../../tests/SAF-T1506/fixtures.jsonl)
- **Runner**: [test_detection.py](../../tests/SAF-T1506/test_detection.py)
- **Detection Result**: [8 of 8 cases passed](../../research/techniques/SAF-T1506/validation/detection-test.txt)
- **Strict Result**: [PASS SAF-T1506](../../research/techniques/SAF-T1506/validation/strict-validation.txt)

## Mitigation Strategies

- **[SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13/README.md)** and **[SAF-M-17: Callback URL Restrictions](../../mitigations/SAF-M-17/README.md)**: Block MCP authorization discovery and redirect targets that resolve to loopback, private, reserved, or link-local addresses; revalidate every redirect and use controlled egress where possible. <!-- SAF-TRACE: claims=SAF-T1506-C015; sources=SRC-mcp-security-2026-07-28 -->
- **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)** and **[SAF-M-31: Proof of Possession Tokens](../../mitigations/SAF-M-31/README.md)**: Use short-lived, audience-bound, least-privilege tokens and sender constraints where supported; do not transit tokens intended for another resource. <!-- SAF-TRACE: claims=SAF-T1506-C015; sources=SRC-rfc9700,SRC-mcp-authorization-2026-07-28 -->
- **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)** and **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Sandbox local MCP servers and avoid placing infrastructure credentials in environments inherited by components that do not need them. <!-- SAF-TRACE: claims=SAF-T1506-C005,SAF-T1506-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->
- **[SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37/README.md)** and **[SAF-M-24: Supply Chain Security](../../mitigations/SAF-M-24/README.md)**: After suspected theft, revoke or rotate exposed tokens and related credentials, upgrade affected packages, and review cloud and cluster audit activity for unauthorized use. <!-- SAF-TRACE: claims=SAF-T1506-C016; sources=SRC-litellm-incident-2026,SRC-aqua-trivy-2026,SRC-fbi-teampcp-2026 -->

## Related Techniques

- [SAF-T1502: File-Based Credential Harvest](../SAF-T1502/README.md) overlaps when an infrastructure token is read from a projected file; SAF-T1506 requires an infrastructure-issued workload credential and ends at its acquisition. <!-- SAF-TRACE: claims=SAF-T1506-C019,SAF-T1506-C020; sources=SRC-rfc6750,SRC-k8s-service-accounts -->
- [SAF-T1507: Authorization Code Interception](../SAF-T1507/README.md) concerns authorization-flow material before token issuance; SAF-T1506 starts with an issued workload token at an infrastructure-local source. <!-- SAF-TRACE: claims=SAF-T1506-C019,SAF-T1506-C020; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc6750 -->

## MITRE ATT&CK Mapping

- [T1552.005 Unsecured Credentials: Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/) maps metadata-service credential retrieval. <!-- SAF-TRACE: claims=SAF-T1506-C017; sources=SRC-mitre-t1552.005 -->
- [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) overlaps theft of cloud and Kubernetes access tokens; SAF-T1506 narrows the subject to infrastructure-issued workload tokens in MCP and agentic execution boundaries. <!-- SAF-TRACE: claims=SAF-T1506-C017; sources=SRC-mitre-t1528 -->

## References

- `SRC-rfc6750` — OAuth 2.0 Bearer Token Usage, RFC 6750. <!-- SAF-TRACE: claims=SAF-T1506-C001,SAF-T1506-C010; sources=SRC-rfc6750 -->
- `SRC-rfc9700` — Best Current Practice for OAuth 2.0 Security, RFC 9700. <!-- SAF-TRACE: claims=SAF-T1506-C010,SAF-T1506-C015; sources=SRC-rfc9700 -->
- `SRC-mcp-authorization-2026-07-28` and `SRC-mcp-security-2026-07-28` — current MCP authorization and security guidance. <!-- SAF-TRACE: claims=SAF-T1506-C003,SAF-T1506-C004,SAF-T1506-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->
- `SRC-litellm-incident-2026`, `SRC-fbi-teampcp-2026`, and `SRC-aqua-trivy-2026` — directly reviewed incident authorities. <!-- SAF-TRACE: claims=SAF-T1506-C006,SAF-T1506-C007,SAF-T1506-C018; sources=SRC-litellm-incident-2026,SRC-fbi-teampcp-2026,SRC-aqua-trivy-2026 -->
- `SRC-cve-2025-6514`, `SRC-jfrog-cve-2025-6514`, `SRC-cve-2025-49596`, and `SRC-oligo-inspector-cve-2025-49596` — CVE records and original vulnerability research. <!-- SAF-TRACE: claims=SAF-T1506-C008,SAF-T1506-C009; sources=SRC-cve-2025-6514,SRC-jfrog-cve-2025-6514,SRC-cve-2025-49596,SRC-oligo-inspector-cve-2025-49596 -->

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0.0 | 2026-09-01 | Initial clean-room release candidate. |
