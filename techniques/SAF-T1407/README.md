# SAF-T1407: Server Proxy Masquerade

## Overview

- **Tactic**: Defense Evasion (ATK-TA0005)
- **Technique ID**: SAF-T1407
- **Research Packet**: [research/techniques/SAF-T1407](../../research/techniques/SAF-T1407/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1407/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A successful endpoint-identity deception can expose bearer tokens, tool arguments, and returned data or enable altered results; impact depends on token privilege, tool sensitivity, and invocation automation. <!-- SAF-TRACE: claims=SAF-T1407-C021; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-mcp-tools-2025-11-25 -->
- **First Observed**: Not observed in production in the bounded authoritative corpus reviewed through 2026-09-01; the earliest selected public MCP endpoint-identity demonstration was published 2026-05-28. <!-- SAF-TRACE: claims=SAF-T1407-C012,SAF-T1407-C024; sources=SRC-nvd-mcp-proxy-identity-corpus-2026,SRC-cisa-kev-2026-09-01,SRC-ghsa-apify-authority -->
- **Last Updated**: 2026-09-01
- **Technique Author**: OpenAI Codex clean-room author; named source authors and research teams are credited in the evidence and references. [Clean-room attestation](../../research/techniques/SAF-T1407/clean-room-attestation.yml)

## Scope

Server Proxy Masquerade covers an attacker-controlled MCP endpoint that appears to be an approved server or protected resource while it relays, is positioned to relay, or reuses MCP or OAuth exchanges associated with a legitimate service. The crossed boundary is the host or client's trust in the configured remote-server identity and its bound authorization relationship. <!-- SAF-TRACE: claims=SAF-T1407-C004,SAF-T1407-C006,SAF-T1407-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728 -->

### In Scope

- An attacker-controlled endpoint claims a legitimate MCP resource identifier or authorization-server association and receives credentials meant for the real resource. <!-- SAF-TRACE: claims=SAF-T1407-C006,SAF-T1407-C008; sources=SRC-rfc9728,SRC-ghsa-librechat-resource -->
- URL-authority confusion causes a nested MCP client to connect and attach a bearer token to an attacker authority that appears within a trusted service path. <!-- SAF-TRACE: claims=SAF-T1407-C009; sources=SRC-ghsa-apify-authority -->
- A remote HTTP MCP endpoint presents a trusted-looking server association while relaying, observing, modifying, or reusing authorization or tool exchanges. <!-- SAF-TRACE: claims=SAF-T1407-C002,SAF-T1407-C007,SAF-T1407-C025; sources=SRC-mcp-transports-2025-11-25,SRC-mcp-authorization-2025-11-25,SRC-rfc9728,SRC-mcp-security-2025-11-25 -->

### Out of Scope

- Discovery, registry substitution, DNS compromise, or configuration tampering used only to place a hostile endpoint in configuration is assigned to [SAF-T1004: Server Impersonation / Name-Collision](../SAF-T1004/README.md); this technique begins when that endpoint acts through a deceptive server identity or association. <!-- SAF-TRACE: claims=SAF-T1407-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728 -->
- A legitimate or compromised server changing its own tool content without impersonating another server is assigned to [SAF-T1404: Response Tampering](../SAF-T1404/README.md). <!-- SAF-TRACE: claims=SAF-T1407-C019; sources=SRC-trustshiftprobe -->
- Token forwarding by an accurately identified gateway without identity deception is assigned to [SAF-T1304: Credential Relay Chain](../SAF-T1304/README.md). <!-- SAF-TRACE: claims=SAF-T1407-C004,SAF-T1407-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728 -->
- Direct local stdio without a proxy does not cross the remote endpoint-identity boundary, although a local proxy can create an equivalent boundary. <!-- SAF-TRACE: claims=SAF-T1407-C025; sources=SRC-mcp-transports-2025-11-25,SRC-mcp-security-2025-11-25 -->

### Distinguishing Characteristics

The defining signal is relational: the endpoint, TLS peer, protected-resource value, authorization-server set, or presented server/tool identity conflicts with the approved association, and a relay-like or credential-reuse condition is present. Mere unapproved-server use, server-controlled content changes, or token forwarding without identity deception is insufficient. <!-- SAF-TRACE: claims=SAF-T1407-C013,SAF-T1407-C014,SAF-T1407-C019,SAF-T1407-C023; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-trustshiftprobe -->

## Description

MCP creates a stateful one-to-one client connection to a server, and Streamable HTTP concentrates exchanges at one endpoint. Servers control the tool metadata and results returned through that connection, but those protocol messages do not prove whether the endpoint originated them or relayed them from elsewhere. <!-- SAF-TRACE: claims=SAF-T1407-C001,SAF-T1407-C002,SAF-T1407-C003; sources=SRC-mcp-architecture,SRC-mcp-transports-2025-11-25,SRC-mcp-tools-2025-11-25 -->

For HTTP authorization, the MCP server is an OAuth protected resource. The client discovers authorization servers from resource metadata, requests a resource-bound token, and sends it to the selected server. RFC 9728 requires exact resource-identifier and TLS checks because a malicious resource can impersonate a legitimate one, induce token issuance for that resource, or proxy a valid authorization server through an inappropriate association. <!-- SAF-TRACE: claims=SAF-T1407-C004,SAF-T1407-C005,SAF-T1407-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728 -->

The end-to-end SAF behavior is an explicit inference from those protocol roles and threat conditions, supported by controlled MCP demonstrations. LibreChat's disclosed flaw demonstrated a fake MCP endpoint claiming the real resource and authorization servers before receiving the real-resource token, while Apify's disclosed flaw demonstrated a trusted-looking path resolving a nested MCP client and bearer token to a different authority. Neither advisory establishes production exploitation or a transparent relay of every MCP method. <!-- SAF-TRACE: claims=SAF-T1407-C007,SAF-T1407-C008,SAF-T1407-C009,SAF-T1407-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728,SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-nvd-mcp-proxy-identity-corpus-2026,SRC-cisa-kev-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: A remote MCP endpoint supplies or derives protected-resource or URL-authority data that binds a trusted service identity to an attacker-controlled destination. <!-- SAF-TRACE: claims=SAF-T1407-C008,SAF-T1407-C009,SAF-T1407-C025; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-mcp-transports-2025-11-25,SRC-mcp-security-2025-11-25 -->
- **Secondary Vectors**: A malicious or hijacked server abuses a proxy client's trust path, or unvalidated OAuth discovery URLs steer a client toward attacker or internal destinations. <!-- SAF-TRACE: claims=SAF-T1407-C010,SAF-T1407-C011; sources=SRC-jfrog-cve-2025-6514,SRC-ghsa-spring-ssrf -->
- **Affected Components**: MCP hosts and clients, Streamable HTTP transport, TLS peer validation, protected-resource metadata, authorization-server discovery, initialization identity, tool discovery, invocations, and results. <!-- SAF-TRACE: claims=SAF-T1407-C002,SAF-T1407-C003,SAF-T1407-C004,SAF-T1407-C013; sources=SRC-mcp-transports-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-mcp-authorization-2025-11-25,SRC-rfc9728 -->
- **Trust Boundary Crossed**: The approval and authorization association between the intended MCP server identity and the endpoint actually receiving protocol data. <!-- SAF-TRACE: claims=SAF-T1407-C005,SAF-T1407-C007; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25 -->

## Technical Details

### Prerequisites

- The client uses remote HTTP MCP, a nested MCP client, a gateway, or another proxy-created identity boundary. <!-- SAF-TRACE: claims=SAF-T1407-C025; sources=SRC-mcp-transports-2025-11-25,SRC-mcp-security-2025-11-25,SRC-ghsa-apify-authority -->
- The adversary controls an endpoint or server-provided identity or URL value that the client accepts as associated with an intended service. <!-- SAF-TRACE: claims=SAF-T1407-C006,SAF-T1407-C008,SAF-T1407-C009; sources=SRC-rfc9728,SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority -->
- At least one identity control is missing or ineffective, such as exact resource matching, destination validation, TLS identity verification, or an approved authorization-server association. <!-- SAF-TRACE: claims=SAF-T1407-C005,SAF-T1407-C016; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-rfc8707 -->

### Attack Flow

1. **Setup**: The adversary prepares an endpoint or server-controlled value that appears related to a trusted MCP resource or service path. <!-- SAF-TRACE: claims=SAF-T1407-C007,SAF-T1407-C008,SAF-T1407-C009; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728,SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority -->
2. **Connection**: The client resolves or accepts that identity and starts Streamable HTTP or nested MCP exchanges with the attacker-controlled destination. <!-- SAF-TRACE: claims=SAF-T1407-C002,SAF-T1407-C009; sources=SRC-mcp-transports-2025-11-25,SRC-ghsa-apify-authority -->
3. **Association**: Protected-resource metadata, an authorization-server set, or a trusted-looking URL causes the destination to remain associated with the legitimate service in the client's trust decision. <!-- SAF-TRACE: claims=SAF-T1407-C004,SAF-T1407-C006,SAF-T1407-C008; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728,SRC-ghsa-librechat-resource -->
4. **Boundary Crossing**: The client sends a token, tool arguments, or other MCP data before detecting that the receiving endpoint differs from the approved identity. <!-- SAF-TRACE: claims=SAF-T1407-C008,SAF-T1407-C009,SAF-T1407-C021; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-mcp-tools-2025-11-25 -->
5. **Objective**: The endpoint observes, reuses, relays, or alters the available exchange within the authority granted to that session. <!-- SAF-TRACE: claims=SAF-T1407-C006,SAF-T1407-C007,SAF-T1407-C021; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority -->
6. **Follow-On Activity**: Credential reuse or changed results can affect the real service or host decisions, but impact remains bounded by token audience, privilege, exposed tools, and approval gates. <!-- SAF-TRACE: claims=SAF-T1407-C017,SAF-T1407-C018,SAF-T1407-C021; sources=SRC-rfc9700,SRC-rfc8707,SRC-mcp-tools-2025-11-25,SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority -->

### Example Scenario

A synthetic client approves `https://mcp.example.invalid`, but telemetry records a different TLS peer and a protected-resource value for `https://trusted.example.invalid`. The client obtains a token for the trusted resource and sends it to the connected endpoint. The analytic alerts because an approved-identity mismatch and a relay-like authorization association occur together; the example contains no usable credentials or endpoint. <!-- SAF-TRACE: claims=SAF-T1407-C008,SAF-T1407-C013,SAF-T1407-C014; sources=SRC-ghsa-librechat-resource,SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-trustshiftprobe -->

```json
{
  "approved_server_uri": "https://mcp.example.invalid",
  "connected_authority": "relay.example.invalid",
  "protected_resource": "https://trusted.example.invalid",
  "token": "synthetic-redacted",
  "result": "identity_mismatch_with_relay_signal"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1407-C001 | MCP clients maintain stateful one-to-one server connections. | Demonstrated | SRC-mcp-architecture: [MCP Architecture](https://modelcontextprotocol.io/specification/2025-11-25/architecture) | The architecture alone does not authenticate the intended server. |
| SAF-T1407-C002 | Streamable HTTP uses one endpoint with session and version state. | Demonstrated | SRC-mcp-transports-2025-11-25: [MCP Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | No end-to-end upstream provenance is defined. |
| SAF-T1407-C003 | Servers supply tool metadata, arguments interfaces, and results. | Demonstrated | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Messages do not reveal whether an endpoint relayed them. |
| SAF-T1407-C004 | HTTP MCP servers are OAuth protected resources with discovered authorization associations and audience validation. | Demonstrated | SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | Authorization is optional and the claim applies to HTTP authorization deployments. |
| SAF-T1407-C005 | Exact resource matching and TLS checking prevent protected-resource impersonation of the configured identifier. | Demonstrated | SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | They cannot prove the user selected the intended identifier. |
| SAF-T1407-C006 | A malicious resource can induce token issuance for a legitimate resource or proxy an authorization server through an unsafe association. | Research-Derived | SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | The standard states a threat condition, not an MCP production incident. |
| SAF-T1407-C007 | MCP's resource role and the RFC threat conditions support the server-proxy masquerade inference. | Research-Derived | SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html); SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Not every masquerading endpoint relays every method. |
| SAF-T1407-C008 | CVE-2026-54030 demonstrates a fake MCP endpoint receiving a token issued for a legitimate resource. | Demonstrated | SRC-ghsa-librechat-resource: [LibreChat advisory](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-gvpj-vm2f-2m23) | Controlled proof of concept; no production exploitation is documented. |
| SAF-T1407-C009 | CVE-2026-50143 demonstrates wrong-authority MCP connection and bearer-token delivery. | Demonstrated | SRC-ghsa-apify-authority: [Apify advisory](https://github.com/apify/apify-mcp-server/security/advisories/GHSA-6gr2-qh89-hxwm) | It does not demonstrate a full transparent upstream relay. |
| SAF-T1407-C010 | CVE-2025-6514 lets a malicious or hijacked server trigger client command execution in affected mcp-remote versions. | Demonstrated | SRC-jfrog-cve-2025-6514: [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) | Enabling vulnerability, not proof of upstream relay. |
| SAF-T1407-C011 | CVE-2026-45609 permits unvalidated OAuth URL fetching when dynamic client registration is enabled. | Demonstrated | SRC-ghsa-spring-ssrf: [mcp-security advisory](https://github.com/spring-ai-community/mcp-security/security/advisories/GHSA-qjp4-4jvr-xqg3) | Destination confusion is shown; masquerading relay is not. |
| SAF-T1407-C012 | No qualifying production incident was identified in the bounded reviewed corpus. | Hypothesized | SRC-nvd-mcp-proxy-identity-corpus-2026: [NVD CVE API](https://services.nvd.nist.gov/rest/json/cves/2.0); SRC-cisa-kev-2026-09-01: [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | A bounded absence result is not proof that the behavior never occurred. |
| SAF-T1407-C013 | Identity analytics can compare approved and actual endpoint, TLS, resource, authorization, serverInfo, and tool-catalog values. | Research-Derived | SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html); SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Approval inventories and catalog fingerprints are not standardized. |
| SAF-T1407-C014 | The experimental detector correlates identity mismatch with a relay signal and suppresses approved gateways. | Research-Derived | SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html); SRC-trustshiftprobe: [TrustShiftProbe](https://arxiv.org/abs/2608.23763v1) | Only synthetic cases validate this exact rule. |
| SAF-T1407-C015 | Gateways, migrations, shared authorization, and cloned catalogs can resemble signals; control of trusted identity can evade them. | Research-Derived | SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html); SRC-trustshiftprobe: [TrustShiftProbe](https://arxiv.org/abs/2608.23763v1) | The conditions are limitations, not prevalence estimates. |
| SAF-T1407-C016 | TLS, exact resource matching, authorization allowlists, audience restriction, and refusal of foreign tokens are preventive controls. | Demonstrated | SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html); SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); SRC-rfc8707: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | A deliberately approved malicious endpoint can still use its own valid tokens. |
| SAF-T1407-C017 | Sender-constrained, audience-restricted, least-privilege tokens reduce misuse but do not validate server identity. | Demonstrated | SRC-rfc9700: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html); SRC-rfc8707: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Token policy does not protect all non-token MCP payloads. |
| SAF-T1407-C018 | MCP recommends visibility into exposed tools and user denial of tool calls. | Demonstrated | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | A confirmation interface can attribute a relayed tool to the wrong server. |
| SAF-T1407-C019 | TrustShiftProbe excludes network interception and studies a server changing its own content, a distinct adjacent boundary. | Demonstrated | SRC-trustshiftprobe: [TrustShiftProbe](https://arxiv.org/abs/2608.23763v1) | The reviewed version is an arXiv preprint and does not test proxy identity. |
| SAF-T1407-C020 | ATT&CK Masquerading and Adversary-in-the-Middle are analogous rather than exact MCP mappings. | Research-Derived | SRC-mitre-attack-t1036: [ATT&CK T1036](https://attack.mitre.org/techniques/T1036/); SRC-mitre-t1557: [ATT&CK T1557](https://attack.mitre.org/techniques/T1557/) | Neither defines MCP-specific resource or tool relay behavior. |
| SAF-T1407-C021 | Successful masquerade can expose tokens and MCP data or enable altered results under bounded privileges. | Demonstrated | SRC-ghsa-librechat-resource: [LibreChat advisory](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-gvpj-vm2f-2m23); SRC-ghsa-apify-authority: [Apify advisory](https://github.com/apify/apify-mcp-server/security/advisories/GHSA-6gr2-qh89-hxwm); SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Impact depends on data sent and authority granted. |
| SAF-T1407-C022 | Response should contain the session, preserve identity telemetry, revoke exposed tokens, verify associations, and reconnect after remediation. | Research-Derived | SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); SRC-rfc9700: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html); SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | Procedures remain platform-specific. |
| SAF-T1407-C023 | Contextual identity mismatches, not one universal artifact, are the useful indicators. | Research-Derived | SRC-rfc9728: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html); SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Incident-specific artifacts may still be durable. |
| SAF-T1407-C024 | The earliest selected directly reviewed demonstration was published 2026-05-28. | Demonstrated | SRC-ghsa-apify-authority: [Apify advisory](https://github.com/apify/apify-mcp-server/security/advisories/GHSA-6gr2-qh89-hxwm); SRC-nvd-mcp-proxy-identity-corpus-2026: [NVD CVE API](https://services.nvd.nist.gov/rest/json/cves/2.0) | Priority is limited to the selected reviewed corpus. |
| SAF-T1407-C025 | The technique chiefly affects remote HTTP, nested clients, gateways, and OAuth deployments. | Research-Derived | SRC-mcp-transports-2025-11-25: [MCP Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports); SRC-mcp-security-2025-11-25: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices); SRC-ghsa-apify-authority: [Apify advisory](https://github.com/apify/apify-mcp-server/security/advisories/GHSA-6gr2-qh89-hxwm) | A local proxy can create the same boundary; only direct stdio is excluded. |

### Current State

- **Affected Environments**: Remote HTTP MCP clients, nested clients, gateways, and OAuth-enabled deployments are the principal environments; direct local stdio without a proxy is outside the defining boundary. <!-- SAF-TRACE: claims=SAF-T1407-C025; sources=SRC-mcp-transports-2025-11-25,SRC-mcp-security-2025-11-25,SRC-ghsa-apify-authority -->
- **Known Exploitation**: Two selected advisories provide controlled direct demonstrations, while no qualifying production incident or CISA KEV listing was identified for the selected CVEs in the reviewed corpus. <!-- SAF-TRACE: claims=SAF-T1407-C008,SAF-T1407-C009,SAF-T1407-C012; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-nvd-mcp-proxy-identity-corpus-2026,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Current guidance requires TLS, exact resource validation, approved authorization associations, and resource-bound tokens; affected products publish fixed versions. <!-- SAF-TRACE: claims=SAF-T1407-C008,SAF-T1407-C009,SAF-T1407-C010,SAF-T1407-C011,SAF-T1407-C016; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-jfrog-cve-2025-6514,SRC-ghsa-spring-ssrf,SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-rfc8707 -->
- **Residual Risk**: A malicious endpoint deliberately entered into the approval inventory, or one controlling the trusted certificate or identity telemetry, can evade these comparisons. <!-- SAF-TRACE: claims=SAF-T1407-C015,SAF-T1407-C016; sources=SRC-rfc9728,SRC-trustshiftprobe,SRC-mcp-authorization-2025-11-25,SRC-rfc8707 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-54030 / GHSA-gvpj-vm2f-2m23, credited to Jian Cui, Minsun Shim, Zhou Li, Xiaojing Liao, and UIUC/UCI research teams | Published 2026-06-02; LibreChat through 0.8.5-rc1 | A fake endpoint receives a legitimate-resource token; fixed in 0.8.5 | Direct vulnerability and controlled demonstration <!-- SAF-TRACE: claims=SAF-T1407-C008; sources=SRC-ghsa-librechat-resource --> | No production exploitation is documented. |
| CVE-2026-50143 / GHSA-6gr2-qh89-hxwm, published by MQ37 and credited to EQSTLab and analyst 232-323 | Published 2026-05-28; Apify MCP Server before 0.10.11 | Wrong-authority connection exposes the configured bearer token; fixed in 0.10.11 | Direct vulnerability and controlled demonstration <!-- SAF-TRACE: claims=SAF-T1407-C009; sources=SRC-ghsa-apify-authority --> | No full transparent upstream relay is shown. |
| CVE-2025-6514 / JFSA-2025-001290844, by Or Peles and the JFrog Security Research Team | Published 2025-07-09; mcp-remote 0.0.5–0.1.15 | A malicious or hijacked server can trigger client command execution; fixed in 0.1.16 | Enabling vulnerability <!-- SAF-TRACE: claims=SAF-T1407-C010; sources=SRC-jfrog-cve-2025-6514 --> | The endpoint need not impersonate or relay a legitimate upstream. |
| CVE-2026-45609 / GHSA-qjp4-4jvr-xqg3, published by Kehrlann and credited to srikanthramu | Published 2026-05-11; mcp-security before 0.1.9 with dynamic client registration | Unvalidated OAuth URLs enable server-side requests; fixed in 0.1.9 | Enabling vulnerability <!-- SAF-TRACE: claims=SAF-T1407-C011; sources=SRC-ghsa-spring-ssrf --> | It demonstrates destination confusion, not server-proxy masquerade. |

The selected set contains two direct vulnerabilities and two high-impact enabling vulnerabilities. No production breach qualified, so the evidence status remains Demonstrated rather than Observed. <!-- SAF-TRACE: claims=SAF-T1407-C008,SAF-T1407-C009,SAF-T1407-C010,SAF-T1407-C011,SAF-T1407-C012; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-jfrog-cve-2025-6514,SRC-ghsa-spring-ssrf,SRC-nvd-mcp-proxy-identity-corpus-2026,SRC-cisa-kev-2026-09-01 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Bearer tokens, tool arguments, and results can be exposed when sent through the masquerading endpoint. <!-- SAF-TRACE: claims=SAF-T1407-C021; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-mcp-tools-2025-11-25 --> |
| Integrity | High | The endpoint's position can permit token reuse or altered returned data within available authority. <!-- SAF-TRACE: claims=SAF-T1407-C006,SAF-T1407-C021; sources=SRC-rfc9728,SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-mcp-tools-2025-11-25 --> |
| Availability | Medium | Disruption is possible through failed or manipulated exchanges, but availability impact is not inherent to the demonstrated identity flaws. <!-- SAF-TRACE: claims=SAF-T1407-C021; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-mcp-tools-2025-11-25 --> |
| Scope | Multi-System | A client, attacker endpoint, authorization service, and legitimate MCP resource can participate, while token audience and tool privilege constrain blast radius. <!-- SAF-TRACE: claims=SAF-T1407-C004,SAF-T1407-C017,SAF-T1407-C021; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc8707,SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-mcp-tools-2025-11-25 --> |

### Severity Conditions

- **Severity increases when** privileged bearer tokens, sensitive tools or data, and unattended tool invocation are present. <!-- SAF-TRACE: claims=SAF-T1407-C018,SAF-T1407-C021; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority -->
- **Severity decreases when** tokens are audience-bound, sender-constrained, least-privilege, and short-lived and users can deny sensitive calls. <!-- SAF-TRACE: claims=SAF-T1407-C017,SAF-T1407-C018; sources=SRC-rfc9700,SRC-rfc8707,SRC-mcp-tools-2025-11-25 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or client lifecycle log | Configuration, connection, initialization, tools/list, and tools/call | Session, approved and configured URI, resolved URI, TLS peer, serverInfo, tool-catalog fingerprint | Normalize values within one connection and retain approval/change records. <!-- SAF-TRACE: claims=SAF-T1407-C013,SAF-T1407-C014; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-trustshiftprobe --> |
| OAuth and protected-resource log | Metadata discovery, authorization-server selection, token issuance, token delivery | Resource identifier, metadata resource value, authorization-server set, token audience, receiving endpoint | Correlate without recording token contents; preserve identity and destination fields. <!-- SAF-TRACE: claims=SAF-T1407-C004,SAF-T1407-C013,SAF-T1407-C022; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728,SRC-rfc9700 --> |

### Indicators of Compromise (IoCs)

- No universal durable IoC is known; the behavior is identified through contextual differences among approved and actual identities. <!-- SAF-TRACE: claims=SAF-T1407-C023; sources=SRC-rfc9728,SRC-mcp-tools-2025-11-25 -->
- Incident-specific hostnames, certificate fingerprints, token identifiers, or approval changes can become local indicators after validation. <!-- SAF-TRACE: claims=SAF-T1407-C015,SAF-T1407-C023; sources=SRC-rfc9728,SRC-trustshiftprobe,SRC-mcp-tools-2025-11-25 -->

### Behavioral Indicators

- The resolved authority, TLS peer, protected-resource value, authorization-server association, initialization identity, or tool fingerprint differs from its approved baseline. <!-- SAF-TRACE: claims=SAF-T1407-C013; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25 -->
- The same session also claims another resource, reuses an authorization association, or presents a catalog matching an upstream identity, increasing confidence that the mismatch is relay-like. <!-- SAF-TRACE: claims=SAF-T1407-C006,SAF-T1407-C013,SAF-T1407-C014; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-trustshiftprobe -->
- An explicitly approved gateway or migration record separates expected mediation from suspicious masquerade. <!-- SAF-TRACE: claims=SAF-T1407-C014,SAF-T1407-C015; sources=SRC-rfc9728,SRC-trustshiftprobe -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify sessions with both an approved server-identity mismatch and a relay-like resource, authorization, or tool-catalog association. <!-- SAF-TRACE: claims=SAF-T1407-C013,SAF-T1407-C014; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-trustshiftprobe -->
- **Rule Status**: Experimental, validated against deterministic synthetic cases and the integrated repository. [Detection proof](../../research/techniques/SAF-T1407/validation/detection-test.txt)
- **Detection Logic**: Require a mismatch across approved identity fields and one relay signal, then exclude records explicitly marked as approved gateways. <!-- SAF-TRACE: claims=SAF-T1407-C014; sources=SRC-rfc9728,SRC-trustshiftprobe -->
- **Correlation Window**: One normalized MCP connection or authorization session. <!-- SAF-TRACE: claims=SAF-T1407-C001,SAF-T1407-C013; sources=SRC-mcp-architecture,SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25 -->
- **Known False Positives**: Approved gateways, endpoint migrations, shared authorization servers, and cloned tool catalogs. <!-- SAF-TRACE: claims=SAF-T1407-C015; sources=SRC-rfc9728,SRC-trustshiftprobe -->
- **Known Limitations**: The rule can miss an attacker controlling the approved endpoint, trusted certificate, baseline, or approval inventory, and its field normalization is implementation-specific. <!-- SAF-TRACE: claims=SAF-T1407-C013,SAF-T1407-C015; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-trustshiftprobe -->
- **Tuning Guidance**: Maintain time-bounded gateway and migration approvals and compare normalized URI origins, certificate identities, resource values, authorization sets, and catalog fingerprints. <!-- SAF-TRACE: claims=SAF-T1407-C013,SAF-T1407-C014,SAF-T1407-C015; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-trustshiftprobe -->

### Validation

- **Test Data**: [cases.json](../../tests/SAF-T1407/cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1407/test_detection_rule.py)
- **Expected Result**: Nine cases spanning positive, negative, boundary, malformed, and expected false-positive inputs pass with no assertion failures. [Detection proof](../../research/techniques/SAF-T1407/validation/detection-test.txt)
- **Last Validated**: 2026-09-01. [Quality review](../../research/techniques/SAF-T1407/quality-review.yml)
- **Feasibility Waiver**: None; synthetic validation does not measure production accuracy. <!-- SAF-TRACE: claims=SAF-T1407-C014,SAF-T1407-C015; sources=SRC-rfc9728,SRC-trustshiftprobe -->

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)**: Validate TLS identity and require exact equality between the configured protected-resource identifier and returned metadata. <!-- SAF-TRACE: claims=SAF-T1407-C005,SAF-T1407-C016; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25 -->
2. **[SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13/README.md)**: Allow only reviewed authorization servers for each MCP resource and refuse tokens whose audience is not the receiving server. <!-- SAF-TRACE: claims=SAF-T1407-C004,SAF-T1407-C016; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728,SRC-rfc8707 -->
3. **[SAF-M-31: Proof of Possession (PoP) Tokens](../../mitigations/SAF-M-31/README.md)**: Use audience-restricted, least-privilege, and sender-constrained tokens to reduce reuse and blast radius. <!-- SAF-TRACE: claims=SAF-T1407-C017; sources=SRC-rfc9700,SRC-rfc8707 -->
4. **Human Approval**: Show users the server identity and exposed tool before invocation and preserve the ability to deny sensitive calls. <!-- SAF-TRACE: claims=SAF-T1407-C018; sources=SRC-mcp-tools-2025-11-25 -->

### Detective Controls

1. **Identity-Tuple Correlation**: Compare approved, configured, resolved, TLS, resource, authorization, initialization, and tool-catalog identities within the same session. <!-- SAF-TRACE: claims=SAF-T1407-C013,SAF-T1407-C014; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-trustshiftprobe -->
2. **Approval-Aware Review**: Suppress explicitly approved gateways while alerting on new cross-origin or resource-association changes. <!-- SAF-TRACE: claims=SAF-T1407-C014,SAF-T1407-C015; sources=SRC-rfc9728,SRC-trustshiftprobe -->

### Response Procedures

#### Immediate Actions

- Stop the suspect MCP session and prevent reconnection to the unverified endpoint. <!-- SAF-TRACE: claims=SAF-T1407-C022; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc9728 -->
- Revoke exposed access and refresh tokens according to the relevant authorization-server procedure. <!-- SAF-TRACE: claims=SAF-T1407-C022; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc9728 -->

#### Investigation Steps

- Preserve configuration, approval, DNS resolution, TLS peer, resource metadata, authorization-server, initialization, and MCP tool telemetry for the affected session. <!-- SAF-TRACE: claims=SAF-T1407-C013,SAF-T1407-C022; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-rfc9700 -->
- Verify the intended endpoint and authorization association out of band, then determine which tokens, arguments, results, and downstream calls were exposed. <!-- SAF-TRACE: claims=SAF-T1407-C021,SAF-T1407-C022; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-mcp-tools-2025-11-25,SRC-mcp-authorization-2025-11-25,SRC-rfc9700,SRC-rfc9728 -->

#### Remediation

- Remove the malicious endpoint or unsafe URL/resource association, apply relevant product fixes, and enforce the protocol identity controls before reconnecting. <!-- SAF-TRACE: claims=SAF-T1407-C008,SAF-T1407-C009,SAF-T1407-C010,SAF-T1407-C011,SAF-T1407-C016,SAF-T1407-C022; sources=SRC-ghsa-librechat-resource,SRC-ghsa-apify-authority,SRC-jfrog-cve-2025-6514,SRC-ghsa-spring-ssrf,SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-rfc8707,SRC-rfc9700 -->
- Rebaseline the approved identity tuple and add a regression case for the specific mismatch after independent validation. <!-- SAF-TRACE: claims=SAF-T1407-C013,SAF-T1407-C014,SAF-T1407-C022; sources=SRC-rfc9728,SRC-mcp-authorization-2025-11-25,SRC-mcp-tools-2025-11-25,SRC-trustshiftprobe,SRC-rfc9700 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1004: Server Impersonation / Name-Collision](../SAF-T1004/README.md) | Prerequisite | Covers how a hostile endpoint enters configuration; this technique covers its deceptive operation as a server or resource association. <!-- SAF-TRACE: claims=SAF-T1407-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728 --> |
| [SAF-T1404: Response Tampering](../SAF-T1404/README.md) | Overlapping | Covers result-side corruption without requiring server-identity masquerade; this technique requires identity or upstream-association deception. <!-- SAF-TRACE: claims=SAF-T1407-C019; sources=SRC-trustshiftprobe --> |
| [SAF-T1304: Credential Relay Chain](../SAF-T1304/README.md) | Co-occurring | Covers unsafe credential forwarding by an identified intermediary; this technique requires server-identity masquerade. <!-- SAF-TRACE: claims=SAF-T1407-C004,SAF-T1407-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-rfc9728 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Analogous | Both use identity or location to appear legitimate, but T1036 does not define MCP resource or relay behavior. <!-- SAF-TRACE: claims=SAF-T1407-C020; sources=SRC-mitre-attack-t1036,SRC-mitre-t1557 --> |
| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Analogous | Both position an adversary to observe or change traffic, but T1557 does not define MCP protected-resource associations. <!-- SAF-TRACE: claims=SAF-T1407-C020; sources=SRC-mitre-attack-t1036,SRC-mitre-t1557 --> |

## References

1. **SRC-mcp-architecture**: [MCP Architecture — Model Context Protocol specification maintainers, 2025](https://modelcontextprotocol.io/specification/2025-11-25/architecture).
2. **SRC-mcp-transports-2025-11-25**: [MCP Transports — Model Context Protocol specification maintainers, 2025](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
3. **SRC-mcp-authorization-2025-11-25**: [MCP Authorization — Model Context Protocol specification maintainers, 2025](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
4. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices — Model Context Protocol security documentation maintainers, 2025](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).
5. **SRC-mcp-tools-2025-11-25**: [MCP Tools — Model Context Protocol specification maintainers, 2025](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
6. **SRC-rfc9728**: [RFC 9728 — Michael B. Jones, Phil Hunt, and Aaron Parecki, 2025](https://www.rfc-editor.org/rfc/rfc9728.html).
7. **SRC-rfc8707**: [RFC 8707 — Brian Campbell, John Bradley, and Hannes Tschofenig, 2020](https://www.rfc-editor.org/rfc/rfc8707.html).
8. **SRC-rfc9700**: [RFC 9700 — Torsten Lodderstedt, John Bradley, Andrey Labunets, and Daniel Fett, 2025](https://www.rfc-editor.org/rfc/rfc9700.html).
9. **SRC-mitre-attack-t1036**: [ATT&CK T1036 Masquerading — MITRE ATT&CK team and named contributors, 2026](https://attack.mitre.org/techniques/T1036/).
10. **SRC-mitre-t1557**: [ATT&CK T1557 Adversary-in-the-Middle — MITRE ATT&CK team and named contributors, 2026](https://attack.mitre.org/techniques/T1557/).
11. **SRC-trustshiftprobe**: [TrustShiftProbe — Mehrdad Rostamzadeh, Sidhant Narula, Mohammad Ghasemigol, and Daniel Takabi, 2026](https://arxiv.org/abs/2608.23763v1).
12. **SRC-cisa-kev-2026-09-01**: [Known Exploited Vulnerabilities Catalog — CISA KEV team, 2026](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
13. **SRC-nvd-mcp-proxy-identity-corpus-2026**: [NVD CVE API — NIST NVD team, reviewed 2026](https://services.nvd.nist.gov/rest/json/cves/2.0).
14. **SRC-ghsa-librechat-resource**: [Missing Resource Parameter Validation in MCP OAuth Flow — LibreChat maintainers; credited to Jian Cui, Minsun Shim, Zhou Li, Xiaojing Liao, UIUC, and UCI research teams, 2026](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-gvpj-vm2f-2m23).
15. **SRC-ghsa-apify-authority**: [Actor MCP path authority injection leaks Apify token — MQ37, EQSTLab, 232-323, and Apify security team, 2026](https://github.com/apify/apify-mcp-server/security/advisories/GHSA-6gr2-qh89-hxwm).
16. **SRC-jfrog-cve-2025-6514**: [Critical RCE Vulnerability in mcp-remote — Or Peles and the JFrog Security Research Team, 2025](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/).
17. **SRC-ghsa-spring-ssrf**: [Unvalidated URL Fetching in MCP Client — Kehrlann, srikanthramu, and the spring-ai-community security team, 2026](https://github.com/spring-ai-community/mcp-security/security/advisories/GHSA-qjp4-4jvr-xqg3).

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Initial independently researched clean-room technique and tested analytic | OpenAI Codex |
