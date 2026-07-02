# SAF-T1004: Server Impersonation / Name-Collision

## Overview
**Tactic**: Initial Access (ATK-TA0001)  
**Technique ID**: SAF-T1004  
**Severity**: High  
**First Observed**: DNS-spoofing threat model formalized in RFC 3833 (2004, citing earlier academic analysis); widely publicized via Kaminsky DNS cache-poisoning disclosure in 2008 (CVE-2008-1447)  
**Last Updated**: 2026-07-01

## Description
Server Impersonation / Name-Collision is an adversary-in-the-middle technique where attackers register or advertise a malicious server using the same name or identifier as a trusted one. By exploiting weaknesses in naming and discovery systems (for example DNS, mDNS, or local MCP server registries), clients can be redirected to attacker-controlled endpoints.

This technique succeeds in MCP environments because trust decisions are often made before strong identity checks. If clients accept duplicated names, unsigned metadata, or weak certificates, an attacker can intercept authentication flows, alter tool responses, and capture sensitive data.

### Registry Context (ODR / Local Registry)
In this technique, **ODR** refers to host-local discovery or registry layers used by MCP host applications to store server metadata (name, endpoint, and trust attributes). On Windows, this concept aligns with the On-Device Agent Registry tooling (`odr.exe`) for MCP server registration and discovery. Implementations vary by platform and product; if your environment does not use ODR by name, apply the same controls to its equivalent local registry/discovery mechanism.

## Attack Vectors
- **Primary Vector**: Malicious server registration with a trusted server's name or identifier
- **Secondary Vectors**:
  - DNS cache poisoning or DNS hijacking
  - Rogue DHCP infrastructure distributing attacker-controlled DNS settings
  - Duplicate local registry entries for an existing trusted server
  - TLS certificate misuse, weak validation, or certificate pinning gaps
  - ARP spoofing on local networks
  - Service redeployment windows where identity checks are temporarily bypassed

## Technical Details

### Prerequisites
- Attacker network position (local segment, rogue upstream DNS, or other interception path)
- Weak discovery protections (no DNSSEC validation, permissive local registry behavior, or missing duplicate-name checks)
- Trust model that treats name as identity without robust certificate validation
- Ability to register or advertise a malicious endpoint with legitimate-appearing metadata

### Attack Flow

```mermaid
graph TD
    A[Attacker deploys endpoint mimicking a trusted MCP server name] --> B{Discovery-layer hijack}
    B -->|DNS cache poisoning / hijack| C[Trusted name resolves to attacker IP]
    B -->|Rogue DHCP points clients at attacker DNS| C
    B -->|ARP spoofing on local segment| C
    B -->|Duplicate local registry / ODR entry| C
    C --> D[Client connects to attacker endpoint]
    D --> E[Attacker presents weak or mismatched identity material]
    E --> F[Impersonation: intercept auth, alter tool responses]
    F --> G[Credential and token capture / data collection]
    F --> H[Registry-poisoning persistence, then pivot with captured credentials]

    style A fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style F fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style G fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style C fill:#fee090,stroke:#000,stroke-width:2px,color:#000
    style B fill:#fc8d59,stroke:#000,stroke-width:2px,color:#000
```

1. **Preparation**: Attacker deploys a malicious endpoint that mimics a trusted MCP server name.
2. **Discovery Hijack**: DNS/mDNS responses or local registry entries are poisoned or duplicated.
3. **Connection**: Client resolves the trusted name to the attacker endpoint and initiates session setup.
4. **Impersonation**: Attacker presents weak or mismatched identity material and intercepts traffic.
5. **Exploitation**: Credentials, tokens, and sensitive data are harvested; malicious responses may be injected.
6. **Post-Exploitation**: Attacker persists through registry poisoning and pivots to additional systems by reusing the credentials and tokens captured in stage 5 against other services the victim can reach.

### Example Scenario
The technique turns on a **name collision**: the local ODR / MCP registry ends up
holding two entries for the same `service_name`. The legitimate record was registered
first; the attacker adds a duplicate pointing at their own endpoint.

```json
{
  "registry": "local ODR / MCP registry (odr mcp list)",
  "entries": [
    {
      "service_name": "analytics-hub.local",
      "endpoint": "10.0.0.10:8443",
      "certificate_fingerprint": "sha256:9c1f... (issued by trusted CA)",
      "source": "odr:mcp",
      "note": "legitimate, pre-existing entry"
    },
    {
      "service_name": "analytics-hub.local",
      "endpoint": "192.168.1.50",
      "certificate_fingerprint": "untrusted-self-signed",
      "source": "local-registry",
      "note": "attacker-added duplicate (name collision)"
    }
  ]
}
```

**Mapping to the Attack Flow and detection:**
- **Stage 2 (Discovery Hijack)**: the attacker writes the second entry, so two records now share `service_name` `analytics-hub.local`. This is what `selection_odr` catches (`duplicate service registration` / `name collision`).
- **Stage 3 (Connection)**: lacking a duplicate-name or identity check, the client resolves the name and binds to the attacker's `192.168.1.50` endpoint instead of `10.0.0.10:8443`.
- **Stage 4 (Impersonation)**: the attacker serves the `untrusted-self-signed` certificate; a client that does not pin or validate accepts it. This is what `selection_tls_untrusted_ca` catches (`self-signed certificate` / `untrusted certificate authority`).

### Advanced Attack Techniques (Research Published)
According to public reporting and ATT&CK campaign tracking, attackers use multiple identity-hijack layers:

1. **DNS Cache Poisoning**: False DNS responses direct clients to malicious infrastructure.
2. **Registrar Hijacking**: Domain and DNS control are taken over to reroute traffic at scale (for example [Sea Turtle / G1041](https://attack.mitre.org/groups/G1041/)).
3. **Hybrid Discovery Poisoning**: DNS hijack combined with local network attacks (ARP/DHCP) to increase reliability and evade single-layer controls.

## Impact Assessment
- **Confidentiality**: High - credentials and sensitive data can be intercepted.
- **Integrity**: High - malicious responses can alter workflow outputs and decisions.
- **Availability**: Medium - service resolution failures and trust breaks can interrupt operations.
- **Scope**: Network-wide - affects any client relying on poisoned discovery/identity signals.

### Current Status (2026)
Organizations are increasingly prioritizing stronger discovery and identity controls, but coverage remains uneven:
- DNSSEC adoption continues to expand, but not all enterprise resolvers and zones validate consistently.
- The MCP roadmap's "Server Cards" initiative is developing a `.well-known` URL standard for publishing structured server metadata so browsers, crawlers, and registries can discover a server's advertised capabilities without first connecting to it. (Advertised, not verified: Server Cards describe capabilities; they do not replace server-identity authentication.)
- Teams with mixed legacy protocols and inconsistent registry governance remain exposed to name-collision attacks.

## Detection Methods

### Indicators of Compromise (IoCs)
- Sudden DNS resolution drift for trusted MCP server names
- Duplicate or conflicting server entries in local MCP registries
- ARP anomalies and MAC/IP mismatch events around MCP traffic
- TLS certificate mismatch or unexpected self-signed certificate acceptance
- Authentication failures and suspicious reconnect loops after resolution changes

### Detection Rules
**Important**: The following Sigma-style rule is an example. Organizations should tailor fields and event IDs to their telemetry pipeline and operating system logging configuration.

```yaml
title: Detection of Server Impersonation / Name-Collision (SAF-T1004)
id: 9f3c2a8e-7d4b-4c2f-9a1e-8e2b7f9c1d23
status: experimental
description: Detects indicators of server impersonation or name-collision attacks across DNS, ARP, TLS, and local registry events. Message-text selections are illustrative; operators should tailor them to their own telemetry pipeline. Elevate from medium to high only when correlated with expected MCP server identity, registry changes, or DHCP/ARP anomalies.
author: Ryan Jennings
date: 2025-11-22
modified: 2026-07-01
references:
  - https://github.com/secure-agentic-framework/saf-mcp/tree/main/techniques/SAF-T1004
  - https://attack.mitre.org/techniques/T1557/
  - https://attack.mitre.org/techniques/T1557/002/
  - https://attack.mitre.org/techniques/T1557/003/
logsource:
  product: windows
  service: system
detection:
  selection_dns:
    EventID: 1014
    Provider_Name: "Microsoft-Windows-DNS-Client"
    Message|contains:
      - "timed out after none of the configured DNS servers responded"
      - "DNSSEC validation failed"
  selection_odr:
    Provider_Name: "ODR"
    Message|contains:
      - "duplicate service registration"
      - "name collision"
  selection_arp:
    Provider_Name: "Microsoft-Windows-TCPIP"
    Message|contains:
      - "duplicate ARP entry"
      - "MAC address mismatch"
  selection_tls_untrusted_ca:
    EventID: 36882
    Provider_Name: "Schannel"
    Message|contains:
      - "issued by an untrusted"
      - "untrusted certificate authority"
      - "self-signed certificate"
  selection_tls_hostname_mismatch:
    EventID: 36884
    Provider_Name: "Schannel"
    Message|contains:
      - "host name"
      - "hostname"
      - "name mismatch"
  condition: selection_dns or selection_odr or selection_arp or selection_tls_untrusted_ca or selection_tls_hostname_mismatch
falsepositives:
  - Legitimate service redeployments that temporarily create duplicate registry entries
  - Controlled test environments using self-signed certificates
  - Planned DNS cutovers during maintenance windows
  - Routine DNS-client timeouts (1014) unrelated to name collision
  - Schannel events (36882/36884) from upstream misconfigurations rather than spoofing
level: medium
tags:
  - attack.credential_access
  - attack.collection
  - attack.t1557
  - attack.t1557.002
  - attack.t1557.003
  - safe.t1004
```

### Behavioral Indicators
- New duplicate service names for trusted MCP endpoints
- Increased DNS cache refreshes and resolver warning events for previously stable names
- Clients connecting to unexpected IP ranges for known servers
- TLS handshake failures or fallback behavior after certificate mismatches
- Correlated ARP anomalies near authentication or token exchange failures

## Mitigation Strategies

### Preventive Controls
1. **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)**: Restrict MCP connections to explicit trusted domains/endpoints.
2. **[SAF-M-2: Cryptographic Integrity for Tool Descriptions](../../mitigations/SAF-M-2/README.md)**: Sign and verify tool metadata to reduce tampering and spoofing risk.
3. **[SAF-M-6: Tool Registry Verification](../../mitigations/SAF-M-6/README.md)**: Enforce trusted registry source controls and signature validation.
4. **[SAF-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAF-M-45/README.md)**: Validate server identity and manifest integrity before accepting tools.
5. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Limit blast radius if a spoofed endpoint is accepted.

### Detective Controls
1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Log registry changes, server identity decisions, and endpoint shifts.
2. **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20/README.md)**: Detect unexpected discovery/connection behavior and resolution drift.
3. **[SAF-M-11: Behavioral Monitoring](../../mitigations/SAF-M-11/README.md)**: Correlate unusual tool behavior with identity and routing anomalies.

### Response Procedures
1. **Immediate Actions**:
   - Block malicious or untrusted endpoint IPs/domains.
   - Remove rogue local registry entries and disable affected server registrations.
   - Flush poisoned DNS and ARP caches on impacted hosts.
2. **Investigation Steps**:
   - Reconstruct timeline of DNS/registry/certificate changes.
   - Identify initial poisoning vector (DNS, ARP, DHCP, registry tampering).
   - Scope impacted clients and exposed credentials/tokens.
3. **Remediation**:
   - Rotate exposed credentials, tokens, and certificates.
   - Re-establish trusted server identity material and pinning policy.
   - Add preventive and detective controls for duplicate-name and identity drift.

## Related Techniques
- [SAF-T1301](../SAF-T1301/README.md): Cross-Server Tool Shadowing - exploits tool-name collisions in multi-server environments.
- [SAF-T1407](../SAF-T1407/README.md): Server Proxy Masquerade - uses intermediary infrastructure to impersonate trusted paths.
- [SAF-T1005](../SAF-T1005/README.md): Exposed Endpoint Exploit - broad endpoint exposure can enable impersonation opportunities.
- [SAF-T1704](../SAF-T1704/README.md): Compromised-Server Pivot - impersonation can provide a foothold for lateral movement.

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [Model Context Protocol Roadmap: Server Cards initiative](https://modelcontextprotocol.io/development/roadmap)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Sea Turtle - ATT&CK Group G1041](https://attack.mitre.org/groups/G1041/)
- [Windows ODR Tool (odr.exe) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/ai/mcp/odr-tool)
- [RFC 3833 - Threat Analysis of the Domain Name System (DNS)](https://www.rfc-editor.org/rfc/rfc3833.html)
- [CVE-2008-1447 - DNS Cache Poisoning (Kaminsky)](https://nvd.nist.gov/vuln/detail/CVE-2008-1447)
- [Internet Society - DNSSEC Deployment Maps (historical snapshot, 2021-06-14)](https://www.internetsociety.org/deploy360/dnssec/maps/)
- [APNIC DNSSEC Validation World Map](https://stats.labs.apnic.net/dnssec)
- [JRC - Internet Standards: DNSSEC standards, an analysis of uptake in the EU (JRC143100, 2025)](https://publications.jrc.ec.europa.eu/repository/handle/JRC143100)

## MITRE ATT&CK Mapping
- [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/)
- [T1557.003 - Adversary-in-the-Middle: DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003/)

> **SAF tactic vs. ATT&CK tactic**: In ATT&CK, T1557 (Adversary-in-the-Middle) is tagged under **Credential Access (TA0006)** and **Collection (TA0009)**, which is why the detection rule carries those tactic tags. Within the SAF-MCP framework, however, this technique is filed under **Initial Access (ATK-TA0001)** - name-collision / discovery hijack is how the attacker first interposes on an MCP client - which is the tactic named in the Overview and in the framework's technique index. The Credential Access / Collection framing above describes the ATT&CK behaviors the AiTM position enables.

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-22 | Initial documentation with ODR explanation | Ryan Jennings |
| 1.1 | 2026-02-24 | Replaced placeholder mitigations, corrected related-technique mapping, updated detection rule example, and added clearer ODR scope language | Bishnu Bista |
| 1.2 | 2026-02-24 | Corrected ATT&CK reference for Sea Turtle, aligned DNS EventID 1014 example wording, reduced over-specific ARP event assumptions, and added ODR/APNIC references for source clarity | Bishnu Bista |
| 1.3 | 2026-04-23 | Overview tactic line corrected to Credential Access + Collection (ATT&CK-faithful to T1557/T1557.002/T1557.003; prior "Initial Access" claim was unsupported); MITRE mapping: replaced T1565.002 (Transmitted Data Manipulation, not DNS-specific) and T1071.004 (DNS-as-C2, not DNS-is-attacked) with T1557.003 (DHCP Spoofing) to match the rogue-DHCP attack vector; Sigma rule split Schannel EventID 36882 (untrusted CA) vs 36884 (hostname mismatch) with Microsoft-faithful Message|contains text, lowered level from high to medium, tactic tags reconciled to attack.credential_access + attack.collection; synced embedded Sigma block in README to canonical detection-rule.yml; added 36882/36884 test-log coverage (12/12 pass); named "MCP Server Cards" roadmap initiative explicitly with accurate "discover advertised capabilities" wording; First Observed anchored to RFC 3833 (2004) + Kaminsky 2008 (CVE-2008-1447); used verbatim JRC report title; annotated Internet Society DNSSEC maps as a 2021 historical snapshot | Bishnu Bista |
| 1.4 | 2026-07-01 | Reconciled the Overview SAF tactic back to Initial Access (ATK-TA0001) to match the framework technique index, and moved the Credential Access / Collection framing into the MITRE ATT&CK Mapping section where T1557's tactics belong; expanded the Example Scenario to show the actual name collision (legitimate vs. attacker registry record) with mapping to Attack-Flow stages 2-4 and to the detection selections; added a discovery-hijack flow diagram; gave stage 6 a stated pivot mechanism; verified the odr.exe Microsoft Learn reference; fixed the non-resolving detection-rule references URL (SAF-MCP -> secure-agentic-framework); softened "dangerous"; normalized author-name casing | Frederick Kautz |
