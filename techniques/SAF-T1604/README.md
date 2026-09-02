# SAF-T1604: Server Version Enumeration

## Overview

- **Tactic**: Discovery (ATK-TA0007)
- **Technique ID**: SAF-T1604
- **Research Packet**: [research/techniques/SAF-T1604](../../research/techniques/SAF-T1604/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1604/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: Low
- **Severity Rationale**: The technique reveals bounded implementation metadata; material harm requires a separate weakness and follow-on action. <!-- SAF-TRACE: claims=SAF-T1604-C016; sources=SRC-rfc9110-server,SRC-attack-t1518 -->
- **First Observed**: No direct MCP production instance identified in the reviewed authoritative corpus as of 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1604-C014; sources=SRC-anthropic-espionage-2025-11,SRC-cisa-kev-2026-09-01,SRC-mitre-attack-t1046-v3.2 -->
- **Last Updated**: 2026-09-02

## Scope

SAF-T1604 covers a client collecting implementation or supported-protocol versions from a reached MCP server or its HTTP serving layer. The crossed boundary is the server-to-client release of version-bearing metadata. <!-- SAF-TRACE: claims=SAF-T1604-C004,SAF-T1604-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-rfc9110-server -->

### In Scope

- Reading the self-reported MCP server name and version returned by `server/discover`. <!-- SAF-TRACE: claims=SAF-T1604-C001,SAF-T1604-C002; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-2026-schema -->
- Collecting supported MCP protocol versions from discovery results or an unsupported-version error. <!-- SAF-TRACE: claims=SAF-T1604-C003; sources=SRC-mcp-2026-versioning -->
- Recording version-bearing HTTP `Server` response metadata associated with an MCP endpoint. <!-- SAF-TRACE: claims=SAF-T1604-C005; sources=SRC-rfc9110-server -->

### Out of Scope

- Finding an unknown endpoint or merely proving that a service is reachable. <!-- SAF-TRACE: claims=SAF-T1604-C018; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2 -->
- Listing tools, resources, prompts, or capabilities without collecting a version-bearing value. <!-- SAF-TRACE: claims=SAF-T1604-C018; sources=SRC-mcp-discovery-2026-07-28 -->
- Exploiting a weakness selected after enumeration or treating `serverInfo` as verified inventory. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C016; sources=SRC-mcp-discovery-2026-07-28,SRC-rfc9110-server -->
- Enumerating software installed locally without querying a server boundary. <!-- SAF-TRACE: claims=SAF-T1604-C017; sources=SRC-attack-t1518 -->

### Distinguishing Characteristics

Classify SAF-T1604 only when the observation contains an implementation or protocol-version value tied to a reached server. Endpoint discovery identifies what is reachable, and capability enumeration identifies what the server can do; neither is sufficient without the version-bearing result. <!-- SAF-TRACE: claims=SAF-T1604-C018; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2 -->

## Description

MCP revision 2026-07-28 requires servers to implement `server/discover`. Its result includes supported protocol versions and can include a server implementation name and version, so an adversarial or compromised client that can make the request can record those values as discovery output. <!-- SAF-TRACE: claims=SAF-T1604-C001,SAF-T1604-C004; sources=SRC-mcp-discovery-2026-07-28,SRC-nmap-vscan -->

The returned `serverInfo` is self-reported and unverified. A version can refine later vulnerability selection, but it does not establish that the implementation is genuine, affected, reachable through a vulnerable path, or compromised. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C016; sources=SRC-mcp-discovery-2026-07-28,SRC-rfc9110-server,SRC-attack-t1518 -->

HTTP transport can add a second signal through the `Server` response field. RFC 9110 advises against needlessly detailed product disclosure, while cautioning that attackers often try weaknesses regardless of apparent versions; suppressing detail is therefore defense in depth rather than a patching substitute. <!-- SAF-TRACE: claims=SAF-T1604-C005,SAF-T1604-C015; sources=SRC-rfc9110-server,SRC-apache-servertokens,SRC-nginx-server-tokens -->

## Attack Vectors

- **Primary Vector**: An accessible `server/discover` request whose response contains `supportedVersions` and `serverInfo.version`. <!-- SAF-TRACE: claims=SAF-T1604-C001,SAF-T1604-C002; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-2026-schema -->
- **Secondary Vector**: An unsupported-protocol-version request that elicits the server's supported version list or reveals its protocol era. <!-- SAF-TRACE: claims=SAF-T1604-C003; sources=SRC-mcp-2026-versioning -->
- **Secondary Vector**: An HTTP response whose `Server` field contains a product version. <!-- SAF-TRACE: claims=SAF-T1604-C005; sources=SRC-rfc9110-server -->
- **Affected Components**: MCP client or host, MCP server, discovery and error messages, and the HTTP serving layer. <!-- SAF-TRACE: claims=SAF-T1604-C001,SAF-T1604-C003,SAF-T1604-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-2026-versioning,SRC-rfc9110-server -->
- **Trust Boundary Crossed**: Server-authored version metadata crosses to a requesting client that may not be trustworthy. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C004; sources=SRC-mcp-discovery-2026-07-28,SRC-nmap-vscan -->

## Technical Details

### Prerequisites

- The actor can reach an MCP server or its HTTP response path and receive a response. <!-- SAF-TRACE: claims=SAF-T1604-C004,SAF-T1604-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-rfc9110-server -->
- If the deployment protects HTTP requests, the actor has a token accepted for that server; MCP authorization itself is optional. <!-- SAF-TRACE: claims=SAF-T1604-C007; sources=SRC-mcp-authorization-2026-07-28 -->
- The server returns a version-bearing discovery, error, or HTTP field; an omitted or generic value yields no exact build result. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C003,SAF-T1604-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-2026-versioning,SRC-rfc9110-server -->

### Attack Flow

1. **Reconnaissance or Setup**: The actor selects a known reachable MCP server; discovering that endpoint is a neighboring behavior. <!-- SAF-TRACE: claims=SAF-T1604-C018; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2 -->
2. **Delivery**: The client sends `server/discover`, sends a request with a protocol-version mismatch, or observes an HTTP response. <!-- SAF-TRACE: claims=SAF-T1604-C001,SAF-T1604-C003,SAF-T1604-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-2026-versioning,SRC-rfc9110-server -->
3. **Trigger or Execution**: The server returns supported versions, a self-reported implementation version, or a product/version field. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C003,SAF-T1604-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-2026-versioning,SRC-rfc9110-server -->
4. **Boundary Crossing**: Version-bearing server metadata becomes visible to the requesting client. <!-- SAF-TRACE: claims=SAF-T1604-C004; sources=SRC-mcp-discovery-2026-07-28,SRC-nmap-vscan -->
5. **Objective**: The actor associates the value with the server for later targeting decisions. <!-- SAF-TRACE: claims=SAF-T1604-C004,SAF-T1604-C016; sources=SRC-mcp-discovery-2026-07-28,SRC-rfc9110-server -->
6. **Follow-On Activity**: Any vulnerability research, exploitation, or compromise is a separate behavior and needs its own evidence. <!-- SAF-TRACE: claims=SAF-T1604-C016; sources=SRC-rfc9110-server,SRC-attack-t1518 -->

### Example Scenario

An untrusted client identity reaches five authorized test servers within five minutes and records each discovery response's self-reported version. The observation qualifies because every result is version-bearing and tied to a distinct server, but investigators must verify the values against deployment records before acting on them. <!-- SAF-TRACE: claims=SAF-T1604-C009,SAF-T1604-C019; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1604-C001 | Current MCP discovery returns versions, capabilities, and identity. | Research-Derived | SRC-mcp-discovery-2026-07-28: [MCP Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) | Normative behavior, not malicious observation. |
| SAF-T1604-C002 | MCP server implementation versions are self-reported and unverified. | Research-Derived | SRC-mcp-discovery-2026-07-28 and SRC-mcp-2026-schema: [MCP schema](https://modelcontextprotocol.io/specification/2026-07-28/schema) | Values may be absent, stale, generic, or deceptive. |
| SAF-T1604-C003 | Version mismatches disclose supported protocol versions and server era. | Research-Derived | SRC-mcp-2026-versioning: [MCP Versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) | Protocol version is not necessarily product build. |
| SAF-T1604-C004 | An able requester can use returned versions as enumeration output. | Research-Derived | SRC-mcp-discovery-2026-07-28 and SRC-nmap-vscan: [Nmap version detection](https://nmap.org/book/vscan.html) | Adversarial MCP use is inferred. |
| SAF-T1604-C005 | HTTP can disclose product versions, with a bounded security warning. | Research-Derived | SRC-rfc9110-server: [RFC 9110 Section 10.2.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.4) | Detail reduction is not exploit prevention. |
| SAF-T1604-C006 | Service-specific probes can demonstrate version enumeration. | Demonstrated | SRC-nmap-vscan: [Nmap Network Scanning, Chapter 7](https://nmap.org/book/vscan.html) | Non-MCP demonstration. |
| SAF-T1604-C007 | Protected MCP HTTP requests carry server-bound authorization. | Research-Derived | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Authorization is optional and no discovery-specific scope is defined. |
| SAF-T1604-C008 | Correlatable logs need actor, time, location, action, object, and result. | Research-Derived | SRC-owasp-logging-cheat-sheet: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | General guidance, not an MCP schema. |
| SAF-T1604-C009 | Distinct-server correlation is a testable enumeration analytic. | Research-Derived | SRC-mcp-discovery-2026-07-28 and SRC-owasp-logging-cheat-sheet | The threshold is locally selected. |
| SAF-T1604-C010 | Legitimate discovery and slow or distributed probes constrain detection. | Research-Derived | SRC-mcp-discovery-2026-07-28, SRC-nmap-vscan, and SRC-owasp-logging-cheat-sheet | No production accuracy study was found. |
| SAF-T1604-C011 | A 2025 campaign used MCP-connected automation for adjacent service discovery. | Observed | SRC-anthropic-espionage-2025-11: [Anthropic Threat Intelligence report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) | It does not report MCP server-version collection. |
| SAF-T1604-C012 | CVE-2021-41773 shows the importance of exact affected versions. | Observed historical analogy | SRC-apache-cve-2021-41773 and SRC-cisa-kev-2026-09-01 | No source links exploitation to version enumeration. |
| SAF-T1604-C013 | CVE-2021-42013 shows an incomplete fix spanning two exact versions. | Observed historical analogy | SRC-apache-cve-2021-42013 and SRC-cisa-kev-2026-09-01 | No source links exploitation to version enumeration. |
| SAF-T1604-C014 | No direct qualifying MCP case was found in the reviewed corpus. | Research-Derived | SRC-anthropic-espionage-2025-11, SRC-cisa-kev-2026-09-01, and SRC-mitre-attack-t1046-v3.2 | Bounded absence, not proof of nonoccurrence. |
| SAF-T1604-C015 | Apache and nginx can reduce HTTP version detail, with material limits. | Research-Derived | SRC-apache-servertokens and SRC-nginx-server-tokens | Does not affect MCP-native version fields. |
| SAF-T1604-C016 | Immediate impact is bounded disclosure, not compromise. | Research-Derived | SRC-rfc9110-server and SRC-attack-t1518 | Downstream impact requires another weakness. |
| SAF-T1604-C017 | ATT&CK T1046 and T1518 are analogous, not exact. | Research-Derived | SRC-mitre-attack-t1046-v3.2 and SRC-attack-t1518 | Mapping is an SAF judgment. |
| SAF-T1604-C018 | A version-bearing result distinguishes this technique from its neighbors. | Research-Derived | SRC-mcp-discovery-2026-07-28 and SRC-mitre-attack-t1046-v3.2 | Synthetic SAF neighbor IDs await integration. |
| SAF-T1604-C019 | Preserve correlation evidence and verify self-reported versions. | Research-Derived | SRC-owasp-logging-cheat-sheet and SRC-mcp-discovery-2026-07-28 | Organization-specific response remains local. |

### Current State

- **Affected Environments**: MCP servers that return `serverInfo`, supported protocol versions, or detailed HTTP `Server` fields to a client able to receive responses. <!-- SAF-TRACE: claims=SAF-T1604-C001,SAF-T1604-C002,SAF-T1604-C003,SAF-T1604-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-2026-schema,SRC-mcp-2026-versioning,SRC-rfc9110-server -->
- **Known Exploitation**: No direct MCP production instance or direct enumeration vulnerability was identified; one MCP-enabled production campaign is retained only as adjacent service discovery. <!-- SAF-TRACE: claims=SAF-T1604-C011,SAF-T1604-C014; sources=SRC-anthropic-espionage-2025-11,SRC-cisa-kev-2026-09-01,SRC-mitre-attack-t1046-v3.2 -->
- **Available Protections**: Protect restricted HTTP deployments with server-bound authorization, reduce unnecessary HTTP version detail where operationally acceptable, and log correlated discovery responses. <!-- SAF-TRACE: claims=SAF-T1604-C007,SAF-T1604-C008,SAF-T1604-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-owasp-logging-cheat-sheet,SRC-apache-servertokens,SRC-nginx-server-tokens -->
- **Residual Risk**: MCP-native version values are useful for interoperability and remain self-reported; suppression does not replace verification or vulnerability remediation. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C015,SAF-T1604-C016; sources=SRC-mcp-discovery-2026-07-28,SRC-apache-servertokens,SRC-rfc9110-server -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| No direct qualifying MCP case | Reviewed through 2026-09-02 | No direct remediation record exists because no direct case qualified. | Explicit evidence gap. | This bounded corpus finding does not prove nonoccurrence. <!-- SAF-TRACE: claims=SAF-T1604-C014; sources=SRC-anthropic-espionage-2025-11,SRC-cisa-kev-2026-09-01,SRC-mitre-attack-t1046-v3.2 --> |
| Anthropic GTG-1002 campaign | September-November 2025; live multi-target intrusions using Claude Code and MCP-connected tools | Anthropic disrupted accounts, notified affected entities, and expanded detections. | Adjacent production incident: service and endpoint discovery, not server-version enumeration. | The report does not say MCP server versions were collected. <!-- SAF-TRACE: claims=SAF-T1604-C011; sources=SRC-anthropic-espionage-2025-11 --> |
| CVE-2021-41773 | 2021; Apache HTTP Server 2.4.49 | File disclosure and conditional remote code execution; known exploitation; fixed in 2.4.50 but superseded by the next fix. | Historical analogy showing why a precise build identifier can matter. | No evidence that exposed version data selected a victim, and this is not MCP. <!-- SAF-TRACE: claims=SAF-T1604-C012,SAF-T1604-C016; sources=SRC-apache-cve-2021-41773,SRC-cisa-kev-2026-09-01,SRC-rfc9110-server --> |
| CVE-2021-42013 | 2021; Apache HTTP Server 2.4.49-2.4.50 | Path traversal and conditional remote code execution after an incomplete fix; fixed in 2.4.51; CISA records known ransomware-campaign use. | Historical analogy showing version-range and remediation-state sensitivity. | No evidence that version enumeration was part of exploitation, and this is not MCP. <!-- SAF-TRACE: claims=SAF-T1604-C013,SAF-T1604-C016; sources=SRC-apache-cve-2021-42013,SRC-cisa-kev-2026-09-01,SRC-rfc9110-server --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Low | The immediate disclosure is implementation metadata; higher consequence requires a separate applicable weakness. <!-- SAF-TRACE: claims=SAF-T1604-C016; sources=SRC-rfc9110-server,SRC-attack-t1518 --> |
| Integrity | None | Enumeration alone does not alter server state or establish exploitation. <!-- SAF-TRACE: claims=SAF-T1604-C016; sources=SRC-rfc9110-server,SRC-attack-t1518 --> |
| Availability | None | The bounded behavior is metadata collection; disruption is outside the contract. <!-- SAF-TRACE: claims=SAF-T1604-C016; sources=SRC-rfc9110-server,SRC-attack-t1518 --> |
| Scope | Local | Each observation applies to the reached server, and a client must repeat collection to build a multi-server inventory. <!-- SAF-TRACE: claims=SAF-T1604-C004,SAF-T1604-C009; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet --> |

### Severity Conditions

- **Severity increases when**: A precise, trustworthy version maps to an unremediated weakness on a sensitive server and the actor can perform separate follow-on exploitation. <!-- SAF-TRACE: claims=SAF-T1604-C012,SAF-T1604-C013,SAF-T1604-C016; sources=SRC-apache-cve-2021-41773,SRC-apache-cve-2021-42013,SRC-rfc9110-server -->
- **Severity decreases when**: Values are generic or independently verified as current, endpoints are access-controlled, and vulnerability remediation is current. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C007,SAF-T1604-C015; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-apache-servertokens -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP client, gateway, or server audit log | `server/discover`, unsupported-version error, and the paired response | timestamp, actor_id, server_id, method, result status, serverInfo.version, supportedVersions | Preserve a common interaction identifier and normalize field names without trusting the value. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C008,SAF-T1604-C009; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet --> |
| Identity or workload inventory | Classification of approved scanners and automation | actor_id, role, authorization context, approval state | Retain events from known users but classify approved inventory activity for tuning. <!-- SAF-TRACE: claims=SAF-T1604-C008,SAF-T1604-C010; sources=SRC-owasp-logging-cheat-sheet,SRC-nmap-vscan --> |

### Indicators of Compromise (IoCs)

- No reliable durable IoC is inherent to this technique; the returned value is server-authored metadata and the collection may use normal protocol behavior. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C004; sources=SRC-mcp-discovery-2026-07-28,SRC-nmap-vscan -->

### Behavioral Indicators

- One actor receives version-bearing discovery results from at least five distinct server identities within five minutes. <!-- SAF-TRACE: claims=SAF-T1604-C009; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet -->
- A burst of unsupported-version errors elicits supported-version lists across multiple servers. <!-- SAF-TRACE: claims=SAF-T1604-C003,SAF-T1604-C009; sources=SRC-mcp-2026-versioning,SRC-owasp-logging-cheat-sheet -->
- Approved inventory activity is a known lookalike and should be classified, not silently discarded. <!-- SAF-TRACE: claims=SAF-T1604-C010; sources=SRC-owasp-logging-cheat-sheet,SRC-nmap-vscan -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect concentrated retrieval of server version metadata across distinct MCP servers by one actor. <!-- SAF-TRACE: claims=SAF-T1604-C009; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet -->
- **Rule Status**: Experimental because no production accuracy study was found. <!-- SAF-TRACE: claims=SAF-T1604-C010,SAF-T1604-C014; sources=SRC-nmap-vscan,SRC-anthropic-espionage-2025-11,SRC-cisa-kev-2026-09-01 -->
- **Detection Logic**: Select successful discovery responses with a nonempty version, exclude identities explicitly classified as approved inventory, and alert at five distinct servers per actor. <!-- SAF-TRACE: claims=SAF-T1604-C009,SAF-T1604-C010; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet -->
- **Correlation Window**: Five minutes, with the threshold and window treated as tunable local choices. <!-- SAF-TRACE: claims=SAF-T1604-C009; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet -->
- **Known False Positives**: Legitimate multi-server clients, compatibility testing, and approved inventory scanners. <!-- SAF-TRACE: claims=SAF-T1604-C010; sources=SRC-mcp-discovery-2026-07-28,SRC-nmap-vscan,SRC-owasp-logging-cheat-sheet -->
- **Known Limitations**: Slow probing, identity rotation, missing actor or server identifiers, and omitted or deceptive version values reduce visibility. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C010; sources=SRC-mcp-discovery-2026-07-28,SRC-nmap-vscan -->
- **Tuning Guidance**: Baseline legitimate discovery rates, classify approved scanners, and tune distinct-server count and window together. <!-- SAF-TRACE: claims=SAF-T1604-C009,SAF-T1604-C010; sources=SRC-owasp-logging-cheat-sheet,SRC-nmap-vscan -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Seven named cases cover positive, negative, threshold, window, expected-false-positive, missing-field, and normalization behavior. <!-- SAF-TRACE: claims=SAF-T1604-C009,SAF-T1604-C010; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet,SRC-nmap-vscan -->
- **Last Validated**: 2026-09-02 ([quality review](../../research/techniques/SAF-T1604/quality-review.yml); [recorded detector output](../../research/techniques/SAF-T1604/validation/detection-test.txt); [strict validation](../../research/techniques/SAF-T1604/validation/strict-validator.txt))
- **Feasibility Waiver**: None; synthetic event-level validation is included, while production efficacy remains unmeasured. <!-- SAF-TRACE: claims=SAF-T1604-C009,SAF-T1604-C010; sources=SRC-mcp-discovery-2026-07-28,SRC-owasp-logging-cheat-sheet -->

## Mitigation Strategies

### Preventive Controls

1. **Minimize unnecessary version detail**: Use product-supported settings to reduce HTTP banner detail where interoperability and operations permit, while preserving the limitation that suppression does not replace remediation. No exact SAF mitigation currently represents this control ([integration notes](../../research/techniques/SAF-T1604/integration/integration-notes.yml)). <!-- SAF-TRACE: claims=SAF-T1604-C005,SAF-T1604-C015; sources=SRC-rfc9110-server,SRC-apache-servertokens,SRC-nginx-server-tokens -->
2. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Apply server-bound authorization to restricted HTTP deployments so only accepted identities can make protected requests, with **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)** where bearer scopes control access. <!-- SAF-TRACE: claims=SAF-T1604-C007; sources=SRC-mcp-authorization-2026-07-28 -->
3. **Patch and verify independently**: Treat self-reported versions as hints, reconcile them with authoritative deployment records, and remediate applicable weaknesses rather than relying on obscurity. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C012,SAF-T1604-C013,SAF-T1604-C015; sources=SRC-mcp-discovery-2026-07-28,SRC-apache-cve-2021-41773,SRC-apache-cve-2021-42013,SRC-apache-servertokens -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Log accepted identity, request, server, result, and classification fields before correlating distinct-server activity. <!-- SAF-TRACE: claims=SAF-T1604-C008,SAF-T1604-C009; sources=SRC-owasp-logging-cheat-sheet,SRC-mcp-discovery-2026-07-28 -->
2. **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20/README.md)**: Investigate unusual multi-server bursts without discarding events from trusted automation, and tune known inventory activity explicitly. <!-- SAF-TRACE: claims=SAF-T1604-C009,SAF-T1604-C010; sources=SRC-owasp-logging-cheat-sheet,SRC-nmap-vscan -->

### Response Procedures

#### Immediate Actions

- Preserve the actor's correlated discovery and authorization events and, when activity is unauthorized, suspend the implicated session or identity under local policy. <!-- SAF-TRACE: claims=SAF-T1604-C008,SAF-T1604-C019; sources=SRC-owasp-logging-cheat-sheet,SRC-mcp-discovery-2026-07-28 -->
- Do not declare a server vulnerable from its self-reported version alone. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C016; sources=SRC-mcp-discovery-2026-07-28,SRC-rfc9110-server -->

#### Investigation Steps

- Correlate request, response, actor, server, authorization, and workload-classification fields using the interaction identifier. <!-- SAF-TRACE: claims=SAF-T1604-C008,SAF-T1604-C019; sources=SRC-owasp-logging-cheat-sheet,SRC-mcp-discovery-2026-07-28 -->
- Verify observed versions against authoritative asset and deployment records, then determine whether separate exploit or follow-on behavior occurred. <!-- SAF-TRACE: claims=SAF-T1604-C002,SAF-T1604-C016,SAF-T1604-C019; sources=SRC-mcp-discovery-2026-07-28,SRC-rfc9110-server,SRC-owasp-logging-cheat-sheet -->

#### Remediation

- Correct access policy, unnecessary HTTP banner detail, or logging gaps identified by the investigation, while preserving required interoperability. <!-- SAF-TRACE: claims=SAF-T1604-C007,SAF-T1604-C008,SAF-T1604-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-owasp-logging-cheat-sheet,SRC-apache-servertokens,SRC-nginx-server-tokens -->
- Patch verified vulnerable software and retain regression coverage for discovery-event collection and correlation. <!-- SAF-TRACE: claims=SAF-T1604-C009,SAF-T1604-C012,SAF-T1604-C013; sources=SRC-mcp-discovery-2026-07-28,SRC-apache-cve-2021-41773,SRC-apache-cve-2021-42013 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1601: MCP Server Enumeration](../SAF-T1601/README.md) | Prerequisite or co-occurring | Finds configured or reachable servers; SAF-T1604 requires a version-bearing result from a server already reached. <!-- SAF-TRACE: claims=SAF-T1604-C018; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2 --> |
| [SAF-T1605: Capability Mapping](../SAF-T1605/README.md) | Overlapping | Inventories exposed functions or capabilities; SAF-T1604 collects implementation or supported protocol versions. <!-- SAF-TRACE: claims=SAF-T1604-C018; sources=SRC-mcp-discovery-2026-07-28 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Analogous | Both collect remote-service information, but T1046 emphasizes discovering services and SAF-T1604 requires version metadata from a reached server. <!-- SAF-TRACE: claims=SAF-T1604-C017; sources=SRC-mitre-attack-t1046-v3.2 --> |
| [T1518](https://attack.mitre.org/techniques/T1518/) | Software Discovery | Analogous | Both can collect software versions, but T1518 describes installed software on a system or cloud environment rather than an MCP server's self-report. <!-- SAF-TRACE: claims=SAF-T1604-C017; sources=SRC-attack-t1518 --> |

## References

1. **SRC-mcp-discovery-2026-07-28**: [MCP Discovery, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) — Model Context Protocol project contributors; discovery request, response, and trust limitation.
2. **SRC-mcp-2026-schema**: [MCP Schema Reference, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/schema) — Model Context Protocol project contributors; `Implementation.version` and `DiscoverResult`.
3. **SRC-mcp-2026-versioning**: [MCP Versioning and Compatibility, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) — Model Context Protocol project contributors; supported-version errors and server-era behavior.
4. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — Model Context Protocol project contributors; optional authorization and protected HTTP request requirements.
5. **SRC-rfc9110-server**: [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.4) — Roy T. Fielding, Mark Nottingham, and Julian Reschke; Server field and product-information disclosure.
6. **SRC-nmap-vscan**: [Nmap Network Scanning, Chapter 7](https://nmap.org/book/vscan.html) — Gordon “Fyodor” Lyon; service and application version detection.
7. **SRC-owasp-logging-cheat-sheet**: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — OWASP Cheat Sheet Series Team; event attributes and interaction identifiers.
8. **SRC-anthropic-espionage-2025-11**: [Disrupting the first reported AI-orchestrated cyber espionage campaign](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) — Anthropic Threat Intelligence Team, November 2025; adjacent MCP-enabled service discovery.
9. **SRC-apache-cve-2021-41773**: [Apache HTTP Server vulnerability entry for CVE-2021-41773](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773) — Apache HTTP Server Security Team; credit to Ash Daulton and the cPanel Security Team.
10. **SRC-apache-cve-2021-42013**: [Apache HTTP Server vulnerability entry for CVE-2021-42013](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013) — Apache HTTP Server Security Team; credit to Juan Escobar, Fernando Muñoz, Shungo Kumasaka, and Nattapon Jongcharoen.
11. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog, version 2026.09.01](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — CISA Vulnerability Management Team; exploitation and ransomware-use status for the two Apache CVEs.
12. **SRC-apache-servertokens**: [Apache HTTP Server ServerTokens directive](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens) — Apache HTTP Server Documentation Team; HTTP banner-detail controls and limitations.
13. **SRC-nginx-server-tokens**: [nginx server_tokens directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens) — nginx Documentation Team; version emission controls.
14. **SRC-mitre-attack-t1046-v3.2**: [MITRE ATT&CK T1046: Network Service Discovery](https://attack.mitre.org/techniques/T1046/) — MITRE ATT&CK Team; contributors Aaron Sullivan (ZerkerEOD) and Praetorian.
15. **SRC-attack-t1518**: [MITRE ATT&CK T1518: Software Discovery](https://attack.mitre.org/techniques/T1518/) — MITRE ATT&CK Team; software-version discovery definition.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial clean-room research-derived draft | OpenAI Codex clean-room agent `/root/cleanroom_saf_t1604` |
