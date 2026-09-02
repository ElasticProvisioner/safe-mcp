# SAF-T1004: Server Impersonation / Name-Collision

## Overview

- **Tactic**: Initial Access (ATK-TA0001)
- **Technique ID**: SAF-T1004
- **Research Packet**: [research/techniques/SAF-T1004](../../research/techniques/SAF-T1004/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1004/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: Medium
- **Severity Rationale**: The demonstrated Registry integrity effect was limited, while a substituted endpoint can conditionally expose requests, credentials, or resource data; that downstream exposure was not demonstrated by the Registry proof. <!-- SAF-TRACE: claims=SAF-T1004-C009; sources=SRC-ghsa-oci-rate-limit,SRC-ms-azure-mcp-security-2026 -->
- **First Observed**: [No qualifying production breach was established in the reviewed corpus as of 2026-09-01](../../research/techniques/SAF-T1004/source-coverage.yml)
- **Last Updated**: 2026-09-01

## Scope

The frozen [technique contract](../../research/techniques/SAF-T1004/technique-contract.yml) covers wrong-server selection caused by an ambiguous, colliding, lookalike, self-asserted, or insufficiently authenticated server identity.

### In Scope

- [Colliding or lookalike server titles and aliases used as selection keys](../../research/techniques/SAF-T1004/technique-contract.yml).
- [Self-reported server names treated as authenticated identity](../../research/techniques/SAF-T1004/technique-contract.yml).
- [Publisher-namespace, package-to-server, artifact, remote-endpoint, or TLS reference-identity binding failures](../../research/techniques/SAF-T1004/technique-contract.yml).
- [Registry or aggregator resolution that selects, installs, configures, or connects to the wrong server](../../research/techniques/SAF-T1004/technique-contract.yml).

### Out of Scope

- [Malicious-server delivery without identity confusion](../../research/techniques/SAF-T1004/technique-contract.yml).
- [Tool-name collision after a server connection is established](../../research/techniques/SAF-T1004/technique-contract.yml).
- [OAuth issuer or token-audience mix-up](../../research/techniques/SAF-T1004/technique-contract.yml).
- [Proxy-mediated traffic masquerading that does not depend on wrong-server selection](../../research/techniques/SAF-T1004/technique-contract.yml).

### Distinguishing Characteristics

The behavior starts when a server candidate enters discovery, marketplace metadata, configuration, package association, or remote-endpoint resolution and ends at selection, installation, configuration, resolution, connection, or pre-action rejection; later tool selection and follow-on effects remain outside the [frozen boundary](../../research/techniques/SAF-T1004/technique-contract.yml).

## Description

Server impersonation / name-collision occurs when a client, registry, marketplace, operator, or deployment process selects or trusts one MCP server while relying on an ambiguous or insufficiently authenticated identity. A substituted server can reuse a familiar title, alias, Registry name, package association, or endpoint presentation while resolving to a different publisher namespace, package artifact, or network endpoint. <!-- SAF-TRACE: claims=SAF-T1004-C001,SAF-T1004-C002,SAF-T1004-C003; sources=SRC-mcp-2026-schema,SRC-mcp-registry-about,SRC-mcp-registry-auth,SRC-mcp-registry-package-types,SRC-mcp-registry-remote -->

The runtime `serverInfo` identity is self-reported and protocol-unverified, so it is insufficient by itself for a security decision. Defensive identity binding therefore compares independently established attributes such as Registry origin, authenticated namespace, package identifier or digest, canonical endpoint URI, and expected TLS reference identity. <!-- SAF-TRACE: claims=SAF-T1004-C001,SAF-T1004-C003,SAF-T1004-C008; sources=SRC-mcp-2026-schema,SRC-mcp-registry-about,SRC-mcp-registry-package-types,SRC-rfc9525 -->

The end-to-end status is Demonstrated because a controlled proof exercised the actual MCP Registry publish path and stored an unverified server-to-OCI association; the advisory expressly excludes a production attack. Adjacent tool collisions and historical package campaigns do not raise that status. <!-- SAF-TRACE: claims=SAF-T1004-C005,SAF-T1004-C011,SAF-T1004-C012; sources=SRC-ghsa-oci-rate-limit,SRC-ghsa-weknora,SRC-jfrog-azure-typosquat -->

## Attack Vectors

- **Primary Vector**: A discovery, marketplace, configuration, or package-resolution path accepts a familiar label without binding the authenticated publisher, intended package or digest, and canonical endpoint. <!-- SAF-TRACE: claims=SAF-T1004-C002,SAF-T1004-C003; sources=SRC-mcp-registry-about,SRC-mcp-registry-auth,SRC-mcp-registry-package-types,SRC-mcp-registry-remote -->
- **Secondary Vectors**: A supplied remote endpoint differs from the trusted canonical URI or expected TLS reference identity. <!-- SAF-TRACE: claims=SAF-T1004-C007,SAF-T1004-C008; sources=SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->
- **Affected Components**: MCP host and client selection logic, Registry or marketplace consumers, server packages and publisher namespaces, remote endpoint configuration, and TLS service identity. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C007,SAF-T1004-C008; sources=SRC-mcp-registry-about,SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->
- **Trust Boundary Crossed**: The intended-server identity is replaced by a different publisher, package, artifact, or endpoint before the discrepancy is rejected. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C007; sources=SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026 -->

## Technical Details

### Prerequisites

- A client or operator accepts a server candidate from discovery, a marketplace, configuration, a package registry, or a supplied endpoint. <!-- SAF-TRACE: claims=SAF-T1004-C002,SAF-T1004-C003; sources=SRC-mcp-registry-about,SRC-mcp-registry-remote -->
- At least one security-relevant identity attribute is ambiguous, mutable, self-asserted, skipped, or not checked against an independent trust source. <!-- SAF-TRACE: claims=SAF-T1004-C001,SAF-T1004-C003,SAF-T1004-C004,SAF-T1004-C008; sources=SRC-mcp-2026-schema,SRC-mcp-registry-package-types,SRC-ghsa-oci-rate-limit,SRC-rfc9525 -->
- The unintended server can receive an installation, connection, or tool request before the discrepancy is rejected. <!-- SAF-TRACE: claims=SAF-T1004-C007; sources=SRC-ms-azure-mcp-security-2026 -->

### Attack Flow

1. The adversary supplies or advertises a server identity through a colliding display name, nearby namespace, misleading package association, or substituted endpoint. <!-- SAF-TRACE: claims=SAF-T1004-C002,SAF-T1004-C003,SAF-T1004-C007; sources=SRC-mcp-registry-auth,SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026 -->
2. Discovery or configuration resolves the familiar label without binding every security-relevant attribute to an approved record. <!-- SAF-TRACE: claims=SAF-T1004-C001,SAF-T1004-C003,SAF-T1004-C008; sources=SRC-mcp-2026-schema,SRC-mcp-registry-package-types,SRC-rfc9525 -->
3. The client installs or connects to the unintended package or endpoint. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C007; sources=SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026 -->
4. The substituted endpoint receives requests and can conditionally receive credentials or resource data exposed through the connection. <!-- SAF-TRACE: claims=SAF-T1004-C007; sources=SRC-ms-azure-mcp-security-2026 -->

### Example Scenario

An inert example is a client that intends to approve `com.example/finance` but resolves a familiar display label to a different authenticated namespace, package digest, or `https://mcp.invalid` endpoint; the analytic compares the complete approved tuple before connection and alerts on any failed binding or mismatch. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C007,SAF-T1004-C008; sources=SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1004-C001 | Runtime serverInfo identity is self-reported and protocol-unverified. | Research-Derived | SRC-mcp-2026-schema: [MCP schema](https://modelcontextprotocol.io/specification/2026-07-28/schema) | Does not establish each client's behavior or package and endpoint identity. |
| SAF-T1004-C002 | The official Registry binds reverse-DNS-style server namespaces to authenticated GitHub accounts or domains. | Research-Derived | SRC-mcp-registry-about and SRC-mcp-registry-auth: [Registry authentication](https://modelcontextprotocol.io/registry/authentication) | Does not guarantee each package or endpoint association. |
| SAF-T1004-C003 | Security decisions need a multi-field publisher, package, artifact, and endpoint binding rather than a display label alone. | Research-Derived | SRC-mcp-registry-about, SRC-mcp-registry-package-types, SRC-mcp-registry-remote, and SRC-mcp-authorization-2026-07-28 | Defensive synthesis; no universal tuple is prescribed. |
| SAF-T1004-C004 | CVE-2026-45781 skipped OCI package-to-server-name validation on HTTP 429 before Registry 1.7.9. | Demonstrated | SRC-ghsa-oci-rate-limit and SRC-nvd-cve-2026-45781: [maintainer advisory](https://github.com/modelcontextprotocol/registry/security/advisories/GHSA-2v5f-5r6w-p67r) | Authenticated attacker namespace only; image bytes unchanged; CVSS 3.5. |
| SAF-T1004-C005 | The advisory proof stored an unverified association through the real publish path and excluded a production attack. | Demonstrated | SRC-ghsa-oci-rate-limit: [GHSA-2v5f-5r6w-p67r](https://github.com/modelcontextprotocol/registry/security/advisories/GHSA-2v5f-5r6w-p67r) | No live namespace; user interaction required. |
| SAF-T1004-C006 | Registry listing is not a complete safety guarantee because moderation is minimal and deeper scanning is delegated. | Research-Derived | SRC-mcp-registry-about, SRC-mcp-registry-moderation, and SRC-mcp-registry-tos | Policies can change and do not assess a specific server. |
| SAF-T1004-C007 | A substituted endpoint can receive requests and expose credentials or resource data; trusted configuration and TLS checks reduce risk. | Research-Derived | SRC-ms-azure-mcp-security-2026: [Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) | Guidance, not incident or exploit evidence; accuracy unquantified. |
| SAF-T1004-C008 | TLS clients independently construct and verify reference identifiers and terminate automated connections on mismatch. | Research-Derived | SRC-rfc9525: [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) | A correctly authenticated endpoint can still be malicious. |
| SAF-T1004-C009 | Demonstrated status and Medium severity combine a limited direct proof with a conditional, undemonstrated downstream exposure. | Demonstrated | SRC-ghsa-oci-rate-limit, SRC-nvd-cve-2026-45781, and SRC-ms-azure-mcp-security-2026 | Medium is an SAF synthesis, not the advisory rating. |
| SAF-T1004-C010 | Unicode confusable matching is inclusive, version-sensitive, and font-dependent, so it is not a sole blocking signal. | Research-Derived | SRC-uts39: [Unicode Technical Standard 39](https://unicode.org/reports/tr39/) | Does not evaluate this detector or an MCP implementation. |
| SAF-T1004-C011 | CVE-2026-30856 is adjacent tool-resolution collision evidence, not direct server-identity evidence. | Research-Derived | SRC-ghsa-weknora, SRC-nvd-cve-2026-30856, and SRC-mcp-tools-2026-07-28 | Occurs after server configuration and does not substitute publisher, package, or endpoint identity. |
| SAF-T1004-C012 | The 2022 Azure-themed npm campaign is historical package-name analogy, not MCP incident evidence. | Research-Derived | SRC-jfrog-azure-typosquat: [JFrog research](https://jfrog.com/blog/large-scale-npm-attack-targets-azure-developers-with-malicious-packages/) | Predates MCP; dependency-confusion involvement was not established. |
| SAF-T1004-C013 | ATT&CK T1036.005 is analogous rather than direct. | Research-Derived | SRC-attck-t1036: [ATT&CK T1036.005](https://attack.mitre.org/techniques/T1036/005/) | ATT&CK does not define MCP Registry, package-binding, or endpoint-resolution semantics. |
| SAF-T1004-C014 | No qualifying production breach was established in the corpus as of 2026-09-01. | Research-Derived | SRC-ghsa-oci-rate-limit and SRC-nvd-cve-2026-45781; [search ledger](../../research/techniques/SAF-T1004/source-coverage.yml) | Bounded search result; cannot prove universal absence. |

### Current State

- **Affected Environments**: MCP clients, hosts, registries, marketplaces, and deployment workflows that accept an identity label without independently binding publisher, package, artifact, endpoint, and TLS identity. <!-- SAF-TRACE: claims=SAF-T1004-C001,SAF-T1004-C003; sources=SRC-mcp-2026-schema,SRC-mcp-registry-package-types,SRC-mcp-registry-remote -->
- **Known Exploitation**: The selected direct source documents a controlled proof, not a production attack; the bounded corpus found no qualifying production breach. <!-- SAF-TRACE: claims=SAF-T1004-C005,SAF-T1004-C014; sources=SRC-ghsa-oci-rate-limit,SRC-nvd-cve-2026-45781 -->
- **Available Protections**: Authenticated namespaces, fail-closed package binding, trusted endpoint configuration, TLS service-identity validation, approved-server inventory, and multi-field change monitoring. <!-- SAF-TRACE: claims=SAF-T1004-C002,SAF-T1004-C003,SAF-T1004-C007,SAF-T1004-C008; sources=SRC-mcp-registry-auth,SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->
- **Residual Risk**: Registry listing, a familiar title, or a valid certificate does not alone establish that the selected server is intended, and products may not emit the normalized identity telemetry required by the analytic. <!-- SAF-TRACE: claims=SAF-T1004-C001,SAF-T1004-C006,SAF-T1004-C007,SAF-T1004-C008; sources=SRC-mcp-2026-schema,SRC-mcp-registry-moderation,SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| GHSA-2v5f-5r6w-p67r / CVE-2026-45781 | 2026; MCP Registry before 1.7.9 | Stored an unverified server-to-OCI association; fixed in 1.7.9 | Direct vulnerability and controlled demonstration; Ryan Vonbrubeck (`@dodge1218`) reported it and `rdimitrov` published the advisory and developed the remediation. <!-- SAF-TRACE: claims=SAF-T1004-C004,SAF-T1004-C005,SAF-T1004-C009; sources=SRC-ghsa-oci-rate-limit,SRC-nvd-cve-2026-45781 --> | No production attack, live namespace, or image-byte takeover; downstream exposure undemonstrated. |
| GHSA-67q9-58vj-32qx / CVE-2026-30856 | 2026; WeKnora through 0.2.14 | Internal tool identifier overwrite; fixed in 0.3.0 | Adjacent tool-resolution collision; the advisory is by `lyingbug` and credits `aleister1102` as reporter. <!-- SAF-TRACE: claims=SAF-T1004-C011; sources=SRC-ghsa-weknora,SRC-nvd-cve-2026-30856 --> | Does not substitute an MCP server publisher, package, or endpoint identity. |
| Azure-themed npm package campaign | 2022; npm ecosystem | More than 200 lookalike packages collected host or user data; malicious packages should be removed and dependencies rebound to approved identities. | Historical non-MCP analogy documented by Andrey Polkovnychenko and Shachar Menashe of JFrog Security Research. <!-- SAF-TRACE: claims=SAF-T1004-C012; sources=SRC-jfrog-azure-typosquat --> | Predates MCP; known downloads were limited and dependency-confusion involvement was not established. |

No qualifying production breach was established in the directly reviewed corpus; the [search record](../../research/techniques/SAF-T1004/source-coverage.yml) preserves the bounded scope and all rejected leads.

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High, conditional | A substituted endpoint can receive requests, credentials, or resource data if the client exposes them through the connection. <!-- SAF-TRACE: claims=SAF-T1004-C007,SAF-T1004-C009; sources=SRC-ms-azure-mcp-security-2026,SRC-ghsa-oci-rate-limit --> |
| Integrity | Medium | The direct proof altered Registry association integrity but did not alter the referenced image bytes. <!-- SAF-TRACE: claims=SAF-T1004-C004,SAF-T1004-C005,SAF-T1004-C009; sources=SRC-ghsa-oci-rate-limit,SRC-nvd-cve-2026-45781 --> |
| Availability | Not established | The reviewed direct demonstration does not establish an availability consequence. <!-- SAF-TRACE: claims=SAF-T1004-C005,SAF-T1004-C009; sources=SRC-ghsa-oci-rate-limit --> |
| Scope | Adjacent or multi-system, conditional | Scope depends on whether the wrong binding propagates from a Registry, marketplace, or configuration source to clients. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C009; sources=SRC-mcp-registry-about,SRC-mcp-registry-package-types,SRC-ghsa-oci-rate-limit --> |

### Severity Conditions

- **Severity increases when**: A wrong binding reaches clients that automatically connect or expose credentials, tool requests, or sensitive resource data. <!-- SAF-TRACE: claims=SAF-T1004-C007,SAF-T1004-C009; sources=SRC-ms-azure-mcp-security-2026,SRC-ghsa-oci-rate-limit -->
- **Severity decreases when**: Authenticated publisher, package, digest, endpoint, and TLS identity checks fail closed before installation or connection. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C004,SAF-T1004-C008; sources=SRC-mcp-registry-package-types,SRC-ghsa-oci-rate-limit,SRC-rfc9525 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or client audit log | Discovery, install, configuration, resolution, connection, and decision | Timestamp, actor, action, alias, Registry origin, namespace, server name, package and digest, endpoint, TLS identity, decision | Retain before-and-after identity values and the approved baseline. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C007,SAF-T1004-C008; sources=SRC-mcp-registry-about,SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026,SRC-rfc9525 --> |
| Registry, package verifier, and TLS verifier | Namespace validation, package binding, artifact verification, and service-identity match | Verification status, error, immutable digest, expected reference identity, presented identity | Preserve skipped and unknown outcomes rather than converting them to success. <!-- SAF-TRACE: claims=SAF-T1004-C004,SAF-T1004-C008; sources=SRC-ghsa-oci-rate-limit,SRC-rfc9525 --> |

### Indicators of Compromise (IoCs)

- No reliable durable IoC is established; the frozen evidence supports identity-binding discrepancies and event sequences rather than a universal malicious artifact. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C007; sources=SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026 -->

### Behavioral Indicators

- An approved alias resolves to a different publisher, package, digest, Registry, endpoint, or expected TLS identity. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C008; sources=SRC-mcp-registry-package-types,SRC-mcp-registry-remote,SRC-rfc9525 -->
- A security-relevant install, configuration, resolution, or connection proceeds after namespace or package binding is failed, skipped, or unknown. <!-- SAF-TRACE: claims=SAF-T1004-C004,SAF-T1004-C007; sources=SRC-ghsa-oci-rate-limit,SRC-ms-azure-mcp-security-2026 -->
- Unicode confusable similarity is a secondary review signal only and cannot by itself establish substitution. <!-- SAF-TRACE: claims=SAF-T1004-C010; sources=SRC-uts39 -->

### Detection Analytic

The complete experimental analytic is maintained in [detection-rule.yml](detection-rule.yml), with its source-or-omit component mapping embedded in the rule.

- **Analytic Goal**: Identify a security-relevant wrong-server decision with an unverified binding, approved-tuple mismatch, or TLS identity mismatch. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C004,SAF-T1004-C007,SAF-T1004-C008; sources=SRC-mcp-registry-package-types,SRC-ghsa-oci-rate-limit,SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->
- **Rule Status**: Experimental; it consumes normalized synthetic telemetry and does not validate live package, Registry, or certificate state. <!-- SAF-TRACE: claims=SAF-T1004-C007,SAF-T1004-C008; sources=SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->
- **Correlation Window**: Evaluate the approved tuple at the install, configuration, resolution, or connection decision; no time aggregation is required by the synthetic rule. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C007; sources=SRC-mcp-registry-package-types,SRC-ms-azure-mcp-security-2026 -->
- **Known False Positives**: Legitimate migration, duplicate human-readable titles, fail-closed verifier outages, and multilingual-name similarity. <!-- SAF-TRACE: claims=SAF-T1004-C006,SAF-T1004-C007,SAF-T1004-C010; sources=SRC-mcp-registry-moderation,SRC-ms-azure-mcp-security-2026,SRC-uts39 -->
- **Known Limitations**: The analytic cannot prove intent, validate a live certificate chain, or detect a malicious server retaining every approved identity attribute. <!-- SAF-TRACE: claims=SAF-T1004-C007,SAF-T1004-C008; sources=SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->
- **Tuning Guidance**: Baseline authenticated publisher, package, digest, endpoint, and TLS identities; review migrations without allowlisting failed verification. <!-- SAF-TRACE: claims=SAF-T1004-C003,SAF-T1004-C004,SAF-T1004-C008; sources=SRC-mcp-registry-package-types,SRC-ghsa-oci-rate-limit,SRC-rfc9525 -->

### Validation

- **Test Data**: [fixtures/detection-events.json](fixtures/detection-events.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: [Six of six synthetic cases pass, including positive, negative, boundary, and expected-false-positive coverage](test-results.json)
- **Last Validated**: [2026-09-01](test-log.jsonl)
- **Feasibility Waiver**: None; the validation is synthetic and its limitations remain explicit in the [quality review](../../research/techniques/SAF-T1004/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. Build allowlists from authenticated publisher namespaces plus package digests or canonical endpoints; never key trust solely on runtime `serverInfo.name`, a title, or a marketplace label. <!-- SAF-TRACE: claims=SAF-T1004-C001,SAF-T1004-C002,SAF-T1004-C003; sources=SRC-mcp-2026-schema,SRC-mcp-registry-auth,SRC-mcp-registry-package-types -->
2. Fail closed when namespace, package-to-server binding, artifact hash, or endpoint identity cannot be verified; the direct Registry weakness shows why an upstream validation error cannot become success. <!-- SAF-TRACE: claims=SAF-T1004-C004,SAF-T1004-C008; sources=SRC-ghsa-oci-rate-limit,SRC-rfc9525 -->
3. Construct expected TLS reference identifiers from trusted configuration, terminate automated connections on mismatch, and do not disable certificate verification. <!-- SAF-TRACE: claims=SAF-T1004-C007,SAF-T1004-C008; sources=SRC-ms-azure-mcp-security-2026,SRC-rfc9525 -->
4. Pin package versions and immutable hashes where supported while retaining separate publisher, package, and endpoint checks; a hash proves bytes, not that the chosen artifact is intended. <!-- SAF-TRACE: claims=SAF-T1004-C003; sources=SRC-mcp-registry-package-types -->

### Detective Controls

1. Maintain an approved-server inventory and review new, unregistered, or changed identity tuples before exposing credentials or sensitive data. <!-- SAF-TRACE: claims=SAF-T1004-C007; sources=SRC-ms-azure-mcp-security-2026 -->
2. Alert on failed or skipped binding, approved-tuple mismatch, and TLS identity mismatch; use Unicode confusable similarity only to prioritize review. <!-- SAF-TRACE: claims=SAF-T1004-C004,SAF-T1004-C008,SAF-T1004-C010; sources=SRC-ghsa-oci-rate-limit,SRC-rfc9525,SRC-uts39 -->

Registry presence is not a complete safety guarantee because moderation is minimal, some scanning is delegated, and removed metadata can remain available. <!-- SAF-TRACE: claims=SAF-T1004-C006; sources=SRC-mcp-registry-about,SRC-mcp-registry-moderation,SRC-mcp-registry-tos -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| SAF-T1003: Malicious MCP-Server Distribution | Alternative or prerequisite | Delivery need not involve identity confusion; SAF-T1004 requires wrong-server selection through identity resolution or binding. [Contract](../../research/techniques/SAF-T1004/technique-contract.yml) |
| SAF-T1008: Cross-Server Tool Shadowing | Adjacent | Misleading tool identity occurs after server selection; SAF-T1004 concerns the server identity. [Contract](../../research/techniques/SAF-T1004/technique-contract.yml) |
| SAF-T1009: Authorization Server Mix-up | Adjacent | Issuer and token-audience binding are different from MCP server publisher, package, and endpoint selection. [Contract](../../research/techniques/SAF-T1004/technique-contract.yml) |
| SAF-T1301: Cross-Server Tool Shadowing | Adjacent | Colliding tool names assume connected servers; SAF-T1004 stops at wrong-server selection, installation, or connection. [Contract](../../research/techniques/SAF-T1004/technique-contract.yml) |
| SAF-T1407: Server Proxy Masquerade | Overlapping but distinct | Proxy masquerade requires mediated traffic behavior; SAF-T1004 does not require a proxy. [Contract](../../research/techniques/SAF-T1004/technique-contract.yml) |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Match Legitimate Resource Name or Location | Analogous | It covers making an object appear legitimate by matching a trusted name or location, but it does not define MCP Registry, package-binding, or endpoint-resolution semantics. <!-- SAF-TRACE: claims=SAF-T1004-C013; sources=SRC-attck-t1036 --> |

Repository-owned tactic, neighboring-technique, and mitigation joins are recorded in the [framework model](../../research/framework-model.yml).

## References

1. **SRC-mcp-2026-schema**: [MCP Specification 2026-07-28 — Schema Reference](https://modelcontextprotocol.io/specification/2026-07-28/schema) — MCP Specification contributors.
2. **SRC-mcp-tools-2026-07-28**: [MCP Specification 2026-07-28 — Server Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — MCP Specification contributors.
3. **SRC-mcp-authorization-2026-07-28**: [MCP Specification 2026-07-28 — Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — MCP Specification contributors.
4. **SRC-mcp-registry-about**: [The MCP Registry](https://modelcontextprotocol.io/registry/about) — MCP Registry maintainers.
5. **SRC-mcp-registry-auth**: [How to Authenticate When Publishing to the Official MCP Registry](https://modelcontextprotocol.io/registry/authentication) — MCP Registry maintainers.
6. **SRC-mcp-registry-package-types**: [MCP Registry Supported Package Types](https://modelcontextprotocol.io/registry/package-types) — MCP Registry maintainers.
7. **SRC-mcp-registry-moderation**: [MCP Registry Moderation Policy](https://modelcontextprotocol.io/registry/moderation-policy) — MCP Registry maintainers.
8. **SRC-mcp-registry-tos**: [Official MCP Registry Terms of Service](https://modelcontextprotocol.io/registry/terms-of-service) — MCP Registry maintainers.
9. **SRC-mcp-registry-remote**: [Publishing Remote Servers](https://modelcontextprotocol.io/registry/remote-servers) — MCP Registry maintainers.
10. **SRC-ghsa-oci-rate-limit**: [GHSA-2v5f-5r6w-p67r](https://github.com/modelcontextprotocol/registry/security/advisories/GHSA-2v5f-5r6w-p67r) — reported by Ryan Vonbrubeck (`@dodge1218`); advisory and remediation by `rdimitrov`.
11. **SRC-nvd-cve-2026-45781**: [NVD — CVE-2026-45781](https://nvd.nist.gov/vuln/detail/CVE-2026-45781) — NVD, GitHub Inc., and CISA-ADP.
12. **SRC-ms-azure-mcp-security-2026**: [Secure your Azure MCP Server deployment](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) — Microsoft Azure MCP Server documentation team.
13. **SRC-rfc9525**: [RFC 9525: Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525.html) — Peter Saint-Andre and Rich Salz.
14. **SRC-uts39**: [Unicode Security Mechanisms](https://unicode.org/reports/tr39/) — Unicode Technical Committee.
15. **SRC-ghsa-weknora**: [GHSA-67q9-58vj-32qx](https://github.com/Tencent/WeKnora/security/advisories/GHSA-67q9-58vj-32qx) — advisory by `lyingbug`; `aleister1102` credited as reporter.
16. **SRC-nvd-cve-2026-30856**: [NVD — CVE-2026-30856](https://nvd.nist.gov/vuln/detail/CVE-2026-30856) — NVD and GitHub Inc.
17. **SRC-jfrog-azure-typosquat**: [Large-scale npm attack targets Azure developers with malicious packages](https://jfrog.com/blog/large-scale-npm-attack-targets-azure-developers-with-malicious-packages/) — Andrey Polkovnychenko and Shachar Menashe, JFrog Security Research.
18. **SRC-attck-t1036**: [ATT&CK T1036.005: Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005/) — MITRE ATT&CK team.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft frozen before repository integration | `/root/cleanroom_saf_t1004` |
| 0.2 | 2026-09-01 | Schema-only normalization to the current canonical packet, readable trace, detection rule, and strict isolated validation gate | `/root/normalize_saf_t1004` |
