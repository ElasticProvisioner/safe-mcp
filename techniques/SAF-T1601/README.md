# SAF-T1601: MCP Server Enumeration

## Overview

- **Tactic**: Discovery (ATK-TA0007)
- **Technique ID**: SAF-T1601
- **Research Packet**: [research/techniques/SAF-T1601](../../research/techniques/SAF-T1601/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1601/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: Medium
- **Severity Rationale**: Enumeration can disclose integration topology and advertised capability classes that improve targeting, but this technique stops before invocation, data access, or identity proof. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C017; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-cli-20260728 -->
- **First Observed**: No qualifying production observation was identified in the reviewed corpus as of 2026-09-01. [NVD MCP corpus query](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol&resultsPerPage=200) <!-- SAF-TRACE: claims=SAF-T1601-C009; sources=SRC-nvd-mcp-corpus-20260901,SRC-cisa-kev-server-enumeration-2026-09-01 -->
- **Last Updated**: 2026-09-02

## Scope

MCP Server Enumeration is the adversarial inventory of the MCP servers available to a compromised or misused host context, using host configuration, connection establishment, or MCP discovery metadata to identify and characterize the server set. [MCP Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) <!-- SAF-TRACE: claims=SAF-T1601-C001,SAF-T1601-C005; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-config-20260728 -->

### In Scope

- Reading MCP host or client configuration to identify named server entries, transports, commands, or endpoints. [Inspector configuration](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/configuration) <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C005; sources=SRC-mcp-inspector-config-20260728 -->
- Establishing metadata-only connections and using `server/discover` or legacy `initialize` results to fingerprint an already-reachable server. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C002,SAF-T1601-C005; sources=SRC-mcp-discovery-2026-07-28 -->
- Correlating configuration identity, endpoint, transport, supported versions, and advertised capability classes across multiple servers. [MCP Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) <!-- SAF-TRACE: claims=SAF-T1601-C001,SAF-T1601-C005; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-discovery-2026-07-28 -->

### Out of Scope

- Generic port or service scanning that does not establish an MCP relationship is covered by a network-service-discovery neighbor. [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/) <!-- SAF-TRACE: claims=SAF-T1601-C015; sources=SRC-mitre-attack-t1046-v3.2 -->
- Enumerating tools, resources, or prompts within one already-selected server is a capability-inventory behavior, not this technique's immediate server-set objective. [MCP Inspector CLI](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/cli) <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C006; sources=SRC-mcp-inspector-cli-20260728 -->
- Invoking tools, reading resources, retrieving prompts, bypassing authorization, modifying configuration, or registering a server is follow-on behavior. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C002,SAF-T1601-C017; sources=SRC-mcp-discovery-2026-07-28 -->

### Distinguishing Characteristics

The immediate objective is a map of MCP server relationships. Offline catalog reads and metadata-only discovery qualify; individual capability use and generic network scanning do not. The boundary is observable through configuration access plus server-specific discovery responses rather than through downstream tool effects. [Inspector catalog documentation](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/cli) <!-- SAF-TRACE: claims=SAF-T1601-C005,SAF-T1601-C006,SAF-T1601-C015; sources=SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728,SRC-mitre-attack-t1046-v3.2 -->

## Description

An MCP host can manage multiple clients, with each client connected to exactly one server and the host maintaining the boundary between servers. That topology makes host configuration and client lifecycle state a natural inventory of integrations. [MCP Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) <!-- SAF-TRACE: claims=SAF-T1601-C001; sources=SRC-mcp-architecture-2026-07-28 -->

For modern revision 2026-07-28 servers, `server/discover` returns supported versions, capability classes, instructions, and self-reported server information; legacy servers expose related metadata during initialization. An actor can combine these results with configuration entries to prioritize follow-on activity, but the adversarial use is an explicit inference rather than a reported MCP-server-enumeration incident. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C002,SAF-T1601-C005,SAF-T1601-C009; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-architecture-2026-07-28,SRC-mcp-inspector-config-20260728,SRC-nvd-mcp-corpus-20260901,SRC-cisa-kev-server-enumeration-2026-09-01 -->

The returned `serverInfo` is self-reported and must not be treated as verified identity. Analysts should bind a server observation to its configured name, endpoint or process, transport, authenticated principal, and protocol response rather than relying on a display name alone. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C003,SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->

## Attack Vectors

- **Primary Vector**: Read access to a host's MCP configuration or server catalog. [Inspector configuration](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/configuration) <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C005; sources=SRC-mcp-inspector-config-20260728 -->
- **Secondary Vector**: Metadata-only requests to candidate local or remote MCP endpoints reachable from the actor's context. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C002,SAF-T1601-C005; sources=SRC-mcp-discovery-2026-07-28 -->
- **Affected Components**: MCP host configuration, client lifecycle state, transport endpoints, and server discovery metadata. [MCP Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) <!-- SAF-TRACE: claims=SAF-T1601-C001,SAF-T1601-C002; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-discovery-2026-07-28 -->
- **Trust Boundary Crossed**: The boundary between an actor's host, client, account, or adjacent-network foothold and the integration topology exposed by MCP configuration and server responses. [MCP Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) <!-- SAF-TRACE: claims=SAF-T1601-C001,SAF-T1601-C005; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-inspector-config-20260728 -->

## Technical Details

### Prerequisites

- The actor can read an MCP configuration/catalog or identify candidate MCP endpoints from another source. [Inspector configuration](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/configuration) <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C005; sources=SRC-mcp-inspector-config-20260728 -->
- The actor's process or principal can query the selected server under whatever network and authorization controls protect discovery. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C002,SAF-T1601-C005; sources=SRC-mcp-discovery-2026-07-28 -->
- The host or server exposes enough stable endpoint, process, or configuration identity to distinguish multiple servers; self-reported `serverInfo` alone is insufficient. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C003,SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->

### Attack Flow

1. **Setup**: The actor obtains read access to an MCP server catalog or a set of candidate endpoints. [Inspector configuration](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/configuration) <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C005; sources=SRC-mcp-inspector-config-20260728 -->
2. **Catalog Enumeration**: The actor extracts server names, transports, commands, or URLs without invoking a server capability. [MCP Inspector CLI](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/cli) <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C006; sources=SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728 -->
3. **Metadata Probe**: For reachable entries, the actor sends `server/discover` or observes a legacy initialization response. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C002,SAF-T1601-C005; sources=SRC-mcp-discovery-2026-07-28 -->
4. **Correlation**: The actor joins configured identity, endpoint, transport, protocol version, and capability classes, while treating display identity as unverified. [MCP Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) <!-- SAF-TRACE: claims=SAF-T1601-C003,SAF-T1601-C005; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-config-20260728 -->
5. **Objective**: The actor produces a server inventory that can prioritize later activity. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C005,SAF-T1601-C017; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728 -->
6. **Stop Condition**: Any tool invocation, resource read, prompt retrieval, authorization bypass, or server modification is classified separately. [MCP Inspector CLI](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/cli) <!-- SAF-TRACE: claims=SAF-T1601-C006,SAF-T1601-C017; sources=SRC-mcp-inspector-cli-20260728,SRC-mcp-discovery-2026-07-28 -->

### Example Scenario

A compromised user-level process reads an inert test host's three configured server entries and records successful discovery responses. It stops after capturing endpoint, transport, protocol version, and capability-class metadata; it does not authenticate beyond the existing test principal or invoke a capability. <!-- SAF-TRACE: claims=SAF-T1601-C005,SAF-T1601-C017; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-config-20260728,SRC-mcp-inspector-cli-20260728 -->

The following sanitized record illustrates the observable event shape used by the detection test. <!-- SAF-TRACE: claims=SAF-T1601-C002,SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->

```json
{
  "timestamp": "2026-09-01T12:00:00Z",
  "actor_id": "test-user",
  "session_id": "session-example",
  "server_id": "server-a.example.test",
  "method": "server/discover",
  "result": "success",
  "capability_classes": ["tools", "resources"]
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1601-C001 | Hosts manage multiple one-to-one client/server relationships. | Research-Derived | SRC-mcp-architecture-2026-07-28: [MCP Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) | Storage and exposure of configuration are implementation-specific. |
| SAF-T1601-C002 | `server/discover` exposes versions, capabilities, and self-reported identity. | Research-Derived | SRC-mcp-discovery-2026-07-28: [MCP Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) | It characterizes an already-reachable server. |
| SAF-T1601-C003 | `serverInfo` is self-reported and unsuitable as verified identity. | Research-Derived | SRC-mcp-discovery-2026-07-28: [MCP Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) | Deployments may add stronger bindings. |
| SAF-T1601-C004 | Inspector can list and show configured servers offline. | Demonstrated | SRC-mcp-inspector-cli-20260728 and SRC-mcp-inspector-config-20260728: [Inspector CLI](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/cli) | Legitimate administration, not adversary observation. |
| SAF-T1601-C005 | Configuration plus discovery results can yield a server inventory. | Research-Derived | SRC-mcp-architecture-2026-07-28, SRC-mcp-discovery-2026-07-28, SRC-mcp-inspector-config-20260728 | Core adversarial use is an explicit inference. |
| SAF-T1601-C006 | Enumeration can stop before connection or capability invocation. | Demonstrated | SRC-mcp-inspector-cli-20260728: [Inspector CLI](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/cli) | Inspector-specific demonstration. |
| SAF-T1601-C007 | CVE-2025-66416 conditionally enabled unauthorized local HTTP MCP requests. | Research-Derived | SRC-nvd-cve-2025-66416 and SRC-ghsa-9h52-p55h-vw2f: [maintainer advisory](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-9h52-p55h-vw2f) | Enabling vulnerability; no production exploitation established. |
| SAF-T1601-C008 | CVE-2026-49257 exposed mcp-pinot without authentication by default. | Research-Derived | SRC-nvd-cve-2026-49257 and SRC-ghsa-mcp-pinot-73cv: [maintainer advisory](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6) | Enabling one known endpoint, not discovering multiple servers. |
| SAF-T1601-C009 | No direct production incident or direct vulnerability qualified in the reviewed corpus. | Research-Derived | SRC-nvd-mcp-corpus-20260901 and SRC-cisa-kev-server-enumeration-2026-09-01 | Dated, bounded absence claim. |
| SAF-T1601-C010 | Anthropic observed adjacent network-service discovery using MCP-connected tools. | Observed | SRC-anthropic-espionage-2025-11: [Anthropic incident report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) | The report does not say MCP servers were enumerated. |
| SAF-T1601-C011 | A three-distinct-server/five-minute analytic is a testable starting point. | Research-Derived | SRC-mcp-discovery-2026-07-28, SRC-mitre-attack-t1046-v3.2, SRC-nist-sp80092 | Threshold is not an empirical universal. |
| SAF-T1601-C012 | Startup, health checks, and administration can be false positives. | Research-Derived | SRC-mcp-inspector-cli-20260728, SRC-mcp-inspector-config-20260728, SRC-mcp-discovery-2026-07-28 | Baselines vary by deployment. |
| SAF-T1601-C013 | Configuration controls, consent, authenticated exposure, sandboxing, and least privilege constrain risk. | Research-Derived | SRC-mcp-security-2026-07-28, SRC-ghsa-9h52-p55h-vw2f, SRC-ghsa-mcp-pinot-73cv | A fully compromised account may still see its authorized topology. |
| SAF-T1601-C014 | Investigation should preserve and correlate host configuration and connection events. | Research-Derived | SRC-nist-sp80092 and SRC-mcp-architecture-2026-07-28 | Retention and legal procedure are deployment-specific. |
| SAF-T1601-C015 | ATT&CK T1046 is analogous, not direct. | Research-Derived | SRC-mitre-attack-t1046-v3.2 and SRC-mcp-discovery-2026-07-28 | T1046 does not cover offline MCP catalogs. |
| SAF-T1601-C016 | The selected CVEs were not in KEV; SSVC status was none or proof of concept. | Research-Derived | SRC-cisa-kev-server-enumeration-2026-09-01, SRC-nvd-cve-2025-66416, SRC-nvd-cve-2026-49257 | KEV absence is not proof of no exploitation. |
| SAF-T1601-C017 | The immediate risk is topology disclosure and target prioritization. | Research-Derived | SRC-mcp-discovery-2026-07-28 and SRC-mcp-inspector-cli-20260728 | Follow-on activity governs ultimate impact. |

### Current State

- **Affected Environments**: MCP hosts or adjacent contexts that expose readable server configuration, client lifecycle data, or reachable discovery endpoints. [Inspector configuration](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/configuration) <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C005; sources=SRC-mcp-inspector-config-20260728 -->
- **Known Exploitation**: No direct production MCP-server-enumeration case was identified; the Inspector is a legitimate demonstration, two selected CVEs are enabling weaknesses, and the Anthropic campaign is adjacent. [Research coverage](../../research/techniques/SAF-T1601/source-coverage.yml)
- **Available Protections**: Restrict configuration access, require consent for new local servers, authenticate non-loopback exposure, sandbox local processes, minimize scopes, and log discovery activity. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1601-C013; sources=SRC-mcp-security-2026-07-28,SRC-ghsa-9h52-p55h-vw2f,SRC-ghsa-mcp-pinot-73cv -->
- **Residual Risk**: A principal legitimately authorized to use multiple servers may still learn that authorized topology, and self-reported identity remains unverified. [MCP Discovery specification](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) <!-- SAF-TRACE: claims=SAF-T1601-C003,SAF-T1601-C013; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-security-2026-07-28,SRC-ghsa-9h52-p55h-vw2f,SRC-ghsa-mcp-pinot-73cv -->

### Known Breaches and Vulnerabilities

No direct production breach or direct vulnerability qualified. The following four examples are retained in descending relationship and impact, with their boundaries explicit. [Research coverage](../../research/techniques/SAF-T1601/source-coverage.yml)

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| MCP Inspector `servers/list` and `servers/show` | Current 2026-07-28 official CLI against a catalog or config | Enumerates configured entries without connecting; protect and audit configuration access. | Direct demonstration of mechanics. | Legitimate first-party administration, not malicious use. <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C006; sources=SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728 --> |
| CVE-2026-49257 / GHSA-73cv-556c-w3g6 | Published 2026-06-18; mcp-pinot through 3.0.1 | Unauthenticated adjacent callers could reach tools under server-side Pinot credentials; fixed in 3.1.0. The advisory credits xiangfu0 and an unnamed independent researcher. | Enabling vulnerability. | One known endpoint; proof of concept is not production exploitation. <!-- SAF-TRACE: claims=SAF-T1601-C008,SAF-T1601-C016; sources=SRC-nvd-cve-2026-49257,SRC-ghsa-mcp-pinot-73cv,SRC-cisa-kev-server-enumeration-2026-09-01 --> |
| CVE-2025-66416 / GHSA-9h52-p55h-vw2f | Published 2025-12-02; MCP Python SDK below 1.23.0 under stated local unauthenticated HTTP conditions | A malicious website could send requests to a local server; 1.23.0 enabled protection by default for loopback hosts, and stdio was unaffected. The advisory credits pcarleton and JLLeitschuh. | Enabling vulnerability. | Does not enumerate servers and has no established production exploitation. <!-- SAF-TRACE: claims=SAF-T1601-C007,SAF-T1601-C016; sources=SRC-nvd-cve-2025-66416,SRC-ghsa-9h52-p55h-vw2f,SRC-cisa-kev-server-enumeration-2026-09-01 --> |
| Anthropic GTG-1002 campaign | September 2025 production intrusions described by Anthropic Threat Intelligence and Safeguards | MCP-connected browser automation helped catalog target infrastructure and internal services; Anthropic banned accounts, notified parties, and expanded detection. | Adjacent network-service discovery. | The enumerated objects were network services, not MCP servers; the report notes model overstatement and limited visibility. <!-- SAF-TRACE: claims=SAF-T1601-C010; sources=SRC-anthropic-espionage-2025-11 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Medium | Server names, endpoints, transports, versions, and capability classes can disclose integration topology and aid targeting; no protected resource is read by this technique. <!-- SAF-TRACE: claims=SAF-T1601-C017; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-cli-20260728 --> |
| Integrity | None | Enumeration does not modify a server, configuration, or downstream system. <!-- SAF-TRACE: claims=SAF-T1601-C006,SAF-T1601-C017; sources=SRC-mcp-inspector-cli-20260728,SRC-mcp-discovery-2026-07-28 --> |
| Availability | None | Enumeration alone does not disrupt service; aggressive network scanning or resource exhaustion is outside scope. <!-- SAF-TRACE: claims=SAF-T1601-C015,SAF-T1601-C017; sources=SRC-mitre-attack-t1046-v3.2,SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-cli-20260728 --> |
| Scope | Adjacent | The inventory may span every server configured for one host principal, but its breadth is limited by configuration visibility and endpoint reachability. <!-- SAF-TRACE: claims=SAF-T1601-C001,SAF-T1601-C005; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-config-20260728 --> |

### Severity Conditions

- **Severity increases when**: A host aggregates many sensitive integrations, configuration reveals privileged endpoints, or enabling weaknesses make local or remote discovery unauthenticated. <!-- SAF-TRACE: claims=SAF-T1601-C007,SAF-T1601-C008,SAF-T1601-C017; sources=SRC-nvd-cve-2025-66416,SRC-ghsa-9h52-p55h-vw2f,SRC-nvd-cve-2026-49257,SRC-ghsa-mcp-pinot-73cv,SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-cli-20260728 -->
- **Severity decreases when**: Configuration access is restricted, server connections require consent, remote exposure is authenticated, local processes are sandboxed, and scopes are minimal. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1601-C013; sources=SRC-mcp-security-2026-07-28,SRC-ghsa-9h52-p55h-vw2f,SRC-ghsa-mcp-pinot-73cv -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or client audit log | Configuration reads, connection attempts, `server/discover`, and legacy `initialize` | Timestamp, actor, process, session, configured server ID, endpoint, transport, method, result, approval context | Correlate one actor across the host's separate one-to-one server clients. <!-- SAF-TRACE: claims=SAF-T1601-C001,SAF-T1601-C011; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 --> |
| MCP response telemetry | Successful discovery or initialization response | Correlation ID, protocol version, capability classes, configured identity, `serverInfo.name`, and `serverInfo.version` | Treat `serverInfo` as self-reported and retain endpoint or process identity. <!-- SAF-TRACE: claims=SAF-T1601-C002,SAF-T1601-C003,SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 --> |

### Indicators of Compromise (IoCs)

- No reliable durable artifact is established; use behavior, actor/session correlation, and unexpected configuration access instead of a static IoC. <!-- SAF-TRACE: claims=SAF-T1601-C009,SAF-T1601-C011; sources=SRC-nvd-mcp-corpus-20260901,SRC-cisa-kev-server-enumeration-2026-09-01,SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->

### Behavioral Indicators

- One non-administrative actor issues successful discovery or initialization operations to at least three distinct configured server identities within five minutes. <!-- SAF-TRACE: claims=SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->
- Configuration reads immediately precede discovery operations across several server endpoints, without an approved startup or inventory workflow. <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C011,SAF-T1601-C012; sources=SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728,SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->
- A single display name appears from multiple endpoints or processes, requiring endpoint-level correlation because `serverInfo` is unverified. <!-- SAF-TRACE: claims=SAF-T1601-C003,SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify rapid, successful metadata discovery across multiple distinct MCP servers by one actor and session. <!-- SAF-TRACE: claims=SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->
- **Rule Status**: Experimental; deterministic representative tests pass, but no production accuracy study was identified. [Quality review](../../research/techniques/SAF-T1601/quality-review.yml)
- **Detection Logic**: Select successful `server/discover` and legacy `initialize` events, remove approved contexts, then require three distinct server IDs within five minutes. <!-- SAF-TRACE: claims=SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->
- **Correlation Window**: Five minutes, inclusive at the boundary, as a tunable starting point. <!-- SAF-TRACE: claims=SAF-T1601-C011; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092 -->
- **Known False Positives**: Approved startup, configuration reload, health checking, and explicit Inspector inventory. <!-- SAF-TRACE: claims=SAF-T1601-C012; sources=SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728,SRC-mcp-discovery-2026-07-28 -->
- **Known Limitations**: Missing host audit fields, endpoint aliasing, self-reported identity, slow enumeration, and authorized administrative reuse can defeat or confuse the analytic. <!-- SAF-TRACE: claims=SAF-T1601-C003,SAF-T1601-C011,SAF-T1601-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092,SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728 -->
- **Tuning Guidance**: Baseline expected server fan-out by process role, use configured endpoint identity, and allowlist only approved lifecycle and administration contexts. <!-- SAF-TRACE: claims=SAF-T1601-C003,SAF-T1601-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1601/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1601/test_detection_rule.py)
- **Expected Result**: [Ten deterministic cases pass](../../research/techniques/SAF-T1601/validation/detection-test.txt), covering positive, negative, exact and outside boundaries, malformed data, and expected false positives.
- **Last Validated**: [2026-09-02](../../research/techniques/SAF-T1601/validation/strict-validator.txt).
- **Feasibility Waiver**: None. [Technique contract](../../research/techniques/SAF-T1601/technique-contract.yml)

## Mitigation Strategies

### Preventive Controls

1. Use **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)**, **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**, and **[SAF-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAF-M-45/README.md)** to restrict MCP host configuration and catalogs and require explicit consent before a new local server command or connection is accepted. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1601-C013; sources=SRC-mcp-security-2026-07-28,SRC-ghsa-9h52-p55h-vw2f,SRC-ghsa-mcp-pinot-73cv -->
2. Apply **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)** to bind local HTTP servers to loopback, require authentication for non-loopback exposure, and enable DNS-rebinding protections. [MCP Python SDK advisory](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-9h52-p55h-vw2f) <!-- SAF-TRACE: claims=SAF-T1601-C007,SAF-T1601-C013; sources=SRC-ghsa-9h52-p55h-vw2f,SRC-mcp-security-2026-07-28,SRC-ghsa-mcp-pinot-73cv -->
3. Use **[SAF-M-9: Sandboxed Testing](../../mitigations/SAF-M-9/README.md)** and **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)** to isolate local MCP server processes and minimize authorization scopes so a discovered server yields less follow-on reach. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1601-C013; sources=SRC-mcp-security-2026-07-28,SRC-ghsa-9h52-p55h-vw2f,SRC-ghsa-mcp-pinot-73cv -->

### Detective Controls

1. Use **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)** to record configuration reads and discovery operations at the host/client boundary with actor, process, session, configured server identity, endpoint, method, and result. <!-- SAF-TRACE: claims=SAF-T1601-C011,SAF-T1601-C014; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092,SRC-mcp-architecture-2026-07-28 -->
2. Use **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20/README.md)** to alert on unexpected fan-out across distinct server identities and retain approved startup, health-check, and administration context for suppression. <!-- SAF-TRACE: claims=SAF-T1601-C011,SAF-T1601-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092,SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728 -->

### Response Procedures

#### Immediate Actions

- Contain the actor, process, or session when discovery is unauthorized, and temporarily block new server connections from that context. <!-- SAF-TRACE: claims=SAF-T1601-C013,SAF-T1601-C014; sources=SRC-mcp-security-2026-07-28,SRC-ghsa-9h52-p55h-vw2f,SRC-ghsa-mcp-pinot-73cv,SRC-nist-sp80092,SRC-mcp-architecture-2026-07-28 -->
- Preserve the relevant configuration and host/client connection events before changing state. <!-- SAF-TRACE: claims=SAF-T1601-C014; sources=SRC-nist-sp80092,SRC-mcp-architecture-2026-07-28 -->

#### Investigation Steps

- Reconstruct the configured and contacted server set by actor, session, endpoint, transport, method, result, and time. <!-- SAF-TRACE: claims=SAF-T1601-C011,SAF-T1601-C014; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092,SRC-mcp-architecture-2026-07-28 -->
- Separately determine whether any discovered server was invoked, a resource was read, a prompt was retrieved, or authorization was bypassed. <!-- SAF-TRACE: claims=SAF-T1601-C006,SAF-T1601-C014,SAF-T1601-C017; sources=SRC-mcp-inspector-cli-20260728,SRC-nist-sp80092,SRC-mcp-architecture-2026-07-28,SRC-mcp-discovery-2026-07-28 -->

#### Remediation

- Remove unauthorized configuration access, close or authenticate exposed endpoints, and restore least-privilege server access. [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) <!-- SAF-TRACE: claims=SAF-T1601-C013,SAF-T1601-C014; sources=SRC-mcp-security-2026-07-28,SRC-ghsa-9h52-p55h-vw2f,SRC-ghsa-mcp-pinot-73cv,SRC-nist-sp80092,SRC-mcp-architecture-2026-07-28 -->
- Tune the analytic with confirmed lifecycle roles and endpoint identities, then add the observed legitimate or malicious sequence to regression tests. <!-- SAF-TRACE: claims=SAF-T1601-C011,SAF-T1601-C012,SAF-T1601-C014; sources=SRC-mcp-discovery-2026-07-28,SRC-mitre-attack-t1046-v3.2,SRC-nist-sp80092,SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728,SRC-mcp-architecture-2026-07-28 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1602: Tool Enumeration](../SAF-T1602/README.md) | Follow-On | Enumerates tools inside one known server; SAF-T1601 identifies the server set first. <!-- SAF-TRACE: claims=SAF-T1601-C004,SAF-T1601-C006; sources=SRC-mcp-inspector-cli-20260728,SRC-mcp-inspector-config-20260728 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Analogous | Both inventory services for targeting, but T1046 focuses on network probing while SAF-T1601 also covers offline host configuration and MCP `server/discover` metadata. <!-- SAF-TRACE: claims=SAF-T1601-C015; sources=SRC-mitre-attack-t1046-v3.2,SRC-mcp-discovery-2026-07-28 --> |

## References

1. **SRC-mcp-architecture-2026-07-28**: [MCP Architecture — Model Context Protocol maintainers, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/architecture) — host/client/server topology and capability negotiation.
2. **SRC-mcp-discovery-2026-07-28**: [MCP Discovery — Model Context Protocol maintainers, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) — discovery request, response, identity, and limitations.
3. **SRC-mcp-inspector-cli-20260728**: [MCP Inspector CLI client — Model Context Protocol maintainers, 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/cli) — catalog listing and metadata-only server selection.
4. **SRC-mcp-inspector-config-20260728**: [MCP Inspector Configuration and flags — Model Context Protocol maintainers, 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/configuration) — catalog/config behavior and `mcpServers` shape.
5. **SRC-mcp-security-2026-07-28**: [MCP Security Best Practices — Model Context Protocol maintainers, 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) — consent, sandboxing, logging, exposure, and least-privilege guidance.
6. **SRC-nvd-mcp-corpus-20260901**: [NVD Model Context Protocol keyword corpus — NIST NVD team, reviewed 2026-09-01](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol&resultsPerPage=200) — direct vulnerability-corpus screen.
7. **SRC-nvd-cve-2025-66416**: [CVE-2025-66416 — NIST NVD and CISA SSVC teams](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-66416) — affected versions, conditions, remediation, and exploitation assessment.
8. **SRC-ghsa-9h52-p55h-vw2f**: [MCP Python SDK advisory — pcarleton and analyst JLLeitschuh, 2025-12-02](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-9h52-p55h-vw2f) — first-party vulnerability and fix details.
9. **SRC-nvd-cve-2026-49257**: [CVE-2026-49257 — NIST NVD and CISA SSVC teams](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-49257) — affected versions, impact, remediation, and exploitation assessment.
10. **SRC-ghsa-mcp-pinot-73cv**: [mcp-pinot advisory — xiangfu0 and an unnamed independent security researcher, 2026-05-25](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6) — insecure defaults, impact, and fix.
11. **SRC-cisa-kev-server-enumeration-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog — CISA Cybersecurity Division, version 2026.09.01](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — exact-CVE membership check.
12. **SRC-anthropic-espionage-2025-11**: [Disrupting the first reported AI-orchestrated cyber espionage campaign — Anthropic Threat Intelligence and Safeguards, November 2025](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) — adjacent production network-service discovery using MCP-connected tools.
13. **SRC-mitre-attack-t1046-v3.2**: [Network Service Discovery T1046 — MITRE ATT&CK, Aaron Sullivan, and Praetorian, version 3.2](https://attack.mitre.org/techniques/T1046/) — analogous behavior and detection strategy.
14. **SRC-nist-sp80092**: [Guide to Computer Security Log Management — Karen Kent and Murugiah Souppaya, NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) — log-management and audit context.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Independent clean-room draft with research packet and tested detection. | SAF-MCP Research Team (clean-room agent `/root/cleanroom_saf_t1601`) |
