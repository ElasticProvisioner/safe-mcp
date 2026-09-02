# SAF-T1605: Capability Mapping

## Overview

- **Tactic**: Discovery (ATK-TA0007)
- **Technique ID**: SAF-T1605
- **Research Packet**: [research/techniques/SAF-T1605](../../research/techniques/SAF-T1605/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1605/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: Medium
- **Severity Rationale**: Mapping exposes decision-useful metadata rather than performing a follow-on action, but a broad catalog can materially improve an adversary's selection of later behavior. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C006; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- **First Observed**: No direct malicious production event was identified in the bounded review completed 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1605-C008; sources=SRC-nvd-mcp-keyword-20260902,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-02

## Scope

Capability Mapping covers an adversary using its current MCP request identity to enumerate advertised server features and correlate the returned metadata into a map for follow-on selection. The crossed boundary is the discovery interface between a requester and the capability metadata visible to that requester's authorization context. <!-- SAF-TRACE: claims=SAF-T1605-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

### In Scope

- Querying `server/discover` for protocol versions, capability classes, instructions, and self-reported server identity. <!-- SAF-TRACE: claims=SAF-T1605-C001; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-architecture-2026-07-28 -->
- Listing tools, resources, resource templates, prompts, or deprecated legacy roots without invoking a tool, obtaining a prompt, or reading a resource. <!-- SAF-TRACE: claims=SAF-T1605-C002,SAF-T1605-C003; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026,SRC-mcp-2026-roots -->
- Correlating names, descriptions, schemas, URIs, arguments, capability classes, and version metadata that the current identity can see. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C006; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

### Out of Scope

- Calling a mapped tool, retrieving prompt content, reading a resource, or using a discovered operation for collection or impact. <!-- SAF-TRACE: claims=SAF-T1605-C002,SAF-T1605-C003; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
- Changing descriptions, schemas, identities, or list-change signals; this technique consumes returned metadata rather than manipulating it. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C006; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- Bypassing authorization, enumerating active task records, or probing non-MCP network services, even when those behaviors create or reveal access paths. <!-- SAF-TRACE: claims=SAF-T1605-C010,SAF-T1605-C011,SAF-T1605-C017; sources=SRC-ghsa-typescript-w48q,SRC-ghsa-python-hvrp,SRC-ghsa-cr22-wjx7-2w6m -->

### Distinguishing Characteristics

The technique ends when the actor has correlated capability metadata. Synthetic neighbor [SAF-T1104](../SAF-T1104/README.md) begins with use of a known operation or content access; synthetic neighbor [SAF-T1001](../SAF-T1001/README.md) changes the metadata itself. These identifiers are isolated integration placeholders, not claims about the current shared catalog. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C006; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 -->

## Description

The 2026-07-28 MCP revision gives clients a compact `server/discover` view of supported versions, capability classes, and self-reported server identity. Servers can separately expose authorization-scoped lists of tools, resources, templates, and prompts; legacy roots provide client-side filesystem guidance but are deprecated and are not an access-control mechanism. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C002,SAF-T1605-C003; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026,SRC-mcp-2026-roots -->

An actor with request access can combine those responses into a working inventory of exposed technical functions. This adversarial purpose is an inference from directly supported protocol surfaces, practical enumeration, and the general discovery pattern represented by ATT&CK Software Discovery; no reviewed authority established the complete behavior as a malicious MCP incident or controlled adversarial demonstration. <!-- SAF-TRACE: claims=SAF-T1605-C004,SAF-T1605-C005,SAF-T1605-C008,SAF-T1605-C015; sources=SRC-mcp-inspector-2026,SRC-mcp-discovery-2026-07-28,SRC-attack-t1518,SRC-nvd-mcp-keyword-20260902 -->

The resulting map is not proof that an operation will succeed. Lists may be empty, paginated, cached, authorization-dependent, or stale; a disclosed Kubernetes server flaw also showed that call-layer authorization can diverge from list filtering. Capability Mapping therefore records advertised visibility, not a guaranteed or complete execution surface. <!-- SAF-TRACE: claims=SAF-T1605-C016,SAF-T1605-C017; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026,SRC-ghsa-cr22-wjx7-2w6m -->

## Attack Vectors

- **Primary Vector**: An actor with MCP request access issues `server/discover` and supported list methods under its existing authorization context. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1605-C003; sources=SRC-mcp-resources-2026,SRC-mcp-prompts-2026,SRC-mcp-2026-roots -->
  - A gateway or aggregated catalog yields many tools, resources, or prompts through paginated discovery. <!-- SAF-TRACE: claims=SAF-T1605-C007,SAF-T1605-C016; sources=SRC-arxiv-scout-2608.23992,SRC-mcp-tools-2026-07-28 -->
  - A legacy client exposes deprecated roots while processing another request. <!-- SAF-TRACE: claims=SAF-T1605-C003; sources=SRC-mcp-2026-roots -->
- **Affected Components**: MCP hosts, clients, servers, gateways, list handlers, and request authorization contexts. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C002,SAF-T1605-C003; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
- **Trust Boundary Crossed**: The actor observes capability metadata returned across the MCP requester-to-server discovery boundary. <!-- SAF-TRACE: claims=SAF-T1605-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 -->

## Technical Details

### Prerequisites

- The actor can send MCP requests to a server, directly or through a host or gateway. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C004; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-inspector-2026 -->
- The relevant capability is advertised or a supported listing method is reachable under the actor's authorization context. <!-- SAF-TRACE: claims=SAF-T1605-C002,SAF-T1605-C003,SAF-T1605-C014; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026,SRC-mcp-authorization-2026-07-28 -->
- Audit or client controls do not prevent the actor from collecting and correlating the returned metadata. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-arxiv-scout-2608.23992 -->

### Attack Flow

1. **Reconnaissance or Setup**: The actor identifies one reachable MCP server and a usable requester identity. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C014; sources=SRC-mcp-architecture-2026-07-28,SRC-mcp-authorization-2026-07-28 -->
2. **Delivery**: The actor sends an ordinary `server/discover` request and records returned capability classes, version support, instructions, and self-reported identity. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C006; sources=SRC-mcp-discovery-2026-07-28 -->
3. **Trigger or Execution**: For advertised or suspected surfaces, the actor issues distinct list requests and follows pagination where available. <!-- SAF-TRACE: claims=SAF-T1605-C002,SAF-T1605-C003,SAF-T1605-C016; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
4. **Boundary Crossing**: The server or client returns the metadata visible to that request's authorization context. <!-- SAF-TRACE: claims=SAF-T1605-C002,SAF-T1605-C003,SAF-T1605-C014; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026,SRC-mcp-authorization-2026-07-28 -->
5. **Objective**: The actor correlates the records into a map of advertised technical functions and selects likely follow-on targets. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C006; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-attack-t1518 -->
6. **Follow-On Activity**: Any later tool invocation or content retrieval is classified separately and is not part of Capability Mapping. <!-- SAF-TRACE: claims=SAF-T1605-C002,SAF-T1605-C003,SAF-T1605-C005; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->

### Example Scenario

An actor using `inventory-user@example.invalid` queries an inert test server, receives three advertised surface types, and stores only their counts; the scenario stops before any operation or content access. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C006; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026 -->

```json
{
  "actor_id": "inventory-user@example.invalid",
  "server_id": "mcp.example.invalid",
  "observed_methods": ["server/discover", "tools/list", "resources/list", "prompts/list"],
  "stored_result": {"tool_count": 12, "resource_count": 4, "prompt_count": 3},
  "follow_on_action": null
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1605-C001 | Current discovery can return versions, capabilities, and self-reported identity before other calls. | Demonstrated | SRC-mcp-discovery-2026-07-28: [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover); SRC-mcp-architecture-2026-07-28: [Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) | One server; identity is unverified. |
| SAF-T1605-C002 | `tools/list` returns the authorization-visible tool set and metadata. | Demonstrated | SRC-mcp-tools-2026-07-28: [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | The set can be empty or change. |
| SAF-T1605-C003 | Resources, templates, prompts, and deprecated roots have listing paths. | Demonstrated | SRC-mcp-resources-2026: [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources); SRC-mcp-prompts-2026: [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts); SRC-mcp-2026-roots: [Roots](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) | Roots are legacy, client-provided, and informational. |
| SAF-T1605-C004 | Inspector can enumerate tools without invocation. | Demonstrated | SRC-mcp-inspector-2026: [Inspector](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector) | Legitimate use, not adversarial proof. |
| SAF-T1605-C005 | Correlating visible capability metadata for follow-on selection defines the adversarial technique. | Research-Derived | SRC-mcp-discovery-2026-07-28: [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover); SRC-mcp-tools-2026-07-28: [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); SRC-mcp-resources-2026: [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources); SRC-mcp-prompts-2026: [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts); SRC-attack-t1518: [ATT&CK T1518](https://attack.mitre.org/techniques/T1518/) | End-to-end adversarial purpose is inferred. |
| SAF-T1605-C006 | Returned metadata can identify server, tool, resource, template, and prompt functions. | Demonstrated | SRC-mcp-discovery-2026-07-28: [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover); SRC-mcp-tools-2026-07-28: [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); SRC-mcp-resources-2026: [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources); SRC-mcp-prompts-2026: [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts) | Metadata does not prove execution success or downstream contents. |
| SAF-T1605-C007 | A PayPal paper reports production discovery across more than 2,000 tools with structured telemetry. | Observed | SRC-arxiv-scout-2608.23992: [SCOUT paper](https://arxiv.org/abs/2608.23992) | Legitimate internal production system, not an attack. |
| SAF-T1605-C008 | The bounded NVD and KEV review found no direct qualifying incident or vulnerability. | Research-Derived | SRC-nvd-mcp-keyword-20260902: [NVD API corpus](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol&resultsPerPage=2000); SRC-cisa-kev-2026-09-01: [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Corpus-and-date absence, not proof of universal absence. |
| SAF-T1605-C009 | CVE-2026-49257 exposed mcp-pinot tools through insecure defaults and was fixed in 3.1.0. | Demonstrated | SRC-ghsa-mcp-pinot-73cv: [GHSA](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6); SRC-nvd-cve-2026-49257: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-49257) | Enabling access, not capability-mapping evidence. |
| SAF-T1605-C010 | CVE-2025-66414 enabled DNS-rebinding reachability to certain local SDK servers before 1.24.0. | Demonstrated | SRC-ghsa-typescript-w48q: [GHSA](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w); SRC-nvd-cve-2025-66414: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-66414) | No capability-mapping act documented. |
| SAF-T1605-C011 | CVE-2026-52870 exposed cross-session experimental task state and was fixed in 1.27.2. | Demonstrated | SRC-ghsa-python-hvrp: [GHSA](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-hvrp-rf83-w775); SRC-nvd-cve-2026-52870: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-52870) | Task-state discovery is adjacent, not capability mapping. |
| SAF-T1605-C012 | A same-actor, same-server concentrated discovery sequence is detectable with sufficient audit fields. | Research-Derived | SRC-mcp-discovery-2026-07-28: [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover); SRC-mcp-tools-2026-07-28: [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); SRC-mcp-resources-2026: [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources); SRC-mcp-prompts-2026: [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts); SRC-arxiv-scout-2608.23992: [SCOUT paper](https://arxiv.org/abs/2608.23992) | Behavioral signal cannot establish intent. |
| SAF-T1605-C013 | Inspector, bootstrap, troubleshooting, and inventory create expected false positives. | Research-Derived | SRC-mcp-inspector-2026: [Inspector](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector); SRC-arxiv-scout-2608.23992: [SCOUT paper](https://arxiv.org/abs/2608.23992) | Purpose labels require governance. |
| SAF-T1605-C014 | Per-request authentication, audience/scope enforcement, filtered lists, and minimal scopes constrain exposure. | Demonstrated | SRC-mcp-authorization-2026-07-28: [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); SRC-mcp-security-2026-07-28: [Security practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices); SRC-mcp-tools-2026-07-28: [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); SRC-mcp-resources-2026: [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources); SRC-mcp-prompts-2026: [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts) | Cannot identify misuse of legitimately granted visibility. |
| SAF-T1605-C015 | ATT&CK Software Discovery is analogous but inventories installed software rather than advertised MCP primitives. | Research-Derived | SRC-attack-t1518: [ATT&CK T1518](https://attack.mitre.org/techniques/T1518/); SRC-mcp-discovery-2026-07-28: [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) | Analogous, not direct. |
| SAF-T1605-C016 | Lists can be paginated, cached, empty, authorization-dependent, and mutable. | Demonstrated | SRC-mcp-tools-2026-07-28: [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); SRC-mcp-resources-2026: [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources); SRC-mcp-prompts-2026: [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts) | Implementations may add constraints. |
| SAF-T1605-C017 | CVE-2026-46519 showed discovery filtering and call authorization can diverge; it was fixed in 3.6.0. | Demonstrated | SRC-ghsa-cr22-wjx7-2w6m: [GHSA](https://github.com/Flux159/mcp-server-kubernetes/security/advisories/GHSA-cr22-wjx7-2w6m); SRC-nvd-cve-2026-46519: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-46519) | Execution-layer bypass, not mapping evidence. |

### Current State

- **Affected Environments**: Any MCP deployment that returns server or feature metadata to a requester; scale increases in gateways and aggregated catalogs. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C002,SAF-T1605-C003,SAF-T1605-C007; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026,SRC-arxiv-scout-2608.23992 -->
- **Known Exploitation**: No direct malicious production exploitation or direct mapping vulnerability was identified in the reviewed corpus. <!-- SAF-TRACE: claims=SAF-T1605-C008; sources=SRC-nvd-mcp-keyword-20260902,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Authenticate protected requests, validate token audience and scope, return only authorized entries, minimize initial scope, and log discovery activity. <!-- SAF-TRACE: claims=SAF-T1605-C014; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- **Residual Risk**: A legitimately authorized identity can still inventory what it is allowed to see, and advertised visibility may differ from actual call-layer authorization. <!-- SAF-TRACE: claims=SAF-T1605-C014,SAF-T1605-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-ghsa-cr22-wjx7-2w6m -->

### Known Breaches and Vulnerabilities

No reviewed example directly documents Capability Mapping. The four selected records are high-impact boundary evidence and remain enabling or adjacent. <!-- SAF-TRACE: claims=SAF-T1605-C008,SAF-T1605-C009,SAF-T1605-C010,SAF-T1605-C011,SAF-T1605-C017; sources=SRC-nvd-mcp-keyword-20260902,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-typescript-w48q,SRC-ghsa-python-hvrp,SRC-ghsa-cr22-wjx7-2w6m -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-46519 / GHSA-cr22-wjx7-2w6m | Published 2026-07-21; mcp-server-kubernetes before 3.6.0 | Known tool names could bypass list filtering at call time; fixed in 3.6.0. Credit: Francisco Rosales, with coordination by Ax Sharma. | Adjacent execution-layer authorization bypass | Public PoC state, but no direct mapping or production exploitation established. <!-- SAF-TRACE: claims=SAF-T1605-C017; sources=SRC-ghsa-cr22-wjx7-2w6m,SRC-nvd-cve-2026-46519 --> |
| CVE-2026-49257 / GHSA-73cv-556c-w3g6 | Published 2026-08-05; mcp-pinot through 3.0.1 | Insecure defaults exposed 14 tools and server credentials; fixed in 3.1.0. Advisory credits an independent researcher. | Enabling reachability vulnerability | Public PoC state, not a documented mapping act or production breach. <!-- SAF-TRACE: claims=SAF-T1605-C009; sources=SRC-ghsa-mcp-pinot-73cv,SRC-nvd-cve-2026-49257 --> |
| CVE-2025-66414 / GHSA-w48q-cv73-mx4w | Published 2025-12-03; certain unauthenticated localhost TypeScript SDK servers before 1.24.0 | DNS rebinding could expose tools or resources; fixed in 1.24.0. Credit: JLLeitschuh. | Enabling reachability vulnerability | NVD records no known exploitation; no mapping act documented. <!-- SAF-TRACE: claims=SAF-T1605-C010; sources=SRC-ghsa-typescript-w48q,SRC-nvd-cve-2025-66414 --> |
| CVE-2026-52870 / GHSA-hvrp-rf83-w775 | Published 2026-08-26; experimental tasks in Python SDK 1.23.0–1.27.1 | Clients could enumerate and affect other sessions' task state; fixed in 1.27.2. Credits: cjmielke, dewankpant, and shrutilohani. | Adjacent task-state discovery | NVD records no known exploitation; the objects are tasks, not capabilities. <!-- SAF-TRACE: claims=SAF-T1605-C011; sources=SRC-ghsa-python-hvrp,SRC-nvd-cve-2026-52870 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Low | The immediate result is metadata visible to the requester's authorization context; names, schemas, URIs, prompts, or versions may still reveal useful technical structure. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C006,SAF-T1605-C014; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28 --> |
| Integrity | None | Mapping itself does not alter the listed capabilities, content, or state. <!-- SAF-TRACE: claims=SAF-T1605-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 --> |
| Availability | None | Mapping itself does not require disruption; high-rate abuse is an implementation concern outside the defining objective. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C016; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 --> |
| Scope | Adjacent | One identity can map one or more reachable servers, while gateway catalogs can aggregate thousands of tools and expand the decision surface. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C007; sources=SRC-mcp-architecture-2026-07-28,SRC-arxiv-scout-2608.23992 --> |

### Severity Conditions

- **Severity increases when**: The identity sees broad catalogs, sensitive names or schemas, multiple servers, or weakly partitioned scopes. <!-- SAF-TRACE: claims=SAF-T1605-C006,SAF-T1605-C007,SAF-T1605-C014; sources=SRC-mcp-tools-2026-07-28,SRC-arxiv-scout-2608.23992,SRC-mcp-security-2026-07-28 -->
- **Severity decreases when**: Lists are narrowly authorization-filtered, scopes are minimal, catalogs are partitioned, and discovery sequences are reviewed. <!-- SAF-TRACE: claims=SAF-T1605-C012,SAF-T1605-C014; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28,SRC-arxiv-scout-2608.23992 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP request audit log | `server/discover` and supported list requests | timestamp, actor_id, server_id, session_id, method, result_status, authorization_context, purpose | Normalize identities and server identifiers; preserve ordering and clock quality for correlation. <!-- SAF-TRACE: claims=SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 --> |
| MCP response summary | Discovery and list result metadata | result_type, result_count, next_cursor_present, cache metadata | Record counts and cursors rather than sensitive returned definitions when full payload retention is unnecessary. <!-- SAF-TRACE: claims=SAF-T1605-C007,SAF-T1605-C016; sources=SRC-arxiv-scout-2608.23992,SRC-mcp-tools-2026-07-28 --> |

### Indicators of Compromise (IoCs)

- No durable artifact is intrinsic to this discovery-only technique; method sequences are behavioral indicators, not standalone IoCs. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 -->

### Behavioral Indicators

- One requester queries `server/discover` and three or more distinct capability-list methods against one server in a short window. <!-- SAF-TRACE: claims=SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
- Discovery breadth or frequency materially exceeds that requester's established client, role, or workflow baseline. <!-- SAF-TRACE: claims=SAF-T1605-C012,SAF-T1605-C013; sources=SRC-arxiv-scout-2608.23992,SRC-mcp-inspector-2026 -->
- The sequence lacks an approved bootstrap, troubleshooting, inventory, conformance, or catalog-refresh purpose. <!-- SAF-TRACE: claims=SAF-T1605-C013; sources=SRC-mcp-inspector-2026,SRC-arxiv-scout-2608.23992 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify broad, concentrated enumeration of one server's advertised surfaces by one requester. <!-- SAF-TRACE: claims=SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- **Rule Status**: Experimental, because its threshold and window are tested SAF choices rather than a published malicious signature. <!-- SAF-TRACE: claims=SAF-T1605-C012,SAF-T1605-C013; sources=SRC-arxiv-scout-2608.23992,SRC-mcp-inspector-2026 -->
- **Detection Logic**: Correlate successful requests by actor and server; alert when `server/discover` is followed by at least three distinct supported list methods. <!-- SAF-TRACE: claims=SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
- **Correlation Window**: Inclusive 120 seconds from the discovery request. <!-- SAF-TRACE: claims=SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-arxiv-scout-2608.23992 -->
- **Known False Positives**: Inspector, initial client negotiation, authorized inventory, troubleshooting, conformance testing, and catalog refresh. <!-- SAF-TRACE: claims=SAF-T1605-C004,SAF-T1605-C013; sources=SRC-mcp-inspector-2026,SRC-arxiv-scout-2608.23992 -->
- **Known Limitations**: Cached responses, pagination, method subsets, missing identities, altered timing, authorization-specific views, and purpose-label quality can change observability. <!-- SAF-TRACE: claims=SAF-T1605-C013,SAF-T1605-C016; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-inspector-2026 -->
- **Tuning Guidance**: Baseline by client and role, govern approved-purpose labels, and adjust breadth or timing only after measuring normal inventory and bootstrap behavior. <!-- SAF-TRACE: claims=SAF-T1605-C007,SAF-T1605-C013; sources=SRC-arxiv-scout-2608.23992,SRC-mcp-inspector-2026 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: All ten deterministic cases pass, covering positive, negative, exact-window, out-of-window, split-identity, split-server, suppression, malformed, pagination, and expected-false-positive behavior. <!-- SAF-TRACE: claims=SAF-T1605-C012,SAF-T1605-C013,SAF-T1605-C016; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-inspector-2026,SRC-mcp-tools-2026-07-28 -->
- **Last Validated**: 2026-09-02. [Recorded detector output](../../research/techniques/SAF-T1605/validation/detection-tests.txt) [Strict validation](../../research/techniques/SAF-T1605/validation/strict-validator.txt) <!-- SAF-TRACE: claims=SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28 -->
- **Feasibility Waiver**: None; the analytic was validated against isolated synthetic events. <!-- SAF-TRACE: claims=SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28 -->

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Require authentication for protected HTTP requests, apply **[SAF-M-13: OAuth Flow Verification](../../mitigations/SAF-M-13/README.md)** to validate token audience, and return only capability entries authorized for that requester. <!-- SAF-TRACE: claims=SAF-T1605-C014; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-mcp-prompts-2026 -->
2. **[SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md)**: Partition catalogs and start with minimal discovery/read scopes, adding narrowly required scope through controlled elevation. <!-- SAF-TRACE: claims=SAF-T1605-C014; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->
3. **Enforce the same policy at use time**: Do not treat list filtering as the authorization boundary for later calls or reads; retain explicit privilege checks at invocation and retrieval. <!-- SAF-TRACE: claims=SAF-T1605-C014,SAF-T1605-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-ghsa-cr22-wjx7-2w6m -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Correlate server discovery and breadth of list methods by requester and server. <!-- SAF-TRACE: claims=SAF-T1605-C012; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-arxiv-scout-2608.23992 -->
2. **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20/README.md)**: Compare alerts with approved inventory, client bootstrap, troubleshooting, and role-specific norms. <!-- SAF-TRACE: claims=SAF-T1605-C013; sources=SRC-mcp-inspector-2026,SRC-arxiv-scout-2608.23992 -->

### Response Procedures

#### Immediate Actions

- Validate the requester identity, authorization context, purpose label, and server scope before containing the session. <!-- SAF-TRACE: claims=SAF-T1605-C012,SAF-T1605-C013,SAF-T1605-C014; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-inspector-2026,SRC-arxiv-scout-2608.23992 -->
- If access is unauthorized or unexplained, apply **[SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37/README.md)** to the relevant token or session and temporarily restrict the exposed catalog. <!-- SAF-TRACE: claims=SAF-T1605-C014; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2026-07-28 -->

#### Investigation Steps

- Preserve discovery, list, authorization, pagination, cache, and subsequent request records for the same identity and server. <!-- SAF-TRACE: claims=SAF-T1605-C012,SAF-T1605-C016; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-arxiv-scout-2608.23992 -->
- Determine whether later calls, reads, or cross-session task access occurred; classify those acts separately from mapping. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C011,SAF-T1605-C017; sources=SRC-mcp-tools-2026-07-28,SRC-ghsa-python-hvrp,SRC-ghsa-cr22-wjx7-2w6m -->

#### Remediation

- Narrow scopes and list filters, align call/read authorization with discovery policy, and remove unauthenticated exposure. <!-- SAF-TRACE: claims=SAF-T1605-C009,SAF-T1605-C010,SAF-T1605-C014,SAF-T1605-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-typescript-w48q,SRC-ghsa-cr22-wjx7-2w6m -->
- Revalidate the analytic with local client baselines and add regression cases for the observed request path. <!-- SAF-TRACE: claims=SAF-T1605-C012,SAF-T1605-C013; sources=SRC-arxiv-scout-2608.23992,SRC-mcp-inspector-2026 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1104: Over-Privileged Tool Abuse](../SAF-T1104/README.md) | Follow-On | Begins when a mapped tool is invoked with excessive authority; Capability Mapping ends at correlated metadata. <!-- SAF-TRACE: claims=SAF-T1605-C005; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026 --> |
| [SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md) | Overlapping surface | Alters or poisons metadata; Capability Mapping reads the advertised surface without changing it. <!-- SAF-TRACE: claims=SAF-T1605-C005,SAF-T1605-C006; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 --> |
| [SAF-T1601: MCP Server Enumeration](../SAF-T1601/README.md) | Broader prerequisite | Inventories configured or reachable servers and protocol identity; Capability Mapping aggregates functional surfaces of a selected server. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-architecture-2026-07-28 --> |
| [SAF-T1602: Tool Enumeration](../SAF-T1602/README.md) | Component behavior | Covers tools/list and returned tool definitions; Capability Mapping correlates multiple discovery and listing surfaces. <!-- SAF-TRACE: claims=SAF-T1605-C001,SAF-T1605-C002,SAF-T1605-C005; sources=SRC-mcp-discovery-2026-07-28,SRC-mcp-tools-2026-07-28 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1518](https://attack.mitre.org/techniques/T1518/) | Software Discovery | Analogous | Both inventory technical functionality to inform follow-on behavior, but T1518 covers installed software while this technique covers advertised MCP primitives. <!-- SAF-TRACE: claims=SAF-T1605-C015; sources=SRC-attack-t1518,SRC-mcp-discovery-2026-07-28 --> |

## References

1. **SRC-mcp-architecture-2026-07-28**: [MCP 2026-07-28 Architecture](https://modelcontextprotocol.io/specification/2026-07-28/architecture) — host, client, server, and capability-negotiation model.
2. **SRC-mcp-discovery-2026-07-28**: [MCP 2026-07-28 Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) — discovery request, response, uses, and self-reported identity limit.
3. **SRC-mcp-tools-2026-07-28**: [MCP 2026-07-28 Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — authorization-scoped listing, metadata, pagination, caching, and security.
4. **SRC-mcp-resources-2026**: [MCP 2026-07-28 Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources) — resource and template discovery.
5. **SRC-mcp-prompts-2026**: [MCP 2026-07-28 Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts) — prompt discovery and user-control model.
6. **SRC-mcp-2026-roots**: [MCP 2026-07-28 Roots](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) — deprecated, informational root exposure.
7. **SRC-mcp-authorization-2026-07-28**: [MCP 2026-07-28 Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — per-request tokens, audience, scope, and errors.
8. **SRC-mcp-security-2026-07-28**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) — scope minimization and correlation logging.
9. **SRC-mcp-inspector-2026**: [MCP Inspector](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector) — legitimate client and tool-listing demonstration.
10. **SRC-attack-t1518**: [MITRE ATT&CK T1518 Software Discovery](https://attack.mitre.org/techniques/T1518/) — analogous discovery behavior.
11. **SRC-arxiv-scout-2608.23992**: [Saha, Wang, and Manoharan, “Hybrid Semantic Tool Discovery for Enterprise MCP Gateway,” 2026](https://arxiv.org/abs/2608.23992) — legitimate production scale, filtering, and observability.
12. **SRC-nvd-mcp-keyword-20260902**: [NVD MCP keyword corpus](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol&resultsPerPage=2000) — bounded 77-record vulnerability screening.
13. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — bounded known-exploitation screening.
14. **SRC-ghsa-cr22-wjx7-2w6m** and **SRC-nvd-cve-2026-46519**: [Originating advisory](https://github.com/Flux159/mcp-server-kubernetes/security/advisories/GHSA-cr22-wjx7-2w6m) and [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-46519) — list/call authorization divergence.
15. **SRC-ghsa-mcp-pinot-73cv** and **SRC-nvd-cve-2026-49257**: [Originating advisory](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6) and [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-49257) — insecure unauthenticated server exposure.
16. **SRC-ghsa-typescript-w48q** and **SRC-nvd-cve-2025-66414**: [Originating advisory](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w) and [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2025-66414) — DNS-rebinding reachability.
17. **SRC-ghsa-python-hvrp** and **SRC-nvd-cve-2026-52870**: [Originating advisory](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-hvrp-rf83-w775) and [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-52870) — adjacent task-state enumeration.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Independent clean-room research draft with tested detection and bounded evidence gap. | SAF-MCP Research Team (OpenAI Codex) |
