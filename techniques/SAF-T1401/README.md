# SAF-T1401: Line Jumping

## Overview

- **Tactic**: Defense Evasion (ATK-TA0005)
- **Technique ID**: SAF-T1401
- **Research Packet**: [research/techniques/SAF-T1401](../../research/techniques/SAF-T1401/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1401/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Successful precedence manipulation can redirect trusted selection and produce high integrity impact, with high confidentiality impact when the selected object can reach sensitive context or capabilities. <!-- SAF-TRACE: claims=SAF-T1401-C010; sources=SRC-nvd-cve-2026-79745,SRC-nvd-api-cve-2026-30856,SRC-ghsa-weknora -->
- **First Observed**: No qualifying production incident was identified in the reviewed authoritative corpus as of 2026-09-01; public evidence consists of controlled vulnerability demonstrations. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C006; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-01

## Scope

Line Jumping covers an attacker causing an MCP tool, prompt, or resource under attacker influence to win a host, proxy, or registry resolution decision ahead of a trusted competing object. The crossed boundary is the provenance and authorization boundary between multiple MCP sources or stores and the resolver that aggregates, ranks, and selects their objects. <!-- SAF-TRACE: claims=SAF-T1401-C001,SAF-T1401-C003,SAF-T1401-C009; sources=SRC-mcp-tools-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->

### In Scope

- Name, URI, normalization, store-order, or ranking-precedence manipulation that makes an attacker-controlled MCP object resolve before a trusted competitor. <!-- SAF-TRACE: claims=SAF-T1401-C001,SAF-T1401-C002,SAF-T1401-C003; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026-07-28,SRC-ghsa-weknora -->
- Unauthorized creation or mutation of a shared higher-precedence prompt or resource and collision-based tool overwrite in an aggregation layer are included. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C004,SAF-T1401-C005; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
- Abuse of priority or recency hints is a research-derived variant only when a host treats untrusted metadata as a controlling rank input. <!-- SAF-TRACE: claims=SAF-T1401-C002,SAF-T1401-C017; sources=SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 -->

### Out of Scope

- Semantic prompt or descriptor injection without an identity or precedence win is outside this technique. <!-- SAF-TRACE: claims=SAF-T1401-C016; sources=SRC-jamshidi-2026-arxiv-2512-06556,SRC-etdi-2506.01333 -->
- Mutation of the same already selected object without displacing a competitor is a separate boundary. <!-- SAF-TRACE: claims=SAF-T1401-C003; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
- Session hijacking or server sandbox escape is not Line Jumping unless a separate act manipulates resolver precedence. <!-- SAF-TRACE: claims=SAF-T1401-C007,SAF-T1401-C008; sources=SRC-jfrog-jfsa-2026-001653030,SRC-nvd-cve-2026-25905,SRC-jfsa-2025-001494691 -->
- Downstream collection, execution, exfiltration, or disruption is consequence, not the immediate objective. <!-- SAF-TRACE: claims=SAF-T1401-C010; sources=SRC-nvd-cve-2026-79745,SRC-nvd-api-cve-2026-30856,SRC-ghsa-weknora -->

### Distinguishing Characteristics

The distinguishing observable is a competing-object decision: preserve both candidates, their canonical source provenance, and the reason one won. Semantic manipulation changes content without requiring this decision, while post-approval mutation changes one object's definition after selection. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C014; sources=SRC-mcp-client-best-practices-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-ghsa-weknora -->

## Description

MCP requires a tool name to be unique within one server, but aggregators can encounter collisions across servers and should disambiguate them; `serverInfo.name` is not guaranteed unique. MCP resources instead use URIs as identifiers. These rules make source provenance part of a safe host-side resolution decision. <!-- SAF-TRACE: claims=SAF-T1401-C001,SAF-T1401-C002; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026-07-28 -->

An adversary line-jumps by influencing registration, mutation, normalization, store order, or a controlling rank hint so its object is reviewed or invoked where a trusted competitor was expected. The vulnerability is not the duplicate alone; it is acceptance of a competing identity or precedence without adequate disambiguation, provenance, or authorization. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C009,SAF-T1401-C014; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->

Two public product advisories demonstrate the complete behavior through different resolver failures. MCPHub served a mutable global built-in object before connected-server alternatives, while WeKnora used an ambiguous normalized name and order-dependent overwrite. Priority or recency abuse remains an inferred variant, not a demonstrated exploit path. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C004,SAF-T1401-C005,SAF-T1401-C017; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-nvd-cve-2026-79745,SRC-ghsa-weknora,SRC-nvd-api-cve-2026-30856,SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 -->

## Attack Vectors

- **Primary Vector**: Register or mutate an attacker-controlled MCP object so a colliding or higher-precedence identity wins aggregation or lookup. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C004,SAF-T1401-C005; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
- **Secondary Vectors**: Ambiguous normalization and last-write-wins tool registration; unauthorized mutation of a global built-in prompt or resource; and, as a research-derived variant, host reliance on untrusted ranking hints. <!-- SAF-TRACE: claims=SAF-T1401-C004,SAF-T1401-C005,SAF-T1401-C017; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- **Affected Components**: MCP hosts, clients, hubs, proxies, registries, tool catalogs, prompt stores, resource stores, and resolver metadata. <!-- SAF-TRACE: claims=SAF-T1401-C001,SAF-T1401-C002,SAF-T1401-C003; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
- **Trust Boundary Crossed**: The provenance and authorization boundary between server- or store-supplied objects and the host resolver that chooses a winner. <!-- SAF-TRACE: claims=SAF-T1401-C009; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->

## Technical Details

### Prerequisites

- The adversary can influence object registration, global mutation, or resolver-consumed metadata. <!-- SAF-TRACE: claims=SAF-T1401-C009; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
- A trusted object competes under a colliding canonical identity or lower-precedence store or rank. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C009; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
- The resolver fails to reject, explicitly disambiguate, or require sufficient authorization for the precedence-changing action. <!-- SAF-TRACE: claims=SAF-T1401-C009,SAF-T1401-C014,SAF-T1401-C015; sources=SRC-mcp-tools-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->

### Attack Flow

1. **Setup**: The adversary identifies a trusted logical object name or URI and a source, store, or mutation path it can influence. <!-- SAF-TRACE: claims=SAF-T1401-C009; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
2. **Delivery**: The adversary registers a colliding object, overwrites a higher-precedence shared object, or supplies controlling rank metadata. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C017; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 -->
3. **Trigger**: A catalog refresh, lookup, prompt/resource retrieval, or tool call asks the resolver to choose among candidates. <!-- SAF-TRACE: claims=SAF-T1401-C004,SAF-T1401-C005,SAF-T1401-C011; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-client-best-practices-2026-07-28 -->
4. **Boundary Crossing**: Ambiguous normalization, store-first lookup, silent overwrite, or trusted rank metadata makes the attacker-controlled object win. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C004,SAF-T1401-C005,SAF-T1401-C017; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 -->
5. **Objective**: Review and selection operate on the wrong object while the user or caller expects the trusted competitor. <!-- SAF-TRACE: claims=SAF-T1401-C003; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
6. **Follow-On Activity**: Consequences depend on the selected object's reachable context and authorized capabilities. <!-- SAF-TRACE: claims=SAF-T1401-C010; sources=SRC-nvd-cve-2026-79745,SRC-nvd-api-cve-2026-30856,SRC-ghsa-weknora -->

### Example Scenario

An inert host connects `trusted.example` and `lab.example`. Both register a logical `summarize` tool, but the resolver silently selects the later untrusted registration. The resolver log records the collision, both canonical sources, the untrusted winner, and no disambiguation; no command or sensitive data is included. <!-- SAF-TRACE: claims=SAF-T1401-C005,SAF-T1401-C011,SAF-T1401-C012; sources=SRC-ghsa-weknora,SRC-mcp-client-best-practices-2026-07-28,SRC-mcp-tools-2026-07-28 -->

The minimum safe event illustrates only the precedence decision. <!-- SAF-TRACE: claims=SAF-T1401-C012; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->

```json
{
  "action": "resolve",
  "object": {"type": "tool", "logical_id": "summarize"},
  "collision": true,
  "disambiguated": false,
  "winner": {"source": "lab.example", "trust": "untrusted"},
  "competitor": {"source": "trusted.example", "trust": "trusted"},
  "outcome": "success",
  "change": {"approved": false}
}
```

### Variants

| Variant | Mechanism | Distinguishing Observables |
| --- | --- | --- |
| Name or normalization collision | Multiple external identities collapse to one internal name and registration order controls the winner. <!-- SAF-TRACE: claims=SAF-T1401-C005; sources=SRC-ghsa-weknora,SRC-nvd-api-cve-2026-30856 --> | Both canonical source identities, normalized identity, collision flag, registration order, and overwritten entry. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C012; sources=SRC-mcp-client-best-practices-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-ghsa-weknora --> |
| Higher-precedence shared store | An unauthorized shared object is consulted before connected-server objects. <!-- SAF-TRACE: claims=SAF-T1401-C004; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-nvd-cve-2026-79745 --> | Mutation actor and role, global scope, object identity, store, authorization result, and subsequent winner. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C012; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-mcp-tools-2026-07-28 --> |
| Ranking-hint precedence | A host treats untrusted priority or recency as controlling inclusion or order. <!-- SAF-TRACE: claims=SAF-T1401-C017; sources=SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 --> | Supplied rank fields, trusted policy rank, source provenance, and explicit reason for selection; no directly qualifying public exploit was found. <!-- SAF-TRACE: claims=SAF-T1401-C017; sources=SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 --> |

## Evidence and Current State

### Evidence Summary

| Claim ID | Summary | Evidence Status | Source IDs | Limitation |
| --- | --- | --- | --- | --- |
| SAF-T1401-C001 | Tool identity and collision scope | Research-Derived | SRC-mcp-tools-2026-07-28 | No mandated cross-server algorithm |
| SAF-T1401-C002 | Resource identity and ranking annotations | Research-Derived | SRC-mcp-resources-2026-07-28 | Host policy is application-defined |
| SAF-T1401-C003 | Competing object wins precedence in two controlled products | Demonstrated | SRC-ghsa-6cvf-cfch-4g7m; SRC-ghsa-weknora | Not a production incident |
| SAF-T1401-C004 | MCPHub built-in-first global shadowing | Demonstrated | SRC-ghsa-6cvf-cfch-4g7m; SRC-nvd-cve-2026-79745 | No documented production exploitation |
| SAF-T1401-C005 | WeKnora normalized-name overwrite | Demonstrated | SRC-ghsa-weknora; SRC-nvd-api-cve-2026-30856 | Configuration prerequisites apply |
| SAF-T1401-C006 | Bounded production-incident gap | Research-Derived | SRC-cisa-kev-2026-09-01; SRC-nvd-api-cve-2026-30856; SRC-ghsa-6cvf-cfch-4g7m | Corpus-bounded absence inference |
| SAF-T1401-C007 | Sandbox escape as enabling evidence | Demonstrated | SRC-jfrog-jfsa-2026-001653030; SRC-nvd-cve-2026-25905 | Not the defining root mechanism |
| SAF-T1401-C008 | Session hijack as adjacent evidence | Research-Derived | SRC-jfsa-2025-001494691 | No precedence decision |
| SAF-T1401-C009 | Access and resolver prerequisites | Research-Derived | SRC-ghsa-6cvf-cfch-4g7m; SRC-ghsa-weknora; SRC-mcp-tools-2026-07-28 | Product-specific access varies |
| SAF-T1401-C010 | Conditional confidentiality, integrity, and availability effects | Research-Derived | SRC-nvd-cve-2026-79745; SRC-nvd-api-cve-2026-30856; SRC-ghsa-weknora | Consequences depend on reach |
| SAF-T1401-C011 | Required resolver telemetry | Research-Derived | SRC-mcp-client-best-practices-2026-07-28; SRC-mcp-tools-2026-07-28 | No universal audit schema |
| SAF-T1401-C012 | Three-branch behavioral analytic | Research-Derived | SRC-ghsa-6cvf-cfch-4g7m; SRC-ghsa-weknora; SRC-mcp-tools-2026-07-28 | Requires provenance logs |
| SAF-T1401-C013 | False positives and tuning | Research-Derived | SRC-jamshidi-2026-arxiv-2512-06556; SRC-etdi-2506.01333 | Synthetic extrapolation |
| SAF-T1401-C014 | Provenance-preserving disambiguation | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-ghsa-weknora | Protocol language is SHOULD |
| SAF-T1401-C015 | Mutation authorization and call approval | Research-Derived | SRC-ghsa-6cvf-cfch-4g7m; SRC-mcp-tools-2026-07-28; SRC-mcp-client-best-practices-2026-07-28 | Policy is application-specific |
| SAF-T1401-C016 | Definition-integrity controls and tradeoffs | Demonstrated | SRC-etdi-2506.01333; SRC-jamshidi-2026-arxiv-2512-06556 | Proposed or controlled, not universally proven |
| SAF-T1401-C017 | Priority and recency variant | Research-Derived | SRC-mcp-resources-2026-07-28; SRC-mcp-tools-2026-07-28 | No direct public exploit found |
| SAF-T1401-C018 | ATT&CK lookup-hijack analogy | Research-Derived | SRC-mitre-t1574-v2 | ATT&CK mechanism is OS-focused |
| SAF-T1401-C019 | Bounded response sequence | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-ghsa-6cvf-cfch-4g7m; SRC-ghsa-weknora | Credential rotation is conditional |

### Current State

- **Affected Environments**: Multi-server MCP hosts, hubs, clients, and registries that collapse identities, silently overwrite collisions, consult mutable shared stores first, or trust server-supplied rank metadata. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C004,SAF-T1401-C005,SAF-T1401-C017; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- **Known Exploitation**: Public controlled reproductions exist for two direct vulnerabilities, but the reviewed corpus does not establish a qualifying production incident. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C006; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-cisa-kev-2026-09-01,SRC-nvd-api-cve-2026-30856 -->
- **Available Protections**: MCPHub 1.0.32 and WeKnora 0.3.0 patch the selected product issues; source disambiguation, mutation authorization, per-call approval, auditing, and definition integrity address broader classes. <!-- SAF-TRACE: claims=SAF-T1401-C004,SAF-T1401-C005,SAF-T1401-C014,SAF-T1401-C015,SAF-T1401-C016; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28,SRC-mcp-client-best-practices-2026-07-28,SRC-etdi-2506.01333,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Residual Risk**: Unpatched products, custom normalization, incomplete provenance, and application-defined ranking can preserve precedence paths even when user approval exists for later calls. <!-- SAF-TRACE: claims=SAF-T1401-C009,SAF-T1401-C014,SAF-T1401-C015,SAF-T1401-C017; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28,SRC-mcp-client-best-practices-2026-07-28,SRC-mcp-resources-2026-07-28 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-79745 / GHSA-6cvf-cfch-4g7m <!-- SAF-TRACE: claims=SAF-T1401-C004; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-nvd-cve-2026-79745 --> | Published 2026-08-23; MCPHub through 1.0.31 <!-- SAF-TRACE: claims=SAF-T1401-C004; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-nvd-cve-2026-79745 --> | Non-admin global prompt/resource tampering and cross-session shadowing; fixed in 1.0.32 <!-- SAF-TRACE: claims=SAF-T1401-C004,SAF-T1401-C010; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-nvd-cve-2026-79745 --> | Direct vulnerability and controlled demonstration <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C004; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-nvd-cve-2026-79745 --> | No documented production exploitation <!-- SAF-TRACE: claims=SAF-T1401-C004,SAF-T1401-C006; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-cisa-kev-2026-09-01 --> |
| CVE-2026-30856 / GHSA-67q9-58vj-32qx <!-- SAF-TRACE: claims=SAF-T1401-C005; sources=SRC-ghsa-weknora,SRC-nvd-api-cve-2026-30856 --> | Published 2026-03-06; WeKnora through 0.2.14 <!-- SAF-TRACE: claims=SAF-T1401-C005; sources=SRC-ghsa-weknora,SRC-nvd-api-cve-2026-30856 --> | Redirected tool execution with conditional context or capability exposure; fixed in 0.3.0 <!-- SAF-TRACE: claims=SAF-T1401-C005,SAF-T1401-C010; sources=SRC-ghsa-weknora,SRC-nvd-api-cve-2026-30856 --> | Direct vulnerability and controlled proof of concept <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C005; sources=SRC-ghsa-weknora,SRC-nvd-api-cve-2026-30856 --> | Requires malicious-server configuration; SSVC records PoC, not active exploitation <!-- SAF-TRACE: claims=SAF-T1401-C005,SAF-T1401-C006; sources=SRC-ghsa-weknora,SRC-nvd-api-cve-2026-30856 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A selected malicious object can expose sensitive context when its call path can receive that context; reach and permissions constrain the result. <!-- SAF-TRACE: claims=SAF-T1401-C010; sources=SRC-nvd-api-cve-2026-30856,SRC-ghsa-weknora --> |
| Integrity | High | The technique changes which prompt, resource, or tool the host serves or invokes while preserving the caller's expectation of the trusted object. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C010; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-nvd-cve-2026-79745,SRC-ghsa-weknora --> |
| Availability | Low | Availability effects are bounded and conditional on the winning object's behavior and the resolver's recovery path. <!-- SAF-TRACE: claims=SAF-T1401-C010; sources=SRC-nvd-cve-2026-79745,SRC-nvd-api-cve-2026-30856 --> |
| Scope | Multi-System | A shared hub or global store can affect multiple sessions or connected sources, while source isolation and scoped authorization limit blast radius. <!-- SAF-TRACE: claims=SAF-T1401-C004,SAF-T1401-C010,SAF-T1401-C015; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-nvd-cve-2026-79745,SRC-mcp-client-best-practices-2026-07-28 --> |

### Severity Conditions

- **Severity increases when** a mutable global store, automated calls, sensitive context, broad tool permissions, ambiguous normalization, or incomplete provenance makes the untrusted winner widely reachable. <!-- SAF-TRACE: claims=SAF-T1401-C009,SAF-T1401-C010; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-nvd-cve-2026-79745,SRC-nvd-api-cve-2026-30856 -->
- **Severity decreases when** collision-resistant source identities, scoped mutation authorization, per-call approval, source grouping, and integrity verification constrain selection or downstream reach. <!-- SAF-TRACE: claims=SAF-T1401-C014,SAF-T1401-C015,SAF-T1401-C016; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-client-best-practices-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-etdi-2506.01333,SRC-jamshidi-2026-arxiv-2512-06556 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP registry or host audit | Object register and mutate events | Timestamp, actor and role, scope, object type, logical and normalized identity, canonical source, collision, approval, outcome, and definition hash | Retain changes across catalog refreshes and sessions. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C012; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-client-best-practices-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora --> |
| MCP resolver decision log | Candidate comparison and winner selection | Request or session, winner source and trust, competing source and trust, disambiguation state, precedence reason, approval, and outcome | Preserve canonical provenance rather than only the normalized winner name. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C012,SAF-T1401-C014; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-client-best-practices-2026-07-28,SRC-ghsa-weknora --> |

### Indicators of Compromise

- No universal durable IoC is known; identities and sources are deployment-specific, so collision and resolver-decision behavior is more reliable than a static value. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C012; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-client-best-practices-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->

### Behavioral Indicators

- A successful registration retains a collision while reporting no disambiguation. <!-- SAF-TRACE: claims=SAF-T1401-C012; sources=SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->
- A non-admin actor successfully mutates an object in a global store. <!-- SAF-TRACE: claims=SAF-T1401-C012,SAF-T1401-C015; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-mcp-tools-2026-07-28 -->
- A resolver chooses an untrusted source over a trusted competitor for the same logical object, absent an approved change. <!-- SAF-TRACE: claims=SAF-T1401-C012; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->

### Detection Analytic

The standalone source-aware behavioral analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect successful unresolved collisions, unauthorized global mutations, and untrusted winners that displace trusted competitors. <!-- SAF-TRACE: claims=SAF-T1401-C012; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C013; sources=SRC-mcp-client-best-practices-2026-07-28,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Detection Logic**: Alert on any of the three suspicious selections, then suppress events tied to an explicitly approved change. <!-- SAF-TRACE: claims=SAF-T1401-C012,SAF-T1401-C013; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-jamshidi-2026-arxiv-2512-06556,SRC-etdi-2506.01333 -->
- **Correlation Window**: One resolver or mutation event; implementations should retain linked lifecycle events across catalog refreshes. <!-- SAF-TRACE: claims=SAF-T1401-C011; sources=SRC-mcp-client-best-practices-2026-07-28,SRC-mcp-tools-2026-07-28 -->
- **Known False Positives**: Planned migration, authorized aliases, and test registrations can resemble a collision. <!-- SAF-TRACE: claims=SAF-T1401-C013; sources=SRC-jamshidi-2026-arxiv-2512-06556,SRC-etdi-2506.01333 -->
- **Known Limitations**: Hosts that omit candidate provenance, actor role, mutation scope, trust, or resolver reasons cannot evaluate every branch. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C012; sources=SRC-mcp-client-best-practices-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->
- **Tuning Guidance**: Require recorded approval, actor role, scope, and canonical source provenance; do not allowlist on object name alone. <!-- SAF-TRACE: claims=SAF-T1401-C013,SAF-T1401-C014; sources=SRC-jamshidi-2026-arxiv-2512-06556,SRC-etdi-2506.01333,SRC-mcp-tools-2026-07-28,SRC-ghsa-weknora -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1401/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1401/test_detection_rule.py)
- **Expected Result**: Three positive, four negative or boundary, one malformed, and one expected-false-positive fixture behave as declared. <!-- SAF-TRACE: claims=SAF-T1401-C012,SAF-T1401-C013; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-jamshidi-2026-arxiv-2512-06556,SRC-etdi-2506.01333 -->
- **Last Validated**: 2026-09-01 using the bundled executable test. <!-- SAF-TRACE: claims=SAF-T1401-C012; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->
- **Feasibility Waiver**: None; representative synthetic validation is included. <!-- SAF-TRACE: claims=SAF-T1401-C012; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->

## Mitigation Strategies

### Preventive Controls

1. Preserve canonical server provenance and fail closed or explicitly disambiguate collisions; do not rely on non-unique server names or silent overwrite. <!-- SAF-TRACE: claims=SAF-T1401-C014; sources=SRC-mcp-tools-2026-07-28,SRC-ghsa-weknora -->
2. Require appropriate authorization for global object creation and mutation, and retain human review, per-call approval, input display, and audit logging for sensitive tool calls. <!-- SAF-TRACE: claims=SAF-T1401-C015; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-mcp-tools-2026-07-28,SRC-mcp-client-best-practices-2026-07-28 -->
3. Bind trusted definitions to version and integrity evidence, then validate before the object enters model context; plan for key management, latency, and false-positive costs. <!-- SAF-TRACE: claims=SAF-T1401-C016; sources=SRC-etdi-2506.01333,SRC-jamshidi-2026-arxiv-2512-06556 -->
4. Treat server-supplied rank and annotation metadata as untrusted and apply host-controlled policy before it can affect inclusion or order. <!-- SAF-TRACE: claims=SAF-T1401-C017; sources=SRC-mcp-resources-2026-07-28,SRC-mcp-tools-2026-07-28 -->

### Detective Controls

1. Log catalog lifecycle and resolution decisions with both winner and competitor provenance, not only the final normalized identity. <!-- SAF-TRACE: claims=SAF-T1401-C011,SAF-T1401-C014; sources=SRC-mcp-client-best-practices-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-ghsa-weknora -->
2. Alert on unauthorized global mutation, unresolved collision, and untrusted-over-trusted selection, while retaining approval evidence for tuning. <!-- SAF-TRACE: claims=SAF-T1401-C012,SAF-T1401-C013; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-jamshidi-2026-arxiv-2512-06556,SRC-etdi-2506.01333 -->

### Response Procedures

#### Immediate Actions

- Preserve resolver and registry evidence, disable the attacker-controlled source or mutation path, and restore a verified trusted mapping. <!-- SAF-TRACE: claims=SAF-T1401-C019; sources=SRC-mcp-tools-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->

#### Investigation Steps

- Determine when the mapping changed, which sessions or requests selected it, which downstream calls occurred, and whether sensitive context or capabilities were reached. <!-- SAF-TRACE: claims=SAF-T1401-C019; sources=SRC-mcp-tools-2026-07-28,SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora -->

#### Remediation

- Patch affected products, remove ambiguous or unauthorized mappings, add collision and authorization regression tests, and rotate credentials only when follow-on exposure or access is established. <!-- SAF-TRACE: claims=SAF-T1401-C004,SAF-T1401-C005,SAF-T1401-C019; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->

## Related Techniques

The nearest boundaries distinguish semantic descriptor manipulation and post-approval mutation from an attacker-controlled object winning a competing identity or rank decision. <!-- SAF-TRACE: claims=SAF-T1401-C003,SAF-T1401-C014; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora,SRC-mcp-tools-2026-07-28 -->

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1001: Tool Poisoning Attack (TPA)](../SAF-T1001/README.md) | Overlapping semantic boundary | Changes descriptor semantics without requiring an attacker-controlled object to win a competing identity or rank decision. <!-- SAF-TRACE: claims=SAF-T1401-C016; sources=SRC-jamshidi-2026-arxiv-2512-06556,SRC-etdi-2506.01333 --> |
| [SAF-T1205: Persistent Tool Redefinition](../SAF-T1205/README.md) | Overlapping temporal boundary | Changes the same selected object after approval rather than displacing a trusted competitor through precedence. <!-- SAF-TRACE: claims=SAF-T1401-C003; sources=SRC-ghsa-6cvf-cfch-4g7m,SRC-ghsa-weknora --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1574](https://attack.mitre.org/techniques/T1574/) | Hijack Execution Flow | Analogous | ATT&CK includes search-order and lookup-location poisoning that redirects execution, but its mechanisms and platforms are operating-system focused rather than MCP object resolution. <!-- SAF-TRACE: claims=SAF-T1401-C018; sources=SRC-mitre-t1574-v2 --> |

## References

1. **SRC-mcp-tools-2026-07-28**: [MCP Specification — Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools.md), Model Context Protocol Working Group, 2026-07-28.
2. **SRC-mcp-resources-2026-07-28**: [MCP Specification — Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources.md), Model Context Protocol Working Group, 2026-07-28.
3. **SRC-mcp-client-best-practices-2026-07-28**: [MCP Client Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices.md), Model Context Protocol Documentation Team, 2026-07-28.
4. **SRC-ghsa-6cvf-cfch-4g7m**: [Missing Authorization on Built-in Prompt and Resource CRUD](https://github.com/samanhappy/mcphub/security/advisories/GHSA-6cvf-cfch-4g7m), reported by waydeshi; samanhappy/mcphub maintainers, 2026-08-23.
5. **SRC-nvd-cve-2026-79745**: [CVE-2026-79745 Detail](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-79745), NIST NVD Analysis Team and GitHub Security Advisories CNA, 2026-08-31.
6. **SRC-ghsa-weknora**: [Tool Execution Hijacking via Ambiguous Naming Convention](https://github.com/Tencent/WeKnora/security/advisories/GHSA-67q9-58vj-32qx), reported by aleister1102, published by lyingbug; Tencent/WeKnora maintainers, 2026-03-06.
7. **SRC-nvd-api-cve-2026-30856**: [CVE-2026-30856 Detail](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-30856), NIST NVD Analysis Team, GitHub Security Advisories CNA, and CISA, 2026-06-17.
8. **SRC-jfrog-jfsa-2026-001653030**: [mcp-run-python lack of isolation MCP takeover](https://research.jfrog.com/vulnerabilities/mcp-run-python-lack-of-isolation-mcp-takeover-jfsa-2026-001653030/), Natan Nehorai and JFrog Security Research Team, 2026-02-09.
9. **SRC-nvd-cve-2026-25905**: [CVE-2026-25905 Detail](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-25905), NIST NVD Analysis Team, JFrog CNA, and CISA, 2026-06-17.
10. **SRC-jfsa-2025-001494691**: [oatpp-mcp prompt hijacking](https://research.jfrog.com/vulnerabilities/oatpp-mcp-prompt-hijacking-jfsa-2025-001494691/), Ori Hollander and JFrog Security Research Team, 2025-10-20.
11. **SRC-cisa-kev-2026-09-01**: [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), CISA Vulnerability Management Team, catalog 2026.09.01.
12. **SRC-jamshidi-2026-arxiv-2512-06556**: [Semantic Attacks on Tool-Augmented LLMs](https://arxiv.org/abs/2512.06556v2), Saeid Jamshidi, Arghavan Moradi Dakhel, Kawser Wazed Nafi, and Foutse Khomh, 2026-05-21.
13. **SRC-etdi-2506.01333**: [ETDI — Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333v1), Manish Bhatt, Vineeth Sai Narajala, and Idan Habler, 2025-06-02.
14. **SRC-mitre-t1574-v2**: [MITRE ATT&CK T1574 — Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/), MITRE ATT&CK Team, version 2.0, 2026-05-12.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Initial clean-room draft, research packet, and tested analytic | /root/cleanroom_saf_t1401 |
