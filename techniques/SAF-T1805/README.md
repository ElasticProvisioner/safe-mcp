# SAF-T1805: Context Snapshot Capture

## Overview

- **Tactic**: Collection (ATK-TA0009)
- **Technique ID**: SAF-T1805
- **Research Packet**: [research/techniques/SAF-T1805](../../research/techniques/SAF-T1805/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1805/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: High applies when a successful read or export crosses users or tenants and returns sensitive active state; isolated, redacted, or low-sensitivity snapshots can have lower impact. <!-- SAF-TRACE: claims=SAF-T1805-C010; sources=SRC-cve-2026-56077, SRC-cve-2026-9130 -->
- **First Observed**: No qualifying production incident was identified; the earliest selected public direct demonstration was published on 2026-04-07. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C020; sources=SRC-ghsa-766v-q9x3-g744, SRC-nvd-search-corpus -->
- **Last Updated**: 2026-09-02

## Scope

Context Snapshot Capture is the unauthorized read, export, or serialization of point-in-time active agent execution state across the state owner's or tenant's authorization boundary. <!-- SAF-TRACE: claims=SAF-T1805-C003; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-langgraph-persistence, SRC-langsmith-observability -->

### In Scope

- Reading or exporting another principal's active conversation history, checkpoint, trace, or equivalent serialized agent state. <!-- SAF-TRACE: claims=SAF-T1805-C003; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130 -->
- Identifier collision, handle misuse, or absent ownership validation that causes a context service to return state from the wrong owner or tenant. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C006; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28 -->
- Snapshots whose classified contents include system instructions, conversation turns, tool results, contextual resources, checkpoint state, or trace inputs and outputs. <!-- SAF-TRACE: claims=SAF-T1805-C004, SAF-T1805-C006, SAF-T1805-C008, SAF-T1805-C009; sources=SRC-mcp-resources-2026, SRC-mcp-tools-2026-07-28, SRC-langgraph-persistence, SRC-langsmith-observability -->

### Out of Scope

- Changing context without obtaining a copy, extracting only a fixed instruction string, or inducing disclosure through adversarial instructions rather than directly reading stored state. <!-- SAF-TRACE: claims=SAF-T1805-C019; sources=SRC-mcp-resources-2026, SRC-msrc-cve-2025-32711 -->
- Enumerating long-lived memory independently of an active execution snapshot, or transferring already captured material outside the environment as follow-on exfiltration. <!-- SAF-TRACE: claims=SAF-T1805-C019; sources=SRC-langgraph-persistence -->

### Distinguishing Characteristics

The defining observable is a completed context-state read or export joined to a failed owner, tenant, authorization, or approval decision; the technique is not established by prompt content or generic data access alone. <!-- SAF-TRACE: claims=SAF-T1805-C003, SAF-T1805-C014, SAF-T1805-C019; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-nist-sp800-61r3 -->

## Description

Agent platforms materialize active execution state in several forms. MCP resources can provide contextual content, MCP tool results can embed resources, and sampling can request context inclusion, while non-MCP agent stacks can persist thread checkpoints and record full run inputs, outputs, and message trajectories in traces. <!-- SAF-TRACE: claims=SAF-T1805-C004, SAF-T1805-C005, SAF-T1805-C006, SAF-T1805-C008, SAF-T1805-C009; sources=SRC-mcp-resources-2026, SRC-mcp-sampling-2026, SRC-mcp-tools-2026-07-28, SRC-langgraph-persistence, SRC-langsmith-observability -->

Those capabilities are legitimate until a requester obtains state belonging to another owner or tenant. The boundary can fail when an attacker-controlled identifier selects shared state, when a state handle is not bound to the authenticated principal, or when an API checks a session key but not its owner. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C006; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28 -->

Public evidence demonstrates the defining mechanism in an agent library and independently documents a second cross-user chat-history vulnerability. Current government status records do not establish exploitation in production, so this technique is Demonstrated rather than Observed. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C011, SAF-T1805-C020; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-cve-2026-56077, SRC-cve-2026-9130, SRC-cisa-kev-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: Invoke a snapshot, history, checkpoint, trace, resource, or state read with a key or handle that resolves to another principal's active context. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C003, SAF-T1805-C006; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28 -->
- **Secondary Vectors**:
  - Register or supply a duplicate agent, session, thread, or state identifier that collides with an existing owner's state. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130 -->
  - Abuse a compromised authenticated principal or a legitimate export surface where owner and approval checks are incomplete. <!-- SAF-TRACE: claims=SAF-T1805-C002, SAF-T1805-C006, SAF-T1805-C015; sources=SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->
- **Affected Components**: MCP hosts and clients, resource and tool-result handlers, agent memory and history services, checkpointers, trace stores, and application authorization layers. <!-- SAF-TRACE: claims=SAF-T1805-C004, SAF-T1805-C006, SAF-T1805-C008, SAF-T1805-C009; sources=SRC-mcp-resources-2026, SRC-mcp-tools-2026-07-28, SRC-langgraph-persistence, SRC-langsmith-observability -->
- **Trust Boundary Crossed**: The requester-to-owner or requester-tenant-to-owner-tenant authorization boundary around active agent state. <!-- SAF-TRACE: claims=SAF-T1805-C003; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130 -->

## Technical Details

### Prerequisites

- The platform persists or can serialize active context as a history, ledger, checkpoint, trace, resource, tool result, or equivalent state object. <!-- SAF-TRACE: claims=SAF-T1805-C004, SAF-T1805-C006, SAF-T1805-C008, SAF-T1805-C009; sources=SRC-mcp-resources-2026, SRC-mcp-tools-2026-07-28, SRC-langgraph-persistence, SRC-langsmith-observability -->
- The adversary can reach a read or export path and control or obtain an identifier, handle, session key, or identity used to select the object. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C006; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28 -->
- The service fails to bind the selected object to the authenticated owner or tenant, or returns it despite a non-allow authorization result. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C006, SAF-T1805-C014; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28 -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies a reachable state-read surface and an attacker-controllable state selector. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C006; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28 -->
2. **Delivery**: The adversary submits an identifier, handle, session key, or authenticated request that selects active state. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130 -->
3. **Trigger or Execution**: The service performs a snapshot, history, checkpoint, trace, resource, or embedded-result read. <!-- SAF-TRACE: claims=SAF-T1805-C004, SAF-T1805-C006, SAF-T1805-C008, SAF-T1805-C009; sources=SRC-mcp-resources-2026, SRC-mcp-tools-2026-07-28, SRC-langgraph-persistence, SRC-langsmith-observability -->
4. **Boundary Crossing**: Ownership, tenant, authorization, or approval validation fails to constrain the selected state. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C006; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28 -->
5. **Objective**: The service returns a point-in-time copy containing one or more sensitive execution-state classes. <!-- SAF-TRACE: claims=SAF-T1805-C003, SAF-T1805-C009, SAF-T1805-C010; sources=SRC-ghsa-766v-q9x3-g744, SRC-langsmith-observability, SRC-cve-2026-56077, SRC-cve-2026-9130 -->
6. **Follow-On Activity**: Replay, forking, credential use, or exfiltration may follow, but none is required for this collection technique. <!-- SAF-TRACE: claims=SAF-T1805-C008, SAF-T1805-C019; sources=SRC-langgraph-time-travel, SRC-langgraph-persistence -->

### Example Scenario

An authenticated user in an invented multi-tenant agent service supplies a colliding thread selector to a history endpoint. The service returns classified metadata showing another tenant's conversation turns; no content values are included in this safe example. <!-- SAF-TRACE: claims=SAF-T1805-C002, SAF-T1805-C003; sources=SRC-ibm-cve-2026-9130, SRC-cve-2026-9130 -->

The resulting normalized audit record is suitable for local defensive testing and contains only inert identifiers. <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C014; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3, SRC-ibm-cve-2026-9130 -->

```json
{
  "event_id": "evt-example-safe",
  "event_type": "checkpoint_history_read",
  "result": "success",
  "actor_id": "user-red",
  "owner_id": "user-blue",
  "actor_tenant_id": "tenant-red",
  "owner_tenant_id": "tenant-blue",
  "authorization_decision": "unknown",
  "approval_status": "not_requested",
  "content_classes": ["conversation_turn"],
  "item_count": 2,
  "bytes": 128,
  "destination": "https://review.example.invalid/context"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1805-C001 | Duplicate agent identifiers can expose another agent's prompt and history through shared ledger state. | Demonstrated | SRC-ghsa-766v-q9x3-g744: [PraisonAI advisory](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-766v-q9x3-g744) | Public demonstration, not a production victim incident. | <!-- SAF-TRACE: claims=SAF-T1805-C001; sources=SRC-ghsa-766v-q9x3-g744 -->
| SAF-T1805-C002 | Affected Langflow multi-user versions allowed cross-user chat-history access through session-key ownership failure. | Demonstrated | SRC-ibm-cve-2026-9130 and SRC-cve-2026-9130: [IBM bulletin](https://www.ibm.com/support/pages/node/7282647) and [CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-9130) | Configuration-bound vulnerability; no production exploitation documented. | <!-- SAF-TRACE: claims=SAF-T1805-C002; sources=SRC-ibm-cve-2026-9130, SRC-cve-2026-9130 -->
| SAF-T1805-C003 | The technique boundary is unauthorized point-in-time active-context acquisition across owner or tenant authorization. | Research-Derived | SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-langgraph-persistence, SRC-langsmith-observability | SAF generalization rather than vendor terminology. | <!-- SAF-TRACE: claims=SAF-T1805-C003; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-langgraph-persistence, SRC-langsmith-observability -->
| SAF-T1805-C004 | MCP resources expose contextual data, support resource reads, and require access control. | Research-Derived | SRC-mcp-resources-2026: [MCP Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources) | Legitimate resource support is not evidence of attack. | <!-- SAF-TRACE: claims=SAF-T1805-C004; sources=SRC-mcp-resources-2026 -->
| SAF-T1805-C005 | Deprecated MCP sampling can request context inclusion, subject to client choice and non-retention guidance. | Research-Derived | SRC-mcp-sampling-2026: [MCP Sampling](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling) | Broad inclusion may be unavailable or ignored. | <!-- SAF-TRACE: claims=SAF-T1805-C005; sources=SRC-mcp-sampling-2026 -->
| SAF-T1805-C006 | MCP tool results can embed resources, while state handles need per-call authorization and owner binding. | Research-Derived | SRC-mcp-tools-2026-07-28 and SRC-mcp-security-spec-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) and [security guidance](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices) | Generic guidance, not a claim about selected product implementations. | <!-- SAF-TRACE: claims=SAF-T1805-C006; sources=SRC-mcp-tools-2026-07-28, SRC-mcp-security-spec-2026-07-28 -->
| SAF-T1805-C007 | MCP security principles require explicit consent and control around user-data exposure and transmission. | Research-Derived | SRC-mcp-overview-2026: [MCP Specification](https://modelcontextprotocol.io/specification/2026-07-28) | Implementations choose concrete enforcement mechanisms. | <!-- SAF-TRACE: claims=SAF-T1805-C007; sources=SRC-mcp-overview-2026 -->
| SAF-T1805-C008 | LangGraph persists thread snapshots and exposes checkpoint history for replay and forking. | Research-Derived | SRC-langgraph-persistence and SRC-langgraph-time-travel: [Persistence](https://docs.langchain.com/oss/python/langgraph/persistence) and [time-travel](https://docs.langchain.com/oss/python/langgraph/use-time-travel) | Legitimate feature; replay can execute downstream work again. | <!-- SAF-TRACE: claims=SAF-T1805-C008; sources=SRC-langgraph-persistence, SRC-langgraph-time-travel -->
| SAF-T1805-C009 | LangSmith traces and trajectories can contain full inputs, outputs, and multi-turn messages. | Research-Derived | SRC-langsmith-observability: [Observability concepts](https://docs.langchain.com/langsmith/observability-concepts) | Content and retention vary by configuration. | <!-- SAF-TRACE: claims=SAF-T1805-C009; sources=SRC-langsmith-observability -->
| SAF-T1805-C010 | High severity is supportable when sensitive context crosses users or tenants. | Research-Derived | SRC-cve-2026-56077 and SRC-cve-2026-9130: official vulnerability scoring | Specific CVSS scores do not rate every generalized case. | <!-- SAF-TRACE: claims=SAF-T1805-C010; sources=SRC-cve-2026-56077, SRC-cve-2026-9130 -->
| SAF-T1805-C011 | Both direct identifiers had exploitation-none enrichment and were absent from the reviewed KEV edition. | Research-Derived | SRC-cve-2026-56077, SRC-cve-2026-9130, SRC-cisa-kev-2026-09-01 | Absence is time-bound and not proof of non-exploitation. | <!-- SAF-TRACE: claims=SAF-T1805-C011; sources=SRC-cve-2026-56077, SRC-cve-2026-9130, SRC-cisa-kev-2026-09-01 -->
| SAF-T1805-C012 | CVE-2025-32711 is a fully mitigated Critical adjacent disclosure case, not direct snapshot evidence. | Research-Derived | SRC-msrc-cve-2025-32711 and SRC-cve-2025-32711: [MSRC record](https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2025-32711) and [CVE record](https://cveawg.mitre.org/api/cve/CVE-2025-32711) | Public records do not identify snapshot or history retrieval. | <!-- SAF-TRACE: claims=SAF-T1805-C012; sources=SRC-msrc-cve-2025-32711, SRC-cve-2025-32711 -->
| SAF-T1805-C013 | Detection requires owner, tenant, authorization, approval, object, content-class, count, byte, destination, result, and time fields. | Research-Derived | SRC-mcp-security-spec-2026-07-28 and SRC-nist-sp800-61r3: protocol audit guidance and [NIST SP 800-61r3](https://doi.org/10.6028/NIST.SP.800-61r3) | Normalized field names require product mapping. | <!-- SAF-TRACE: claims=SAF-T1805-C013; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->
| SAF-T1805-C014 | The local analytic alerts on successful sensitive reads with authorization, tenant, or unapproved owner mismatch. | Demonstrated | SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-nist-sp800-61r3 | Local logic test, not production efficacy evidence. | <!-- SAF-TRACE: claims=SAF-T1805-C014; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-nist-sp800-61r3 -->
| SAF-T1805-C015 | Missing logs and authorized-principal compromise create blind spots; legitimate delegation can create false positives. | Research-Derived | SRC-nist-sp800-61r3 and SRC-langsmith-sensitive-trace-controls: [NIST](https://doi.org/10.6028/NIST.SP.800-61r3) and [trace controls](https://docs.langchain.com/langsmith/mask-inputs-outputs) | Error rates are environment-specific. | <!-- SAF-TRACE: claims=SAF-T1805-C015; sources=SRC-nist-sp800-61r3, SRC-langsmith-sensitive-trace-controls -->
| SAF-T1805-C016 | Owner binding, per-call authorization, least privilege, consent, retention limits, and trace redaction reduce risk. | Research-Derived | SRC-mcp-security-spec-2026-07-28, SRC-mcp-overview-2026, SRC-langsmith-sensitive-trace-controls | Redaction does not replace authorization and can miss data. | <!-- SAF-TRACE: claims=SAF-T1805-C016; sources=SRC-mcp-security-spec-2026-07-28, SRC-mcp-overview-2026, SRC-langsmith-sensitive-trace-controls -->
| SAF-T1805-C017 | Response should preserve evidence and provenance, scope affected assets, contain, eradicate, and retain under policy. | Research-Derived | SRC-nist-sp800-61r3: [NIST SP 800-61r3](https://doi.org/10.6028/NIST.SP.800-61r3) | Legal and retention duties remain environment-specific. | <!-- SAF-TRACE: claims=SAF-T1805-C017; sources=SRC-nist-sp800-61r3 -->
| SAF-T1805-C018 | ATT&CK T1213 is an Analogous repository-collection mapping, not a direct agent-snapshot definition. | Research-Derived | SRC-mitre-t1213-v3.4: [Data from Information Repositories](https://attack.mitre.org/techniques/T1213/) | ATT&CK behavior is broader than active agent state. | <!-- SAF-TRACE: claims=SAF-T1805-C018; sources=SRC-mitre-t1213-v3.4 -->
| SAF-T1805-C019 | Prompt-only extraction, context mutation, persistent-memory enumeration, and prompt-induced disclosure remain distinct neighbors. | Research-Derived | SRC-mcp-resources-2026, SRC-langgraph-persistence, SRC-msrc-cve-2025-32711 | Neighbor IDs are synthetic until integration. | <!-- SAF-TRACE: claims=SAF-T1805-C019; sources=SRC-mcp-resources-2026, SRC-langgraph-persistence, SRC-msrc-cve-2025-32711 -->
| SAF-T1805-C020 | The authority corpus found two direct vulnerabilities, one direct demonstration, one adjacent case, and no qualifying production breach. | Research-Derived | SRC-nvd-search-corpus, SRC-cisa-kev-2026-09-01, SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130 | Absence finding is corpus- and date-bounded. | <!-- SAF-TRACE: claims=SAF-T1805-C020; sources=SRC-nvd-search-corpus, SRC-cisa-kev-2026-09-01, SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130 -->

### Current State

- **Affected Environments**: Agent or MCP-adjacent systems that persist active context and expose a reachable read or export surface without complete owner and tenant binding. <!-- SAF-TRACE: claims=SAF-T1805-C003, SAF-T1805-C004, SAF-T1805-C006, SAF-T1805-C008, SAF-T1805-C009; sources=SRC-mcp-resources-2026, SRC-mcp-tools-2026-07-28, SRC-langgraph-persistence, SRC-langsmith-observability -->
- **Known Exploitation**: One public direct demonstration exists, but current CISA enrichment and the reviewed KEV edition do not establish production exploitation of the two direct CVEs. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C011, SAF-T1805-C020; sources=SRC-ghsa-766v-q9x3-g744, SRC-cve-2026-56077, SRC-cve-2026-9130, SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Fixed product versions, owner-bound state handles, per-call authorization, least privilege, consent, reduced retention, trace suppression or masking, and correlated audit logging. <!-- SAF-TRACE: claims=SAF-T1805-C002, SAF-T1805-C006, SAF-T1805-C007, SAF-T1805-C013, SAF-T1805-C016; sources=SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28, SRC-mcp-overview-2026, SRC-langsmith-sensitive-trace-controls, SRC-nist-sp800-61r3 -->
- **Residual Risk**: Logging gaps, compromised authorized identities, inconsistent delegation metadata, and incomplete redaction can leave blind spots after common controls are applied. <!-- SAF-TRACE: claims=SAF-T1805-C015, SAF-T1805-C016; sources=SRC-nist-sp800-61r3, SRC-langsmith-sensitive-trace-controls, SRC-mcp-security-spec-2026-07-28 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-56077 / GHSA-766v-q9x3-g744 | Published 2026-04-07; praisonaiagents through 1.5.114 | Cross-agent prompt and history disclosure; fixed in 1.5.115 | Direct vulnerability and direct public demonstration | No production victim exploitation is documented. | <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C010, SAF-T1805-C011; sources=SRC-ghsa-766v-q9x3-g744, SRC-cve-2026-56077 -->
| CVE-2026-9130 | Published 2026-08-05; Langflow OSS 1.0.0 through 1.10.3 in affected multi-user configuration | Cross-user chat-history disclosure; upgrade to 1.11.0 or newer | Direct vulnerability | No public production incident or demonstration is documented. | <!-- SAF-TRACE: claims=SAF-T1805-C002, SAF-T1805-C010, SAF-T1805-C011; sources=SRC-ibm-cve-2026-9130, SRC-cve-2026-9130 -->
| CVE-2025-32711 | Released 2025-06-11; M365 Copilot cloud service | Critical network information disclosure through AI command injection; fully mitigated with no user action | Enabling or adjacent; aligns to synthetic SAF-T1102 pending integration | Public authority records do not establish direct snapshot, checkpoint, history, or trace retrieval. | <!-- SAF-TRACE: claims=SAF-T1805-C012, SAF-T1805-C019; sources=SRC-msrc-cve-2025-32711, SRC-cve-2025-32711 -->

### Author and Source Credits

- **Technique author and isolated validation operator**: [OpenAI Codex clean-room record](../../research/techniques/SAF-T1805/quality-review.yml).
- **PraisonAI advisory credit**: MervinPraison published the advisory and credited offset as reporter. <!-- SAF-TRACE: claims=SAF-T1805-C001; sources=SRC-ghsa-766v-q9x3-g744 -->
- **Langflow vulnerability credit**: IBM credits Sergio Cabrera, also identified as ddlxstudio, as finder. <!-- SAF-TRACE: claims=SAF-T1805-C002; sources=SRC-ibm-cve-2026-9130, SRC-cve-2026-9130 -->
- **Framework and response credits**: Named ATT&CK contributors and NIST authors are preserved in References and the source manifest. <!-- SAF-TRACE: claims=SAF-T1805-C017, SAF-T1805-C018; sources=SRC-nist-sp800-61r3, SRC-mitre-t1213-v3.4 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Cross-user or cross-tenant snapshots can contain prompts, conversation turns, tool and resource results, checkpoints, or full trace inputs and outputs; severity falls with isolation and redaction. | <!-- SAF-TRACE: claims=SAF-T1805-C003, SAF-T1805-C009, SAF-T1805-C010; sources=SRC-ghsa-766v-q9x3-g744, SRC-langsmith-observability, SRC-cve-2026-56077, SRC-cve-2026-9130 -->
| Integrity | None for the core technique | Capture obtains a copy; state mutation, replay, or forked execution is separate or follow-on behavior. | <!-- SAF-TRACE: claims=SAF-T1805-C003, SAF-T1805-C008, SAF-T1805-C019; sources=SRC-langgraph-time-travel, SRC-langgraph-persistence, SRC-ghsa-766v-q9x3-g744 -->
| Availability | None for the core technique | The immediate objective is collection, not disruption; product-specific side effects are not generalized. | <!-- SAF-TRACE: claims=SAF-T1805-C003, SAF-T1805-C010; sources=SRC-ghsa-766v-q9x3-g744, SRC-cve-2026-56077, SRC-cve-2026-9130 -->
| Scope | Local to Multi-System | A single owner may be affected, or a shared service can expose multiple users or tenants when identifiers collide or ownership binding is missing. | <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002, SAF-T1805-C010; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-cve-2026-9130 -->

### Severity Conditions

- **Severity increases when**: Context includes credentials, system instructions, regulated data, tool results, or multi-tenant histories and the read surface is network reachable or automatable. <!-- SAF-TRACE: claims=SAF-T1805-C009, SAF-T1805-C010; sources=SRC-langsmith-observability, SRC-cve-2026-56077, SRC-cve-2026-9130 -->
- **Severity decreases when**: State is owner-isolated, redacted, short-lived, explicitly approved, least-privilege scoped, and audited with reliable tenant metadata. <!-- SAF-TRACE: claims=SAF-T1805-C007, SAF-T1805-C013, SAF-T1805-C015, SAF-T1805-C016; sources=SRC-mcp-overview-2026, SRC-mcp-security-spec-2026-07-28, SRC-langsmith-sensitive-trace-controls, SRC-nist-sp800-61r3 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Agent or MCP-adjacent application audit log | Snapshot read or export, checkpoint-history read, and trace export | Time, event and result, actor and owner, actor and owner tenant, authorization, approval, object IDs, content classes, count, bytes, and destination | Log metadata and classifications rather than context bodies; preserve correlation identifiers and access controls. | <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C016; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3, SRC-langsmith-sensitive-trace-controls -->
| Identity and authorization log | Session, owner, tenant, policy, approval, and delegation decisions | Authenticated principal, effective principal, owner, tenant, policy result, approval actor, and request correlation ID | Correlate with the application event and normalize delegation before alerting. | <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C015; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->

### Indicators of Compromise (IoCs)

- No reliable durable artifact is known; this is a behavioral authorization-boundary analytic rather than a fixed-indicator technique. <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C020; sources=SRC-mcp-security-spec-2026-07-28, SRC-nvd-search-corpus -->

### Behavioral Indicators

- A successful classified context read despite a deny, unknown, or missing authorization decision. <!-- SAF-TRACE: claims=SAF-T1805-C014; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-nist-sp800-61r3 -->
- A successful snapshot or history operation where actor and owner tenants differ, or where an actor-owner mismatch lacks an approved delegation. <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C014; sources=SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->
- Repeated state reads across unrelated owners, unusual export destinations, or access volumes above an owner's normal baseline increase confidence but require local tuning. <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C015, SAF-T1805-C018; sources=SRC-nist-sp800-61r3, SRC-mitre-t1213-v3.4 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect completed sensitive context acquisition with an authorization, tenant, or unapproved owner anomaly. <!-- SAF-TRACE: claims=SAF-T1805-C014; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-nist-sp800-61r3 -->
- **Rule Status**: Experimental; the portable schema requires implementation-specific field mapping and baseline validation. <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C015; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->
- **Detection Logic**: Require a successful non-empty sensitive read or export and at least one non-allow authorization, tenant mismatch, or unapproved actor-owner mismatch. <!-- SAF-TRACE: claims=SAF-T1805-C014; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-nist-sp800-61r3 -->
- **Correlation Window**: One application event joined to its authorization and identity decision by correlation identifier; longer owner-access baselines are optional. <!-- SAF-TRACE: claims=SAF-T1805-C013; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->
- **Known False Positives**: Approved support, incident-response, export, or migration workflows whose delegation is not normalized, plus stale tenant or owner metadata. <!-- SAF-TRACE: claims=SAF-T1805-C015; sources=SRC-nist-sp800-61r3, SRC-langsmith-sensitive-trace-controls -->
- **Known Limitations**: Unlogged reads, compromised authorized identities, suppressed traces, and incomplete authorization fields can evade or degrade the analytic. <!-- SAF-TRACE: claims=SAF-T1805-C015; sources=SRC-nist-sp800-61r3, SRC-langsmith-sensitive-trace-controls -->
- **Tuning Guidance**: Normalize approved delegation, validate owner and tenant sources, baseline legitimate exporters, and tune false-positive and false-negative rates before enforcement. <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C015; sources=SRC-nist-sp800-61r3, SRC-mcp-security-spec-2026-07-28 -->

### Validation

- **Test Data**: [events.jsonl](../../tests/SAF-T1805/events.jsonl)
- **Validation Script**: [test_detector.py](../../tests/SAF-T1805/test_detector.py)
- **Expected Result**: [Four canonical alerts](../../tests/SAF-T1805/expected_alerts.json) with benign, empty, denied, unrelated, and malformed records suppressed.
- **Last Validated**: 2026-09-02 in the isolated bundle. <!-- SAF-TRACE: claims=SAF-T1805-C014; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-nist-sp800-61r3 -->
- **Feasibility Waiver**: None; the portable detector and fixtures execute with the Python standard library. <!-- SAF-TRACE: claims=SAF-T1805-C014; sources=SRC-nist-sp800-61r3, SRC-ghsa-766v-q9x3-g744 -->

## Mitigation Strategies

### Preventive Controls

1. **Bind every state key to its authenticated owner and tenant**: Treat snapshot, session, thread, trace, checkpoint, and tool-state identifiers as selectors, not authorization, and enforce access on every call. <!-- SAF-TRACE: claims=SAF-T1805-C002, SAF-T1805-C006, SAF-T1805-C016; sources=SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28 -->
2. **Enforce consent, least privilege, and approval**: Constrain who can expose resources, include context, and perform exports, with explicit user visibility for sensitive actions. <!-- SAF-TRACE: claims=SAF-T1805-C007, SAF-T1805-C016; sources=SRC-mcp-overview-2026, SRC-mcp-security-spec-2026-07-28 -->
3. **Reduce snapshot sensitivity and lifetime**: Disable unnecessary tracing, hide inputs, outputs, and metadata, mask sensitive fields, and apply short retention appropriate to the use case. <!-- SAF-TRACE: claims=SAF-T1805-C009, SAF-T1805-C015, SAF-T1805-C016; sources=SRC-langsmith-observability, SRC-langsmith-sensitive-trace-controls -->
4. **Apply vendor remediation**: Upgrade PraisonAI to 1.5.115 or newer and affected Langflow OSS deployments to 1.11.0 or newer. <!-- SAF-TRACE: claims=SAF-T1805-C001, SAF-T1805-C002; sources=SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130, SRC-cve-2026-9130 -->

### Detective Controls

1. **Preserve and correlate context-access audit events**: Centralize application, identity, authorization, and approval decisions with stable correlation identifiers. <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C016; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->
2. **Alert on owner and tenant anomalies**: Use the portable analytic as a starting point, then baseline approved support, migration, and incident-response exporters. <!-- SAF-TRACE: claims=SAF-T1805-C014, SAF-T1805-C015; sources=SRC-nist-sp800-61r3, SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130 -->

### Response Procedures

#### Immediate Actions

- Contain the affected session, identity, state service, and export path while preserving audit integrity and provenance. <!-- SAF-TRACE: claims=SAF-T1805-C017; sources=SRC-nist-sp800-61r3 -->
- Disable breached accounts or selectors, revoke active handles and tokens, and rotate credentials only when the captured classifications show they may have been exposed. <!-- SAF-TRACE: claims=SAF-T1805-C016, SAF-T1805-C017; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->

#### Investigation Steps

- Correlate application, identity, authorization, approval, checkpoint, trace, resource, and tool audit events to reconstruct sequence, scope, and affected owners. <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C017; sources=SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->
- Preserve incident data and metadata under evidence-handling and retention policy, and distinguish attempted denied reads from successful collection. <!-- SAF-TRACE: claims=SAF-T1805-C014, SAF-T1805-C017; sources=SRC-nist-sp800-61r3 -->

#### Remediation

- Patch the affected implementation, enforce object-owner binding at every read path, invalidate colliding or leaked selectors, and validate tenant isolation. <!-- SAF-TRACE: claims=SAF-T1805-C002, SAF-T1805-C006, SAF-T1805-C016, SAF-T1805-C017; sources=SRC-ibm-cve-2026-9130, SRC-mcp-security-spec-2026-07-28, SRC-nist-sp800-61r3 -->
- Re-test with positive and negative ownership cases, restore only trusted state, and add monitoring for recurrence. <!-- SAF-TRACE: claims=SAF-T1805-C014, SAF-T1805-C017; sources=SRC-nist-sp800-61r3, SRC-ghsa-766v-q9x3-g744, SRC-ibm-cve-2026-9130 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1603: System Prompt Disclosure](../SAF-T1603/README.md) | Overlapping | Fixed prompt-only extraction does not require a copy of active assembled or persisted execution state. | <!-- SAF-TRACE: claims=SAF-T1805-C019; sources=SRC-mcp-resources-2026, SRC-langgraph-persistence -->
| [SAF-T1204: Context Memory Implant](../SAF-T1204/README.md) | Co-occurring | Mutation changes context, while this technique acquires a point-in-time copy. | <!-- SAF-TRACE: claims=SAF-T1805-C019; sources=SRC-mcp-resources-2026, SRC-langgraph-persistence -->
| [SAF-T1505: In-Memory Secret Extraction](../SAF-T1505/README.md) | Alternative | Persistent memory exists independently of an active thread snapshot. | <!-- SAF-TRACE: claims=SAF-T1805-C019; sources=SRC-langgraph-persistence -->
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Alternative or prerequisite | Adversarial instructions cause disclosure rather than directly reading stored active context. | <!-- SAF-TRACE: claims=SAF-T1805-C012, SAF-T1805-C019; sources=SRC-msrc-cve-2025-32711, SRC-cve-2025-32711 -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | Analogous | Both collect sensitive data from managed repositories and support unusual-access detection, but T1213 does not define active agent snapshots or owner-bound execution state. | <!-- SAF-TRACE: claims=SAF-T1805-C018; sources=SRC-mitre-t1213-v3.4 -->

### Additional Framework Mappings

| Framework | ID | Name | Rationale |
| --- | --- | --- | --- |
| NIST CSF 2.0 Community Profile in SP 800-61r3 | PR.PS-04, DE.CM, DE.AE, RS.AN, RS.MI | Log preservation, monitoring, analysis, evidence, and mitigation outcomes | These outcomes support audit collection, correlation, evidence preservation, containment, and eradication without claiming a one-to-one attack-technique mapping. | <!-- SAF-TRACE: claims=SAF-T1805-C013, SAF-T1805-C015, SAF-T1805-C017; sources=SRC-nist-sp800-61r3 -->

## References

1. **SRC-mcp-overview-2026**: [Model Context Protocol Specification, version 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) — MCP project maintainers; consent and privacy principles.
2. **SRC-mcp-resources-2026**: [MCP Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources) — MCP project maintainers; contextual resource semantics and access controls.
3. **SRC-mcp-sampling-2026**: [MCP Sampling](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling) — MCP project maintainers; deprecated context-inclusion and retention behavior.
4. **SRC-mcp-tools-2026-07-28**: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — MCP project maintainers; embedded resources and stateful tool requirements.
5. **SRC-mcp-security-spec-2026-07-28**: [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices) — MCP project maintainers; state-handle ownership, authorization, and audit guidance.
6. **SRC-langgraph-persistence**: [LangGraph Persistence](https://docs.langchain.com/oss/python/langgraph/persistence) — LangChain documentation team; checkpoints, threads, and memory stores.
7. **SRC-langgraph-time-travel**: [Use time-travel](https://docs.langchain.com/oss/python/langgraph/use-time-travel) — LangChain documentation team; replay and fork behavior.
8. **SRC-langsmith-observability**: [LangSmith Observability concepts](https://docs.langchain.com/langsmith/observability-concepts) — LangChain documentation team; traces, threads, trajectories, and retention.
9. **SRC-langsmith-sensitive-trace-controls**: [Prevent logging of sensitive data in traces](https://docs.langchain.com/langsmith/mask-inputs-outputs) — LangChain documentation team; suppression, masking, conditional tracing, and limits.
10. **SRC-ghsa-766v-q9x3-g744**: [PraisonAI Memory State Leakage advisory](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-766v-q9x3-g744) — MervinPraison; offset credited as reporter; published 2026-04-07.
11. **SRC-cve-2026-56077**: [CVE-2026-56077](https://cveawg.mitre.org/api/cve/CVE-2026-56077) — VulnCheck CNA and CISA ADP; affected versions, scoring, and exploitation status.
12. **SRC-ibm-cve-2026-9130**: [IBM Security Bulletin containing CVE-2026-9130](https://www.ibm.com/support/pages/node/7282647) — IBM PSIRT; Sergio Cabrera credited as finder; initial publication 2026-08-05.
13. **SRC-cve-2026-9130**: [CVE-2026-9130](https://cveawg.mitre.org/api/cve/CVE-2026-9130) — IBM CNA and CISA ADP; version, scoring, remediation, credit, and exploitation status.
14. **SRC-msrc-cve-2025-32711**: [MSRC CVE-2025-32711 record](https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2025-32711) — Microsoft Security Response Center; cloud mitigation and public status.
15. **SRC-cve-2025-32711**: [CVE-2025-32711](https://cveawg.mitre.org/api/cve/CVE-2025-32711) — Microsoft CNA and CISA ADP; mechanism, scoring, and exploitation status.
16. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — CISA; catalog version 2026.09.01.
17. **SRC-mitre-t1213-v3.4**: [ATT&CK T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213/) — MITRE; contributors Isif Ibrahima, Milos Stojadinovic, Naveen Vijayaraghavan, Nilesh Dherange, Obsidian Security, Praetorian, and Regina Elwell.
18. **SRC-nist-sp800-61r3**: [NIST SP 800-61 Revision 3](https://doi.org/10.6028/NIST.SP.800-61r3) — Alexander Nelson, Sanjay Rekhi, Murugiah Souppaya, and Karen Scarfone; April 2025.
19. **SRC-nvd-search-corpus**: [NVD CVE API](https://services.nvd.nist.gov/rest/json/cves/2.0/) — NIST NVD; six recorded direct keyword queries reviewed through 2026-09-02.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial clean-room research draft, detector, evidence packet, and integration fragments | OpenAI Codex clean-room author |
