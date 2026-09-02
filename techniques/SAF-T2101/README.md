# SAF-T2101: Data Destruction

## Overview

- **Tactic**: Impact (ATK-TA0040) <!-- SAF-TRACE: claims=SAF-T2101-C015; sources=SRC-mitre-t1485 -->
- **Technique ID**: SAF-T2101
- **Research Packet**: [research/techniques/SAF-T2101](../../research/techniques/SAF-T2101/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T2101/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: High <!-- SAF-TRACE: claims=SAF-T2101-C016; sources=SRC-aws-agent-access,SRC-mitre-t1485 -->
- **Severity Rationale**: An authorized destructive tool can affect production data at agent speed, but the blast radius remains bounded by effective tool and resource permissions. <!-- SAF-TRACE: claims=SAF-T2101-C006,SAF-T2101-C016; sources=SRC-aws-agent-access,SRC-mitre-t1485 -->
- **First Observed**: Not observed in production in the reviewed MCP and agentic-system corpus. <!-- SAF-TRACE: claims=SAF-T2101-C014; sources=SRC-cisa-kev-fsp-2026-09-01,SRC-nvd-cve-2025-53098,SRC-nvd-cve-2025-64443,SRC-nvd-cve-54377 -->
- **Last Updated**: 2026-09-02

## Scope

Data Destruction is an adversary-directed MCP or agent action whose immediate objective is deleting stored data or irreversibly corrupting an addressable resource through a tool or delegated service authority. The crossed boundary is the transition from model-selected or attacker-influenced intent to an authorized external side effect. <!-- SAF-TRACE: claims=SAF-T2101-C001; sources=SRC-mcp-tools-2026-07-28,SRC-aws-agent-access,SRC-ms-sql-mcp,SRC-ms-documentdb-mcp -->

### In Scope

- Successful or attempted deletion of records, objects, collections, databases, snapshots, or similarly stored resources through an MCP-exposed or agent-accessible operation. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C004,SAF-T2101-C005; sources=SRC-ms-sql-mcp,SRC-ms-documentdb-mcp,SRC-aws-agent-access -->
- Abuse of model-controlled tool selection, compromised server behavior, or delegated credentials where destruction is the immediate adversary objective. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C011; sources=SRC-mcp-tools-2026-07-28,SRC-arxiv-trustshift,SRC-aws-agent-access -->

### Out of Scope

- Prompt injection, tool poisoning, command execution, or server compromise when the evidence establishes only delivery or control and not a destruction objective; those mechanisms may precede this technique. <!-- SAF-TRACE: claims=SAF-T2101-C008,SAF-T2101-C009,SAF-T2101-C010,SAF-T2101-C011; sources=SRC-nvd-cve-2025-53098,SRC-nvd-cve-2025-64443,SRC-nvd-cve-54377,SRC-arxiv-mcp-threat -->
- Service exhaustion, ransomware-style encryption, disk-structure wiping, evidence cleanup, and accidental administrative deletion, each of which has a different immediate objective or mechanism. <!-- SAF-TRACE: claims=SAF-T2101-C015; sources=SRC-mitre-t1485 -->

### Distinguishing Characteristics

The defining observable is a delete, drop, purge, truncate, destroy, or terminate operation against stored state, coupled to adversarial intent. Instruction manipulation is a delivery mechanism; service exhaustion consumes capacity; encryption denies access without necessarily deleting the underlying object. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C012,SAF-T2101-C015; sources=SRC-mitre-t1485,SRC-arxiv-agenttrust-v2 -->

## Description

MCP tools are model-controlled: a language model can discover a tool and issue a `tools/call`, while the server performs the external operation. The specification recommends human confirmation and logging for sensitive operations but does not itself make an annotation or model decision an authorization boundary. <!-- SAF-TRACE: claims=SAF-T2101-C002,SAF-T2101-C003; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-annotations-2026-03-16 -->

The end-to-end technique is Research-Derived. First-party implementations expose deletion-capable MCP tools, and AWS documents that an agent can exercise any granted entitlement, including object deletion, when influenced by prompt injection. Taken together, the evidence supports the technique's feasibility, but it does not establish a public production incident or controlled end-to-end data-destruction demonstration. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C004,SAF-T2101-C005,SAF-T2101-C006,SAF-T2101-C014; sources=SRC-aws-agent-access,SRC-ms-sql-mcp,SRC-ms-documentdb-mcp,SRC-cisa-kev-fsp-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: Attacker influence over agent planning or tool selection causes an authorized destructive tool call. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C006; sources=SRC-mcp-tools-2026-07-28,SRC-aws-agent-access -->
- **Secondary Vectors**:
  - A compromised MCP server changes behavior after a trusted period or returns schema-valid manipulations that influence later actions. <!-- SAF-TRACE: claims=SAF-T2101-C011; sources=SRC-arxiv-trustshift -->
  - An implementation flaw exposes command execution or manipulation of MCP tools, creating an enabling path without independently proving destruction. <!-- SAF-TRACE: claims=SAF-T2101-C008,SAF-T2101-C009,SAF-T2101-C010; sources=SRC-nvd-cve-2025-53098,SRC-nvd-cve-2025-64443,SRC-nvd-cve-54377 -->
- **Affected Components**: MCP host, client, server, tool, delegated identity, and external data service. <!-- SAF-TRACE: claims=SAF-T2101-C001; sources=SRC-mcp-tools-2026-07-28,SRC-aws-agent-access -->
- **Trust Boundary Crossed**: Model-selected or server-influenced intent becomes an authorized, state-changing service operation. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C011; sources=SRC-mcp-tools-2026-07-28,SRC-arxiv-trustshift -->

## Technical Details

### Prerequisites

- A reachable tool or general-purpose capability can delete or irreversibly alter stored resources. <!-- SAF-TRACE: claims=SAF-T2101-C004,SAF-T2101-C005,SAF-T2101-C006; sources=SRC-ms-sql-mcp,SRC-ms-documentdb-mcp,SRC-aws-agent-access -->
- The agent or server's effective identity is authorized for the target resource. <!-- SAF-TRACE: claims=SAF-T2101-C006; sources=SRC-aws-agent-access,SRC-aws-agentic-lens -->
- Attacker influence, server defection, or another enabling mechanism reaches tool planning or execution without an effective independent approval or policy denial. <!-- SAF-TRACE: claims=SAF-T2101-C002,SAF-T2101-C007,SAF-T2101-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-elicitation-2026-07-28,SRC-arxiv-trustshift -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies an agent path that can reach a destructive operation and a target within the delegated identity's scope. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C006; sources=SRC-aws-agent-access,SRC-ms-sql-mcp -->
2. **Delivery**: Attacker-controlled input, a compromised server response, or an enabling implementation weakness influences the action path. <!-- SAF-TRACE: claims=SAF-T2101-C008,SAF-T2101-C009,SAF-T2101-C010,SAF-T2101-C011; sources=SRC-nvd-cve-2025-53098,SRC-nvd-cve-2025-64443,SRC-nvd-cve-54377,SRC-arxiv-trustshift -->
3. **Trigger or Execution**: The host issues a destructive tool call using inertly represented arguments such as target `example-record-17`. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C004; sources=SRC-mcp-tools-2026-07-28,SRC-ms-sql-mcp -->
4. **Boundary Crossing**: Authorization succeeds and no independent approval, scope, or policy control denies the call. <!-- SAF-TRACE: claims=SAF-T2101-C002,SAF-T2101-C007,SAF-T2101-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-elicitation-2026-07-28,SRC-aws-agentic-lens -->
5. **Objective**: The addressed data or resource is deleted or made irrecoverable. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C015; sources=SRC-mitre-t1485,SRC-ms-documentdb-mcp -->
6. **Follow-On Activity**: The adversary may repeat the operation across targets; this technique does not presume persistence, collection, or exfiltration. <!-- SAF-TRACE: claims=SAF-T2101-C012,SAF-T2101-C015; sources=SRC-mitre-t1485,SRC-aws-agent-access -->

### Example Scenario

The following scenario is an inert, Research-Derived illustration rather than a reported incident: attacker-controlled content influences an agent with an overbroad data role; the agent requests deletion of a fictional production record; an absent approval field permits execution; audit telemetry records the tool, actor, target, decision, and result. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C006,SAF-T2101-C012,SAF-T2101-C014; sources=SRC-aws-agent-access,SRC-ms-documentdb-mcp,SRC-cisa-kev-fsp-2026-09-01 -->

```json
{
  "event_type": "mcp_tool_call",
  "tool_name": "delete_record",
  "target": {"id": "example-record-17", "environment": "production"},
  "decision": "allow",
  "result_status": "success",
  "approval": {"status": "missing"}
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T2101-C001 | An adversary-influenced agent with an authorized destructive tool can use that path to delete stored state. | Research-Derived | SRC-mcp-tools-2026-07-28, SRC-aws-agent-access, SRC-ms-sql-mcp, SRC-ms-documentdb-mcp | No direct incident or end-to-end demonstration was identified. <!-- SAF-TRACE: claims=SAF-T2101-C001; sources=SRC-mcp-tools-2026-07-28,SRC-aws-agent-access,SRC-ms-sql-mcp,SRC-ms-documentdb-mcp --> |
| SAF-T2101-C002 | MCP guidance treats tools as model-controlled and recommends human confirmation and logging for sensitive operations. | Demonstrated | SRC-mcp-tools-2026-07-28 | Guidance is not enforcement. <!-- SAF-TRACE: claims=SAF-T2101-C002; sources=SRC-mcp-tools-2026-07-28 --> |
| SAF-T2101-C003 | Tool annotations, including destructive hints, are untrusted metadata and cannot enforce a decision. | Demonstrated | SRC-mcp-annotations-2026-03-16 | Describes the annotation contract, not every client implementation. <!-- SAF-TRACE: claims=SAF-T2101-C003; sources=SRC-mcp-annotations-2026-03-16 --> |
| SAF-T2101-C004 | SQL MCP Server exposes `delete_record`, enabled by default with the DML surface, and supports disabling it. | Demonstrated | SRC-ms-sql-mcp | Product documentation, not adversarial testing. <!-- SAF-TRACE: claims=SAF-T2101-C004; sources=SRC-ms-sql-mcp --> |
| SAF-T2101-C005 | Azure DocumentDB MCP Toolkit exposes delete and drop tools with layered authorization, flags, confirmation, and audit fields. | Demonstrated | SRC-ms-documentdb-mcp | Preview product documentation, not an incident. <!-- SAF-TRACE: claims=SAF-T2101-C005; sources=SRC-ms-documentdb-mcp --> |
| SAF-T2101-C006 | AWS states that agents can exercise granted delete permissions and that prompt injection can direct unintended deletion. | Research-Derived | SRC-aws-agent-access | Architectural guidance and scenario, not a reported breach. <!-- SAF-TRACE: claims=SAF-T2101-C006; sources=SRC-aws-agent-access --> |
| SAF-T2101-C007 | Current MCP supports an input-required round trip that can request confirmation before completion. | Demonstrated | SRC-mcp-release-2026-07-28, SRC-mcp-elicitation-2026-07-28 | Applications must implement and enforce the decision. <!-- SAF-TRACE: claims=SAF-T2101-C007; sources=SRC-mcp-release-2026-07-28,SRC-mcp-elicitation-2026-07-28 --> |
| SAF-T2101-C008 | CVE-2025-53098 enabled prompt-influenced writes to Roo Code MCP configuration under stated prerequisites before 3.20.3. | Demonstrated | SRC-nvd-cve-2025-53098 | Enabling command execution; destruction was not reported. <!-- SAF-TRACE: claims=SAF-T2101-C008; sources=SRC-nvd-cve-2025-53098 --> |
| SAF-T2101-C009 | CVE-2025-64443 allowed browser-based manipulation of tools behind certain Docker MCP Gateway transports before 0.28.0. | Demonstrated | SRC-nvd-cve-2025-64443 | Enabling access-path flaw; destruction was not reported. <!-- SAF-TRACE: claims=SAF-T2101-C009; sources=SRC-nvd-cve-2025-64443 --> |
| SAF-T2101-C010 | CVE-2025-54377 allowed a multiline command-input allow-list bypass in Roo Code before 3.23.19. | Demonstrated | SRC-nvd-cve-54377 | Command execution with public proof-of-concept status; destruction was not reported. <!-- SAF-TRACE: claims=SAF-T2101-C010; sources=SRC-nvd-cve-54377 --> |
| SAF-T2101-C011 | Controlled MCP studies demonstrate tool poisoning and temporally defecting servers, while also showing partial client and runtime defenses. | Demonstrated | SRC-arxiv-mcp-threat, SRC-arxiv-trustshift | Neither study establishes the scoped destruction objective. <!-- SAF-TRACE: claims=SAF-T2101-C011; sources=SRC-arxiv-mcp-threat,SRC-arxiv-trustshift --> |
| SAF-T2101-C012 | A deterministic analytic can identify explicit destructive verbs and bursts, but semantic intent remains a structural limitation. | Research-Derived | SRC-mitre-t1485, SRC-arxiv-agenttrust-v1, SRC-arxiv-agenttrust-v2 | Requires normalized, structured pre-execution or audit telemetry. <!-- SAF-TRACE: claims=SAF-T2101-C012; sources=SRC-mitre-t1485,SRC-arxiv-agenttrust-v1,SRC-arxiv-agenttrust-v2 --> |
| SAF-T2101-C013 | Least privilege, tool removal, independent authorization, confirmation, rate limits, and auditable decisions reduce opportunity or blast radius. | Demonstrated | SRC-aws-agent-access, SRC-aws-agentic-lens, SRC-ms-sql-mcp, SRC-ms-documentdb-mcp | Control effectiveness depends on deployment and bypass paths. <!-- SAF-TRACE: claims=SAF-T2101-C013; sources=SRC-aws-agent-access,SRC-aws-agentic-lens,SRC-ms-sql-mcp,SRC-ms-documentdb-mcp --> |
| SAF-T2101-C014 | The reviewed corpus did not identify a qualifying direct production incident or end-to-end destruction demonstration. | Research-Derived | SRC-cisa-kev-fsp-2026-09-01, SRC-nvd-cve-2025-53098, SRC-nvd-cve-2025-64443, SRC-nvd-cve-54377 | Negative finding is bounded by the documented search date and corpus. <!-- SAF-TRACE: claims=SAF-T2101-C014; sources=SRC-cisa-kev-fsp-2026-09-01,SRC-nvd-cve-2025-53098,SRC-nvd-cve-2025-64443,SRC-nvd-cve-54377 --> |
| SAF-T2101-C015 | ATT&CK T1485 is an analogous mapping for deletion and irrecoverable corruption, including cloud resources and mass-delete analytics. | Demonstrated | SRC-mitre-t1485 | ATT&CK is platform-oriented and not MCP-specific. <!-- SAF-TRACE: claims=SAF-T2101-C015; sources=SRC-mitre-t1485 --> |
| SAF-T2101-C016 | Successful production deletion primarily affects integrity and availability, with severity governed by target criticality and authorized scope. | Research-Derived | SRC-aws-agent-access, SRC-mitre-t1485 | Actual impact is deployment-specific. <!-- SAF-TRACE: claims=SAF-T2101-C016; sources=SRC-aws-agent-access,SRC-mitre-t1485 --> |

### Current State

- **Affected Environments**: Agent deployments with destructive MCP tools or general-purpose tools and identities authorized to modify production state. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C006; sources=SRC-aws-agent-access,SRC-ms-sql-mcp,SRC-ms-documentdb-mcp -->
- **Known Exploitation**: No qualifying direct production incident or end-to-end destruction demonstration was identified; reviewed advisories are enabling only. <!-- SAF-TRACE: claims=SAF-T2101-C008,SAF-T2101-C009,SAF-T2101-C010,SAF-T2101-C014; sources=SRC-cisa-kev-fsp-2026-09-01,SRC-nvd-cve-2025-53098,SRC-nvd-cve-2025-64443,SRC-nvd-cve-54377 -->
- **Available Protections**: Disable destructive tools, restrict effective permissions, require independent approval, rate-limit mutating actions, and retain structured audit events. <!-- SAF-TRACE: claims=SAF-T2101-C007,SAF-T2101-C013; sources=SRC-mcp-elicitation-2026-07-28,SRC-aws-agentic-lens,SRC-ms-sql-mcp,SRC-ms-documentdb-mcp -->
- **Residual Risk**: Direct shell or API paths can bypass MCP-specific controls, annotations may be inaccurate, and deterministic verb matching cannot resolve benign and malicious semantic twins. <!-- SAF-TRACE: claims=SAF-T2101-C003,SAF-T2101-C012,SAF-T2101-C013; sources=SRC-mcp-annotations-2026-03-16,SRC-aws-agent-access,SRC-arxiv-agenttrust-v2 -->

### Known Breaches and Vulnerabilities

No qualifying direct production breach, direct data-destruction vulnerability, or end-to-end data-destruction demonstration was identified. The strongest reviewed advisories are retained below only as enabling evidence and do not raise the technique above Research-Derived. <!-- SAF-TRACE: claims=SAF-T2101-C014; sources=SRC-cisa-kev-fsp-2026-09-01,SRC-nvd-cve-2025-53098,SRC-nvd-cve-2025-64443,SRC-nvd-cve-54377 -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-53098 | 2025-06-27; Roo Code before 3.20.3 with MCP and auto-approved project writes | Prompt-influenced MCP configuration write could lead to command execution; upgrade to 3.20.3 or later | Enabling vulnerability | No deletion or destructive objective is documented. <!-- SAF-TRACE: claims=SAF-T2101-C008; sources=SRC-nvd-cve-2025-53098 --> |
| CVE-2025-64443 | 2025-12-03; Docker MCP Gateway 0.27.0 and earlier using SSE or streaming transport | Browser-based exploitation could manipulate exposed MCP tools; upgrade to 0.28.0 or use unaffected stdio | Enabling vulnerability | CISA SSVC recorded exploitation as none; no destruction is documented. <!-- SAF-TRACE: claims=SAF-T2101-C009; sources=SRC-nvd-cve-2025-64443 --> |
| CVE-2025-54377 | 2025-07-23; Roo Code before 3.23.19 | Multiline input could bypass command allow-list checking; upgrade to 3.23.19 or later | Enabling vulnerability | CISA SSVC recorded proof-of-concept exploitation, not data destruction. <!-- SAF-TRACE: claims=SAF-T2101-C010; sources=SRC-nvd-cve-54377 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | None | Deletion alone does not disclose data; a separate collection or exfiltration behavior would be required. <!-- SAF-TRACE: claims=SAF-T2101-C016; sources=SRC-mitre-t1485 --> |
| Integrity | High | Authorized deletion or irreversible corruption changes stored state, especially when it affects production records or resources. <!-- SAF-TRACE: claims=SAF-T2101-C016; sources=SRC-aws-agent-access,SRC-mitre-t1485 --> |
| Availability | High | Loss of critical records, objects, databases, snapshots, or infrastructure can interrupt dependent services. <!-- SAF-TRACE: claims=SAF-T2101-C016; sources=SRC-mitre-t1485,SRC-aws-agent-access --> |
| Scope | Multi-System | Machine-speed calls and broad delegated permissions can expand the blast radius; scoped roles and rate limits constrain it. <!-- SAF-TRACE: claims=SAF-T2101-C006,SAF-T2101-C013,SAF-T2101-C016; sources=SRC-aws-agent-access,SRC-aws-agentic-lens --> |

### Severity Conditions

- **Severity increases when**: Destructive permissions cover production resources, agent actions are auto-approved, operations can repeat rapidly, and recovery copies share the same authority boundary. <!-- SAF-TRACE: claims=SAF-T2101-C006,SAF-T2101-C013,SAF-T2101-C016; sources=SRC-aws-agent-access,SRC-aws-agentic-lens,SRC-mitre-t1485 -->
- **Severity decreases when**: Destructive tools are absent, identities are read-only or narrowly scoped, confirmation is independently enforced, mutation rates are capped, and protected recovery copies exist. <!-- SAF-TRACE: claims=SAF-T2101-C007,SAF-T2101-C013; sources=SRC-mcp-elicitation-2026-07-28,SRC-aws-agentic-lens,SRC-ms-sql-mcp,SRC-mitre-t1485 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host, client, gateway, or server audit log | Tool-call attempt, authorization decision, approval, and result | Timestamp, actor, server, tool, normalized operation, arguments or target, decision, result, approval state | Preserve denied and successful calls; do not rely on tool annotations as ground truth. <!-- SAF-TRACE: claims=SAF-T2101-C003,SAF-T2101-C012; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-annotations-2026-03-16,SRC-ms-documentdb-mcp --> |
| Identity and target-service audit log | Delete, drop, purge, truncate, destroy, or terminate operations | Effective identity, resource, environment, API action, status, request origin, and correlation ID | Correlate MCP-mediated and direct paths because MCP-specific context does not cover shell or direct API execution. <!-- SAF-TRACE: claims=SAF-T2101-C006,SAF-T2101-C012,SAF-T2101-C013; sources=SRC-aws-agent-access,SRC-mitre-t1485 --> |

### Indicators of Compromise (IoCs)

- None known; the technique is behavioral, and no stable infrastructure or artifact is inherent to a destructive tool call. <!-- SAF-TRACE: claims=SAF-T2101-C012,SAF-T2101-C014; sources=SRC-mitre-t1485,SRC-cisa-kev-fsp-2026-09-01 -->

### Behavioral Indicators

- A successful destructive operation against a production or critical target where approval is absent, denied, mismatched, or not requested. <!-- SAF-TRACE: claims=SAF-T2101-C002,SAF-T2101-C007,SAF-T2101-C012; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-elicitation-2026-07-28,SRC-mitre-t1485 -->
- Three or more distinct destructive targets for one actor, server, and session within five minutes. <!-- SAF-TRACE: claims=SAF-T2101-C006,SAF-T2101-C012; sources=SRC-aws-agent-access,SRC-mitre-t1485 -->
- A destructive tool call whose effective operation conflicts with benign metadata such as `readOnlyHint` or `destructiveHint: false`. <!-- SAF-TRACE: claims=SAF-T2101-C003,SAF-T2101-C012; sources=SRC-mcp-annotations-2026-03-16,SRC-arxiv-agenttrust-v1 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect explicit destructive tool operations against protected targets without valid approval and destructive bursts across distinct targets. <!-- SAF-TRACE: claims=SAF-T2101-C012; sources=SRC-mitre-t1485,SRC-aws-agent-access -->
- **Rule Status**: Test <!-- SAF-TRACE: claims=SAF-T2101-C012; sources=SRC-mitre-t1485 -->
- **Detection Logic**: Unicode-normalize and case-fold the tool name and declared action, match destructive verbs, then combine target criticality and approval state or apply a three-distinct-target threshold. <!-- SAF-TRACE: claims=SAF-T2101-C012; sources=SRC-arxiv-agenttrust-v1,SRC-mitre-t1485 -->
- **Correlation Window**: Five minutes per actor, server, and session. <!-- SAF-TRACE: claims=SAF-T2101-C012; sources=SRC-mitre-t1485 -->
- **Known False Positives**: Approved bulk retention, test-fixture cleanup, lifecycle administration, and emergency decommissioning can match the burst logic. <!-- SAF-TRACE: claims=SAF-T2101-C012; sources=SRC-mitre-t1485,SRC-arxiv-agenttrust-v2 -->
- **Known Limitations**: Semantic aliases, indirect stored procedures, missing audit fields, direct paths outside MCP, and intent-dependent benign/malicious twins can evade or confuse the analytic. <!-- SAF-TRACE: claims=SAF-T2101-C012,SAF-T2101-C013; sources=SRC-arxiv-agenttrust-v2,SRC-aws-agent-access -->
- **Tuning Guidance**: Inventory destructive tools, map protected environments, require explicit approval states, baseline maintenance identities, and tune the threshold only after preserving a high-confidence protected-target branch. <!-- SAF-TRACE: claims=SAF-T2101-C012,SAF-T2101-C013; sources=SRC-aws-agentic-lens,SRC-ms-documentdb-mcp -->

### Validation

- **Test Data**: [test-events.jsonl](../../tests/SAF-T2101/test-events.jsonl)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T2101/test_detection_rule.py)
- **Expected Result**: Positive, negative, threshold boundary, malformed or missing-field, expected false-positive, and normalization or evasion cases all pass ([test result](../../research/techniques/SAF-T2101/validation/detection-test-result.txt)).
- **Last Validated**: 2026-09-02 ([canonical proof](../../research/techniques/SAF-T2101/validation/canonical-validation.txt))
- **Feasibility Waiver**: None ([test result](../../research/techniques/SAF-T2101/validation/detection-test-result.txt))

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-16: Least-Privilege Tool Authorization](../../mitigations/SAF-M-16/README.md)**: Remove unused destructive tools and deny delete permissions at the external service for identities that do not require them. <!-- SAF-TRACE: claims=SAF-T2101-C013; sources=SRC-aws-agent-access,SRC-ms-sql-mcp -->
2. **[SAF-M-69: Human Approval for Destructive Actions](../../mitigations/SAF-M-69/README.md)**: Enforce confirmation outside model reasoning and bind it to the exact action and target. <!-- SAF-TRACE: claims=SAF-T2101-C002,SAF-T2101-C007,SAF-T2101-C013; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-elicitation-2026-07-28,SRC-ms-documentdb-mcp -->
3. **Protected Backups and Recovery**: Keep recoverable copies outside the agent's destructive authority and test restoration. The catalog has no dedicated SAF mitigation identifier for this control. <!-- SAF-TRACE: claims=SAF-T2101-C013,SAF-T2101-C016; sources=SRC-mitre-t1485 -->

### Detective Controls

1. **[SAF-M-16: Least-Privilege Tool Authorization](../../mitigations/SAF-M-16/README.md)**: Log allow and deny decisions with the effective identity, policy, tool, target, and result. <!-- SAF-TRACE: claims=SAF-T2101-C013; sources=SRC-aws-agentic-lens,SRC-ms-documentdb-mcp -->
2. **[SAF-M-69: Human Approval for Destructive Actions](../../mitigations/SAF-M-69/README.md)**: Alert on protected-target mutations without a valid target-bound approval and on repeated destructive actions. <!-- SAF-TRACE: claims=SAF-T2101-C007,SAF-T2101-C012,SAF-T2101-C013; sources=SRC-mcp-elicitation-2026-07-28,SRC-mitre-t1485 -->

### Response Procedures

#### Immediate Actions

- Disable the affected tool path, suspend the agent session, and revoke or narrow the effective identity before further destructive calls can complete. <!-- SAF-TRACE: claims=SAF-T2101-C013; sources=SRC-aws-agent-access,SRC-aws-agentic-lens -->
- Protect remaining recovery copies and stop lifecycle or automation rules that could continue deletion. <!-- SAF-TRACE: claims=SAF-T2101-C013,SAF-T2101-C015; sources=SRC-mitre-t1485 -->

#### Investigation Steps

- Preserve tool-call, authorization, approval, identity, and target-service audit events; correlate on actor, server, session, target, and time. <!-- SAF-TRACE: claims=SAF-T2101-C012,SAF-T2101-C013; sources=SRC-aws-agent-access,SRC-ms-documentdb-mcp -->
- Determine the delivery path, every affected target, whether the same identity used a direct non-MCP path, and whether collection or persistence occurred separately. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C013; sources=SRC-aws-agent-access,SRC-arxiv-trustshift -->

#### Remediation

- Patch enabling implementation flaws, remove overbroad tools and permissions, require independent target-bound approval, and add rate limits. <!-- SAF-TRACE: claims=SAF-T2101-C008,SAF-T2101-C009,SAF-T2101-C010,SAF-T2101-C013; sources=SRC-nvd-cve-2025-53098,SRC-nvd-cve-2025-64443,SRC-nvd-cve-54377,SRC-aws-agentic-lens -->
- Restore affected state from protected recovery copies and validate integrity before reconnecting the agent. <!-- SAF-TRACE: claims=SAF-T2101-C013,SAF-T2101-C016; sources=SRC-mitre-t1485 -->
- Add the observed tool aliases, approval failures, target classes, and direct-path events to regression tests and monitoring. <!-- SAF-TRACE: claims=SAF-T2101-C012,SAF-T2101-C013; sources=SRC-arxiv-agenttrust-v1,SRC-aws-agent-access -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite | Manipulation changes model intent; this technique requires deletion or irreversible corruption as the immediate objective. <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C011; sources=SRC-aws-agent-access,SRC-arxiv-mcp-threat --> |
| [SAF-T2102: Service Disruption](../SAF-T2102/README.md) | Alternative | Exhaustion consumes capacity; this technique destroys stored state. <!-- SAF-TRACE: claims=SAF-T2101-C015; sources=SRC-mitre-t1485 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Analogous | Both center on deletion or irrecoverable corruption for availability impact, including cloud resources and mass-delete observables; ATT&CK does not specify MCP or agent mediation. <!-- SAF-TRACE: claims=SAF-T2101-C015; sources=SRC-mitre-t1485 --> |

## References

1. **SRC-mcp-tools-2026-07-28**: [MCP 2026-07-28 Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) - MCP maintainers and contributors; model control, calls, confirmations, logging, and untrusted annotations.
2. **SRC-mcp-elicitation-2026-07-28**: [MCP 2026-07-28 Elicitation specification](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation) - MCP maintainers and contributors; user review and confirmation flows.
3. **SRC-mcp-annotations-2026-03-16**: [Tool Annotations: Making MCP Tools Safer and Smarter](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/) - Ola Hungerford, Sam Morrow, and Luca Chang; destructive hints and enforcement limits.
4. **SRC-mcp-release-2026-07-28**: [The 2026-07-28 Specification](https://blog.modelcontextprotocol.io/posts/2026-07-28/) - MCP specification maintainers and ecosystem contributors; multi-round-trip input requirements.
5. **SRC-aws-agent-access**: [Secure AI agent access patterns to AWS resources using Model Context Protocol](https://aws.amazon.com/blogs/security/secure-ai-agent-access-patterns-to-aws-resources-using-model-context-protocol/) - Riggs Goodman III; granted entitlements, prompt injection, least privilege, and audit context.
6. **SRC-aws-agentic-lens**: [Secure agent tool usage](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentsec02.html) - AWS Well-Architected Agentic AI Lens team; authorization, approval, rate limits, and observability.
7. **SRC-ms-sql-mcp**: [Data manipulation language tools in SQL MCP Server](https://learn.microsoft.com/en-us/azure/data-api-builder/mcp/data-manipulation-language-tools) - Microsoft Data API builder documentation team; delete tool and controls.
8. **SRC-ms-documentdb-mcp**: [Azure DocumentDB MCP Toolkit](https://learn.microsoft.com/en-us/azure/documentdb/mcp-toolkit) - Microsoft Azure DocumentDB documentation team; destructive tools, guardrails, and audit schema.
9. **SRC-nvd-cve-2025-53098**: [CVE-2025-53098](https://nvd.nist.gov/vuln/detail/CVE-2025-53098) - NIST NVD, GitHub CNA, and CISA Coordinator; affected versions, prerequisites, fix, and exploitation status.
10. **SRC-nvd-cve-2025-64443**: [CVE-2025-64443](https://nvd.nist.gov/vuln/detail/CVE-2025-64443) - NIST NVD, GitHub CNA, and CISA Coordinator; gateway manipulation, transport scope, fix, and exploitation status.
11. **SRC-nvd-cve-54377**: [CVE-2025-54377](https://nvd.nist.gov/vuln/detail/CVE-2025-54377) - NIST NVD, GitHub CNA, and CISA Coordinator; command-input bypass, fix, and proof-of-concept status.
12. **SRC-arxiv-mcp-threat**: [Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning](https://arxiv.org/abs/2603.22489) - Charoes Huang, Xin Huang, Ngoc Phu Tran, and Amin Milani Fard; controlled client evaluation.
13. **SRC-arxiv-agenttrust-v1**: [AgentTrust: Runtime Safety Evaluation and Interception for AI Agent Tool Use](https://arxiv.org/abs/2605.04785) - Chenglin Yang; normalization, pre-execution interception, and evaluation limitations.
14. **SRC-arxiv-agenttrust-v2**: [AgentTrust: A Self-Improving Trust Layer for AI-Agent Actions](https://arxiv.org/abs/2606.08539) - Chenglin Yang; deterministic-rule limits on semantic threats.
15. **SRC-arxiv-trustshift**: [TrustShiftProbe](https://arxiv.org/abs/2608.23763) - Mehrdad Rostamzadeh, Sidhant Narula, Mohammad Ghasemigol, and Daniel Takabi; temporal server defection and runtime defense.
16. **SRC-mitre-t1485**: [MITRE ATT&CK T1485: Data Destruction](https://attack.mitre.org/techniques/T1485/) - MITRE ATT&CK and named contributors; scope, cloud examples, mitigation, and detection.
17. **SRC-cisa-kev-fsp-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog CSV](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) - CISA KEV Catalog team; exploitation-status cross-check.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial clean-room research-derived technique and tested analytic | OpenAI Codex clean-room author <!-- SAF-TRACE: claims=SAF-T2101-C001,SAF-T2101-C014; sources=SRC-mcp-tools-2026-07-28,SRC-cisa-kev-fsp-2026-09-01 --> |
