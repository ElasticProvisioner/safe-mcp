# SAF-T1406: Metadata Manipulation

## Overview

- **Tactic**: Defense Evasion (ATK-TA0005)
- **Technique ID**: SAF-T1406
- **Research Packet**: [technique-contract.yml](../../research/techniques/SAF-T1406/technique-contract.yml)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1406/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: The technique can silently reuse trust for a changed object and enable high-impact follow-on activity when the consumer has sensitive access. <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **First Observed**: Not established in production; the strongest evidence is a disclosed vulnerability and controlled demonstrations. <!-- SAF-TRACE: claims=SAF-T1406-C006; sources=SRC-cve-2025-54136,SRC-cisa-kev-2026-09-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Last Updated**: 2026-09-01

## Scope

Metadata Manipulation covers adversary-controlled changes to MCP or agentic object descriptors that cause a client, host, model, reviewer, policy engine, inventory, or monitor to treat the object as safer, more trusted, or more appropriate than it is. The crossed boundary is between the metadata producer or updater and the consumer making or reusing that decision. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-mcp-2026-schema,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cursor-ghsa-24mc-g4xr-4395 -->

### In Scope

- Changing names, titles, descriptions, schemas, icons, or risk annotations to influence identification, selection, approval, inventory, or policy. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C007; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-2026-schema -->
- Changing those descriptors after approval and presenting the new state without equivalent re-review. <!-- SAF-TRACE: claims=SAF-T1406-C002,SAF-T1406-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cursor-ghsa-24mc-g4xr-4395 -->
- Metadata-only deception demonstrated in MCP or a matching agentic tool-selection boundary. <!-- SAF-TRACE: claims=SAF-T1406-C002,SAF-T1406-C003,SAF-T1406-C004; sources=SRC-invariant-tpa-2025-04-01,SRC-arxiv-2508.02110v2,SRC-mcptox-2508.14925 -->

### Out of Scope

- Hostile instructions carried only in retrieved content, without manipulated object metadata. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-mcp-2026-schema,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- Command injection, missing authentication, transport compromise, or payload execution when metadata does not drive the trust error. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-cursor-ghsa-24mc-g4xr-4395,SRC-mcp-2026-schema -->
- Benign descriptor updates that complete equivalent re-review before reuse. <!-- SAF-TRACE: claims=SAF-T1406-C007,SAF-T1406-C010; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-tools-2026-07-28 -->

### Distinguishing Characteristics

The decisive observable is a security-relevant metadata change or misleading metadata baseline at the moment a consumer makes or reuses a trust decision. A later malicious action is follow-on behavior, not required to classify this technique. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-mcp-2026-schema,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cursor-ghsa-24mc-g4xr-4395 -->

## Description

MCP tools expose metadata such as names, titles, descriptions, input schemas, icons, and annotations. The current specification explicitly treats annotations from untrusted servers as non-authoritative hints, yet these descriptors remain inputs to display, model selection, approval, and policy workflows. <!-- SAF-TRACE: claims=SAF-T1406-C001; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-2026-schema -->

An adversary who controls or can update a descriptor can make an object appear benign during review, then alter the descriptor while retaining the earlier approval, or can supply misleading metadata at first discovery. Controlled MCP experiments demonstrate both hostile descriptions and sleeper-style changes after approval. <!-- SAF-TRACE: claims=SAF-T1406-C002,SAF-T1406-C007; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->

The immediate result is a classification or trust error. Data access, command execution, state change, or disruption occurs only if a later consumer action and relevant privilege are present. <!-- SAF-TRACE: claims=SAF-T1406-C007,SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-arxiv-2508.02110v2 -->

## Attack Vectors

- **Primary Vector**: An adversary-controlled server or update path returns misleading tool or server metadata during discovery or refresh. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C007; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-2026-schema -->
- **Secondary Vectors**:
  - A previously approved definition is changed through a repository or local configuration update without a new approval decision. <!-- SAF-TRACE: claims=SAF-T1406-C005,SAF-T1406-C007; sources=SRC-cve-2025-54136,SRC-cursor-ghsa-24mc-g4xr-4395 -->
  - A sleeper server changes descriptive metadata only after establishing an initially benign approval state. <!-- SAF-TRACE: claims=SAF-T1406-C002,SAF-T1406-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01 -->
- **Affected Components**: MCP hosts, clients, servers, discovery or registry services, approval services, policy engines, and monitoring pipelines. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C007; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-2026-schema -->
- **Trust Boundary Crossed**: The producer-to-consumer metadata boundary used for selection, approval, inventory, or policy. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-mcp-2026-schema,SRC-cursor-ghsa-24mc-g4xr-4395 -->

## Technical Details

### Prerequisites

- The adversary can author, replace, or update metadata for an object the consumer can discover or has already approved. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cursor-ghsa-24mc-g4xr-4395 -->
- The consumer uses that metadata in a security-relevant decision or reuses approval without binding it to the reviewed metadata state. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C005,SAF-T1406-C007; sources=SRC-mcp-2026-schema,SRC-cve-2025-54136,SRC-cursor-ghsa-24mc-g4xr-4395 -->
- A downstream consequence requires the misclassified object to be selected or used with relevant access. <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395,SRC-invariant-whatsapp-mcp-2025-04-07 -->

### Attack Flow

1. **Setup**: The adversary obtains control of an object definition or its update path. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cursor-ghsa-24mc-g4xr-4395 -->
2. **Presentation**: The consumer receives metadata that appears benign or differs from the state originally reviewed. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C002; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-tpa-2025-04-01 -->
3. **Trigger**: Discovery, refresh, selection, or invocation causes the current descriptor to be consumed. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C009; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-mcp-scan-2025 -->
4. **Boundary Crossing**: The consumer trusts the descriptor or reuses approval without detecting and reviewing the security-relevant change. <!-- SAF-TRACE: claims=SAF-T1406-C002,SAF-T1406-C005,SAF-T1406-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cve-2025-54136,SRC-cursor-ghsa-24mc-g4xr-4395 -->
5. **Objective**: The object is misclassified as trusted, safe, or appropriate. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-mcp-2026-schema,SRC-invariant-whatsapp-mcp-2025-04-07 -->
6. **Follow-On**: If selected with sufficient access, the object may contribute to disclosure, unauthorized state change, execution, or disruption. <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395,SRC-invariant-whatsapp-mcp-2025-04-07 -->

### Example Scenario

An inert monitoring example records a tool whose description hash differs from the approved hash before any invocation. The fixture represents only the classification boundary and contains no executable instruction, credential, network location, or real server. <!-- SAF-TRACE: claims=SAF-T1406-C007,SAF-T1406-C009; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-mcp-scan-2025 -->

The safe synthetic event shape is: <!-- SAF-TRACE: claims=SAF-T1406-C009; sources=SRC-invariant-mcp-scan-2025,SRC-mcp-tools-2026-07-28 -->

```json
{
  "event_type": "mcp_metadata_snapshot",
  "server_id": "server.synthetic.example",
  "object_type": "tool",
  "object_name": "read_public_note",
  "metadata_hash": "sha256:new-description",
  "approved_metadata_hash": "sha256:approved-description",
  "metadata_changed": true,
  "changed_fields": ["description"],
  "approval_state": "previously_approved"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1406-C001 | MCP defines security-relevant tool metadata and marks annotations as untrusted hints. | Observed protocol behavior | SRC-mcp-tools-2026-07-28 and SRC-mcp-2026-schema | Client compliance was not measured. |
| SAF-T1406-C002 | Controlled demonstrations show hostile and post-approval descriptions altering agent behavior. | Demonstrated | SRC-invariant-tpa-2025-04-01 and SRC-invariant-whatsapp-mcp-2025-04-07 | Researcher-controlled, not a production breach. |
| SAF-T1406-C003 | A malicious-tool-metadata study reported high success and weak content-only auditing in tested settings. | Demonstrated | SRC-arxiv-2508.02110v2 | Synthetic scenarios and bounded models. |
| SAF-T1406-C004 | MCPTox tested 1,312 constructed cases derived from 353 tools on 45 live servers and reported a 72.8% maximum rate. | Demonstrated | SRC-mcptox-2508.14925 | Constructed attacks were not observed on those servers. |
| SAF-T1406-C005 | CVE-2025-54136 disclosed a previously trusted MCP definition bypassing reapproval; version 1.3 is patched. | Observed disclosure | SRC-cve-2025-54136 and SRC-cursor-ghsa-24mc-g4xr-4395 | No production exploitation established; affected-range conflict retained. |
| SAF-T1406-C006 | The reviewed corpus did not establish a qualifying production incident. | Research-Derived | SRC-cisa-kev-2026-09-01, SRC-cve-2025-54136, and SRC-invariant-whatsapp-mcp-2025-04-07 | Bounded absence finding, not proof of non-occurrence. |
| SAF-T1406-C007 | Adversary metadata influence before a decision or reused approval is the defining prerequisite and misclassification the immediate outcome. | Demonstrated | SRC-mcp-2026-schema, SRC-invariant-whatsapp-mcp-2025-04-07, and SRC-cursor-ghsa-24mc-g4xr-4395 | Follow-on harm is separate and conditional. |
| SAF-T1406-C008 | Misclassification can enable confidentiality, integrity, or availability harm only with later trust and access. | Demonstrated | SRC-cursor-ghsa-24mc-g4xr-4395, SRC-invariant-whatsapp-mcp-2025-04-07, and SRC-arxiv-2508.02110v2 | Metadata change alone does not guarantee harm. |
| SAF-T1406-C009 | Canonical current-versus-approved metadata comparison supports a bounded change analytic. | Research-Derived | SRC-mcp-tools-2026-07-28 and SRC-invariant-mcp-scan-2025 | Initial malicious baselines and missing telemetry are blind spots. |
| SAF-T1406-C010 | Legitimate dynamic changes require identity, canonicalization, context, and reapproval tuning. | Research-Derived | SRC-mcp-tools-2026-07-28 and SRC-jamshidi-2026-arxiv-2512-06556 | False-positive rates do not generalize from simulation. |
| SAF-T1406-C011 | Descriptor distrust, identity binding, change verification, and semantic or runtime review are complementary. | Research-Derived | SRC-mcp-2026-schema, SRC-invariant-tpa-2025-04-01, and SRC-jamshidi-2026-arxiv-2512-06556 | Layered-defense results are not production guarantees. |
| SAF-T1406-C012 | ATT&CK T1036 is an analogous, broader mapping. | Research-Derived | SRC-mitre-attack-t1036 | It spans many non-agentic artifact types. |

### Current State

- **Affected Environments**: MCP or agentic systems that consume mutable descriptors for selection, approval, inventory, or policy without binding the decision to the reviewed metadata state. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C007; sources=SRC-mcp-2026-schema,SRC-cursor-ghsa-24mc-g4xr-4395 -->
- **Known Exploitation**: One direct disclosed vulnerability and multiple controlled demonstrations qualify; no reviewed direct authority established production exploitation of the exact mechanism. <!-- SAF-TRACE: claims=SAF-T1406-C002,SAF-T1406-C005,SAF-T1406-C006; sources=SRC-cve-2025-54136,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Treat annotations as untrusted, bind approval to canonical metadata and identity, re-review drift, and layer semantic or runtime controls. <!-- SAF-TRACE: claims=SAF-T1406-C011; sources=SRC-mcp-2026-schema,SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Residual Risk**: Integrity monitoring cannot identify a malicious descriptor accepted as the initial baseline and loses visibility when discovery or approval telemetry is incomplete. <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C011; sources=SRC-invariant-mcp-scan-2025,SRC-jamshidi-2026-arxiv-2512-06556 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-54136 / GHSA-24mc-g4xr-4395 <!-- SAF-TRACE: claims=SAF-T1406-C005; sources=SRC-cve-2025-54136,SRC-cursor-ghsa-24mc-g4xr-4395 --> | 2025; Cursor MCP trust workflow <!-- SAF-TRACE: claims=SAF-T1406-C005; sources=SRC-cve-2025-54136,SRC-cursor-ghsa-24mc-g4xr-4395 --> | Prior approval could be reused after definition replacement; upgrade to 1.3 or later. <!-- SAF-TRACE: claims=SAF-T1406-C005; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> | Direct vulnerability <!-- SAF-TRACE: claims=SAF-T1406-C005; sources=SRC-cve-2025-54136 --> | Disclosure, not a production incident; sources conflict on affected lower bound. <!-- SAF-TRACE: claims=SAF-T1406-C005,SAF-T1406-C006; sources=SRC-cve-2025-54136,SRC-cursor-ghsa-24mc-g4xr-4395 --> |
| WhatsApp MCP sleeper-server experiment <!-- SAF-TRACE: claims=SAF-T1406-C002; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> | 2025; controlled Cursor and WhatsApp test <!-- SAF-TRACE: claims=SAF-T1406-C002; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> | Post-approval descriptor change produced disclosure in the test; surface and reapprove changes. <!-- SAF-TRACE: claims=SAF-T1406-C002,SAF-T1406-C011; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01 --> | Direct demonstration <!-- SAF-TRACE: claims=SAF-T1406-C002; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> | Researcher-controlled and partly model-dependent. <!-- SAF-TRACE: claims=SAF-T1406-C002; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| Malicious tool metadata study <!-- SAF-TRACE: claims=SAF-T1406-C003; sources=SRC-arxiv-2508.02110v2 --> | 2025-2026; simulated MCP tool-use scenarios <!-- SAF-TRACE: claims=SAF-T1406-C003; sources=SRC-arxiv-2508.02110v2 --> | Metadata altered behavior in tested settings; combine integrity, least privilege, and runtime review. <!-- SAF-TRACE: claims=SAF-T1406-C003,SAF-T1406-C011; sources=SRC-arxiv-2508.02110v2,SRC-jamshidi-2026-arxiv-2512-06556 --> | Direct demonstration <!-- SAF-TRACE: claims=SAF-T1406-C003; sources=SRC-arxiv-2508.02110v2 --> | Simulated scenarios and public data, not a live deployment. <!-- SAF-TRACE: claims=SAF-T1406-C003; sources=SRC-arxiv-2508.02110v2 --> |
| MCPTox benchmark <!-- SAF-TRACE: claims=SAF-T1406-C004; sources=SRC-mcptox-2508.14925 --> | 2025; authentic definitions with constructed cases <!-- SAF-TRACE: claims=SAF-T1406-C004; sources=SRC-mcptox-2508.14925 --> | Broad susceptibility in evaluated settings supports descriptor vetting and privilege restriction. <!-- SAF-TRACE: claims=SAF-T1406-C004,SAF-T1406-C011; sources=SRC-mcptox-2508.14925,SRC-jamshidi-2026-arxiv-2512-06556 --> | Direct demonstration <!-- SAF-TRACE: claims=SAF-T1406-C004; sources=SRC-mcptox-2508.14925 --> | Single-turn constructed attacks were not observed on live servers. <!-- SAF-TRACE: claims=SAF-T1406-C004; sources=SRC-mcptox-2508.14925 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> | High <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> | Sensitive disclosure requires later use of the misclassified object with data access. <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| Integrity <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> | High <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> | Approval and selection integrity are directly affected; downstream state change requires privilege. <!-- SAF-TRACE: claims=SAF-T1406-C007,SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> |
| Availability <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> | Medium <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> | Disruption is possible only through separate follow-on behavior and relevant access. <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> |
| Scope <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-arxiv-2508.02110v2 --> | Adjacent to Multi-System <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-arxiv-2508.02110v2 --> | Blast radius follows the host's connected services, permissions, and automation. <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-arxiv-2508.02110v2,SRC-invariant-whatsapp-mcp-2025-04-07 --> |

### Severity Conditions

- **Severity increases when** the host has broad credentials, automatic invocation, sensitive context, or cross-service access. <!-- SAF-TRACE: claims=SAF-T1406-C008; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cursor-ghsa-24mc-g4xr-4395 -->
- **Severity decreases when** descriptors are bound to stable identity and approval, privileges are scoped, and changes are reviewed before use. <!-- SAF-TRACE: claims=SAF-T1406-C010,SAF-T1406-C011; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-tpa-2025-04-01,SRC-jamshidi-2026-arxiv-2512-06556 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host metadata-integrity log <!-- SAF-TRACE: claims=SAF-T1406-C009; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-mcp-scan-2025 --> | Discovery, list change, refresh, approval, and pre-invocation snapshot <!-- SAF-TRACE: claims=SAF-T1406-C009; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-mcp-scan-2025 --> | Time, session, stable server and object identity, canonical current and approved hashes, changed fields, and approval state <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C010; sources=SRC-invariant-mcp-scan-2025,SRC-mcp-tools-2026-07-28 --> | Preserve canonicalization version and join changes to completed reapproval. <!-- SAF-TRACE: claims=SAF-T1406-C010; sources=SRC-mcp-tools-2026-07-28,SRC-jamshidi-2026-arxiv-2512-06556 --> |

### Indicators of Compromise (IoCs)

- No universal durable IoC exists; metadata values and hashes are deployment-specific. <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C010; sources=SRC-invariant-mcp-scan-2025,SRC-mcp-tools-2026-07-28 -->

### Behavioral Indicators

- A current canonical metadata hash differs from the approved hash for the same stable object identity. <!-- SAF-TRACE: claims=SAF-T1406-C009; sources=SRC-invariant-mcp-scan-2025 -->
- Security-relevant fields change after approval without a corresponding review record. <!-- SAF-TRACE: claims=SAF-T1406-C002,SAF-T1406-C009; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-mcp-scan-2025 -->
- Confidence increases when a risk-lowering annotation, description, name, or schema change precedes selection or invocation. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C009; sources=SRC-mcp-2026-schema,SRC-invariant-mcp-scan-2025 -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect unapproved drift in security-relevant MCP tool or server metadata. <!-- SAF-TRACE: claims=SAF-T1406-C009; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-mcp-scan-2025 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1406-C009; sources=SRC-invariant-mcp-scan-2025 -->
- **Detection Logic**: Require a metadata snapshot, verified canonical drift, a watched field, and no completed reapproval. <!-- SAF-TRACE: claims=SAF-T1406-C007,SAF-T1406-C009; sources=SRC-invariant-mcp-scan-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Correlation Window**: Bind the latest snapshot to the exact approval version rather than relying on a fixed time window. <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C010; sources=SRC-invariant-mcp-scan-2025,SRC-mcp-tools-2026-07-28 -->
- **Known False Positives**: Approved upgrades, localization, schema changes, and canonicalization migrations whose approval record arrives late. <!-- SAF-TRACE: claims=SAF-T1406-C010; sources=SRC-mcp-tools-2026-07-28,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Known Limitations**: Initial malicious baselines, unstable identity, incomplete discovery logs, and semantic deception without hash drift. <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C011; sources=SRC-invariant-mcp-scan-2025,SRC-jamshidi-2026-arxiv-2512-06556 -->
- **Tuning Guidance**: Canonicalize deterministically, bind approval to server and object identity, and suppress only after equivalent review. <!-- SAF-TRACE: claims=SAF-T1406-C010,SAF-T1406-C011; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-tpa-2025-04-01 -->

### Validation

- **Test Data**: [test-events.json](../../tests/SAF-T1406/test-events.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1406/test_detection_rule.py)
- **Expected Result**: [All seven inert fixtures match their declared alert outcome](../../tests/SAF-T1406/test-events.json).
- **Last Validated**: [2026-09-01](../../research/techniques/SAF-T1406/quality-review.yml)
- **Feasibility Waiver**: [None; deterministic isolated validation is available](../../research/techniques/SAF-T1406/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. Treat untrusted server annotations and descriptions as claims, not authorization facts. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C011; sources=SRC-mcp-2026-schema,SRC-invariant-tpa-2025-04-01 -->
2. Bind each approval to canonical metadata, stable server and object identity, and a reviewed version; require equivalent review after drift. <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C011; sources=SRC-invariant-mcp-scan-2025,SRC-invariant-tpa-2025-04-01 -->
3. Limit tool and server privileges so a classification failure does not automatically expose unrelated data or services. <!-- SAF-TRACE: claims=SAF-T1406-C008,SAF-T1406-C011; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-jamshidi-2026-arxiv-2512-06556 -->
4. Add semantic and runtime checks because integrity verification alone accepts a malicious first baseline. <!-- SAF-TRACE: claims=SAF-T1406-C011; sources=SRC-jamshidi-2026-arxiv-2512-06556,SRC-invariant-tpa-2025-04-01 -->

### Detective Controls

1. Collect and compare canonical descriptors at discovery, list change, approval, and invocation. <!-- SAF-TRACE: claims=SAF-T1406-C009; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-mcp-scan-2025 -->
2. Prioritize unapproved risk-lowering or identity-changing fields and correlate them with later selection. <!-- SAF-TRACE: claims=SAF-T1406-C001,SAF-T1406-C009; sources=SRC-mcp-2026-schema,SRC-invariant-mcp-scan-2025 -->

### Response Procedures

#### Immediate Actions

- Suspend the changed object from automatic selection and preserve both current and approved canonical snapshots. <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C011; sources=SRC-invariant-mcp-scan-2025,SRC-invariant-tpa-2025-04-01 -->
- Revoke approval for the affected object version and scope connected credentials if the object was used after drift. <!-- SAF-TRACE: claims=SAF-T1406-C008,SAF-T1406-C011; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-jamshidi-2026-arxiv-2512-06556 -->

#### Investigation Steps

- Determine who or what changed each descriptor and whether the stable server or object identity also changed. <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C010; sources=SRC-invariant-mcp-scan-2025,SRC-mcp-tools-2026-07-28 -->
- Correlate drift with discovery, approval, selection, invocation, and connected-service access. <!-- SAF-TRACE: claims=SAF-T1406-C008,SAF-T1406-C009; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-mcp-scan-2025 -->

#### Remediation

- Restore a reviewed descriptor state, patch affected clients, and reapprove only after identity and metadata verification. <!-- SAF-TRACE: claims=SAF-T1406-C005,SAF-T1406-C011; sources=SRC-cursor-ghsa-24mc-g4xr-4395,SRC-invariant-tpa-2025-04-01 -->
- Add regression fixtures for the changed field and validate that stale approvals no longer authorize the new state. <!-- SAF-TRACE: claims=SAF-T1406-C009,SAF-T1406-C010; sources=SRC-invariant-mcp-scan-2025,SRC-jamshidi-2026-arxiv-2512-06556 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-mcp-2026-schema --> | Alternative input boundary <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-mcp-2026-schema --> | Hostile instructions arrive in runtime content rather than object metadata used for selection or approval. <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-mcp-2026-schema,SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| [SAF-T1205: Persistent Tool Redefinition](../SAF-T1205/README.md) <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> | Overlapping update path <!-- SAF-TRACE: claims=SAF-T1406-C007; sources=SRC-cursor-ghsa-24mc-g4xr-4395 --> | Persistent redefinition requires a post-trust change; metadata manipulation belongs here when misleading or unreviewed metadata produces the trust error. <!-- SAF-TRACE: claims=SAF-T1406-C005,SAF-T1406-C007; sources=SRC-cve-2025-54136,SRC-cursor-ghsa-24mc-g4xr-4395 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1036](https://attack.mitre.org/techniques/T1036/) <!-- SAF-TRACE: claims=SAF-T1406-C012; sources=SRC-mitre-attack-t1036 --> | Masquerading <!-- SAF-TRACE: claims=SAF-T1406-C012; sources=SRC-mitre-attack-t1036 --> | Analogous <!-- SAF-TRACE: claims=SAF-T1406-C012; sources=SRC-mitre-attack-t1036 --> | Both manipulate artifact features or metadata to appear benign, but T1036 is broader than the agentic object-metadata and trust-decision boundary here. <!-- SAF-TRACE: claims=SAF-T1406-C012; sources=SRC-mitre-attack-t1036 --> |

## References

1. **SRC-mcp-tools-2026-07-28**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — current tool fields, list changes, and security guidance.
2. **SRC-mcp-2026-schema**: [MCP Schema reference](https://modelcontextprotocol.io/specification/2026-07-28/schema) — annotation semantics and trust warning.
3. **SRC-invariant-tpa-2025-04-01**: [MCP Security Notification — Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — Luca Beurer-Kellner and Marc Fischer; controlled demonstrations and mitigations.
4. **SRC-invariant-whatsapp-mcp-2025-04-07**: [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) — Luca Beurer-Kellner and Marc Fischer; controlled sleeper-server demonstration.
5. **SRC-invariant-mcp-scan-2025**: [Introducing MCP-scan](https://invariantlabs.ai/blog/introducing-mcp-scan) — descriptor retrieval, hashing, and comparison design.
6. **SRC-cve-2025-54136**: [CVE-2025-54136 record](https://cveawg.mitre.org/api/cve/CVE-2025-54136) — official vulnerability record and GitHub advisory provenance.
7. **SRC-cursor-ghsa-24mc-g4xr-4395**: [Cursor MCP reapproval bypass advisory](https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395) — impact, remediation, and credits.
8. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — dated exact-identifier catalog check.
9. **SRC-arxiv-2508.02110v2**: [Attacking Model Context Protocol via Malicious Tool Metadata](https://arxiv.org/abs/2508.02110) — Kanghua Mo, Li Hu, Yucheng Long, and Zhihao Li; controlled evaluation and limitations.
10. **SRC-mcptox-2508.14925**: [MCPTox](https://arxiv.org/abs/2508.14925) — Zhiqiang Wang and coauthors; benchmark design, results, and limitations.
11. **SRC-jamshidi-2026-arxiv-2512-06556**: [Semantic Descriptor Attacks on MCP Tool Selection](https://arxiv.org/abs/2512.06556) — Saeid Jamshidi, Arghavan Moradi Dakhel, Kawser Wazed Nafi, Foutse Khomh, and SWAT Lab; layered defenses and limitations.
12. **SRC-mitre-attack-t1036**: [MITRE ATT&CK T1036 Masquerading](https://attack.mitre.org/techniques/T1036/) — analogous framework mapping.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Initial clean-room draft | OpenAI Codex |
