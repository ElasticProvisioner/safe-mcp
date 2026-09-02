# SAF-T1404: Response Tampering

## Overview

- **Tactic**: Defense Evasion (ATK-TA0005)
- **Technique ID**: SAF-T1404
- **Research Packet**: [research/techniques/SAF-T1404](../../research/techniques/SAF-T1404/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1404/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A trusted-looking altered result can change model decisions or downstream actions, but impact depends on the result's authority and the automation allowed after consumption. <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C004; sources=SRC-zhan-aei-2026 -->
- **First Observed**: Not observed in production in the bounded corpus; directly demonstrated in controlled research and a disclosed proof of concept. <!-- SAF-TRACE: claims=SAF-T1404-C005, SAF-T1404-C008; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-01

## Scope

Response Tampering covers modification, substitution, or misrouting after an MCP operation emits a response and before a host, model, or downstream application consumes it as authentic. <!-- SAF-TRACE: claims=SAF-T1404-C002; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002 -->

### In Scope

- Changing structured or unstructured result content in transit or in an intermediary after a legitimate invocation. <!-- SAF-TRACE: claims=SAF-T1404-C002; sources=SRC-cwe-924, SRC-capec-384 -->
- Substituting an attacker-controlled upstream or misrouting one correlated result to another client or request. <!-- SAF-TRACE: claims=SAF-T1404-C005, SAF-T1404-C006; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p -->

### Out of Scope

- Instructions planted in tool metadata before invocation and attacker-changed request arguments belong to discovery or request-side behaviors, not this response-side boundary. <!-- SAF-TRACE: claims=SAF-T1404-C002; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002 -->
- Faithfully returned hostile source content is ordinary indirect prompt injection unless the result is also modified, substituted, or provenance-confused after emission. <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C011; sources=SRC-cwe-924, SRC-capec-384, SRC-mcp-tools-2026-07-28, SRC-zhan-aei-2026 -->
- Downstream code execution, credential theft, or data destruction is follow-on impact rather than the defining response-integrity failure. <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C007; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-ghsa-5ire-8527, SRC-nvd-mcp-catalog-2026-09-01 -->

### Distinguishing Characteristics

Analysts should identify two representations of the same correlated result and ask whether content or provenance changed between producer-side receipt and consumption; request mutation or faithfully retrieved hostile content lacks that response-path delta. <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C009; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->

## Description

An adversary uses Response Tampering to make an MCP consumer accept data that is not the authentic result of the invoked operation. The manipulated object may be text, structured content, an embedded resource, or result routing and framing that determines which consumer receives it. <!-- SAF-TRACE: claims=SAF-T1404-C001, SAF-T1404-C002; sources=SRC-mcp-tools-2026-07-28, SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002 -->

The boundary starts when a response is emitted or received at a trusted transport checkpoint and ends immediately before the result enters model context or a downstream workflow. The current Streamable HTTP transport relates response-stream messages to an originating request and validates routing metadata, but those checks do not authenticate the semantic truth of result values. <!-- SAF-TRACE: claims=SAF-T1404-C011, SAF-T1404-C013; sources=SRC-mcp-tools-2026-07-28, SRC-zhan-aei-2026, SRC-mcp-streamable-http-2026-07-28 -->

The end-to-end behavior is demonstrated in a controlled MCP-compatible proxy and in an advisory where a fetcher could be redirected so attacker-originated content appeared as enterprise tool results. This packet does not elevate either source into evidence of a production breach. <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C005, SAF-T1404-C008; sources=SRC-zhan-aei-2026, SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-cisa-kev-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: An intermediary or server-side adapter transforms a legitimate result before host or model consumption. <!-- SAF-TRACE: claims=SAF-T1404-C003; sources=SRC-zhan-aei-2026 -->
- **Secondary Vectors**: An upstream-address weakness substitutes the response origin, or unsafe shared transport state associates a response with the wrong client. <!-- SAF-TRACE: claims=SAF-T1404-C005, SAF-T1404-C006; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-ghsa-ts-sdk-345p -->
- **Affected Components**: MCP hosts and clients, servers and upstream adapters, Streamable HTTP or stdio intermediaries, and context-assembly or result-validation layers. <!-- SAF-TRACE: claims=SAF-T1404-C001, SAF-T1404-C013; sources=SRC-mcp-tools-2026-07-28, SRC-mcp-streamable-http-2026-07-28 -->
- **Trust Boundary Crossed**: The integrity and provenance boundary between a correlated operation result and the representation accepted for model or application use. <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C009; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->

## Technical Details

### Prerequisites

- The adversary must influence a response-producing upstream, adapter, intermediary, or shared routing state after invocation. <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C005, SAF-T1404-C006; sources=SRC-zhan-aei-2026, SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-ghsa-ts-sdk-345p -->
- The consumer must lack an independent provenance check or accept schema-valid content as sufficiently trustworthy. <!-- SAF-TRACE: claims=SAF-T1404-C011; sources=SRC-mcp-tools-2026-07-28, SRC-zhan-aei-2026 -->

### Attack Flow

1. **Setup**: The adversary gains influence over an intermediary or directs a vulnerable adapter toward an attacker-controlled upstream. <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C005; sources=SRC-zhan-aei-2026, SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01 -->
2. **Invocation**: The host makes a legitimate MCP operation and expects its correlated result. <!-- SAF-TRACE: claims=SAF-T1404-C001, SAF-T1404-C013; sources=SRC-mcp-tools-2026-07-28, SRC-mcp-streamable-http-2026-07-28 -->
3. **Transformation or substitution**: The response content, origin, or association is changed before consumption. <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C003, SAF-T1404-C005, SAF-T1404-C006; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-zhan-aei-2026, SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p -->
4. **Acceptance**: Structural validation succeeds or provenance is not independently verified, so the result is admitted to model context or downstream logic. <!-- SAF-TRACE: claims=SAF-T1404-C011; sources=SRC-mcp-tools-2026-07-28, SRC-zhan-aei-2026 -->
5. **Objective**: The consumer reasons or acts on inauthentic content while attributing it to the invoked operation. <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C004; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-zhan-aei-2026 -->

### Example Scenario

A research assistant invokes an inert record lookup. An intermediary changes one result field after trusted receipt, and the altered field is then consumed as though returned by the original server; the paired digests differ for the same request and trace. <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C009; sources=SRC-zhan-aei-2026, SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->

The following sanitized message shows only the minimum integrity-changing field and contains no executable content. <!-- SAF-TRACE: claims=SAF-T1404-C003; sources=SRC-zhan-aei-2026 -->

```json
{
  "request_id": 17,
  "trusted_receipt": {"status": "approved"},
  "pre_consumption": {"status": "denied"}
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1404-C001 | MCP defines multiple result forms and expects client-side result validation and tool-use logging. | Demonstrated | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | No mandatory end-to-end content signature is specified. | <!-- SAF-TRACE: claims=SAF-T1404-C001; sources=SRC-mcp-tools-2026-07-28 -->
| SAF-T1404-C002 | The SAF technique specializes established message-integrity and transmitted-data manipulation concepts to MCP results. | Research-Derived | SRC-cwe-924; SRC-capec-384; SRC-attack-t1565-002 | The SAF boundary is a framework synthesis. | <!-- SAF-TRACE: claims=SAF-T1404-C002; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002 -->
| SAF-T1404-C003 | A controlled MCP-compatible proxy intercepted and transformed responses before returning them to agents. | Demonstrated | SRC-zhan-aei-2026: [Zhan et al.](https://arxiv.org/abs/2604.18874) | Controlled frozen datasets; no production compromise. | <!-- SAF-TRACE: claims=SAF-T1404-C003; sources=SRC-zhan-aei-2026 -->
| SAF-T1404-C004 | Controlled poisoned and structural results changed decisions or consumed step budgets, with material agent and engagement variation. | Demonstrated | SRC-zhan-aei-2026 | Results are not production prevalence estimates. | <!-- SAF-TRACE: claims=SAF-T1404-C004; sources=SRC-zhan-aei-2026 -->
| SAF-T1404-C005 | A disclosed adapter weakness allowed attacker-originated data to appear as Jira or Confluence tool results. | Demonstrated | SRC-ghsa-mcp-atlassian-7r34; SRC-nvd-mcp-catalog-2026-09-01 | Advisory proof of concept, not a breach report. | <!-- SAF-TRACE: claims=SAF-T1404-C005; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01 -->
| SAF-T1404-C006 | Shared TypeScript SDK transport state could misroute responses across clients. | Demonstrated | SRC-ghsa-ts-sdk-345p; SRC-nvd-mcp-catalog-2026-09-01 | Adjacent concurrency defect, not intentional rewriting. | <!-- SAF-TRACE: claims=SAF-T1404-C006; sources=SRC-ghsa-ts-sdk-345p, SRC-nvd-mcp-catalog-2026-09-01 -->
| SAF-T1404-C007 | A client rendering flaw listed compromised MCP content as one delivery vector for unsafe evaluation. | Demonstrated | SRC-ghsa-5ire-8527; SRC-nvd-mcp-catalog-2026-09-01 | Downstream unsafe evaluation is the root weakness. | <!-- SAF-TRACE: claims=SAF-T1404-C007; sources=SRC-ghsa-5ire-8527, SRC-nvd-mcp-catalog-2026-09-01 -->
| SAF-T1404-C008 | The reviewed corpus established vulnerabilities and demonstrations but no qualifying direct production breach. | Research-Derived | SRC-nvd-mcp-catalog-2026-09-01; SRC-cisa-kev-2026-09-01 | Bounded corpus finding, not universal absence. | <!-- SAF-TRACE: claims=SAF-T1404-C008; sources=SRC-nvd-mcp-catalog-2026-09-01, SRC-cisa-kev-2026-09-01 -->
| SAF-T1404-C009 | A paired canonical-digest mismatch can detect post-receipt modification. | Research-Derived | SRC-attack-t1565-002; SRC-rfc8785; SRC-mcp-tools-2026-07-28 | Cannot see content already corrupted at first receipt. | <!-- SAF-TRACE: claims=SAF-T1404-C009; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->
| SAF-T1404-C010 | Common canonicalization and authorized-transform metadata prevent benign digest mismatches. | Research-Derived | SRC-rfc8785 | Authorization metadata is implementation-specific. | <!-- SAF-TRACE: claims=SAF-T1404-C010; sources=SRC-rfc8785 -->
| SAF-T1404-C011 | Output schemas constrain structure but do not establish truth or provenance. | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-zhan-aei-2026 | Independent provenance controls are implementation-specific. | <!-- SAF-TRACE: claims=SAF-T1404-C011; sources=SRC-mcp-tools-2026-07-28, SRC-zhan-aei-2026 -->
| SAF-T1404-C012 | Response should isolate the path, preserve correlated telemetry, localize the change, and remediate the implicated component. | Research-Derived | SRC-ghsa-mcp-atlassian-7r34; SRC-ghsa-ts-sdk-345p; SRC-nist-sp800-61r3 | Exact containment depends on deployment. | <!-- SAF-TRACE: claims=SAF-T1404-C012; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p, SRC-nist-sp800-61r3 -->
| SAF-T1404-C013 | Streamable HTTP associates response streams with requests and validates routing metadata. | Demonstrated | SRC-mcp-streamable-http-2026-07-28 | Routing checks do not authenticate semantic content. | <!-- SAF-TRACE: claims=SAF-T1404-C013; sources=SRC-mcp-streamable-http-2026-07-28 -->

### Current State

- **Affected Environments**: Hosts that accept results through modifiable intermediaries, redirectable upstream adapters, or incorrectly shared routing state. <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C005, SAF-T1404-C006; sources=SRC-zhan-aei-2026, SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-ghsa-ts-sdk-345p -->
- **Known Exploitation**: Controlled demonstrations and proof-of-concept evidence exist; production exploitation was not established in the reviewed corpus. <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C005, SAF-T1404-C008; sources=SRC-zhan-aei-2026, SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Patched adapter and SDK releases address the two selected implementation flaws; protocol result validation and paired provenance telemetry address separate parts of the risk. <!-- SAF-TRACE: claims=SAF-T1404-C001, SAF-T1404-C005, SAF-T1404-C006, SAF-T1404-C009; sources=SRC-mcp-tools-2026-07-28, SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-ghsa-ts-sdk-345p, SRC-attack-t1565-002, SRC-rfc8785 -->
- **Residual Risk**: Schema-valid false values, already-corrupted first-checkpoint content, and uninstrumented transformations remain blind spots. <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C010, SAF-T1404-C011; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28, SRC-zhan-aei-2026 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| POTEMKIN man-in-the-tool study | 2026; controlled MCP-compatible citation agents | Modified results changed decisions or consumed steps; evaluated defenses retained utility/security tradeoffs. | Direct demonstration | Frozen controlled domain; no production breach. | <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C004; sources=SRC-zhan-aei-2026 -->
| CVE-2026-27826 / GHSA-7r34-79r5-rcc9 | 2026; mcp-atlassian before 0.17.0 | Attacker-selected upstream content could appear as Jira or Confluence results; fixed in 0.17.0. | Direct vulnerability | Proof of concept; no production breach established. | <!-- SAF-TRACE: claims=SAF-T1404-C005; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01 -->
| CVE-2026-25536 / GHSA-345p-7cg4-v4c7 | 2026; TypeScript SDK 1.10.0 through 1.25.3 with shared instances | Responses could cross client boundaries; fixed in 1.26.0 with reuse guards. | Adjacent provenance confusion | Concurrency defect; intentional attacker rewriting not established. | <!-- SAF-TRACE: claims=SAF-T1404-C006; sources=SRC-ghsa-ts-sdk-345p, SRC-nvd-mcp-catalog-2026-09-01 -->

### Real-World Incidents or Demonstrations

No qualifying direct production incident was identified. The most direct empirical evidence is the controlled POTEMKIN study; its clean baselines and engagement-conditioned reporting support mechanism claims, while its frozen citation domain and model variation constrain generalization. <!-- SAF-TRACE: claims=SAF-T1404-C003, SAF-T1404-C004, SAF-T1404-C008; sources=SRC-zhan-aei-2026, SRC-nvd-mcp-catalog-2026-09-01, SRC-cisa-kev-2026-09-01 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Medium | Altered results may steer follow-on collection, but disclosure requires a later action and sufficient tool authority. | <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C004; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-zhan-aei-2026 -->
| Integrity | High | The defining objective is acceptance of inauthentic content that can change decisions or workflow state. | <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C004; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-zhan-aei-2026 -->
| Availability | Medium | Structural manipulation can waste bounded agent steps, but availability is not required for the technique. | <!-- SAF-TRACE: claims=SAF-T1404-C004; sources=SRC-zhan-aei-2026 -->
| Scope | Multi-System | A shared adapter or transport can affect multiple consumers, while isolated correctly configured instances limit blast radius. | <!-- SAF-TRACE: claims=SAF-T1404-C005, SAF-T1404-C006; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p, SRC-nvd-mcp-catalog-2026-09-01 -->

### Severity Conditions

- **Severity increases when** results authorize high-impact automated actions, intermediaries serve many clients, or provenance is not independently checked. <!-- SAF-TRACE: claims=SAF-T1404-C004, SAF-T1404-C006, SAF-T1404-C011; sources=SRC-zhan-aei-2026, SRC-ghsa-ts-sdk-345p, SRC-nvd-mcp-catalog-2026-09-01, SRC-mcp-tools-2026-07-28 -->
- **Severity decreases when** result consumers are isolated, actions require approval, upstream destinations are fixed, and both integrity checkpoints are monitored. <!-- SAF-TRACE: claims=SAF-T1404-C005, SAF-T1404-C006, SAF-T1404-C009; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-ghsa-ts-sdk-345p, SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Trusted MCP transport receipt | Canonical digest for each received result | timestamp, trace ID, request ID, server identity, tool name, canonical SHA-256 | Record before mutable application transforms. | <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C013; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28, SRC-mcp-streamable-http-2026-07-28 -->
| Pre-consumption context assembly | Canonical digest and transformation decision | matching correlation fields, digest, transform authorization, transform type | Use the same canonicalization and binary convention as receipt. | <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C010; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->

### Indicators of Compromise (IoCs)

- No universal durable indicator is established; the technique is identified through correlated integrity telemetry rather than a fixed attacker artifact. <!-- SAF-TRACE: claims=SAF-T1404-C009; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->

### Behavioral Indicators

- The same trace, request, server, and tool identifiers carry different canonical result digests at receipt and consumption without an authorized transformation. <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C010; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->
- A result's observed origin or client association differs from the invocation's configured upstream or isolated routing state. <!-- SAF-TRACE: claims=SAF-T1404-C005, SAF-T1404-C006, SAF-T1404-C013; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01, SRC-ghsa-ts-sdk-345p, SRC-mcp-streamable-http-2026-07-28 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect unexplained post-receipt MCP result modification. <!-- SAF-TRACE: claims=SAF-T1404-C009; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->
- **Detection Logic**: Correlate both checkpoints and alert on a canonical digest mismatch unless an approved transformation is recorded. <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C010; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->
- **Correlation Window**: The lifecycle of one correlated request from trusted receipt through consumption. <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C013; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28, SRC-mcp-streamable-http-2026-07-28 -->
- **Known False Positives**: Unmarked redaction, normalization, encoding conversion, or inconsistent canonicalization. <!-- SAF-TRACE: claims=SAF-T1404-C010; sources=SRC-rfc8785 -->
- **Known Limitations**: Already-corrupted first receipt, absent checkpoints, and unstable binary encodings remain blind spots. <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C010; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->
- **Tuning Guidance**: Authorize transforms narrowly by type and component, and investigate missing checkpoints separately from content mismatches. <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C010; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1404/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1404/test_detection_rule.py)
- **Expected Result**: [Five of five cases pass](../../tests/SAF-T1404/test_detection_rule.py): one alert, three no-alert outcomes, and one insufficient-telemetry outcome.
- **Last Validated**: [2026-09-01](../../tests/SAF-T1404/test_detection_rule.py)
- **Feasibility Waiver**: [None](../../tests/SAF-T1404/test_detection_rule.py).

## Mitigation Strategies

### Preventive Controls

1. Fix response origins and validate redirect targets; upgrade mcp-atlassian to 0.17.0 or later where applicable. <!-- SAF-TRACE: claims=SAF-T1404-C005; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-nvd-mcp-catalog-2026-09-01 -->
2. Keep server and transport instances isolated per client and upgrade the TypeScript SDK to 1.26.0 or later where affected. <!-- SAF-TRACE: claims=SAF-T1404-C006; sources=SRC-ghsa-ts-sdk-345p, SRC-nvd-mcp-catalog-2026-09-01 -->
3. Validate result structure before model use, while treating schema conformance as distinct from truth and provenance. <!-- SAF-TRACE: claims=SAF-T1404-C001, SAF-T1404-C011; sources=SRC-mcp-tools-2026-07-28, SRC-zhan-aei-2026 -->

### Detective Controls

1. Capture canonical digests at trusted receipt and pre-consumption, bound to the same trace, request, server, and tool identifiers. <!-- SAF-TRACE: claims=SAF-T1404-C009; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->
2. Record authorized redaction or normalization so legitimate changes are explainable and suppressible. <!-- SAF-TRACE: claims=SAF-T1404-C010; sources=SRC-rfc8785 -->

### Response Procedures

#### Immediate Actions

- Isolate the implicated result path and pause automated consumption for the affected server, tool, or session. <!-- SAF-TRACE: claims=SAF-T1404-C012; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p, SRC-nist-sp800-61r3 -->
- Preserve both result representations and their request, identity, transport, and transformation metadata. <!-- SAF-TRACE: claims=SAF-T1404-C012; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p, SRC-nist-sp800-61r3 -->

#### Investigation Steps

- Determine whether the first trusted-receipt record was already substituted, or whether a later component changed it before consumption. <!-- SAF-TRACE: claims=SAF-T1404-C009, SAF-T1404-C012; sources=SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28, SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p, SRC-nist-sp800-61r3 -->
- Review upstream destination controls, transport-instance ownership, and correlated results for other affected clients. <!-- SAF-TRACE: claims=SAF-T1404-C005, SAF-T1404-C006, SAF-T1404-C012; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p, SRC-nvd-mcp-catalog-2026-09-01, SRC-nist-sp800-61r3 -->

#### Remediation

- Patch or reconfigure the implicated adapter or SDK, remove unauthorized intermediaries, restore from a verified response source, and rerun paired-digest regression tests before resuming automation. <!-- SAF-TRACE: claims=SAF-T1404-C005, SAF-T1404-C006, SAF-T1404-C012; sources=SRC-ghsa-mcp-atlassian-7r34, SRC-ghsa-ts-sdk-345p, SRC-nvd-mcp-catalog-2026-09-01, SRC-nist-sp800-61r3 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Co-occurring | Prompt injection can be faithfully present in retrieved content; Response Tampering requires post-emission modification, substitution, or provenance confusion. | <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C011; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-mcp-tools-2026-07-28, SRC-zhan-aei-2026 -->
| [SAF-T1309: Privileged Tool Invocation via Prompt Manipulation](../SAF-T1309/README.md) | Alternative | SAF-T1309 changes model-controlled tool selection or arguments before invocation; Response Tampering changes the result side after execution. | <!-- SAF-TRACE: claims=SAF-T1404-C002; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002 -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1565.002](https://attack.mitre.org/techniques/T1565/002/) | Transmitted Data Manipulation | Analogous | Both change transmitted data to affect decisions; the ATT&CK entry is enterprise-wide rather than MCP-result specific. | <!-- SAF-TRACE: claims=SAF-T1404-C002, SAF-T1404-C009; sources=SRC-cwe-924, SRC-capec-384, SRC-attack-t1565-002, SRC-rfc8785, SRC-mcp-tools-2026-07-28 -->

## References

1. **SRC-mcp-tools-2026-07-28**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), accessed 2026-09-01.
2. **SRC-mcp-streamable-http-2026-07-28**: [MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), accessed 2026-09-01.
3. **SRC-cwe-924**: [CWE-924](https://cwe.mitre.org/data/definitions/924.html), accessed 2026-09-01.
4. **SRC-capec-384**: [CAPEC-384](https://capec.mitre.org/data/definitions/384.html), accessed 2026-09-01.
5. **SRC-attack-t1565-002**: [ATT&CK T1565.002](https://attack.mitre.org/techniques/T1565/002/), accessed 2026-09-01.
6. **SRC-zhan-aei-2026**: [Zhan et al., How Adversarial Environments Mislead Agentic AI?](https://arxiv.org/abs/2604.18874), 2026.
7. **SRC-ghsa-mcp-atlassian-7r34**: [GHSA-7r34-79r5-rcc9](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-7r34-79r5-rcc9), accessed 2026-09-01; exact URL obtained from NVD before opening.
8. **SRC-ghsa-ts-sdk-345p**: [GHSA-345p-7cg4-v4c7](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-345p-7cg4-v4c7), accessed 2026-09-01; exact URL obtained from NVD before opening.
9. **SRC-ghsa-5ire-8527**: [GHSA-8527-3cch-95gf](https://github.com/nanbingxyz/5ire/security/advisories/GHSA-8527-3cch-95gf), accessed 2026-09-01; exact URL obtained from NVD before opening.
10. **SRC-nvd-mcp-catalog-2026-09-01**: [NVD CVE API 2.0 MCP keyword result](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol), reviewed 2026-09-01.
11. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), catalog version 2026.09.01.
12. **SRC-rfc8785**: [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html), Rundgren, Jordan, and Erdtman, 2020.
13. **SRC-nist-sp800-61r3**: [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), Nelson, Rekhi, Souppaya, and Scarfone, 2025.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft | The SAF-MCP Authors |
