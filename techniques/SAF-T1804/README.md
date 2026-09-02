# SAF-T1804: API Data Harvest

## Overview

- **Tactic**: Collection (ATK-TA0009) <!-- SAF-TRACE: claims=SAF-T1804-C014; sources=SRC-mitre-t1213-v3.4 -->
- **Technique ID**: SAF-T1804 <!-- SAF-TRACE: claims=SAF-T1804-C011; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->
- **Research Packet**: [research/techniques/SAF-T1804](../../research/techniques/SAF-T1804/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1804/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High <!-- SAF-TRACE: claims=SAF-T1804-C012; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->
- **Severity Rationale**: Broad delegated credentials or a read-path bypass can expose sensitive records across several collections; write effects are not part of the core behavior. <!-- SAF-TRACE: claims=SAF-T1804-C012; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->
- **First Observed**: Not observed in production; public MCP demonstrations were identified. <!-- SAF-TRACE: claims=SAF-T1804-C011; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-nvd-mcp-corpus-20260901,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-02 <!-- SAF-TRACE: claims=SAF-T1804-C011; sources=SRC-nvd-mcp-corpus-20260901 -->

## Scope

API Data Harvest covers repeated MCP resource reads or data-query tool calls that enumerate collections or retrieve API- or database-backed records beyond the breadth, fields, rows, or volume justified by the immediate user task. The crossed boundary is between authority available to the MCP-connected identity and the narrower access justified for that task. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C002,SAF-T1804-C004,SAF-T1804-C005; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-mcp-authorization-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->

### In Scope

- Enumeration followed by broad or high-volume retrieval through `resources/read` or a data-query tool. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C007; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-mitre-t1213-v3.4 -->
- Use of overly broad delegated authority or exploitation of a read-path authorization or query-construction weakness. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C004,SAF-T1804-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->
- Collection from an external API, database, SaaS repository, or comparable structured information store reached through MCP. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C005,SAF-T1804-C014; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-mitre-t1213-v3.4 -->

### Out of Scope

- Stealing a credential or token before the collection session, which is a prerequisite rather than the harvest itself. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C009; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-gtig-drift-2025,SRC-salesloft-drift-update -->
- Unauthorized invocation that does not enumerate or retrieve records, local-file collection, write or mutation activity, and transfer of collected data after retrieval. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C012; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->
- Ordinary, explicitly approved exports, backups, migrations, indexing, and synchronization within their authorized scope. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->

### Distinguishing Characteristics

The distinguishing outcome is collection: a discovery-to-read sequence spans several targets or returns substantially more data than the task needs. Credential acquisition and tool invocation may precede it, but the technique begins at repository enumeration or retrieval and ends before separate exfiltration or write behavior. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C007,SAF-T1804-C013; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-mitre-t1213-v3.4,SRC-nist-sp800-228-upd1 -->

## Description

MCP defines tools that may query external APIs and resource methods that list and read identified content. Those capabilities are legitimate; the abuse arises when the caller uses available credentials, an exposed server, or a query weakness to retrieve data at a breadth or volume not justified by the current task. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C004,SAF-T1804-C005; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->

Protocol authorization can restrict scopes and token audiences, yet those controls do not automatically express record-, field-, collection-, volume-, or task-level intent for every downstream service. MCP security guidance therefore favors narrow progressive scopes and rejects token passthrough, while downstream APIs still need their own authorization and query bounds. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-nist-sp800-228-upd1 -->

The end-to-end behavior is demonstrated, not observed in a confirmed production MCP incident. Public advisories show table enumeration and read-query exposure in mcp-pinot and arbitrary-query execution through injected ADX metadata operations; controlled MCP-SQL research separately observed genuine authorization-policy failures. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C005,SAF-T1804-C008,SAF-T1804-C011; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-arxiv-securemcp-2605-05260,SRC-nvd-mcp-corpus-20260901,SRC-cisa-kev-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: An exposed or compromised MCP data server accepts list, read, or query operations under authority broader than the immediate task. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C004; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-ghsa-mcp-pinot-73cv -->
- **Secondary Vectors**: Query construction injection, overly broad OAuth or service credentials, and model-mediated requests that are not constrained by deterministic data policy. <!-- SAF-TRACE: claims=SAF-T1804-C003,SAF-T1804-C005,SAF-T1804-C008,SAF-T1804-C009; sources=SRC-mcp-security-2025-11-25,SRC-ghsa-vphc-468g-8rfp,SRC-arxiv-securemcp-2605-05260,SRC-gtig-drift-2025,SRC-salesloft-drift-update -->
- **Affected Components**: MCP host or client, server resource or data-query tool, downstream API or database, delegated identity, and audit pipeline. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C006; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-nist-sp800-228-upd1 -->
- **Trust Boundary Crossed**: Delegated identity authority is treated as sufficient for task-level data access, or a read-path validation weakness bypasses the intended boundary. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C004,SAF-T1804-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->

## Technical Details

### Prerequisites

- A reachable MCP resource or tool backed by an API, database, or SaaS information repository. <!-- SAF-TRACE: claims=SAF-T1804-C001; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25 -->
- Credentials or server-side authority capable of reading data, or a weakness that supplies equivalent access. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C004,SAF-T1804-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->
- Missing or ineffective task-, row-, field-, query-, pagination-, response-, or rate controls. <!-- SAF-TRACE: claims=SAF-T1804-C003,SAF-T1804-C006,SAF-T1804-C008; sources=SRC-mcp-security-2025-11-25,SRC-nist-sp800-228-upd1,SRC-arxiv-securemcp-2605-05260 -->

### Attack Flow

1. **Reconnaissance or Setup**: The actor obtains a session or reaches an exposed server and discovers resources, tools, schemas, or collection names. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C004,SAF-T1804-C007; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-mitre-t1213-v3.4 -->
2. **Delivery**: Actor-controlled requests reach a resource-read method or data-query tool under a delegated or server-side identity. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C002; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-mcp-authorization-2025-11-25 -->
3. **Trigger or Execution**: The actor paginates reads or issues queries spanning multiple targets, rows, or fields. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C005,SAF-T1804-C007; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-mitre-t1213-v3.4 -->
4. **Boundary Crossing**: Broad credentials are accepted without task-level constraint, or input construction bypasses the intended read policy. <!-- SAF-TRACE: claims=SAF-T1804-C003,SAF-T1804-C005,SAF-T1804-C008; sources=SRC-mcp-security-2025-11-25,SRC-ghsa-vphc-468g-8rfp,SRC-arxiv-securemcp-2605-05260 -->
5. **Objective**: Records are collected at unauthorized breadth or volume through the MCP-mediated path. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C005,SAF-T1804-C014; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-mitre-t1213-v3.4 -->
6. **Follow-On Activity**: Separate credential abuse, staging, exfiltration, or mutation may follow, but those outcomes are outside this technique. <!-- SAF-TRACE: claims=SAF-T1804-C009,SAF-T1804-C012; sources=SRC-gtig-drift-2025,SRC-salesloft-drift-update,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->

### Example Scenario

A synthetic support assistant has read access to three business collections. An attacker-controlled session first lists available capabilities, then requests 20 pages across customer, order, and ticket targets. The server authorizes by broad service scope but does not enforce the current task's target or volume bounds; correlated audit events cross the detector's starter thresholds. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C003,SAF-T1804-C006,SAF-T1804-C013; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-mcp-security-2025-11-25,SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->

```json
{
  "timestamp": "2026-09-02T12:01:00Z",
  "session_id": "synthetic-session",
  "action": "resources/read",
  "target_id": "customers",
  "page_index": 19,
  "record_count": 1800,
  "response_bytes": 18000000,
  "approval_state": "not_requested"
}
```

The example is inert and represents only audit telemetry; it contains no endpoint, credential, query, exploit payload, or customer data. <!-- SAF-TRACE: claims=SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1804-C001 | MCP exposes API-querying tools and list/read resources. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools); SRC-mcp-resources-2025-11-25: [MCP Resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources) | Capability is not abuse. |
| SAF-T1804-C002 | MCP authorization supports least privilege and audience-restricted bearer tokens. | Research-Derived | SRC-mcp-authorization-2025-11-25: [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Does not express every task-level record policy. |
| SAF-T1804-C003 | MCP security guidance rejects token passthrough and favors progressive scopes. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Guidance requires implementation. |
| SAF-T1804-C004 | mcp-pinot exposure demonstrates unauthenticated table listing and read queries under server credentials. | Demonstrated | SRC-ghsa-mcp-pinot-73cv: [GHSA-73cv-556c-w3g6](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6); SRC-nvd-mcp-corpus-20260901: [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol&resultsPerPage=200) | No confirmed production exploitation or bulk theft. |
| SAF-T1804-C005 | ADX metadata-tool injection demonstrates arbitrary-query execution across a read boundary. | Demonstrated | SRC-ghsa-vphc-468g-8rfp: [GHSA-vphc-468g-8rfp](https://github.com/pab1it0/adx-mcp-server/security/advisories/GHSA-vphc-468g-8rfp); SRC-nvd-mcp-corpus-20260901: [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol&resultsPerPage=200) | No production incident; version and remediation metadata conflict. |
| SAF-T1804-C006 | NIST recommends response, query, pagination, rate, and telemetry controls for API abuse. | Research-Derived | SRC-nist-sp800-228-upd1: [NIST SP 800-228-upd1](https://csrc.nist.gov/pubs/sp/800/228/upd1/final) | Numeric values remain contextual. |
| SAF-T1804-C007 | ATT&CK detects repository collection through programmatic access, enumeration, and burst downloads. | Research-Derived | SRC-mitre-t1213-v3.4: [ATT&CK T1213](https://attack.mitre.org/techniques/T1213/) | ATT&CK lacks MCP task semantics. |
| SAF-T1804-C008 | SecureMCP observed controlled MCP-SQL policy failures and evaluated deterministic defenses. | Demonstrated | SRC-arxiv-securemcp-2605-05260: [Kim and Yoo](https://arxiv.org/abs/2605.05260v1) | Single-model, single-benchmark controlled study. |
| SAF-T1804-C009 | Stolen Drift OAuth tokens enabled systematic Salesforce API exports in production. | Observed | SRC-gtig-drift-2025: [Google GTIG/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift); SRC-salesloft-drift-update: [Salesloft](https://trust.salesloft.com/?uid=Drift%2FSalesforce+Security+Notification) | Adjacent API incident, not MCP. |
| SAF-T1804-C010 | Silk Typhoon used stolen API keys and OAuth apps for Graph and EWS collection. | Observed | SRC-microsoft-silk-typhoon-2025: [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2025/03/05/silk-typhoon-targeting-it-supply-chain/) | Historical API analogy, not MCP. |
| SAF-T1804-C011 | Overall evidence is Demonstrated, with no direct production MCP incident identified. | Demonstrated | SRC-ghsa-mcp-pinot-73cv, SRC-ghsa-vphc-468g-8rfp, SRC-nvd-mcp-corpus-20260901, SRC-cisa-kev-2026-09-01: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Authority-corpus absence cannot prove universal absence. |
| SAF-T1804-C012 | Conditional confidentiality impact is high; integrity and availability are not intrinsic. | Research-Derived | SRC-ghsa-mcp-pinot-73cv; SRC-ghsa-vphc-468g-8rfp | Deployment data and scope determine actual impact. |
| SAF-T1804-C013 | A tunable sequence, breadth, and volume analytic is evidence-aligned and synthetically testable. | Research-Derived | SRC-nist-sp800-228-upd1; SRC-mitre-t1213-v3.4 | Starter values may miss low-and-slow or unlogged access. |
| SAF-T1804-C014 | The behavior directly maps to ATT&CK T1213 by collection objective. | Research-Derived | SRC-mitre-t1213-v3.4 | Mapping is behavioral, not architectural. |

### Current State

- **Affected Environments**: MCP servers that expose API-, SaaS-, or database-backed read capabilities under broad credentials or weak query construction. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C005,SAF-T1804-C008; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-arxiv-securemcp-2605-05260 -->
- **Known Exploitation**: Direct public demonstrations exist; the reviewed corpus did not establish a direct production MCP incident. <!-- SAF-TRACE: claims=SAF-T1804-C011; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-nvd-mcp-corpus-20260901,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Patched mcp-pinot, scoped and audience-bound authorization, no token passthrough, downstream access checks, query and response limits, rate limits, and correlated audit telemetry. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C004,SAF-T1804-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-nist-sp800-228-upd1 -->
- **Residual Risk**: Authorized identities can still over-collect when downstream policy is broader than task intent, and low-and-slow activity may remain below local thresholds. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C008,SAF-T1804-C013; sources=SRC-mcp-authorization-2025-11-25,SRC-arxiv-securemcp-2605-05260,SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| [CVE-2026-49257 / GHSA-73cv-556c-w3g6](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6) | 2026; mcp-pinot through 3.0.1 | Server credentials could expose table listing and cluster reads; upgrade to 3.1.0 or later and require safe binding and authorization. | Direct vulnerability and demonstration. | No production exploitation established. <!-- SAF-TRACE: claims=SAF-T1804-C004; sources=SRC-ghsa-mcp-pinot-73cv,SRC-nvd-mcp-corpus-20260901 --> |
| [CVE-2026-33980 / GHSA-vphc-468g-8rfp](https://github.com/pab1it0/adx-mcp-server/security/advisories/GHSA-vphc-468g-8rfp) | 2026; ADX MCP Server through 0.1.0 per advisory | Injection could execute arbitrary data queries; use parameterized construction and external authorization. The advisory lists no patched release. | Direct vulnerability and demonstration. | No production exploitation; NVD version and patch metadata differ. <!-- SAF-TRACE: claims=SAF-T1804-C005; sources=SRC-ghsa-vphc-468g-8rfp,SRC-nvd-mcp-corpus-20260901 --> |
| [SecureMCP controlled evaluation](https://arxiv.org/abs/2605.05260v1) | 2026; controlled IoT-SQL benchmark | Genuine policy failures occurred; RBAC, cost gating, interception, risk filtering, and isolation improved compliance. | Direct controlled demonstration. | One model and one researcher-designed benchmark. <!-- SAF-TRACE: claims=SAF-T1804-C008; sources=SRC-arxiv-securemcp-2605-05260 --> |
| [Salesloft Drift connected-app incident](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift) | August 2025; connected Salesforce environments | Compromised OAuth tokens enabled systematic exports; tokens were revoked and integrations were disabled or reauthorized. | Adjacent production API incident. | No MCP or model-directed action established. <!-- SAF-TRACE: claims=SAF-T1804-C009; sources=SRC-gtig-drift-2025,SRC-salesloft-drift-update --> |

### Real-World Incidents or Demonstrations

The Salesloft Drift case shows the production consequence of broad integration authority: compromised OAuth tokens were used for systematic Salesforce export and secret-oriented searches. It is useful context for scope, monitoring, and containment, but it remains adjacent because the sources do not identify MCP or a model-directed call. <!-- SAF-TRACE: claims=SAF-T1804-C009; sources=SRC-gtig-drift-2025,SRC-salesloft-drift-update -->

Microsoft's Silk Typhoon report independently shows a historical API analogy in which stolen API keys and OAuth applications enabled Graph and EWS email collection, including downstream access through service providers. It does not establish this MCP technique. <!-- SAF-TRACE: claims=SAF-T1804-C010; sources=SRC-microsoft-silk-typhoon-2025 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Broad credentials or query bypass can expose sensitive records across multiple collections; actual impact depends on data sensitivity and scope. <!-- SAF-TRACE: claims=SAF-T1804-C012; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp --> |
| Integrity | None for core behavior | Writing or changing data is outside this read-focused contract, even when a vulnerable product exposes separate write capability. <!-- SAF-TRACE: claims=SAF-T1804-C012; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp --> |
| Availability | Low | High-volume reads can impose cost or load, but disruption is conditional and not the immediate objective. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C012; sources=SRC-nist-sp800-228-upd1,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp --> |
| Scope | Multi-System | A service identity may reach several downstream collections or customer environments, but credentials and repository policy bound the blast radius. <!-- SAF-TRACE: claims=SAF-T1804-C009,SAF-T1804-C010,SAF-T1804-C012; sources=SRC-gtig-drift-2025,SRC-salesloft-drift-update,SRC-microsoft-silk-typhoon-2025,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp --> |

### Severity Conditions

- **Severity increases when** sensitive multi-tenant records, broad service credentials, unauthenticated exposure, unrestricted queries, large page sizes, or weak monitoring coexist. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C005,SAF-T1804-C006,SAF-T1804-C012; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-nist-sp800-228-upd1 -->
- **Severity decreases when** each request is audience-bound and least-privileged, downstream row and field policy is enforced, responses and rates are limited, and high-risk scope elevation is explicit and logged. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C006; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-nist-sp800-228-upd1 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host, client, or server audit log | Resource/tool discovery and read/query invocation | Timestamp, session, actor, client, server, action, tool, target, approval, scope, status | Preserve ordering and a common session identifier. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C006,SAF-T1804-C007; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 --> |
| API or database gateway log | Page, record, query, response, and enforcement outcome | Target, page index, record count, response bytes, query class, policy decision | Normalize counts without retaining sensitive returned values. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 --> |
| Identity and network context | Token use, source, and workload classification | Actor, client, audience, scopes, source IP, workload class | Correlate suspicious breadth with scope elevation and approved bulk jobs. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C007; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-mitre-t1213-v3.4 --> |

### Indicators of Compromise (IoCs)

- None known that are durable and specific to this technique; product advisory identifiers are vulnerability references, not compromise indicators. <!-- SAF-TRACE: claims=SAF-T1804-C011,SAF-T1804-C013; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-nvd-mcp-corpus-20260901,SRC-cisa-kev-2026-09-01,SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->

### Behavioral Indicators

- Resource, tool, or schema discovery immediately followed by paginated reads or repeated data queries. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C007; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-mitre-t1213-v3.4 -->
- A single actor and session reaches several targets and returns unusually large record or byte totals. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C007,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
- The access originates from an unusual identity, client, source address, or newly elevated scope and lacks an approved bulk-workload classification. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C007,SAF-T1804-C013; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-mitre-t1213-v3.4,SRC-nist-sp800-228-upd1 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect discovery followed by broad, high-volume repository reads in one actor and session. <!-- SAF-TRACE: claims=SAF-T1804-C007,SAF-T1804-C013; sources=SRC-mitre-t1213-v3.4,SRC-nist-sp800-228-upd1 -->
- **Rule Status**: Experimental; tested against deterministic synthetic fixtures. <!-- SAF-TRACE: claims=SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
- **Detection Logic**: Within 15 minutes, require discovery before collection, at least three distinct targets, and at least one starter threshold of 20 pages, 5,000 records, or 52,428,800 response bytes; exclude explicitly approved bulk jobs. <!-- SAF-TRACE: claims=SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
- **Correlation Window**: 15 minutes, selected as a starter burst window for local validation. <!-- SAF-TRACE: claims=SAF-T1804-C007,SAF-T1804-C013; sources=SRC-mitre-t1213-v3.4,SRC-nist-sp800-228-upd1 -->
- **Known False Positives**: Unlabeled backups, exports, migrations, indexing, synchronization, investigations, and incident-response collections. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
- **Known Limitations**: Low-and-slow activity, a single large target, missing counts, session fragmentation, and actor-controlled or incomplete logging can evade the rule. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
- **Tuning Guidance**: Baseline each workload; adjust targets, values, and window; label approved jobs; and retain a separate alert for denied or elevated-scope attempts. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C006,SAF-T1804-C013; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Eight cases pass: two positive and six negative, including exact-boundary, just-below, allowlisted, missing-discovery, outside-window, and malformed-input coverage. <!-- SAF-TRACE: claims=SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
- **Last Validated**: 2026-09-02 <!-- SAF-TRACE: claims=SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
- **Validation Proof**: [Detector transcript](../../research/techniques/SAF-T1804/validation/detection-tests.txt) and [strict-validator transcript](../../research/techniques/SAF-T1804/validation/strict-validator.txt).
- **Feasibility Waiver**: None; representative synthetic validation is available. <!-- SAF-TRACE: claims=SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->

## Mitigation Strategies

### Preventive Controls

1. Apply [SAF-M-16: Token Scope Limiting](../../mitigations/SAF-M-16/README.md) and [SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md): issue audience-bound tokens with the minimum initial scopes; require explicit, logged elevation for additional collections or operations; never pass client tokens through unchanged to downstream APIs. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25 -->
2. Apply SAF-M-29, [SAF-M-71: Query Guardrails and Result Limits](../../mitigations/SAF-M-71/README.md), and [SAF-M-72: Data Loss Prevention on Tool Outputs](../../mitigations/SAF-M-72/README.md): validate resource URIs and permissions, apply tenant, row, field, and task policy at the server or downstream API, and parameterize query construction. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C005,SAF-T1804-C008; sources=SRC-mcp-resources-2025-11-25,SRC-ghsa-vphc-468g-8rfp,SRC-arxiv-securemcp-2605-05260 -->
3. Apply SAF-M-71 and [SAF-M-69: Out-of-Band Authorization](../../mitigations/SAF-M-69/README.md): limit response size, page size and count, time range, query complexity, total records, and rate; require separate approval for bulk jobs. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C008; sources=SRC-nist-sp800-228-upd1,SRC-arxiv-securemcp-2605-05260 -->
4. Apply [SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md): upgrade mcp-pinot to 3.1.0 or later, authenticate remote access, avoid unsafe network binding, and isolate data servers from untrusted clients. <!-- SAF-TRACE: claims=SAF-T1804-C004; sources=SRC-ghsa-mcp-pinot-73cv,SRC-nvd-mcp-corpus-20260901 -->

### Detective Controls

1. Apply [SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md): record actor, client, session, action, target, scope, decision, record count, bytes, page index, source, and status, then alert on discovery-to-read sequences and repository breadth. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C007,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
2. Apply [SAF-M-70: Tool-Invocation Anomaly Detection](../../mitigations/SAF-M-70/README.md): monitor scope elevation, new service principals or connected applications, unusual sources, enforcement errors, and approved-bulk classification changes alongside MCP events. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C009,SAF-T1804-C010; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-gtig-drift-2025,SRC-salesloft-drift-update,SRC-microsoft-silk-typhoon-2025 -->

### Response Procedures

#### Immediate Actions

- Stop the MCP session or isolate the server; disable the affected integration when continued access could enlarge collection. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C009; sources=SRC-nist-sp800-228-upd1,SRC-gtig-drift-2025,SRC-salesloft-drift-update -->
- Revoke or rotate affected tokens and server credentials, remove excess scopes, and preserve authorization and access logs. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C003,SAF-T1804-C009,SAF-T1804-C010; sources=SRC-mcp-authorization-2025-11-25,SRC-mcp-security-2025-11-25,SRC-gtig-drift-2025,SRC-salesloft-drift-update,SRC-microsoft-silk-typhoon-2025 -->

#### Investigation Steps

- Correlate discovery, read, query, scope, identity, gateway, and network events by actor, session, target, and time; calculate records and bytes returned. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C007,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 -->
- Determine the entry point, first and last access, affected tenants and collections, policy decisions, failed requests, and any subsequent staging, write, or exfiltration behavior. <!-- SAF-TRACE: claims=SAF-T1804-C009,SAF-T1804-C010,SAF-T1804-C012; sources=SRC-gtig-drift-2025,SRC-salesloft-drift-update,SRC-microsoft-silk-typhoon-2025,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp -->

#### Remediation

- Patch exposed products, correct query construction, require authenticated safe binding, and move authorization, pagination, response, and rate enforcement outside model discretion. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C005,SAF-T1804-C006,SAF-T1804-C008; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-nist-sp800-228-upd1,SRC-arxiv-securemcp-2605-05260 -->
- Add regression fixtures for the failed boundary, re-baseline the analytic, and verify that logs capture denied, allowed, and elevated access without sensitive returned content. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C008,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1,SRC-arxiv-securemcp-2605-05260,SRC-mitre-t1213-v3.4 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1801: Automated Data Harvesting](../SAF-T1801/README.md) | Generalization | Covers systematic collection across source types; SAF-T1804 requires API- or repository-backed record enumeration or retrieval. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C014; sources=SRC-mcp-resources-2025-11-25,SRC-mitre-t1213-v3.4 --> |
| [SAF-T1803: Database Dump](../SAF-T1803/README.md) | Sibling specialization | Requires dump-equivalent database acquisition; SAF-T1804 includes paginated API and repository-record harvesting. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C014; sources=SRC-mcp-resources-2025-11-25,SRC-mitre-t1213-v3.4 --> |
| [SAF-T1504: Token Theft via API Response](../SAF-T1504/README.md) | Prerequisite | Obtains authority; API Data Harvest starts when repository enumeration or retrieval uses it. <!-- SAF-TRACE: claims=SAF-T1804-C002,SAF-T1804-C009; sources=SRC-mcp-authorization-2025-11-25,SRC-gtig-drift-2025,SRC-salesloft-drift-update --> |
| [SAF-T1104: Over-Privileged Tool Abuse](../SAF-T1104/README.md) | Prerequisite or co-occurring | Covers the invocation authority decision; API Data Harvest requires the collection outcome. <!-- SAF-TRACE: claims=SAF-T1804-C001,SAF-T1804-C004,SAF-T1804-C005; sources=SRC-mcp-tools-2025-11-25,SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | Direct | Both behaviors collect information from repositories; SAF-T1804 narrows the mechanism to MCP and adds task-intent and delegated-authority boundaries. <!-- SAF-TRACE: claims=SAF-T1804-C014; sources=SRC-mitre-t1213-v3.4 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), MCP maintainers and contributors, 2025-11-25. <!-- SAF-TRACE: claims=SAF-T1804-C001; sources=SRC-mcp-tools-2025-11-25 -->
2. **SRC-mcp-resources-2025-11-25**: [MCP Resources specification](https://modelcontextprotocol.io/specification/2025-11-25/server/resources), MCP maintainers and contributors, 2025-11-25. <!-- SAF-TRACE: claims=SAF-T1804-C001; sources=SRC-mcp-resources-2025-11-25 -->
3. **SRC-mcp-authorization-2025-11-25**: [MCP Authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), MCP maintainers and contributors, 2025-11-25. <!-- SAF-TRACE: claims=SAF-T1804-C002; sources=SRC-mcp-authorization-2025-11-25 -->
4. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices), MCP maintainers and contributors, 2025-11-25. <!-- SAF-TRACE: claims=SAF-T1804-C003; sources=SRC-mcp-security-2025-11-25 -->
5. **SRC-nist-sp800-228-upd1**: [NIST SP 800-228-upd1](https://csrc.nist.gov/pubs/sp/800/228/upd1/final), Ramaswamy Chandramouli and Zack Butcher, June 2025 with updates through 2026-03-13. <!-- SAF-TRACE: claims=SAF-T1804-C006,SAF-T1804-C013; sources=SRC-nist-sp800-228-upd1 -->
6. **SRC-mitre-t1213-v3.4**: [ATT&CK T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213/), MITRE ATT&CK and named contributors, version 3.4. <!-- SAF-TRACE: claims=SAF-T1804-C007,SAF-T1804-C014; sources=SRC-mitre-t1213-v3.4 -->
7. **SRC-nvd-mcp-corpus-20260901**: [NVD CVE API MCP corpus](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol&resultsPerPage=200), National Vulnerability Database, reviewed 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C005,SAF-T1804-C011; sources=SRC-nvd-mcp-corpus-20260901 -->
8. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), catalog version 2026.09.01. <!-- SAF-TRACE: claims=SAF-T1804-C011; sources=SRC-cisa-kev-2026-09-01 -->
9. **SRC-ghsa-mcp-pinot-73cv**: [GHSA-73cv-556c-w3g6](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6), xiangfu0, reporting researcher, and StarTree Data maintainers, 2026. <!-- SAF-TRACE: claims=SAF-T1804-C004,SAF-T1804-C011,SAF-T1804-C012; sources=SRC-ghsa-mcp-pinot-73cv -->
10. **SRC-ghsa-vphc-468g-8rfp**: [GHSA-vphc-468g-8rfp](https://github.com/pab1it0/adx-mcp-server/security/advisories/GHSA-vphc-468g-8rfp), pab1it0 and reporter romain-deperne, 2026. <!-- SAF-TRACE: claims=SAF-T1804-C005,SAF-T1804-C011,SAF-T1804-C012; sources=SRC-ghsa-vphc-468g-8rfp -->
11. **SRC-arxiv-securemcp-2605-05260**: [SecureMCP](https://arxiv.org/abs/2605.05260v1), Wonbae Kim and Hee-Kyong Yoo, 2026. <!-- SAF-TRACE: claims=SAF-T1804-C008; sources=SRC-arxiv-securemcp-2605-05260 -->
12. **SRC-gtig-drift-2025**: [Data Theft from Salesforce Instances via Salesloft Drift](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift), Austin Larsen, Matt Lin, Tyler McLellan, Omar ElAhdan, GTIG/Mandiant, 2025. <!-- SAF-TRACE: claims=SAF-T1804-C009; sources=SRC-gtig-drift-2025 -->
13. **SRC-salesloft-drift-update**: [Drift and Salesforce Security Notification](https://trust.salesloft.com/?uid=Drift%2FSalesforce+Security+Notification), Salesloft incident response and Mandiant investigation teams. <!-- SAF-TRACE: claims=SAF-T1804-C009; sources=SRC-salesloft-drift-update -->
14. **SRC-microsoft-silk-typhoon-2025**: [Silk Typhoon Targeting IT Supply Chain](https://www.microsoft.com/en-us/security/blog/2025/03/05/silk-typhoon-targeting-it-supply-chain/), Microsoft Threat Intelligence, 2025. <!-- SAF-TRACE: claims=SAF-T1804-C010; sources=SRC-microsoft-silk-typhoon-2025 -->

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial independent clean-room draft; authority research, tested detector, rights review, and isolated strict validation. | OpenAI Codex clean-room research agent <!-- SAF-TRACE: claims=SAF-T1804-C011,SAF-T1804-C013; sources=SRC-ghsa-mcp-pinot-73cv,SRC-ghsa-vphc-468g-8rfp,SRC-nvd-mcp-corpus-20260901,SRC-cisa-kev-2026-09-01,SRC-nist-sp800-228-upd1,SRC-mitre-t1213-v3.4 --> |
