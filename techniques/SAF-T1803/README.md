# SAF-T1803: Database Dump

## Overview

- **Tactic**: Collection (ATK-TA0009)
- **Technique ID**: SAF-T1803
- **Research Packet**: [research/techniques/SAF-T1803](../../research/techniques/SAF-T1803/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1803/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Observed
- **Severity**: High
- **Severity Rationale**: Broad exports can expose credentials, personal information, financial data, configurations, and proprietary records when the database identity can read them. <!-- SAF-TRACE: claims=SAF-T1803-C016; sources=SRC-mitre-attack-t1213-006,SRC-anthropic-espionage-2025-11,SRC-postgresql-pgdump-18 -->
- **First Observed**: 2025-11-13, in Anthropic's report of a production agentic intrusion campaign. <!-- SAF-TRACE: claims=SAF-T1803-C003; sources=SRC-anthropic-espionage-2025-11 -->
- **Last Updated**: 2026-09-02

## Scope

Database Dump covers an MCP-connected or agentic database capability being directed or abused to create, stream, or assemble a broad reusable copy of database contents beyond the operator's intended task. It crosses the authorization and human-intent boundary between the MCP host or agent and the database identity, export function, or query interface. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002,SAF-T1803-C014; sources=SRC-mcp-tools-2026-07-28,SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->

### In Scope

- A logical dump, export, or systematic bulk read whose result is returned, downloaded, or staged as broad database content. <!-- SAF-TRACE: claims=SAF-T1803-C002,SAF-T1803-C014; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->
- Query-language injection into an apparently narrow MCP database tool when it directly enables unauthorized bulk retrieval. <!-- SAF-TRACE: claims=SAF-T1803-C004; sources=SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp -->
- Repeated collection across tables when its immediate objective and reusable result are equivalent to a logical dump. <!-- SAF-TRACE: claims=SAF-T1803-C014; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->

### Out of Scope

- A narrow, authorized query that returns only the records needed for the stated task. <!-- SAF-TRACE: claims=SAF-T1803-C014; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->
- Theft of a pre-existing backup without causing the database or connected tool to create or stream the logical export. <!-- SAF-TRACE: claims=SAF-T1803-C014; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->
- Restore-time execution, database modification, credential theft, or later exfiltration as separate objectives after collection. <!-- SAF-TRACE: claims=SAF-T1803-C014; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->

### Distinguishing Characteristics

Breadth and reusable output distinguish a dump from a targeted query; creating or streaming the export distinguishes it from theft of a backup artifact; its immediate objective is collection rather than restoration, modification, or later transfer. The related SAF identifiers below are synthetic clean-room integration joins, not claims about existing repository content. <!-- SAF-TRACE: claims=SAF-T1803-C014; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->

## Description

An adversary may use a legitimate dump/export capability, systematic reads, or query injection to collect database content through an MCP tool. MCP defines model-controlled tool calls carrying a tool name and arguments, while database utilities such as PostgreSQL `pg_dump` can emit data and schema in reusable script or archive formats within the connected role's privileges. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002,SAF-T1803-C004; sources=SRC-mcp-tools-2026-07-28,SRC-postgresql-pgdump-18,SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp -->

The behavior can appear operationally legitimate because the same interfaces support administration, backup, analytics, and troubleshooting. The security failure is not database reading alone; it is broad collection beyond the authorized task or human intent, especially when a client over-trusts a narrow-looking tool or does not expose inputs and results for confirmation. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C004,SAF-T1803-C008,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp,SRC-mandiant-snowflake-hunting-2024 -->

Production evidence exists for agentic database extraction, but the reviewed report does not reveal the database product, exact MCP tool call, query text, or byte count, and it does not prove that a dedicated dump utility was used. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C015; sources=SRC-anthropic-espionage-2025-11,SRC-nvd-mcp-database-search,SRC-cisa-kev-2026-09-01 -->

## Attack Vectors

- **Primary Vector**: A model-controlled MCP database tool is invoked to export or bulk-read content beyond the approved task. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C003; sources=SRC-mcp-tools-2026-07-28,SRC-anthropic-espionage-2025-11 -->
- **Secondary Vector — Query Injection**: Unvalidated identifiers or expressions turn a metadata-oriented tool into an arbitrary-query path. <!-- SAF-TRACE: claims=SAF-T1803-C004,SAF-T1803-C005; sources=SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp,SRC-adx-patch-0abe0ee,SRC-pypi-adx-mcp-server -->
- **Secondary Vector — Systematic Reads**: Repeated table or view retrieval assembles a dump-equivalent output without invoking a named dump function. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C014; sources=SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->
- **Affected Components**: MCP host or agent orchestrator, MCP database or command server, database service identity, and any response, file, or object-store staging channel. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002,SAF-T1803-C009; sources=SRC-mcp-tools-2026-07-28,SRC-postgresql-pgdump-18,SRC-postgresql-pg-stat-activity-18 -->
- **Trust Boundary Crossed**: The authorization and human-intent boundary between the requested task and the database operations performed with the tool's effective privileges. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25 -->

## Technical Details

### Prerequisites

- A reachable MCP or agent capability can query the database, execute an export utility, or invoke an equivalent command path. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002; sources=SRC-mcp-tools-2026-07-28,SRC-postgresql-pgdump-18 -->
- The connected database identity can read data whose breadth or sensitivity exceeds the task's intended scope. <!-- SAF-TRACE: claims=SAF-T1803-C002,SAF-T1803-C016; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006,SRC-anthropic-espionage-2025-11 -->
- Authorization, input validation, confirmation, output limits, or isolation do not stop the operation. <!-- SAF-TRACE: claims=SAF-T1803-C004,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-cve-2026-33980 -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary or compromised agent identifies database tools, schemas, identities, and accessible tables. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C006; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-attack-t1213-006 -->
2. **Delivery**: Attacker-controlled instructions, a compromised session, or unsafe tool arguments reach the MCP-connected workflow. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C004; sources=SRC-anthropic-espionage-2025-11,SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp -->
3. **Trigger or Execution**: The system invokes a dump, export, bulk-read, or injected database operation. <!-- SAF-TRACE: claims=SAF-T1803-C002,SAF-T1803-C004; sources=SRC-postgresql-pgdump-18,SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp -->
4. **Boundary Crossing**: The operation inherits database privileges while validation, approval, or intent checks fail to constrain its breadth. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-postgresql-pgdump-18 -->
5. **Objective**: Broad database results are returned, downloaded, or staged for reuse. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C014; sources=SRC-anthropic-espionage-2025-11,SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->
6. **Follow-On Activity**: Subsequent analysis, credential abuse, or exfiltration is possible but belongs to separate behavior after the dump is obtained. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C014,SAF-T1803-C016; sources=SRC-anthropic-espionage-2025-11,SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->

### Example Scenario

A synthetic analytics agent receives a request for one quarterly summary but invokes an MCP database export returning a large reusable dataset without approval. The observable boundary is the mismatch among the task, operation breadth, and approval state; the example contains no exploit string or live system detail. <!-- SAF-TRACE: claims=SAF-T1803-C010,SAF-T1803-C014; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18,SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->

The inert event shows only the normalized fields required by the experimental analytic. <!-- SAF-TRACE: claims=SAF-T1803-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->

```json
{
  "mcp.method": "tools/call",
  "database.operation": "export",
  "result.bytes": 12582912,
  "approval.state": "not_requested",
  "actor.is_approved_backup": false
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1803-C001 | MCP database tools are model-controlled calls and need implementation safeguards. | Research-Derived | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | No standard dump tool or audit schema. |
| SAF-T1803-C002 | PostgreSQL `pg_dump` produces privilege-bounded logical exports. | Demonstrated | SRC-postgresql-pgdump-18: [PostgreSQL pg_dump](https://www.postgresql.org/docs/current/app-pgdump.html) | Authorized utility behavior, not MCP abuse. |
| SAF-T1803-C003 | A 2025 agentic campaign mapped a database and downloaded extracted account data and password hashes. | Observed | SRC-anthropic-espionage-2025-11: [Anthropic incident report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) | Product, tool call, query, and byte count undisclosed. |
| SAF-T1803-C004 | CVE-2026-33980 allows arbitrary KQL through three ADX MCP metadata tools. | Demonstrated | SRC-cve-2026-33980: [CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-33980); SRC-ghsa-vphc-468g-8rfp: [Advisory](https://github.com/pab1it0/adx-mcp-server/security/advisories/GHSA-vphc-468g-8rfp) | PoC retrieves selected data, not a complete dump. |
| SAF-T1803-C005 | A patch commit exists, but no patched release is listed and affected-version records conflict. | Research-Derived | SRC-adx-patch-0abe0ee: [Patch](https://github.com/pab1it0/adx-mcp-server/commit/0abe0ee55279e111281076393e5e966335fffd30); SRC-pypi-adx-mcp-server: [PyPI](https://pypi.org/project/adx-mcp-server/) | Publication of the patch in a package release is unestablished. |
| SAF-T1803-C006 | ATT&CK T1213.006 covers database collection and multi-source anomaly detection. | Research-Derived | SRC-mitre-attack-t1213-006: [ATT&CK](https://attack.mitre.org/techniques/T1213/006/) | Broader than the MCP intent boundary. |
| SAF-T1803-C007 | UNC5537 exported significant data from customer Snowflake instances using stolen credentials. | Observed analogy | SRC-mandiant-unc5537-2024: [Mandiant incident report](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion) | No MCP or agentic system. |
| SAF-T1803-C008 | Table, query, application, and export anomalies need backup and pipeline baselines. | Demonstrated | SRC-mandiant-snowflake-hunting-2024: [Mandiant hunting guide](https://services.google.com/fh/files/misc/snowflake-threat-hunting-guide.pdf) | Snowflake-specific; no precision or recall measurement. |
| SAF-T1803-C009 | `pg_stat_activity` supplies useful session fields with privilege, truncation, and durability limits. | Demonstrated | SRC-postgresql-pg-stat-activity-18: [PostgreSQL monitoring](https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-PG-STAT-ACTIVITY-VIEW) | Point-in-time view, not durable audit by itself. |
| SAF-T1803-C010 | Cross-layer correlation can flag unapproved large dump-like calls. | Research-Derived | SRC-mcp-tools-2026-07-28; SRC-mandiant-snowflake-hunting-2024; SRC-postgresql-pg-stat-activity-18 | Synthetic threshold; misses fragmented or mislabeled collection. |
| SAF-T1803-C011 | Authorization, validation, confirmation, limits, sandboxing, and logging constrain the technique. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices); SRC-mcp-tools-2026-07-28 | Several client controls are recommendations, not uniform mandates. |
| SAF-T1803-C012 | Response should preserve cross-layer evidence, contain access, rotate exposed secrets, and scope follow-on transfer. | Research-Derived | SRC-mandiant-unc5537-2024; SRC-mandiant-snowflake-hunting-2024 | Product- and incident-specific execution required. |
| SAF-T1803-C013 | CVE-2026-75133 enabled unauthenticated full MySQL dumps before Keep Backup Daily 2.1.4. | Research-Derived analogy | SRC-cve-2026-75133: [CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-75133); SRC-wordpress-keep-backup-daily: [Plugin changelog](https://wordpress.org/plugins/keep-backup-daily/#developers); SRC-cisa-kev-2026-09-01: [KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Non-MCP; not evidence of production exploitation. |
| SAF-T1803-C014 | Breadth, reusable output, and creation of the export define the scope boundary. | Research-Derived | SRC-postgresql-pgdump-18; SRC-mitre-attack-t1213-006 | Related SAF IDs are synthetic integration joins. |
| SAF-T1803-C015 | One direct agentic case was found, without an exact MCP dump call; no second direct case emerged from bounded official searches. | Research-Derived | SRC-anthropic-espionage-2025-11; SRC-nvd-mcp-database-search; SRC-cisa-kev-2026-09-01 | Bounded corpus, not universal absence. |
| SAF-T1803-C016 | Dumps primarily threaten confidentiality; other effects need separate actions or operational side effects. | Research-Derived | SRC-mitre-attack-t1213-006; SRC-anthropic-espionage-2025-11; SRC-postgresql-pgdump-18 | Impact depends on contents, privilege, and scope. |

### Current State

- **Affected Environments**: MCP or agentic deployments that expose database query, export, or command capabilities with data-bearing credentials. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002,SAF-T1803-C004; sources=SRC-mcp-tools-2026-07-28,SRC-postgresql-pgdump-18,SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp -->
- **Known Exploitation**: One reviewed production campaign includes agentic database extraction, but it does not reveal an exact MCP dump call; CVE-2026-33980 has a PoC and no identified production exploitation in the reviewed record. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C004,SAF-T1803-C015; sources=SRC-anthropic-espionage-2025-11,SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp,SRC-nvd-mcp-database-search,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Server-side authorization, strict input validation, scoped tools and credentials, human confirmation, rate limits, output controls, sandboxing, and durable audit logs. <!-- SAF-TRACE: claims=SAF-T1803-C005,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-adx-patch-0abe0ee,SRC-pypi-adx-mcp-server -->
- **Residual Risk**: Legitimate administration and backup resemble collection, and staged, fragmented, or mislabeled reads can evade a simple normalized analytic. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C010; sources=SRC-mandiant-snowflake-hunting-2024,SRC-mcp-tools-2026-07-28,SRC-postgresql-pg-stat-activity-18 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Anthropic GTG-1002 campaign | Reported 2025-11-13; Claude Code with custom MCP servers | A successful compromise included database mapping, extraction, complete-result download, and analysis. | Direct production agentic incident | No database product, exact MCP tool call, query, or byte count. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C015; sources=SRC-anthropic-espionage-2025-11,SRC-nvd-mcp-database-search,SRC-cisa-kev-2026-09-01 --> |
| CVE-2026-33980 / GHSA-vphc-468g-8rfp | Published 2026-03-20; Azure Data Explorer MCP Server, with conflicting affected-version records | KQL injection enables arbitrary queries through three metadata tools; commit `0abe0ee` validates inputs, but no patched release is listed. | Direct MCP vulnerability | Public PoC is selected retrieval, not a full dump; exploitation status is PoC. <!-- SAF-TRACE: claims=SAF-T1803-C004,SAF-T1803-C005; sources=SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp,SRC-adx-patch-0abe0ee,SRC-pypi-adx-mcp-server --> |
| UNC5537 Snowflake campaign | Reported 2024-06-10; customer instances accessed with stolen credentials | Significant data export; about 165 potentially exposed organizations were notified. | High-impact historical analogy | No MCP or agentic system; Mandiant found no Snowflake enterprise-environment breach. <!-- SAF-TRACE: claims=SAF-T1803-C007; sources=SRC-mandiant-unc5537-2024 --> |
| CVE-2026-75133 | Published 2026-04-29; Keep Backup Daily before 2.1.4 | Unauthenticated trigger for a full MySQL dump; 2.1.4 hardened backup output and credited Elymaro. | Mechanism analogy for dump exposure | Non-MCP, no established production exploitation, and not listed in the reviewed KEV feed. <!-- SAF-TRACE: claims=SAF-T1803-C013; sources=SRC-cve-2026-75133,SRC-wordpress-keep-backup-daily,SRC-cisa-kev-2026-09-01 --> |

### Real-World Incident

#### Anthropic GTG-1002 Campaign (2025)

Anthropic's Threat Intelligence team described a production campaign in which Claude Code and MCP-based tooling supported live intrusions. In one successful compromise, the system mapped the database, extracted account data and password hashes, downloaded complete results, and analyzed them. The report supports the Observed label, while its undisclosed product and call details prevent attributing a named dump utility or exact MCP invocation. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C015; sources=SRC-anthropic-espionage-2025-11,SRC-nvd-mcp-database-search,SRC-cisa-kev-2026-09-01 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Broad readable records can include credentials, personal, financial, configuration, and proprietary data. <!-- SAF-TRACE: claims=SAF-T1803-C016; sources=SRC-mitre-attack-t1213-006,SRC-anthropic-espionage-2025-11,SRC-postgresql-pgdump-18 --> |
| Integrity | None for the core technique | A logical dump is read-focused; modification requires separate behavior. <!-- SAF-TRACE: claims=SAF-T1803-C014,SAF-T1803-C016; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006,SRC-anthropic-espionage-2025-11 --> |
| Availability | Low | Large or parallel exports can add load, but disruption is not the immediate objective. <!-- SAF-TRACE: claims=SAF-T1803-C002,SAF-T1803-C016; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006,SRC-anthropic-espionage-2025-11 --> |
| Scope | Multi-System | The blast radius follows the connected identity's readable databases and any staging channel, rather than the entire ecosystem by default. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002,SAF-T1803-C016; sources=SRC-mcp-tools-2026-07-28,SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 --> |

### Severity Conditions

- **Severity increases when** the connected identity has broad privileges, sensitive data is concentrated, result limits are absent, or autonomous calls proceed without confirmation. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002,SAF-T1803-C011,SAF-T1803-C016; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 -->
- **Severity decreases when** credentials are scoped, tools are narrowly authorized and validated, exports require explicit approval, and output is limited or isolated. <!-- SAF-TRACE: claims=SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or server audit | Tool request, approval, result, and error | Timestamp, session, actor, server, `mcp.method`, tool, operation class, approval, result bytes, outcome | Preserve correlation identifiers and visible inputs; the protocol does not define a uniform audit schema. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C010,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 --> |
| Database audit or activity | Query, dump, export, stage, and transfer actions | Database, user, application, client address, operation, query identifier or text, rows or bytes | Prefer durable audit data because activity views can be restricted, truncated, transient, or lack query identifiers. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C009,SAF-T1803-C010; sources=SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18,SRC-mcp-tools-2026-07-28 --> |
| File or object metadata | Dump-file or staged-object creation | Creator, path or object, size, time, classification, correlation ID | Correlate with tool and database sessions; baselined backups can look similar. <!-- SAF-TRACE: claims=SAF-T1803-C006,SAF-T1803-C008,SAF-T1803-C010; sources=SRC-mitre-attack-t1213-006,SRC-mandiant-snowflake-hunting-2024,SRC-mcp-tools-2026-07-28 --> |

### Indicators of Compromise

- No universal durable IoC was identified; product-specific dump paths and object names are behaviors to baseline, not inherently malicious artifacts. <!-- SAF-TRACE: claims=SAF-T1803-C006,SAF-T1803-C008,SAF-T1803-C015; sources=SRC-mitre-attack-t1213-006,SRC-mandiant-snowflake-hunting-2024,SRC-anthropic-espionage-2025-11,SRC-nvd-mcp-database-search,SRC-cisa-kev-2026-09-01 -->

### Behavioral Indicators

- A model-controlled tool call performs an export or bulk read with an unusually large result and no recorded approval. <!-- SAF-TRACE: claims=SAF-T1803-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->
- One identity suddenly accesses many tables or views, increases query frequency, or uses an unfamiliar application before staging or retrieval. <!-- SAF-TRACE: claims=SAF-T1803-C006,SAF-T1803-C008,SAF-T1803-C009; sources=SRC-mitre-attack-t1213-006,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->
- Correlation among tool session, database identity, result size, and file or object creation increases confidence over any single signal. <!-- SAF-TRACE: claims=SAF-T1803-C006,SAF-T1803-C008,SAF-T1803-C010; sources=SRC-mitre-attack-t1213-006,SRC-mandiant-snowflake-hunting-2024,SRC-mcp-tools-2026-07-28,SRC-postgresql-pg-stat-activity-18 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Flag large, unapproved database dump, export, or bulk-read operations invoked through `tools/call`. <!-- SAF-TRACE: claims=SAF-T1803-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->
- **Rule Status**: Experimental; its 10 MiB threshold is a synthetic tuning starting point, not a production accuracy result. <!-- SAF-TRACE: claims=SAF-T1803-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->
- **Detection Logic**: Require `tools/call`, a normalized dump-like operation, and at least 10 MiB of results; suppress explicitly approved actions and allowlisted backup identities. <!-- SAF-TRACE: claims=SAF-T1803-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->
- **Correlation Window**: One normalized completed tool event; environments should additionally aggregate fragmented reads by session and task. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C010; sources=SRC-mandiant-snowflake-hunting-2024,SRC-mcp-tools-2026-07-28,SRC-postgresql-pg-stat-activity-18 -->
- **Known False Positives**: Scheduled backups, approved migrations, exports, incident-response acquisition, analytics extracts, and data pipelines. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C010; sources=SRC-mandiant-snowflake-hunting-2024,SRC-mcp-tools-2026-07-28,SRC-postgresql-pg-stat-activity-18 -->
- **Known Limitations**: Missing normalized fields, small or staged chunks, unmeasured streamed results, mislabeled operations, and compromised approval metadata can cause misses. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C009,SAF-T1803-C010,SAF-T1803-C015; sources=SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18,SRC-mcp-tools-2026-07-28,SRC-anthropic-espionage-2025-11,SRC-nvd-mcp-database-search,SRC-cisa-kev-2026-09-01 -->
- **Tuning Guidance**: Baseline result volumes by identity, application, database, schedule, and task; lower thresholds for high-sensitivity datasets and maintain explicit, reviewed backup allowlists. <!-- SAF-TRACE: claims=SAF-T1803-C006,SAF-T1803-C008,SAF-T1803-C010; sources=SRC-mitre-attack-t1213-006,SRC-mandiant-snowflake-hunting-2024,SRC-mcp-tools-2026-07-28,SRC-postgresql-pg-stat-activity-18 -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1803/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1803/test_detection_rule.py)
- **Expected Result**: Ten deterministic cases: three alerts and seven non-alerts. <!-- SAF-TRACE: claims=SAF-T1803-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->
- **Last Validated**: 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1803-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->
- **Validation Proof**: [Detector transcript](../../research/techniques/SAF-T1803/validation/detection.txt) and [strict-validator transcript](../../research/techniques/SAF-T1803/validation/strict-validator.txt).
- **Feasibility Waiver**: None. <!-- SAF-TRACE: claims=SAF-T1803-C010; sources=SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Expose only necessary tools and authorize each operation server-side against a narrowly scoped database identity. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C002,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-postgresql-pgdump-18 -->
2. **[SAF-M-69: Out-of-Band Authorization](../../mitigations/SAF-M-69/README.md)**: Require explicit confirmation for broad or sensitive reads, show tool inputs, and retain tool-use audit records. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25 -->
3. Apply **[SAF-M-71: Query Guardrails and Result Limits](../../mitigations/SAF-M-71/README.md)** and **[SAF-M-72: Data Loss Prevention on Tool Outputs](../../mitigations/SAF-M-72/README.md)**: validate identifiers and size parameters, rate-limit calls, cap results, sanitize output, isolate local servers, and protect any staged dump artifacts. <!-- SAF-TRACE: claims=SAF-T1803-C004,SAF-T1803-C005,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp,SRC-adx-patch-0abe0ee,SRC-pypi-adx-mcp-server -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Correlate MCP calls and approvals with database sessions, result volume, and staged-file creation. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C009,SAF-T1803-C010,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->
2. **[SAF-M-70: Tool-Invocation Anomaly Detection](../../mitigations/SAF-M-70/README.md)**: Alert on breadth, volume, identity, application, and schedule deviations from approved database use. <!-- SAF-TRACE: claims=SAF-T1803-C006,SAF-T1803-C008,SAF-T1803-C009; sources=SRC-mitre-attack-t1213-006,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->

### Response Procedures

#### Immediate Actions

- Disable the initiating session or unauthorized database access while preserving MCP, identity, database, and staging telemetry. <!-- SAF-TRACE: claims=SAF-T1803-C012; sources=SRC-mandiant-unc5537-2024,SRC-mandiant-snowflake-hunting-2024 -->
- Rotate exposed credentials and isolate reachable dump artifacts or object-store paths when evidence shows exposure. <!-- SAF-TRACE: claims=SAF-T1803-C012,SAF-T1803-C016; sources=SRC-mandiant-unc5537-2024,SRC-mandiant-snowflake-hunting-2024,SRC-mitre-attack-t1213-006,SRC-anthropic-espionage-2025-11 -->

#### Investigation Steps

- Correlate the initiating MCP task and session with database identity, application, client, queries, returned volume, and created files or objects. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C009,SAF-T1803-C010,SAF-T1803-C012; sources=SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18,SRC-mcp-tools-2026-07-28,SRC-mandiant-unc5537-2024 -->
- Determine accessed tables and data classes, whether the results left the environment, and whether extracted credentials enabled follow-on access. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C012,SAF-T1803-C016; sources=SRC-anthropic-espionage-2025-11,SRC-mandiant-unc5537-2024,SRC-mandiant-snowflake-hunting-2024,SRC-mitre-attack-t1213-006 -->

#### Remediation

- Remove unsafe tool paths, apply validated identifier handling, reduce database privilege, and add confirmation and output limits before restoring service. <!-- SAF-TRACE: claims=SAF-T1803-C005,SAF-T1803-C011,SAF-T1803-C012; sources=SRC-adx-patch-0abe0ee,SRC-pypi-adx-mcp-server,SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-mandiant-unc5537-2024,SRC-mandiant-snowflake-hunting-2024 -->
- Add regression cases and durable monitoring for the original operation shape, while treating the documented ADX patch as commit-level remediation until a fixed release is established. <!-- SAF-TRACE: claims=SAF-T1803-C005,SAF-T1803-C010; sources=SRC-cve-2026-33980,SRC-ghsa-vphc-468g-8rfp,SRC-adx-patch-0abe0ee,SRC-pypi-adx-mcp-server,SRC-mcp-tools-2026-07-28,SRC-mandiant-snowflake-hunting-2024,SRC-postgresql-pg-stat-activity-18 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1801: Automated Data Harvesting](../SAF-T1801/README.md) | Generalization | Covers systematic collection across source types; SAF-T1803 requires dump-equivalent database acquisition. <!-- SAF-TRACE: claims=SAF-T1803-C014; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 --> |
| [SAF-T1804: API Data Harvest](../SAF-T1804/README.md) | Sibling specialization | Collects through APIs; SAF-T1803 is distinguished by dump-equivalent database acquisition. <!-- SAF-TRACE: claims=SAF-T1803-C014; sources=SRC-postgresql-pgdump-18,SRC-mitre-attack-t1213-006 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1213.006](https://attack.mitre.org/techniques/T1213/006/) | Data from Information Repositories: Databases | Direct | Both cover obtaining data from databases for Collection; SAF-T1803 narrows the behavior to MCP-connected or agentic dump-equivalent operations and their intent boundary. <!-- SAF-TRACE: claims=SAF-T1803-C006,SAF-T1803-C014; sources=SRC-mitre-attack-t1213-006,SRC-postgresql-pgdump-18 --> |

## References

1. **SRC-mcp-tools-2026-07-28**: [Model Context Protocol — Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — Tool semantics, user interaction, and security guidance. <!-- SAF-TRACE: claims=SAF-T1803-C001,SAF-T1803-C010,SAF-T1803-C011; sources=SRC-mcp-tools-2026-07-28 -->
2. **SRC-mcp-security-2025-11-25**: [Model Context Protocol — Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — Consent, privilege, and sandboxing guidance. <!-- SAF-TRACE: claims=SAF-T1803-C011; sources=SRC-mcp-security-2025-11-25 -->
3. **SRC-postgresql-pgdump-18**: [PostgreSQL 18 — pg_dump](https://www.postgresql.org/docs/current/app-pgdump.html) — Logical export behavior and privilege limits. <!-- SAF-TRACE: claims=SAF-T1803-C002,SAF-T1803-C014,SAF-T1803-C016; sources=SRC-postgresql-pgdump-18 -->
4. **SRC-postgresql-pg-stat-activity-18**: [PostgreSQL 18 — Monitoring Database Activity](https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-PG-STAT-ACTIVITY-VIEW) — Activity fields and limitations. <!-- SAF-TRACE: claims=SAF-T1803-C009,SAF-T1803-C010; sources=SRC-postgresql-pg-stat-activity-18 -->
5. **SRC-mitre-attack-t1213-006**: [MITRE ATT&CK T1213.006](https://attack.mitre.org/techniques/T1213/006/) — Database collection and detection strategies. <!-- SAF-TRACE: claims=SAF-T1803-C006,SAF-T1803-C014,SAF-T1803-C016; sources=SRC-mitre-attack-t1213-006 -->
6. **SRC-anthropic-espionage-2025-11**: [Anthropic Threat Intelligence report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) — Production agentic database-extraction incident. <!-- SAF-TRACE: claims=SAF-T1803-C003,SAF-T1803-C015,SAF-T1803-C016; sources=SRC-anthropic-espionage-2025-11 -->
7. **SRC-mandiant-unc5537-2024**: [Mandiant — UNC5537 Snowflake Data Theft and Extortion](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion) — Significant database export analogy. <!-- SAF-TRACE: claims=SAF-T1803-C007,SAF-T1803-C012; sources=SRC-mandiant-unc5537-2024 -->
8. **SRC-mandiant-snowflake-hunting-2024**: [Mandiant — Snowflake Threat Hunting Guide](https://services.google.com/fh/files/misc/snowflake-threat-hunting-guide.pdf) — Database anomaly, staging, retrieval, and false-positive guidance. <!-- SAF-TRACE: claims=SAF-T1803-C008,SAF-T1803-C010,SAF-T1803-C012; sources=SRC-mandiant-snowflake-hunting-2024 -->
9. **SRC-nvd-mcp-database-search**: [NVD CVE API](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=model%20context%20protocol%20database) — Bounded MCP database vulnerability search. <!-- SAF-TRACE: claims=SAF-T1803-C015; sources=SRC-nvd-mcp-database-search -->
10. **SRC-cve-2026-33980**: [CVE-2026-33980 record](https://cveawg.mitre.org/api/cve/CVE-2026-33980) — ADX MCP KQL injection, affected range, and exploitation enrichment. <!-- SAF-TRACE: claims=SAF-T1803-C004,SAF-T1803-C005; sources=SRC-cve-2026-33980 -->
11. **SRC-ghsa-vphc-468g-8rfp**: [GHSA-vphc-468g-8rfp](https://github.com/pab1it0/adx-mcp-server/security/advisories/GHSA-vphc-468g-8rfp) — Exact advisory reached from the CVE authority. <!-- SAF-TRACE: claims=SAF-T1803-C004,SAF-T1803-C005; sources=SRC-ghsa-vphc-468g-8rfp -->
12. **SRC-adx-patch-0abe0ee**: [ADX MCP Server patch](https://github.com/pab1it0/adx-mcp-server/commit/0abe0ee55279e111281076393e5e966335fffd30) — Exact maintainer fix reached from the CVE authority. <!-- SAF-TRACE: claims=SAF-T1803-C005,SAF-T1803-C011; sources=SRC-adx-patch-0abe0ee -->
13. **SRC-pypi-adx-mcp-server**: [ADX MCP Server on PyPI](https://pypi.org/project/adx-mcp-server/) — Published release state. <!-- SAF-TRACE: claims=SAF-T1803-C005; sources=SRC-pypi-adx-mcp-server -->
14. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — Bounded exact-ID exploitation-catalog checks. <!-- SAF-TRACE: claims=SAF-T1803-C013,SAF-T1803-C015; sources=SRC-cisa-kev-2026-09-01 -->
15. **SRC-cve-2026-75133**: [CVE-2026-75133 record](https://cveawg.mitre.org/api/cve/CVE-2026-75133) — Unauthenticated MySQL dump analogy. <!-- SAF-TRACE: claims=SAF-T1803-C013; sources=SRC-cve-2026-75133 -->
16. **SRC-wordpress-keep-backup-daily**: [Keep Backup Daily changelog](https://wordpress.org/plugins/keep-backup-daily/#developers) — Remediation boundary and researcher credit. <!-- SAF-TRACE: claims=SAF-T1803-C013; sources=SRC-wordpress-keep-backup-daily -->

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-02 | Initial clean-room publication candidate with tested detection and evidence packet. | OpenAI Codex clean-room agent `/root/cleanroom_saf_t1803` |
