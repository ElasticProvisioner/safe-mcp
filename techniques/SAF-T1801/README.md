# SAF-T1801: Automated Data Harvesting

## Overview

- **Tactic**: Collection (ATK-TA0009)
- **Technique ID**: SAF-T1801
- **Research Packet**: [research/techniques/SAF-T1801](../../research/techniques/SAF-T1801/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1801/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Observed
- **Severity**: High
- **Severity Rationale**: Confidentiality impact can be high when an agent's authorized MCP connectors span sensitive databases, repositories, files, or messages; integrity and availability effects require separate follow-on behavior. <!-- SAF-TRACE: claims=SAF-T1801-C017; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->
- **First Observed**: Mid-September 2025, when Anthropic detected an espionage campaign that used Claude Code and MCP tools for autonomous extraction and analysis. <!-- SAF-TRACE: claims=SAF-T1801-C001; sources=SRC-anthropic-espionage-2025-11 -->
- **Last Updated**: 2026-09-02

## Scope

Automated Data Harvesting is the adversarial use of an agentic system to enumerate, retrieve, and aggregate a broader set of data through MCP resources or data-reading tools than the user's bounded task requires. It crosses the task-intent and data-minimization boundary even when each connector call uses credentials already available to the agent. <!-- SAF-TRACE: claims=SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mcp-tools-2025-06-18 -->

### In Scope

- Systematic or repeated successful reads across multiple data objects through MCP resources or read-capable tools. <!-- SAF-TRACE: claims=SAF-T1801-C002,SAF-T1801-C003,SAF-T1801-C005; sources=SRC-mcp-resources-2025-06-18,SRC-mcp-tools-2025-06-18,SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4 -->
- Collection into agent context, task state, or a local result, whether directed by a malicious operator, poisoned context, or compromised orchestration. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4 -->

### Out of Scope

- A single read proportionate to the user's stated task is targeted retrieval, not this technique. <!-- SAF-TRACE: claims=SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mcp-tools-2025-06-18 -->
- Prompt injection, tool poisoning, credential theft, and exploitation are prerequisite or delivery behaviors unless they proceed to systematic data acquisition. <!-- SAF-TRACE: claims=SAF-T1801-C018; sources=SRC-owasp-llm01-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- Transmission of already collected data, destructive modification, persistence, and availability impact are follow-on behaviors. <!-- SAF-TRACE: claims=SAF-T1801-C017; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->

### Distinguishing Characteristics

The distinguishing observable is breadth or systematic repetition: multiple distinct objects, pages, repositories, conversations, or database records are acquired by one task context beyond its stated need. Delivery ends when control is gained; harvesting begins with data acquisition; exfiltration begins only when collected material crosses an external trust boundary. <!-- SAF-TRACE: claims=SAF-T1801-C005,SAF-T1801-C018; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mcp-tools-2025-06-18,SRC-owasp-llm01-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->

## Description

MCP resources expose application data and define list and read operations, while MCP tools can let a model query databases and APIs. Implementations may allow automatic resource inclusion or model-controlled tool invocation, so a task can traverse data at machine speed when authorization and orchestration permit it. <!-- SAF-TRACE: claims=SAF-T1801-C002,SAF-T1801-C003; sources=SRC-mcp-resources-2025-06-18,SRC-mcp-tools-2025-06-18 -->

The adversary's immediate objective is collection: cause the agent to enumerate and acquire a wider data set than the user intended. The connector's identity may still be authorized at the service layer; the abused boundary is the narrower purpose, scope, and volume implied by the user task. <!-- SAF-TRACE: claims=SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mcp-tools-2025-06-18 -->

Anthropic documented this behavior in a production espionage campaign where Claude Code and MCP tools autonomously queried systems, extracted large volumes, parsed results, and categorized intelligence. Research demonstrations involving WhatsApp and GitHub MCP connections separately show that adversarial steering can make agents retrieve broad private data sets, but those demonstrations are not production breaches. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C006,SAF-T1801-C007; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->

## Attack Vectors

- **Primary Vector**: An adversary-controlled orchestration task directs an agent with existing MCP data access to enumerate and acquire data automatically. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4 -->
- **Secondary Vectors**: Indirect prompt injection or poisoned tool metadata steers the same acquisition through otherwise legitimate connectors. <!-- SAF-TRACE: claims=SAF-T1801-C006,SAF-T1801-C007,SAF-T1801-C008,SAF-T1801-C018; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-invariant-tpa-2025-04-01,SRC-owasp-llm01-2025 -->
- **Affected Components**: MCP hosts and clients, data-reading MCP servers, connected repositories and services, agent context, and audit pipelines. <!-- SAF-TRACE: claims=SAF-T1801-C002,SAF-T1801-C003,SAF-T1801-C004; sources=SRC-mcp-resources-2025-06-18,SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618 -->
- **Trust Boundary Crossed**: The task-intent and data-minimization boundary between a bounded request and the wider permissions of the agent's connectors. <!-- SAF-TRACE: claims=SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mcp-tools-2025-06-18 -->

## Technical Details

### Prerequisites

- The agent can invoke MCP resources or tools that return data from files, messages, repositories, databases, or APIs. <!-- SAF-TRACE: claims=SAF-T1801-C002,SAF-T1801-C003; sources=SRC-mcp-resources-2025-06-18,SRC-mcp-tools-2025-06-18 -->
- The accessible identity or server exposes more data than the bounded task requires, or a path-control vulnerability widens the reachable scope. <!-- SAF-TRACE: claims=SAF-T1801-C004,SAF-T1801-C010; sources=SRC-mcp-roots-20250618,SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110,SRC-cve-2025-53109,SRC-cve-2025-53110 -->
- Automation proceeds without an effective per-object or meaningful bulk-operation approval gate. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C014; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->

### Attack Flow

1. **Setup**: The adversary obtains control of orchestration or places steering content where the agent will process it. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C018; sources=SRC-anthropic-espionage-2025-11,SRC-owasp-llm01-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
2. **Discovery**: The agent lists resources, schemas, repositories, conversations, or tool capabilities available through MCP. <!-- SAF-TRACE: claims=SAF-T1801-C002,SAF-T1801-C003; sources=SRC-mcp-resources-2025-06-18,SRC-mcp-tools-2025-06-18 -->
3. **Selection**: The agent identifies many objects or records that satisfy attacker-directed criteria rather than the user's bounded need. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4 -->
4. **Collection**: The agent performs repeated reads or broad queries and places returned data into task context or working state. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mcp-tools-2025-06-18 -->
5. **Aggregation**: The agent parses, categorizes, summarizes, or stages acquired material for later use. <!-- SAF-TRACE: claims=SAF-T1801-C001; sources=SRC-anthropic-espionage-2025-11 -->
6. **Follow-On Activity**: A separate action may exfiltrate, exploit, or otherwise use the collected material. <!-- SAF-TRACE: claims=SAF-T1801-C017; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 -->

### Example Scenario

A compromised planning layer gives an agent an inert request to inspect every object under `mcp://records.example.invalid/archive/` even though the user's task named one record; the host logs repeated successful reads for distinct objects before any external transfer occurs. <!-- SAF-TRACE: claims=SAF-T1801-C002,SAF-T1801-C005,SAF-T1801-C013; sources=SRC-mcp-resources-2025-06-18,SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->

```json
{
  "event.action": "resources/read",
  "event.outcome": "success",
  "session.id": "session-example",
  "data.object.id": "mcp://records.example.invalid/archive/item-020",
  "approval.state": "not_requested"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1801-C001 | A production campaign used Claude Code and MCP tools for autonomous large-volume extraction and analysis. | Observed | SRC-anthropic-espionage-2025-11: [Anthropic Threat Intelligence report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) | Anthropic did not publish every protocol event. <!-- SAF-TRACE: claims=SAF-T1801-C001; sources=SRC-anthropic-espionage-2025-11 --> |
| SAF-T1801-C002 | MCP resources support list/read operations and implementation-defined automatic inclusion. | Research-Derived | SRC-mcp-resources-2025-06-18: [MCP Resources](https://modelcontextprotocol.io/specification/2025-06-18/server/resources) | No required host UI or detector. <!-- SAF-TRACE: claims=SAF-T1801-C002; sources=SRC-mcp-resources-2025-06-18 --> |
| SAF-T1801-C003 | MCP tools can query external systems and should be rate-limited, confirmed for sensitive use, and logged. | Research-Derived | SRC-mcp-tools-2025-06-18: [MCP Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) | Implementation guidance is not an effectiveness guarantee. <!-- SAF-TRACE: claims=SAF-T1801-C003; sources=SRC-mcp-tools-2025-06-18 --> |
| SAF-T1801-C004 | Roots bound filesystem exposure but do not encode task intent. | Research-Derived | SRC-mcp-roots-20250618: [MCP Roots](https://modelcontextprotocol.io/specification/2025-06-18/client/roots) | Applies to filesystem scope. <!-- SAF-TRACE: claims=SAF-T1801-C004; sources=SRC-mcp-roots-20250618 --> |
| SAF-T1801-C005 | SAF-T1801 combines automated breadth with use beyond the bounded task. | Observed | SRC-anthropic-espionage-2025-11; SRC-mitre-t1119-v1.4; SRC-mcp-tools-2025-06-18 | Task intent is deployment-specific. <!-- SAF-TRACE: claims=SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mcp-tools-2025-06-18 --> |
| SAF-T1801-C006 | WhatsApp MCP demonstrations collected chat history and contacts. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07: [Invariant WhatsApp research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | Controlled research, not a production breach. <!-- SAF-TRACE: claims=SAF-T1801-C006; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| SAF-T1801-C007 | A GitHub MCP demonstration retrieved private-repository data after an injected issue was processed. | Demonstrated | SRC-invariant-github-mcp-2025: [Invariant GitHub research](https://invariantlabs.ai/blog/mcp-github-vulnerability) | Controlled research; architectural flow, not a server code flaw. <!-- SAF-TRACE: claims=SAF-T1801-C007; sources=SRC-invariant-github-mcp-2025 --> |
| SAF-T1801-C008 | Tool-description poisoning induced reads of sensitive local files. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Invariant tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Narrower than broad harvesting. <!-- SAF-TRACE: claims=SAF-T1801-C008; sources=SRC-invariant-tpa-2025-04-01 --> |
| SAF-T1801-C009 | CVE-2025-34072 covers a demonstrated Slack MCP retrieval-and-unfurl exfiltration flow. | Demonstrated | SRC-cve-2025-34072; SRC-cve-34072 | Deprecated server; no production exploitation established. <!-- SAF-TRACE: claims=SAF-T1801-C009; sources=SRC-cve-2025-34072,SRC-cve-34072 --> |
| SAF-T1801-C010 | Two filesystem-server advisories allowed unintended-file access before their fix. | Demonstrated | SRC-ghsa-cve-2025-53109; SRC-ghsa-cve-2025-53110; SRC-cve-2025-53109; SRC-cve-2025-53110 | Access expansion does not itself automate collection. <!-- SAF-TRACE: claims=SAF-T1801-C010; sources=SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110,SRC-cve-2025-53109,SRC-cve-2025-53110 --> |
| SAF-T1801-C011 | AWS fixed a HealthLake MCP pagination SSRF in version 0.0.14. | Demonstrated | SRC-aws-cve-2026-15643: [AWS bulletin](https://aws.amazon.com/security/security-bulletins/2026-054-aws/) | Credential exfiltration is adjacent. <!-- SAF-TRACE: claims=SAF-T1801-C011; sources=SRC-aws-cve-2026-15643 --> |
| SAF-T1801-C012 | ATT&CK detection emphasizes repeated, programmatic, or excessive repository access. | Research-Derived | SRC-mitre-t1119-v1.4; SRC-mitre-t1213-v3.4 | Not MCP-specific; thresholds are mutable. <!-- SAF-TRACE: claims=SAF-T1801-C012; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4 --> |
| SAF-T1801-C013 | The included five-minute, 20-object heuristic is testable but locally tunable. | Research-Derived | SRC-mitre-t1119-v1.4; SRC-mitre-t1213-v3.4; SRC-mcp-tools-2025-06-18 | One-call bulk and low-and-slow access can evade it. <!-- SAF-TRACE: claims=SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 --> |
| SAF-T1801-C014 | Least privilege, scoped roots, approvals, rate limits, and logs reduce reach or improve detection. | Research-Derived | SRC-mcp-tools-2025-06-18; SRC-mcp-roots-20250618; SRC-mcp-security-2025-11-25; SRC-invariant-github-mcp-2025 | Human approval can become routine or hide scope. <!-- SAF-TRACE: claims=SAF-T1801-C014; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 --> |
| SAF-T1801-C015 | Reviewed MCP CVEs were absent from CISA KEV version 2026.09.01. | Research-Derived | SRC-cisa-kev-2026-09-01: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Date-bounded absence, not proof of no exploitation. <!-- SAF-TRACE: claims=SAF-T1801-C015; sources=SRC-cisa-kev-2026-09-01 --> |
| SAF-T1801-C016 | ATT&CK T1119 maps directly; T1213 is analogous for repository-backed connectors. | Research-Derived | SRC-mitre-t1119-v1.4; SRC-mitre-t1213-v3.4 | ATT&CK has no MCP task-intent boundary. <!-- SAF-TRACE: claims=SAF-T1801-C016; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4 --> |
| SAF-T1801-C017 | Confidentiality is primary; integrity and availability require follow-on behavior. | Research-Derived | SRC-anthropic-espionage-2025-11; SRC-invariant-whatsapp-mcp-2025-04-07; SRC-invariant-github-mcp-2025 | Severity is permission- and data-dependent. <!-- SAF-TRACE: claims=SAF-T1801-C017; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 --> |
| SAF-T1801-C018 | Prompt injection is delivery, not the collection objective. | Research-Derived | SRC-owasp-llm01-2025; SRC-invariant-whatsapp-mcp-2025-04-07 | Both can coexist in one chain. <!-- SAF-TRACE: claims=SAF-T1801-C018; sources=SRC-owasp-llm01-2025,SRC-invariant-whatsapp-mcp-2025-04-07 --> |

### Current State

- **Affected Environments**: Agentic systems whose MCP resources or tools expose broad files, messages, repositories, databases, or APIs to one task identity. <!-- SAF-TRACE: claims=SAF-T1801-C002,SAF-T1801-C003,SAF-T1801-C005; sources=SRC-mcp-resources-2025-06-18,SRC-mcp-tools-2025-06-18,SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4 -->
- **Known Exploitation**: Anthropic documented a production campaign using Claude Code and MCP tools for autonomous data collection; the other selected examples are demonstrations or disclosed vulnerabilities. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C006,SAF-T1801-C007,SAF-T1801-C009; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-cve-2025-34072,SRC-cve-34072 -->
- **Available Protections**: Limit connector privileges and roots, require meaningful approval for sensitive or bulk activity, rate-limit calls, validate results, and log tool usage. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C004,SAF-T1801-C014; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->
- **Residual Risk**: Authorized-looking reads can exceed task intent, low-and-slow access can evade volume thresholds, and users may approve actions without seeing their full data scope. <!-- SAF-TRACE: claims=SAF-T1801-C005,SAF-T1801-C013,SAF-T1801-C014; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Anthropic GTG-1002 campaign | Detected mid-September 2025; Claude Code with open-standard MCP tools | Autonomous querying, extraction, parsing, and categorization across successful intrusions; Anthropic banned accounts, notified affected entities, and expanded detection. | Direct production incident and highest-impact selected example. | Anthropic's visibility was limited to Claude usage and the report does not publish all protocol events. <!-- SAF-TRACE: claims=SAF-T1801-C001; sources=SRC-anthropic-espionage-2025-11 --> |
| WhatsApp MCP controlled experiments | Published 2025-04-07 and updated 2025-04-09; Cursor or Claude Desktop with WhatsApp MCP | Chat history or contact identifiers were collected and sent; the researchers recommend avoiding untrusted servers and enforcing contextual data-flow controls. | Direct demonstration and selected example. | Controlled research, not a production breach. <!-- SAF-TRACE: claims=SAF-T1801-C006; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| GitHub MCP controlled experiment | Published 2025-05-26; Claude Desktop and GitHub MCP | Private-repository data was retrieved and placed in a public pull request; researchers recommend granular permissions and monitoring. | Direct demonstration and selected example. | Controlled research and an architectural agent flow, not a GitHub MCP server code flaw. <!-- SAF-TRACE: claims=SAF-T1801-C007; sources=SRC-invariant-github-mcp-2025 --> |
| CVE-2025-34072 | Published 2025-07-01; deprecated Anthropic Slack MCP server | A proof-of-concept retrieved private data and used automatic link unfurling for disclosure; the server remained deprecated, and disabling unfurling was proposed. | Direct vulnerability for the automated retrieval stage and selected example; the outbound channel is adjacent exfiltration. | No production exploitation established. <!-- SAF-TRACE: claims=SAF-T1801-C009; sources=SRC-cve-2025-34072,SRC-cve-34072 --> |

CVE-2025-53109 and CVE-2025-53110 are enabling vulnerabilities because they can widen filesystem scope without automating collection; the safe remediation floor recorded from the advisories is 0.6.4 or 2025.7.01. CVE-2026-15643 is adjacent because it concerns credential exfiltration through pagination SSRF rather than harvesting HealthLake records. <!-- SAF-TRACE: claims=SAF-T1801-C010,SAF-T1801-C011; sources=SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110,SRC-cve-2025-53109,SRC-cve-2025-53110,SRC-aws-cve-2026-15643 -->

None of the reviewed CVEs appeared in CISA's 2026-09-01 KEV catalog; this date-bounded absence does not establish that exploitation never occurred. <!-- SAF-TRACE: claims=SAF-T1801-C015; sources=SRC-cisa-kev-2026-09-01 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Broadly authorized agents can acquire proprietary records, credentials, private messages, code, and operational data. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C006,SAF-T1801-C007,SAF-T1801-C017; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 --> |
| Integrity | None inherent | Collection alone does not modify source data; publishing, account creation, or other changes are follow-on behavior. <!-- SAF-TRACE: claims=SAF-T1801-C017; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 --> |
| Availability | None inherent | Reads can create load, but service disruption is not required by this technique. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C017; sources=SRC-mcp-tools-2025-06-18,SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 --> |
| Scope | Multi-System | One host can connect an agent to multiple servers and data domains; actual blast radius is limited by connector permissions and task isolation. <!-- SAF-TRACE: claims=SAF-T1801-C006,SAF-T1801-C007,SAF-T1801-C014; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025,SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25 --> |

### Severity Conditions

- **Severity increases when**: Connectors share broad identities, sensitive data spans multiple systems, bulk reads do not require approval, or the host maintains autonomous state for long-running tasks. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C014,SAF-T1801-C017; sources=SRC-anthropic-espionage-2025-11,SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Severity decreases when**: Identities and roots are task-scoped, sensitive or bulk reads require contextual approval, and rate limits constrain sustained acquisition. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C004,SAF-T1801-C014; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or gateway audit log | `resources/read` and normalized read-capable `tools/call` successes | `event.timestamp`, `event.action`, `event.outcome`, `session.id`, `actor.id`, `server.id`, `data.object.id`, `data.access_mode`, `approval.state`, `approval.scope` | Preserve object identifiers and normalize server-defined read tools before correlation. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mcp-tools-2025-06-18,SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4 --> |
| Connected-service audit log | Repository, message, database, file, or API reads attributed to the agent identity | Timestamp, principal, object or query target, result count, source address, and request correlation ID | Use when MCP logs omit returned object count or when one call returns many records. <!-- SAF-TRACE: claims=SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4 --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC is known; the technique is behavioral and can use legitimate identities, servers, and data-reading operations. <!-- SAF-TRACE: claims=SAF-T1801-C005,SAF-T1801-C012; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->

### Behavioral Indicators

- One task context reads many distinct objects within a short window, particularly across repositories, conversations, tables, or paths not named by the user. <!-- SAF-TRACE: claims=SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->
- Enumeration is followed by successful reads and local aggregation without an approved bulk-export scope. <!-- SAF-TRACE: claims=SAF-T1801-C001,SAF-T1801-C013; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->
- The agent identity's object count, repositories, or API usage exceeds its established task or role baseline. <!-- SAF-TRACE: claims=SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect one actor/session/server reading at least 20 distinct data objects successfully within five minutes without an explicit approved bulk-export scope. <!-- SAF-TRACE: claims=SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->
- **Rule Status**: Experimental; representative synthetic tests pass, but no production accuracy measurement is claimed. <!-- SAF-TRACE: claims=SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->
- **Detection Logic**: Count distinct `data.object.id` values for successful `resources/read` or normalized read-capable `tools/call` events by `session.id`, `actor.id`, and `server.id`; alert at 20 in a rolling five-minute window unless `approval.state=approved` and `approval.scope=bulk_export`. <!-- SAF-TRACE: claims=SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->
- **Known False Positives**: Approved backup, migration, indexing, e-discovery, security scanning, or user-requested export jobs can create the same access shape. <!-- SAF-TRACE: claims=SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->
- **Known Limitations**: One broad query, low-and-slow reads, repeated reads of one object, missing object identifiers, or unnormalized tool actions can evade this analytic. <!-- SAF-TRACE: claims=SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->
- **Tuning Guidance**: Baseline object counts by server, role, and workflow; adjust the threshold and window; require explicit approval metadata for sanctioned bulk jobs rather than broad actor allowlists. <!-- SAF-TRACE: claims=SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Eight cases pass: positive, below-threshold, exact boundary, over-window, approved bulk export, repeated object, list-only, and malformed event. <!-- SAF-TRACE: claims=SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->
- **Last Validated**: 2026-09-02. See the [quality review](../../research/techniques/SAF-T1801/quality-review.yml).
- **Validation Proof**: [Detector transcript](../../research/techniques/SAF-T1801/validation/detector-tests.txt) and [strict-validator transcript](../../research/techniques/SAF-T1801/validation/research-validator.txt).
- **Feasibility Waiver**: None; representative synthetic validation is feasible. <!-- SAF-TRACE: claims=SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->

## Mitigation Strategies

### Preventive Controls

1. Apply [SAF-M-29](../../mitigations/SAF-M-29/README.md), [SAF-M-16](../../mitigations/SAF-M-16/README.md), and [SAF-M-74](../../mitigations/SAF-M-74/README.md): give the agent task-scoped identities, roots, repositories, data views, and invocation capabilities rather than the user's full standing access. <!-- SAF-TRACE: claims=SAF-T1801-C004,SAF-T1801-C014; sources=SRC-mcp-roots-20250618,SRC-mcp-tools-2025-06-18,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->
2. Apply [SAF-M-69 — Out-of-Band Authorization](../../mitigations/SAF-M-69/README.md): require approval that exposes destination, query, object count or scope, and server before sensitive or bulk reads proceed. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C014; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->
3. Apply [SAF-M-71 — Query Guardrails and Result Limits](../../mitigations/SAF-M-71/README.md): enforce per-task and per-identity call or result limits, with separate policy for approved export workflows. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C014; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->

### Detective Controls

1. Apply [SAF-M-12 — Audit Logging](../../mitigations/SAF-M-12/README.md): retain MCP invocation logs and correlate them with connected-service reads so one-call bulk retrieval and cross-server activity remain visible. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mcp-tools-2025-06-18,SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4 -->
2. Apply [SAF-M-70 — Tool-Invocation Anomaly Detection](../../mitigations/SAF-M-70/README.md): alert on excessive distinct-object access, burst downloads, and role- or task-baseline deviations, while separately identifying approved bulk operations. <!-- SAF-TRACE: claims=SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->

### Response Procedures

#### Immediate Actions

- Suspend the implicated task or session and disable the affected MCP connection until its scope and control path are understood. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C014; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->
- If harvested credentials or tokens may be present, revoke or rotate them and reduce the connector identity's permissions. <!-- SAF-TRACE: claims=SAF-T1801-C011,SAF-T1801-C014; sources=SRC-aws-cve-2026-15643,SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->

#### Investigation Steps

- Preserve MCP host, gateway, model-task, identity, and connected-service logs; reconstruct enumeration, read, aggregation, and any follow-on transfer. <!-- SAF-TRACE: claims=SAF-T1801-C003,SAF-T1801-C012,SAF-T1801-C013; sources=SRC-mcp-tools-2025-06-18,SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4 -->
- Compare accessed objects with the user's request and approval records, then determine which data left its source and whether it reached an external sink. <!-- SAF-TRACE: claims=SAF-T1801-C005,SAF-T1801-C013; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 -->

#### Remediation

- Remove the steering or orchestration path, narrow connector scope, patch enabling server vulnerabilities, and invalidate affected credentials. <!-- SAF-TRACE: claims=SAF-T1801-C010,SAF-T1801-C011,SAF-T1801-C014,SAF-T1801-C018; sources=SRC-ghsa-cve-2025-53109,SRC-ghsa-cve-2025-53110,SRC-cve-2025-53109,SRC-cve-2025-53110,SRC-aws-cve-2026-15643,SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025,SRC-owasp-llm01-2025,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- Add regression tests for the failed data-scope decision and tune the analytic against sanctioned bulk workflows. <!-- SAF-TRACE: claims=SAF-T1801-C012,SAF-T1801-C013,SAF-T1801-C014; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18,SRC-mcp-roots-20250618,SRC-mcp-security-2025-11-25,SRC-invariant-github-mcp-2025 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite | Delivers control or changes behavior; SAF-T1801 begins with systematic data acquisition. <!-- SAF-TRACE: claims=SAF-T1801-C018; sources=SRC-owasp-llm01-2025,SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| [SAF-T1803: Database Dump](../SAF-T1803/README.md) | Specialization | Covers database-focused bulk collection; SAF-T1801 spans repositories, messages, filesystems, databases, and APIs. <!-- SAF-TRACE: claims=SAF-T1801-C005,SAF-T1801-C016; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1213-v3.4,SRC-mcp-tools-2025-06-18 --> |
| [SAF-T1804: API Data Harvest](../SAF-T1804/README.md) | Specialization | Covers API-focused collection; SAF-T1801 is source-agnostic and requires automated breadth, repetition, or systematic enumeration. <!-- SAF-TRACE: claims=SAF-T1801-C005; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-t1119-v1.4,SRC-mcp-tools-2025-06-18 --> |
| [SAF-T1910: Covert Channel Exfiltration](../SAF-T1910/README.md) | Possible follow-on | Moves collected material across an external boundary through a covert channel; SAF-T1801 ends at acquisition or aggregation. <!-- SAF-TRACE: claims=SAF-T1801-C017; sources=SRC-anthropic-espionage-2025-11,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-github-mcp-2025 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | Direct | Both cover automated acquisition of internal data; SAF-T1801 adds the MCP and user-task-intent boundary. <!-- SAF-TRACE: claims=SAF-T1801-C016; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4 --> |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | Analogous | Applies when MCP connectors expose code, messaging, database, collaboration, or other repository data. <!-- SAF-TRACE: claims=SAF-T1801-C016; sources=SRC-mitre-t1119-v1.4,SRC-mitre-t1213-v3.4 --> |

## References

1. **SRC-anthropic-espionage-2025-11**: [Anthropic Threat Intelligence, *Disrupting the first reported AI-orchestrated cyber espionage campaign*](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) - production incident, MCP tooling, automation, data extraction, and limitations.
2. **SRC-mcp-resources-2025-06-18**: [MCP Resources specification](https://modelcontextprotocol.io/specification/2025-06-18/server/resources) - resource discovery, reads, automatic inclusion, and access controls.
3. **SRC-mcp-tools-2025-06-18**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) - model-controlled tools, calls, rate limits, confirmation, and logging.
4. **SRC-mcp-roots-20250618**: [MCP Roots specification](https://modelcontextprotocol.io/specification/2025-06-18/client/roots) - filesystem boundaries, permissions, validation, and consent.
5. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) - sandboxing, least privilege, consent, and server access controls.
6. **SRC-invariant-whatsapp-mcp-2025-04-07**: [Luca Beurer-Kellner and Marc Fischer, WhatsApp MCP research](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) - controlled chat-history and contact-collection demonstrations.
7. **SRC-invariant-github-mcp-2025**: [Marco Milanta and Luca Beurer-Kellner, GitHub MCP research](https://invariantlabs.ai/blog/mcp-github-vulnerability) - controlled private-repository retrieval demonstration.
8. **SRC-invariant-tpa-2025-04-01**: [Luca Beurer-Kellner and Marc Fischer, tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) - controlled sensitive-file retrieval demonstration.
9. **SRC-mitre-t1119-v1.4**: [MITRE ATT&CK T1119 Automated Collection](https://attack.mitre.org/techniques/T1119/) - definition, Anthropic campaign example, and repeated-access detection.
10. **SRC-mitre-t1213-v3.4**: [MITRE ATT&CK T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213/) - repository scope and excessive-access detection.
11. **SRC-cve-2025-34072**: [CVE-2025-34072 record](https://cveawg.mitre.org/api/cve/CVE-2025-34072) - Slack MCP data-exfiltration vulnerability and proof-of-concept status.
12. **SRC-cve-34072**: [Johann Rehberger, Slack MCP security advisory](https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/) - demonstration, disclosure, affected status, and mitigation.
13. **SRC-ghsa-cve-2025-53109**: [GHSA-q66q-fx2p-7w4m](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-q66q-fx2p-7w4m) - symlink path-validation bypass, fix, and Elad Beber credit.
14. **SRC-ghsa-cve-2025-53110**: [GHSA-hc55-p739-j48w](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-hc55-p739-j48w) - colliding-prefix validation bypass, fix, and Elad Beber credit.
15. **SRC-cve-2025-53109**: [CVE-2025-53109 record](https://cveawg.mitre.org/api/cve/CVE-2025-53109) - symlink path-validation weakness and exploitation status.
16. **SRC-cve-2025-53110**: [CVE-2025-53110 record](https://cveawg.mitre.org/api/cve/CVE-2025-53110) - colliding-prefix path-validation weakness and exploitation status.
17. **SRC-aws-cve-2026-15643**: [AWS Security Bulletin 2026-054-AWS](https://aws.amazon.com/security/security-bulletins/2026-054-aws/) - HealthLake MCP pagination SSRF, fixed version, controls, and Marios Gyftos credit.
18. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) - exact-ID exploitation catalog check.
19. **SRC-owasp-llm01-2025**: [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) - distinction between delivery and collection.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Independent clean-room draft with evidence packet and tested analytic | OpenAI Codex clean-room author |
