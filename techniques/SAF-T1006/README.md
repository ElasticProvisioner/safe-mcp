# SAF-T1006: User-Social-Engineering Install

## Overview

- **Tactic**: Initial Access (ATK-TA0001)
- **Technique ID**: SAF-T1006
- **Research Packet**: [research/techniques/SAF-T1006](../../research/techniques/SAF-T1006/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1006/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Deceptive MCP installation can produce attacker-selected code execution with the accepting user's access; sandboxing and least privilege bound the consequence. <!-- SAF-TRACE: claims=SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494 -->
- **First Observed**: No qualifying MCP production incident was identified in the reviewed corpus as of 2026-09-01; the direct evidence consists of public vulnerability demonstrations. [Coverage record](../../research/techniques/SAF-T1006/source-coverage.yml)
- **Last Updated**: 2026-09-01

## Scope

This technique covers deception that causes a user to initiate or approve an attacker-controlled local MCP server installation, configuration, trust decision, or first launch, crossing the user-to-local-runtime boundary. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003,SAF-T1006-C004; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523,SRC-mcp-security-2025-11-25 -->

### In Scope

- Attacker-supplied MCP install links, configuration records, package identities, or startup commands that are presented deceptively to a user. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523 -->
- User interaction that initiates or approves adding, trusting, or starting the supplied integration. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523 -->
- Registration or execution of the attacker-controlled local server command with the client or user account's access. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003,SAF-T1006-C004; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523,SRC-mcp-security-2025-11-25 -->

### Out of Scope

- Lure delivery that does not culminate in an MCP install or trust action, and generic malicious-file execution outside MCP. <!-- SAF-TRACE: claims=SAF-T1006-C010,SAF-T1006-C011; sources=SRC-mitre-attack-t1204-002,SRC-unit42-contagious-interview -->
- Automatic project-configuration execution without a user MCP install or trust decision. <!-- SAF-TRACE: claims=SAF-T1006-C009; sources=SRC-zed-secure-default -->
- Post-install prompt injection, malicious tool behavior, credential use, persistence, and other follow-on objectives. <!-- SAF-TRACE: claims=SAF-T1006-C004,SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494 -->
- Compromise or substitution of an already trusted package or update; origin and integrity failure is related but does not require social engineering at installation. <!-- SAF-TRACE: claims=SAF-T1006-C012; sources=SRC-cwe-494 -->

### Distinguishing Characteristics

The decisive observable is a user-mediated MCP install or trust action followed by registration or execution of the same server. Project-open auto-execution lacks that decision; a later package substitution occurs after it. [The reconciled neighboring-technique boundaries are recorded in the contract.](../../research/techniques/SAF-T1006/technique-contract.yml)

## Description

Local MCP servers can be downloaded or configured as local binaries and may access resources available to the user or client. A deceptive installation therefore converts an apparently legitimate integration choice into local code execution. <!-- SAF-TRACE: claims=SAF-T1006-C004,SAF-T1006-C006; sources=SRC-mcp-security-2025-11-25,SRC-mcp-connect-local -->

The behavior is demonstrated, not observed in a qualifying production MCP incident: Cursor, Cherry Studio, and Dive advisories document user-interaction paths from an MCP installation deep link to attacker-selected local commands. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523 -->

Consent and trust dialogs are part of the security boundary. MCP guidance calls for the full command, an explicit code-execution warning, approval, and cancellation; VS Code separately warns that local servers can run arbitrary code and exposes first-start trust. <!-- SAF-TRACE: claims=SAF-T1006-C005,SAF-T1006-C007; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers -->

## Attack Vectors

- **Primary Vector**: A deceptive MCP installation deep link or dialog causes the user to accept a server whose actual identity or command differs from its presentation. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523 -->
- **Secondary Vectors**: A copied local-server configuration or package-launch command is represented as a useful integration and then saved or started by the user. <!-- SAF-TRACE: claims=SAF-T1006-C004,SAF-T1006-C006; sources=SRC-mcp-security-2025-11-25,SRC-mcp-connect-local -->
- **Affected Components**: MCP client or host trust UI, local server configuration, package launcher, and child-process runtime. <!-- SAF-TRACE: claims=SAF-T1006-C004,SAF-T1006-C007; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers -->
- **Trust Boundary Crossed**: User intent and displayed server identity or command are converted into a persisted integration and local execution. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C005; sources=SRC-ghsa-cursor-64106,SRC-mcp-security-2025-11-25 -->

## Technical Details

### Prerequisites

- The target uses an MCP client that can add or start a local server from a link, configuration record, or package command. <!-- SAF-TRACE: claims=SAF-T1006-C004,SAF-T1006-C006,SAF-T1006-C007; sources=SRC-mcp-security-2025-11-25,SRC-mcp-connect-local,SRC-vscode-mcp-servers -->
- The adversary can place deceptive installation content where the user will interact with it. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523 -->
- The client permits the supplied local command to run, with consent missing, bypassed, incomplete, or defeated by the deception. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003,SAF-T1006-C005; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523,SRC-mcp-security-2025-11-25 -->

### Attack Flow

1. **Setup**: The adversary prepares an MCP server identity and installation representation that appears useful or trusted. <!-- SAF-TRACE: claims=SAF-T1006-C001; sources=SRC-ghsa-cursor-64106 -->
2. **Delivery**: The installation link or configuration reaches the user through a site, message, shared instruction, or comparable channel. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523 -->
3. **User Action**: The user opens the link, accepts the install, saves the configuration, or starts the presented server. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523 -->
4. **Boundary Crossing**: The client records the supplied server or passes its command to the local process runtime. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003,SAF-T1006-C004; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523,SRC-mcp-security-2025-11-25 -->
5. **Objective**: Attacker-controlled integration code executes with the access available to the client or user. <!-- SAF-TRACE: claims=SAF-T1006-C004,SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494 -->
6. **Follow-On Activity**: Any collection, modification, persistence, or disruption after launch is separately classified and bounded by privileges and sandbox controls. <!-- SAF-TRACE: claims=SAF-T1006-C008,SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-cwe-494 -->

### Example Scenario

An attacker presents an inertly named “calendar helper” MCP integration from an unverified publisher. A user accepts it; the client adds the server and starts a local process whose actual command is not associated with the represented publisher. The scenario stops at process start and includes no payload or operational command. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C004; sources=SRC-ghsa-cursor-64106,SRC-mcp-security-2025-11-25 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1006-C001 | Deceptive Cursor deep link and acceptance can execute concealed commands. | Demonstrated | SRC-ghsa-cursor-64106: [Cursor advisory](https://github.com/cursor/cursor/security/advisories/GHSA-4575-fh42-7848); SRC-nvd-mcp-catalog: [NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-64106) | Vulnerability demonstration, not production exploitation. <!-- SAF-TRACE: claims=SAF-T1006-C001; sources=SRC-ghsa-cursor-64106,SRC-nvd-mcp-catalog --> |
| SAF-T1006-C002 | Cherry Studio MCP URL click directly triggers its command before 1.6.4. | Demonstrated | SRC-ghsa-cherry-61929: [Cherry Studio advisory](https://github.com/CherryHQ/cherry-studio/security/advisories/GHSA-hh6w-rmjc-26f6); SRC-nvd-mcp-catalog: [NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-61929) | Low-consent edge of scope; no production exploitation shown. <!-- SAF-TRACE: claims=SAF-T1006-C002; sources=SRC-ghsa-cherry-61929,SRC-nvd-mcp-catalog --> |
| SAF-T1006-C003 | Dive crafted deep link bypasses confirmation and reaches local process execution through 0.12.6. | Demonstrated | SRC-ghsa-dive-23523: [Dive advisory](https://github.com/OpenAgentPlatform/Dive/security/advisories/GHSA-pjj5-f3wm-f9m8); SRC-nvd-mcp-catalog: [NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-23523) | Client flaw, not a protocol requirement or production incident. <!-- SAF-TRACE: claims=SAF-T1006-C003; sources=SRC-ghsa-dive-23523,SRC-nvd-mcp-catalog --> |
| SAF-T1006-C004 | Local MCP server configuration can produce user-context local execution. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices); SRC-mcp-connect-local: [MCP local-server guide](https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers) | Privileges depend on client and operating-system controls. <!-- SAF-TRACE: claims=SAF-T1006-C004; sources=SRC-mcp-security-2025-11-25,SRC-mcp-connect-local --> |
| SAF-T1006-C005 | One-click configuration guidance requires exact command display and explicit consent. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Guidance does not prove universal client compliance. <!-- SAF-TRACE: claims=SAF-T1006-C005; sources=SRC-mcp-security-2025-11-25 --> |
| SAF-T1006-C007 | VS Code documents arbitrary-code risk, source review, trust, and a direct-config prompt exception. | Research-Derived | SRC-vscode-mcp-servers: [VS Code MCP documentation](https://code.visualstudio.com/docs/agent-customization/mcp-servers) | Product-specific behavior. <!-- SAF-TRACE: claims=SAF-T1006-C007; sources=SRC-vscode-mcp-servers --> |
| SAF-T1006-C014 | Cross-source install-to-process correlation is a defensible experimental analytic. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices); SRC-sysmon-15-21: [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Requires normalized client events and environment tuning. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-sysmon-15-21 --> |

### Current State

- **Affected Environments**: MCP clients that accept local-server configuration or installation links and launch local commands. <!-- SAF-TRACE: claims=SAF-T1006-C004,SAF-T1006-C006,SAF-T1006-C007; sources=SRC-mcp-security-2025-11-25,SRC-mcp-connect-local,SRC-vscode-mcp-servers -->
- **Known Exploitation**: Three direct public vulnerability demonstrations qualify; no direct MCP production incident was found in the reviewed corpus. [Coverage record](../../research/techniques/SAF-T1006/source-coverage.yml)
- **Available Protections**: Exact command disclosure, explicit trust and cancellation, source and publisher review, integrity verification, least privilege, and server sandboxing reduce likelihood or impact. <!-- SAF-TRACE: claims=SAF-T1006-C005,SAF-T1006-C007,SAF-T1006-C008,SAF-T1006-C012; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-cwe-494 -->
- **Residual Risk**: A user can still accept a deceptive presentation, signed software can be malicious, and local telemetry may not expose normalized MCP semantics. <!-- SAF-TRACE: claims=SAF-T1006-C005,SAF-T1006-C012,SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494,SRC-sysmon-15-21 -->

### Known Breaches and Vulnerabilities

No qualifying direct production breach was identified in the reviewed official and first-party corpus as of 2026-09-01. This is a bounded search result, not a claim of universal nonoccurrence. [Coverage and exclusion record](../../research/techniques/SAF-T1006/source-coverage.yml)

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-64106 / GHSA-4575-fh42-7848 | Published 2025-11-03; Cursor 1.7.28 | User-accepted deceptive install can execute hidden commands; Cursor 2.0 is patched. | Direct vulnerability and controlled demonstration. | No production exploitation stated; absent from CISA KEV on the review date. <!-- SAF-TRACE: claims=SAF-T1006-C001; sources=SRC-ghsa-cursor-64106,SRC-nvd-mcp-catalog --> |
| CVE-2025-61929 / GHSA-hh6w-rmjc-26f6 | Published 2025-10-10; Cherry Studio before 1.6.4 | Clicking deceptive content can trigger the MCP URL command; 1.6.4 is patched. | Direct vulnerability at the weak-consent edge of scope. | Public proof of concept, not a production incident. <!-- SAF-TRACE: claims=SAF-T1006-C002; sources=SRC-ghsa-cherry-61929,SRC-nvd-mcp-catalog --> |
| CVE-2026-23523 / GHSA-pjj5-f3wm-f9m8 | Published 2026-01-16; Dive through 0.12.6 | Crafted deep link bypasses confirmation and reaches local execution; 0.13.0 is patched. | Direct vulnerability and controlled demonstration. | Product-specific confirmation flaw; no production exploitation stated. <!-- SAF-TRACE: claims=SAF-T1006-C003; sources=SRC-ghsa-dive-23523,SRC-nvd-mcp-catalog --> |

### Real-World Incidents or Demonstrations

Palo Alto Networks Unit 42 documented the non-MCP Contagious Interview campaign, in which fake recruiters persuaded technology job seekers to install disguised conferencing software that collected data and deployed a backdoor. It is a historical analogy for social-engineering impact, not evidence of an MCP incident. <!-- SAF-TRACE: claims=SAF-T1006-C011; sources=SRC-unit42-contagious-interview -->

Zed's project-open MCP configuration flaw is also adjacent: the project itself caused automatic command execution before worktree trust was added, so no deceived MCP install or trust decision was required. <!-- SAF-TRACE: claims=SAF-T1006-C009; sources=SRC-zed-secure-default,SRC-nvd-mcp-catalog -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Local code can read resources available to the process, subject to sandbox and privilege boundaries. <!-- SAF-TRACE: claims=SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494 --> |
| Integrity | High | Attacker-selected code can modify user-accessible state; restricted permissions reduce reach. <!-- SAF-TRACE: claims=SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494 --> |
| Availability | High | User-context code can disrupt accessible applications or data; isolation can constrain the blast radius. <!-- SAF-TRACE: claims=SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494 --> |
| Scope | Local to Adjacent | Initial execution is local; connected credentials and explicitly granted resources can extend reachable systems. <!-- SAF-TRACE: claims=SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494 --> |

### Severity Conditions

- **Severity increases when**: The client runs with broad file, network, credential, or administrative access and the server is unsandboxed. <!-- SAF-TRACE: claims=SAF-T1006-C008,SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-cwe-494 -->
- **Severity decreases when**: Commands and publishers are reviewed, packages are integrity-verified, and the process is sandboxed with least privilege. <!-- SAF-TRACE: claims=SAF-T1006-C005,SAF-T1006-C007,SAF-T1006-C008,SAF-T1006-C012; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-cwe-494 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP client or host | Server add or configuration write, installation deep-link acceptance, trust decision, server start | Timestamp, user, host, server ID, source URI, displayed identity, approval state, source trust | Normalize product-specific fields and retain denied as well as accepted decisions. <!-- SAF-TRACE: claims=SAF-T1006-C005,SAF-T1006-C007,SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 --> |
| Endpoint process telemetry | Child process started for the configured local server; optional file and network context | Timestamp, user, host, parent and child image, command line, signer or publisher state, hash, process correlation ID | Sysmon is one Windows example; other platforms need equivalent process telemetry. <!-- SAF-TRACE: claims=SAF-T1006-C013,SAF-T1006-C014; sources=SRC-sysmon-15-21 --> |

### Indicators of Compromise (IoCs)

- No durable technique-wide IoC exists: server names, commands, publishers, and sources vary, so behavior and provenance should be evaluated together. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->

### Behavioral Indicators

- A user-initiated MCP add, configuration change, or deep-link acceptance is followed by the same server's local process start from an unknown or untrusted source. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- The displayed integration identity or publisher does not match the executed image, command, signer, or package origin. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C007,SAF-T1006-C012; sources=SRC-ghsa-cursor-64106,SRC-vscode-mcp-servers,SRC-cwe-494 -->
- A new server launches outside an approved installation window or from a user-writable or unexpected path. <!-- SAF-TRACE: claims=SAF-T1006-C013,SAF-T1006-C014; sources=SRC-sysmon-15-21 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify user-mediated addition of an unknown or untrusted local MCP server followed by its process start. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- **Rule Status**: Experimental; it is a transparent SAF inference rather than a vendor-validated detector. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- **Detection Logic**: Correlate an install-side event initiated by a user with the same user, host, and server's process-start event when source trust is unknown or untrusted. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- **Correlation Window**: Fifteen minutes; exactly 900 seconds is included and 901 seconds is excluded in the deterministic boundary tests. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- **Known False Positives**: First use of verified internal development servers before provenance data is populated. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- **Known Limitations**: Missing client audit events, remote-only servers, delayed starts, trusted-but-malicious publishers, and incomplete endpoint telemetry are blind spots. <!-- SAF-TRACE: claims=SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- **Tuning Guidance**: Allowlist only verified server identity, publisher, command, and origin tuples; do not allowlist on display name alone. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C007,SAF-T1006-C012,SAF-T1006-C014; sources=SRC-ghsa-cursor-64106,SRC-vscode-mcp-servers,SRC-cwe-494,SRC-sysmon-15-21 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: Seven synthetic cases pass: positive, exact-window boundary, trusted negative, automated adjacent negative, outside-window negative, malformed negative, and expected legitimate lookalike. [Quality review](../../research/techniques/SAF-T1006/quality-review.yml)
- **Last Validated**: 2026-09-01. [Quality review](../../research/techniques/SAF-T1006/quality-review.yml)
- **Feasibility Waiver**: None. [Technique contract](../../research/techniques/SAF-T1006/technique-contract.yml)

## Mitigation Strategies

### Preventive Controls

1. **Make consent specific**: Display the complete command and arguments, identify local code execution, require explicit approval, and support cancellation before adding or starting a server. <!-- SAF-TRACE: claims=SAF-T1006-C005; sources=SRC-mcp-security-2025-11-25 -->
2. **Verify provenance**: Review server source, publisher, configuration, and package integrity; a familiar display name is not sufficient. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C007,SAF-T1006-C012; sources=SRC-ghsa-cursor-64106,SRC-vscode-mcp-servers,SRC-cwe-494 -->
3. **Constrain execution**: Run local servers with least privilege and explicit filesystem and network grants in a maintained sandbox where supported. <!-- SAF-TRACE: claims=SAF-T1006-C008,SAF-T1006-C012,SAF-T1006-C015; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-cwe-494 -->
4. **Patch install handlers**: Apply the fixed client releases for the selected deep-link vulnerabilities and preserve regression coverage for confirmation and command display. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523 -->

### Detective Controls

1. Record accepted and denied install or trust decisions, configuration changes, server identity and origin, and local server starts. <!-- SAF-TRACE: claims=SAF-T1006-C005,SAF-T1006-C007,SAF-T1006-C014; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
2. Correlate client-side install evidence with endpoint parent/child process, command-line, signer, hash, file, and optional network context. <!-- SAF-TRACE: claims=SAF-T1006-C012,SAF-T1006-C013,SAF-T1006-C014; sources=SRC-sysmon-15-21,SRC-cwe-494 -->

### Response Procedures

#### Immediate Actions

- Stop or disable the newly added server and preserve its configuration, trust decision, and process evidence before removal. <!-- SAF-TRACE: claims=SAF-T1006-C016; sources=SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- Contain the process and associated account or host when follow-on activity or sensitive-resource access is observed. <!-- SAF-TRACE: claims=SAF-T1006-C015,SAF-T1006-C016; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494,SRC-sysmon-15-21 -->

#### Investigation Steps

- Reconstruct the delivery, displayed identity, user action, stored configuration, child process tree, and outbound activity. <!-- SAF-TRACE: claims=SAF-T1006-C013,SAF-T1006-C016; sources=SRC-vscode-mcp-servers,SRC-sysmon-15-21 -->
- Determine which files, credentials, tools, and connected services were reachable; rotate credentials only when exposure is established or reasonably suspected. <!-- SAF-TRACE: claims=SAF-T1006-C015,SAF-T1006-C016; sources=SRC-mcp-security-2025-11-25,SRC-cwe-494,SRC-sysmon-15-21 -->

#### Remediation

- Remove the untrusted configuration and executable material, patch the client, and restore state altered after process start. <!-- SAF-TRACE: claims=SAF-T1006-C001,SAF-T1006-C002,SAF-T1006-C003,SAF-T1006-C016; sources=SRC-ghsa-cursor-64106,SRC-ghsa-cherry-61929,SRC-ghsa-dive-23523,SRC-vscode-mcp-servers -->
- Add a verified provenance allowlist and regression test for the exact install and confirmation path that failed. <!-- SAF-TRACE: claims=SAF-T1006-C005,SAF-T1006-C007,SAF-T1006-C012,SAF-T1006-C016; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-cwe-494 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1003: Malicious MCP-Server Distribution](../../research/techniques/SAF-T1006/technique-contract.yml) | Overlapping boundary | Covers distribution of an attacker-controlled server artifact; SAF-T1006 requires deception at the user's install or trust decision. |
| [SAF-T1002: Supply Chain Compromise](../../research/techniques/SAF-T1006/technique-contract.yml) | Adjacent | Changes a producer or distribution path the consumer already trusts; SAF-T1006 instead begins with deception at installation. |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Analogous | Both depend on social engineering that causes user-mediated execution, but SAF-T1006 is limited to an MCP installation or trust boundary and need not use a file. <!-- SAF-TRACE: claims=SAF-T1006-C010; sources=SRC-mitre-attack-t1204-002 --> |

## References

1. **SRC-mcp-security-2025-11-25**: [Security Best Practices — Model Context Protocol project contributors](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — local server compromise, consent, command display, sandboxing, and logging.
2. **SRC-mcp-connect-local**: [Connect to local MCP servers — Model Context Protocol project contributors](https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers) — configuration-driven package launch and user-permission boundary.
3. **SRC-vscode-mcp-servers**: [Add and manage MCP servers in VS Code — Microsoft Visual Studio Code Documentation Team](https://code.visualstudio.com/docs/agent-customization/mcp-servers) — trust, source review, direct-config warning, sandbox, and server controls.
4. **SRC-ghsa-cursor-64106**: [GHSA-4575-fh42-7848 — yardenporat353, hmwildermuth, and Cursor security team](https://github.com/cursor/cursor/security/advisories/GHSA-4575-fh42-7848) — CVE-2025-64106 attack path, affected version, impact, remediation, and credits.
5. **SRC-ghsa-cherry-61929**: [GHSA-hh6w-rmjc-26f6 — h3rrr, kangfenmao, and Cherry Studio security team](https://github.com/CherryHQ/cherry-studio/security/advisories/GHSA-hh6w-rmjc-26f6) — CVE-2025-61929 demonstration, versions, impact, and credits.
6. **SRC-ghsa-dive-23523**: [GHSA-pjj5-f3wm-f9m8 — TonyCrane, c kaznable, and Dive maintainers](https://github.com/OpenAgentPlatform/Dive/security/advisories/GHSA-pjj5-f3wm-f9m8) — CVE-2026-23523 confirmation bypass, process path, versions, and credits.
7. **SRC-nvd-mcp-catalog**: [NVD MCP server install records — NIST NVD Team and originating CNAs](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=MCP%20server%20install) — CVE identifiers, publication and modification dates, descriptions, and advisory links.
8. **SRC-zed-secure-default**: [Zed Moves Toward Secure-by-Default — John Swanson, Kirill Bulatov, Aaron Portnoy, and Mindgard](https://zed.dev/blog/secure-by-default) — adjacent automatic configuration execution and worktree-trust remediation.
9. **SRC-mitre-attack-t1204-002**: [User Execution: Malicious File — MITRE ATT&CK Team and TruKno](https://attack.mitre.org/techniques/T1204/002/) — analogous social-engineering execution behavior and mapping metadata.
10. **SRC-unit42-contagious-interview**: [Contagious Interview — Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/) — observed non-MCP historical analogy.
11. **SRC-cwe-494**: [CWE-494 — CWE Content Team, CLASP, and Eric Dalci](https://cwe.mitre.org/data/definitions/494.html) — origin and integrity weakness, consequences, controls, and detection methods.
12. **SRC-sysmon-15-21**: [Sysmon v15.21 — Mark Russinovich and Thomas Garnier](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — process, file, network, hash, and correlation telemetry.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Independent clean-room draft, evidence packet, detection analytic, and strict synthetic validation candidate. | OpenAI Codex clean-room agent `/root/cleanroom_saf_t1006_retry3` |
