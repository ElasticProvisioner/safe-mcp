# SAF-T1503: Env-Var Scraping

## Overview

- **Tactic**: Credential Access (ATK-TA0006)
- **Technique ID**: SAF-T1503
- **Research Packet**: [research/techniques/SAF-T1503](../../research/techniques/SAF-T1503/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1503/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: Secret-bearing variables can expose credentials and external services when those values are present in the launched server environment. <!-- SAF-TRACE: claims=SAF-T1503-C013,SAF-T1503-C014; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023,SRC-claude-code-mcp-2026-09-01 -->
- **First Observed**: No qualifying direct MCP or agentic production event was identified in the [source-coverage assessment](../../research/techniques/SAF-T1503/source-coverage.yml).
- **Last Updated**: 2026-09-01

## Scope

Env-Var Scraping covers a malicious or compromised local stdio MCP server enumerating the variable names and values visible inside its own launched process. It crosses the host-to-server process boundary; values absent from that process environment are outside the mechanism. <!-- SAF-TRACE: claims=SAF-T1503-C004; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25 -->

### In Scope

- Direct in-process access to the launched server's environment mapping. <!-- SAF-TRACE: claims=SAF-T1503-C002,SAF-T1503-C003,SAF-T1503-C004; sources=SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-python-os-3.14.7,SRC-mcp-transports-2025-11-25,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25 -->
- External environment-enumeration utilities invoked by that server process. <!-- SAF-TRACE: claims=SAF-T1503-C009,SAF-T1503-C017; sources=SRC-codecov-bash-uploader-2021,SRC-sysmon-15-21,SRC-rhel9-audit -->
- Collection of secret-bearing values present in the environment; credential use or exfiltration is follow-on behavior. <!-- SAF-TRACE: claims=SAF-T1503-C013,SAF-T1503-C014; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023,SRC-claude-code-mcp-2026-09-01 -->

### Out of Scope

- Reading `.env`, configuration, credential, shell-history, or key files; stealing stored platform records; and reading another process's memory or procfs environment use different mechanisms. [The contract records the boundary](../../research/techniques/SAF-T1503/technique-contract.yml).
- Initial compromise, malicious package delivery, prompt injection, credential use, persistence, and exfiltration are separate preceding or follow-on behaviors. [The contract records the boundary](../../research/techniques/SAF-T1503/technique-contract.yml).

### Distinguishing Characteristics

The defining observable is access to the live environment supplied to the running local server, not access to a file or a configuration datastore. [Scope contract](../../research/techniques/SAF-T1503/technique-contract.yml).

## Description

The stdio transport requires an MCP client to launch the server as a subprocess. Common Node.js and Python runtimes expose that subprocess's environment directly to application code, while current client documentation shows that environment entries can be supplied through MCP configuration. <!-- SAF-TRACE: claims=SAF-T1503-C001,SAF-T1503-C002,SAF-T1503-C003,SAF-T1503-C005; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-python-os-3.14.7,SRC-claude-code-mcp-2026-09-01 -->

The complete technique is a research-derived synthesis: server-controlled code enumerates the names and values it received at launch, collecting any secret-bearing values present. Current MCP guidance independently warns that local servers execute with client privileges and may have direct system access. <!-- SAF-TRACE: claims=SAF-T1503-C004,SAF-T1503-C007,SAF-T1503-C014; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25,SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 -->

This exposure is not universal. A launcher can construct a minimal environment, and one current client removes credential-named variables in specified helper scopes while explicitly leaving other scopes unaffected. <!-- SAF-TRACE: claims=SAF-T1503-C006,SAF-T1503-C020; sources=SRC-claude-code-mcp-2026-09-01,SRC-node-child-process-26.8.1 -->

## Attack Vectors

- **Primary Vector**: A malicious or compromised local stdio server reads its own runtime environment after the MCP client launches it. <!-- SAF-TRACE: claims=SAF-T1503-C001,SAF-T1503-C004; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25 -->
- **Secondary Vector**: An MCP-specific code-execution flaw may supply attacker-controlled execution within a client-launched context, but the reviewed CVE demonstrations did not enumerate environment variables. <!-- SAF-TRACE: claims=SAF-T1503-C011,SAF-T1503-C012; sources=SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596,SRC-ghsa-inspector-7f8r -->
- **Affected Components**: The MCP host or agent runtime, its local stdio server process, and the process-launch environment policy. <!-- SAF-TRACE: claims=SAF-T1503-C001,SAF-T1503-C005; sources=SRC-mcp-transports-2025-11-25,SRC-claude-code-mcp-2026-09-01 -->
- **Trust Boundary Crossed**: The host-to-local-server subprocess boundary. <!-- SAF-TRACE: claims=SAF-T1503-C004; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25 -->

## Technical Details

### Prerequisites

- The client launches attacker-controlled or compromised code as a local MCP server. <!-- SAF-TRACE: claims=SAF-T1503-C001,SAF-T1503-C004,SAF-T1503-C007; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25 -->
- The launched environment contains values useful to the actor. <!-- SAF-TRACE: claims=SAF-T1503-C004,SAF-T1503-C014; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25,SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 -->
- Environment allowlisting or name-based removal did not exclude those values. <!-- SAF-TRACE: claims=SAF-T1503-C006,SAF-T1503-C020; sources=SRC-claude-code-mcp-2026-09-01,SRC-node-child-process-26.8.1 -->

### Attack Flow

1. **Setup**: The actor gains control of code that the client will run as a local stdio server. <!-- SAF-TRACE: claims=SAF-T1503-C001,SAF-T1503-C007; sources=SRC-mcp-transports-2025-11-25,SRC-mcp-security-2025-11-25 -->
2. **Launch**: The client starts that server with an explicit or inherited process environment. <!-- SAF-TRACE: claims=SAF-T1503-C001,SAF-T1503-C002,SAF-T1503-C005; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01 -->
3. **Enumeration**: Server code uses its runtime mapping or an external utility to enumerate visible names and values. <!-- SAF-TRACE: claims=SAF-T1503-C002,SAF-T1503-C003,SAF-T1503-C004,SAF-T1503-C017; sources=SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-python-os-3.14.7,SRC-mcp-transports-2025-11-25,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25,SRC-codecov-bash-uploader-2021,SRC-sysmon-15-21,SRC-rhel9-audit -->
4. **Collection**: Any credential-like values present become available to the controlled server. <!-- SAF-TRACE: claims=SAF-T1503-C004,SAF-T1503-C014; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25,SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 -->
5. **Follow-On**: Credential use, persistence, or exfiltration may follow, but those actions are not part of this technique. <!-- SAF-TRACE: claims=SAF-T1503-C013; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 -->

### Safe Example Scenario

A synthetic local server is launched with `PATH=/usr/bin` and `EXAMPLE_TOKEN=[REDACTED]`. It reads only the variable names and reports that a credential-shaped name was visible; the example neither contains a live secret nor transmits a value. <!-- SAF-TRACE: claims=SAF-T1503-C004,SAF-T1503-C014; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25,SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Summary | Evidence Status | Source IDs | Limitation |
| --- | --- | --- | --- | --- |
| SAF-T1503-C001 | MCP stdio launches the server as a subprocess. | Research-Derived | SRC-mcp-transports-2025-11-25 | The standard does not define environment inheritance. |
| SAF-T1503-C002 | Node exposes `process.env` and defaults a spawned child's environment to it. | Research-Derived | SRC-node-process-26.8.1; SRC-node-child-process-26.8.1 | A launcher may pass a restricted environment. |
| SAF-T1503-C003 | Python exposes the process environment through `os.environ`. | Research-Derived | SRC-python-os-3.14.7 | It does not establish client-supplied values. |
| SAF-T1503-C004 | A controlled local server can enumerate values supplied at launch. | Research-Derived | SRC-mcp-transports-2025-11-25; SRC-node-process-26.8.1; SRC-node-child-process-26.8.1; SRC-claude-code-mcp-2026-09-01; SRC-mcp-security-2025-11-25 | No direct MCP incident or end-to-end demonstration was found. |
| SAF-T1503-C005 | A current client supports explicit environment entries and expansion. | Research-Derived | SRC-claude-code-mcp-2026-09-01 | It does not establish universal parent inheritance. |
| SAF-T1503-C006 | A current client filters credential-like variables in specified helper scopes. | Research-Derived | SRC-claude-code-mcp-2026-09-01 | The filtering is not universal. |
| SAF-T1503-C007 | MCP guidance treats local servers as privileged code and recommends isolation. | Research-Derived | SRC-mcp-security-2025-11-25 | It does not prescribe an environment allowlist. |
| SAF-T1503-C008 | VS Code documents local-server code risk and an optional sandbox. | Research-Derived | SRC-vscode-mcp-servers | The sandbox is platform-limited and does not claim environment filtering. |
| SAF-T1503-C009 | Codecov's compromised uploader enumerated CI environments. | Observed analogy | SRC-codecov-bash-uploader-2021 | It was not an MCP incident. |
| SAF-T1503-C010 | Shai-Hulud malware scanned `process.env` and published secret dumps. | Observed analogy | SRC-aikido-shai-hulud-2025 | It was not an MCP incident. |
| SAF-T1503-C011 | CVE-2025-6514 enabled commands through affected `mcp-remote`. | Demonstrated enabler | SRC-jfrog-cve-2025-6514 | No environment collection or production exploitation was established. |
| SAF-T1503-C012 | CVE-2025-49596 enabled commands through affected MCP Inspector. | Demonstrated enabler | SRC-oligo-inspector-cve-2025-49596; SRC-ghsa-inspector-7f8r | No environment collection or production exploitation was established. |
| SAF-T1503-C013 | The immediate effect is confidentiality loss; other effects require follow-on action. | Research-Derived | SRC-codecov-bash-uploader-2021; SRC-circleci-incident-2023 | Sensitivity depends on values present. |
| SAF-T1503-C014 | Environments may contain credentials, keys, tokens, and API keys. | Research-Derived | SRC-codecov-bash-uploader-2021; SRC-circleci-incident-2023; SRC-claude-code-mcp-2026-09-01 | Not every variable is sensitive. |
| SAF-T1503-C015 | Sysmon process events support process-lineage analysis. | Research-Derived | SRC-sysmon-15-21 | Network events are optional; runtime reads remain invisible. |
| SAF-T1503-C016 | RHEL Audit exposes executable, parent, process, and command-line data. | Research-Derived | SRC-rhel9-audit | Required rules must be configured. |
| SAF-T1503-C017 | An enumeration utility under known server ancestry is a testable low-specificity indicator. | Research-Derived | SRC-codecov-bash-uploader-2021; SRC-sysmon-15-21; SRC-rhel9-audit | Diagnostics can match. |
| SAF-T1503-C018 | Process creation does not reveal direct runtime API reads. | Research-Derived | SRC-node-process-26.8.1; SRC-python-os-3.14.7; SRC-sysmon-15-21 | Other instrumentation was not established. |
| SAF-T1503-C019 | Command-line audit data can itself contain sensitive values. | Research-Derived | SRC-windows-command-line-audit | The cited warning is Windows-specific. |
| SAF-T1503-C020 | A minimal explicit environment reduces values available to the server. | Research-Derived | SRC-node-child-process-26.8.1; SRC-claude-code-mcp-2026-09-01 | Name filters can miss or overmatch. |
| SAF-T1503-C021 | Sandboxing reduces follow-on reach but does not remove supplied values. | Research-Derived | SRC-mcp-security-2025-11-25; SRC-vscode-mcp-servers | It is not environment filtering. |
| SAF-T1503-C022 | Suspected exposed credentials should be invalidated or rotated and audited. | Research-Derived | SRC-codecov-bash-uploader-2021; SRC-circleci-incident-2023 | Rotation does not fix collection. |
| SAF-T1503-C023 | ATT&CK T1552.001 is analogous because a procedure uses `process.env` while its definition is file-centered. | Research-Derived | SRC-mitre-attack-t1552.001-v1.3; SRC-aikido-shai-hulud-2025 | The mapping is not direct. |

### Current State

- **Affected Environments**: Local stdio deployments in which the launched server receives sensitive values. <!-- SAF-TRACE: claims=SAF-T1503-C001,SAF-T1503-C004,SAF-T1503-C005,SAF-T1503-C014; sources=SRC-mcp-transports-2025-11-25,SRC-node-process-26.8.1,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25,SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 -->
- **Known Exploitation**: The reviewed record contains historical non-MCP analogies and controlled MCP code-execution enablers, but no direct end-to-end MCP event. [See the bounded assessment](../../research/techniques/SAF-T1503/source-coverage.yml).
- **Available Protections**: Explicit minimal environments, scoped credential-name filtering, server trust review, and sandbox restrictions. <!-- SAF-TRACE: claims=SAF-T1503-C006,SAF-T1503-C007,SAF-T1503-C008,SAF-T1503-C020,SAF-T1503-C021; sources=SRC-claude-code-mcp-2026-09-01,SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers,SRC-node-child-process-26.8.1 -->
- **Residual Risk**: A server can still read values supplied to it, and direct runtime reads evade the example process-creation detector. <!-- SAF-TRACE: claims=SAF-T1503-C018,SAF-T1503-C021; sources=SRC-node-process-26.8.1,SRC-python-os-3.14.7,SRC-sysmon-15-21,SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers -->

### Known Breaches and Vulnerabilities

| Event | Environment and Date | Impact and Remediation | Relationship | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Codecov Bash Uploader compromise | CI; 2021 | Environment variables were sent to attacker infrastructure; Codecov remediated and advised credential rotation. <!-- SAF-TRACE: claims=SAF-T1503-C009,SAF-T1503-C022; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 --> | Observed historical analogy | Not MCP or agentic. |
| Shai-Hulud npm supply-chain attack | Node.js ecosystems; 2025 | Malware scanned `process.env` and published secret dumps; affected-package cleanup and credential rotation were advised. <!-- SAF-TRACE: claims=SAF-T1503-C010; sources=SRC-aikido-shai-hulud-2025 --> | Observed historical analogy | Not MCP or agentic. |
| CVE-2025-6514 | `mcp-remote` 0.0.5–0.1.15; fixed in 0.1.16 | Attacker-controlled command execution was demonstrated; upgrade and trusted HTTPS servers reduce exposure. <!-- SAF-TRACE: claims=SAF-T1503-C011; sources=SRC-jfrog-cve-2025-6514 --> | Enabling vulnerability | No scraping or production exploitation established. |
| CVE-2025-49596 / GHSA-7f8r-222p-6f5g | MCP Inspector before 0.14.1; fixed in 0.14.1 | Unauthenticated command launch was demonstrated; the fix added authorization and origin checks. <!-- SAF-TRACE: claims=SAF-T1503-C012; sources=SRC-oligo-inspector-cve-2025-49596,SRC-ghsa-inspector-7f8r --> | Enabling vulnerability | No scraping or production exploitation established. |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Secret-bearing values present in the launched environment become readable by the controlled server. <!-- SAF-TRACE: claims=SAF-T1503-C013,SAF-T1503-C014; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023,SRC-claude-code-mcp-2026-09-01 --> |
| Integrity | None intrinsic | Integrity effects require separate credential use or another follow-on action. <!-- SAF-TRACE: claims=SAF-T1503-C013; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 --> |
| Availability | None intrinsic | Enumeration itself does not disrupt service; availability effects require another action. <!-- SAF-TRACE: claims=SAF-T1503-C013; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 --> |
| Scope | Local-to-adjacent | Collection is local to the server process, while reusable credentials can reach external services. <!-- SAF-TRACE: claims=SAF-T1503-C014; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023,SRC-claude-code-mcp-2026-09-01 --> |

## Detection Methods

### Required Telemetry

| Source | Events | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Windows process creation | Sysmon Event ID 1 or Event 4688 | Image, command line, process and parent identifiers, user, host, time | Command-line collection can contain private data and needs restricted access. <!-- SAF-TRACE: claims=SAF-T1503-C015,SAF-T1503-C019; sources=SRC-sysmon-15-21,SRC-windows-command-line-audit --> |
| Linux Audit | SYSCALL, EXECVE, and PROCTITLE records | Executable, arguments, PID, PPID, user, host, time | Configure suitable executable or syscall rules and normalize correlated records. <!-- SAF-TRACE: claims=SAF-T1503-C016; sources=SRC-rhel9-audit --> |
| Deployment inventory | Local MCP server process identities and ancestry | Approved host, server, executable, and lineage | This deployment-owned enrichment is required by the [tested analytic](detection-rule.yml). |

### Behavioral Indicators

- A child `env`, `printenv`, or `cmd.exe /c set` process under known local MCP server ancestry is a low-specificity indicator. <!-- SAF-TRACE: claims=SAF-T1503-C017; sources=SRC-codecov-bash-uploader-2021,SRC-sysmon-15-21,SRC-rhel9-audit -->
- Correlate the process with user, host, server identity, and surrounding activity before escalation. <!-- SAF-TRACE: claims=SAF-T1503-C015,SAF-T1503-C016,SAF-T1503-C017; sources=SRC-sysmon-15-21,SRC-rhel9-audit,SRC-codecov-bash-uploader-2021 -->
- Direct `process.env` or `os.environ` reads create no required child process and are outside this detector. <!-- SAF-TRACE: claims=SAF-T1503-C018; sources=SRC-node-process-26.8.1,SRC-python-os-3.14.7,SRC-sysmon-15-21 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect bounded command-based enumeration under a known local-server process lineage. <!-- SAF-TRACE: claims=SAF-T1503-C017; sources=SRC-codecov-bash-uploader-2021,SRC-sysmon-15-21,SRC-rhel9-audit -->
- **Known False Positives**: Trusted server diagnostics and administrator-approved troubleshooting can match. <!-- SAF-TRACE: claims=SAF-T1503-C017; sources=SRC-codecov-bash-uploader-2021,SRC-sysmon-15-21,SRC-rhel9-audit -->
- **Known Limitations**: Direct runtime access, renamed or embedded utilities, and incomplete ancestry enrichment evade or weaken the signal. <!-- SAF-TRACE: claims=SAF-T1503-C018; sources=SRC-node-process-26.8.1,SRC-python-os-3.14.7,SRC-sysmon-15-21 -->
- **Tuning Guidance**: Build the server-ancestry set from deployment inventory and allowlist only reviewed diagnostic behavior. <!-- SAF-TRACE: claims=SAF-T1503-C017; sources=SRC-codecov-bash-uploader-2021,SRC-sysmon-15-21,SRC-rhel9-audit -->

### Validation

- **Test Cases**: [Nine inert fixtures](../../tests/SAF-T1503/test-cases.json) cover positive, negative, boundary, malformed, normalization, and expected legitimate false-positive behavior.
- **Validation Script**: [test_detection.py](../../tests/SAF-T1503/test_detection.py)
- **Result**: [Nine of nine cases passed on 2026-09-01](../../tests/SAF-T1503/test-result.txt).
- **Feasibility Waiver**: None; the bounded analytic was tested with synthetic process records. [See the result](../../tests/SAF-T1503/test-result.txt).

## Mitigation Strategies

### Preventive Controls

1. Launch each local server with a minimal explicit allowlist; exclude credential-like names unless required for that server's reviewed function. <!-- SAF-TRACE: claims=SAF-T1503-C006,SAF-T1503-C020; sources=SRC-claude-code-mcp-2026-09-01,SRC-node-child-process-26.8.1 -->
2. Treat local servers as privileged code: approve trusted implementations, run with least privilege, and restrict filesystem, network, and other resources. <!-- SAF-TRACE: claims=SAF-T1503-C007,SAF-T1503-C008,SAF-T1503-C021; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers -->
3. Do not treat sandboxing as environment filtering; a sandboxed process can still read values supplied to it. <!-- SAF-TRACE: claims=SAF-T1503-C021; sources=SRC-mcp-security-2025-11-25,SRC-vscode-mcp-servers -->

### Detective Controls

1. Collect privacy-governed process telemetry and evaluate the experimental [lineage analytic](detection-rule.yml). <!-- SAF-TRACE: claims=SAF-T1503-C015,SAF-T1503-C016,SAF-T1503-C017,SAF-T1503-C019; sources=SRC-sysmon-15-21,SRC-rhel9-audit,SRC-codecov-bash-uploader-2021,SRC-windows-command-line-audit -->
2. Investigate matches in context and retain the documented in-process blind spot. <!-- SAF-TRACE: claims=SAF-T1503-C017,SAF-T1503-C018; sources=SRC-codecov-bash-uploader-2021,SRC-sysmon-15-21,SRC-rhel9-audit,SRC-node-process-26.8.1,SRC-python-os-3.14.7 -->

### Response Procedures

- Stop or isolate the untrusted local server and preserve relevant process telemetry without broadly exposing logged arguments. <!-- SAF-TRACE: claims=SAF-T1503-C007,SAF-T1503-C019,SAF-T1503-C021; sources=SRC-mcp-security-2025-11-25,SRC-windows-command-line-audit,SRC-vscode-mcp-servers -->
- Identify which credential-like values were present, invalidate or rotate affected credentials at their issuers, and audit subsequent use. <!-- SAF-TRACE: claims=SAF-T1503-C022; sources=SRC-codecov-bash-uploader-2021,SRC-circleci-incident-2023 -->
- Correct the launch environment and server trust decision before restoration. <!-- SAF-TRACE: claims=SAF-T1503-C007,SAF-T1503-C020; sources=SRC-mcp-security-2025-11-25,SRC-node-child-process-26.8.1,SRC-claude-code-mcp-2026-09-01 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1502: File-Based Credential Harvest](../SAF-T1502/README.md) | Alternative or overlapping | Reads stored credential or configuration files, whereas SAF-T1503 enumerates the live environment after process launch. [Scope contract](../../research/techniques/SAF-T1503/technique-contract.yml). |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | Analogous | A current procedure example names Shai-Hulud collection from `process.env`, but the formal definition is file-centered. <!-- SAF-TRACE: claims=SAF-T1503-C023; sources=SRC-mitre-attack-t1552.001-v1.3,SRC-aikido-shai-hulud-2025 --> |

## References

1. **SRC-mcp-transports-2025-11-25**: [Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) — Model Context Protocol maintainers and contributors, 2025-11-25.
2. **SRC-mcp-security-2025-11-25**: [Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — Model Context Protocol maintainers and contributors, 2025-11-25.
3. **SRC-node-process-26.8.1**: [Process](https://nodejs.org/api/process.html#processenv) — Node.js Documentation Team, v26.8.1.
4. **SRC-node-child-process-26.8.1**: [Child process](https://nodejs.org/api/child_process.html#child_processspawncommand-args-options) — Node.js Documentation Team, v26.8.1.
5. **SRC-python-os-3.14.7**: [os — Miscellaneous operating system interfaces](https://docs.python.org/3/library/os.html#os.environ) — Python Documentation Team, v3.14.7.
6. **SRC-claude-code-mcp-2026-09-01**: [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp) — Anthropic Claude Code Documentation Team, reviewed 2026-09-01.
7. **SRC-vscode-mcp-servers**: [Add and manage MCP servers in VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers) — Microsoft Visual Studio Code Documentation Team, 2026-08-26.
8. **SRC-codecov-bash-uploader-2021**: [Bash Uploader Security Update](https://about.codecov.io/security-update/) — Jerrod Engelberg and the Codecov Incident Response Team, 2021.
9. **SRC-circleci-incident-2023**: [CircleCI Jan 4, 2023 security incident report](https://circleci.com/blog/jan-4-2023-incident-report/) — Rob Zuber and the CircleCI Security Team, 2023-01-12.
10. **SRC-jfrog-cve-2025-6514**: [Critical RCE Vulnerability in mcp-remote](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) — Or Peles and JFrog Security Research, 2025-07-09.
11. **SRC-oligo-inspector-cve-2025-49596**: [Critical RCE Vulnerability in Anthropic MCP Inspector](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) — Avi Lumelsky and Oligo Security Research, 2025-06-27.
12. **SRC-ghsa-inspector-7f8r**: [Inspector proxy server vulnerabilities](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g) — petery-ant and Rémy Marot, 2025-06-13; exact URL supplied by SRC-oligo-inspector-cve-2025-49596 before direct review.
13. **SRC-aikido-shai-hulud-2025**: [S1ngularity/nx attackers strike again](https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again) — Charlie Eriksen, 2025-09-19 update.
14. **SRC-mitre-attack-t1552.001-v1.3**: [Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) — MITRE ATT&CK Team and listed contributors, v1.3.
15. **SRC-sysmon-15-21**: [Sysmon v15.21](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — Mark Russinovich and Thomas Garnier, 2026-06-17.
16. **SRC-windows-command-line-audit**: [Command line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing) — Justin Turner, reviewed 2026-09-01.
17. **SRC-rhel9-audit**: [RHEL 9 Security Hardening: Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening) — Red Hat Documentation Team, reviewed 2026-09-01.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Initial clean-room, research-derived draft with bounded tested detection | OpenAI Codex clean-room author |
