# SAF-T1305: Host OS Priv-Esc (RCE)

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1305
- **Research Packet**: [research/techniques/SAF-T1305](../../research/techniques/SAF-T1305/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1305/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: Exploitation can convert lower-trust MCP access into code execution with the host-side process or service account's privileges, while the resulting authority remains bounded by that account and its isolation. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C003,SAF-T1305-C007; sources=SRC-jfrog-cve-2025-6514,SRC-zdi-cve-2026-0758 -->
- **First Observed**: Not observed in a qualifying production incident; controlled public demonstrations were published by Oligo Security Research and JFrog Security Research in June and July 2025. [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) <!-- SAF-TRACE: claims=SAF-T1305-C004,SAF-T1305-C005; sources=SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596 -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers exploitation of an MCP host-side client, proxy, inspector, or server flaw that changes an attacker's authority from MCP-level or low-privileged interaction to arbitrary host operating-system code execution in the vulnerable process account. [MCP architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C001,SAF-T1305-C003,SAF-T1305-C007; sources=SRC-mcp-architecture-2025-06-18,SRC-zdi-cve-2026-0758 -->

### In Scope

- Exploitation of input validation, authentication, or command-launch flaws in an MCP-connected component to run attacker-chosen code as its host process account. [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C003,SAF-T1305-C005,SAF-T1305-C006; sources=SRC-oligo-inspector-cve-2025-49596,SRC-zdi-aws-26-245 -->
- Local stdio subprocesses and independently running HTTP MCP components are both in scope when the exploit reaches the host OS security context. [MCP transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) <!-- SAF-TRACE: claims=SAF-T1305-C002,SAF-T1305-C003; sources=SRC-mcp-transports-2025-06-18 -->

### Out of Scope

- Commands transparently approved as an intended tool capability are ordinary tool use unless a vulnerability or failed boundary grants more authority than the caller was meant to have. [MCP specification](https://modelcontextprotocol.io/specification/2025-11-25) <!-- SAF-TRACE: claims=SAF-T1305-C017; sources=SRC-mcp-spec-2025-11-25 -->
- Silent installation of an attacker-supplied local MCP server is a neighboring configuration-execution behavior; it does not require exploitation of an established component. [MCP SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) <!-- SAF-TRACE: claims=SAF-T1305-C012,SAF-T1305-C017; sources=SRC-mcp-sep-1024 -->
- Prompt injection that induces an authorized tool call is a neighboring decision-integrity behavior unless that call reaches a software flaw that expands OS authority. [MCP specification](https://modelcontextprotocol.io/specification/2025-11-25) [git-mcp-server advisory](https://github.com/cyanheads/git-mcp-server/security/advisories/GHSA-3q26-f695-pp76) <!-- SAF-TRACE: claims=SAF-T1305-C017; sources=SRC-mcp-spec-2025-11-25,SRC-ghsa-cve-2025-53107 -->

### Distinguishing Characteristics

The decisive observable is an authority-changing process transition: attacker-controlled MCP input reaches a vulnerable host-side component and causes OS execution as that component's account. SAF-T1309 ends at unintended but authorized tool invocation; SAF-T1003 ends at launching an attacker-selected server configuration. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) [MCP SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) <!-- SAF-TRACE: claims=SAF-T1305-C003,SAF-T1305-C017; sources=SRC-zdi-cve-2026-0758,SRC-mcp-sep-1024 -->

## Description

MCP uses a host-client-server architecture: the host manages client instances and security decisions, while servers may be local processes or remote services. In stdio transport, the client launches the server as a subprocess. [MCP architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) [MCP transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) <!-- SAF-TRACE: claims=SAF-T1305-C001,SAF-T1305-C002; sources=SRC-mcp-architecture-2025-06-18,SRC-mcp-transports-2025-06-18 -->

Host OS Priv-Esc (RCE) occurs when a flaw in that local execution path or an independently running MCP component lets lower-trust input execute arbitrary code as the vulnerable process account. Public demonstrations have reached Windows host execution through a malicious remote MCP authorization endpoint and browser-to-Inspector requests; coordinated disclosures also document command injection into MCP server process and service-account contexts. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C003,SAF-T1305-C004,SAF-T1305-C005,SAF-T1305-C006; sources=SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596,SRC-zdi-aws-26-245 -->

The privilege gain is relative to the attacker's starting authority: code runs with the client, proxy, server, or service account's rights. The evidence does not establish that every instance reaches root or SYSTEM, and process isolation can constrain impact. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) <!-- SAF-TRACE: claims=SAF-T1305-C007,SAF-T1305-C009; sources=SRC-zdi-cve-2026-0758,SRC-mitre-attack-t1068 -->

## Attack Vectors

- **Primary Vector**: Attacker-controlled values reach a vulnerable command-launch, authorization, or proxy path in an MCP-connected component. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C004,SAF-T1305-C006; sources=SRC-jfrog-cve-2025-6514,SRC-zdi-aws-26-245 -->
- **Secondary Vectors**: A malicious web origin can reach an unauthenticated local Inspector proxy; a low-privileged local actor can inject a parameter consumed by a higher-privileged MCP service. [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C005,SAF-T1305-C007; sources=SRC-oligo-inspector-cve-2025-49596,SRC-zdi-cve-2026-0758 -->
- **Affected Components**: MCP hosts, client-side bridges, Inspector proxies, and MCP servers that launch operating-system processes. [MCP architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C001,SAF-T1305-C006; sources=SRC-mcp-architecture-2025-06-18,SRC-zdi-aws-26-245 -->
- **Trust Boundary Crossed**: The boundary from MCP request, metadata, browser origin, or low-privileged local input to the OS account running the vulnerable component. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C003,SAF-T1305-C004,SAF-T1305-C005,SAF-T1305-C007; sources=SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596,SRC-zdi-cve-2026-0758 -->

## Technical Details

### Prerequisites

- A vulnerable MCP-connected host component must be running and reachable through the path described by its advisory. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C006; sources=SRC-zdi-aws-26-245 -->
- The attacker must control the relevant metadata, request field, web-origin request, or low-privileged local input; prerequisites differ by vulnerability. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C004,SAF-T1305-C005,SAF-T1305-C007; sources=SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596,SRC-zdi-cve-2026-0758 -->

### Attack Flow

1. **Setup**: The actor identifies an affected MCP client, proxy, Inspector, or server and a reachable input path. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C006; sources=SRC-zdi-aws-26-245 -->
2. **Delivery**: The actor supplies a crafted MCP-adjacent value through server metadata, an HTTP request, a tool parameter, or a local service input. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C004,SAF-T1305-C005,SAF-T1305-C007; sources=SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596,SRC-zdi-cve-2026-0758 -->
3. **Trigger**: Vulnerable code passes attacker-controlled data into a process-launch or system-call path, or accepts an unauthenticated request that launches an MCP command. [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C005,SAF-T1305-C006; sources=SRC-oligo-inspector-cve-2025-49596,SRC-zdi-aws-26-245 -->
4. **Boundary Crossing**: The operating system creates a process in the vulnerable component's account rather than preserving the attacker's lower-trust authority. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C003,SAF-T1305-C007; sources=SRC-zdi-cve-2026-0758 -->
5. **Objective**: The actor obtains arbitrary code execution bounded by that account, its credentials, and any sandbox. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) <!-- SAF-TRACE: claims=SAF-T1305-C007,SAF-T1305-C009; sources=SRC-zdi-cve-2026-0758,SRC-mitre-attack-t1068 -->
6. **Follow-On Activity**: Any collection, persistence, lateral movement, or further elevation is separate follow-on behavior and is not established merely by proving this boundary crossing. [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) <!-- SAF-TRACE: claims=SAF-T1305-C009,SAF-T1305-C017; sources=SRC-mitre-attack-t1068 -->

### Example Scenario

An inert lab case sends the placeholder value `example.invalid/metadata` to a synthetic MCP bridge; the fixture emits a normalized process event showing an MCP runtime as parent and a shell as child, without executing a command. This models the observable boundary crossing without reproducing a payload. [detection test data](../../tests/SAF-T1305/test-logs.json)

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1305-C003 | Exploitation of MCP-connected components can turn lower-trust interaction into code execution as a host-side process account. | Demonstrated | SRC-jfrog-cve-2025-6514: [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/); SRC-oligo-inspector-cve-2025-49596: [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596); SRC-zdi-cve-2026-0758: [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) | Demonstrations and advisories do not establish a production incident or universal root/SYSTEM access. |
| SAF-T1305-C004 | CVE-2025-6514 demonstrated host execution through crafted authorization metadata in mcp-remote and was fixed in 0.1.16. | Demonstrated | SRC-jfrog-cve-2025-6514: [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) | Full arbitrary command parameters were demonstrated on Windows; other platforms had narrower execution. |
| SAF-T1305-C005 | CVE-2025-49596 demonstrated browser-originated arbitrary command execution through an unauthenticated MCP Inspector proxy; 0.14.1 added protections. | Demonstrated | SRC-oligo-inspector-cve-2025-49596: [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) | The publication is a controlled demonstration, not an incident report. |
| SAF-T1305-C006 | CVE-2026-5059 documents unauthenticated command injection into aws-mcp-server's process context and was disclosed as a zero-day after vendor rejection. | Research-Derived | SRC-zdi-aws-26-245: [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) | The advisory does not document in-the-wild exploitation or a vendor patch. |
| SAF-T1305-C007 | CVE-2026-0758 documents a low-privileged local actor escalating to arbitrary code execution in an MCP server service account. | Research-Derived | SRC-zdi-cve-2026-0758: [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) | The advisory does not identify a production incident or fixed version. |
| SAF-T1305-C008 | The reviewed authoritative corpus contains no qualifying production incident as of 2026-09-01. | Research-Derived | SRC-jfrog-cve-2025-6514, SRC-oligo-inspector-cve-2025-49596, SRC-zdi-aws-26-245: selected disclosures and demonstrations | This is a bounded dated search conclusion, not a claim that no incident has ever occurred. |

### Current State

- **Affected Environments**: Exposure is product- and version-specific; selected evidence covers MCP bridges, Inspectors, and servers on host systems. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C004,SAF-T1305-C005,SAF-T1305-C006; sources=SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596,SRC-zdi-aws-26-245 -->
- **Known Exploitation**: No qualifying production incident was identified in the reviewed corpus as of 2026-09-01; the selected records are controlled demonstrations or disclosed vulnerabilities. [source coverage](../../research/techniques/SAF-T1305/source-coverage.yml)
- **Available Protections**: Apply vendor fixes where available, restrict untrusted MCP connections, require authentication and origin validation for local HTTP servers, and show users exact local-server commands before execution. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [MCP transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) [MCP SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) <!-- SAF-TRACE: claims=SAF-T1305-C012,SAF-T1305-C013,SAF-T1305-C014; sources=SRC-jfrog-cve-2025-6514,SRC-mcp-transports-2025-06-18,SRC-mcp-sep-1024 -->
- **Residual Risk**: Consent does not cure a vulnerable implementation, and approved or expected tools can create shell children, so prevention and detection require patching, isolation, and environmental tuning. [MCP SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C011,SAF-T1305-C012,SAF-T1305-C015; sources=SRC-mcp-sep-1024,SRC-microsoft-sysmon -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-5059 / ZDI-26-245 | 2026-04-21; aws-mcp-server | Unauthenticated arbitrary code in the MCP server context; ZDI advised restricting interaction and recorded vendor rejection. | Direct vulnerability and public advisory. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) | No production exploitation or patch is documented. <!-- SAF-TRACE: claims=SAF-T1305-C006; sources=SRC-zdi-aws-26-245 --> |
| CVE-2025-6514 | 2025-07-09; mcp-remote 0.0.5 through 0.1.15 | Windows arbitrary command execution from crafted authorization metadata; fixed in 0.1.16. | Direct vulnerability and controlled demonstration. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) | Non-Windows demonstrations had limited parameter control; no incident is established. <!-- SAF-TRACE: claims=SAF-T1305-C004; sources=SRC-jfrog-cve-2025-6514 --> |
| CVE-2025-49596 | 2025-06-27 disclosure; MCP Inspector before 0.14.1 | Browser-originated arbitrary commands through the Inspector proxy; 0.14.1 added session-token and origin protections. | Direct vulnerability and controlled demonstration. [Oligo research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) | Internet-exposed instances were identified, but the source does not document exploitation against a victim. <!-- SAF-TRACE: claims=SAF-T1305-C005; sources=SRC-oligo-inspector-cve-2025-49596 --> |
| CVE-2026-0758 / ZDI-26-024 | 2026-01-09; mcp-server-siri-shortcuts | Low-privileged local input could execute code as the service account; ZDI advised restricting interaction. | Direct privilege-escalation vulnerability. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) | No affected-version range, patch, or production exploitation is documented. <!-- SAF-TRACE: claims=SAF-T1305-C007; sources=SRC-zdi-cve-2026-0758 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Arbitrary code may access data readable by the vulnerable process account; isolation and account permissions bound exposure. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C007,SAF-T1305-C009; sources=SRC-zdi-cve-2026-0758 --> |
| Integrity | High | Code execution can modify state writable by the process account. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C006,SAF-T1305-C009; sources=SRC-zdi-aws-26-245 --> |
| Availability | High | Arbitrary code can disrupt the vulnerable component and resources available to its account. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C006,SAF-T1305-C009; sources=SRC-zdi-aws-26-245 --> |
| Scope | Local to Adjacent | The immediate scope is the host account; reachable credentials and services may enable separate follow-on behavior. [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) <!-- SAF-TRACE: claims=SAF-T1305-C009; sources=SRC-mitre-attack-t1068 --> |

### Severity Conditions

- **Severity increases when** the vulnerable component runs as a service account with broader rights, holds sensitive credentials, or lacks sandboxing. [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) <!-- SAF-TRACE: claims=SAF-T1305-C007,SAF-T1305-C009,SAF-T1305-C015; sources=SRC-zdi-cve-2026-0758,SRC-mitre-attack-t1068 -->
- **Severity decreases when** the MCP component is patched, minimally privileged, isolated, and prevented from reaching sensitive host resources. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) <!-- SAF-TRACE: claims=SAF-T1305-C014,SAF-T1305-C015; sources=SRC-jfrog-cve-2025-6514,SRC-mitre-attack-t1068 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or gateway audit | Connection, tool call, approval, and component launch | Timestamp, session, server, transport, tool, approval state, component process identifier | Preserve a stable join to endpoint process telemetry. [MCP architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) <!-- SAF-TRACE: claims=SAF-T1305-C001,SAF-T1305-C011; sources=SRC-mcp-architecture-2025-06-18,SRC-microsoft-sysmon --> |
| Endpoint process creation | New process execution | Timestamp, process image, command line, parent image, parent/process identifier, user | Sysmon Event ID 1 provides full command line, parent process, hashes, and Process GUID for correlation on Windows. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C010; sources=SRC-microsoft-sysmon --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC is established; the technique is behavior-defined and product-specific. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C011; sources=SRC-microsoft-sysmon -->

### Behavioral Indicators

- A shell or interpreter appears as a child of an MCP runtime, proxy, Inspector, or server process near an MCP interaction. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C010,SAF-T1305-C011; sources=SRC-microsoft-sysmon -->
- Confidence increases when host audit data ties the child process to an unapproved or unexpected server, transport, or tool call. [MCP architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C001,SAF-T1305-C011; sources=SRC-mcp-architecture-2025-06-18,SRC-microsoft-sysmon -->
- Expected tool implementations that intentionally spawn interpreters are legitimate lookalikes and require allowlisting or a learned baseline. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C011; sources=SRC-microsoft-sysmon -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify shell or interpreter process creation by a known MCP component within 60 seconds of a correlated MCP interaction. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C010,SAF-T1305-C011; sources=SRC-microsoft-sysmon -->
- **Rule Status**: Experimental; it detects a suspicious boundary transition, not exploitation intent. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C011; sources=SRC-microsoft-sysmon -->
- **Detection Logic**: Require a known MCP parent role, a shell or interpreter child, a matching host/session join, and a time delta from zero through 60 seconds; exclude configured expected tool-child pairs. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C010,SAF-T1305-C011; sources=SRC-microsoft-sysmon -->
- **Correlation Window**: Inclusive 60-second boundary in the synthetic analytic. [test logs](../../tests/SAF-T1305/test-logs.json)
- **Known False Positives**: Legitimate MCP tools that intentionally run a shell or interpreter. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C011; sources=SRC-microsoft-sysmon -->
- **Known Limitations**: In-process execution, renamed binaries, missing parent lineage, or absent MCP-to-process joins can evade this analytic; process telemetry alone does not establish malicious intent. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C010,SAF-T1305-C011; sources=SRC-microsoft-sysmon -->
- **Tuning Guidance**: Inventory MCP runtime paths and expected tool-child pairs per environment before alerting. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C011; sources=SRC-microsoft-sysmon -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1305/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1305/test_detection_rule.py)
- **Expected Result**: [Two positive cases, four negative cases, and one inclusive 60-second boundary case pass](../../tests/SAF-T1305/test-logs.json)
- **Last Validated**: [2026-09-01](../../tests/SAF-T1305/test-logs.json)
- **Feasibility Waiver**: None; deterministic normalized-event tests are included. [quality review](../../research/techniques/SAF-T1305/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Run MCP components with the minimum OS privileges and isolate their filesystem, credential, process, and network reach. [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) <!-- SAF-TRACE: claims=SAF-T1305-C015; sources=SRC-mitre-attack-t1068 -->
2. **[SAF-M-14: Server Allowlisting](../../mitigations/SAF-M-14/README.md)**: Apply fixed releases and restrict connections to trusted servers and protected transports; where no fix is documented, restrict interaction with the affected product. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C014; sources=SRC-jfrog-cve-2025-6514,SRC-zdi-aws-26-245 -->
3. **[MCP transport controls](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)**: Validate Origin, bind local HTTP servers to localhost, and implement authentication. <!-- SAF-TRACE: claims=SAF-T1305-C013; sources=SRC-mcp-transports-2025-06-18 -->
4. **[MCP SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-)**: Show exact local-server commands and arguments, warn about risk, and require explicit approval before execution. <!-- SAF-TRACE: claims=SAF-T1305-C012; sources=SRC-mcp-sep-1024 -->

### Detective Controls

1. **[SAF-M-11: Behavioral Monitoring](../../mitigations/SAF-M-11/README.md)**: Correlate MCP interactions with endpoint process creation and alert on unexpected interpreter children. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C010,SAF-T1305-C011; sources=SRC-microsoft-sysmon -->
2. **Telemetry health**: Monitor loss or reconfiguration of process and MCP audit sources because missing lineage weakens the analytic. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C010,SAF-T1305-C011; sources=SRC-microsoft-sysmon -->

### Response Procedures

#### Immediate Actions

- Stop or isolate the affected MCP component and its host session, then preserve its process tree and MCP audit records. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C018; sources=SRC-microsoft-sysmon -->
- Revoke or rotate credentials accessible to the compromised process account when investigation shows exposure. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) <!-- SAF-TRACE: claims=SAF-T1305-C018; sources=SRC-jfrog-cve-2025-6514 -->

#### Investigation Steps

- Reconstruct the parent-child process chain and correlate it with server metadata, transport, tool, approval, and session records. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C010,SAF-T1305-C018; sources=SRC-microsoft-sysmon -->
- Determine the vulnerable product and version, the account context reached, and any subsequent access outside that context. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) <!-- SAF-TRACE: claims=SAF-T1305-C004,SAF-T1305-C007,SAF-T1305-C018; sources=SRC-jfrog-cve-2025-6514,SRC-zdi-cve-2026-0758 -->

#### Remediation

- Upgrade to a fixed release when one is documented, or remove/restrict the component when no fix is available. [JFrog research](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) [TrendAI ZDI](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) <!-- SAF-TRACE: claims=SAF-T1305-C014,SAF-T1305-C018; sources=SRC-jfrog-cve-2025-6514,SRC-zdi-aws-26-245 -->
- Restore affected state from trusted sources and add regression tests for the vulnerable input path and process-lineage alert. [Microsoft Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) <!-- SAF-TRACE: claims=SAF-T1305-C018; sources=SRC-microsoft-sysmon -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1309: Privileged Tool Invocation via Prompt Manipulation](../SAF-T1309/README.md) | Prerequisite or co-occurring | Ends at unintended use of an authorized capability; SAF-T1305 requires a flaw that expands authority into OS code execution. [MCP specification](https://modelcontextprotocol.io/specification/2025-11-25) <!-- SAF-TRACE: claims=SAF-T1305-C017; sources=SRC-mcp-spec-2025-11-25 --> |
| [SAF-T1003: Malicious MCP-Server Distribution](../SAF-T1003/README.md) | Alternative | Executes an attacker-selected configuration directly; SAF-T1305 exploits an established component. [MCP SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) <!-- SAF-TRACE: claims=SAF-T1305-C012,SAF-T1305-C017; sources=SRC-mcp-sep-1024 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Analogous | Both exploit software flaws to execute code with higher authority; SAF-T1305 narrows the vulnerable boundary to MCP-connected host components and may stop at a non-root process or service account. [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) <!-- SAF-TRACE: claims=SAF-T1305-C016; sources=SRC-mitre-attack-t1068 --> |

## References

1. **SRC-mcp-spec-2025-11-25**: [Model Context Protocol Specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) - MCP components, tool-safety principles, consent, and implementation guidance.
2. **SRC-mcp-architecture-2025-06-18**: [MCP Architecture, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/architecture) - Host, client, server roles and trust boundaries.
3. **SRC-mcp-transports-2025-06-18**: [MCP Transports, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) - stdio subprocess behavior and HTTP security requirements.
4. **SRC-mcp-sep-1024**: [MCP Client Security Requirements for Local Server Installation - Den Delimarsky](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) - Consent and command-transparency requirements.
5. **SRC-jfrog-cve-2025-6514**: [Critical RCE Vulnerability in mcp-remote - Or Peles and the JFrog Security Research Team](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) - Demonstration, platform limits, affected and fixed versions.
6. **SRC-oligo-inspector-cve-2025-49596**: [Critical RCE in MCP Inspector - Avi Lumelsky and Oligo Security Research](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596) - Browser-based demonstration, disclosure timeline, and fix.
7. **SRC-zdi-aws-26-245**: [ZDI-26-245 - Alfredo Oliveira and David Fiser of Trend Research](https://www.zerodayinitiative.com/advisories/ZDI-26-245/) - aws-mcp-server command injection and disclosure state.
8. **SRC-zdi-cve-2026-0758**: [ZDI-26-024 - Peter Girnus and Brandon Niemczyk of Trend Zero Day Initiative](https://www.zerodayinitiative.com/advisories/ZDI-26-024/) - MCP service-account privilege escalation.
9. **SRC-ghsa-cve-2025-53107**: [GHSA-3q26-f695-pp76 - dellalibera and cyanheads](https://github.com/cyanheads/git-mcp-server/security/advisories/GHSA-3q26-f695-pp76) - Prompt-influence and command-injection boundary evidence; opened only from the exact NVD-provenanced URL.
10. **SRC-mitre-attack-t1068**: [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/) - Privilege-escalation definition, mapping limits, and isolation/update controls.
11. **SRC-microsoft-sysmon**: [Sysmon Events - Microsoft](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) - Process-creation fields and correlation limits.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft with evidence packet and tested analytic | OpenAI Codex clean-room agent |
