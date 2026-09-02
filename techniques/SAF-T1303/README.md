# SAF-T1303: Sandbox Escape via Server Exec

## Overview

- **Tactic**: Privilege Escalation (ATK-TA0004)
- **Technique ID**: SAF-T1303
- **Research Packet**: [research/techniques/SAF-T1303](../../research/techniques/SAF-T1303/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1303/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: Critical
- **Severity Rationale**: The technique can yield the MCP launcher, gateway, service-account, container-root, or host-root context; actual impact is bounded by that process's privileges and isolation. <!-- SAF-TRACE: claims=SAF-T1303-C014,SAF-T1303-C016; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->
- **First Observed**: No qualifying production incident was identified in the authoritative corpus reviewed through 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1303-C007; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-jfrog-malicious-mcp -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers attacker-controlled MCP configuration or tool input reaching a server-side process launcher and escaping the caller's intended sandbox or authorization boundary into a more-privileged service, container, or host context. <!-- SAF-TRACE: claims=SAF-T1303-C001; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->

### In Scope

- A server, manager, or gateway starts a process from attacker-controlled command material that crossed an MCP-facing boundary. <!-- SAF-TRACE: claims=SAF-T1303-C001; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->
- The new process runs with privileges or host reach beyond the caller's intended sandbox or assigned role. <!-- SAF-TRACE: claims=SAF-T1303-C014; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->

### Out of Scope

- Installing a malicious MCP package or configuration whose code runs at startup is delivery or supply-chain behavior, not a server-exec boundary failure. <!-- SAF-TRACE: claims=SAF-T1303-C007; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-jfrog-malicious-mcp -->
- Prompt injection that merely causes an approved, correctly constrained tool call is neighboring tool misuse; a process that remains in the expected sandbox is not this technique. <!-- SAF-TRACE: claims=SAF-T1303-C001,SAF-T1303-C013; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-mcp-tools-2025-11-25 -->
- Persistence, discovery, credential access, and lateral movement after the escape are follow-on behaviors. <!-- SAF-TRACE: claims=SAF-T1303-C001; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->

### Distinguishing Characteristics

The decisive observable is a correlated MCP-facing request or server configuration followed by process creation in a security context that differs from the expected sandbox. [SAF-T1203](../SAF-T1203/README.md) ends at startup-time execution; [SAF-T1104](../SAF-T1104/README.md) stays within an authorized tool boundary. <!-- SAF-TRACE: claims=SAF-T1303-C001,SAF-T1303-C008; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->

## Description

MCP `tools/call` requests carry a tool name and an arguments object to the server. The protocol boundary does not itself make an operating-system command safe; tool annotations are untrusted hints unless they come from a trusted server. <!-- SAF-TRACE: claims=SAF-T1303-C002,SAF-T1303-C013; sources=SRC-mcp-tools-2025-11-25 -->

The technique occurs when an MCP-connected component treats externally influenced command material as process-launch configuration or concatenates it into an operating-system invocation, and the resulting process runs beyond the caller's intended role or sandbox. Multiple disclosed vulnerabilities establish the components of that path, but the synthesis across products is an inference rather than a documented production intrusion. <!-- SAF-TRACE: claims=SAF-T1303-C001,SAF-T1303-C007; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-jfrog-malicious-mcp -->

## Attack Vectors

- **Primary Vector**: An authenticated or exposed MCP management or tool endpoint accepts attacker-controlled stdio command, executable, argument, or environment configuration. <!-- SAF-TRACE: claims=SAF-T1303-C003,SAF-T1303-C004,SAF-T1303-C006; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-cve-langchain-30617 -->
- **Secondary Vectors**: A malicious referenced image or configuration object supplies unvalidated process-launch metadata and requires user interaction. <!-- SAF-TRACE: claims=SAF-T1303-C005; sources=SRC-zdi-docker-26-363 -->
- **Affected Components**: MCP server tool handlers, stdio launchers, MCP managers and gateways, and their endpoint process-creation interfaces. <!-- SAF-TRACE: claims=SAF-T1303-C001; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->
- **Trust Boundary Crossed**: Caller or sandbox context to the MCP component's effective service, container-root, current-process, or host-root context. <!-- SAF-TRACE: claims=SAF-T1303-C014; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->

## Technical Details

### Prerequisites

- The target exposes a process-launching MCP tool, stdio preview path, management interface, or metadata consumer. <!-- SAF-TRACE: claims=SAF-T1303-C003,SAF-T1303-C004,SAF-T1303-C005,SAF-T1303-C006; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->
- Attacker-controlled data reaches executable, argument, environment, or system-call construction without an effective authorization or data-to-command boundary. <!-- SAF-TRACE: claims=SAF-T1303-C001,SAF-T1303-C010; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->
- The server-side process holds privileges or host reach beyond the caller's intended sandbox; otherwise the call is ordinary in-sandbox execution. <!-- SAF-TRACE: claims=SAF-T1303-C014; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->

### Attack Flow

1. **Setup**: The adversary identifies an MCP-facing route that creates or launches a local process. <!-- SAF-TRACE: claims=SAF-T1303-C001; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->
2. **Delivery**: Attacker-controlled command material reaches a tool argument, stdio configuration, management request, or image metadata field. <!-- SAF-TRACE: claims=SAF-T1303-C003,SAF-T1303-C004,SAF-T1303-C005,SAF-T1303-C006; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->
3. **Execution**: The MCP-connected component passes that material to a subprocess or system-call path. <!-- SAF-TRACE: claims=SAF-T1303-C001; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->
4. **Boundary Crossing**: The process starts in a context more privileged or less isolated than the caller's expected sandbox. <!-- SAF-TRACE: claims=SAF-T1303-C014; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->
5. **Objective**: The adversary obtains command execution with the server-side context. <!-- SAF-TRACE: claims=SAF-T1303-C016; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->
6. **Follow-On Activity**: Any later collection, persistence, or movement must be classified separately. <!-- SAF-TRACE: claims=SAF-T1303-C001; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->

### Example Scenario

A low-privilege user submits an inert stdio preview request whose placeholder executable is permitted only for testing; the vulnerable gateway starts it under the gateway service account rather than the user's sandbox, producing a correlated process-start event. <!-- SAF-TRACE: claims=SAF-T1303-C003,SAF-T1303-C008; sources=SRC-cve-litellm-42271,SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->

```json
{"method":"tools/call","params":{"name":"preview_stdio","arguments":{"command":"inert-example","args":["boundary-check"]}}}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1303-C001 | Server-side process launch from attacker-controlled MCP-facing input can cross the intended sandbox or authorization boundary. | Research-Derived | SRC-cve-litellm-42271, SRC-nvd-librechat-22252, SRC-zdi-docker-26-363, SRC-cve-langchain-30617 | Cross-product synthesis; no qualifying production intrusion was found. |
| SAF-T1303-C003 | LiteLLM versions 1.74.2 through 1.83.6 allowed low-privilege API-key holders to spawn supplied stdio commands with proxy-process privileges; 1.83.7 patched the issue. | Research-Derived | SRC-cve-litellm-42271: [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-42271) | The record documents a vulnerability, not production exploitation. |
| SAF-T1303-C004 | LibreChat before v0.8.2-rc2 allowed an authenticated user to execute shell commands as root inside its container; CISA-ADP records proof-of-concept status. | Demonstrated | SRC-nvd-librechat-22252: [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-22252) | Container-root impact is not automatically host-root impact. |
| SAF-T1303-C005 | Docker MCP Plugin could execute on the host as root when a target referenced a malicious image; Docker issued an update. | Research-Derived | SRC-zdi-docker-26-363: [ZDI advisory](https://www.zerodayinitiative.com/advisories/ZDI-26-363/) | User interaction is required; affected version details are not stated in the reviewed advisory. |
| SAF-T1303-C006 | LangChain-ChatChat 0.3.1 exposed an MCP management path that could configure attacker-controlled stdio commands for later service-context execution. | Research-Derived | SRC-cve-langchain-30617: [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-30617) | The reviewed record does not state a fixed version or production exploitation. |
| SAF-T1303-C008 | Correlating MCP request identity with parent process, command line, and effective context can detect a boundary mismatch. | Research-Derived | SRC-mcp-tools-2025-11-25, SRC-microsoft-sysmon, SRC-elastic-ecs-process | Requires instrumentation to carry one correlation identifier across layers. |

### Current State

- **Affected Environments**: Products that let MCP-facing users or content influence stdio launch configuration, system-call arguments, or executable selection. <!-- SAF-TRACE: claims=SAF-T1303-C001; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 -->
- **Known Exploitation**: A proof of concept is recorded for LibreChat; the reviewed sources did not establish a qualifying production intrusion for the complete technique. <!-- SAF-TRACE: claims=SAF-T1303-C004,SAF-T1303-C007; sources=SRC-nvd-librechat-22252,SRC-cve-litellm-42271,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-jfrog-malicious-mcp -->
- **Available Protections**: Patched releases exist for LiteLLM and LibreChat, Docker issued an update, and command construction should avoid direct OS calls or strictly separate and validate command data. <!-- SAF-TRACE: claims=SAF-T1303-C003,SAF-T1303-C004,SAF-T1303-C005,SAF-T1303-C010; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-owasp-command-injection -->
- **Residual Risk**: Patching one implementation does not protect other exec-capable MCP integrations; the maximum consequence remains bounded by launcher privilege and isolation. <!-- SAF-TRACE: claims=SAF-T1303-C014; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-22252 (LibreChat) | Published 2026-01-12; versions before v0.8.2-rc2 | Authenticated command execution as root inside the container; fixed in v0.8.2-rc2 | Direct vulnerability and proof-of-concept demonstration <!-- SAF-TRACE: claims=SAF-T1303-C004; sources=SRC-nvd-librechat-22252 --> | No production incident is documented; host escape is not established. |
| CVE-2026-55887 / ZDI-26-363 (Docker MCP Plugin) | Published 2026-06-24; malicious image reference required | Host-root execution; Docker issued an update | Direct vulnerability <!-- SAF-TRACE: claims=SAF-T1303-C005; sources=SRC-zdi-docker-26-363 --> | Reviewed advisory omits affected and fixed version numbers and requires user interaction. |
| CVE-2026-42271 (LiteLLM) | Published 2026-05-08; versions 1.74.2 through 1.83.6 | Low-privilege key holder could run commands with proxy privileges; fixed in 1.83.7 | Direct vulnerability <!-- SAF-TRACE: claims=SAF-T1303-C003; sources=SRC-cve-litellm-42271 --> | No production exploitation is documented. |
| CVE-2026-30617 (LangChain-ChatChat) | Published 2026-04-15; version 0.3.1 | Public management access could stage commands executed by later agent activity in the service context; remediation was not stated | Direct vulnerability <!-- SAF-TRACE: claims=SAF-T1303-C006; sources=SRC-cve-langchain-30617 --> | Source does not state a fixed version or observed exploitation. |

No qualifying direct production breach was identified in the reviewed authoritative corpus. Guy Korolevski and the JFrog Security Research team documented malicious MCP packages with reverse-shell behavior and downloads, but that code ran during server startup and is therefore an adjacent installation/supply-chain event, not evidence that this server-exec boundary was exploited. <!-- SAF-TRACE: claims=SAF-T1303-C007; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-jfrog-malicious-mcp -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Critical | A launcher running with proxy, service, container-root, or host-root context may expose data reachable by that context. <!-- SAF-TRACE: claims=SAF-T1303-C016; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 --> |
| Integrity | Critical | Arbitrary process execution can alter resources writable by the obtained context. <!-- SAF-TRACE: claims=SAF-T1303-C016; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 --> |
| Availability | High | Arbitrary commands can disrupt the affected service or resources it controls, but blast radius depends on privilege and isolation. <!-- SAF-TRACE: claims=SAF-T1303-C016; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617 --> |
| Scope | Multi-System | Host-root or broadly privileged service contexts can extend beyond one MCP session; container-root may remain container-bounded. <!-- SAF-TRACE: claims=SAF-T1303-C014,SAF-T1303-C016; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection --> |

### Severity Conditions

- **Severity increases when** the launcher is root, shares host files or credentials, exposes unauthenticated management, or lacks containment. <!-- SAF-TRACE: claims=SAF-T1303-C014,SAF-T1303-C016; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->
- **Severity decreases when** the launcher uses a dedicated least-privilege identity, rootless containment, minimal mounts, and narrow process allowlists. <!-- SAF-TRACE: claims=SAF-T1303-C010,SAF-T1303-C011; sources=SRC-owasp-command-injection,SRC-docker-rootless -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host, manager, gateway, or server audit log | Tool call, stdio preview, connection test, server start | Timestamp, request ID, actor, method, tool or endpoint, argument classification, approval, expected sandbox context | Carry a correlation identifier to endpoint telemetry. <!-- SAF-TRACE: claims=SAF-T1303-C002,SAF-T1303-C008; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process --> |
| Endpoint process-creation telemetry | Child process start from an MCP component | Timestamp, parent identity, executable, arguments or command line, effective context, correlation ID | Sysmon Event ID 1 supplies command line, parent process, hash, and Process GUID on Windows; equivalent ECS process fields can normalize other platforms. <!-- SAF-TRACE: claims=SAF-T1303-C008; sources=SRC-microsoft-sysmon,SRC-elastic-ecs-process,SRC-mcp-tools-2025-11-25 --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC exists; product and payload artifacts vary, so treat request-to-process boundary mismatch as behavior rather than a fixed indicator. <!-- SAF-TRACE: claims=SAF-T1303-C008,SAF-T1303-C009; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->

### Behavioral Indicators

- A process created by an MCP server or launcher within 60 seconds of a correlated call or configuration action, with an effective context different from the recorded expected sandbox. <!-- SAF-TRACE: claims=SAF-T1303-C008; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->
- Higher confidence follows when the action lacked approval or came from an actor not authorized for process-launch configuration. <!-- SAF-TRACE: claims=SAF-T1303-C008,SAF-T1303-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->
- A process-start event alone is insufficient because endpoint telemetry is observational and normal administration can produce similar children. <!-- SAF-TRACE: claims=SAF-T1303-C009; sources=SRC-microsoft-sysmon -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect correlated MCP-triggered process creation whose observed security context differs from the expected sandbox. <!-- SAF-TRACE: claims=SAF-T1303-C008; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1303-C009; sources=SRC-microsoft-sysmon -->
- **Detection Logic**: Join an MCP-facing action to a child process by request ID, require an MCP-server parent role, and alert on a context mismatch without explicit privileged approval. <!-- SAF-TRACE: claims=SAF-T1303-C008; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->
- **Correlation Window**: 60 seconds, including the exact boundary. <!-- SAF-TRACE: claims=SAF-T1303-C008; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->
- **Known False Positives**: Approved administrative maintenance or a stale expected-context inventory. <!-- SAF-TRACE: claims=SAF-T1303-C009; sources=SRC-microsoft-sysmon -->
- **Known Limitations**: Missing request correlation, suppressed command lines, in-process execution, and an incorrect sandbox baseline create blind spots. <!-- SAF-TRACE: claims=SAF-T1303-C008,SAF-T1303-C009; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->
- **Tuning Guidance**: Inventory server parent identities and allowed context transitions; keep approvals explicit rather than allowlisting all children of an MCP process. <!-- SAF-TRACE: claims=SAF-T1303-C008,SAF-T1303-C009; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1303/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1303/test_detection_rule.py)
- **Expected Result**: Eight deterministic cases cover two positives, normal in-sandbox execution, approved administration, a 60-second boundary, a 61-second negative, missing fields, and an unrelated process. [Test fixtures](../../tests/SAF-T1303/test-logs.json)
- **Last Validated**: 2026-09-01. [Quality review](../../research/techniques/SAF-T1303/quality-review.yml)
- **Feasibility Waiver**: None. [Technique contract](../../research/techniques/SAF-T1303/technique-contract.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-52: Input Validation Pipeline](../../mitigations/SAF-M-52/README.md)**: Avoid direct OS commands where practical; otherwise, separate commands from data and positively validate executables and arguments. <!-- SAF-TRACE: claims=SAF-T1303-C010; sources=SRC-owasp-command-injection -->
2. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Run launchers under dedicated low-privilege identities and constrain mounts, credentials, and host interfaces. <!-- SAF-TRACE: claims=SAF-T1303-C010,SAF-T1303-C011; sources=SRC-owasp-command-injection,SRC-docker-rootless -->
3. **Patch and restrict exposed launch paths**: Upgrade LiteLLM to 1.83.7 or later, LibreChat to v0.8.2-rc2 or later, apply Docker's update, and disable unnecessary stdio preview or management routes. <!-- SAF-TRACE: claims=SAF-T1303-C003,SAF-T1303-C004,SAF-T1303-C005,SAF-T1303-C017; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363 -->

### Detective Controls

1. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Alert on process-context transitions outside the runtime's declared sandbox profile. <!-- SAF-TRACE: claims=SAF-T1303-C008,SAF-T1303-C011; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process,SRC-docker-rootless -->
2. **Correlated process monitoring**: Preserve MCP actions and process lineage together; a single endpoint event is not sufficient attribution. <!-- SAF-TRACE: claims=SAF-T1303-C008,SAF-T1303-C009; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->

### Response Procedures

#### Immediate Actions

- Disable the affected process-launch path, isolate the launcher identity, and terminate only confirmed unauthorized child processes after preserving evidence. <!-- SAF-TRACE: claims=SAF-T1303-C015,SAF-T1303-C017; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363 -->
- Rotate credentials reachable by the obtained service, container, or host context when investigation shows access. <!-- SAF-TRACE: claims=SAF-T1303-C014,SAF-T1303-C017; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection -->

#### Investigation Steps

- Correlate the MCP request, actor, approval, configuration, and expected sandbox with endpoint process lineage, command line, effective context, files, and network events. <!-- SAF-TRACE: claims=SAF-T1303-C008,SAF-T1303-C015; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process -->
- Determine which privileges, mounts, credentials, and downstream systems were reachable from the launcher context before classifying follow-on behavior. <!-- SAF-TRACE: claims=SAF-T1303-C014,SAF-T1303-C015; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-owasp-command-injection,SRC-microsoft-sysmon -->

#### Remediation

- Patch the affected component, remove arbitrary executable selection, use structured process APIs, positively validate arguments, and reduce runtime privilege. <!-- SAF-TRACE: claims=SAF-T1303-C010,SAF-T1303-C011,SAF-T1303-C017; sources=SRC-owasp-command-injection,SRC-docker-rootless,SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363 -->
- Re-run boundary and false-positive tests, then monitor for recurrence before restoring the launch path. <!-- SAF-TRACE: claims=SAF-T1303-C008,SAF-T1303-C009,SAF-T1303-C017; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-sysmon,SRC-elastic-ecs-process,SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1203: Backdoored Server Binary](../SAF-T1203/README.md) | Prerequisite or alternative | Runs malicious code during installation or startup; it does not require an unsafe request-to-exec boundary. <!-- SAF-TRACE: claims=SAF-T1303-C007; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-jfrog-malicious-mcp --> |
| [SAF-T1104: Over-Privileged Tool Abuse](../SAF-T1104/README.md) | Co-occurring | Persuades an agent to misuse an authorized tool; SAF-T1303 requires process creation outside the intended sandbox or role. <!-- SAF-TRACE: claims=SAF-T1303-C001,SAF-T1303-C013; sources=SRC-cve-litellm-42271,SRC-nvd-librechat-22252,SRC-zdi-docker-26-363,SRC-cve-langchain-30617,SRC-mcp-tools-2025-11-25 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Analogous | Both cover adversary command execution, but ATT&CK T1059 does not define the MCP request-to-server privilege boundary. <!-- SAF-TRACE: claims=SAF-T1303-C012; sources=SRC-mitre-t1059-current --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — Model Context Protocol contributors; `tools/call`, tool metadata, and trust guidance.
2. **SRC-cve-litellm-42271**: [CVE-2026-42271](https://www.cve.org/CVERecord?id=CVE-2026-42271) — CVE Program record published by the GitHub maintainer-advisory CNA team; LiteLLM affected range, privilege boundary, and fix.
3. **SRC-nvd-librechat-22252**: [NVD CVE-2026-22252](https://nvd.nist.gov/vuln/detail/CVE-2026-22252) — NIST NVD with GitHub CNA and CISA-ADP enrichment; LibreChat affected range, fix, and proof-of-concept status.
4. **SRC-zdi-docker-26-363**: [ZDI-26-363](https://www.zerodayinitiative.com/advisories/ZDI-26-363/) — Jabr Al-Otaibi of DarkCov and TrendAI Zero Day Initiative; Docker MCP Plugin host-root execution and update status.
5. **SRC-cve-langchain-30617**: [CVE-2026-30617](https://www.cve.org/CVERecord?id=CVE-2026-30617) — MITRE Corporation CNA; LangChain-ChatChat MCP stdio execution path.
6. **SRC-jfrog-malicious-mcp**: [3 Malicious MCP servers found on PyPI](https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/) — Guy Korolevski and JFrog Security Research; adjacent malicious-package campaign.
7. **SRC-microsoft-sysmon**: [Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) — Microsoft Learn contributors; process creation and correlation fields.
8. **SRC-elastic-ecs-process**: [Elastic Common Schema process fields](https://www.elastic.co/docs/reference/ecs/ecs-process) — Elastic documentation team; normalized process arguments, command line, executable, and entity ID.
9. **SRC-owasp-command-injection**: [OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) — OWASP Cheat Sheet Series contributors; command separation, validation, and least privilege.
10. **SRC-docker-rootless**: [Docker Rootless mode](https://docs.docker.com/engine/security/rootless/) — Docker documentation team; non-root daemon and container isolation.
11. **SRC-mitre-t1059-current**: [ATT&CK T1059](https://attack.mitre.org/techniques/T1059/) — MITRE ATT&CK team; command and scripting interpreter behavior.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft with current vulnerability research, tested detection, exclusions, and publication-rights review | OpenAI Codex clean-room authoring agent |
