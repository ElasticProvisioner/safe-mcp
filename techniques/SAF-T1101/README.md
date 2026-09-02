# SAF-T1101: Command Injection

- **Tactic**: Execution (ATK-TA0002)
- **Technique ID**: SAF-T1101
- **Severity**: Critical
- **Severity Rationale**: A successful boundary crossing can execute with the affected component's privileges and compromise confidentiality, integrity, and availability. <!-- SAF-TRACE: claims=SAF-T1101-C009; sources=SRC-cwe-78-v4.20 -->
- **Evidence Status**: Observed
- **Documentation Status**: Stable
- **First Observed**: Public evidence in the reviewed corpus dates to the 2025 MCP Inspector and mcp-remote disclosures; CISA added the selected known-exploited LiteLLM vulnerability in 2026. <!-- SAF-TRACE: claims=SAF-T1101-C004,SAF-T1101-C007,SAF-T1101-C008; sources=SRC-cisa-kev-2026-09-01,SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596 -->
- **Last Updated**: 2026-09-01
- **Research Packet**: [research/techniques/SAF-T1101/](../../research/techniques/SAF-T1101/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1101/traceability-ledger.yml)

## Overview

Command Injection is the abuse of an MCP or agentic component's command-generation boundary so that attacker-influenced data changes executable syntax or selects an unintended operating-system command or program. <!-- SAF-TRACE: claims=SAF-T1101-C001,SAF-T1101-C011; sources=SRC-cwe-78-v4.20,SRC-mcp-security-2026-07-28 -->

The immediate objective is execution with the affected component's privileges; later privilege escalation, collection, exfiltration, or impact is separate behavior. <!-- SAF-TRACE: claims=SAF-T1101-C009; sources=SRC-cwe-78-v4.20 -->

## Scope

The defining security boundary lies between untrusted MCP-derived data or configuration and a shell, interpreter, or direct process-launch API used by a host, client, server, proxy, or tool. <!-- SAF-TRACE: claims=SAF-T1101-C011; sources=SRC-cwe-78-v4.20,SRC-mcp-security-2026-07-28 -->

In scope are both command modification through executable syntax and full command or program selection; both require a reachable launch boundary and attacker influence over command-bearing data. <!-- SAF-TRACE: claims=SAF-T1101-C001,SAF-T1101-C011; sources=SRC-cwe-78-v4.20 -->

Prompt manipulation, browser access to localhost, malicious configuration persistence, and authorized command execution are out of scope unless the evidence also establishes this process-launch boundary crossing. <!-- SAF-TRACE: claims=SAF-T1101-C011; sources=SRC-cwe-78-v4.20,SRC-mcp-security-2026-07-28 -->

## Description

MCP tool calls carry a tool name and arguments, and tools are model-controlled. The protocol requires servers to validate inputs and advises clients to show tool inputs, obtain confirmation, and log use. <!-- SAF-TRACE: claims=SAF-T1101-C002; sources=SRC-mcp-tools-2026-07-28 -->

Those duties become security-critical when an implementation turns a URL, tool argument, server configuration, environment field, or proxy request into a local process. The reviewed cases show that failing to preserve the data-versus-code boundary can yield either shell-syntax injection or an unintended executable. <!-- SAF-TRACE: claims=SAF-T1101-C001,SAF-T1101-C010; sources=SRC-cwe-78-v4.20,SRC-jfrog-cve-2025-6514,SRC-ghsa-litellm-v4p8,SRC-ibm-2026-12940,SRC-oligo-inspector-cve-2025-49596 -->

## Attack Vectors

- **Authorization metadata**: a remote MCP server supplies a command-bearing authorization URL that an unsafe client passes to a shell. <!-- SAF-TRACE: claims=SAF-T1101-C003,SAF-T1101-C010; sources=SRC-mcp-security-2026-07-28,SRC-jfrog-cve-2025-6514 -->
- **Tool or proxy input**: a caller reaches an MCP endpoint that accepts a command, argument list, or complete executable selection. <!-- SAF-TRACE: claims=SAF-T1101-C005,SAF-T1101-C008,SAF-T1101-C010; sources=SRC-ghsa-litellm-v4p8,SRC-oligo-inspector-cve-2025-49596 -->
- **Server configuration**: an attacker influences local MCP startup command, argument, or environment data that crosses into a process launch. <!-- SAF-TRACE: claims=SAF-T1101-C006,SAF-T1101-C010; sources=SRC-ibm-2026-12940 -->

## Technical Details

1. The adversary influences a URL, tool field, proxy request, startup command, argument, or environment value. <!-- SAF-TRACE: claims=SAF-T1101-C010,SAF-T1101-C011; sources=SRC-jfrog-cve-2025-6514,SRC-ghsa-litellm-v4p8,SRC-ibm-2026-12940,SRC-oligo-inspector-cve-2025-49596 -->
2. An MCP-related component accepts the value at a reachable launch path without sufficiently constraining shell syntax, executable choice, or startup state. <!-- SAF-TRACE: claims=SAF-T1101-C001,SAF-T1101-C011; sources=SRC-cwe-78-v4.20,SRC-mcp-security-2026-07-28 -->
3. The operating system starts an altered command, command interpreter, or unintended program with the component's privileges. <!-- SAF-TRACE: claims=SAF-T1101-C009; sources=SRC-cwe-78-v4.20 -->

This model does not treat MCP or stdio as inherently unsafe: the weakness is the implementation boundary that converts attacker-influenced data into process behavior. <!-- SAF-TRACE: claims=SAF-T1101-C003,SAF-T1101-C011; sources=SRC-mcp-security-2026-07-28,SRC-cwe-78-v4.20 -->

## Evidence and Current State

### Evidence Summary

| Claim | Evidence status | Sources | Limitation |
|---|---|---|---|
| SAF-T1101-C001 | Research-derived | SRC-cwe-78-v4.20 | A weakness definition does not prove an MCP implementation is vulnerable. |
| SAF-T1101-C002 | Research-derived | SRC-mcp-tools-2026-07-28 | Protocol requirements do not prove universal compliance. |
| SAF-T1101-C003 | Research-derived | SRC-mcp-security-2026-07-28 | The guidance describes an unsafe implementation class. |
| SAF-T1101-C004 | Observed | SRC-cisa-kev-2026-09-01; SRC-ghsa-litellm-v4p8 | No victim, campaign, or exploit telemetry is public in the reviewed record. |
| SAF-T1101-C005 | Observed vulnerability | SRC-ghsa-litellm-v4p8; SRC-nvd-2026-42271 | The project advisory publishes no in-the-wild exploitation detail. |
| SAF-T1101-C006 | Observed vulnerability | SRC-ibm-2026-12940; SRC-nvd-2026-12940 | Production exploitation was not established. |
| SAF-T1101-C007 | Demonstrated | SRC-jfrog-cve-2025-6514; SRC-jfsa-2025-6514; SRC-nvd-2025-6514 | A demonstration is not a production incident. |
| SAF-T1101-C008 | Demonstrated | SRC-oligo-inspector-cve-2025-49596; SRC-ghsa-inspector-7f8r; SRC-nvd-2025-49596 | Missing authorization is the primary weakness; command selection is the matched variant. |
| SAF-T1101-C009 | Research-derived | SRC-cwe-78-v4.20 | Impact depends on process privileges and surrounding controls. |
| SAF-T1101-C010 | Observed | SRC-jfrog-cve-2025-6514; SRC-ghsa-litellm-v4p8; SRC-ibm-2026-12940; SRC-oligo-inspector-cve-2025-49596 | The vector list is representative. |
| SAF-T1101-C011 | Research-derived inference | SRC-cwe-78-v4.20; SRC-mcp-security-2026-07-28 | The boundary model is a synthesis. |
| SAF-T1101-C012 | Research-derived | SRC-sysmon-15-21 | Sysmon is Windows-specific and must be configured. |
| SAF-T1101-C013 | Research-derived | SRC-ecs-process-current | Schema support does not ensure field population. |
| SAF-T1101-C014 | Research-derived inference | SRC-sysmon-15-21; SRC-ecs-process-current; SRC-mitre-t1059-current | Validation uses synthetic fixtures only. |
| SAF-T1101-C015 | Research-derived | SRC-cwe-78-v4.20; SRC-mitre-t1059-current | No production error rate is claimed. |
| SAF-T1101-C016 | Research-derived | SRC-owasp-command-injection; SRC-python-subprocess-3.14; SRC-node-child-process-v26 | Escaping alone is platform-dependent. |
| SAF-T1101-C017 | Research-derived | SRC-mcp-tools-2026-07-28; SRC-mcp-security-2026-07-28 | Defense in depth does not repair unsafe construction. |
| SAF-T1101-C018 | Research-derived inference | SRC-mitre-t1059-current; SRC-cwe-78-v4.20 | ATT&CK T1059 is analogous, not identical. |

### Selected Current Examples

| Example | Relationship | Why selected | Remediation state |
|---|---|---|---|
| CVE-2026-42271 / LiteLLM | Direct vulnerability; CISA known exploited | Strongest exploitation evidence and direct low-privilege MCP stdio process launch; no named victim is inferred. | Fixed in 1.83.7 with administrator-only access; downstream vendor fixes also exist. | <!-- SAF-TRACE: claims=SAF-T1101-C004,SAF-T1101-C005; sources=SRC-cisa-kev-2026-09-01,SRC-ghsa-litellm-v4p8,SRC-nvd-2026-42271 -->
| CVE-2026-12940 / Langflow | Direct vulnerability | Current first-party, critical, unauthenticated environment-injection path into an MCP stdio launcher. | Fixed in 1.10.2; IBM lists no workaround. | <!-- SAF-TRACE: claims=SAF-T1101-C006; sources=SRC-ibm-2026-12940,SRC-nvd-2026-12940 -->
| CVE-2025-6514 / mcp-remote | Direct vulnerability and demonstration | End-to-end authorization-URL command-injection evidence with distinct shell and executable-launch behavior. | Fixed in 0.1.16. | <!-- SAF-TRACE: claims=SAF-T1101-C007; sources=SRC-jfrog-cve-2025-6514,SRC-jfsa-2025-6514,SRC-nvd-2025-6514 -->
| CVE-2025-49596 / MCP Inspector | Direct full-command-selection vulnerability and demonstration | Captures the local-proxy and arbitrary executable-selection variant while preserving the missing-authorization limitation. | Fixed in 0.14.1 with session-token and origin protections. | <!-- SAF-TRACE: claims=SAF-T1101-C008; sources=SRC-oligo-inspector-cve-2025-49596,SRC-ghsa-inspector-7f8r,SRC-nvd-2025-49596 -->

The evidence status is conservatively **Observed** because KEV establishes exploitation of one direct instance; it is not labeled as a named breach, and demonstrations remain separately classified. <!-- SAF-TRACE: claims=SAF-T1101-C004,SAF-T1101-C007,SAF-T1101-C008; sources=SRC-cisa-kev-2026-09-01,SRC-jfrog-cve-2025-6514,SRC-oligo-inspector-cve-2025-49596 -->

## Impact Assessment

Execution occurs with the affected component's privileges. Consequences can include unauthorized access to data, alteration of local state, service disruption, and a platform for later adversary actions. <!-- SAF-TRACE: claims=SAF-T1101-C009; sources=SRC-cwe-78-v4.20 -->

Severity depends on reachability, authentication, component privilege, sandbox boundaries, and whether the launch occurs on a developer workstation, server, or shared gateway. <!-- SAF-TRACE: claims=SAF-T1101-C009,SAF-T1101-C011; sources=SRC-cwe-78-v4.20,SRC-mcp-security-2026-07-28 -->

## Detection Methods

Use the repository's [correlation rule](detection-rule.yml) with [synthetic fixtures](test-logs.json), the [standalone harness](test_detection_rule.py), and the recorded [test results](test-results.json).

The analytic joins an untrusted MCP command-bearing event to a child process within ten seconds, requires matching correlation and parent identities, and alerts on either shell-control syntax or an unexpected executable change. <!-- SAF-TRACE: claims=SAF-T1101-C011,SAF-T1101-C014; sources=SRC-cwe-78-v4.20,SRC-sysmon-15-21,SRC-ecs-process-current -->

Collect MCP action, trust, source, approval, policy, component, and correlation fields together with process timestamp, entity, parent, executable, arguments, and command line. Sysmon Event ID 1 supplies key Windows values, while ECS defines portable normalized fields. <!-- SAF-TRACE: claims=SAF-T1101-C012,SAF-T1101-C013; sources=SRC-sysmon-15-21,SRC-ecs-process-current -->

Expect ambiguity from authorized automation and diagnostics, missing approval context, indirect launch chains, encoding, and telemetry gaps. The ten-case fixture result validates logic boundaries but not production precision or recall. <!-- SAF-TRACE: claims=SAF-T1101-C015; sources=SRC-cwe-78-v4.20,SRC-mitre-t1059-current -->

## Mitigation Strategies

- Avoid shell command construction; call a library or direct process API and keep executable and argument values separate. <!-- SAF-TRACE: claims=SAF-T1101-C016; sources=SRC-owasp-command-injection,SRC-python-subprocess-3.14,SRC-node-child-process-v26 -->
- Constrain executable names, arguments, URL schemes, and startup environment through narrow allowlists; do not treat quoting alone as the primary control. <!-- SAF-TRACE: claims=SAF-T1101-C003,SAF-T1101-C016; sources=SRC-mcp-security-2026-07-28,SRC-owasp-command-injection -->
- Run local servers, proxies, and tools with least privilege and sandboxing; authenticate local proxies and restrict administrative test endpoints. <!-- SAF-TRACE: claims=SAF-T1101-C016,SAF-T1101-C017; sources=SRC-owasp-command-injection,SRC-mcp-security-2026-07-28 -->
- Show users the exact tool inputs, require meaningful confirmation, and log command-bearing tool, authorization, configuration, and proxy events. <!-- SAF-TRACE: claims=SAF-T1101-C002,SAF-T1101-C017; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2026-07-28 -->

## Related Techniques

| Neighbor concept | Distinction |
|---|---|
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Changes model or tool intent; SAF-T1101 additionally requires an unsafe operating-system launch boundary. | <!-- SAF-TRACE: claims=SAF-T1101-C011; sources=SRC-cwe-78-v4.20,SRC-mcp-security-2026-07-28 -->
| [SAF-T1104: Over-Privileged Tool Abuse](../SAF-T1104/README.md) | Uses an authorized tool or command path beyond the intended privilege boundary; SAF-T1101 requires unintended syntax or executable selection. | <!-- SAF-TRACE: claims=SAF-T1101-C001,SAF-T1101-C011; sources=SRC-cwe-78-v4.20 -->
| Malicious server configuration | Is persistence or setup until a documented unsafe launch boundary produces execution. | <!-- SAF-TRACE: claims=SAF-T1101-C011; sources=SRC-cwe-78-v4.20,SRC-mcp-security-2026-07-28 -->

The canonical SAF-T1102 and SAF-T1104 neighboring-technique joins are recorded in the clean-room attestation after post-freeze framework reconciliation. <!-- SAF-TRACE: claims=SAF-T1101-C018; sources=SRC-mitre-t1059-current,SRC-cwe-78-v4.20 -->

## MITRE ATT&CK Mapping

| ATT&CK technique | Relationship | Rationale |
|---|---|---|
| T1059 — Command and Scripting Interpreter | Analogous and conditional | Applies when the boundary crossing launches a command or scripting interpreter; ATT&CK does not encode the injection weakness or MCP trust boundary. | <!-- SAF-TRACE: claims=SAF-T1101-C018; sources=SRC-mitre-t1059-current,SRC-cwe-78-v4.20 -->

## References

- **SRC-mcp-tools-2026-07-28** — [Model Context Protocol: Server tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- **SRC-mcp-security-2026-07-28** — [Model Context Protocol: Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- **SRC-cwe-78-v4.20** — [MITRE CWE-78](https://cwe.mitre.org/data/definitions/78.html)
- **SRC-python-subprocess-3.14** — [Python subprocess security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- **SRC-node-child-process-v26** — [Node.js child_process](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback)
- **SRC-owasp-command-injection** — [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- **SRC-cisa-kev-2026-09-01** — [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- **SRC-ghsa-litellm-v4p8** — [LiteLLM GHSA-v4p8-mg3p-g94g](https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g)
- **SRC-nvd-2026-42271** — [NVD CVE-2026-42271](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-42271)
- **SRC-ibm-2026-12940** — [IBM Langflow Security Bulletin](https://www.ibm.com/support/pages/node/7279995)
- **SRC-nvd-2026-12940** — [NVD CVE-2026-12940](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-12940)
- **SRC-jfrog-cve-2025-6514** — [JFrog analysis of CVE-2025-6514](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
- **SRC-jfsa-2025-6514** — [JFSA-2025-001290844](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/)
- **SRC-nvd-2025-6514** — [NVD CVE-2025-6514](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-6514)
- **SRC-oligo-inspector-cve-2025-49596** — [Oligo analysis of CVE-2025-49596](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)
- **SRC-ghsa-inspector-7f8r** — [MCP Inspector GHSA-7f8r-222p-6f5g](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g)
- **SRC-nvd-2025-49596** — [NVD CVE-2025-49596](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-49596)
- **SRC-sysmon-15-21** — [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **SRC-ecs-process-current** — [Elastic Common Schema process fields](https://www.elastic.co/guide/en/ecs/current/ecs-process.html)
- **SRC-mitre-t1059-current** — [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)

### Research and Disclosure Credits

- Or Peles and JFrog Security Research are credited for CVE-2025-6514 discovery and analysis. SRC-jfrog-cve-2025-6514; SRC-jfsa-2025-6514
- Avi Lumelsky and Oligo Security Research are credited for the MCP Inspector analysis; the project advisory credits Rémy Marot as reporter. SRC-oligo-inspector-cve-2025-49596; SRC-ghsa-inspector-7f8r
- The LiteLLM advisory publisher `jaydns`, BerriAI maintainers, IBM PSIRT, CISA, NIST NVD, Mark Russinovich, Thomas Garnier, OWASP, MITRE, Elastic, Python, Node.js, and MCP contributors are credited through their source records. SRC-ghsa-litellm-v4p8; SRC-ibm-2026-12940; SRC-cisa-kev-2026-09-01; SRC-sysmon-15-21

## Version History

| Date | Version | Changes |
|---|---|---|
| 2026-09-01 | 1.0 | Clean-room evidence freeze with observed classification, four selected examples, tested detection, and isolated strict-validation proof. |
