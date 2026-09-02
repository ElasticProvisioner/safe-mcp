# SAF-T1903: Malicious Server Control Channel

## Overview

- **Tactic**: Command and Control (ATK-TA0011)
- **Technique ID**: SAF-T1903
- **Research Packet**: [research/techniques/SAF-T1903](../../research/techniques/SAF-T1903/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1903/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Observed
- **Severity**: High
- **Severity Rationale**: A control channel can expose the permissions, credentials, and reachability of the launched server process, while sandboxing, least privilege, and egress controls constrain impact. <!-- SAF-TRACE: claims=SAF-T1903-C015; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->
- **First Observed**: 2025-10-19, when JFrog Security Research publicly documented malicious MCP packages that opened an attacker-facing reverse shell. <!-- SAF-TRACE: claims=SAF-T1903-C001; sources=SRC-jfrog-malicious-mcp -->
- **Last Updated**: 2026-09-02

## Scope

This technique covers a malicious or trojanized MCP server, or a server-adjacent integration presented as one, that uses its execution placement to establish or service a bidirectional operator channel for receiving commands and returning results. The channel can be a separate outbound connection or a custom MCP-compatible transport; the crossed boundary is the host's trust in the configured server executable and its network activity. <!-- SAF-TRACE: claims=SAF-T1903-C003,SAF-T1903-C004; sources=SRC-mcp-overview-2026,SRC-mcp-transports-2026,SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2 -->

### In Scope

- A launched server process opens an unapproved external channel and accepts remote operator instructions. <!-- SAF-TRACE: claims=SAF-T1903-C001; sources=SRC-jfrog-malicious-mcp -->
- A server-branded integration persistently reconnects to an attacker-controlled endpoint and exposes remote command functions. <!-- SAF-TRACE: claims=SAF-T1903-C002; sources=SRC-unit42-browser-c2 -->

### Out of Scope

- Delivery, installation, or configuration substitution that ends once the malicious server starts is a prerequisite behavior, not the ongoing channel. <!-- SAF-TRACE: claims=SAF-T1903-C004; sources=SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code -->
- Tool-description poisoning, server-originated model steering, one-way exfiltration, and exploitation of an otherwise benign server without an operator command loop use different mechanisms or objectives. <!-- SAF-TRACE: claims=SAF-T1903-C004; sources=SRC-mcp-overview-2026 -->

### Distinguishing Characteristics

The defining observable is a bidirectional command-and-result path attributable to a server process or server-branded integration. SAF-T1003 ends at malicious server delivery, while SAF-T1001 changes model decisions through server-originated content without requiring a remote operator loop. <!-- SAF-TRACE: claims=SAF-T1903-C004; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2 -->

## Description

MCP hosts can launch local servers as subprocesses, and implementations can use custom transports that preserve MCP message semantics over a bidirectional channel. Those facilities are legitimate; this technique begins when attacker-controlled server code uses that placement for remote interactive control. <!-- SAF-TRACE: claims=SAF-T1903-C003; sources=SRC-mcp-overview-2026,SRC-mcp-transports-2026 -->

The channel need not be the host's expected MCP transport. JFrog documented packages that opened a reverse shell before normal server operation, while Unit 42 documented a Chrome extension marketed as an MCP server that maintained a remote WebSocket command channel. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2 -->

The immediate objective is command exchange at the server process's privilege and connectivity. Follow-on collection, credential theft, persistence, or destructive action requires separate evidence and should not be inferred merely from channel establishment. <!-- SAF-TRACE: claims=SAF-T1903-C015; sources=SRC-mcp-overview-2026,SRC-google-mcp-security-2026 -->

## Attack Vectors

- **Primary Vector**: A user or host launches an attacker-controlled package or executable configured as an MCP server. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C007,SAF-T1903-C008; sources=SRC-jfrog-malicious-mcp,SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code -->
- **Secondary Vectors**: A browser integration presented as an MCP server connects to remote operator infrastructure; a project-local server configuration silently launches a command that creates a channel. <!-- SAF-TRACE: claims=SAF-T1903-C002,SAF-T1903-C007,SAF-T1903-C008; sources=SRC-unit42-browser-c2,SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code -->
- **Affected Components**: MCP host, server process, server configuration, endpoint process tree, and network transport. <!-- SAF-TRACE: claims=SAF-T1903-C003,SAF-T1903-C010,SAF-T1903-C011; sources=SRC-mcp-transports-2026,SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
- **Trust Boundary Crossed**: The host treats configured server startup as authorized integration activity, after which the process reaches an unapproved operator endpoint. <!-- SAF-TRACE: claims=SAF-T1903-C004,SAF-T1903-C007,SAF-T1903-C008; sources=SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code,SRC-jfrog-malicious-mcp -->

## Technical Details

### Prerequisites

- Attacker-controlled server code or a server-branded integration must execute in the target environment. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2 -->
- The process must have an egress path, or a reachable custom transport, to an operator-controlled endpoint. <!-- SAF-TRACE: claims=SAF-T1903-C003,SAF-T1903-C010; sources=SRC-mcp-transports-2026,SRC-elastic-unusual-domain -->
- Impact depends on the server process's permissions, accessible credentials, and isolation boundary. <!-- SAF-TRACE: claims=SAF-T1903-C012,SAF-T1903-C015; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->

### Attack Flow

1. **Setup**: The adversary prepares a malicious server package, extension, or project-local startup definition. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002,SAF-T1903-C007; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2,SRC-checkpoint-codex-cli -->
2. **Delivery**: The artifact reaches a host through installation, a browser store, or repository-controlled configuration. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002,SAF-T1903-C008; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2,SRC-checkpoint-claude-code -->
3. **Execution**: The host or user starts the server-designated process. <!-- SAF-TRACE: claims=SAF-T1903-C003,SAF-T1903-C007; sources=SRC-mcp-transports-2026,SRC-checkpoint-codex-cli -->
4. **Boundary Crossing**: The process creates an unapproved connection and binds it to command-handling behavior. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2 -->
5. **Objective**: The remote operator supplies commands and receives results through that channel. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2 -->
6. **Follow-On Activity**: Any subsequent credential access, collection, persistence, or impact must be classified from its own evidence. <!-- SAF-TRACE: claims=SAF-T1903-C015; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->

### Example Scenario

An organization approves a local data helper from an unverified package source. When the host launches it, the process contacts `control.example.invalid`, then starts an interactive child and exchanges command-result records. This inert scenario expresses the tested behavioral sequence without an executable payload. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1903-C001 | Malicious packages presented as MCP servers opened a reverse shell to attacker infrastructure. | Observed | SRC-jfrog-malicious-mcp: [JFrog report](https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/) | Downloads do not establish victim execution or a named breach. |
| SAF-T1903-C002 | A browser extension presented as an MCP server maintained a remote WebSocket command channel with reconnect behavior. | Observed | SRC-unit42-browser-c2: [Unit 42 report](https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/) | The report does not establish protocol conformance or known victim compromise. |
| SAF-T1903-C003 | MCP supports client-launched subprocess servers and custom bidirectional transports. | Research-Derived | SRC-mcp-overview-2026 and SRC-mcp-transports-2026: [current specification](https://modelcontextprotocol.io/specification/2026-07-28) | Legitimate protocol capability is not malicious by itself. |
| SAF-T1903-C004 | The technique boundary is the ongoing command loop, not delivery, model steering, or one-way transfer. | Research-Derived | SRC-jfrog-malicious-mcp and SRC-unit42-browser-c2: incident reports | This is a catalog inference from documented mechanisms. |
| SAF-T1903-C005 | The JFrog campaign involved three malicious packages and about 1,600 downloads. | Observed | SRC-jfrog-malicious-mcp: [JFrog report](https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/) | Download counts are exposure, not compromise counts. |
| SAF-T1903-C006 | The Unit 42 extension exposed more than 30 remote commands and persistent reconnect behavior. | Observed | SRC-unit42-browser-c2: [Unit 42 report](https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/) | The extension was MCP-branded; standards-conformant transport was not shown. |
| SAF-T1903-C007 | A Codex CLI project-local configuration flaw could start an arbitrary MCP command without a fresh prompt. | Demonstrated | SRC-checkpoint-codex-cli and SRC-cve-2025-61260: [research report](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/) | Public sources disagree at the patch-version boundary; no production exploitation was shown. |
| SAF-T1903-C008 | A Claude Code project configuration could bypass MCP startup consent and execute a configured command before the trust dialog. | Demonstrated | SRC-checkpoint-claude-code and SRC-cve-2025-59536: [research report](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) | The source presents a controlled demonstration, not production exploitation. |
| SAF-T1903-C009 | The selected reports do not establish a named victim breach attributable to this technique. | Research-Derived | SRC-jfrog-malicious-mcp and SRC-unit42-browser-c2: incident reports | Absence in these reports is not proof that no breach exists. |
| SAF-T1903-C010 | Unusual external destinations from GenAI processes are useful C2 or exfiltration signals but produce legitimate-service false positives. | Research-Derived | SRC-elastic-unusual-domain: [Elastic rule](https://www.elastic.co/guide/en/security/8.19/genai-process-connection-to-unusual-domain.html) | Domain novelty alone cannot establish a command channel. |
| SAF-T1903-C011 | Child processes of MCP or GenAI processes provide useful execution telemetry for correlation. | Research-Derived | SRC-elastic-mcp-child: [Elastic rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules_building_block/execution_mcp_server_child_process) | Parentage alone is high-volume and not proof of malicious control. |
| SAF-T1903-C012 | Least privilege, tool allowlisting, audit logging, isolation, and network restriction reduce malicious-server risk. | Research-Derived | SRC-google-mcp-security-2026 and SRC-mcp-overview-2026: [Google guidance](https://docs.cloud.google.com/mcp/ai-security-safety) | Control effectiveness depends on implementation and coverage. |
| SAF-T1903-C013 | ATT&CK T1071 is the closest analogy because it covers commands and results over application-layer protocols. | Research-Derived | SRC-mitre-t1071: [MITRE ATT&CK](https://attack.mitre.org/techniques/T1071/) | A separate reverse shell or WebSocket is not necessarily MCP protocol traffic. |
| SAF-T1903-C014 | Pre-execution and behavioral-deviation analysis has shown promise for malicious MCP server detection. | Demonstrated | SRC-arxiv-connor: [Huang et al.](https://arxiv.org/abs/2604.01905) | The evaluation used a curated research dataset and was not specific to control channels. |
| SAF-T1903-C015 | Impact is bounded by the launched process's privileges, accessible data, and network reach. | Research-Derived | SRC-google-mcp-security-2026 and SRC-mcp-overview-2026: security guidance | This is a conditional impact inference, not a measured loss estimate. |

### Current State

- **Affected Environments**: Local hosts that launch configured server processes and browser environments that install server-branded integrations are represented in public reports. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002,SAF-T1903-C007,SAF-T1903-C008; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2,SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code -->
- **Known Exploitation**: Malicious packages and an MCP-branded browser RAT were found in distribution channels; the selected reports do not establish named victim compromise. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002,SAF-T1903-C009; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2 -->
- **Available Protections**: Verify server provenance, allow only needed tools and destinations, isolate local servers, apply least privilege, and preserve audit logs. <!-- SAF-TRACE: claims=SAF-T1903-C012; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->
- **Residual Risk**: A server allowed to execute and reach arbitrary destinations can blend control traffic with legitimate integration activity. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C015; sources=SRC-elastic-unusual-domain,SRC-google-mcp-security-2026 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| JFrog malicious MCP packages | 2025-10-19 publication; three PyPI packages | Reverse shell behavior; remove packages and block reported infrastructure | Direct production incident | No named victim or execution count was reported. | <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C005; sources=SRC-jfrog-malicious-mcp -->
| Chrome MCP Server extension | 2026; Chrome extension | Persistent WebSocket C2 and remote browser actions; extension was reported and removed or warned on | Direct production incident | Protocol conformance and victim compromise were not established. | <!-- SAF-TRACE: claims=SAF-T1903-C002,SAF-T1903-C006; sources=SRC-unit42-browser-c2 -->
| CVE-2025-61260 | 2025 disclosure; Codex CLI project-local configuration | Arbitrary startup command; Check Point reports remediation in v0.23.0 | Enabling vulnerability | The CVE record's affected range conflicts with the researcher's patch boundary. | <!-- SAF-TRACE: claims=SAF-T1903-C007; sources=SRC-checkpoint-codex-cli,SRC-cve-2025-61260 -->
| CVE-2025-59536 | 2025 disclosure; Claude Code before 1.0.111 | MCP consent bypass and startup execution; fixed in 1.0.111 | Enabling vulnerability | Controlled demonstration only. | <!-- SAF-TRACE: claims=SAF-T1903-C008; sources=SRC-checkpoint-claude-code,SRC-cve-2025-59536 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A control channel can reach data and credentials readable by the server identity. | <!-- SAF-TRACE: claims=SAF-T1903-C012,SAF-T1903-C015; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->
| Integrity | High | Remote commands can alter resources within the process's authorization boundary. | <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002,SAF-T1903-C015; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2,SRC-google-mcp-security-2026 -->
| Availability | Medium | Disruption is possible but not established by the selected incidents. | <!-- SAF-TRACE: claims=SAF-T1903-C009,SAF-T1903-C015; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2,SRC-google-mcp-security-2026 -->
| Scope | Local | The immediate blast radius follows the launched process, with expansion dependent on its credentials and network reach. | <!-- SAF-TRACE: claims=SAF-T1903-C015; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->

### Severity Conditions

- **Severity increases when** the server runs with broad credentials, sensitive filesystem access, or unrestricted egress. <!-- SAF-TRACE: claims=SAF-T1903-C012,SAF-T1903-C015; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->
- **Severity decreases when** the server is sandboxed, uses a dedicated least-privilege identity, and can reach only approved destinations. <!-- SAF-TRACE: claims=SAF-T1903-C012; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or process inventory | Server process start | timestamp, host_id, process_id, server_id, role, approved_destinations | Normalize role and server identity before correlation. | <!-- SAF-TRACE: claims=SAF-T1903-C003,SAF-T1903-C011; sources=SRC-mcp-transports-2026,SRC-elastic-mcp-child -->
| Endpoint and network telemetry | Outbound connection and child process start | timestamp, host_id, process_id, destination, direction, interactive, child_category | Preserve DNS and process ancestry for at least the correlation window. | <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
| Channel audit telemetry | Inbound command and outbound result | timestamp, host_id, process_id, direction, semantic, channel_id | Content is unnecessary when direction and semantic labels are available. | <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C014; sources=SRC-elastic-unusual-domain,SRC-arxiv-connor -->

### Indicators of Compromise (IoCs)

- No durable universal IoC is assigned; package names and endpoints from a single report should be handled as incident-specific intelligence. <!-- SAF-TRACE: claims=SAF-T1903-C001,SAF-T1903-C002; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2 -->

### Behavioral Indicators

- A server-role process reaches an external destination outside its approved set and starts an interactive shell-like child. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
- A server-role process reaches an unapproved destination and receives a remote-command event followed by a command-result event on the same channel. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C014; sources=SRC-elastic-unusual-domain,SRC-arxiv-connor -->
- Destination novelty or process ancestry alone remains insufficient because legitimate services and server tools create both patterns. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml). <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->

- **Analytic Goal**: Detect correlated unapproved egress and command-capable behavior by a normalized server-role process. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
- **Rule Status**: Test. <!-- SAF-TRACE: claims=SAF-T1903-C010; sources=SRC-elastic-unusual-domain -->
- **Detection Logic**: Within 300 seconds of server start, require unapproved external egress plus either an interactive shell-like child or an inbound remote command and outbound result on one channel. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011,SAF-T1903-C014; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child,SRC-arxiv-connor -->
- **Correlation Window**: 300 seconds, inclusive. <!-- SAF-TRACE: claims=SAF-T1903-C010; sources=SRC-elastic-unusual-domain -->
- **Known False Positives**: Unregistered development servers, test harnesses, and newly approved backends can appear suspicious until inventory is current. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
- **Known Limitations**: Encrypted channels without destination or semantic metadata, in-process command execution, proxy-shared identities, and compromised approved endpoints can evade or confuse the analytic. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011,SAF-T1903-C014; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child,SRC-arxiv-connor -->
- **Tuning Guidance**: Maintain process-bound destination allowlists and suppress only reviewed, time-bounded development exceptions. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C012; sources=SRC-elastic-unusual-domain,SRC-google-mcp-security-2026 -->

### Validation

- **Test Data**: [cases.json](../../tests/SAF-T1903/cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1903/test_detection_rule.py)
- **Expected Result**: Eight cases pass, including positive, negative, exact-boundary, beyond-boundary, malformed, expected-false-positive, missing-field, and normalization cases. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
- **Last Validated**: [2026-09-02 destination detector and strict-validator run](../../research/techniques/SAF-T1903/validation/canonical-validation.txt)
- **Feasibility Waiver**: None; deterministic synthetic validation is included. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->

## Mitigation Strategies

### Preventive Controls

1. Verify server source and review the exact startup command before first use and after changes. <!-- SAF-TRACE: claims=SAF-T1903-C007,SAF-T1903-C008,SAF-T1903-C012; sources=SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code,SRC-google-mcp-security-2026 -->
2. Run local servers in an isolated environment with a dedicated least-privilege identity and narrowly scoped credentials. <!-- SAF-TRACE: claims=SAF-T1903-C012,SAF-T1903-C015; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->
3. Default-deny outbound network access and explicitly allow only required service destinations. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C012; sources=SRC-elastic-unusual-domain,SRC-google-mcp-security-2026 -->

### Detective Controls

1. Correlate server process ancestry with unusual external destinations and interactive child processes. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
2. Alert on destination-allowlist changes and preserve server lifecycle and channel-direction audit records. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C012; sources=SRC-elastic-unusual-domain,SRC-google-mcp-security-2026 -->

### Response Procedures

#### Immediate Actions

- Stop and isolate the identified server process, block its unapproved destinations, and preserve volatile connection and process evidence. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
- Revoke credentials accessible to the process when investigation shows exposure or command use. <!-- SAF-TRACE: claims=SAF-T1903-C012,SAF-T1903-C015; sources=SRC-google-mcp-security-2026,SRC-mcp-overview-2026 -->

#### Investigation Steps

- Reconstruct installation provenance, server configuration changes, process ancestry, destinations, and command-result timing. <!-- SAF-TRACE: claims=SAF-T1903-C007,SAF-T1903-C008,SAF-T1903-C010,SAF-T1903-C011; sources=SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code,SRC-elastic-unusual-domain,SRC-elastic-mcp-child -->
- Separate confirmed operator commands from inferred follow-on actions and document the evidence limit for each. <!-- SAF-TRACE: claims=SAF-T1903-C009,SAF-T1903-C015; sources=SRC-jfrog-malicious-mcp,SRC-unit42-browser-c2,SRC-google-mcp-security-2026 -->

#### Remediation

- Remove the malicious artifact, restore a reviewed server definition, update vulnerable hosts, and rotate exposed secrets. <!-- SAF-TRACE: claims=SAF-T1903-C007,SAF-T1903-C008,SAF-T1903-C012; sources=SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code,SRC-google-mcp-security-2026 -->
- Add the observed sequence to regression tests and enforce process-bound egress policy. <!-- SAF-TRACE: claims=SAF-T1903-C010,SAF-T1903-C011,SAF-T1903-C012; sources=SRC-elastic-unusual-domain,SRC-elastic-mcp-child,SRC-google-mcp-security-2026 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1003: Malicious MCP-Server Distribution](../SAF-T1003/README.md) | Prerequisite | Distribution ends when attacker-controlled server code starts; this technique requires an ongoing operator command loop. | <!-- SAF-TRACE: claims=SAF-T1903-C004; sources=SRC-checkpoint-codex-cli,SRC-checkpoint-claude-code -->
| [SAF-T1001: Tool Poisoning Attack](../SAF-T1001/README.md) | Alternative | Tool poisoning changes agent decisions through server-authored metadata or content; this technique exchanges commands with a remote operator. | <!-- SAF-TRACE: claims=SAF-T1903-C004; sources=SRC-mcp-overview-2026,SRC-jfrog-malicious-mcp -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Analogous | Both involve commands and results carried through application-layer communication, but the observed examples can use a separate shell or WebSocket rather than MCP messages. | <!-- SAF-TRACE: claims=SAF-T1903-C013; sources=SRC-mitre-t1071 -->

## References

1. **SRC-mcp-overview-2026**: [Model Context Protocol Specification, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) - protocol roles, tool trust, consent, and implementation-security boundaries.
2. **SRC-mcp-transports-2026**: [MCP Transports, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) - subprocess and custom-transport properties.
3. **SRC-jfrog-malicious-mcp**: [3 Malicious MCP Servers Found on PyPI](https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/) - Guy Korolevski and the JFrog Security Research Team, 2025.
4. **SRC-unit42-browser-c2**: [That AI Extension Helping You Write? It Might Be a RAT](https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/) - Unit 42 Threat Research team, 2026.
5. **SRC-checkpoint-codex-cli**: [OpenAI Codex CLI Vulnerability: Command Injection](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/) - Isabel Mill and Oded Vanunu, 2025.
6. **SRC-cve-2025-61260**: [CVE-2025-61260](https://www.cve.org/CVERecord?id=CVE-2025-61260) - MITRE CVE Program record, 2026.
7. **SRC-checkpoint-claude-code**: [Caught in the Hook](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) - Aviv Donenfeld and Oded Vanunu, 2026.
8. **SRC-cve-2025-59536**: [CVE-2025-59536](https://www.cve.org/CVERecord?id=CVE-2025-59536) - MITRE CVE Program record, 2025.
9. **SRC-elastic-unusual-domain**: [GenAI Process Connection to Unusual Domain](https://www.elastic.co/guide/en/security/8.19/genai-process-connection-to-unusual-domain.html) - Elastic, rule version 5.
10. **SRC-elastic-mcp-child**: [GenAI or MCP Server Child Process Execution](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules_building_block/execution_mcp_server_child_process) - Elastic, rule version 4.
11. **SRC-google-mcp-security-2026**: [AI security and safety](https://docs.cloud.google.com/mcp/ai-security-safety) - Google Cloud Documentation, updated 2026-08-28.
12. **SRC-mitre-t1071**: [Application Layer Protocol, T1071](https://attack.mitre.org/techniques/T1071/) - MITRE ATT&CK, version 2.4.
13. **SRC-arxiv-connor**: [From Component Manipulation to System Compromise](https://arxiv.org/abs/2604.01905) - Yiheng Huang et al., 2026.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Clean-room initial draft | OpenAI Security Research Team |
