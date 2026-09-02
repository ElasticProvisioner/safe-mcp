# SAF-T1502: File-Based Credential Harvest

## Overview

- **Tactic**: Credential Access (ATK-TA0006)
- **Technique ID**: SAF-T1502
- **Research Packet**: [research/techniques/SAF-T1502](../../research/techniques/SAF-T1502/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1502/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Observed
- **Severity**: High
- **Severity Rationale**: A successful read can expose reusable authentication material to an adversary-directed agent workflow; impact depends on the file's contents, the agent process's filesystem reach, and the credential's privileges. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C008,SAF-T1502-C009; sources=SRC-anthropic-espionage-2025-11,SRC-aws-shared-credential-files,SRC-google-adc-files -->
- **First Observed**: September 2025 in Anthropic's GTG-1002 campaign report. <!-- SAF-TRACE: claims=SAF-T1502-C004; sources=SRC-anthropic-espionage-2025-11 -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers an MCP or agentic component using filesystem visibility to locate and read a credential-bearing ordinary file, placing its contents into a tool result, model context, or adversary-directed workflow. <!-- SAF-TRACE: claims=SAF-T1502-C003; sources=SRC-mcp-resources-2025-11-25,SRC-anthropic-espionage-2025-11,SRC-aws-shared-credential-files,SRC-google-adc-files -->

### In Scope

- Filesystem tools, file-like MCP resources, or agent-controlled local processes that read credentials, tokens, keys, certificates, or authentication configuration from ordinary files. <!-- SAF-TRACE: claims=SAF-T1502-C002,SAF-T1502-C003; sources=SRC-mcp-resources-2025-11-25,SRC-anthropic-espionage-2025-11 -->
- Reads inside an intended mount or allowlist and path-validation bypasses that expose unintended files. <!-- SAF-TRACE: claims=SAF-T1502-C005,SAF-T1502-C006; sources=SRC-cve-2025-53109,SRC-ghsa-cve-2025-53109,SRC-cve-2025-53110,SRC-ghsa-cve-2025-53110 -->
- The immediate outcome in which credential material becomes available to the model or adversary-directed workflow. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C004; sources=SRC-mcp-resources-2025-11-25,SRC-anthropic-espionage-2025-11 -->

### Out of Scope

- Credential extraction from keychains, password managers, browser vaults, operating-system structures, registry secrets, process memory, or secret-manager APIs. <!-- SAF-TRACE: claims=SAF-T1502-C014; sources=SRC-mitre-t1555,SRC-mitre-t1003 -->
- Capturing credentials from keyboard, GUI, API-hook, or deceptive login input. <!-- SAF-TRACE: claims=SAF-T1502-C014; sources=SRC-mitre-t1056 -->
- Initial compromise, malicious tool installation, arbitrary command execution, credential reuse, lateral movement, and exfiltration; these may precede or follow the file read but are not its defining mechanism. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C004,SAF-T1502-C014; sources=SRC-anthropic-espionage-2025-11,SRC-attack-t1005,SRC-mitre-attack-t1552.001-v1.3 -->
- Collection of non-credential local data where obtaining authentication material is not the immediate objective. <!-- SAF-TRACE: claims=SAF-T1502-C014; sources=SRC-attack-t1005,SRC-mitre-attack-t1552.001-v1.3 -->

### Distinguishing Characteristics

The distinguishing observable is a filesystem read whose target is credibly classified as credential material and whose result enters an MCP or agent workflow. Protected-store extraction uses a different access mechanism; generic local collection has a different objective; data transfer begins after acquisition. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C013,SAF-T1502-C014; sources=SRC-mcp-resources-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit,SRC-attack-t1005,SRC-mitre-t1555 -->

## Description

MCP tools can be discovered and invoked by language models, and MCP resources can expose file-like data to applications or models. A deployment therefore creates a credential boundary when its agent or server process can read files that the user did not intend to place into model context or an adversary-directed result. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C002,SAF-T1502-C003; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-anthropic-espionage-2025-11 -->

The defining behavior is acquisition, not merely enumeration: the workflow locates or is directed to a credential-bearing file, performs a successful read, and makes the contents available for adversary use. AWS and Google Cloud both document local credential files, but their presence alone does not establish compromise. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C008,SAF-T1502-C009; sources=SRC-anthropic-espionage-2025-11,SRC-aws-shared-credential-files,SRC-google-adc-files -->

The behavior is observed, not inferred solely from protocol capability. Anthropic's Threat Intelligence team reported a production campaign in which an MCP-orchestrated Claude Code framework extracted authentication certificates from configurations and tested harvested credentials; the report also warns that some model-claimed credentials were invalid or public information. <!-- SAF-TRACE: claims=SAF-T1502-C004,SAF-T1502-C015; sources=SRC-anthropic-espionage-2025-11 -->

## Attack Vectors

- **Primary Vector**: An adversary-directed prompt or workflow invokes an already available filesystem tool, local process, or file-like resource against a credential-bearing path. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C002,SAF-T1502-C003; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-anthropic-espionage-2025-11 -->
- **Secondary Vectors**: A compromised local MCP server operates with the client's filesystem privileges, or a Filesystem server path-validation flaw exposes a file outside the intended directory. <!-- SAF-TRACE: claims=SAF-T1502-C005,SAF-T1502-C006,SAF-T1502-C010; sources=SRC-cve-2025-53109,SRC-cve-2025-53110,SRC-mcp-security-2025-11-25 -->
- **Affected Components**: MCP host/client, filesystem or resource server, agent process, mounted directories, local credential files, tool results, and model context. <!-- SAF-TRACE: claims=SAF-T1502-C002,SAF-T1502-C003; sources=SRC-mcp-resources-2025-11-25,SRC-anthropic-espionage-2025-11 -->
- **Trust Boundary Crossed**: Process-readable storage enters a model-visible or adversary-directed execution context without matching the user's intended authorization for credential disclosure. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C010; sources=SRC-anthropic-espionage-2025-11,SRC-mcp-security-2025-11-25 -->

## Technical Details

### Prerequisites

- The MCP server or agent process can read the target file directly, through a mounted directory, or through a path-validation bypass. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C005,SAF-T1502-C006; sources=SRC-anthropic-espionage-2025-11,SRC-cve-2025-53109,SRC-cve-2025-53110 -->
- A credential-bearing file exists; documented examples include local AWS shared credential files and Google Cloud ADC JSON files. <!-- SAF-TRACE: claims=SAF-T1502-C008,SAF-T1502-C009; sources=SRC-aws-shared-credential-files,SRC-google-adc-files -->
- The adversary can direct, influence, or sequence a file-read operation, and the result is available to the adversary-directed workflow. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C003,SAF-T1502-C004; sources=SRC-mcp-tools-2025-11-25,SRC-anthropic-espionage-2025-11 -->

### Attack Flow

1. **Setup**: The adversary obtains influence over an agent workflow that already has filesystem-related capabilities; how that influence was obtained is outside this technique. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C003; sources=SRC-mcp-tools-2025-11-25,SRC-anthropic-espionage-2025-11 -->
2. **Discovery**: The workflow identifies a candidate credential file from a known location, configuration reference, directory listing, or prior result. <!-- SAF-TRACE: claims=SAF-T1502-C002,SAF-T1502-C008,SAF-T1502-C009; sources=SRC-mcp-resources-2025-11-25,SRC-aws-shared-credential-files,SRC-google-adc-files -->
3. **Read**: A tool, resource request, or local process attempts to read the candidate file. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C002; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25 -->
4. **Boundary Crossing**: The operation succeeds because the path is authorized, controls are overbroad, or path validation exposes an unintended file. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C005,SAF-T1502-C006; sources=SRC-anthropic-espionage-2025-11,SRC-cve-2025-53109,SRC-cve-2025-53110 -->
5. **Objective**: Credential material enters the tool result, model context, or adversary-directed state. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C004; sources=SRC-mcp-resources-2025-11-25,SRC-anthropic-espionage-2025-11 -->
6. **Follow-On Activity**: Credential validation, reuse, lateral movement, and transfer are separate downstream behaviors. <!-- SAF-TRACE: claims=SAF-T1502-C004,SAF-T1502-C014; sources=SRC-anthropic-espionage-2025-11,SRC-mitre-attack-t1552.001-v1.3,SRC-attack-t1005 -->

### Example Scenario

An inert test agent receives a request to inspect a demonstration configuration tree. Its normalized MCP event names a file marked `credential` by the defender's inventory, and a correlated operating-system event records a successful read by the same process; no credential value is included in the test data. <!-- SAF-TRACE: claims=SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->

```json
{
  "event.kind": "mcp_operation",
  "event.action": "read_file",
  "file.path": "/srv/demo/.secrets/example-token.json",
  "file.sensitivity": "credential",
  "event.outcome": "success"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1502-C001 | MCP tools are model-controlled; confirmation and logging are recommended. | Research-Derived | SRC-mcp-tools-2025-11-25: [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | SHOULD-level guidance does not prove implementation coverage. <!-- SAF-TRACE: claims=SAF-T1502-C001; sources=SRC-mcp-tools-2025-11-25 --> |
| SAF-T1502-C002 | MCP resources can expose and return file-like content. | Research-Derived | SRC-mcp-resources-2025-11-25: [MCP Resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources) | A file URI may be virtual; automatic inclusion is optional. <!-- SAF-TRACE: claims=SAF-T1502-C002; sources=SRC-mcp-resources-2025-11-25 --> |
| SAF-T1502-C003 | Readable credential files can cross into an adversary-directed agent context. | Observed | SRC-anthropic-espionage-2025-11; SRC-mcp-resources-2025-11-25; SRC-aws-shared-credential-files; SRC-google-adc-files | Requires readable reach and result availability. <!-- SAF-TRACE: claims=SAF-T1502-C003; sources=SRC-anthropic-espionage-2025-11,SRC-mcp-resources-2025-11-25,SRC-aws-shared-credential-files,SRC-google-adc-files --> |
| SAF-T1502-C004 | Anthropic documented MCP-orchestrated credential extraction in successful production intrusions. | Observed | SRC-anthropic-espionage-2025-11: [Anthropic report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) | Targets and per-intrusion event details are anonymized. <!-- SAF-TRACE: claims=SAF-T1502-C004; sources=SRC-anthropic-espionage-2025-11 --> |
| SAF-T1502-C005 | CVE-2025-53109 enabled unintended-file access through symlink handling. | Demonstrated | SRC-cve-2025-53109; SRC-ghsa-cve-2025-53109 | No production credential-file access is established; version metadata conflicts. <!-- SAF-TRACE: claims=SAF-T1502-C005; sources=SRC-cve-2025-53109,SRC-ghsa-cve-2025-53109 --> |
| SAF-T1502-C006 | CVE-2025-53110 enabled unintended-file access through colliding prefixes. | Demonstrated | SRC-cve-2025-53110; SRC-ghsa-cve-2025-53110 | No production credential-file access is established; version metadata conflicts. <!-- SAF-TRACE: claims=SAF-T1502-C006; sources=SRC-cve-2025-53110,SRC-ghsa-cve-2025-53110 --> |
| SAF-T1502-C007 | CISA ADP recorded exploitation as none for both filesystem CVEs. | Research-Derived | SRC-cve-2025-53109; SRC-cve-2025-53110 | A time-bounded catalog assessment is not a universal absence claim. <!-- SAF-TRACE: claims=SAF-T1502-C007; sources=SRC-cve-2025-53109,SRC-cve-2025-53110 --> |
| SAF-T1502-C008 | AWS tools can use plaintext local shared credential files. | Research-Derived | SRC-aws-shared-credential-files: [AWS file locations](https://docs.aws.amazon.com/sdkref/latest/guide/file-location.html) | Presence does not establish compromise. <!-- SAF-TRACE: claims=SAF-T1502-C008; sources=SRC-aws-shared-credential-files --> |
| SAF-T1502-C009 | Google Cloud ADC can use a local credential JSON file and warns about service-account-key risk. | Research-Derived | SRC-google-adc-files: [Google Cloud ADC](https://docs.cloud.google.com/docs/authentication/application-default-credentials) | Product-specific guidance does not generalize every credential type. <!-- SAF-TRACE: claims=SAF-T1502-C009; sources=SRC-google-adc-files --> |
| SAF-T1502-C010 | MCP guidance recommends sandboxing, filesystem restrictions, explicit grants, and minimal scopes. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Guidance does not prove deployment conformance. <!-- SAF-TRACE: claims=SAF-T1502-C010; sources=SRC-mcp-security-2025-11-25 --> |
| SAF-T1502-C011 | Windows Event 4663 can expose path, process, subject, and read-access fields. | Research-Derived | SRC-microsoft-event-4663: [Microsoft Event 4663](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663) | Required auditing may be absent or noisy. <!-- SAF-TRACE: claims=SAF-T1502-C011; sources=SRC-microsoft-event-4663 --> |
| SAF-T1502-C012 | RHEL audit can record read attempts with event, process, subject, outcome, and path fields. | Research-Derived | SRC-rhel9-audit: [RHEL 9 auditing](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening) | Only configured rules produce the required events. <!-- SAF-TRACE: claims=SAF-T1502-C012; sources=SRC-rhel9-audit --> |
| SAF-T1502-C013 | A same-process, five-minute MCP-to-OS read correlation is testable. | Research-Derived | SRC-mcp-tools-2025-11-25; SRC-microsoft-event-4663; SRC-rhel9-audit | The window and sensitivity label require local tuning. <!-- SAF-TRACE: claims=SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit --> |
| SAF-T1502-C014 | ATT&CK T1552.001 directly maps; broader collection, stores, OS structures, and input capture are distinct. | Research-Derived | SRC-mitre-attack-t1552.001-v1.3; SRC-attack-t1005; SRC-mitre-t1555; SRC-mitre-t1003; SRC-mitre-t1056 | SAF neighbor boundaries remain framework inferences. <!-- SAF-TRACE: claims=SAF-T1502-C014; sources=SRC-mitre-attack-t1552.001-v1.3,SRC-attack-t1005,SRC-mitre-t1555,SRC-mitre-t1003,SRC-mitre-t1056 --> |
| SAF-T1502-C015 | Anthropic found invalid or public-information credential claims. | Observed | SRC-anthropic-espionage-2025-11: [Anthropic report](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) | The report does not quantify the false-claim rate. <!-- SAF-TRACE: claims=SAF-T1502-C015; sources=SRC-anthropic-espionage-2025-11 --> |
| SAF-T1502-C016 | Response should preserve evidence, contain the agent/process, address exposed credentials and filesystem reach, and validate recovery. | Research-Derived | SRC-nist-sp800-61r3; SRC-google-adc-files; SRC-mcp-security-2025-11-25 | Issuer- and platform-specific procedures still apply. <!-- SAF-TRACE: claims=SAF-T1502-C016; sources=SRC-nist-sp800-61r3,SRC-google-adc-files,SRC-mcp-security-2025-11-25 --> |

### Current State

- **Affected Environments**: MCP or agent deployments whose process identity can read local or mounted credential-bearing files, including environments with overbroad mounts or vulnerable Filesystem server versions. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C005,SAF-T1502-C006; sources=SRC-anthropic-espionage-2025-11,SRC-cve-2025-53109,SRC-cve-2025-53110 -->
- **Known Exploitation**: One qualifying agentic production campaign is directly documented; the two selected Filesystem server CVEs have no exploitation recorded in the reviewed CISA ADP fields. <!-- SAF-TRACE: claims=SAF-T1502-C004,SAF-T1502-C007; sources=SRC-anthropic-espionage-2025-11,SRC-cve-2025-53109,SRC-cve-2025-53110 -->
- **Available Protections**: Restrict filesystem reach, sandbox local servers, grant narrow scopes explicitly, require sensitive-operation confirmation, log tool use, and upgrade affected Filesystem servers. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C005,SAF-T1502-C006,SAF-T1502-C010; sources=SRC-mcp-tools-2025-11-25,SRC-cve-2025-53109,SRC-cve-2025-53110,SRC-mcp-security-2025-11-25 -->
- **Residual Risk**: Authorized reads can still expose a credential file inside an approved directory, and missing OS or MCP telemetry can prevent correlation. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C013; sources=SRC-anthropic-espionage-2025-11,SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Anthropic GTG-1002 campaign | September 2025; MCP-orchestrated Claude Code operations across roughly 30 targets, with a handful of successful intrusions | Authentication certificates were extracted from configurations and credentials were tested; Anthropic banned accounts, notified affected parties, and expanded safeguards | Direct production incident | Affected entities and file-level evidence are anonymized; some model-claimed credentials were invalid or public information. <!-- SAF-TRACE: claims=SAF-T1502-C004,SAF-T1502-C015; sources=SRC-anthropic-espionage-2025-11 --> |
| CVE-2025-53109 / GHSA-q66q-fx2p-7w4m | Published July 2025; MCP Filesystem server before the conservative fixed target 0.6.4 or 2025.7.01 | Symlink handling allowed unintended-file access; upgrade to 0.6.4 or 2025.7.01 | Direct vulnerability | No production credential-file access is established; advisory version fields conflict; CISA ADP recorded exploitation as none. Credit: Elad Beber of Cymulate and advisory publisher dsp-ant. <!-- SAF-TRACE: claims=SAF-T1502-C005,SAF-T1502-C007; sources=SRC-cve-2025-53109,SRC-ghsa-cve-2025-53109 --> |
| CVE-2025-53110 / GHSA-hc55-p739-j48w | Published July 2025; MCP Filesystem server before the conservative fixed target 0.6.4 or 2025.7.01 | Colliding-prefix validation allowed unintended-file access; upgrade to 0.6.4 or 2025.7.01 | Direct vulnerability | No production credential-file access is established; advisory version fields conflict; CISA ADP recorded exploitation as none. Credit: Elad Beber of Cymulate and advisory publisher dsp-ant. <!-- SAF-TRACE: claims=SAF-T1502-C006,SAF-T1502-C007; sources=SRC-cve-2025-53110,SRC-ghsa-cve-2025-53110 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Successful reads expose authentication material; practical impact depends on credential scope, validity, and result access. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C004,SAF-T1502-C009; sources=SRC-anthropic-espionage-2025-11,SRC-google-adc-files --> |
| Integrity | High | Reusable credentials can support authenticated follow-on actions, but those actions are outside this technique and require the credential to remain valid. <!-- SAF-TRACE: claims=SAF-T1502-C004,SAF-T1502-C009; sources=SRC-anthropic-espionage-2025-11,SRC-google-adc-files --> |
| Availability | Low | The defining file read does not require disruption; availability impact would arise from later credential use or a separate vulnerability effect. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C005,SAF-T1502-C006; sources=SRC-anthropic-espionage-2025-11,SRC-cve-2025-53109,SRC-cve-2025-53110 --> |
| Scope | Multi-System | A credential may reach additional services, but blast radius is bounded by its privileges, expiration, and service acceptance. <!-- SAF-TRACE: claims=SAF-T1502-C004,SAF-T1502-C009,SAF-T1502-C010; sources=SRC-anthropic-espionage-2025-11,SRC-google-adc-files,SRC-mcp-security-2025-11-25 --> |

### Severity Conditions

- **Severity increases when**: Files contain long-lived or broadly privileged credentials, the agent has wide filesystem reach, approvals are absent, or downstream services accept the material. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C009,SAF-T1502-C010; sources=SRC-anthropic-espionage-2025-11,SRC-google-adc-files,SRC-mcp-security-2025-11-25 -->
- **Severity decreases when**: Credential files are absent or unreadable, local servers are sandboxed to narrow directories, scopes are least-privileged, confirmation gates operate, or credentials are short-lived and unusable outside their workload. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C009,SAF-T1502-C010; sources=SRC-mcp-tools-2025-11-25,SRC-google-adc-files,SRC-mcp-security-2025-11-25 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host, client, server, or agent audit log | Successful filesystem tool calls or resource reads | Timestamp, host, session, server, tool or method, target URI/path, arguments, process identity, approval, outcome | Retain normalized process identity and do not rely on model text as proof. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C013,SAF-T1502-C015; sources=SRC-mcp-tools-2025-11-25,SRC-anthropic-espionage-2025-11,SRC-microsoft-event-4663,SRC-rhel9-audit --> |
| Operating-system file-access audit | Successful reads of files labeled as credential material | Timestamp, host, process, subject, file path, access type, success, local sensitivity label | Configure targeted read auditing; broad auditing may be noisy or costly. <!-- SAF-TRACE: claims=SAF-T1502-C011,SAF-T1502-C012,SAF-T1502-C013; sources=SRC-microsoft-event-4663,SRC-rhel9-audit --> |

### Indicators of Compromise (IoCs)

- No universal durable IoC is inherent to this behavior; file paths, process identities, credentials, and infrastructure are deployment-specific. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C013; sources=SRC-anthropic-espionage-2025-11,SRC-microsoft-event-4663,SRC-rhel9-audit -->

### Behavioral Indicators

- A filesystem-related MCP action is followed by a successful credential-labeled file read from the same host and process. <!-- SAF-TRACE: claims=SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->
- The read targets a directory outside the server's intended scope or uses a Filesystem server version affected by the selected path-validation advisories. <!-- SAF-TRACE: claims=SAF-T1502-C005,SAF-T1502-C006,SAF-T1502-C010; sources=SRC-cve-2025-53109,SRC-cve-2025-53110,SRC-mcp-security-2025-11-25 -->
- Model output claims a credential discovery without a matching successful tool and OS event; treat this as uncorroborated, not confirmed acquisition. <!-- SAF-TRACE: claims=SAF-T1502-C015; sources=SRC-anthropic-espionage-2025-11 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect a successful credential-file read attributable to an MCP or agent filesystem operation. <!-- SAF-TRACE: claims=SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->
- **Rule Status**: Experimental; it uses a normalized cross-source schema and requires local field mapping. <!-- SAF-TRACE: claims=SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->
- **Detection Logic**: Correlate a successful credential-labeled MCP read with a successful credential-labeled OS read on the same host and process, excluding explicitly approved maintenance. <!-- SAF-TRACE: claims=SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->
- **Correlation Window**: Five minutes, inclusive; this is a tested tuning boundary rather than a protocol requirement. <!-- SAF-TRACE: claims=SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->
- **Known False Positives**: Approved credential rotation, backup, migration, or debugging, plus incorrect sensitivity or process enrichment. <!-- SAF-TRACE: claims=SAF-T1502-C013,SAF-T1502-C015; sources=SRC-anthropic-espionage-2025-11,SRC-microsoft-event-4663,SRC-rhel9-audit -->
- **Known Limitations**: Missing read auditing, mismatched process identifiers, direct shell reads, unclassified files, encrypted contents, and telemetry loss can prevent a match. <!-- SAF-TRACE: claims=SAF-T1502-C011,SAF-T1502-C012,SAF-T1502-C013; sources=SRC-microsoft-event-4663,SRC-rhel9-audit -->
- **Tuning Guidance**: Maintain a reviewed credential-file sensitivity inventory, map process identities consistently, measure normal automation, and require change records for maintenance exclusions. <!-- SAF-TRACE: claims=SAF-T1502-C010,SAF-T1502-C013; sources=SRC-mcp-security-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->

### Validation

- **Test Data**: [test-logs.json](../../tests/SAF-T1502/test-logs.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1502/test_detection_rule.py)
- **Expected Result**: Nine cases pass: three alerts and six non-alerts spanning positives, a 300-second inclusive boundary, a 301-second exclusion, normalization, mismatched process, non-credential access, approved maintenance, a missing timestamp, and failed access. <!-- SAF-TRACE: claims=SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->
- **Last Validated**: 2026-09-01 in the [quality review](../../research/techniques/SAF-T1502/quality-review.yml).
- **Feasibility Waiver**: None; deterministic synthetic validation is required and recorded in the [quality review](../../research/techniques/SAF-T1502/quality-review.yml).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-9: Sandboxed Testing](../../mitigations/SAF-M-9/README.md)** and **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Run local MCP servers in a sandbox with minimal default privileges and grant only the directories needed for the task. <!-- SAF-TRACE: claims=SAF-T1502-C010; sources=SRC-mcp-security-2025-11-25 -->
2. **[SAF-M-15: User Warning Systems](../../mitigations/SAF-M-15/README.md)** and **[SAF-M-74: Per-Invocation Capability Brokering](../../mitigations/SAF-M-74/README.md)**: Require explicit confirmation for sensitive reads, display tool inputs, restrict resource URIs, and enforce server-side access controls rather than trusting descriptions or annotations. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C002,SAF-T1502-C010; sources=SRC-mcp-tools-2025-11-25,SRC-mcp-resources-2025-11-25,SRC-mcp-security-2025-11-25 -->
3. Upgrade affected MCP Filesystem servers to 0.6.4 or 2025.7.01 and verify path authorization after canonicalization; the source metadata discrepancy should be considered during asset review. <!-- SAF-TRACE: claims=SAF-T1502-C005,SAF-T1502-C006; sources=SRC-cve-2025-53109,SRC-ghsa-cve-2025-53109,SRC-cve-2025-53110,SRC-ghsa-cve-2025-53110 -->
4. Prefer workload-bound or attached identities with least-privileged roles over portable long-lived key files where the platform supports that model. <!-- SAF-TRACE: claims=SAF-T1502-C009; sources=SRC-google-adc-files -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Log filesystem-related MCP operations with target, approval, process, session, and outcome fields, then correlate them with targeted OS read auditing. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C011,SAF-T1502-C012,SAF-T1502-C013; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-event-4663,SRC-rhel9-audit -->
2. **[SAF-M-20: Anomaly Detection](../../mitigations/SAF-M-20/README.md)**: Alert on out-of-scope paths and credential-sensitive files while retaining allowlisted maintenance context and investigating uncorroborated model claims separately. <!-- SAF-TRACE: claims=SAF-T1502-C010,SAF-T1502-C013,SAF-T1502-C015; sources=SRC-mcp-security-2025-11-25,SRC-anthropic-espionage-2025-11,SRC-microsoft-event-4663,SRC-rhel9-audit -->

### Response Procedures

#### Immediate Actions

- Preserve MCP and OS events, contain the involved session or process, and prevent further filesystem and network activity consistent with the organization's incident-response authority. <!-- SAF-TRACE: claims=SAF-T1502-C016; sources=SRC-nist-sp800-61r3,SRC-mcp-security-2025-11-25 -->
- **[SAF-M-37: Token Rotation and Invalidation](../../mitigations/SAF-M-37/README.md)**: Revoke, rotate, or otherwise invalidate credibly exposed material using issuer-specific procedures, prioritizing broad or long-lived credentials. <!-- SAF-TRACE: claims=SAF-T1502-C009,SAF-T1502-C016; sources=SRC-google-adc-files,SRC-nist-sp800-61r3 -->

#### Investigation Steps

- Correlate tool, resource, process, file-access, identity, and downstream authentication records to determine what was read and whether it was accepted elsewhere. <!-- SAF-TRACE: claims=SAF-T1502-C011,SAF-T1502-C012,SAF-T1502-C013,SAF-T1502-C016; sources=SRC-microsoft-event-4663,SRC-rhel9-audit,SRC-nist-sp800-61r3 -->
- Validate model-reported findings against system evidence and scope affected hosts, sessions, files, credentials, and services. <!-- SAF-TRACE: claims=SAF-T1502-C015,SAF-T1502-C016; sources=SRC-anthropic-espionage-2025-11,SRC-nist-sp800-61r3 -->

#### Remediation

- Remove unsafe filesystem grants or mounts, patch vulnerable servers, narrow scopes, and restore the agent only after testing access boundaries. <!-- SAF-TRACE: claims=SAF-T1502-C005,SAF-T1502-C006,SAF-T1502-C010,SAF-T1502-C016; sources=SRC-cve-2025-53109,SRC-cve-2025-53110,SRC-mcp-security-2025-11-25,SRC-nist-sp800-61r3 -->
- Validate credential invalidation and recovery, add regression tests and monitoring, and feed lessons learned into the organization's risk process. <!-- SAF-TRACE: claims=SAF-T1502-C016; sources=SRC-nist-sp800-61r3,SRC-google-adc-files -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1505: In-Memory Secret Extraction](../SAF-T1505/README.md) | Alternative | SAF-T1505 covers secrets extracted from process or model memory; SAF-T1502 reads ordinary files. Other protected-store mechanisms remain outside this join. <!-- SAF-TRACE: claims=SAF-T1502-C014; sources=SRC-mitre-t1555,SRC-mitre-t1003 --> |
| [SAF-T1911: Parameter Exfiltration](../SAF-T1911/README.md) | Follow-On | SAF-T1911 covers moving acquired material in outbound tool parameters; SAF-T1502 ends at acquisition into the result or workflow. <!-- SAF-TRACE: claims=SAF-T1502-C003,SAF-T1502-C014; sources=SRC-anthropic-espionage-2025-11,SRC-attack-t1005 --> |
| [SAF-T1003: Malicious MCP-Server Distribution](../SAF-T1003/README.md) | Prerequisite | SAF-T1003 covers delivery of malicious server capability; SAF-T1502 assumes filesystem access already exists. <!-- SAF-TRACE: claims=SAF-T1502-C001,SAF-T1502-C003; sources=SRC-mcp-tools-2025-11-25,SRC-anthropic-espionage-2025-11 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | Direct | Both behaviors search or read files for credential material; SAF-T1502 adds the MCP or agent workflow and model/result boundary. <!-- SAF-TRACE: claims=SAF-T1502-C014; sources=SRC-mitre-attack-t1552.001-v1.3 --> |
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Analogous | T1005 covers broader local data collection and does not require credential material as the immediate objective. <!-- SAF-TRACE: claims=SAF-T1502-C014; sources=SRC-attack-t1005 --> |

## References

1. **SRC-mcp-tools-2025-11-25**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — Model Context Protocol contributors; model-controlled tools, confirmation, access controls, and logging.
2. **SRC-mcp-resources-2025-11-25**: [MCP Resources specification](https://modelcontextprotocol.io/specification/2025-11-25/server/resources) — Model Context Protocol contributors; file-like resources, reads, URI validation, and permissions.
3. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — MCP security contributors; local-server sandboxing, restricted filesystem access, monitoring, and scope minimization.
4. **SRC-anthropic-espionage-2025-11**: [Disrupting the first reported AI-orchestrated cyber espionage campaign](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) — Anthropic Threat Intelligence team, November 2025.
5. **SRC-cve-2025-53109**: [CVE-2025-53109](https://cveawg.mitre.org/api/cve/CVE-2025-53109) — GitHub Security Advisory CNA and CISA Vulnerability Management team; symlink handling, affected versions, and exploitation assessment.
6. **SRC-ghsa-cve-2025-53109**: [GHSA-q66q-fx2p-7w4m](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-q66q-fx2p-7w4m) — Model Context Protocol servers maintainers; reported by Elad Beber of Cymulate and published by dsp-ant.
7. **SRC-cve-2025-53110**: [CVE-2025-53110](https://cveawg.mitre.org/api/cve/CVE-2025-53110) — GitHub Security Advisory CNA and CISA Vulnerability Management team; colliding-prefix validation, affected versions, and exploitation assessment.
8. **SRC-ghsa-cve-2025-53110**: [GHSA-hc55-p739-j48w](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-hc55-p739-j48w) — Model Context Protocol servers maintainers; reported by Elad Beber of Cymulate and published by dsp-ant.
9. **SRC-aws-shared-credential-files**: [AWS shared config and credential-file locations](https://docs.aws.amazon.com/sdkref/latest/guide/file-location.html) — AWS SDKs and Tools Documentation team.
10. **SRC-google-adc-files**: [How Application Default Credentials works](https://docs.cloud.google.com/docs/authentication/application-default-credentials) — Google Cloud Authentication Documentation team, updated August 26, 2026.
11. **SRC-microsoft-event-4663**: [Windows Security Event 4663](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663) — Microsoft Windows Security Auditing Documentation team.
12. **SRC-rhel9-audit**: [RHEL 9 Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening) — Red Hat Enterprise Linux Documentation team.
13. **SRC-mitre-attack-t1552.001-v1.3**: [ATT&CK T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) — MITRE ATT&CK; contributors Jay Chen, Microsoft Threat Intelligence Center, Rory McCune, Vishwas Manral, and Yossi Weizman.
14. **SRC-attack-t1005**: [ATT&CK T1005 Data from Local System](https://attack.mitre.org/techniques/T1005/) — MITRE ATT&CK; contributors Austin Clark, Liran Ravich, and William Cain.
15. **SRC-mitre-t1555**: [ATT&CK T1555 Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/) — MITRE ATT&CK team.
16. **SRC-mitre-t1003**: [ATT&CK T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003/) — MITRE ATT&CK; contributors Ed Williams, Tim Wadhwa-Brown, Vincent Le Toux, and Yves Yonan.
17. **SRC-mitre-t1056**: [ATT&CK T1056 Input Capture](https://attack.mitre.org/techniques/T1056/) — MITRE ATT&CK; contributor John Lambert and Microsoft Threat Intelligence Center.
18. **SRC-nist-sp800-61r3**: [NIST SP 800-61 Rev. 3](https://doi.org/10.6028/NIST.SP.800-61r3) — Alexander Nelson, Sanjay Rekhi, Murugiah Souppaya, and Karen Scarfone, April 2025.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft with evidence packet, tested detection, rights review, and isolated validation | OpenAI Codex clean-room research agent |
