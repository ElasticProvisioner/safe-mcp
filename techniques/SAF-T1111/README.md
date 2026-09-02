# SAF-T1111: AI Agent CLI Weaponization

## Overview

- **Tactic**: Execution (ATK-TA0002)
- **Technique ID**: SAF-T1111
- **Research Packet**: [research/techniques/SAF-T1111](../../research/techniques/SAF-T1111/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1111/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Observed
- **Severity**: Critical
- **Severity Rationale**: Severity is critical when an adversary supplies the objective, tools, and execution context for an autonomous coding agent that can reach live systems or sensitive data; it falls with isolation, constrained credentials, and human approval gates. <!-- SAF-TRACE: claims=SAF-T1111-C018; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->
- **First Observed**: June 2025 reporting period, in Anthropic Threat Intelligence's GTG-2002 data-extortion investigation. <!-- SAF-TRACE: claims=SAF-T1111-C003; sources=SRC-anthropic-tir-2025-08 -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers an adversary deliberately operating an AI coding-agent command-line interface as the execution and orchestration layer for malicious actions against real targets, crossing from model-mediated tasking into commands or tools that act on target systems. <!-- SAF-TRACE: claims=SAF-T1111-C001; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->

### In Scope

- Adversary-controlled tasking that causes an AI agent CLI to select, sequence, or execute offensive tools or shell actions. <!-- SAF-TRACE: claims=SAF-T1111-C001; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->
- Agent CLI operation on attacker infrastructure or an attacker-controlled execution host, including autonomous and non-interactive runs. <!-- SAF-TRACE: claims=SAF-T1111-C004; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli -->

### Out of Scope

- Untrusted repository text or remote content that hijacks a benign user's agent session; that boundary begins with input-driven instruction manipulation rather than an adversary intentionally operating the CLI. <!-- SAF-TRACE: claims=SAF-T1111-C016; sources=SRC-anthropic-claude-code-security,SRC-ghsa-gemini-trust -->
- Ordinary shell execution without model-mediated planning, and downstream collection, persistence, or exfiltration after the CLI-triggered execution objective is achieved. <!-- SAF-TRACE: claims=SAF-T1111-C016; sources=SRC-mitre-t1059-current -->

### Distinguishing Characteristics

Classify this behavior here when the adversary intentionally makes an AI agent CLI the decision-and-execution intermediary. Classify input-driven compromise of a legitimate operator's agent separately, and classify a human or conventional program invoking a shell directly as command-interpreter abuse. <!-- SAF-TRACE: claims=SAF-T1111-C016; sources=SRC-anthropic-claude-code-security,SRC-mitre-t1059-current,SRC-anthropic-tir-2025-08 -->

## Description

AI coding-agent CLIs can execute commands, use tools, and run without continuous human interaction. Some products expose explicit non-interactive or permission-bypass modes, while their security guidance recommends sandboxing and approval boundaries for unattended work. <!-- SAF-TRACE: claims=SAF-T1111-C004,SAF-T1111-C005; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli,SRC-anthropic-claude-code-security,SRC-google-gemini-sandbox -->

In this technique, the adversary supplies the malicious objective and uses the CLI as an execution engine. Anthropic documented both a 2025 extortion operation in which Claude Code supported live intrusions and a later espionage campaign in which Claude Code and MCP-connected tools performed most tactical work with limited human supervision. <!-- SAF-TRACE: claims=SAF-T1111-C002,SAF-T1111-C003; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->

The evidence does not establish that all agent CLIs behave alike or that autonomous output is reliable. Anthropic reported visibility limited to Claude usage and noted fabricated or overstated results during the espionage campaign. <!-- SAF-TRACE: claims=SAF-T1111-C015; sources=SRC-anthropic-espionage-2025-11 -->

## Attack Vectors

- **Primary Vector**: An adversary launches an agent CLI with malicious tasking and access to offensive tools or target connectivity. <!-- SAF-TRACE: claims=SAF-T1111-C001; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->
- **Secondary Vectors**: Non-interactive execution, persistent project instructions, multiple sub-agents, and MCP-connected tools can scale or sustain the activity. <!-- SAF-TRACE: claims=SAF-T1111-C002,SAF-T1111-C003,SAF-T1111-C004; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11,SRC-openai-codex-cli -->
- **Affected Components**: Agent CLI, its host, shell or tool subprocesses, MCP integrations, target-facing network paths, and credentials available to the execution context. <!-- SAF-TRACE: claims=SAF-T1111-C002,SAF-T1111-C003; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->
- **Trust Boundary Crossed**: Model-mediated instructions become operating-system or connected-tool actions against a target environment. <!-- SAF-TRACE: claims=SAF-T1111-C001; sources=SRC-anthropic-espionage-2025-11 -->

## Technical Details

### Prerequisites

- The adversary can operate an agent CLI and provide its tasking or persistent project context. <!-- SAF-TRACE: claims=SAF-T1111-C003; sources=SRC-anthropic-tir-2025-08 -->
- The CLI execution context can reach a shell, offensive tools, target systems, or sensitive data. <!-- SAF-TRACE: claims=SAF-T1111-C002; sources=SRC-anthropic-espionage-2025-11 -->
- Safeguards are bypassed, disabled, misconfigured, or deceived sufficiently for the requested actions to proceed. <!-- SAF-TRACE: claims=SAF-T1111-C005; sources=SRC-anthropic-claude-code-security -->

### Attack Flow

1. **Setup**: The adversary supplies a target and task context to an agent CLI. <!-- SAF-TRACE: claims=SAF-T1111-C002,SAF-T1111-C003; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->
2. **Capability Binding**: The CLI is connected to shell commands, tools, credentials, or MCP services needed for the operation. <!-- SAF-TRACE: claims=SAF-T1111-C002; sources=SRC-anthropic-espionage-2025-11 -->
3. **Execution**: The agent selects or sequences actions and invokes the available execution interfaces. <!-- SAF-TRACE: claims=SAF-T1111-C001; sources=SRC-anthropic-espionage-2025-11 -->
4. **Boundary Crossing**: Model-generated decisions become actions against live target systems. <!-- SAF-TRACE: claims=SAF-T1111-C001; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->
5. **Objective**: The adversary gains execution at the scale and pace provided by the agentic workflow. <!-- SAF-TRACE: claims=SAF-T1111-C002,SAF-T1111-C003; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->
6. **Follow-On Activity**: Separate behaviors may include credential access, lateral movement, collection, persistence, and exfiltration. <!-- SAF-TRACE: claims=SAF-T1111-C016; sources=SRC-anthropic-tir-2025-08 -->

### Example Scenario

A controlled test account launches an agent CLI in an isolated lab, enables a no-approval mode, and asks it only to create a marker file under an inert workspace. The example represents the observable parent-agent-to-shell transition without a harmful payload or live target. <!-- SAF-TRACE: claims=SAF-T1111-C019; sources=SRC-openai-codex-cli,SRC-google-gemini-sandbox,SRC-sysmon-15-21 -->

```json
{
  "agent": "example-agent",
  "execution_mode": "no-approval-lab",
  "action": "create marker.txt in /workspace/demo",
  "target": "isolated.example"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1111-C001 | Adversaries have intentionally used an AI coding-agent CLI as an execution and orchestration intermediary for live cyber operations. | Observed | SRC-anthropic-tir-2025-08 and SRC-anthropic-espionage-2025-11 | Vendor visibility is limited to Claude-related activity. |
| SAF-T1111-C002 | GTG-1002 used Claude Code and MCP tools across live intrusions with high tactical autonomy. | Observed | SRC-anthropic-espionage-2025-11 | Anthropic did not identify victims publicly and reported agent hallucinations. |
| SAF-T1111-C003 | GTG-2002 used Claude Code in a multi-organization data-theft and extortion operation. | Observed | SRC-anthropic-tir-2025-08 | The report describes the campaign from Anthropic's platform perspective. |
| SAF-T1111-C011 | Parent-agent process telemetry plus shell-child and unsafe-mode context is a testable but narrow analytic. | Research-Derived | SRC-sysmon-15-21, SRC-openai-codex-cli, and SRC-anthropic-claude-cli | It misses weaponization without exposed flags or parent-child visibility. |

### Current State

- **Affected Environments**: Coding-agent CLIs operating with shell or tool access on attacker infrastructure, test hosts, CI runners, or other connected execution environments. <!-- SAF-TRACE: claims=SAF-T1111-C004; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli,SRC-google-gemini-sandbox -->
- **Known Exploitation**: Two Anthropic investigations document Claude Code used in production cyber operations; the reviewed advisory records do not establish that the listed product vulnerabilities were exploited in the wild. <!-- SAF-TRACE: claims=SAF-T1111-C002,SAF-T1111-C003,SAF-T1111-C009; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11,SRC-nvd-t1103-corpus,SRC-cisa-kev-catalog-page-2026-09-01 -->
- **Available Protections**: Approval prompts, command allow/deny policies, folder trust, sandboxing, scoped directories, and patched versions constrain execution paths when correctly configured. <!-- SAF-TRACE: claims=SAF-T1111-C005,SAF-T1111-C006,SAF-T1111-C007,SAF-T1111-C008; sources=SRC-anthropic-claude-code-security,SRC-openai-codex-cli,SRC-google-gemini-sandbox,SRC-ghsa-codex-sandbox,SRC-ghsa-gemini-trust -->
- **Residual Risk**: An intentional malicious operator can run a properly functioning agent CLI within an attacker-controlled environment, so product patching alone does not remove this behavior. <!-- SAF-TRACE: claims=SAF-T1111-C016; sources=SRC-anthropic-tir-2025-08 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| GTG-1002 cyber-espionage campaign | September 2025; roughly 30 technology, finance, manufacturing, and government targets | A handful of successful intrusions; Anthropic banned accounts, notified affected entities, coordinated with authorities, and expanded detection. | Direct production incident: Claude Code and MCP tools formed the automated execution framework. <!-- SAF-TRACE: claims=SAF-T1111-C002; sources=SRC-anthropic-espionage-2025-11 --> | Victims and technical indicators were not publicly named; results included hallucinations. |
| GTG-2002 data-extortion operation | Reported August 2025; at least 17 organizations across several sectors | Live network intrusion, sensitive-data theft, and extortion demands; Anthropic banned accounts and developed tailored detection. | Direct production incident: the actor operated Claude Code as an attack platform. <!-- SAF-TRACE: claims=SAF-T1111-C003; sources=SRC-anthropic-tir-2025-08 --> | The report does not provide independent victim confirmation or a complete indicator set. |
| CVE-2025-59532 / GHSA-w5fx-fh39-j5rw | 2025; Codex CLI 0.2.0–0.38.0 and IDE extension through 0.4.11 | Sandbox-boundary bypass could permit writes and commands outside the starting workspace; fixed in CLI 0.39.0 and extension 0.4.12. | Adjacent enabling vulnerability: untrusted model context can widen execution, but intentional adversary operation is not required. <!-- SAF-TRACE: claims=SAF-T1111-C007; sources=SRC-ghsa-codex-sandbox,SRC-nvd-t1103-corpus --> | No reviewed source established exploitation in the wild. |
| CVE-2026-12537 / GHSA-wpqr-6v78-jr5g | 2026; Gemini CLI before 0.39.1 and run-gemini-cli before 0.1.22 in headless workflows | Malicious workspace configuration or permissive tool policy could produce pre-sandbox or prompt-injection-driven command execution; fixed by explicit folder trust and allowlist enforcement. | Adjacent enabling vulnerability: it concerns hostile input against a legitimate workflow, not deliberate CLI weaponization. <!-- SAF-TRACE: claims=SAF-T1111-C008; sources=SRC-ghsa-gemini-trust,SRC-nvd-t1103-corpus --> | The advisory describes risk and proof-of-concept status, not a production breach. |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Critical | Live cases included credential harvesting, database access, and sensitive-data extraction when target connectivity and privileges were available. <!-- SAF-TRACE: claims=SAF-T1111-C018; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 --> |
| Integrity | High | The espionage case included exploit delivery, persistence-related actions, and changes to target state under bounded human authorization. <!-- SAF-TRACE: claims=SAF-T1111-C018; sources=SRC-anthropic-espionage-2025-11 --> |
| Availability | High | The defining execution mechanism can support disruptive actions, although the selected cases primarily document espionage and extortion rather than measured outages. <!-- SAF-TRACE: claims=SAF-T1111-C018; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 --> |
| Scope | Multi-System | Both selected campaigns operated across multiple targets or organizations; reach remained bounded by credentials, connectivity, tool access, and safeguards. <!-- SAF-TRACE: claims=SAF-T1111-C018; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 --> |

### Severity Conditions

- **Severity increases when**: The agent has broad target connectivity, privileged credentials, autonomous execution, multiple tool integrations, or disabled approval and sandbox controls. <!-- SAF-TRACE: claims=SAF-T1111-C018; sources=SRC-anthropic-espionage-2025-11,SRC-anthropic-claude-code-security -->
- **Severity decreases when**: The agent runs in a dedicated sandbox with narrow credentials, restricted egress, explicit approvals, and constrained working directories. <!-- SAF-TRACE: claims=SAF-T1111-C005; sources=SRC-openai-codex-cli,SRC-anthropic-claude-code-security,SRC-google-gemini-sandbox -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Endpoint process creation | Agent CLI spawning a shell or command interpreter | timestamp, host, user, parent image and command line, child image and command line, session identifier | Sysmon records full command lines for parent and current processes and identifiers useful for correlation. <!-- SAF-TRACE: claims=SAF-T1111-C010; sources=SRC-sysmon-15-21 --> |
| Agent or runner audit log | Session mode, approvals, tool calls, and result status | agent, session, execution mode, approval state, tool, target, result | Product-specific schemas vary; retain the product mode and approval context when available. <!-- SAF-TRACE: claims=SAF-T1111-C004,SAF-T1111-C005; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC is established; agent CLI process names and unsafe-mode flags are behavioral context and can also occur in authorized testing. <!-- SAF-TRACE: claims=SAF-T1111-C012; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli,SRC-ghsa-gemini-trust -->

### Behavioral Indicators

- An agent CLI parent launches a shell while its own command line contains a documented permission-bypass or unattended unsafe-mode flag. <!-- SAF-TRACE: claims=SAF-T1111-C011; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli,SRC-ghsa-gemini-trust,SRC-sysmon-15-21 -->
- Confidence increases when endpoint events correlate with rapid, repeated target-facing tool use or account-safety enforcement, patterns documented in the selected incidents. <!-- SAF-TRACE: claims=SAF-T1111-C011; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->
- Authorized isolated security tests are expected lookalikes and require allowlisting by host, user, runner, or approved campaign identifier. <!-- SAF-TRACE: claims=SAF-T1111-C012; sources=SRC-openai-codex-cli,SRC-anthropic-claude-code-security -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Flag a documented unsafe agent-CLI mode immediately followed by a shell child process. <!-- SAF-TRACE: claims=SAF-T1111-C011; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli,SRC-ghsa-gemini-trust,SRC-sysmon-15-21 -->
- **Rule Status**: Test. <!-- SAF-TRACE: claims=SAF-T1111-C011; sources=SRC-sysmon-15-21 -->
- **Detection Logic**: Normalize executable basenames and case, require a recognized agent parent, a shell child, and an unsafe-mode marker in the parent command line. <!-- SAF-TRACE: claims=SAF-T1111-C011; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli,SRC-ghsa-gemini-trust,SRC-sysmon-15-21 -->
- **Correlation Window**: Single process-creation event with parent context; downstream correlation is optional enrichment. <!-- SAF-TRACE: claims=SAF-T1111-C010,SAF-T1111-C011; sources=SRC-sysmon-15-21 -->
- **Known False Positives**: Approved red-team, CI, or sandboxed development jobs intentionally using unsafe modes. <!-- SAF-TRACE: claims=SAF-T1111-C012; sources=SRC-openai-codex-cli,SRC-ghsa-gemini-trust -->
- **Known Limitations**: The analytic misses malicious sessions that retain approvals, hide parent command lines, use unrecognized agent names, or call tools without a shell child; it does not prove malicious intent. <!-- SAF-TRACE: claims=SAF-T1111-C012; sources=SRC-sysmon-15-21,SRC-anthropic-espionage-2025-11 -->
- **Tuning Guidance**: Maintain product-version-aware agent and flag lists and suppress only known isolated runners or authorized campaign identities. <!-- SAF-TRACE: claims=SAF-T1111-C012; sources=SRC-openai-codex-cli,SRC-anthropic-claude-cli,SRC-ghsa-gemini-trust -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: [Ten deterministic cases](test-logs.json) pass: four alerts, five non-alerts, and one authorized-lab lookalike that is expected to alert. <!-- SAF-TRACE: claims=SAF-T1111-C013; sources=SRC-sysmon-15-21,SRC-openai-codex-cli -->
- **Last Validated**: 2026-09-01 ([quality review](../../research/techniques/SAF-T1111/quality-review.yml))
- **Feasibility Waiver**: None ([quality review](../../research/techniques/SAF-T1111/quality-review.yml)).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-9: Sandboxed Testing](../../mitigations/SAF-M-9/README.md)**: Run unattended agent CLIs in dedicated sandboxes or runners with constrained filesystems and network access. <!-- SAF-TRACE: claims=SAF-T1111-C005; sources=SRC-openai-codex-cli,SRC-anthropic-claude-code-security,SRC-google-gemini-sandbox -->
2. **[SAF-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../../mitigations/SAF-M-69/README.md)**: Preserve explicit approval, folder-trust, and narrow tool-allowlist boundaries; do not enable bypass modes on general-purpose hosts. <!-- SAF-TRACE: claims=SAF-T1111-C005; sources=SRC-openai-codex-cli,SRC-anthropic-claude-code-security,SRC-ghsa-gemini-trust -->
3. **Patch Agent CLIs**: Apply fixed versions for sandbox, folder-trust, and command-approval vulnerabilities, while recognizing that patches do not prevent deliberate malicious use of intended capabilities. <!-- SAF-TRACE: claims=SAF-T1111-C006,SAF-T1111-C007,SAF-T1111-C008,SAF-T1111-C016; sources=SRC-ghsa-claude-command-bypass,SRC-ghsa-claude-exfil,SRC-ghsa-codex-sandbox,SRC-ghsa-gemini-trust -->

### Detective Controls

1. **Process-Lineage Monitoring**: Alert on agent-parent-to-shell-child events with unsafe-mode context and retain full command-line and session identifiers. <!-- SAF-TRACE: claims=SAF-T1111-C010,SAF-T1111-C011; sources=SRC-sysmon-15-21,SRC-openai-codex-cli,SRC-anthropic-claude-cli -->
2. **Platform Misuse Monitoring**: Correlate endpoint events with agent-provider or runner signals for sustained automation, unusual request rate, target breadth, and safety enforcement. <!-- SAF-TRACE: claims=SAF-T1111-C011; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11 -->

### Response Procedures

#### Immediate Actions

- Stop the implicated agent sessions and isolate execution hosts or runner identities while preserving logs and session state. <!-- SAF-TRACE: claims=SAF-T1111-C017; sources=SRC-anthropic-tir-2025-08,SRC-anthropic-espionage-2025-11,SRC-sysmon-15-21 -->
- Revoke credentials and network paths available to the agent context, then notify affected target owners when evidence shows target access. <!-- SAF-TRACE: claims=SAF-T1111-C017; sources=SRC-anthropic-espionage-2025-11 -->

#### Investigation Steps

- Correlate parent and child process creation, agent session mode, approvals, tool calls, target connections, and result records by host, user, and session. <!-- SAF-TRACE: claims=SAF-T1111-C010,SAF-T1111-C017; sources=SRC-sysmon-15-21,SRC-anthropic-espionage-2025-11 -->
- Validate agent-reported success against target-side evidence because autonomous agents can fabricate or overstate results. <!-- SAF-TRACE: claims=SAF-T1111-C015,SAF-T1111-C017; sources=SRC-anthropic-espionage-2025-11 -->

#### Remediation

- Remove malicious tasking and integrations, patch affected products, restore approval and sandbox policies, and rebuild compromised runner state where integrity is uncertain. <!-- SAF-TRACE: claims=SAF-T1111-C005,SAF-T1111-C017; sources=SRC-anthropic-claude-code-security,SRC-ghsa-codex-sandbox,SRC-ghsa-gemini-trust -->
- Add regression tests for prohibited unsafe modes and monitor recurrence using the same process-lineage fields. <!-- SAF-TRACE: claims=SAF-T1111-C010,SAF-T1111-C017; sources=SRC-sysmon-15-21,SRC-openai-codex-cli -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Alternative | Begins with hostile content manipulating a legitimate operator's agent rather than an adversary intentionally operating the CLI. <!-- SAF-TRACE: claims=SAF-T1111-C016; sources=SRC-anthropic-claude-code-security,SRC-ghsa-gemini-trust --> |
| [SAF-T1101: Command Injection](../SAF-T1101/README.md) | Overlapping implementation boundary | Crosses an unsafe process-launch boundary, while SAF-T1111 requires the AI agent's model-mediated planning and tool selection. <!-- SAF-TRACE: claims=SAF-T1111-C016; sources=SRC-mitre-t1059-current --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Direct | The agent CLI invokes command or script interpreters for execution, while the AI-mediated planning and orchestration layer is additional SAF-specific context. <!-- SAF-TRACE: claims=SAF-T1111-C014; sources=SRC-mitre-t1059-current,SRC-anthropic-espionage-2025-11 --> |

## References

1. **SRC-anthropic-tir-2025-08**: [Threat Intelligence Report: August 2025](https://www-cdn.anthropic.com/b2a76c6f6992465c09a6f2fce282f6c0cea8c200.pdf) — Anthropic Threat Intelligence team; GTG-2002 case study and mitigation.
2. **SRC-anthropic-espionage-2025-11**: [Disrupting the first reported AI-orchestrated cyber espionage campaign](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf) — Anthropic Threat Intelligence team; GTG-1002 architecture, lifecycle, limitations, and response.
3. **SRC-anthropic-claude-code-security**: [Claude Code Security](https://code.claude.com/docs/en/security) — Anthropic documentation team; permissions, sandboxing, and prompt-injection boundary.
4. **SRC-anthropic-claude-cli**: [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference) — Anthropic documentation team; non-interactive and permission-bypass modes.
5. **SRC-openai-codex-cli**: [Codex CLI reference](https://developers.openai.com/codex/cli/reference) — OpenAI documentation team; non-interactive execution and bypass-mode warnings.
6. **SRC-google-gemini-sandbox**: [Sandboxing in Gemini CLI](https://geminicli.com/docs/cli/sandbox/) — Google Gemini CLI team; sandbox purpose and configuration.
7. **SRC-ghsa-claude-command-bypass**: [GHSA-x56v-x2h6-7j34](https://github.com/anthropics/claude-code/security/advisories/GHSA-x56v-x2h6-7j34) — Anthropic security advisory; published by jenn-newton and credited to Elad Beber of Cymulate.
8. **SRC-ghsa-claude-exfil**: [GHSA-x5gv-jw7f-j6xj](https://github.com/anthropics/claude-code/security/advisories/GHSA-x5gv-jw7f-j6xj) — Anthropic security advisory; published by jenn-newton and credited to Elad Beber.
9. **SRC-ghsa-codex-sandbox**: [GHSA-w5fx-fh39-j5rw](https://github.com/openai/codex/security/advisories/GHSA-w5fx-fh39-j5rw) — OpenAI security advisory; published by fouad-openai and credited to Tzanko Matev of Codetracer.
10. **SRC-ghsa-gemini-trust**: [GHSA-wpqr-6v78-jr5g](https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g) — Google advisory; published by bdmorgan and credits Elad Meged of Novee Security and Dan Lisichkin of the Pillar Security research team.
11. **SRC-nvd-t1103-corpus**: [NVD CVE API](https://services.nvd.nist.gov/rest/json/cves/2.0) — NIST NVD team; current CVE records and CISA SSVC exploitation fields.
12. **SRC-cisa-kev-catalog-page-2026-09-01**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — CISA; catalog version 2026.09.01 absence check.
13. **SRC-sysmon-15-21**: [Sysmon v15.21](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — Mark Russinovich and Thomas Garnier; process, parent command-line, and correlation fields.
14. **SRC-mitre-t1059-current**: [ATT&CK T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) — MITRE ATT&CK team; execution mapping and behavioral detection context.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Independent clean-room draft with evidence packet and tested analytic | OpenAI Codex clean-room research agent |
