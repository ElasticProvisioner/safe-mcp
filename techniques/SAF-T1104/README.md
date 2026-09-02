# SAF-T1104: Over-Privileged Tool Abuse

## Overview

- **Tactic**: Execution (ATK-TA0002)
- **Technique ID**: SAF-T1104
- **Research Packet**: [research/techniques/SAF-T1104](../../research/techniques/SAF-T1104/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1104/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A successful invocation can inherit broad host, database, messaging, or workspace authority, but actual impact remains bounded by the tool identity and reachable systems. <!-- SAF-TRACE: claims=SAF-T1104-C019; sources=SRC-ghsa-3645-fxcv-hqr4,SRC-ghsa-g8r9-g2v8-jv6f,SRC-ghsa-898v-775g-777c,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **First Observed**: Not observed in a qualifying production incident; publicly demonstrated in controlled MCP research on 2025-04-07. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C013; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-cisa-kev-2026-09-01,SRC-nvd-cve-2025-32711 -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers an adversary causing an MCP or agentic system to invoke a legitimate tool outside the user's intended authority because the tool, delegated credential, local process, or downstream service can do more than the current task requires. <!-- SAF-TRACE: claims=SAF-T1104-C001,SAF-T1104-C004,SAF-T1104-C005; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07 -->

### In Scope

- A model-controlled tool call that uses excess effective scopes or resource reach to read, modify, send, or execute beyond the current task. <!-- SAF-TRACE: claims=SAF-T1104-C001,SAF-T1104-C004; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25 -->
- Abuse of a trusted MCP tool after adversarial content, a poisoned description, or another delivery mechanism has influenced the agent. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C006; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01 -->
- Excess authority supplied by OAuth scopes, a service account, a local process identity, or an intentionally powerful operation set. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C004,SAF-T1104-C008,SAF-T1104-C010; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25,SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c -->

### Out of Scope

- Prompt injection and tool poisoning considered only as delivery, before any privileged tool execution. <!-- SAF-TRACE: claims=SAF-T1104-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- Direct command, query, or path injection where excess delegated authority is not part of the vulnerable condition. <!-- SAF-TRACE: claims=SAF-T1104-C008,SAF-T1104-C009,SAF-T1104-C011; sources=SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2026-27966,SRC-ghsa-g8r9-g2v8-jv6f,SRC-nvd-cve-2026-29783,SRC-ghsa-wr2q-46pg-f228,SRC-nvd-cve-2025-53097 -->
- Privileged administration that remains within explicit, current approval and the recorded task intent. <!-- SAF-TRACE: claims=SAF-T1104-C015,SAF-T1104-C016; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-agentdojo-2024,SRC-anthropic-claude-code-security -->

### Distinguishing Characteristics

The decisive observable is not merely malicious text or a dangerous tool. It is an executed tool call where effective authority exceeds the operation's required authority and the action conflicts with task intent or lacks a valid approval. <!-- SAF-TRACE: claims=SAF-T1104-C006,SAF-T1104-C015; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28 -->

## Description

MCP tools are model-controlled interfaces to external systems. The specification permits authorization-sensitive tool discovery, requires server-side access controls, and recommends that clients expose sensitive inputs and retain a human denial path. <!-- SAF-TRACE: claims=SAF-T1104-C001,SAF-T1104-C002; sources=SRC-mcp-tools-2026-07-28 -->

Over-Privileged Tool Abuse occurs when those controls leave a gap between the narrow operation a user intends and the broader authority available at execution. Broad scopes, shared service credentials, unsandboxed local identities, or unrestricted operations turn a manipulated call into a higher-impact action without a separate privilege-acquisition step. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C004,SAF-T1104-C005; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07 -->

The defining behavior has been demonstrated in controlled MCP environments, but the reviewed corpus does not establish a qualifying production breach. Direct vulnerabilities show concrete variants in code-execution, shell, database, and workspace tools; they remain vulnerability or demonstration evidence unless a primary incident source documents malicious production use. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C008,SAF-T1104-C009,SAF-T1104-C010,SAF-T1104-C011,SAF-T1104-C013; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c,SRC-nvd-cve-2025-53097,SRC-ghsa-wr2q-46pg-f228,SRC-cisa-kev-2026-09-01,SRC-nvd-cve-2025-32711 -->

## Attack Vectors

- **Primary Vector**: Adversarially influenced planning invokes a trusted high-risk tool whose credential or runtime authority exceeds the current task. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C007; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-agentdojo-2024 -->
- **Secondary Vectors**: A poisoned tool description redirects another server's tool, or a safety classifier incorrectly treats a privileged operation as benign. <!-- SAF-TRACE: claims=SAF-T1104-C006,SAF-T1104-C009; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f -->
- **Affected Components**: MCP host, client, server, tool-call approval layer, delegated credential, local process, and downstream resource. <!-- SAF-TRACE: claims=SAF-T1104-C001,SAF-T1104-C003,SAF-T1104-C004; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25 -->
- **Trust Boundary Crossed**: Task-scoped user intent to broader effective tool authority. <!-- SAF-TRACE: claims=SAF-T1104-C004,SAF-T1104-C005; sources=SRC-mcp-security-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07 -->

## Technical Details

### Prerequisites

- The agent can invoke a tool that reaches data, actions, or execution beyond what the current task needs. <!-- SAF-TRACE: claims=SAF-T1104-C001,SAF-T1104-C004; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25 -->
- Adversarial input, a malicious server, or flawed safety classification can influence the call or its arguments. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C006,SAF-T1104-C009; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f -->
- Operation-specific authorization or approval does not reject the action before execution. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C009,SAF-T1104-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f,SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07 -->

### Attack Flow

1. **Setup**: The adversary places influence in content, tool metadata, or command text that the agent will process. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C006,SAF-T1104-C009; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f -->
2. **Selection**: The model chooses a legitimate tool and supplies attacker-aligned arguments. <!-- SAF-TRACE: claims=SAF-T1104-C001,SAF-T1104-C007; sources=SRC-mcp-tools-2026-07-28,SRC-agentdojo-2024 -->
3. **Authorization**: A broad token, service identity, local process, or unrestricted operation set satisfies the call without narrow step-up authorization. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C004,SAF-T1104-C008,SAF-T1104-C010; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25,SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c -->
4. **Execution**: The server or local tool performs a read, write, send, or code-execution action beyond recorded task intent. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C008,SAF-T1104-C009,SAF-T1104-C010; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c -->
5. **Objective**: The adversary obtains the immediate unauthorized operation; later collection, exfiltration, persistence, or impact is follow-on activity. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C019; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-ghsa-3645-fxcv-hqr4,SRC-ghsa-g8r9-g2v8-jv6f,SRC-ghsa-898v-775g-777c -->

### Example Scenario

An assistant is asked to summarize a synthetic support record. Untrusted record text influences it to call a trusted messaging tool, and a broad service credential permits sending the summary plus unrelated record data to `audit@example.invalid`; the excess send authority and task mismatch, rather than the injected text alone, define this technique. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C006; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-invariant-tpa-2025-04-01 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1104-C001 | MCP tools are model-controlled and should retain a user denial path. | Research-Derived | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Interaction UI is not mandated. |
| SAF-T1104-C002 | Tool visibility may depend on authorization; access controls and logging are required or recommended. | Research-Derived | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | No standard audit schema. |
| SAF-T1104-C003 | MCP supports least-privilege initial scopes and operation-specific step-up. | Research-Derived | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); SRC-rfc8707: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Authorization is optional and stdio differs. |
| SAF-T1104-C004 | Broad scopes expand blast radius and obscure operation intent. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Guidance, not prevalence data. |
| SAF-T1104-C005 | Trusted-tool abuse was reproduced in controlled WhatsApp MCP experiments. | Demonstrated | SRC-invariant-whatsapp-mcp-2025-04-07: [Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | Not a production incident. |
| SAF-T1104-C006 | Tool poisoning is delivery; privileged execution is separable. | Demonstrated | SRC-invariant-tpa-2025-04-01: [Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks); SRC-invariant-whatsapp-mcp-2025-04-07: [WhatsApp MCP](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | SAF analytic distinction. |
| SAF-T1104-C007 | Stateful benchmarks reproduce attacker-directed tool calls; evaluated detectors do not eliminate them. | Demonstrated | SRC-agentdojo-2024: [AgentDojo](https://arxiv.org/html/2406.13352) | Synthetic environments and time-sensitive model results. |
| SAF-T1104-C008 | Langflow exposed a dangerous Python REPL tool; 1.8.0 fixed CVE-2026-27966. | Demonstrated | SRC-nvd-cve-2026-27966: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-27966); SRC-ghsa-3645-fxcv-hqr4: [Vendor advisory](https://github.com/langflow-ai/langflow/security/advisories/GHSA-3645-fxcv-hqr4) | Affected-range display conflict; no production exploitation shown. |
| SAF-T1104-C009 | Copilot CLI's read-only classification could be bypassed; 0.0.423 fixed CVE-2026-29783. | Demonstrated | SRC-nvd-cve-2026-29783: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-29783); SRC-ghsa-g8r9-g2v8-jv6f: [Vendor advisory](https://github.com/github/copilot-cli/security/advisories/GHSA-g8r9-g2v8-jv6f) | Proof of concept, not a production incident. |
| SAF-T1104-C010 | Neuron's unrestricted MySQLWriteTool made broad database privilege dangerous; 2.8.12 fixed CVE-2025-67510. | Research-Derived | SRC-nvd-cve-2025-67510: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-67510); SRC-ghsa-898v-775g-777c: [Vendor advisory](https://github.com/neuron-core/neuron-ai/security/advisories/GHSA-898v-775g-777c) | No production exploitation shown. |
| SAF-T1104-C011 | Roo Code could read beyond its workspace and trigger an unapproved network request; 3.20.3 fixed CVE-2025-53097. | Research-Derived | SRC-nvd-cve-2025-53097: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-53097); SRC-ghsa-wr2q-46pg-f228: [Vendor advisory](https://github.com/RooCodeInc/Roo-Code/security/advisories/GHSA-wr2q-46pg-f228) | Potential path; CISA-ADP recorded exploitation none. |
| SAF-T1104-C012 | Continue CLI's unattended Bash policy could permit destructive prompt-driven operations. | Research-Derived | SRC-nvd-cve-2026-76072: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76072); SRC-vulncheck-cve-2026-76072: [VulnCheck](https://www.vulncheck.com/advisories/continue-cli-through-incomplete-destructive-command-denylist-in-headless-and-auto-mode) | No fixed version or production exploitation established. |
| SAF-T1104-C013 | No direct production incident was found in the reviewed corpus. | Research-Derived | SRC-cisa-kev-2026-09-01: [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json); SRC-invariant-whatsapp-mcp-2025-04-07: [Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited); SRC-nvd-cve-2025-32711: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32711) | Date- and corpus-bounded absence claim. |
| SAF-T1104-C014 | Detection needs tool, user, parameter, authorization, approval, and time context. | Research-Derived | SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); SRC-mcp-security-2025-11-25: [MCP Security](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices); SRC-owasp-mcp-security: [OWASP MCP Security](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) | Normalized fields are proposed. |
| SAF-T1104-C015 | Excess scope plus intent or approval mismatch is a high-confidence correlation. | Research-Derived | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); SRC-invariant-whatsapp-mcp-2025-04-07: [Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | Intent matching is local and fallible. |
| SAF-T1104-C016 | Legitimate administration can look similar; detector-only defenses remain incomplete. | Research-Derived | SRC-agentdojo-2024: [AgentDojo](https://arxiv.org/html/2406.13352); SRC-anthropic-claude-code-security: [Claude Code Security](https://code.claude.com/docs/en/security) | False-positive rate requires local measurement. |
| SAF-T1104-C017 | Least privilege, step-up, sandboxing, and explicit approval constrain the technique. | Research-Derived | SRC-mcp-authorization-2026-07-28: [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); SRC-mcp-security-2025-11-25: [MCP Security](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices); SRC-anthropic-claude-code-security: [Claude Code Security](https://code.claude.com/docs/en/security) | Controls do not prove intent. |
| SAF-T1104-C018 | Response should contain the tool path, constrain credentials, preserve records, and verify downstream state. | Research-Derived | SRC-mcp-security-2025-11-25: [MCP Security](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices); SRC-nist-sp800-207: [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) | Recovery is system-specific. |
| SAF-T1104-C019 | Broad tool authority can affect confidentiality, integrity, and availability across connected systems. | Demonstrated | SRC-ghsa-3645-fxcv-hqr4, SRC-ghsa-g8r9-g2v8-jv6f, SRC-ghsa-898v-775g-777c, SRC-invariant-whatsapp-mcp-2025-04-07 | Environment bounds impact. |
| SAF-T1104-C020 | ATT&CK T1106 is analogous, not direct. | Research-Derived | SRC-mitre-attack-t1106: [MITRE ATT&CK](https://attack.mitre.org/techniques/T1106/); SRC-mcp-tools-2026-07-28: [MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | T1106 is native-OS-API specific. |

### Current State

- **Affected Environments**: Systems where model-controlled tools use broad OAuth scopes, service credentials, local user authority, unrestricted interpreters, or similarly expansive operation sets. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C004,SAF-T1104-C008,SAF-T1104-C010; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25,SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c -->
- **Known Exploitation**: Controlled demonstrations and disclosed vulnerabilities exist; no qualifying malicious production use was identified. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C008,SAF-T1104-C009,SAF-T1104-C010,SAF-T1104-C011,SAF-T1104-C013; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c,SRC-nvd-cve-2025-53097,SRC-ghsa-wr2q-46pg-f228,SRC-cisa-kev-2026-09-01,SRC-nvd-cve-2025-32711 -->
- **Available Protections**: Narrow initial scopes, step-up authorization, scope-sensitive tool discovery, sandboxing, and explicit approval reduce exposure. <!-- SAF-TRACE: claims=SAF-T1104-C002,SAF-T1104-C003,SAF-T1104-C017; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25,SRC-anthropic-claude-code-security -->
- **Residual Risk**: A broad credential, unsafe local identity, flawed classifier, or misleading approval can still authorize an attacker-aligned call. <!-- SAF-TRACE: claims=SAF-T1104-C004,SAF-T1104-C005,SAF-T1104-C009,SAF-T1104-C016; sources=SRC-mcp-security-2025-11-25,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f,SRC-agentdojo-2024,SRC-anthropic-claude-code-security -->

### Known Breaches and Vulnerabilities

No qualifying direct production breach was identified in the reviewed corpus as of 2026-09-01. The selected examples are controlled demonstrations or direct vulnerabilities, not production incidents. <!-- SAF-TRACE: claims=SAF-T1104-C013; sources=SRC-cisa-kev-2026-09-01,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2025-32711 -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| WhatsApp MCP controlled experiments | 2025-04-07/09; Cursor or Claude Desktop with WhatsApp MCP | Chat-history or contact disclosure through trusted messaging tools; research controls recommended | Direct demonstration of trusted-tool execution beyond user intent <!-- SAF-TRACE: claims=SAF-T1104-C005; sources=SRC-invariant-whatsapp-mcp-2025-04-07 --> | Controlled experiment, not production exploitation |
| CVE-2026-27966 / GHSA-3645-fxcv-hqr4 | 2026-02-25/26; Langflow CSV Agent before the recorded 1.8.0 fix | Prompt-driven Python and OS command execution; fixed in 1.8.0 | Direct vulnerability with proof of concept: an unnecessarily exposed interpreter amplified the agent's authority <!-- SAF-TRACE: claims=SAF-T1104-C008; sources=SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4 --> | Affected-range display conflict; no production incident |
| CVE-2026-29783 / GHSA-g8r9-g2v8-jv6f | 2026-03-06; GitHub Copilot CLI through 0.0.422 | Hidden command execution could bypass write approval; fixed in 0.0.423 | Direct vulnerability and proof of concept at the privileged shell-tool approval boundary <!-- SAF-TRACE: claims=SAF-T1104-C009; sources=SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f --> | Potential impact, not observed production exploitation |
| CVE-2025-67510 / GHSA-898v-775g-777c | 2025-12-09/10; Neuron AI through 2.8.11 with MySQLWriteTool and broad DB privilege | Destructive or privilege-related SQL was possible; fixed in 2.8.12 | Direct vulnerability: unrestricted write-tool semantics plus excess database privilege <!-- SAF-TRACE: claims=SAF-T1104-C010; sources=SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c --> | No production exploitation or independent end-to-end reproduction established |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Broad messaging, workspace, or host-read authority can disclose unrelated data; impact is limited by the effective identity and reachable resources. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C011,SAF-T1104-C019; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-nvd-cve-2025-53097,SRC-ghsa-wr2q-46pg-f228,SRC-ghsa-3645-fxcv-hqr4,SRC-ghsa-g8r9-g2v8-jv6f,SRC-ghsa-898v-775g-777c --> |
| Integrity | High | Unrestricted shell, interpreter, or database operations can alter host or application state. <!-- SAF-TRACE: claims=SAF-T1104-C008,SAF-T1104-C009,SAF-T1104-C010,SAF-T1104-C019; sources=SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2026-29783,SRC-ghsa-g8r9-g2v8-jv6f,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c,SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| Availability | High | Code, shell, or database authority can disrupt the affected service when destructive operations are reachable. <!-- SAF-TRACE: claims=SAF-T1104-C008,SAF-T1104-C010,SAF-T1104-C012,SAF-T1104-C019; sources=SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c,SRC-nvd-cve-2026-76072,SRC-vulncheck-cve-2026-76072,SRC-ghsa-g8r9-g2v8-jv6f,SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| Scope | Multi-System | A single agent may bridge multiple servers and downstream services, but isolation and per-server credentials constrain propagation. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C017,SAF-T1104-C019; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2025-11-25,SRC-anthropic-claude-code-security,SRC-ghsa-3645-fxcv-hqr4,SRC-ghsa-g8r9-g2v8-jv6f,SRC-ghsa-898v-775g-777c --> |

### Severity Conditions

- **Severity increases when**: the tool holds wildcard scopes, broad service credentials, unrestricted interpreters, sensitive data access, cross-server reach, or unattended approval. <!-- SAF-TRACE: claims=SAF-T1104-C004,SAF-T1104-C008,SAF-T1104-C010,SAF-T1104-C019; sources=SRC-mcp-security-2025-11-25,SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c,SRC-ghsa-g8r9-g2v8-jv6f,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Severity decreases when**: scopes are operation-specific, credentials are isolated, paths and networks are sandboxed, and sensitive calls require current approval. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25,SRC-anthropic-claude-code-security -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP or agent tool-call audit | Discovery, approval, execution, result | timestamp, session_id, task_id, actor_id, server_id, tool_name, action, resource, parameters, decision, tool_risk, outcome | Preserve correlation IDs and redact secrets without removing authorization context. <!-- SAF-TRACE: claims=SAF-T1104-C014; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security --> |
| Authorization and policy log | Scope issue, step-up, grant, deny, token use | credential_id, audience, effective_scopes, required_scopes, approval_state, approval_id, intent_match, elevation_id | Normalize per-operation scope and approval records to the tool-call session. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C014,SAF-T1104-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security,SRC-invariant-whatsapp-mcp-2025-04-07 --> |

### Indicators of Compromise (IoCs)

- No durable universal IoC is known; this technique is identified through authorization and behavior context rather than a fixed artifact. <!-- SAF-TRACE: claims=SAF-T1104-C014,SAF-T1104-C015; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security,SRC-mcp-authorization-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07 -->

### Behavioral Indicators

- A high-risk executed call where `effective_scopes` contains permissions absent from `required_scopes`. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- An excess-authority call paired with `intent_match=false` or an absent, denied, or stale approval. <!-- SAF-TRACE: claims=SAF-T1104-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- Cross-server data movement, newly used high-risk tools, or administrator-level actions that diverge from the recorded task can raise confidence. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C014; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect executed high-risk tool calls that combine excess effective authority with an intent or approval gap. <!-- SAF-TRACE: claims=SAF-T1104-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Rule Status**: Test. <!-- SAF-TRACE: claims=SAF-T1104-C014,SAF-T1104-C015; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security,SRC-mcp-authorization-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Detection Logic**: Require an executed MCP tool call, high or critical risk, at least one scope beyond the operation's required set, and either mismatched intent or approval that is absent, denied, or stale. <!-- SAF-TRACE: claims=SAF-T1104-C015; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07 -->
- **Correlation Window**: Join the authorization, approval, and tool records by session, task, and elevation identifiers for the life of the attempted operation. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C014; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security -->
- **Known False Positives**: Emergency or administrative work using intentionally broad credentials when approval or task records are incomplete. <!-- SAF-TRACE: claims=SAF-T1104-C016; sources=SRC-agentdojo-2024,SRC-anthropic-claude-code-security -->
- **Known Limitations**: The rule cannot evaluate omitted scopes, absent task context, misclassified tool risk, or malicious actions that remain inside a broadly worded approval. <!-- SAF-TRACE: claims=SAF-T1104-C014,SAF-T1104-C015,SAF-T1104-C016; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security,SRC-mcp-authorization-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-agentdojo-2024,SRC-anthropic-claude-code-security -->
- **Tuning Guidance**: Define required scopes per tool and action, fail closed on missing approval for sensitive operations, and allowlist only reviewed administrative workflows with complete task records. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C016,SAF-T1104-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-agentdojo-2024,SRC-anthropic-claude-code-security,SRC-mcp-security-2025-11-25 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json)
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py)
- **Expected Result**: [Eight positive, negative, boundary, malformed, and legitimate-lookalike cases pass](test-logs.json)
- **Last Validated**: [2026-09-01](test-logs.json)
- **Feasibility Waiver**: [None; deterministic representative cases pass](test-logs.json)

## Mitigation Strategies

### Preventive Controls

1. Request only the scopes required for basic operation and use per-operation step-up challenges for privileged actions. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C017; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25,SRC-anthropic-claude-code-security -->
2. Use per-server credentials and restrict each tool's files, network, database objects, and operation set to its documented purpose. <!-- SAF-TRACE: claims=SAF-T1104-C004,SAF-T1104-C017; sources=SRC-mcp-security-2025-11-25,SRC-mcp-authorization-2026-07-28,SRC-anthropic-claude-code-security -->
3. Require explicit, complete approval for sensitive calls and show the actual destination, action, and arguments rather than only a tool name. <!-- SAF-TRACE: claims=SAF-T1104-C001,SAF-T1104-C005,SAF-T1104-C017; sources=SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2025-11-25,SRC-anthropic-claude-code-security -->
4. Sandbox local tools and disable unrestricted interpreters or write APIs unless a narrow, reviewed workflow requires them. <!-- SAF-TRACE: claims=SAF-T1104-C008,SAF-T1104-C010,SAF-T1104-C017; sources=SRC-nvd-cve-2026-27966,SRC-ghsa-3645-fxcv-hqr4,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c,SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2025-11-25,SRC-anthropic-claude-code-security -->

### Detective Controls

1. Log every tool invocation and scope elevation with task, actor, server, parameters, approval, and outcome context. <!-- SAF-TRACE: claims=SAF-T1104-C014; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security -->
2. Alert on new high-risk tools, excess effective scopes, cross-server data flows, and privileged actions that disagree with task or approval records. <!-- SAF-TRACE: claims=SAF-T1104-C005,SAF-T1104-C015; sources=SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28 -->
3. Test the authorization policy with malicious, benign, boundary, and legitimate administrative cases; do not treat a prompt-injection detector as a complete control. <!-- SAF-TRACE: claims=SAF-T1104-C007,SAF-T1104-C016; sources=SRC-agentdojo-2024,SRC-anthropic-claude-code-security -->

### Response Procedures

#### Immediate Actions

- Stop the implicated session or tool path and temporarily disable the broad credential or dangerous operation. <!-- SAF-TRACE: claims=SAF-T1104-C017,SAF-T1104-C018; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-security-2025-11-25,SRC-anthropic-claude-code-security,SRC-nist-sp800-207 -->
- Revoke, rotate, or down-scope affected tokens and service credentials before allowing the workflow to resume. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C018; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-mcp-security-2025-11-25,SRC-nist-sp800-207 -->

#### Investigation Steps

- Preserve tool-call, approval, authorization, endpoint, and downstream service records under the same session and task correlation identifiers. <!-- SAF-TRACE: claims=SAF-T1104-C014,SAF-T1104-C018; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-security-2025-11-25,SRC-owasp-mcp-security,SRC-nist-sp800-207 -->
- Compare the executed action and reached resources with the recorded user task, displayed approval, required scopes, and resulting state. <!-- SAF-TRACE: claims=SAF-T1104-C015,SAF-T1104-C018; sources=SRC-mcp-authorization-2026-07-28,SRC-mcp-tools-2026-07-28,SRC-invariant-whatsapp-mcp-2025-04-07,SRC-mcp-security-2025-11-25,SRC-nist-sp800-207 -->

#### Remediation

- Replace broad credentials or operations with task-specific scopes, constrained APIs, and sandboxed identities. <!-- SAF-TRACE: claims=SAF-T1104-C003,SAF-T1104-C010,SAF-T1104-C017,SAF-T1104-C018; sources=SRC-mcp-authorization-2026-07-28,SRC-rfc8707,SRC-nvd-cve-2025-67510,SRC-ghsa-898v-775g-777c,SRC-mcp-security-2025-11-25,SRC-anthropic-claude-code-security,SRC-nist-sp800-207 -->
- Verify downstream data and system state, restore altered resources, and add the observed sequence to authorization and detection regression tests. <!-- SAF-TRACE: claims=SAF-T1104-C007,SAF-T1104-C018; sources=SRC-agentdojo-2024,SRC-mcp-security-2025-11-25,SRC-nist-sp800-207 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Prerequisite or co-occurring | Changes agent instructions; SAF-T1104 requires subsequent execution through authority broader than the task. <!-- SAF-TRACE: claims=SAF-T1104-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 --> |
| [SAF-T1001: Tool Poisoning Attack (TPA)](../SAF-T1001/README.md) | Prerequisite or co-occurring | Corrupts discovery metadata; SAF-T1104 covers the over-authorized trusted-tool call that follows. <!-- SAF-TRACE: claims=SAF-T1104-C006; sources=SRC-invariant-tpa-2025-04-01,SRC-invariant-whatsapp-mcp-2025-04-07 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1106](https://attack.mitre.org/techniques/T1106/) | Native API | Analogous | Both concern adversary use of an authorized interface to execute behavior, but T1106 is limited to native OS APIs and does not directly describe MCP application tools. <!-- SAF-TRACE: claims=SAF-T1104-C020; sources=SRC-mitre-attack-t1106,SRC-mcp-tools-2026-07-28 --> |

## References

1. **SRC-mcp-tools-2026-07-28**: [MCP Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) — Model Context Protocol contributors; tool control, authorization-sensitive discovery, access control, approval, and logging.
2. **SRC-mcp-authorization-2026-07-28**: [MCP Authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — Model Context Protocol contributors; least-privilege scopes and step-up authorization.
3. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — Model Context Protocol contributors; broad-scope risk, sandboxing, and elevation logging.
4. **SRC-rfc8707**: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) — Brian Campbell, John Bradley, and Hannes Tschofenig; resource and scope binding.
5. **SRC-invariant-whatsapp-mcp-2025-04-07**: [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) — Luca Beurer-Kellner and Marc Fischer; controlled end-to-end MCP demonstrations.
6. **SRC-invariant-tpa-2025-04-01**: [MCP Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) — Luca Beurer-Kellner and Marc Fischer; delivery and cross-server shadowing experiments.
7. **SRC-agentdojo-2024**: [AgentDojo](https://arxiv.org/html/2406.13352) — Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr; stateful tool-use security evaluation.
8. **SRC-nvd-cve-2026-27966**: [NVD CVE-2026-27966](https://nvd.nist.gov/vuln/detail/CVE-2026-27966) — Langflow CSV Agent record and vendor-advisory provenance.
9. **SRC-ghsa-3645-fxcv-hqr4**: [Langflow advisory](https://github.com/langflow-ai/langflow/security/advisories/GHSA-3645-fxcv-hqr4) — published by Empreiteiro; reporter weblover12, analyst andifilhohub, remediation developer Adam-Aghili.
10. **SRC-nvd-cve-2026-29783**: [NVD CVE-2026-29783](https://nvd.nist.gov/vuln/detail/CVE-2026-29783) — GitHub Copilot CLI record and vendor-advisory provenance.
11. **SRC-ghsa-g8r9-g2v8-jv6f**: [GitHub Copilot CLI advisory](https://github.com/github/copilot-cli/security/advisories/GHSA-g8r9-g2v8-jv6f) — published by andyfeller; shell safety-classification bypass and fix.
12. **SRC-nvd-cve-2025-67510**: [NVD CVE-2025-67510](https://nvd.nist.gov/vuln/detail/CVE-2025-67510) — Neuron MySQLWriteTool record and vendor-advisory provenance.
13. **SRC-ghsa-898v-775g-777c**: [Neuron AI advisory](https://github.com/neuron-core/neuron-ai/security/advisories/GHSA-898v-775g-777c) — published by ilvalerione; finder siewer.
14. **SRC-nvd-cve-2025-53097**: [NVD CVE-2025-53097](https://nvd.nist.gov/vuln/detail/CVE-2025-53097) — Roo Code scope-failure record.
15. **SRC-ghsa-wr2q-46pg-f228**: [Roo Code advisory](https://github.com/RooCodeInc/Roo-Code/security/advisories/GHSA-wr2q-46pg-f228) — published by mrubens; reporter MaccariTA.
16. **SRC-nvd-cve-2026-76072**: [NVD CVE-2026-76072](https://nvd.nist.gov/vuln/detail/CVE-2026-76072) — Continue CLI unattended destructive-operation record.
17. **SRC-vulncheck-cve-2026-76072**: [VulnCheck advisory](https://www.vulncheck.com/advisories/continue-cli-through-incomplete-destructive-command-denylist-in-headless-and-auto-mode) — George Chen; originating CNA description.
18. **SRC-nvd-cve-2025-32711**: [NVD CVE-2025-32711](https://nvd.nist.gov/vuln/detail/CVE-2025-32711) — adjacent M365 Copilot information-disclosure record.
19. **SRC-cisa-kev-2026-09-01**: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — CISA Cybersecurity Division; exploitation-status cross-check.
20. **SRC-owasp-mcp-security**: [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) — OWASP contributors; operational least-privilege and monitoring guidance.
21. **SRC-anthropic-claude-code-security**: [Claude Code Security](https://code.claude.com/docs/en/security) — Anthropic Claude Code team; current permission and sandbox implementation pattern.
22. **SRC-nist-sp800-207**: [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) — Scott Rose, Oliver Borchert, Stu Mitchell, and Sean Connelly; explicit authorization boundaries.
23. **SRC-mitre-attack-t1106**: [MITRE ATT&CK T1106](https://attack.mitre.org/techniques/T1106/) — contributor credits listed by MITRE; analogous native-API mapping.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Clean-room research, authoring, detection, and evidence packet | OpenAI Codex (/root/cleanroom_saf_t1104) |
