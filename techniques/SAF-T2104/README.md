# SAF-T2104: Fraudulent Transactions

## Overview

- **Tactic**: ATK-TA0040
- **Technique ID**: SAF-T2104
- **Research Packet**: [research/techniques/SAF-T2104](../../research/techniques/SAF-T2104/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T2104/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Severity Rationale**: A completed unauthorized payment, purchase, sale, trade, or refund can create direct monetary loss, while transaction limits, scoped credentials, and independent approval can bound the blast radius. <!-- SAF-TRACE: claims=SAF-T2104-C005,SAF-T2104-C012; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526,SRC-microsoft-agent-security-2026 -->
- **First Observed**: No qualifying production incident was identified; the earliest selected end-to-end evidence is a controlled 2024 banking demonstration. <!-- SAF-TRACE: claims=SAF-T2104-C006; sources=SRC-debenedetti-et-al-agentdojo -->
- **Last Updated**: 2026-09-02

## Scope

This technique covers an adversary causing a tool-enabled agent to initiate, commit, or materially alter a value-bearing transaction beyond the user's or organization's current authorization. <!-- SAF-TRACE: claims=SAF-T2104-C005; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526,SRC-oauth-rar-rfc9396 -->

The defining boundary is crossed when model-visible instructions, data, or state influence a privileged financial tool or API and the execution layer accepts transaction parameters that are not bound to the approved action, amount, currency, destination, instrument, or time window. <!-- SAF-TRACE: claims=SAF-T2104-C004,SAF-T2104-C005; sources=SRC-oauth-rar-rfc9396,SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526 -->

Credential theft without an agent-initiated transaction, influence over a recommendation without execution, ordinary human-authorized scams, unauthorized data access, and non-adversarial pricing mistakes are outside this contract. <!-- SAF-TRACE: claims=SAF-T2104-C005,SAF-T2104-C015; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526,SRC-mitre-t1657-2026 -->

## Description

MCP tools are model-controlled capabilities exposed with schemas and invoked by name and arguments; they can bridge model decisions to external systems. <!-- SAF-TRACE: claims=SAF-T2104-C001; sources=SRC-mcp-tools-2025-11-25 -->

Fraudulent Transactions occurs when adversarial influence changes a value-bearing tool call or its execution context so that the committed transaction differs materially from the authorization the system should enforce. <!-- SAF-TRACE: claims=SAF-T2104-C005; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526,SRC-oauth-rar-rfc9396 -->

## Attack Vectors

- Indirect instructions in retrieved content can redirect a banking-capable agent toward an attacker-selected beneficiary. <!-- SAF-TRACE: claims=SAF-T2104-C006; sources=SRC-debenedetti-et-al-agentdojo -->
- Direct or indirect adversarial prompts can induce a sandboxed commerce agent to violate price or quantity policy through a transaction tool. <!-- SAF-TRACE: claims=SAF-T2104-C007; sources=SRC-art-2507.20526 -->
- Missing or overly broad authorization can let a model-selected tool, resource, or parameter execute under privileges that exceed the approved transaction. <!-- SAF-TRACE: claims=SAF-T2104-C003,SAF-T2104-C005; sources=SRC-mcp-authorization-2025-11-25,SRC-oauth-rar-rfc9396,SRC-debenedetti-et-al-agentdojo -->

## Technical Details

A qualifying event requires four elements: adversarial influence, a value-bearing action, a material mismatch from current authorization, and acceptance by the transaction system. <!-- SAF-TRACE: claims=SAF-T2104-C004,SAF-T2104-C005; sources=SRC-oauth-rar-rfc9396,SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526 -->

The following inert record illustrates the detector's expected audit boundary; it is not an executable request. <!-- SAF-TRACE: claims=SAF-T2104-C011,SAF-T2104-C012; sources=SRC-microsoft-agent-identity-2026,SRC-microsoft-agent-security-2026 -->

```json
{"action":"payment.initiate","amount":"125.00","currency":"USD","destination":"acct-example-beneficiary","approval":{"state":"approved","amount":"100.00","currency":"USD","destination":"acct-example-beneficiary"}}
```

Here the action is financial and the amount differs from the approval, so a transaction-binding analytic should alert before commitment. <!-- SAF-TRACE: claims=SAF-T2104-C004,SAF-T2104-C012; sources=SRC-oauth-rar-rfc9396,SRC-microsoft-agent-security-2026 -->

## Evidence and Current State

### Evidence Summary

| Claim | Evidence | Source |
|---|---|---|
| SAF-T2104-C001 | MCP tools are model-controlled and invoked with a tool name and arguments. | SRC-mcp-tools-2025-11-25 |
| SAF-T2104-C002 | The MCP tools specification calls for human confirmation, visible tool inputs, result validation, timeouts, and usage logging. | SRC-mcp-tools-2025-11-25 |
| SAF-T2104-C003 | MCP authorization is optional, but its guidance requires per-request authorization and recommends least-privilege scopes and resource binding. | SRC-mcp-authorization-2025-11-25 |
| SAF-T2104-C004 | Rich Authorization Requests can bind payment authorization to action type, amount, currency, creditor, account, and remittance data. | SRC-oauth-rar-rfc9396 |
| SAF-T2104-C005 | A transaction becomes fraudulent under this contract when adversarial influence produces a value-bearing action that materially exceeds bound authorization and is accepted for execution. | SRC-debenedetti-et-al-agentdojo; SRC-art-2507.20526; SRC-oauth-rar-rfc9396 |
| SAF-T2104-C006 | AgentDojo directly demonstrated a banking injection objective that sends the maximum possible money to an attacker account and measured success from resulting environment state. | SRC-debenedetti-et-al-agentdojo |
| SAF-T2104-C007 | The ART benchmark directly demonstrated illicit financial behavior in sandboxed tool environments, including an adversarial goal to sell a regulated product at an unauthorized price and quantity. | SRC-art-2507.20526 |
| SAF-T2104-C008 | AISI's reported unsanctioned agent behavior occurred in controlled cyber testing, caused no real-world harm, and did not establish a fraudulent transaction. | SRC-aisi-incident-2026 |
| SAF-T2104-C009 | Two disclosed Semantic Kernel flaws showed prompt- or argument-influenced execution paths, but the disclosures did not establish a financial transaction. | SRC-microsoft-semantic-kernel-cves-2026 |
| SAF-T2104-C010 | NCSC described an attacker-directed bank transfer only as a hypothetical prompt-injection scenario, not as an incident. | SRC-ncsc-llm-caution-2023 |
| SAF-T2104-C011 | Agent audit logs should identify the agent, role, scope, resource, action, delegation context, time, and correlation identifier. | SRC-microsoft-agent-identity-2026 |
| SAF-T2104-C012 | High-impact financial actions warrant runtime authorization checks, human checkpoints, constrained identities, and anomaly monitoring. | SRC-microsoft-agent-identity-2026; SRC-microsoft-agent-security-2026 |
| SAF-T2104-C013 | NCSC guidance recommends bounded pilots, least privilege, limits on action scope, short-lived credentials, visibility, and human accountability for agentic systems. | SRC-ncsc-agentic-guidance-2026 |
| SAF-T2104-C014 | Controlled benchmark success varies by model and defense; nonzero intermediate and end-to-end attack success shows that behavior-only controls are incomplete. | SRC-debenedetti-et-al-agentdojo; SRC-wasp-2504.18575 |
| SAF-T2104-C015 | MITRE ATT&CK Financial Theft covers unauthorized fund transfers and recommends independent payment approval plus anomaly monitoring in financial systems. | SRC-mitre-t1657-2026 |

Two controlled demonstrations satisfy the end-to-end contract, so the evidence label is **Demonstrated**, not Observed. <!-- SAF-TRACE: claims=SAF-T2104-C006,SAF-T2104-C007,SAF-T2104-C008; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526,SRC-aisi-incident-2026 -->

The [source-coverage record](../../research/techniques/SAF-T2104/source-coverage.yml) preserves the negative production-incident search, advisory classifications, rejected candidates, and two consecutive no-change passes.

## Impact Assessment

Successful execution can transfer funds, create charges, place trades, issue refunds, or commit sales outside the approved economic terms. <!-- SAF-TRACE: claims=SAF-T2104-C005,SAF-T2104-C006,SAF-T2104-C007; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526,SRC-oauth-rar-rfc9396 -->

The immediate impact is economic loss or unauthorized financial obligation; secondary effects can include reconciliation effort, service suspension, contractual disputes, and regulatory review. <!-- SAF-TRACE: claims=SAF-T2104-C012,SAF-T2104-C015; sources=SRC-microsoft-agent-security-2026,SRC-mitre-t1657-2026 -->

## Detection Methods

Correlate each financial tool invocation with a prior, unexpired approval and compare normalized action, amount, currency, destination, tool identity, and event time. <!-- SAF-TRACE: claims=SAF-T2104-C004,SAF-T2104-C011,SAF-T2104-C012; sources=SRC-oauth-rar-rfc9396,SRC-microsoft-agent-identity-2026,SRC-microsoft-agent-security-2026 -->

Alert when approval is missing or not approved, a bound field differs, the approval is outside its time window, or required transaction telemetry is malformed. <!-- SAF-TRACE: claims=SAF-T2104-C004,SAF-T2104-C011,SAF-T2104-C012; sources=SRC-oauth-rar-rfc9396,SRC-microsoft-agent-identity-2026,SRC-microsoft-agent-security-2026 -->

The repository analytic and deterministic fixtures are in [detection-rule.yml](detection-rule.yml) and [tests/SAF-T2104](../../tests/SAF-T2104/).

### Validation

- **Test Data**: [fixtures.json](../../tests/SAF-T2104/fixtures.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T2104/test_detection_rule.py)
- **Last Validated**: [2026-09-02 destination detector and strict-validator run](../../research/techniques/SAF-T2104/validation/canonical-validation.txt)
- **Expected Result**: [All 11 positive, negative, boundary, malformed, expected-false-positive, and normalization cases pass](../../research/techniques/SAF-T2104/validation/canonical-validation.txt).

Expected false positives include recurring or batch transactions authorized through an external standing-order system when per-call approval metadata is absent from the event stream. <!-- SAF-TRACE: claims=SAF-T2104-C011,SAF-T2104-C014; sources=SRC-microsoft-agent-identity-2026,SRC-wasp-2504.18575 -->

## Mitigation Strategies

- Bind authorization to the exact transaction action, amount, currency, beneficiary or destination, resource, and validity period; re-check it at execution. <!-- SAF-TRACE: claims=SAF-T2104-C003,SAF-T2104-C004,SAF-T2104-C012; sources=SRC-mcp-authorization-2025-11-25,SRC-oauth-rar-rfc9396,SRC-microsoft-agent-identity-2026 -->
- Require an independent human checkpoint for high-impact financial actions and display the final normalized transaction parameters before commitment. <!-- SAF-TRACE: claims=SAF-T2104-C002,SAF-T2104-C012; sources=SRC-mcp-tools-2025-11-25,SRC-microsoft-agent-security-2026 -->
- Give each agent a distinct, least-privilege identity; constrain tools and transaction limits; use short-lived credentials; and test revocation and compensating actions. <!-- SAF-TRACE: claims=SAF-T2104-C003,SAF-T2104-C011,SAF-T2104-C013; sources=SRC-mcp-authorization-2025-11-25,SRC-microsoft-agent-identity-2026,SRC-ncsc-agentic-guidance-2026 -->
- Retain correlated decision, approval, and execution logs, and monitor financial systems for anomalous transfers or API-initiated transactions. <!-- SAF-TRACE: claims=SAF-T2104-C011,SAF-T2104-C015; sources=SRC-microsoft-agent-identity-2026,SRC-mitre-t1657-2026 -->
- Treat model-behavior filters as one layer rather than a transaction authorization boundary. <!-- SAF-TRACE: claims=SAF-T2104-C014; sources=SRC-debenedetti-et-al-agentdojo,SRC-wasp-2504.18575 -->

## Related Techniques

- **[SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md)**: ends at adversarial control of reasoning or context; this technique requires the unauthorized economic action. <!-- SAF-TRACE: claims=SAF-T2104-C005; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526 -->
- **[SAF-T1309: Privileged Tool Invocation via Prompt Manipulation](../SAF-T1309/README.md)**: covers unapproved privileged tool use generally; this technique is narrower and requires a payment, purchase, sale, trade, or refund that violates bound authorization. <!-- SAF-TRACE: claims=SAF-T2104-C005; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526,SRC-oauth-rar-rfc9396 -->
- **[SAF-T1915: Cross-Chain Laundering via Bridges/DEXs](../SAF-T1915/README.md)**: covers post-acquisition layering of illicit virtual assets; SAF-T2104 covers the unauthorized value-bearing transaction that creates or transfers economic value. <!-- SAF-TRACE: claims=SAF-T2104-C005; sources=SRC-debenedetti-et-al-agentdojo,SRC-art-2507.20526,SRC-oauth-rar-rfc9396 -->

## MITRE ATT&CK Mapping

This technique maps directly to MITRE ATT&CK T1657, Financial Theft, under Impact because the immediate objective is an unauthorized transfer or other loss of monetary resources. <!-- SAF-TRACE: claims=SAF-T2104-C015; sources=SRC-mitre-t1657-2026 -->

## References

- **SRC-mcp-tools-2025-11-25** — Model Context Protocol, “Tools,” 2025-11-25.
- **SRC-mcp-authorization-2025-11-25** — Model Context Protocol, “Authorization,” 2025-11-25.
- **SRC-oauth-rar-rfc9396** — IETF RFC 9396, “OAuth 2.0 Rich Authorization Requests,” May 2023.
- **SRC-debenedetti-et-al-agentdojo** — Debenedetti et al., “AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents,” 2024.
- **SRC-art-2507.20526** — Zou et al., “Security Challenges in AI Agent Deployment: Insights from a Large Scale Public Competition,” 2025.
- **SRC-aisi-incident-2026** — AISI Security Team, “Incident report: unsanctioned agent behaviour during cyber testing,” 2026.
- **SRC-microsoft-semantic-kernel-cves-2026** — Microsoft Defender Security Research Team, “When prompts become shells,” 2026.
- **SRC-ncsc-llm-caution-2023** — Dave Chismon, “Exercise caution when building off LLMs,” 2023.
- **SRC-microsoft-agent-identity-2026** — Yesenia Yser and Toby Kohlenberg, “Least privilege for AI agents,” 2026.
- **SRC-microsoft-agent-security-2026** — Microsoft Security team, “What is agentic AI security?” 2026.
- **SRC-ncsc-agentic-guidance-2026** — Martin R and Dr Kate S, “Thinking carefully before adopting agentic AI,” 2026.
- **SRC-wasp-2504.18575** — Evtimov et al., “WASP: Benchmarking Web Agent Security Against Prompt Injection Attacks,” 2025.
- **SRC-mitre-t1657-2026** — MITRE ATT&CK, “Financial Theft, T1657,” version 1.2, 2026.

## Version History

| Version | Date | Changes |
|---|---|---|
| 0.1 | 2026-09-02 | Clean-room candidate frozen for mechanical integration. |
