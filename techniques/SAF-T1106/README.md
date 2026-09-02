# SAF-T1106: Autonomous Loop Exploit

## Overview

Autonomous Loop Exploit is adversarial influence over an agent's input, retrieved content, tool result, or tool-facing message that causes a model/tool/workflow feedback path to repeat without an effective external bound. The immediate objective is to keep autonomous execution running beyond task-normal work, multiplying model, tool, context, time, or budget consumption and sometimes repeating external effects. <!-- SAF-TRACE: claims=SAF-T1106-C001,SAF-T1106-C002,SAF-T1106-C003; sources=SRC-zhou-2026 -->

- **Technique ID**: SAF-T1106
- **Tactic**: Execution (ATK-TA0002)
- **Research Packet**: [research/techniques/SAF-T1106/](../../research/techniques/SAF-T1106/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1106/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Last Updated**: 2026-09-01

**Evidence status:** Demonstrated. Controlled studies produced end-to-end resource amplification in tool-using agents; repository analysis separately confirmed structurally unbounded agentic feedback paths, but no qualifying production breach was found in the reviewed current sources. <!-- SAF-TRACE: claims=SAF-T1106-C001,SAF-T1106-C002,SAF-T1106-C003,SAF-T1106-C014; sources=SRC-zhou-2026 -->

## Scope

The security boundary is the handoff from untrusted or attacker-influenced content into an autonomous orchestrator's continuation decision. In scope, that influence repeatedly reaches model calls, tools, agent handoffs, or workflow transitions while termination, time, token, cost, or iteration controls are absent or ineffective. <!-- SAF-TRACE: claims=SAF-T1106-C001,SAF-T1106-C003,SAF-T1106-C004; sources=SRC-zhou-2026 -->

This technique excludes a single expensive inference with no autonomous re-entry, direct high-volume request flooding, ordinary bounded iteration, deterministic parser recursion, and unauthorized tool use whose objective is the action itself rather than continued repetition. <!-- SAF-TRACE: claims=SAF-T1106-C015; sources=SRC-hou-ial-2026 -->

## Description

Tool-using agents commonly alternate between model decisions and tool results. MCP describes tools as model-controlled, lets clients invoke them with `tools/call`, and permits actionable tool errors to be returned to the model for correction; those legitimate feedback paths become the execution surface when hostile content biases the next-step decision toward continued calls. [SRC-mcp-tools-2026-07-28] <!-- SAF-TRACE: claims=SAF-T1106-C004,SAF-T1106-C005; sources=SRC-mcp-tools-2026-07-28 -->

The exploit is not defined by any particular prompt string. It is defined by attacker influence reaching an autonomous continuation gate and producing repeated costly or state-changing execution without an effective independent bound. <!-- SAF-TRACE: claims=SAF-T1106-C001,SAF-T1106-C002,SAF-T1106-C003; sources=SRC-zhou-2026 -->

## Attack Vectors

- A malicious tool or MCP server returns plausible follow-up instructions that induce another tool call, then continues the chain after each result. <!-- SAF-TRACE: claims=SAF-T1106-C001; sources=SRC-zhou-2026 -->
- Untrusted task, document, webpage, or environment content causes repeated planning or tool activity while the agent continues to judge the task incomplete. <!-- SAF-TRACE: claims=SAF-T1106-C002,SAF-T1106-C003; sources=SRC-li-otora-2026 -->
- A completion signal is withheld, reset, or made to appear just out of reach so completed work or a workflow transition is repeatedly revisited. <!-- SAF-TRACE: claims=SAF-T1106-C003,SAF-T1106-C013; sources=SRC-hou-ial-2026 -->

## Technical Details

The minimal attack path is: attacker-controlled content enters a permitted observation channel; the agent treats it as relevant to its next decision; the agent invokes a model, tool, subagent, or workflow step; the resulting observation re-enters the decision context; and the cycle remains reachable after each iteration. Exploitation requires the cycle to lack an effective independent stop condition or for the attacker to keep the apparent completion condition unsatisfied. <!-- SAF-TRACE: claims=SAF-T1106-C001,SAF-T1106-C002,SAF-T1106-C003; sources=SRC-zhou-2026 -->

A safe inert illustration is a test agent repeatedly calling a local `status.example.invalid` lookup whose fixture returns “verification pending” while the orchestrator lacks a call cap. The example contains no live endpoint or destructive action; it demonstrates re-entry, not a deployable payload. <!-- SAF-TRACE: claims=SAF-T1106-C016; sources=SRC-hou-ial-2026 -->

## Evidence and Current State

| Example | Relationship | Result | Limitation |
|---|---|---|---|
| Zhou et al., *Beyond Max Tokens* [SRC-zhou-2026] | Direct demonstration | A controlled MCP simulator produced multi-turn tool-call chains with up to 658.10× token amplification and reduced throughput while preserving task success. <!-- SAF-TRACE: claims=SAF-T1106-C001; sources=SRC-zhou-2026 --> | The work used controlled emulation, selected single-tool/single-turn benchmark subsets, and no real external actions. <!-- SAF-TRACE: claims=SAF-T1106-C001; sources=SRC-zhou-2026 --> |
| Li et al., *OTora* [SRC-li-otora-2026] | Direct demonstration | Two-stage triggers increased reasoning time by as much as 10.8× across agent benchmarks while often retaining answer correctness. <!-- SAF-TRACE: claims=SAF-T1106-C002; sources=SRC-li-otora-2026 --> | The study used research benchmarks and reports a small evaluation set for defense tuning; it does not establish production compromise. <!-- SAF-TRACE: claims=SAF-T1106-C002,SAF-T1106-C011; sources=SRC-li-otora-2026 --> |
| Hou et al., *When Agents Do Not Stop* [SRC-hou-ial-2026] | Direct vulnerability research | Static analysis plus manual review confirmed 68 unbounded agentic-loop findings across 47 projects. <!-- SAF-TRACE: claims=SAF-T1106-C003; sources=SRC-hou-ial-2026 --> | Findings were structurally confirmed, not dynamically exploited in production, and the analyzer can produce false positives and false negatives. <!-- SAF-TRACE: claims=SAF-T1106-C003; sources=SRC-hou-ial-2026 --> |

Current searches of CISA KEV, NVD, vendor bulletins, and incident-status sources found no qualifying public production breach. Several disclosed infinite-loop or resource-exhaustion defects were excluded because they were deterministic parser, recursion, or user-composed workflow failures rather than attacker-driven autonomous continuation. <!-- SAF-TRACE: claims=SAF-T1106-C014,SAF-T1106-C015; sources=SRC-ms-unbounded-dos -->

## Impact Assessment

**Severity:** High. A single accepted input can multiply token, model, tool, latency, and downstream-service consumption, degrading availability and increasing cost; cycles that revisit state-changing tools can also repeat external effects. Severity depends on reachable autonomy, tool expense and privilege, and the absence or weakness of hard bounds. <!-- SAF-TRACE: claims=SAF-T1106-C001,SAF-T1106-C002,SAF-T1106-C003,SAF-T1106-C013; sources=SRC-zhou-2026 -->

**First observed:** Not observed in a qualifying production incident as of 2026-09-01; the evidence base is controlled demonstration and vulnerability research. <!-- SAF-TRACE: claims=SAF-T1106-C014; sources=SRC-ms-unbounded-dos -->

## Detection Methods

Correlate orchestrator events by run or session and alert on a bounded window containing repeated tool invocations with recurring normalized arguments or unchanged progress fingerprints while completion remains nonterminal. Enrich the signal with cumulative tokens, elapsed time, cost, retries, and downstream latency; keep tool identity, parameters, results, agent identity, and decision context for investigation. [SRC-ms-agent-responsibility] [SRC-ms-agentic-rag] <!-- SAF-TRACE: claims=SAF-T1106-C008,SAF-T1106-C009,SAF-T1106-C010; sources=SRC-ms-agent-responsibility -->

Where available, MCP deployments can also retain the documented `Mcp-Method`, `Mcp-Name`, and W3C trace-context fields as correlation aids; the analytic does not depend on those exact names. [SRC-mcp-rc-20260728] <!-- SAF-TRACE: claims=SAF-T1106-C007; sources=SRC-mcp-rc-20260728 -->

The repository analytic [detection-rule.yml](detection-rule.yml) implements a deterministic threshold: within 300 seconds, at least six calls in one session, at least four to one tool, and at least three matching normalized-argument or progress fingerprints, with no terminal completion and no approved-long-running marker. [tests/test_detection_rule.py](tests/test_detection_rule.py) verifies positive, negative, boundary, normalization, malformed-event, and approved-work cases. <!-- SAF-TRACE: claims=SAF-T1106-C010,SAF-T1106-C011; sources=SRC-ms-agentic-rag -->

Repeated calls can be legitimate for long-running polling, iterative search, or recovery. Tune by tool class and task contract, require independent progress evidence where available, and route ambiguous high-value work to review rather than treating a threshold alone as proof of attack. A controlled progress study found that in-band self-judgment could misclassify stagnation, supporting external or world-state progress signals. [SRC-park-progress-2026] <!-- SAF-TRACE: claims=SAF-T1106-C011; sources=SRC-park-progress-2026 -->

## Mitigation Strategies

- Enforce independent ceilings for iterations, wall-clock time, cumulative tokens, cost, retries, tool calls, and nested-agent depth; cancel work when any hard ceiling is crossed. <!-- SAF-TRACE: claims=SAF-T1106-C006,SAF-T1106-C009,SAF-T1106-C012; sources=SRC-mcp-tools-2026-07-28 -->
- Treat retrieved content, tool output, and agent messages as untrusted data; validate results before model re-entry and require per-action authorization or human approval for sensitive effects. <!-- SAF-TRACE: claims=SAF-T1106-C006,SAF-T1106-C008,SAF-T1106-C012; sources=SRC-mcp-tools-2026-07-28 -->
- Define externally grounded completion and progress contracts, persist loop counters across retries or restarts, and halt or escalate after repeated nonprogress. <!-- SAF-TRACE: claims=SAF-T1106-C003,SAF-T1106-C012,SAF-T1106-C013; sources=SRC-hou-ial-2026 -->
- Log every invocation and retain cancellation, completion, arguments, outputs, identity, token, cost, and timing fields so containment does not destroy the evidence needed to distinguish attack from failure. <!-- SAF-TRACE: claims=SAF-T1106-C006,SAF-T1106-C008,SAF-T1106-C010; sources=SRC-mcp-tools-2026-07-28 -->

## Related Techniques

| Technique | Relationship |
|---|---|
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Adjacent: the objective is an unauthorized change in model or tool behavior; repetition is incidental rather than the defining execution mechanism. <!-- SAF-TRACE: claims=SAF-T1106-C015; sources=SRC-hou-ial-2026 --> |
| [SAF-T2102: Service Disruption](../SAF-T2102/README.md) | Adjacent: load is submitted directly or through a pathological single request, without an autonomous model/tool feedback path deciding to re-enter. <!-- SAF-TRACE: claims=SAF-T1106-C015; sources=SRC-hou-ial-2026 --> |

## MITRE ATT&CK Mapping

| ATT&CK technique | Mapping |
|---|---|
| [T1499.003 – Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003/) | Analogous impact mapping: repeated invocation of resource-intensive application behavior can exhaust resources and deny availability, but ATT&CK does not require autonomous agent feedback. [SRC-mitre-t1499-003] <!-- SAF-TRACE: claims=SAF-T1106-C017; sources=SRC-mitre-t1499-003 --> |

## References

- [SRC-mcp-tools-2026-07-28] Model Context Protocol Working Group, “Tools,” specification revision 2026-07-28, reviewed 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1106-C004,SAF-T1106-C005,SAF-T1106-C006; sources=SRC-mcp-tools-2026-07-28 -->
- [SRC-mcp-rc-20260728] David Soria Parra and Den Delimarsky, “The 2026-07-28 MCP Release Candidate,” reviewed 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1106-C007; sources=SRC-mcp-rc-20260728 -->
- [SRC-zhou-2026] Kaiyu Zhou et al., “Beyond Max Tokens: Stealthy Resource Amplification via Tool Calling Chains in LLM Agents,” arXiv:2601.10955v2, 2026. <!-- SAF-TRACE: claims=SAF-T1106-C001,SAF-T1106-C013; sources=SRC-zhou-2026 -->
- [SRC-li-otora-2026] Xinyu Li et al., “OTora: A Unified Red Teaming Framework for Reasoning-Level Denial-of-Service in LLM Agents,” arXiv:2605.08876v3, 2026. <!-- SAF-TRACE: claims=SAF-T1106-C002,SAF-T1106-C011; sources=SRC-li-otora-2026 -->
- [SRC-hou-ial-2026] Xinyi Hou et al., “When Agents Do Not Stop: Uncovering Infinite Agentic Loops in LLM Agents,” arXiv:2607.01641v1, 2026. <!-- SAF-TRACE: claims=SAF-T1106-C003,SAF-T1106-C013; sources=SRC-hou-ial-2026 -->
- [SRC-ms-agent-responsibility] Microsoft Security, “AI agent shared responsibility model,” reviewed 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1106-C008,SAF-T1106-C012; sources=SRC-ms-agent-responsibility -->
- [SRC-ms-unbounded-dos] Microsoft Security, “Unbounded AI Consumption and Agentic DoS,” reviewed 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1106-C014; sources=SRC-ms-unbounded-dos -->
- [SRC-ms-agentic-rag] Microsoft Azure Architecture Center, “Develop an Agentic RAG Solution on Azure,” reviewed 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1106-C009,SAF-T1106-C010; sources=SRC-ms-agentic-rag -->
- [SRC-park-progress-2026] Hyundoo Park and Byungho Choi, “When Do Agent Loops Mistake Stagnation for Progress?,” arXiv:2607.25152v1, 2026. <!-- SAF-TRACE: claims=SAF-T1106-C011; sources=SRC-park-progress-2026 -->
- [SRC-mitre-t1499-003] MITRE ATT&CK, “Application Exhaustion Flood,” T1499.003 version 1.3, 2025. <!-- SAF-TRACE: claims=SAF-T1106-C017; sources=SRC-mitre-t1499-003 -->

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-01 | Initial clean-room draft. |
