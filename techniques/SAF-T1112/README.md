# SAF-T1112: Sampling Request Abuse

- **Tactic**: ATK-TA0002 (Execution)
- **Technique ID**: SAF-T1112
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Last Updated**: 2026-09-02
- **Research Packet**: [SAF-T1112 research](../../research/techniques/SAF-T1112/)
- **Traceability Ledger**: [Source-or-omit ledger](../../research/techniques/SAF-T1112/traceability-ledger.yml)

## Overview

Sampling Request Abuse is the inferred misuse of a supporting Model Context Protocol (MCP) client's model access when a malicious or compromised server causes an attacker-influenced generation outside meaningful request-specific approval or policy enforcement. <!-- SAF-TRACE: claims=SAF-T1112-C008 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

The current protocol places model access, model selection, and permission control with the client, so this technique crosses the client-mediated generation boundary rather than the ordinary tool-execution boundary. <!-- SAF-TRACE: claims=SAF-T1112-C001 ; sources=SRC-mcp-sampling-2026 -->

## Scope

This technique applies only where an MCP client supports server-initiated `sampling/createMessage`, accepts the request, and lacks sufficient approval, context, or budget controls. <!-- SAF-TRACE: claims=SAF-T1112-C002,SAF-T1112-C010 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

It excludes content manipulation through ordinary tool descriptions or responses, unauthorized host tool execution, vulnerable server-side tools, direct provider-API abuse, and explicitly approved sampling within enforced limits. <!-- SAF-TRACE: claims=SAF-T1112-C008,SAF-T1112-C012 ; sources=SRC-mcp-sampling-2026,SRC-mdpi-remote-mcp-2026 -->

Sampling is deprecated as of MCP 2026-07-28 but remains relevant to supporting implementations until removal; new implementations should avoid it and existing implementations should migrate to direct provider integration. <!-- SAF-TRACE: claims=SAF-T1112-C007 ; sources=SRC-mcp-sampling-2026,SRC-mcp-deprecated-2026 -->

## Description

A server can return an input-required result containing a `sampling/createMessage` request. The client then decides whether and how to use its LLM connection and whether a reviewed result may return to the requesting server. <!-- SAF-TRACE: claims=SAF-T1112-C001,SAF-T1112-C002,SAF-T1112-C009 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

The abusive condition is not the presence of sampling alone. It is execution without meaningful request-specific authorization or policy enforcement, such as an absent approval decision, automatic approval, inappropriate context release, or an uncontrolled request budget. <!-- SAF-TRACE: claims=SAF-T1112-C008,SAF-T1112-C010 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

## Attack Vectors

- **Unreviewed request**: A server supplies a sampling request that the client performs without a user able to inspect and deny it. <!-- SAF-TRACE: claims=SAF-T1112-C003,SAF-T1112-C008 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->
- **Context overreach**: A request seeks deprecated `thisServer` or `allServers` context and the client does not constrain sensitive material. <!-- SAF-TRACE: claims=SAF-T1112-C005,SAF-T1112-C017 ; sources=SRC-mcp-sampling-2026,SRC-mcp-deprecated-2026 -->
- **Budget amplification**: Repeated requests or large requested token budgets exploit absent per-server rate, cumulative-token, or loop limits. <!-- SAF-TRACE: claims=SAF-T1112-C006,SAF-T1112-C017 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->
- **Tool-enabled sampling**: A capable client accepts request-scoped tool definitions; those definitions need not match registered MCP tools and the server performs the sampling tool loop. <!-- SAF-TRACE: claims=SAF-T1112-C004 ; sources=SRC-mcp-sampling-2026 -->

## Technical Details

The current schema carries the request in `InputRequiredResult`. Relevant parameters include messages, model preferences, system prompt, context inclusion, required `maxTokens`, request-scoped tools, and tool choice. <!-- SAF-TRACE: claims=SAF-T1112-C002,SAF-T1112-C006 ; sources=SRC-mcp-2026-schema,SRC-mcp-sampling-2026 -->

The minimum preconditions are advertised client support, an active server interaction capable of returning input-required state, client acceptance of the request, and insufficient authorization or resource controls. <!-- SAF-TRACE: claims=SAF-T1112-C010 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

The immediate outcome is an attacker-influenced generation through the client's model access; after client review, the sampled result can be returned to the server. <!-- SAF-TRACE: claims=SAF-T1112-C009 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

## Evidence and Current State

The evidence status is Research-Derived: protocol authorities establish the complete boundary and controls, while malicious use of that complete flow is an explicit inference. <!-- SAF-TRACE: claims=SAF-T1112-C008,SAF-T1112-C009,SAF-T1112-C010 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

No qualifying direct incident, disclosed vulnerability, or independently reviewable end-to-end demonstration was identified in the government and scholarly authority corpus reviewed on 2026-09-02. This is a bounded corpus-and-date finding. <!-- SAF-TRACE: claims=SAF-T1112-C011 ; sources=SRC-nvd-fsp-catalog-queries-2026-09-01,SRC-nvd-sampling-query-2026,SRC-cisa-kev-2026-09-01,SRC-crossref-sampling-query-2026,SRC-arxiv-sampling-query-2026 -->

Park, Kim, Lee, and Park demonstrated five malicious-remote-server attacks across three LLM platforms, but the reviewed mechanisms used tool descriptions and responses, not `sampling/createMessage`; the study is adjacent evidence only. <!-- SAF-TRACE: claims=SAF-T1112-C012 ; sources=SRC-mdpi-remote-mcp-2026 -->

### Evidence Summary

| Claim ID | Validated proposition | Evidence status |
|---|---|---|
| SAF-T1112-C001 | Sampling lets a server request generation through a client that retains model and permission control. | Research-Derived |
| SAF-T1112-C002 | The current request transport and parameter family are defined. | Research-Derived |
| SAF-T1112-C003 | Client review, validation, rate limiting, and loop limits are recommended. | Research-Derived |
| SAF-T1112-C004 | Tool-enabled sampling uses request-scoped tool definitions and capability negotiation. | Research-Derived |
| SAF-T1112-C005 | Context inclusion defaults to none and broader values are deprecated. | Research-Derived |
| SAF-T1112-C006 | `maxTokens` is required; no universal rate or cumulative-token threshold is specified. | Research-Derived |
| SAF-T1112-C007 | Sampling is deprecated with migration guidance and a future removal window. | Research-Derived |
| SAF-T1112-C008 | Abuse without meaningful request-specific enforcement is an explicit framework inference. | Research-Derived |
| SAF-T1112-C009 | Attacker-influenced generation and possible result return are inferred outcomes. | Research-Derived |
| SAF-T1112-C010 | Capability, interaction, acceptance, and weak-control states are necessary preconditions. | Research-Derived |
| SAF-T1112-C011 | Direct incident, vulnerability, and demonstration evidence was absent from the dated reviewed corpus. | Research-Derived |
| SAF-T1112-C012 | A reviewed cross-platform malicious-server study is adjacent rather than direct. | Demonstrated adjacent research |
| SAF-T1112-C013 | MCP Inspector documents inspectable, grouped protocol transcripts with secret masking. | Research-Derived |
| SAF-T1112-C014 | The proposed approval-or-burst analytic is practical but experimental. | Research-Derived |
| SAF-T1112-C015 | Intent, low-rate activity, missing telemetry, and unstable identities limit the analytic. | Research-Derived |
| SAF-T1112-C016 | Disablement, review, validation, budgets, and migration form the preventive control set. | Research-Derived |
| SAF-T1112-C017 | Disclosure, integrity, and resource effects are conditional impacts. | Research-Derived |
| SAF-T1112-C018 | ATT&CK T1204 is analogous only when deceptive user approval is required. | Research-Derived |

## Impact Assessment

- **Confidentiality**: Sensitive included context or sampled output may be released to the requesting server, depending on client constraints and review. <!-- SAF-TRACE: claims=SAF-T1112-C005,SAF-T1112-C017 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->
- **Integrity**: The client can produce model output shaped by attacker-controlled request content, with downstream effects determined by the host and server. <!-- SAF-TRACE: claims=SAF-T1112-C009,SAF-T1112-C017 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->
- **Availability and quota**: Repetition or large budgets can pressure model capacity or allocated quotas, but no reviewed source quantified realized loss from this technique. <!-- SAF-TRACE: claims=SAF-T1112-C006,SAF-T1112-C017 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

## Detection Methods

Retain normalized MCP client audit events with event time, stable server and session identifiers, direction, method, requested token budget, approval state, context mode, tool-choice mode, and result state. Official Inspector documentation shows that grouped protocol transcripts are technically inspectable, but it is not a universal production audit schema. <!-- SAF-TRACE: claims=SAF-T1112-C002,SAF-T1112-C013,SAF-T1112-C014 ; sources=SRC-mcp-2026-schema,SRC-mcp-inspector-web-2026,SRC-mcp-sampling-2026 -->

The included experimental analytic alerts on a server-to-client sampling request with absent or automatic approval, or at least five requests totaling at least 16,384 requested tokens for one server and session within five minutes. The numerical thresholds require local baselining. <!-- SAF-TRACE: claims=SAF-T1112-C014,SAF-T1112-C015 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema,SRC-mcp-inspector-web-2026 -->

The analytic does not establish intent and can miss low-rate activity, unlogged approval failures, unstable server identities, and clients without normalized sampling records. <!-- SAF-TRACE: claims=SAF-T1112-C015 ; sources=SRC-mcp-sampling-2026,SRC-mcp-inspector-web-2026 -->

The safe executable tests cover positive, negative, exact-threshold, outside-window, malformed, and legitimate-lookalike cases using inert identifiers and no payload content. [Detection rule](detection-rule.yml), [test logic](test_detection_rule.py), and [test events](test-logs.json). <!-- SAF-TRACE: claims=SAF-T1112-C014,SAF-T1112-C015 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema,SRC-mcp-inspector-web-2026 -->

## Mitigation Strategies

- Apply [SAF-M-29 — Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md): disable sampling capability where it is not required, and do not add it to new implementations. <!-- SAF-TRACE: claims=SAF-T1112-C007,SAF-T1112-C016 ; sources=SRC-mcp-sampling-2026,SRC-mcp-deprecated-2026 -->
- Apply [SAF-M-69 — Out-of-Band Authorization](../../mitigations/SAF-M-69/README.md): require request-specific review with a user able to inspect and deny both request and response content. <!-- SAF-TRACE: claims=SAF-T1112-C003,SAF-T1112-C016 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->
- Apply [SAF-M-22 — Semantic Output Validation](../../mitigations/SAF-M-22/README.md): validate prompt content, constrain context inclusion, and reject deprecated broad-context modes when sensitive data could be shared. <!-- SAF-TRACE: claims=SAF-T1112-C003,SAF-T1112-C005,SAF-T1112-C016 ; sources=SRC-mcp-sampling-2026,SRC-mcp-deprecated-2026 -->
- Apply [SAF-M-73 — Sampling Budget and Iteration Caps](../../mitigations/SAF-M-73/README.md): enforce per-server request, cumulative-token, and tool-loop budgets; choose thresholds from environment baselines rather than the experimental detector defaults. <!-- SAF-TRACE: claims=SAF-T1112-C006,SAF-T1112-C014,SAF-T1112-C016 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->
- Migrate existing sampling implementations to direct provider API integration under explicit host policy. <!-- SAF-TRACE: claims=SAF-T1112-C007,SAF-T1112-C016 ; sources=SRC-mcp-sampling-2026,SRC-mcp-deprecated-2026 -->

## Related Techniques

- **[SAF-T1102 — Prompt Injection](../SAF-T1102/README.md)**: changes model instructions or content through ordinary MCP inputs; this technique specifically invokes the client-mediated sampling boundary. <!-- SAF-TRACE: claims=SAF-T1112-C008,SAF-T1112-C012 ; sources=SRC-mcp-sampling-2026,SRC-mdpi-remote-mcp-2026 -->
- **[SAF-T1104 — Over-Privileged Tool Abuse](../SAF-T1104/README.md)**: crosses a host tool-authorization boundary; this technique can complete without a host tool invocation. <!-- SAF-TRACE: claims=SAF-T1112-C004,SAF-T1112-C008 ; sources=SRC-mcp-sampling-2026 -->
- **[SAF-T2102 — Service Disruption](../SAF-T2102/README.md)**: covers generic request-driven availability pressure; repetition is an amplifier here, while one unapproved generation can satisfy this technique. <!-- SAF-TRACE: claims=SAF-T1112-C006,SAF-T1112-C008 ; sources=SRC-mcp-sampling-2026,SRC-mcp-2026-schema -->

## MITRE ATT&CK Mapping

MITRE ATT&CK T1204 User Execution is a conditional analogy only when an adversary deceives a user into approving the request. It does not describe automatically approved sampling or the MCP-specific model-generation boundary. <!-- SAF-TRACE: claims=SAF-T1112-C018 ; sources=SRC-mitre-attack-t1204,SRC-mcp-sampling-2026 -->

## References

- **SRC-mcp-sampling-2026** — Model Context Protocol Core Maintainers and contributors, [Sampling, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling).
- **SRC-mcp-2026-schema** — Model Context Protocol Core Maintainers and contributors, [Schema Reference, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/schema).
- **SRC-mcp-deprecated-2026** — Model Context Protocol Core Maintainers and contributors, [Deprecated Features, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/deprecated).
- **SRC-mcp-inspector-web-2026** — MCP Inspector maintainers and Model Context Protocol contributors, [MCP Inspector Web Client](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/web).
- **SRC-nvd-fsp-catalog-queries-2026-09-01** — National Vulnerability Database team, [NVD CVE API: Model Context Protocol query](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol).
- **SRC-nvd-sampling-query-2026** — National Vulnerability Database team, [NVD CVE API: MCP sampling query](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Model%20Context%20Protocol%20sampling).
- **SRC-cisa-kev-2026-09-01** — CISA Vulnerability Management team, [Known Exploited Vulnerabilities Catalog, version 2026.09.01](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
- **SRC-crossref-sampling-query-2026** — Crossref metadata services team, [Crossref MCP sampling bibliographic query](https://api.crossref.org/works?query.bibliographic=%22Model%20Context%20Protocol%22%20sampling&rows=20).
- **SRC-arxiv-sampling-query-2026** — arXiv operations team, [arXiv MCP sampling query](https://export.arxiv.org/api/query?search_query=all%3A%22Model%20Context%20Protocol%22%20AND%20all%3Asampling&start=0&max_results=20).
- **SRC-mdpi-remote-mcp-2026** — Jinwoo Park, Geonhee Kim, Hyeokjae Lee, and Jeman Park; academic editors Jiawei Zhang and Teng Li, [Beyond Tool Poisoning: Attack Surfaces of Malicious Remote MCP Servers Across LLM Platforms](https://doi.org/10.3390/electronics15102214), CC BY 4.0.
- **SRC-mitre-attack-t1204** — MITRE ATT&CK, [T1204 User Execution, version 1.8](https://attack.mitre.org/techniques/T1204/); contributors Ale Houspanossian, Fernando Bacchin, Harikrishnan Muthu of Cyble, Menachem Goldstein, Oleg Skulkin of Group-IB, and ReliaQuest; copyright The MITRE Corporation.

## Version History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-09-02 | OpenAI Codex clean-room agent | Initial independently researched clean-room technique. |
