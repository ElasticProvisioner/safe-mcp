# SAF-T1403: Consent-Fatigue Exploit

## Overview

- **Tactic**: Defense Evasion (ATK-TA0005)
- **Technique ID**: SAF-T1403
- **Research Packet**: [research/techniques/SAF-T1403](../../research/techniques/SAF-T1403/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1403/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: Medium
- **Severity Rationale**: Consequence is bounded by the action and approval scope, ranging from a low-risk one-time call to sensitive data access or state change. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 -->
- **First Observed**: No qualifying MCP or agentic-system production incident was identified in the reviewed corpus as of 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1403-C011; sources=SRC-mcp-security-2025-11-25 -->
- **Last Updated**: 2026-09-01

## Scope

Consent-Fatigue Exploit covers an adversary causing materially equivalent agent or MCP approval requests to recur until a user accepts one, crossing the human authorization boundary that gates a tool call, privilege elevation, or data disclosure. The complete MCP behavior is a synthesis of documented approval primitives and observed authentication-fatigue behavior, not a directly observed agentic incident. [MCP Tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) <!-- SAF-TRACE: claims=SAF-T1403-C001; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4 -->

### In Scope

- A server, tool, untrusted prompt source, or workflow induces repeated approval or elicitation requests after denial, cancellation, or non-response. <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C003; sources=SRC-mcp-elicitation-2025-06-18,SRC-nist-sp800-63b-4 -->
- A later acceptance authorizes the requested action or creates a reusable permission. <!-- SAF-TRACE: claims=SAF-T1403-C004,SAF-T1403-C005; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026 -->

### Out of Scope

- First-prompt deception through misleading labels, hidden arguments, or visual spoofing is separate because repetition is not the operative mechanism. <!-- SAF-TRACE: claims=SAF-T1403-C001; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4 -->
- OAuth consent bypass, redirect failure, and confused-deputy flaws are separate because the user decision is omitted or misbound rather than fatigued. <!-- SAF-TRACE: claims=SAF-T1403-C009; sources=SRC-nvd-cve-2026-27124,SRC-ghsa-rww4-4w9c-7733 -->
- Bounded retries for independently initiated actions are operational lookalikes and should not be classified without matching requester, operation, fingerprint, and decision history. <!-- SAF-TRACE: claims=SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0,SRC-anthropic-permissions-2026 -->

### Distinguishing Characteristics

The required sequence is a materially repeated request followed by approval; the nearest pre-integration neighbors are first-request approval-context deception and technical consent-enforcement bypass. Their repository IDs remain mechanical joins identified in `integration-notes.yml`. <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C009; sources=SRC-mcp-tools-2025-06-18,SRC-nvd-cve-2026-27124 -->

## Description

MCP tools can be selected by a model, while clients are advised to expose confirmation controls, show sensitive inputs, rate-limit calls, and log usage. MCP elicitation separately allows a server to request user input and receive explicit accept, decline, or cancel decisions; the specification advises client-side rate limiting and clear requester identity. [MCP Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) [MCP Elicitation](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation) <!-- SAF-TRACE: claims=SAF-T1403-C002,SAF-T1403-C003; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-elicitation-2025-06-18 -->

The adversary objective is not to bypass the approval mechanism, but to make a previously resisted decision recur until the user authorizes it. NIST records the analogous authentication-fatigue pattern: many approval requests can culminate in a fraudulent approval intended to stop the requests. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C006; sources=SRC-nist-sp800-63b-4,SRC-mcp-tools-2025-06-18 -->

OpenAI and Anthropic document approval scopes ranging from per-call decisions to skipped, session, or persistent permissions. Impact therefore depends on what the accepted request authorizes and how long that authorization remains effective. [OpenAI MCP approvals](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) [Claude Code permissions](https://code.claude.com/docs/en/permissions) <!-- SAF-TRACE: claims=SAF-T1403-C004,SAF-T1403-C005,SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 -->

## Attack Vectors

- **Primary Vector**: An adversary-influenced agent workflow repeatedly reaches a client-side approval boundary for the same consequential action. <!-- SAF-TRACE: claims=SAF-T1403-C001; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4 -->
- **Secondary Vectors**: MCP elicitation or denied-scope elevation loops can produce repeated user-facing decisions when client controls do not suppress them. <!-- SAF-TRACE: claims=SAF-T1403-C003,SAF-T1403-C010; sources=SRC-mcp-elicitation-2025-06-18,SRC-mcp-security-2025-11-25 -->
- **Affected Components**: MCP clients and hosts, agent permission managers, MCP servers and tools, and workflows that can trigger approval-generating operations. <!-- SAF-TRACE: claims=SAF-T1403-C002,SAF-T1403-C004,SAF-T1403-C005; sources=SRC-mcp-tools-2025-06-18,SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026 -->
- **Trust Boundary Crossed**: The user's explicit authorization decision for an agent action, permission, or disclosure. <!-- SAF-TRACE: claims=SAF-T1403-C001; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4 -->

## Technical Details

### Prerequisites

- The adversary can influence a server, tool, prompt source, or workflow that reaches an approval-capable client. <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C002; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4 -->
- The client permits the materially equivalent request to recur after denial, cancellation, or timeout instead of suppressing or rate-limiting it. <!-- SAF-TRACE: claims=SAF-T1403-C003,SAF-T1403-C010; sources=SRC-mcp-elicitation-2025-06-18,SRC-mcp-security-2025-11-25 -->
- Acceptance produces an action or permission whose value exceeds an ordinary low-risk retry. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 -->

### Attack Flow

1. **Setup**: The adversary shapes an agent or MCP workflow so that it requests a consequential operation. <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C002; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4 -->
2. **Initial Decision**: The client displays the requester, operation, scope, and arguments; the user denies, cancels, or does not answer. <!-- SAF-TRACE: claims=SAF-T1403-C003,SAF-T1403-C004; sources=SRC-mcp-elicitation-2025-06-18,SRC-clean-t1301-openai-mcp-guide -->
3. **Repetition**: The workflow generates materially equivalent requests within a short interval because no effective retry limit or denial cache stops it. <!-- SAF-TRACE: claims=SAF-T1403-C006,SAF-T1403-C010; sources=SRC-nist-sp800-63b-4,SRC-mcp-security-2025-11-25 -->
4. **Boundary Crossing**: The user approves one request, creating a one-time or reusable authorization. <!-- SAF-TRACE: claims=SAF-T1403-C004,SAF-T1403-C005; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026 -->
5. **Objective**: The client executes the approved action or permits later matching actions under the accepted scope. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 -->
6. **Follow-On Activity**: Any collection, modification, or wider compromise depends on the granted tool and permission scope and is not inherent to this technique. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 -->

### Example Scenario

An untrusted calendar-summary input causes an agent to request the same inert `calendar.preview` operation four times in ten minutes; the first request is denied and the fourth is approved. The example illustrates event correlation only and does not model human susceptibility. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C014; sources=SRC-mitre-det0160-v1.0,SRC-mcp-tools-2025-06-18 -->

```json
{"event_type":"approval_request","user_id":"user-example","requester_id":"server.example","operation":"calendar.preview","request_fingerprint":"sha256:example","decision":"denied"}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1403-C001 | Repeated agent approvals are a bounded cross-domain synthesis. | Research-Derived | SRC-mcp-tools-2025-06-18 and SRC-nist-sp800-63b-4 | No direct MCP incident or end-to-end demonstration. <!-- SAF-TRACE: claims=SAF-T1403-C001; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4 --> |
| SAF-T1403-C002 | MCP tools are model-controlled and clients should confirm, rate-limit, and log. | Research-Derived | SRC-mcp-tools-2025-06-18 | The protocol leaves the UI model to implementations. <!-- SAF-TRACE: claims=SAF-T1403-C002; sources=SRC-mcp-tools-2025-06-18 --> |
| SAF-T1403-C003 | Elicitation exposes accept, decline, cancel, provenance, and rate-limit controls. | Research-Derived | SRC-mcp-elicitation-2025-06-18 | Elicitation is not a universal authorization primitive. <!-- SAF-TRACE: claims=SAF-T1403-C003; sources=SRC-mcp-elicitation-2025-06-18 --> |
| SAF-T1403-C004 | OpenAI exposes MCP approval requests and responses with configurable scope. | Research-Derived | SRC-clean-t1301-openai-mcp-guide | Benign implementation documentation only. <!-- SAF-TRACE: claims=SAF-T1403-C004; sources=SRC-clean-t1301-openai-mcp-guide --> |
| SAF-T1403-C005 | Claude Code documents one-time and reusable permission decisions. | Research-Derived | SRC-anthropic-permissions-2026 | No malicious repetition is documented. <!-- SAF-TRACE: claims=SAF-T1403-C005; sources=SRC-anthropic-permissions-2026 --> |
| SAF-T1403-C006 | Repeated approval fatigue is documented for authentication. | Observed | SRC-nist-sp800-63b-4 | The boundary is authentication, not agent action consent. <!-- SAF-TRACE: claims=SAF-T1403-C006; sources=SRC-nist-sp800-63b-4 --> |
| SAF-T1403-C007 | Uber documented repeated two-factor requests followed by acceptance. | Observed analogy | SRC-uber-security-update-2022 | Non-agentic identity incident. <!-- SAF-TRACE: claims=SAF-T1403-C007; sources=SRC-uber-security-update-2022 --> |
| SAF-T1403-C008 | Microsoft observed DEV-0537 using repeated simple-approval MFA prompts. | Observed analogy | SRC-microsoft-dev0537-2022 | Campaign impact is not attributable to this step alone. <!-- SAF-TRACE: claims=SAF-T1403-C008; sources=SRC-microsoft-dev0537-2022 --> |
| SAF-T1403-C009 | FastMCP's consent-check flaw was demonstrated and patched. | Demonstrated adjacent vulnerability | SRC-nvd-cve-2026-27124 and SRC-ghsa-rww4-4w9c-7733 | Consent bypass, not fatigue. <!-- SAF-TRACE: claims=SAF-T1403-C009; sources=SRC-nvd-cve-2026-27124,SRC-ghsa-rww4-4w9c-7733 --> |
| SAF-T1403-C010 | MCP guidance suppresses repeated denied-scope elevation loops. | Research-Derived | SRC-mcp-security-2025-11-25 | Guidance does not establish exploitation. <!-- SAF-TRACE: claims=SAF-T1403-C010; sources=SRC-mcp-security-2025-11-25 --> |
| SAF-T1403-C011 | No direct production case appeared in the reviewed corpus. | Research-Derived absence finding | SRC-mcp-security-2025-11-25 | Bounded to recorded searches through 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1403-C011; sources=SRC-mcp-security-2025-11-25 --> |
| SAF-T1403-C012 | No end-to-end adversarial controlled demonstration appeared in the reviewed corpus. | Research-Derived absence finding | SRC-clean-t1301-openai-mcp-guide and SRC-ghsa-rww4-4w9c-7733 | Benign flow and adjacent bypass only. <!-- SAF-TRACE: claims=SAF-T1403-C012; sources=SRC-clean-t1301-openai-mcp-guide,SRC-ghsa-rww4-4w9c-7733 --> |
| SAF-T1403-C013 | Correlating equivalent requests and decision sequence is a defensible detector design. | Research-Derived | SRC-mitre-det0160-v1.0 | Thresholds do not prove coercion. <!-- SAF-TRACE: claims=SAF-T1403-C013; sources=SRC-mitre-det0160-v1.0 --> |
| SAF-T1403-C014 | Four requests in ten minutes is an experimental test threshold. | Research-Derived | SRC-mitre-det0160-v1.0 | Requires local tuning. <!-- SAF-TRACE: claims=SAF-T1403-C014; sources=SRC-mitre-det0160-v1.0 --> |
| SAF-T1403-C015 | Retry and user-initiated lookalikes require contextual fields. | Research-Derived | SRC-mitre-det0160-v1.0 | No measured agent-telemetry false-positive rate. <!-- SAF-TRACE: claims=SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0 --> |
| SAF-T1403-C016 | Rate limits, denial suppression, clear context, and stronger confirmation constrain the mechanism. | Research-Derived | SRC-mcp-elicitation-2025-06-18 and SRC-nist-sp800-63b-4 | Authentication controls require adaptation. <!-- SAF-TRACE: claims=SAF-T1403-C016; sources=SRC-mcp-elicitation-2025-06-18,SRC-nist-sp800-63b-4 --> |
| SAF-T1403-C017 | Number matching binds a push decision to sign-in context. | Research-Derived | SRC-microsoft-number-match-2025 | Authentication control, not an agent protocol. <!-- SAF-TRACE: claims=SAF-T1403-C017; sources=SRC-microsoft-number-match-2025 --> |
| SAF-T1403-C018 | Impact depends on action sensitivity and permission duration. | Research-Derived | SRC-clean-t1301-openai-mcp-guide and SRC-anthropic-permissions-2026 | No direct incident quantifies agentic impact. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026 --> |
| SAF-T1403-C019 | ATT&CK T1621 is analogous, not direct. | Research-Derived | SRC-mitre-t1621-v1.2 | T1621 concerns MFA authentication. <!-- SAF-TRACE: claims=SAF-T1403-C019; sources=SRC-mitre-t1621-v1.2 --> |

### Current State

- **Affected Environments**: Approval-capable MCP clients, hosts, and agent runtimes that allow materially equivalent requests after a negative or absent decision. <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C010; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-security-2025-11-25 -->
- **Known Exploitation**: None identified for the complete MCP or agentic behavior; repeated-approval exploitation is observed in MFA incidents, and consent-bypass CVEs are adjacent. <!-- SAF-TRACE: claims=SAF-T1403-C006,SAF-T1403-C007,SAF-T1403-C008,SAF-T1403-C011; sources=SRC-nist-sp800-63b-4,SRC-uber-security-update-2022,SRC-microsoft-dev0537-2022,SRC-mcp-security-2025-11-25 -->
- **Available Protections**: Client rate limits, denial caching, explicit requester and operation context, scoped approval, and stronger transaction-bound confirmation. <!-- SAF-TRACE: claims=SAF-T1403-C016,SAF-T1403-C017; sources=SRC-mcp-elicitation-2025-06-18,SRC-mcp-security-2025-11-25,SRC-nist-sp800-63b-4,SRC-microsoft-number-match-2025 -->
- **Residual Risk**: Controls that merely add a confirmation prompt remain dependent on the user's decision when materially equivalent requests can recur. <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C016; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4,SRC-mcp-elicitation-2025-06-18 -->

### Known Breaches and Vulnerabilities

No reviewed example is a direct MCP or agentic production incident or direct end-to-end demonstration; the selected examples are retained only as a mechanism-specific implementation condition, an adjacent consent vulnerability, and two historical analogies. <!-- SAF-TRACE: claims=SAF-T1403-C007,SAF-T1403-C008,SAF-T1403-C009,SAF-T1403-C010,SAF-T1403-C011,SAF-T1403-C012; sources=SRC-uber-security-update-2022,SRC-microsoft-dev0537-2022,SRC-nvd-cve-2026-27124,SRC-ghsa-rww4-4w9c-7733,SRC-mcp-security-2025-11-25,SRC-clean-t1301-openai-mcp-guide -->

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| MCP denied-scope elevation-loop guidance | 2025-11-25 MCP clients | Repeated loops are constrained by caching recent denials, precise scopes, and correlated elevation logs. | Enabling implementation condition: repetition is in scope, but adversarial control and user acceptance are not established. | First-party guidance, not a product advisory or incident. <!-- SAF-TRACE: claims=SAF-T1403-C010; sources=SRC-mcp-security-2025-11-25 --> |
| CVE-2026-27124 / GHSA-rww4-4w9c-7733 | 2026-03-31; FastMCP before 3.2.0 | A demonstrated OAuth proxy consent-check failure could expose account-linked resources; fixed in 3.2.0. | Adjacent vulnerability: it bypasses consent validation instead of exhausting the user with repeated decisions. | Proof of concept does not demonstrate fatigue. <!-- SAF-TRACE: claims=SAF-T1403-C009; sources=SRC-nvd-cve-2026-27124,SRC-ghsa-rww4-4w9c-7733 --> |
| Uber security incident | 2022-09-15 to 2022-09-19; corporate identity environment | The accepted request enabled internal-system access; Uber blocked accounts, rotated keys, disabled tools, reauthenticated users, and strengthened MFA. | Historical analogy: exact repeated-approval mechanism, different boundary. | Not MCP or agentic; Uber reported no production-system or sensitive-user-database access. <!-- SAF-TRACE: claims=SAF-T1403-C007; sources=SRC-uber-security-update-2022 --> |
| Microsoft DEV-0537 observations | Published 2022-03-22; multiple target organizations | Repeated simple-approval prompts were one initial-access method in campaigns involving theft, destructive actions, and extortion; Microsoft recommended stronger MFA. | Historical analogy: observed repeated approval requests, different boundary. | Consequences cannot be attributed solely to the fatigue step. <!-- SAF-TRACE: claims=SAF-T1403-C008; sources=SRC-microsoft-dev0537-2022 --> |

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Medium | Approval of a data-reading tool can expose data within the accepted scope; a one-time low-risk operation sharply limits this consequence. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 --> |
| Integrity | Medium | Approval of a state-changing action or reusable write permission can alter reachable state; read-only scope prevents this path. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 --> |
| Availability | Low | Availability impact is conditional on approval of a disruptive action and is not inherent to repeated prompting. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 --> |
| Scope | Adjacent | The default boundary is one user's client session, but reusable permissions and broad scopes can extend reachable systems. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 --> |

### Severity Conditions

- **Severity increases when**: the request authorizes privileged, state-changing, data-exporting, or persistent activity across multiple resources. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 -->
- **Severity decreases when**: the client binds approval to one low-risk operation, suppresses denials, and enforces narrow scopes and rate limits. <!-- SAF-TRACE: claims=SAF-T1403-C016,SAF-T1403-C018; sources=SRC-mcp-elicitation-2025-06-18,SRC-mcp-security-2025-11-25,SRC-clean-t1301-openai-mcp-guide -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Agent or MCP approval audit log | Approval request and decision lifecycle | `event_time`, `event_type`, `user_id`, `session_id`, `requester_id`, `operation`, `request_fingerprint`, `decision`, `approval_scope` | Normalize timestamps and fingerprints; retain at least the correlation window. <!-- SAF-TRACE: claims=SAF-T1403-C013; sources=SRC-mitre-det0160-v1.0,SRC-mcp-tools-2025-06-18,SRC-mcp-security-2025-11-25 --> |
| Tool and identity logs | Tool execution and user-initiated session context | `approval_id`, execution result, origin, and risk context | Use to verify that the approval led to action and to separate legitimate retries. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0,SRC-mcp-tools-2025-06-18 --> |

### Indicators of Compromise (IoCs)

- No durable artifact is inherent to this behavior; approval-sequence telemetry is the primary evidence. <!-- SAF-TRACE: claims=SAF-T1403-C013; sources=SRC-mitre-det0160-v1.0,SRC-mcp-tools-2025-06-18 -->

### Behavioral Indicators

- Four or more equivalent requests for one user, requester, operation, and fingerprint within ten minutes, with a prior denial or cancellation and a later approval. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C014; sources=SRC-mitre-det0160-v1.0 -->
- Equivalent requests spanning new sessions or request identifiers after a negative decision increase suspicion. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0,SRC-anthropic-permissions-2026 -->
- Repeated user-initiated operations with distinct fingerprints or a documented retry cause are expected lookalikes. <!-- SAF-TRACE: claims=SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0,SRC-anthropic-permissions-2026 -->

### Detection Analytic

The standalone experimental analytic is maintained in [detection-rule.yml](detection-rule.yml). <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C014; sources=SRC-mitre-det0160-v1.0 -->

- **Analytic Goal**: Identify a sequence of materially equivalent approval requests that follows a negative decision and culminates in approval. <!-- SAF-TRACE: claims=SAF-T1403-C013; sources=SRC-mitre-det0160-v1.0 -->
- **Rule Status**: Experimental. <!-- SAF-TRACE: claims=SAF-T1403-C014; sources=SRC-mitre-det0160-v1.0 -->
- **Detection Logic**: Group by user, requester, operation, and normalized fingerprint; require at least four requests, a denial or cancellation before the final approval, and no `user_initiated` marker. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C014,SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0 -->
- **Correlation Window**: Ten minutes. <!-- SAF-TRACE: claims=SAF-T1403-C014; sources=SRC-mitre-det0160-v1.0 -->
- **Known False Positives**: Legitimate retry loops, flaky integrations, and separately initiated equivalent actions. <!-- SAF-TRACE: claims=SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0,SRC-anthropic-permissions-2026 -->
- **Known Limitations**: Missing decision events, unstable fingerprints, alternate requesters, or delays outside the window can evade correlation; an alert does not prove coercion. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0 -->
- **Tuning Guidance**: Baseline per-tool retry behavior, lower thresholds for persistent or high-impact scopes, and allowlist documented automation only when it preserves decision history. <!-- SAF-TRACE: claims=SAF-T1403-C014,SAF-T1403-C015,SAF-T1403-C018; sources=SRC-mitre-det0160-v1.0,SRC-clean-t1301-openai-mcp-guide -->

### Validation

- **Test Data**: [cases.json](../../tests/SAF-T1403/cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1403/test_detection_rule.py)
- **Expected Result**: Ten cases pass, covering positive, negative, boundary, false-positive, malformed, missing-field, and normalization behavior; see [quality-review.yml](../../research/techniques/SAF-T1403/quality-review.yml).
- **Last Validated**: 2026-09-01; see [quality-review.yml](../../research/techniques/SAF-T1403/quality-review.yml).
- **Feasibility Waiver**: None; see [technique-contract.yml](../../research/techniques/SAF-T1403/technique-contract.yml).

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-73: Sampling Budget and Iteration Caps](../../mitigations/SAF-M-73/README.md)**: Rate-limit equivalent requests, cache denials, and require a fresh user-initiated context before retry. <!-- SAF-TRACE: claims=SAF-T1403-C010,SAF-T1403-C016; sources=SRC-mcp-security-2025-11-25,SRC-mcp-elicitation-2025-06-18 -->
2. **[SAF-M-69: Out-of-Band Authorization for Privileged Tool Invocations](../../mitigations/SAF-M-69/README.md)**: Display the requester, exact operation, arguments, scope, and duration, and bind consequential approval to transaction context. <!-- SAF-TRACE: claims=SAF-T1403-C016,SAF-T1403-C017; sources=SRC-mcp-elicitation-2025-06-18,SRC-nist-sp800-63b-4,SRC-microsoft-number-match-2025 -->
3. **Platform policy**: Keep sensitive actions on explicit per-action approval and prevent untrusted content from broadening or persisting permission scope. <!-- SAF-TRACE: claims=SAF-T1403-C004,SAF-T1403-C005,SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-anthropic-permissions-2026,SRC-mcp-security-2025-11-25 -->

### Detective Controls

1. **Sequence alerting**: Correlate prompt count, negative decisions, final approval, and subsequent execution under one request fingerprint. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C014; sources=SRC-mitre-det0160-v1.0 -->
2. **Control-health monitoring**: Alert when a denied request is immediately reissued without a fresh user action or when retry suppression is disabled. <!-- SAF-TRACE: claims=SAF-T1403-C010,SAF-T1403-C013; sources=SRC-mcp-security-2025-11-25,SRC-mitre-det0160-v1.0 -->

### Response Procedures

#### Immediate Actions

- Pause the requester or workflow, revoke reusable approval created by the sequence, and preserve the complete decision and execution history. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C018; sources=SRC-mitre-det0160-v1.0,SRC-anthropic-permissions-2026 -->
- Contain affected credentials or connected services only when the approved action or follow-on telemetry shows exposure. <!-- SAF-TRACE: claims=SAF-T1403-C018; sources=SRC-clean-t1301-openai-mcp-guide,SRC-mcp-security-2025-11-25 -->

#### Investigation Steps

- Reconstruct the ordered request, decision, permission, and execution events and determine whether requester, operation, arguments, or scope changed between prompts. <!-- SAF-TRACE: claims=SAF-T1403-C013,SAF-T1403-C015; sources=SRC-mitre-det0160-v1.0,SRC-mcp-tools-2025-06-18 -->
- Determine whether the user initiated each retry and whether a server, tool output, or untrusted input kept regenerating the request. <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C015; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4,SRC-mitre-det0160-v1.0 -->

#### Remediation

- Add retry suppression and a bounded backoff after decline or cancel, then require an explicit new user action to resume. <!-- SAF-TRACE: claims=SAF-T1403-C010,SAF-T1403-C016; sources=SRC-mcp-security-2025-11-25,SRC-mcp-elicitation-2025-06-18 -->
- Reduce broad or persistent grants to the minimum operation and duration, and add regression tests for denial loops. <!-- SAF-TRACE: claims=SAF-T1403-C016,SAF-T1403-C018; sources=SRC-mcp-security-2025-11-25,SRC-clean-t1301-openai-mcp-guide -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1007: OAuth Authorization Phishing](../SAF-T1007/README.md) | Alternative | Wins authorization through misleading first-request context; this technique requires materially repeated requests and a later acceptance. <!-- SAF-TRACE: claims=SAF-T1403-C001; sources=SRC-mcp-tools-2025-06-18,SRC-nist-sp800-63b-4 --> |
| [SAF-T1307: Confused Deputy Attack](../SAF-T1307/README.md) | Overlapping | Omits or misbinds consent through a technical deputy failure; this technique records an actual user approval after repeated requests. <!-- SAF-TRACE: claims=SAF-T1403-C001,SAF-T1403-C009; sources=SRC-mcp-tools-2025-06-18,SRC-nvd-cve-2026-27124 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1621](https://attack.mitre.org/techniques/T1621/) | Multi-Factor Authentication Request Generation | Analogous | Both behaviors repeat approval requests to obtain acceptance, but T1621 gates authentication while this technique gates agent or MCP actions. <!-- SAF-TRACE: claims=SAF-T1403-C019; sources=SRC-mitre-t1621-v1.2 --> |

## References

1. **SRC-mcp-tools-2025-06-18**: [MCP Tools specification, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) — Model-controlled tools, confirmation, rate limiting, input display, and audit logging.
2. **SRC-mcp-elicitation-2025-06-18**: [MCP Elicitation specification, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation) — Request decisions, requester clarity, decline, and rate limiting.
3. **SRC-mcp-security-2025-11-25**: [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) — Scope minimization, denial caching, and elevation logging.
4. **SRC-nist-sp800-63b-4**: [NIST SP 800-63B-4, Temoshok et al., 2025](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) — Authentication fatigue, rate limits, intent, and stronger out-of-band confirmation.
5. **SRC-mitre-t1621-v1.2**: [MITRE ATT&CK T1621, version 1.2](https://attack.mitre.org/versions/v19/techniques/T1621/) — Repeated MFA request behavior and procedure examples; contributors include Arun Seelagan, Jon Sternstein, Obsidian Security, Pawel Partyka, and Shanief Webb.
6. **SRC-mitre-det0160-v1.0**: [MITRE ATT&CK DET0160, version 1.0](https://attack.mitre.org/detectionstrategies/DET0160/) — Frequency, time-window, source, and decision-sequence analytics.
7. **SRC-uber-security-update-2022**: [Uber Security update, Uber Team, 2022](https://www.uber.com/us/en/newsroom/security-update/) — Repeated two-factor requests, acceptance, impact, and response.
8. **SRC-microsoft-dev0537-2022**: [DEV-0537 campaign analysis, Microsoft Threat Intelligence and Microsoft Defender Experts Cybersecurity Incident Response, 2022](https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/) — Observed simple-approval prompt abuse and campaign consequences.
9. **SRC-clean-t1301-openai-mcp-guide**: [OpenAI MCP and Connectors guide](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) — MCP approval request and response flow and sensitive-action guidance.
10. **SRC-anthropic-permissions-2026**: [Anthropic Claude Code permissions](https://code.claude.com/docs/en/permissions) — One-time, session, persistent, ask, deny, and managed permission behavior.
11. **SRC-nvd-cve-2026-27124**: [NVD CVE-2026-27124 record](https://nvd.nist.gov/vuln/detail/CVE-2026-27124) — Affected range, patch, CVSS, and proof-of-concept status.
12. **SRC-ghsa-rww4-4w9c-7733**: [FastMCP advisory GHSA-rww4-4w9c-7733, jlowin and reporter an7y, 2026](https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-rww4-4w9c-7733) — Consent-check flaw, demonstration, limitations, and fix; exact URL obtained from the reviewed NVD record.
13. **SRC-microsoft-number-match-2025**: [Microsoft Authenticator number matching](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match) — Transaction-context confirmation and legacy limitations.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Independent clean-room draft with evidence packet and tested analytic. | OpenAI Codex clean-room agent `/root/cleanroom_saf_t1403` |
