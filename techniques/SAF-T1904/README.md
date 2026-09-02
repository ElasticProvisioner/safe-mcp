# SAF-T1904: Chat-Based Backchannel

## Overview

- **Tactic**: ATK-TA0011
- **Technique ID**: SAF-T1904
- **Research Packet**: [research/techniques/SAF-T1904](../../research/techniques/SAF-T1904/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1904/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: Consequence is deployment-dependent but can reach privileged commands, host-execution approval, or persistent operator credentials when chat identities inherit powerful agent capabilities. <!-- SAF-TRACE: claims=SAF-T1904-C017; sources=SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->
- **First Observed**: Not observed in a qualifying production incident in the direct-authority corpus reviewed through 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1904-C012; sources=SRC-nvd-openclaw-corpus-20260902,SRC-cisa-kev-2026-09-01 -->
- **Last Updated**: 2026-09-02

## Scope

Chat-Based Backchannel covers a repeatable bidirectional operator-control path in which an external chat identity or conversation can supply actionable input to a tool-capable agent and receive returned status or results outside the authorized control plane. <!-- SAF-TRACE: claims=SAF-T1904-C007; sources=SRC-slack-events-api-20260902,SRC-mcp-tools-2025-06-18 -->

### In Scope

- An external sender can place messages in a conversation monitored by the agent or its connector. <!-- SAF-TRACE: claims=SAF-T1904-C003,SAF-T1904-C006; sources=SRC-slack-events-api-20260902,SRC-telegram-bot-api-10-3 -->
- The message reaches a model-controlled tool or privileged command path under a failed, ambiguous, or missing authorization decision. <!-- SAF-TRACE: claims=SAF-T1904-C002,SAF-T1904-C007; sources=SRC-mcp-tools-2025-06-18 -->
- The agent or connector returns a reply to the same service and conversation, permitting repeated control and feedback. <!-- SAF-TRACE: claims=SAF-T1904-C003,SAF-T1904-C006,SAF-T1904-C007; sources=SRC-slack-chat-postmessage,SRC-telegram-bot-api-10-3 -->

### Out of Scope

- One-shot prompt injection without a correlated returned control path is only an enabling condition. <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C012; sources=SRC-ghsa-xh72-v6v9-mwhc -->
- One-way chat delivery, exfiltration without inbound control, malicious MCP-server behavior, and fully authorized chat operations fall outside this mechanism. <!-- SAF-TRACE: claims=SAF-T1904-C001,SAF-T1904-C007,SAF-T1904-C015; sources=SRC-mcp-architecture-2025-06-18,SRC-slack-events-api-20260902 -->

### Distinguishing Characteristics

Analysts should require three linked stages—unapproved or identity-ambiguous chat ingress, a consequential agent action, and a same-conversation response—rather than classify isolated messages, isolated tool calls, or authorized chat operations as this technique. <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C014,SAF-T1904-C015; sources=SRC-slack-message-event-20260902,SRC-slack-chat-postmessage -->

## Description

MCP hosts coordinate clients and servers, enforce security and consent decisions, and route messages between participants; MCP tools can be model-controlled and can expose arbitrary functions. <!-- SAF-TRACE: claims=SAF-T1904-C001,SAF-T1904-C002; sources=SRC-mcp-architecture-2025-06-18,SRC-mcp-tools-2025-06-18 -->

Chat providers independently supply the other two primitives: application-visible inbound events and application-authored replies. Slack documents a first-party flow that sends message text to an LLM and posts the answer in the originating thread, while Telegram documents Update delivery, webhook authentication, and bot replies. <!-- SAF-TRACE: claims=SAF-T1904-C003,SAF-T1904-C006; sources=SRC-slack-events-api-20260902,SRC-telegram-bot-api-10-3 -->

The adversarial backchannel is therefore a framework inference from directly documented components and authorization failures. No reviewed authority establishes the complete malicious chat-message, consequential tool action, and attacker-observed reply loop in one production incident or controlled demonstration. <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C012; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-nvd-openclaw-corpus-20260902 -->

## Attack Vectors

- **Primary Vector**: An attacker-controlled chat message or callback enters an agent connector under a missing, bypassed, or mutable sender/conversation authorization check. <!-- SAF-TRACE: claims=SAF-T1904-C008,SAF-T1904-C009; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-ghsa-fhvm-j76f-qmjv -->
- **Secondary Vectors**: Forged webhooks, permissive direct-message policy, cross-context authorization, and command-specific approval or ownership bypasses can expose the same boundary. <!-- SAF-TRACE: claims=SAF-T1904-C008,SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C011; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->
- **Affected Components**: External chat service, bot or channel connector, agent or MCP host, tool/command dispatcher, approval subsystem, and outbound reply path. <!-- SAF-TRACE: claims=SAF-T1904-C001,SAF-T1904-C002,SAF-T1904-C007; sources=SRC-mcp-architecture-2025-06-18,SRC-mcp-tools-2025-06-18 -->
- **Trust Boundary Crossed**: The stable external chat identity and conversation policy is confused with authorization to control the agent's tools, commands, approvals, or credentials. <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C011; sources=SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->

## Technical Details

### Prerequisites

- The target exposes a bot, connector, webhook, callback, or chat-command path that can deliver external service events into the agent. <!-- SAF-TRACE: claims=SAF-T1904-C003,SAF-T1904-C006; sources=SRC-slack-events-api-20260902,SRC-telegram-bot-api-10-3 -->
- The reachable path can invoke a tool, command, approval action, or credential workflow with consequence beyond returning ordinary conversational text. <!-- SAF-TRACE: claims=SAF-T1904-C002,SAF-T1904-C017; sources=SRC-mcp-tools-2025-06-18,SRC-ghsa-98hh-7ghg-x6rq -->
- A sender, conversation, webhook, callback, role, or approval check is absent, bypassed, mutable, or incorrectly inherited. <!-- SAF-TRACE: claims=SAF-T1904-C008,SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C011; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->

### Attack Flow

1. **Setup**: The adversary identifies a chat entry point whose bot or connector reaches a tool-capable agent. <!-- SAF-TRACE: claims=SAF-T1904-C002,SAF-T1904-C007; sources=SRC-mcp-tools-2025-06-18 -->
2. **Delivery**: The adversary sends a message, update, or callback through the external chat service. <!-- SAF-TRACE: claims=SAF-T1904-C003,SAF-T1904-C006; sources=SRC-slack-events-api-20260902,SRC-telegram-bot-api-10-3 -->
3. **Trigger**: The connector associates the event with an agent session and a tool, command, approval, or enrollment path runs. <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C010,SAF-T1904-C011; sources=SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->
4. **Boundary Crossing**: Stable sender, conversation, webhook, role, or approval authorization fails to constrain the external input. <!-- SAF-TRACE: claims=SAF-T1904-C008,SAF-T1904-C009,SAF-T1904-C010; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq -->
5. **Objective**: The adversary receives a correlated reply, status, or other control feedback in the same chat conversation. <!-- SAF-TRACE: claims=SAF-T1904-C003,SAF-T1904-C006,SAF-T1904-C007; sources=SRC-slack-chat-postmessage,SRC-telegram-bot-api-10-3 -->
6. **Continuation**: Repeated messages and replies preserve the operator-control loop, while exposed privileges determine follow-on collection, modification, execution, or persistence. <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C017; sources=SRC-ghsa-xr4f-mjxj-w6w5,SRC-mcp-tools-2025-06-18 -->

### Example Scenario

In this inert detection scenario, an unapproved synthetic sender posts a status request, the agent invokes a non-destructive lookup tool, and the bot replies to the originating message; the sequence illustrates the analytic only and is not a reproduction of a product vulnerability. <!-- SAF-TRACE: claims=SAF-T1904-C014,SAF-T1904-C015; sources=SRC-slack-message-event-20260902,SRC-slack-chat-postmessage -->

The full synthetic fixture and expected result are maintained in [test-cases.json](../../tests/SAF-T1904/test-cases.json).

```json
{
  "service": "example-chat",
  "sender_id": "user-unapproved",
  "sender_authorized": false,
  "conversation_id": "room-7",
  "session_id": "session-1",
  "tool_name": "lookup_status",
  "reply_to": "msg-1"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1904-C001 | MCP hosts route bidirectional messages and own security/consent decisions. | Research-Derived | SRC-mcp-architecture-2025-06-18: [MCP Architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) | Does not describe the adversarial chat loop. |
| SAF-T1904-C002 | MCP tools can be model-controlled and require explicit safety controls. | Research-Derived | SRC-mcp-tools-2025-06-18: [MCP Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) | Implementations vary. |
| SAF-T1904-C003 | Slack supports message events and application replies, including a first-party LLM reply sample. | Research-Derived | SRC-slack-events-api-20260902 and SRC-slack-chat-postmessage: [Events API](https://docs.slack.dev/apis/events-api/) | Sample is benign and has no consequential tool call. |
| SAF-T1904-C004 | Slack events expose sender, app, channel, event, and time correlation fields. | Research-Derived | SRC-slack-message-event-20260902: [message event](https://docs.slack.dev/reference/events/message/) | Fields vary by subtype and scope. |
| SAF-T1904-C005 | Slack Audit Logs expose administrative attribution but not message content. | Research-Derived | SRC-slack-audit-logs-20260902: [Audit Logs API](https://docs.slack.dev/admins/audit-logs-api/) | Deployment-specific logs may be richer. |
| SAF-T1904-C006 | Telegram supports inbound updates, authenticated webhooks, and replies. | Research-Derived | SRC-telegram-bot-api-10-3: [Bot API](https://core.telegram.org/bots/api) | Does not imply agent tool execution. |
| SAF-T1904-C007 | The complete repeatable chat-to-tool-to-chat backchannel is a multi-source inference. | Research-Derived | SRC-mcp-tools-2025-06-18, SRC-slack-events-api-20260902, SRC-telegram-bot-api-10-3, and SRC-ghsa-xh72-v6v9-mwhc | No single incident or demonstration establishes the complete sequence. |
| SAF-T1904-C008 | Feishu webhook or card-action authentication could fail open and reach command dispatch. | Research-Derived | SRC-ghsa-xh72-v6v9-mwhc and SRC-nvd-openclaw-corpus-20260902: [vendor advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-xh72-v6v9-mwhc) | Disclosure, not production exploitation. |
| SAF-T1904-C009 | Forged Telegram updates could bypass allowlists and reach privileged bot commands. | Research-Derived | SRC-ghsa-fhvm-j76f-qmjv and SRC-nvd-openclaw-corpus-20260902: [vendor advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-fhvm-j76f-qmjv) | Webhook mode/reachability required; patch-version conflict retained. |
| SAF-T1904-C010 | A Discord command sender outside the approver list could approve pending host execution. | Research-Derived | SRC-ghsa-98hh-7ghg-x6rq and SRC-nvd-openclaw-corpus-20260902: [vendor advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-98hh-7ghg-x6rq) | Command access and a pending request were prerequisites. |
| SAF-T1904-C011 | A non-owner chat sender could mint a bootstrap code for persistent operator/node credentials. | Research-Derived | SRC-ghsa-xr4f-mjxj-w6w5 and SRC-nvd-openclaw-corpus-20260902: [vendor advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-xr4f-mjxj-w6w5) | Sender already needed chat-command access. |
| SAF-T1904-C012 | No qualifying incident or complete adversarial demonstration was found in the reviewed corpus. | Research-Derived | SRC-nvd-openclaw-corpus-20260902 and SRC-cisa-kev-2026-09-01: [NVD corpus](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenClaw) | Bounded search result, not proof of absence. |
| SAF-T1904-C013 | ATT&CK bidirectional web-service C2 is the closest historical analogy. | Research-Derived | SRC-mitre-t1102-002-v1-1: [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | Non-agentic and not MCP-specific. |
| SAF-T1904-C014 | Correlate unapproved ingress, same-session tool use, and same-conversation reply within five minutes. | Research-Derived | SRC-slack-message-event-20260902, SRC-slack-chat-postmessage, and SRC-mitre-t1102-002-v1-1 | Window and joins require tuning. |
| SAF-T1904-C015 | Authorized chatops is a false-positive class, and Audit Logs alone are insufficient. | Research-Derived | SRC-slack-audit-logs-20260902 and SRC-slack-events-api-20260902 | Private telemetry may differ. |
| SAF-T1904-C016 | Stable identity, webhook authentication, least privilege, approval, and patching address the boundary. | Research-Derived | SRC-mcp-security-spec-2025-11-25, SRC-mcp-tools-2025-06-18, SRC-telegram-bot-api-10-3, and SRC-ghsa-fhvm-j76f-qmjv | No single control covers every connector. |
| SAF-T1904-C017 | Impact depends on reachable tools and can include commands, host approval, credentials, and C/I/A loss. | Research-Derived | SRC-ghsa-xh72-v6v9-mwhc, SRC-ghsa-98hh-7ghg-x6rq, SRC-ghsa-xr4f-mjxj-w6w5, and SRC-mcp-tools-2025-06-18 | Deployment privileges bound severity. |

### Current State

- **Affected Environments**: Tool-capable agent deployments that ingest external chat events and return chat replies, especially when webhook, sender, conversation, role, approval, or ownership policy is weak. <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C008,SAF-T1904-C009; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-ghsa-fhvm-j76f-qmjv -->
- **Known Exploitation**: The reviewed NVD CISA SSVC entries record exploitation as none, and the selected identifiers do not appear in the CISA KEV snapshot reviewed on 2026-09-02. <!-- SAF-TRACE: claims=SAF-T1904-C008,SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C011,SAF-T1904-C012; sources=SRC-nvd-openclaw-corpus-20260902,SRC-cisa-kev-2026-09-01 -->
- **Available Protections**: Provider webhook authentication, stable identity binding, host authorization, human approval, least-privilege connector/tool scopes, and vendor patches constrain known paths. <!-- SAF-TRACE: claims=SAF-T1904-C016; sources=SRC-mcp-security-spec-2025-11-25,SRC-telegram-bot-api-10-3,SRC-ghsa-fhvm-j76f-qmjv -->
- **Residual Risk**: Authorized or misclassified chat input can remain difficult to distinguish from legitimate chatops when immutable identity and session/reply joins are absent. <!-- SAF-TRACE: claims=SAF-T1904-C014,SAF-T1904-C015; sources=SRC-slack-message-event-20260902,SRC-slack-audit-logs-20260902 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2026-44109 / GHSA-xh72-v6v9-mwhc | Published 2026; OpenClaw before 2026.4.15 with affected Feishu webhook or card-action conditions | Unauthenticated traffic could reach command dispatch; upgrade to 2026.4.15 or later and enforce webhook/callback authentication. | Direct vulnerability | No reviewed production exploitation or complete returned loop. | <!-- SAF-TRACE: claims=SAF-T1904-C008; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-nvd-openclaw-corpus-20260902 -->
| CVE-2026-28454 / GHSA-fhvm-j76f-qmjv | Published 2026; reachable Telegram webhook in affected pre-fix OpenClaw versions | Forged updates could bypass allowlists and reach privileged commands; use 2026.2.2 or later and require the secret token. | Direct vulnerability | Webhook mode/reachability required; advisory patch-version conflict remains. | <!-- SAF-TRACE: claims=SAF-T1904-C009; sources=SRC-ghsa-fhvm-j76f-qmjv,SRC-nvd-openclaw-corpus-20260902 -->
| CVE-2026-41303 / GHSA-98hh-7ghg-x6rq | Published 2026; OpenClaw before 2026.3.28 with Discord text approvals | A non-approver command sender could approve pending host execution; upgrade to 2026.3.28 or later. | Direct vulnerability | Requires command authorization and a pending execution request. | <!-- SAF-TRACE: claims=SAF-T1904-C010; sources=SRC-ghsa-98hh-7ghg-x6rq,SRC-nvd-openclaw-corpus-20260902 -->
| CVE-2026-32905 / GHSA-xr4f-mjxj-w6w5 | Published 2026; OpenClaw before 2026.5.4 with bundled device-pair chat command | A non-owner sender could enroll persistent operator/node credentials; upgrade to 2026.5.4 or later, remove unknown devices, and rotate exposed credentials. | Direct vulnerability | Requires existing chat-command authorization; no complete returned loop shown. | <!-- SAF-TRACE: claims=SAF-T1904-C011; sources=SRC-ghsa-xr4f-mjxj-w6w5,SRC-nvd-openclaw-corpus-20260902 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Tool or credential access may expose data only when the connected agent can read sensitive resources. | <!-- SAF-TRACE: claims=SAF-T1904-C002,SAF-T1904-C017; sources=SRC-mcp-tools-2025-06-18,SRC-ghsa-xr4f-mjxj-w6w5 -->
| Integrity | High | Unauthorized commands, approval decisions, or persistent enrollment can change host or agent state. | <!-- SAF-TRACE: claims=SAF-T1904-C010,SAF-T1904-C011,SAF-T1904-C017; sources=SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->
| Availability | Medium | Availability loss is possible only when exposed tools or commands can disrupt service or resources. | <!-- SAF-TRACE: claims=SAF-T1904-C017; sources=SRC-mcp-tools-2025-06-18 -->
| Scope | Multi-System | The chat service, connector, agent host, tools, and enrolled devices may be involved, but actual blast radius follows granted privileges. | <!-- SAF-TRACE: claims=SAF-T1904-C001,SAF-T1904-C017; sources=SRC-mcp-architecture-2025-06-18,SRC-ghsa-xr4f-mjxj-w6w5 -->

### Severity Conditions

- **Severity increases when**: The connector reaches privileged tools, approvals are bypassable, long-lived credentials can be issued, sensitive data is reachable, or chat identity policy uses mutable values. <!-- SAF-TRACE: claims=SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C011,SAF-T1904-C017; sources=SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->
- **Severity decreases when**: Webhooks authenticate before parsing, immutable IDs are explicitly allowlisted, tools are narrowly scoped, consequential actions require independent approval, and outbound replies disclose minimal results. <!-- SAF-TRACE: claims=SAF-T1904-C002,SAF-T1904-C016; sources=SRC-mcp-tools-2025-06-18,SRC-telegram-bot-api-10-3 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Chat connector or bot event log | Message/update received and reply sent | Timestamp, service, tenant/workspace, immutable sender ID, app/bot ID, conversation ID, message/event ID, reply relation, sender/conversation authorization, identity-binding type | Normalize provider identifiers and retain reply joins; administrative audit logs may lack message content. | <!-- SAF-TRACE: claims=SAF-T1904-C004,SAF-T1904-C005,SAF-T1904-C006,SAF-T1904-C014; sources=SRC-slack-message-event-20260902,SRC-slack-audit-logs-20260902,SRC-telegram-bot-api-10-3 -->
| Agent host and tool audit log | Session creation, command/tool invocation, result, and approval | Timestamp, session ID, conversation ID, tool/command name, result, approval state, principal | Preserve clocks and the provider-to-agent session mapping for ordered correlation. | <!-- SAF-TRACE: claims=SAF-T1904-C002,SAF-T1904-C014; sources=SRC-mcp-tools-2025-06-18,SRC-mitre-t1102-002-v1-1 -->

### Indicators of Compromise (IoCs)

- No universal durable IoC is established; identities, channels, tools, and reply artifacts are deployment-specific. <!-- SAF-TRACE: claims=SAF-T1904-C012,SAF-T1904-C014; sources=SRC-nvd-openclaw-corpus-20260902,SRC-slack-message-event-20260902 -->
- Durable local indicators can include an unexpected device enrollment or approval record when those consequences occur. <!-- SAF-TRACE: claims=SAF-T1904-C010,SAF-T1904-C011; sources=SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->

### Behavioral Indicators

- An unapproved sender or mutable identity binding precedes a tool invocation and reply in the same agent session and conversation. <!-- SAF-TRACE: claims=SAF-T1904-C014; sources=SRC-slack-message-event-20260902,SRC-slack-chat-postmessage -->
- Privileged commands, approval changes, or credential enrollment initiated from an external chat context increase confidence. <!-- SAF-TRACE: claims=SAF-T1904-C008,SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C011; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->
- Stable, explicitly approved sender, conversation, app, and approval policy indicate legitimate chatops and should suppress the analytic. <!-- SAF-TRACE: claims=SAF-T1904-C015; sources=SRC-slack-events-api-20260902 -->

### Detection Analytic

The standalone tested analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Identify the complete unauthorized or identity-ambiguous inbound-chat, same-session tool, and same-conversation reply sequence. <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C014; sources=SRC-slack-message-event-20260902,SRC-slack-chat-postmessage -->
- **Rule Status**: Experimental; provider normalization and authorization fields require deployment validation. <!-- SAF-TRACE: claims=SAF-T1904-C014,SAF-T1904-C015; sources=SRC-slack-message-event-20260902,SRC-slack-audit-logs-20260902 -->
- **Detection Logic**: Join unapproved or mutable-identity ingress to an ordered tool event and a reply targeting the originating message under the same tenant, app, conversation, and session. <!-- SAF-TRACE: claims=SAF-T1904-C014; sources=SRC-slack-message-event-20260902,SRC-slack-chat-postmessage -->
- **Correlation Window**: Five minutes, inclusive, as a tunable analytic choice. <!-- SAF-TRACE: claims=SAF-T1904-C014; sources=SRC-mitre-t1102-002-v1-1 -->
- **Known False Positives**: Approved break-glass chatops with a missing propagated authorization decision, connector migrations, and non-production replay traffic. <!-- SAF-TRACE: claims=SAF-T1904-C015; sources=SRC-slack-events-api-20260902,SRC-slack-audit-logs-20260902 -->
- **Known Limitations**: Missing immutable IDs, authorization decisions, provider-to-agent session joins, or reply relations prevent reliable correlation. <!-- SAF-TRACE: claims=SAF-T1904-C004,SAF-T1904-C005,SAF-T1904-C014; sources=SRC-slack-message-event-20260902,SRC-slack-audit-logs-20260902 -->
- **Tuning Guidance**: Suppress only stable approved identities and conversations; adjust latency without removing the session, conversation, and reply joins. <!-- SAF-TRACE: claims=SAF-T1904-C014,SAF-T1904-C015; sources=SRC-slack-message-event-20260902,SRC-slack-chat-postmessage -->

### Validation

- **Test Data**: [test-cases.json](../../tests/SAF-T1904/test-cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1904/test_detection_rule.py)
- **Expected Result**: [Twelve positive, negative, boundary, missing-field, malformed-field, and correlation cases pass](../../research/techniques/SAF-T1904/validation/detection-tests.txt).
- **Last Validated**: [2026-09-02 destination detector and strict-validator run](../../research/techniques/SAF-T1904/validation/canonical-validation.txt).
- **Feasibility Waiver**: None; the normalized analytic is executable and tested. <!-- SAF-TRACE: claims=SAF-T1904-C014; sources=SRC-slack-message-event-20260902 -->

## Mitigation Strategies

### Preventive Controls

1. Bind sender, conversation, application, and approver policy to immutable provider identifiers and fail closed when the mapping or policy is absent. <!-- SAF-TRACE: claims=SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C016; sources=SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq -->
2. Authenticate chat webhooks and callbacks before processing, including Telegram's secret-token header where Telegram webhooks are used. <!-- SAF-TRACE: claims=SAF-T1904-C006,SAF-T1904-C016; sources=SRC-telegram-bot-api-10-3,SRC-ghsa-fhvm-j76f-qmjv -->
3. Restrict connector and tool scopes, show tool inputs, allow human denial, and require independent approval for consequential actions. <!-- SAF-TRACE: claims=SAF-T1904-C002,SAF-T1904-C016; sources=SRC-mcp-tools-2025-06-18,SRC-mcp-security-spec-2025-11-25 -->
4. Apply vendor fixes for disclosed channel, approval, and enrollment defects and regression-test the affected authorization boundaries. <!-- SAF-TRACE: claims=SAF-T1904-C008,SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C011,SAF-T1904-C016; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->

### Detective Controls

1. Preserve normalized connector receipt/reply and agent tool/approval telemetry with a stable provider-to-session mapping. <!-- SAF-TRACE: claims=SAF-T1904-C004,SAF-T1904-C005,SAF-T1904-C014; sources=SRC-slack-message-event-20260902,SRC-slack-audit-logs-20260902 -->
2. Alert on unauthorized or mutable-identity ingress followed by sensitive commands, approval resolution, enrollment, or tool output returned to the originating conversation. <!-- SAF-TRACE: claims=SAF-T1904-C010,SAF-T1904-C011,SAF-T1904-C014; sources=SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5,SRC-slack-chat-postmessage -->

### Response Procedures

#### Immediate Actions

- Disable or isolate the affected chat connector and pause the linked agent session or tool path. <!-- SAF-TRACE: claims=SAF-T1904-C016,SAF-T1904-C017; sources=SRC-mcp-security-spec-2025-11-25,SRC-mcp-tools-2025-06-18 -->
- Revoke unexpected device or operator credentials, rotate exposed secrets, and preserve connector, session, tool, approval, and reply telemetry. <!-- SAF-TRACE: claims=SAF-T1904-C011,SAF-T1904-C014,SAF-T1904-C016; sources=SRC-ghsa-xr4f-mjxj-w6w5,SRC-slack-message-event-20260902 -->

#### Investigation Steps

- Reconstruct the ordered message, session, tool/command, approval, credential, and reply sequence using immutable provider identifiers. <!-- SAF-TRACE: claims=SAF-T1904-C004,SAF-T1904-C014; sources=SRC-slack-message-event-20260902,SRC-slack-chat-postmessage -->
- Determine whether the entry point was a forged webhook, mutable identity, permissive policy, cross-context scope, or command-specific authorization bypass. <!-- SAF-TRACE: claims=SAF-T1904-C008,SAF-T1904-C009,SAF-T1904-C010,SAF-T1904-C011; sources=SRC-ghsa-xh72-v6v9-mwhc,SRC-ghsa-fhvm-j76f-qmjv,SRC-ghsa-98hh-7ghg-x6rq,SRC-ghsa-xr4f-mjxj-w6w5 -->

#### Remediation

- Patch the affected connector or agent, correct stable identity and role policy, authenticate webhooks, and reduce tool/credential scope. <!-- SAF-TRACE: claims=SAF-T1904-C016; sources=SRC-mcp-tools-2025-06-18,SRC-telegram-bot-api-10-3,SRC-ghsa-fhvm-j76f-qmjv -->
- Validate recovery with the detector's approved, unauthorized, missing-field, and timing-boundary cases before restoring chat connectivity. <!-- SAF-TRACE: claims=SAF-T1904-C014,SAF-T1904-C015; sources=SRC-slack-message-event-20260902,SRC-slack-audit-logs-20260902 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) | Enabling or overlapping | Prompt injection controls model input but does not by itself establish a repeatable same-chat response path. | <!-- SAF-TRACE: claims=SAF-T1904-C007,SAF-T1904-C012; sources=SRC-ghsa-xh72-v6v9-mwhc -->
| [SAF-T1911: Parameter Exfiltration](../SAF-T1911/README.md) | Follow-on or overlapping | Outbound data movement lacks this technique's required inbound operator control when used alone. | <!-- SAF-TRACE: claims=SAF-T1904-C007; sources=SRC-slack-events-api-20260902 -->
| SAF-T1903: Malicious Server Control Channel | Alternative | A malicious MCP server crosses the host-server boundary, while this technique crosses the external chat identity/conversation boundary. Catalog link pending clean-room authoring. | <!-- SAF-TRACE: claims=SAF-T1904-C001,SAF-T1904-C007; sources=SRC-mcp-architecture-2025-06-18 -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1102.002](https://attack.mitre.org/techniques/T1102/002/) | Web Service: Bidirectional Communication | Analogous | Both use a legitimate web service to carry commands and results, but ATT&CK's historical definition is non-agentic and does not model MCP tools or chat identity authorization. | <!-- SAF-TRACE: claims=SAF-T1904-C013; sources=SRC-mitre-t1102-002-v1-1 -->

## References

1. **SRC-mcp-architecture-2025-06-18**: [MCP Architecture, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/architecture) — host, client, server, security, and bidirectional-routing model.
2. **SRC-mcp-tools-2025-06-18**: [MCP Tools, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) — model-controlled tools and tool safety controls.
3. **SRC-mcp-security-spec-2025-11-25**: [MCP Security Best Practices, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices) — authorization-boundary guidance.
4. **SRC-slack-events-api-20260902**: [Slack Events API](https://docs.slack.dev/apis/events-api/) — event delivery and first-party LLM reply sample.
5. **SRC-slack-message-event-20260902**: [Slack message event](https://docs.slack.dev/reference/events/message/) — message correlation fields.
6. **SRC-slack-chat-postmessage**: [Slack chat.postMessage](https://docs.slack.dev/reference/methods/chat.postMessage/) — application messages and thread replies.
7. **SRC-slack-audit-logs-20260902**: [Slack Audit Logs API](https://docs.slack.dev/admins/audit-logs-api/) — administrative audit fields and message-content limitation.
8. **SRC-telegram-bot-api-10-3**: [Telegram Bot API 10.3](https://core.telegram.org/bots/api) — updates, webhooks, secret token, and replies.
9. **SRC-mitre-t1102-002-v1-1**: [MITRE ATT&CK T1102.002, version 1.1](https://attack.mitre.org/techniques/T1102/002/) — non-agentic bidirectional web-service analogy and detection context.
10. **SRC-nvd-openclaw-corpus-20260902**: [NVD OpenClaw CVE API corpus](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenClaw) — 592-record candidate corpus, CVE metadata, references, and CISA SSVC fields.
11. **SRC-cisa-kev-2026-09-01**: [CISA Known Exploited Vulnerabilities catalog, version 2026.09.01](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) — bounded selected-CVE catalog check.
12. **SRC-ghsa-xh72-v6v9-mwhc**: [OpenClaw Feishu authentication advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-xh72-v6v9-mwhc) — OpenClaw maintainers; reporter credit to dhyabi2.
13. **SRC-ghsa-fhvm-j76f-qmjv**: [OpenClaw Telegram webhook advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-fhvm-j76f-qmjv) — OpenClaw maintainers; reporter credit to simecek and analyst credit to stanislavfortaisle.
14. **SRC-ghsa-98hh-7ghg-x6rq**: [OpenClaw Discord approval advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-98hh-7ghg-x6rq) — published by steipete; reporter credit to tdjackey.
15. **SRC-ghsa-xr4f-mjxj-w6w5**: [OpenClaw device-pairing advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-xr4f-mjxj-w6w5) — published by steipete; reporter credit to Kherrisan.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-02 | Initial clean-room research-derived technique, evidence packet, tested analytic, and isolated validation bundle. | OpenAI Codex fresh-agent author (`/root/cleanroom_saf_t1904`) |
