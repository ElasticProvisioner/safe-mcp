# SAF-T1105: Path Traversal via File Tool

## Overview

- **Tactic**: ATK-TA0002 / Execution
- **Technique ID**: SAF-T1105
- **Research Packet**: [SAF-T1105 research](../../research/techniques/SAF-T1105/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1105/traceability-ledger.yml)
- **Documentation Status**: Stable
- **Evidence Status**: Demonstrated
- **Severity**: High
- **Last Updated**: 2026-09-01

- **Severity Rationale**: A boundary bypass can expose local data, create or replace files, delete data, or reach context-dependent code execution, while effective permissions and isolation bound the result. <!-- SAF-TRACE: claims=SAF-T1105-C003,SAF-T1105-C014 ; sources=SRC-cwe-22,SRC-aws-cve-2026-18953 -->
- **First Observed**: No hostile production incident was established; the earliest selected evidence is a controlled 2026 public-endpoint demonstration. <!-- SAF-TRACE: claims=SAF-T1105-C005,SAF-T1105-C009 ; sources=SRC-varonis-cve-2026-4270,SRC-aws-cve-2026-4270 -->

## Scope

This technique covers an MCP or agent file-capable tool when attacker-influenced path data resolves beyond the configured file scope, or bypasses a no-access mode, and the tool attempts a filesystem operation. <!-- SAF-TRACE: claims=SAF-T1105-C004 ; sources=SRC-mcp-tools-2026-07-28,SRC-cwe-22 -->

Prompt injection that only supplies a path, authorized operations wholly inside a permitted root, archive extraction outside a tool, and follow-on collection or execution are separate behaviors. <!-- SAF-TRACE: claims=SAF-T1105-C004 ; sources=SRC-mcp-tools-2026-07-28,SRC-cwe-22 -->

## Description

MCP tools are model-invocable and receive named arguments; the server remains responsible for validating those inputs and enforcing access controls. <!-- SAF-TRACE: claims=SAF-T1105-C001 ; sources=SRC-mcp-tools-2026-07-28 -->

The failure occurs when external input helps construct a pathname intended to remain beneath a restricted parent but the resolved target escapes it. <!-- SAF-TRACE: claims=SAF-T1105-C003 ; sources=SRC-cwe-22 -->

For file resources, the protocol also requires URI validation, permission checks, and path sanitization against directory traversal. <!-- SAF-TRACE: claims=SAF-T1105-C002 ; sources=SRC-mcp-resources-2026 -->

## Attack Vectors

- Relative or absolute path arguments can target an object outside the allowed root when a tool trusts lexical input rather than the canonical target. <!-- SAF-TRACE: claims=SAF-T1105-C004,SAF-T1105-C013 ; sources=SRC-cwe-22 -->
- Prefix collisions, alternate path forms, encoding, or separators can defeat substring and denylist checks. <!-- SAF-TRACE: claims=SAF-T1105-C013 ; sources=SRC-cwe-22,SRC-aws-cve-2026-4270 -->
- A path that appears inside the root can resolve through a link to an external object. <!-- SAF-TRACE: claims=SAF-T1105-C010,SAF-T1105-C013 ; sources=SRC-cwe-59,SRC-cwe-22 -->
- A path-bearing parameter can expose a secondary write, copy, move, or deletion primitive even when the tool's headline function is not file management. <!-- SAF-TRACE: claims=SAF-T1105-C006,SAF-T1105-C007,SAF-T1105-C008 ; sources=SRC-aws-cve-2026-18953,SRC-aws-cve-2026-15415,SRC-vulncheck-cve-2026-74798 -->

## Technical Details

The defining sequence is a tool invocation, attacker influence over a pathname or alternate file reference, canonical resolution beyond the intended boundary, and an attempted read, write, copy, move, or delete under the tool process identity. <!-- SAF-TRACE: claims=SAF-T1105-C004 ; sources=SRC-mcp-tools-2026-07-28,SRC-cwe-22 -->

Token-only matching is insufficient because the security decision belongs on the decoded canonical object and must account for links, exact directory boundaries, alternate access paths, and changes between validation and use. <!-- SAF-TRACE: claims=SAF-T1105-C010,SAF-T1105-C013 ; sources=SRC-cwe-22,SRC-cwe-59 -->

The following inert event illustrates the minimum enriched audit shape used by the tested analytic. <!-- SAF-TRACE: claims=SAF-T1105-C011,SAF-T1105-C012 ; sources=SRC-google-mcp-logging-2025,SRC-cwe-22 -->

```json
{
  "event_type": "mcp_tool_call",
  "operation": "read_file",
  "requested_path": "../outside/sample.txt",
  "resolved_path": "/srv/agent/outside/sample.txt",
  "allowed_roots": ["/srv/agent/allowed"],
  "path_scope": "outside_allowed_root",
  "approved_override": false
}
```

## Evidence and Current State

The evidence class is Demonstrated because an end-to-end controlled reproduction reached an AWS-owned public MCP endpoint; the reviewed corpus does not establish hostile production exploitation. <!-- SAF-TRACE: claims=SAF-T1105-C005,SAF-T1105-C009 ; sources=SRC-varonis-cve-2026-4270,SRC-aws-cve-2026-4270 -->

Four examples were selected for direct boundary fit, consequence, currency, remediation clarity, and evidence quality. <!-- SAF-TRACE: claims=SAF-T1105-C005,SAF-T1105-C006,SAF-T1105-C007,SAF-T1105-C008 ; sources=SRC-aws-cve-2026-4270,SRC-aws-cve-2026-18953,SRC-aws-cve-2026-15415,SRC-vulncheck-cve-2026-74798 -->

- CVE-2026-4270: Coby Abrams and Varonis Threat Labs reproduced authenticated local-file content exposure after no-access/workdir bypass; AWS fixed versions 0.2.14 through 1.3.8 in 1.3.9. <!-- SAF-TRACE: claims=SAF-T1105-C005 ; sources=SRC-varonis-cve-2026-4270,SRC-aws-cve-2026-4270 -->
- CVE-2026-18953: AWS Transform MCP Server through 0.1.4 permitted an out-of-directory write through `savePath`, with bounded potential local code execution; AWS fixed it in 0.1.5 and credited Drew Raines. <!-- SAF-TRACE: claims=SAF-T1105-C006 ; sources=SRC-aws-cve-2026-18953 -->
- CVE-2026-15415: AWS HealthOmics MCP Server through 0.0.35 allowed traversal-sequence writes outside a workflow bundle; AWS fixed it in 0.0.36 and credited Rotimi Akinyele of Deriv. <!-- SAF-TRACE: claims=SAF-T1105-C007 ; sources=SRC-aws-cve-2026-15415 -->
- CVE-2026-74798: SiYuan before 3.7.4 accepted an unvalidated database identifier that could copy a readable external file into history and delete its original; the advisory credits alham-rizvi, who explicitly did not run the path on a live compiled kernel. <!-- SAF-TRACE: claims=SAF-T1105-C008 ; sources=SRC-vulncheck-cve-2026-74798,SRC-ghsa-cve-2026-74798 -->

### Evidence Summary

| Claim | Result | Sources |
|---|---|---|
| SAF-T1105-C001 | Tool invocation, validation, and access-control requirements | SRC-mcp-tools-2026-07-28 |
| SAF-T1105-C002 | File-resource path sanitization requirement | SRC-mcp-resources-2026 |
| SAF-T1105-C003 | Restricted-directory definition and consequences | SRC-cwe-22 |
| SAF-T1105-C004 | SAF behavior boundary | SRC-mcp-tools-2026-07-28; SRC-cwe-22 |
| SAF-T1105-C005 | Controlled public-endpoint demonstration | SRC-varonis-cve-2026-4270; SRC-aws-cve-2026-4270 |
| SAF-T1105-C006 | Direct arbitrary-write vulnerability | SRC-aws-cve-2026-18953 |
| SAF-T1105-C007 | Direct traversal-write vulnerability | SRC-aws-cve-2026-15415 |
| SAF-T1105-C008 | Direct read-and-delete vulnerability with test limitation | SRC-vulncheck-cve-2026-74798; SRC-ghsa-cve-2026-74798 |
| SAF-T1105-C009 | Bounded absence of hostile production evidence | SRC-aws-cve-2026-4270; SRC-aws-cve-2026-18953; SRC-aws-cve-2026-15415; SRC-vulncheck-cve-2026-74798 |
| SAF-T1105-C010 | Canonicalization, allowlist, privilege, isolation, and link controls | SRC-cwe-22; SRC-cwe-59 |
| SAF-T1105-C011 | MCP audit context and field guidance | SRC-google-mcp-logging-2025; SRC-mcp-tools-2026-07-28 |
| SAF-T1105-C012 | Deterministic canonical-containment analytic | SRC-cwe-22; SRC-google-mcp-logging-2025 |
| SAF-T1105-C013 | Limits of lexical traversal matching | SRC-cwe-22; SRC-cwe-59; SRC-aws-cve-2026-4270 |
| SAF-T1105-C014 | Context-dependent severity | SRC-cwe-22; SRC-aws-cve-2026-18953; SRC-vulncheck-cve-2026-74798 |
| SAF-T1105-C015 | Response and remediation sequence | SRC-google-mcp-logging-2025; SRC-aws-cve-2026-4270; SRC-aws-cve-2026-18953 |
| SAF-T1105-C016 | Analogous ATT&CK T1005 mapping | SRC-attack-t1005 |
| SAF-T1105-C017 | Conditional analogous ATT&CK T1083 mapping | SRC-attack-t1083 |

## Impact Assessment

Unauthorized reads can disclose local data; writes or deletes can corrupt state; and writes to executable configuration can create context-dependent code execution. <!-- SAF-TRACE: claims=SAF-T1105-C003,SAF-T1105-C006,SAF-T1105-C007,SAF-T1105-C008 ; sources=SRC-cwe-22,SRC-aws-cve-2026-18953,SRC-aws-cve-2026-15415,SRC-vulncheck-cve-2026-74798 -->

Risk rises with sensitive accessible files, write or delete power, privileged service identities, automated invocation, and executable targets; least privilege, isolation, approval, and read-only operation reduce it. <!-- SAF-TRACE: claims=SAF-T1105-C014 ; sources=SRC-cwe-22,SRC-aws-cve-2026-18953 -->

## Detection Methods

Use the tested [detection rule](detection-rule.yml) to compare the canonical resolved target with exact canonical allowed roots and to flag non-overridden operations that violate a no-access policy. <!-- SAF-TRACE: claims=SAF-T1105-C012 ; sources=SRC-cwe-22,SRC-google-mcp-logging-2025 -->

Log timestamp, agent and session identifiers, server, tool, operation, requested and resolved paths, allowed roots or access mode, validation decision, outcome, and approved-override state. <!-- SAF-TRACE: claims=SAF-T1105-C011,SAF-T1105-C012 ; sources=SRC-google-mcp-logging-2025,SRC-mcp-tools-2026-07-28 -->

The analytic is blind when canonical targets, roots, nested file references, or outcomes are absent or falsified; traversal-token matching alone misses non-lexical and alternate-path variants. <!-- SAF-TRACE: claims=SAF-T1105-C012,SAF-T1105-C013 ; sources=SRC-cwe-22,SRC-cwe-59 -->

## Mitigation Strategies

- Decode and canonicalize first, then enforce containment with an allowlist and exact path-component boundaries. <!-- SAF-TRACE: claims=SAF-T1105-C010,SAF-T1105-C013 ; sources=SRC-cwe-22 -->
- Resolve and re-check link targets, and minimize the interval between validation and the filesystem operation. <!-- SAF-TRACE: claims=SAF-T1105-C010,SAF-T1105-C013 ; sources=SRC-cwe-59,SRC-cwe-22 -->
- Run tools with least privilege and an OS-enforced filesystem sandbox; isolation limits impact but does not repair the validation defect. <!-- SAF-TRACE: claims=SAF-T1105-C010,SAF-T1105-C014 ; sources=SRC-cwe-22 -->
- Upgrade affected implementations to the vendor-fixed versions because the selected AWS bulletins provide no configuration-only workaround. <!-- SAF-TRACE: claims=SAF-T1105-C005,SAF-T1105-C006,SAF-T1105-C007 ; sources=SRC-aws-cve-2026-4270,SRC-aws-cve-2026-18953,SRC-aws-cve-2026-15415 -->
- During response, stop the affected path, preserve correlated audit records, scope files touched under the process identity, upgrade, and rotate secrets only when exposure is established. <!-- SAF-TRACE: claims=SAF-T1105-C015 ; sources=SRC-google-mcp-logging-2025,SRC-aws-cve-2026-4270,SRC-aws-cve-2026-18953 -->

## Related Techniques

- [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md) can deliver a malicious path or manipulate tool input; SAF-T1105 begins only when path resolution crosses the configured file boundary and an operation is attempted. <!-- SAF-TRACE: claims=SAF-T1105-C004 ; sources=SRC-mcp-tools-2026-07-28,SRC-cwe-22 -->
- [SAF-T1104: Over-Privileged Tool Abuse](../SAF-T1104/README.md) uses intentionally broad tool authority; SAF-T1105 instead requires a pathname or alternate-path bypass of an intended restriction. <!-- SAF-TRACE: claims=SAF-T1105-C004 ; sources=SRC-mcp-tools-2026-07-28,SRC-cwe-22 -->

## MITRE ATT&CK Mapping

- T1005, Data from Local System, is analogous for the read variant, but it describes collection after access rather than this path-boundary bypass. <!-- SAF-TRACE: claims=SAF-T1105-C016 ; sources=SRC-attack-t1005 -->
- T1083, File and Directory Discovery, is analogous only when the tool enumerates files or directories; a targeted read, write, or delete need not perform discovery. <!-- SAF-TRACE: claims=SAF-T1105-C017 ; sources=SRC-attack-t1083 -->

## References

- SRC-attack-t1005 — MITRE ATT&CK contributors, “Data from Local System (T1005),” official technique page, reviewed 2026-09-01.
- SRC-attack-t1083 — MITRE ATT&CK contributors and Austin Clark / c2defense, “File and Directory Discovery (T1083),” official technique page, reviewed 2026-09-01.
- SRC-aws-cve-2026-15415 — AWS Security, “CVE-2026-15415 — AWS HealthOmics MCP Server,” crediting Rotimi Akinyele, reviewed 2026-09-01.
- SRC-aws-cve-2026-18953 — AWS Security, “CVE-2026-18953 — AWS Transform MCP Server,” crediting Drew Raines, reviewed 2026-09-01.
- SRC-aws-cve-2026-4270 — AWS Security, “CVE-2026-4270 — AWS API MCP Server,” crediting Varonis Threat Labs, reviewed 2026-09-01.
- SRC-cwe-22 — CWE Content Team / MITRE, “CWE-22: Improper Limitation of a Pathname to a Restricted Directory,” version 4.20.
- SRC-cwe-59 — CWE Content Team / MITRE, “CWE-59: Improper Link Resolution Before File Access,” version 4.20.
- SRC-ghsa-cve-2026-74798 — SiYuan maintainers and alham-rizvi, “GHSA-43jx-gxq4-jpjc,” reviewed 2026-09-01.
- SRC-google-mcp-logging-2025 — Lanre Ogunmola and Biodun Awojobi, Google Cloud, “How to secure your remote MCP server on Google Cloud,” reviewed 2026-09-01.
- SRC-mcp-resources-2026 — Model Context Protocol contributors, “Resources,” protocol version 2026-07-28.
- SRC-mcp-tools-2026-07-28 — Model Context Protocol contributors, “Tools,” protocol version 2026-07-28.
- SRC-varonis-cve-2026-4270 — Coby Abrams and Varonis Threat Labs, “How We Found an LFI Vulnerability in AWS's Remote MCP Server,” reviewed 2026-09-01.
- SRC-vulncheck-cve-2026-74798 — VulnCheck and alham-rizvi, “SiYuan Kernel Path Traversal via database_clean MCP Tool,” reviewed 2026-09-01.

## Version History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-09-01 | /root/cleanroom_saf_t1105 (OpenAI Codex clean-room author) | Independent research, trace-linked technique, tested analytic, evidence review, and publication-rights review. |
