# SAF-T1203: Backdoored Server Binary

## Overview

- **Tactic**: Persistence (ATK-TA0003) <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2 -->
- **Technique ID**: SAF-T1203
- **Research Packet**: [research/techniques/SAF-T1203](../../research/techniques/SAF-T1203/) <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2 -->
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1203/traceability-ledger.yml) <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2 -->
- **Documentation Status**: Draft
- **Evidence Status**: Research-Derived
- **Severity**: High <!-- SAF-TRACE: claims=SAF-T1203-C018; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025 -->
- **Severity Rationale**: Replacement can give attacker code repeated execution with the server process's permissions and reachable capabilities; actual impact is bounded by that server's privileges, isolation, credentials, and connected tools or data. <!-- SAF-TRACE: claims=SAF-T1203-C018; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025 -->
- **First Observed**: Not observed in a production MCP incident in the reviewed authoritative corpus as of 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1203-C010; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025,SRC-redhat-cve-2026-44192 -->
- **Last Updated**: 2026-09-01 <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2 -->

## Scope

This technique covers post-approval or post-deployment replacement, patching, or infection of a configured MCP server executable or a support binary it directly loads. It crosses the host's time-of-use trust boundary: an executable path or server identity that was approved earlier is trusted again after its contents have changed. <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2,SRC-mitre-t1554 -->

### In Scope

- Altering a previously approved local MCP server executable at its configured path so that a later host connection runs attacker code. <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2,SRC-mitre-t1554 -->
- Replacing or patching a directly loaded support binary while preserving enough expected server behavior to avoid immediate operational discovery. <!-- SAF-TRACE: claims=SAF-T1203-C003,SAF-T1203-C005; sources=SRC-mitre-t1554,SRC-unit42-mcp-sampling-2025 -->

### Out of Scope

- Initial installation of a malicious server, even when the user is deceived into approving its command; that crosses an installation-consent boundary rather than a post-deployment integrity boundary. <!-- SAF-TRACE: claims=SAF-T1203-C002,SAF-T1203-C017; sources=SRC-mcp-sep-1024,SRC-mitre-attack-t1195 -->
- Malicious tool metadata, prompt injection, or covert tool behavior when the installed executable remains unchanged. <!-- SAF-TRACE: claims=SAF-T1203-C005,SAF-T1203-C017; sources=SRC-unit42-mcp-sampling-2025,SRC-mitre-t1505-v1.5 -->
- Compromise introduced before a consumer receives the software, which is a supply-chain mechanism, and persistence through a separately installed server extension or component. <!-- SAF-TRACE: claims=SAF-T1203-C017; sources=SRC-mitre-attack-t1195,SRC-mitre-t1505-v1.5 -->

### Distinguishing Characteristics

The defining observable is a content, digest, or signing-state change for an already configured server artifact, followed by execution under the same trusted path or identity. [SAF-T1006: Malicious MCP Server Distribution](../SAF-T1006/README.md) ends at first approval of an attacker-selected server; [SAF-T1001: Tool Poisoning Attack (TPA)](../SAF-T1001/README.md) changes protocol-visible tool metadata without requiring an on-disk binary change. <!-- SAF-TRACE: claims=SAF-T1203-C017; sources=SRC-mitre-attack-t1195,SRC-mitre-t1505-v1.5 -->

## Description

Current Model Context Protocol TypeScript SDK documentation describes local stdio connections in which the client spawns a configured command as a child process and exchanges JSON-RPC over standard input and output. A host that later launches the same path therefore relies on the continuing integrity of that path, not only on the user's earlier approval. <!-- SAF-TRACE: claims=SAF-T1203-C001; sources=SRC-mcp-ts-stdio-v2 -->

An adversary with sufficient write access can replace or patch that server executable, or a support binary it loads, and wait for the host to reconnect or restart it. ATT&CK documents the general persistence mechanism of modifying, replacing, or infecting routinely executed host software; applying that mechanism to an approved MCP server path is an inference from independently supported components, not a reported MCP incident. <!-- SAF-TRACE: claims=SAF-T1203-C003,SAF-T1203-C004; sources=SRC-mitre-t1554,SRC-mcp-ts-stdio-v2 -->

A malicious MCP server can retain legitimate functionality while performing covert behavior, as shown in Unit 42's controlled MCP demonstrations. That research supports concealment feasibility, but it begins with an already malicious connected server and does not demonstrate binary replacement. <!-- SAF-TRACE: claims=SAF-T1203-C005; sources=SRC-unit42-mcp-sampling-2025 -->

## Attack Vectors

- **Primary Vector**: Host-level write access to an already configured local server executable or its directly loaded support binary. <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2,SRC-mitre-t1554 -->
- **Secondary Vectors**: Exploitation of an arbitrary-file-write weakness that reaches the artifact, or abuse of an overly permissive update path; neither is this technique until replacement occurs. <!-- SAF-TRACE: claims=SAF-T1203-C009; sources=SRC-redhat-cve-2026-44192 -->
- **Affected Components**: MCP host or client, local MCP server process, executable and directly loaded support artifacts. <!-- SAF-TRACE: claims=SAF-T1203-C001,SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2 -->
- **Trust Boundary Crossed**: Continued host trust in a previously approved server path, version, digest, or signer. <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2,SRC-mitre-t1554 -->

## Technical Details

### Prerequisites

- The host uses a local-process transport that launches a configured server command. <!-- SAF-TRACE: claims=SAF-T1203-C001; sources=SRC-mcp-ts-stdio-v2 -->
- The adversary can modify the executable or a directly loaded artifact, whether through prior host access, an unsafe update channel, or an enabling file-write flaw. <!-- SAF-TRACE: claims=SAF-T1203-C003,SAF-T1203-C009; sources=SRC-mitre-t1554,SRC-redhat-cve-2026-44192 -->
- No effective pre-execution integrity decision prevents the changed artifact from running. <!-- SAF-TRACE: claims=SAF-T1203-C012; sources=SRC-nist-sp800-53r5.1 -->

### Attack Flow

1. **Setup**: Identify an approved local server path and the account that launches it. <!-- SAF-TRACE: claims=SAF-T1203-C001,SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2 -->
2. **Delivery**: Replace or patch that executable, or a support binary it directly loads, while retaining the expected path and interface. <!-- SAF-TRACE: claims=SAF-T1203-C003,SAF-T1203-C005; sources=SRC-mitre-t1554,SRC-unit42-mcp-sampling-2025 -->
3. **Trigger**: Wait for the host to connect, restart, or otherwise spawn the configured command. <!-- SAF-TRACE: claims=SAF-T1203-C001,SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2 -->
4. **Boundary Crossing**: The host reuses prior approval without detecting the artifact's changed identity. <!-- SAF-TRACE: claims=SAF-T1203-C002,SAF-T1203-C004; sources=SRC-mcp-sep-1024,SRC-mcp-ts-stdio-v2 -->
5. **Objective**: Execute attacker code repeatedly inside the trusted server process context. <!-- SAF-TRACE: claims=SAF-T1203-C003,SAF-T1203-C004; sources=SRC-mitre-t1554,SRC-mcp-ts-stdio-v2 -->
6. **Follow-On Activity**: Use only the permissions, credentials, tools, and data reachable from that process unless a separate technique expands access. <!-- SAF-TRACE: claims=SAF-T1203-C018; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025 -->

### Example Scenario

An administrator approves `/opt/example-mcp/server` and records its SHA-256 digest. Later, an attacker who already has write access substitutes an inert test artifact at the same path. At the next connection, the host launches the path; endpoint telemetry records a digest different from the approved baseline while the server still returns a benign health response. The safe fixture models only that mismatch and does not contain executable payloads. <!-- SAF-TRACE: claims=SAF-T1203-C004,SAF-T1203-C011; sources=SRC-mcp-ts-stdio-v2,SRC-mitre-det0336-v1 -->

```json
{
  "event_type": "mcp_server_process_start",
  "server_id": "example.local/benign-server",
  "executable_path": "/opt/example-mcp/server",
  "observed_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "approved_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "change_approved": false,
  "signature_valid": true
}
```
<!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1203-C001 | A current MCP TypeScript SDK local stdio client spawns the configured server command as a child process. | Demonstrated implementation fact | SRC-mcp-ts-stdio-v2: [MCP TypeScript SDK client transport](https://ts.sdk.modelcontextprotocol.io/v2/clients/connect) | SDK documentation does not establish tampering. | <!-- SAF-TRACE: claims=SAF-T1203-C001; sources=SRC-mcp-ts-stdio-v2 -->
| SAF-T1203-C004 | Replacing a configured MCP server artifact can turn later launches into a persistence trigger. | Research-Derived | SRC-mcp-ts-stdio-v2 and SRC-mitre-t1554: [SDK transport](https://ts.sdk.modelcontextprotocol.io/v2/clients/connect), [ATT&CK T1554](https://attack.mitre.org/techniques/T1554/) | No direct MCP replacement case was identified. | <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2,SRC-mitre-t1554 -->
| SAF-T1203-C005 | A malicious MCP server can preserve useful behavior while performing covert actions. | Demonstrated component | SRC-unit42-mcp-sampling-2025: [Unit 42 research](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) | The demonstrations start with a malicious connected server; they do not replace a binary. | <!-- SAF-TRACE: claims=SAF-T1203-C005; sources=SRC-unit42-mcp-sampling-2025 -->
| SAF-T1203-C011 | Hash baselines, file-integrity events, and process starts can expose unexpected binary changes followed by execution. | Research-Derived detection | SRC-mitre-det0336-v1: [ATT&CK DET0336](https://attack.mitre.org/detectionstrategies/DET0336/) | Detection depends on complete artifact inventory and trustworthy baselines. | <!-- SAF-TRACE: claims=SAF-T1203-C011; sources=SRC-mitre-det0336-v1 -->

### Current State

- **Affected Environments**: Local-process MCP deployments in which a host repeatedly launches an executable path and the artifact is writable through an attacker-reachable path. <!-- SAF-TRACE: claims=SAF-T1203-C001,SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2,SRC-mitre-t1554 -->
- **Known Exploitation**: No direct production MCP binary-replacement incident was identified in the reviewed authoritative corpus; the evidence is a synthesis of MCP process behavior, host-binary incidents, and an adjacent MCP demonstration. <!-- SAF-TRACE: claims=SAF-T1203-C010; sources=SRC-mcp-ts-stdio-v2,SRC-mandiant-unc3886-2024,SRC-unit42-mcp-sampling-2025 -->
- **Available Protections**: Pre-execution integrity verification, centrally managed file-integrity monitoring, restrictive write permissions, and controlled artifact changes address the defining boundary. <!-- SAF-TRACE: claims=SAF-T1203-C012,SAF-T1203-C014; sources=SRC-nist-sp800-53r5.1,SRC-mitre-det0336-v1 -->
- **Residual Risk**: A maliciously approved baseline, compromised signing infrastructure, in-memory modification, or unmonitored support library can evade a simple file-hash comparison. <!-- SAF-TRACE: claims=SAF-T1203-C013,SAF-T1203-C015; sources=SRC-nist-code-signing-2018,SRC-mitre-det0336-v1 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| UNC3886 replacement of `tac_plus` | 2024 report; compromised network device | Mandiant observed replacement of the legitimate daemon with a credential-logging binary; rebuild from trusted media and credential response are environment-dependent. | Historical production analogy; closest post-deployment replacement mechanism. | Not MCP. | <!-- SAF-TRACE: claims=SAF-T1203-C006; sources=SRC-mandiant-unc3886-2024 -->
| SolarWinds SUNBURST | 2020 incident; signed Orion update DLL | Trojanized signed updates enabled a backdoor across victim environments; vendor and incident-response remediation followed. | Historical production supply-chain analogy. | Introduced before consumer deployment, so it is outside this technique's boundary. | <!-- SAF-TRACE: claims=SAF-T1203-C007,SAF-T1203-C017; sources=SRC-mandiant-solarwinds,SRC-mitre-attack-t1195 -->
| CVE-2024-3094 | 2024; xz 5.6.0 and 5.6.1 upstream tarballs | Malicious liblzma code could interfere with the OpenSSH daemon; affected builds were withdrawn and Red Hat reported no affected RHEL release. | Historical backdoor analogy. | NVD's reviewed record reported no known exploitation; not MCP and not post-deployment replacement. | <!-- SAF-TRACE: claims=SAF-T1203-C008; sources=SRC-redhat-cve-2024-3094,SRC-nvd-cve-2024-3094 -->
| Unit 42 malicious MCP server demonstrations | 2025; controlled coding-copilot environment | A connected malicious server preserved legitimate functionality while enabling covert prompt and file operations; publication recommends isolating trust boundaries and reviewing server behavior. | Adjacent direct MCP demonstration. | Does not replace an installed binary and cannot raise this technique above Research-Derived. | <!-- SAF-TRACE: claims=SAF-T1203-C005; sources=SRC-unit42-mcp-sampling-2025 -->

### Real-World Incidents or Demonstrations

#### UNC3886 TACACS+ Daemon Replacement (2024)

Mandiant reported observing UNC3886 replace `/usr/bin/tac_plus` with a malicious credential-logging binary. The event establishes the real-world feasibility of preserving a daemon path while changing its code, but it involved network-device administration rather than MCP. <!-- SAF-TRACE: claims=SAF-T1203-C006; sources=SRC-mandiant-unc3886-2024 -->

#### Unit 42 MCP Demonstrations (2025)

Unit 42 demonstrated malicious MCP servers that retained legitimate functionality while carrying out covert behavior across conversation turns. This supports the concealment component only; the threat model explicitly began after a malicious server was connected and excluded installation. <!-- SAF-TRACE: claims=SAF-T1203-C005; sources=SRC-unit42-mcp-sampling-2025 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | A replaced server can access data and credentials available to its process, but not resources outside that process's effective reach without another technique. | <!-- SAF-TRACE: claims=SAF-T1203-C018; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025 -->
| Integrity | High | Attacker code can alter outputs or invoke capabilities granted to the server process; isolation and least privilege bound the effect. | <!-- SAF-TRACE: claims=SAF-T1203-C018; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025 -->
| Availability | Medium | A malformed replacement can prevent the server from starting, while a compatible backdoor may leave normal service available. | <!-- SAF-TRACE: claims=SAF-T1203-C005,SAF-T1203-C018; sources=SRC-unit42-mcp-sampling-2025,SRC-mcp-ts-stdio-v2 -->
| Scope | Local | The initial execution scope is the host and server account; connected privileges and tools determine any expansion. | <!-- SAF-TRACE: claims=SAF-T1203-C018; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025 -->

### Severity Conditions

- **Severity increases when**: The server runs with broad filesystem, credential, network, or tool access and starts automatically or frequently. <!-- SAF-TRACE: claims=SAF-T1203-C018; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025 -->
- **Severity decreases when**: The server runs in a confined low-privilege environment, its artifact is immutable to the process account, and each launch verifies an independently managed digest. <!-- SAF-TRACE: claims=SAF-T1203-C012,SAF-T1203-C014; sources=SRC-nist-sp800-53r5.1,SRC-mitre-det0336-v1 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| MCP host or endpoint process telemetry | Configured server process start | `event_type`, `server_id`, `executable_path`, `observed_sha256`, `approved_sha256`, `change_approved` | Resolve the executable path and compute the digest at execution time or from a trusted execution-control event. | <!-- SAF-TRACE: claims=SAF-T1203-C011; sources=SRC-mitre-det0336-v1 -->
| File-integrity and change-management records | Artifact modification and approved deployment | artifact path, old and new digest, actor, timestamp, approval state | Correlate changes with the next server start and keep the baseline outside the server's write boundary. | <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->

### Indicators of Compromise (IoCs)

- No universal digest, filename, or signer identifies this technique; indicators are deployment-specific deviations from an approved artifact. <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->

### Behavioral Indicators

- A configured server starts with a digest different from the approved digest and no corresponding approved change. <!-- SAF-TRACE: claims=SAF-T1203-C011; sources=SRC-mitre-det0336-v1 -->
- A file-integrity event on the server path is followed by process execution outside a patch or deployment window. <!-- SAF-TRACE: claims=SAF-T1203-C011; sources=SRC-mitre-det0336-v1 -->
- Signature validity alone does not clear the event because compromised signing infrastructure can produce signed malicious code. <!-- SAF-TRACE: claims=SAF-T1203-C013; sources=SRC-nist-code-signing-2018 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml). <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->

- **Analytic Goal**: Detect execution of a registered local MCP server whose observed digest differs from its approved digest without an approved change. <!-- SAF-TRACE: claims=SAF-T1203-C011; sources=SRC-mitre-det0336-v1 -->
- **Rule Status**: Test. <!-- SAF-TRACE: claims=SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->
- **Detection Logic**: Require a registered server process-start event, valid SHA-256 values, a mismatch, and `change_approved: false`. <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->
- **Correlation Window**: One server-process-start decision; upstream collection may correlate the immediately preceding file change. <!-- SAF-TRACE: claims=SAF-T1203-C011; sources=SRC-mitre-det0336-v1 -->
- **Known False Positives**: Legitimate upgrades or local rebuilds whose new digest was not entered into change management before first launch. <!-- SAF-TRACE: claims=SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->
- **Known Limitations**: In-memory patching, malicious baseline enrollment, compromised build or signing infrastructure, missing support-library inventory, and absent execution-time hashing. <!-- SAF-TRACE: claims=SAF-T1203-C013,SAF-T1203-C015; sources=SRC-nist-code-signing-2018,SRC-mitre-det0336-v1 -->
- **Tuning Guidance**: Maintain per-server digests in a separately controlled registry and update them only through an authenticated, audited deployment workflow. <!-- SAF-TRACE: claims=SAF-T1203-C014,SAF-T1203-C015; sources=SRC-nist-sp800-53r5.1,SRC-mitre-det0336-v1 -->

### Validation

- **Test Data**: [test-logs.json](test-logs.json) <!-- SAF-TRACE: claims=SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->
- **Validation Script**: [test_detection_rule.py](test_detection_rule.py) <!-- SAF-TRACE: claims=SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->
- **Expected Result**: Ten fixtures pass: three alerts and seven non-alerts, including uppercase digest input to verify normalization. <!-- SAF-TRACE: claims=SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->
- **Last Validated**: 2026-09-01 <!-- SAF-TRACE: claims=SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->
- **Feasibility Waiver**: None. <!-- SAF-TRACE: claims=SAF-T1203-C015; sources=SRC-mitre-det0336-v1 -->

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAF-M-45/README.md)**: Compare the resolved executable and inventoried support artifacts with an independently managed approved digest immediately before launch. <!-- SAF-TRACE: claims=SAF-T1203-C012,SAF-T1203-C014; sources=SRC-nist-sp800-53r5.1 -->
2. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Prevent the runtime server account and unprivileged users from changing the approved executable, support artifacts, or digest registry. <!-- SAF-TRACE: claims=SAF-T1203-C014; sources=SRC-nist-sp800-53r5.1,SRC-mitre-det0336-v1 -->
3. **Code signing plus digest pinning**: Validate signer and artifact digest; do not treat a valid signature as sufficient where signing keys or infrastructure could be compromised. <!-- SAF-TRACE: claims=SAF-T1203-C013,SAF-T1203-C014; sources=SRC-nist-code-signing-2018,SRC-nist-sp800-53r5.1 -->

### Detective Controls

1. **[SAF-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAF-M-45/README.md)**: Record failed comparisons and block or alert before the first unapproved launch. <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C012; sources=SRC-mitre-det0336-v1,SRC-nist-sp800-53r5.1 -->
2. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Alert on denied and successful writes to configured server paths, then correlate them with process starts. <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C014; sources=SRC-mitre-det0336-v1 -->

### Response Procedures

#### Immediate Actions

- Stop launching the affected server path and isolate the host or server account from sensitive connected resources until artifact provenance is established. <!-- SAF-TRACE: claims=SAF-T1203-C016; sources=SRC-nist-sp800-53r5.1 -->
- Preserve the changed artifact, digest, filesystem metadata, process-start records, and change approvals before restoration. <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C016; sources=SRC-mitre-det0336-v1,SRC-nist-sp800-53r5.1 -->

#### Investigation Steps

- Compare the resolved executable and loaded support artifacts with a trusted release or internal build record; determine when and by whom each changed. <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C016; sources=SRC-mitre-det0336-v1,SRC-nist-sp800-53r5.1 -->
- Review every execution after the first unexplained change and scope accessible credentials, tools, data, and downstream actions to the server account. <!-- SAF-TRACE: claims=SAF-T1203-C018; sources=SRC-mcp-ts-stdio-v2,SRC-unit42-mcp-sampling-2025 -->

#### Remediation

- Restore the server from a trusted artifact, correct write permissions and the update path, and establish a new independently verified baseline before reconnection. <!-- SAF-TRACE: claims=SAF-T1203-C012,SAF-T1203-C014; sources=SRC-nist-sp800-53r5.1,SRC-mitre-det0336-v1 -->
- Rotate credentials shown by investigation to have been reachable from the affected process and validate that subsequent starts match the approved artifact. <!-- SAF-TRACE: claims=SAF-T1203-C016,SAF-T1203-C018; sources=SRC-nist-sp800-53r5.1,SRC-mcp-ts-stdio-v2 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1006: Malicious MCP Server Distribution](../SAF-T1006/README.md) | Alternative | Distribution concerns initial delivery or installation; SAF-T1203 requires an already trusted artifact to change afterward. | <!-- SAF-TRACE: claims=SAF-T1203-C017; sources=SRC-mitre-attack-t1195 -->
| [SAF-T1001: Tool Poisoning Attack (TPA)](../SAF-T1001/README.md) | Alternative or co-occurring | Tool poisoning changes protocol-visible instructions or metadata; SAF-T1203 requires executable or directly loaded binary modification. | <!-- SAF-TRACE: claims=SAF-T1203-C005,SAF-T1203-C017; sources=SRC-unit42-mcp-sampling-2025,SRC-mitre-t1505-v1.5 -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1554](https://attack.mitre.org/techniques/T1554/) | Compromise Host Software Binary | Direct | Both behaviors modify or replace routinely executed host software to obtain persistent execution; SAF-T1203 narrows the artifact to a configured MCP server or directly loaded support binary. | <!-- SAF-TRACE: claims=SAF-T1203-C003; sources=SRC-mitre-t1554 -->

## References

1. **SRC-mcp-ts-stdio-v2**: [MCP TypeScript SDK v2, Connect to local servers](https://ts.sdk.modelcontextprotocol.io/v2/clients/connect) — MCP TypeScript SDK maintainers; current v2 documentation reviewed 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1203-C001; sources=SRC-mcp-ts-stdio-v2 -->
2. **SRC-mcp-sep-1024**: [SEP-1024: MCP Client Security Requirements for Local Servers](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) — Den Delimarsky, 2025. <!-- SAF-TRACE: claims=SAF-T1203-C002; sources=SRC-mcp-sep-1024 -->
3. **SRC-mitre-t1554**: [ATT&CK T1554: Compromise Host Software Binary](https://attack.mitre.org/techniques/T1554/) — MITRE ATT&CK, version 2.2, 2026. <!-- SAF-TRACE: claims=SAF-T1203-C003,SAF-T1203-C004; sources=SRC-mitre-t1554 -->
4. **SRC-mitre-det0336-v1**: [ATT&CK DET0336: Detect Compromise of Host Software Binaries](https://attack.mitre.org/detectionstrategies/DET0336/) — MITRE ATT&CK, version 1.0, 2026. <!-- SAF-TRACE: claims=SAF-T1203-C011,SAF-T1203-C014; sources=SRC-mitre-det0336-v1 -->
5. **SRC-mitre-attack-t1195**: [ATT&CK T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/) — MITRE ATT&CK, version 1.7, 2025. <!-- SAF-TRACE: claims=SAF-T1203-C017; sources=SRC-mitre-attack-t1195 -->
6. **SRC-mitre-t1505-v1.5**: [ATT&CK T1505: Server Software Component](https://attack.mitre.org/techniques/T1505/) — MITRE ATT&CK, version 1.5, 2025. <!-- SAF-TRACE: claims=SAF-T1203-C017; sources=SRC-mitre-t1505-v1.5 -->
7. **SRC-mandiant-unc3886-2024**: [Cloaked and Covert: Uncovering UNC3886 Espionage Operations](https://cloud.google.com/blog/topics/threat-intelligence/uncovering-unc3886-espionage-operations) — Punsaen Boonyakarn, Shawn Chew, Logeswaran Nadarajan, Mathew Potaczek, Jakub Jozwiak, and Alex Marvi, 2024. <!-- SAF-TRACE: claims=SAF-T1203-C006; sources=SRC-mandiant-unc3886-2024 -->
8. **SRC-mandiant-solarwinds**: [Highly Evasive Attacker Leverages SolarWinds Supply Chain](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor/) — FireEye/Mandiant research team, 2020. <!-- SAF-TRACE: claims=SAF-T1203-C007; sources=SRC-mandiant-solarwinds -->
9. **SRC-redhat-cve-2024-3094**: [CVE-2024-3094](https://access.redhat.com/security/cve/cve-2024-3094) — Red Hat Product Security, 2024. <!-- SAF-TRACE: claims=SAF-T1203-C008; sources=SRC-redhat-cve-2024-3094 -->
10. **SRC-nvd-cve-2024-3094**: [NVD CVE-2024-3094 record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094) — NIST National Vulnerability Database, last modified 2026-06-17. <!-- SAF-TRACE: claims=SAF-T1203-C008; sources=SRC-nvd-cve-2024-3094 -->
11. **SRC-unit42-mcp-sampling-2025**: [New Prompt Injection Attack Vectors Through MCP Sampling](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) — Yongzhe Huang, Akshata Rao, Changjiang Li, Yang Ji, and Wenjun Hu, 2025. <!-- SAF-TRACE: claims=SAF-T1203-C005,SAF-T1203-C010,SAF-T1203-C018; sources=SRC-unit42-mcp-sampling-2025 -->
12. **SRC-redhat-cve-2026-44192**: [CVE-2026-44192](https://access.redhat.com/security/cve/cve-2026-44192) — Red Hat Product Security; discovery credited to Laura Pardo, Red Hat Inc., 2026. <!-- SAF-TRACE: claims=SAF-T1203-C009; sources=SRC-redhat-cve-2026-44192 -->
13. **SRC-nist-sp800-53r5.1**: [NIST SP 800-53 Rev. 5.1 derived OSCAL control catalog](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf) — Joint Task Force, 2021. <!-- SAF-TRACE: claims=SAF-T1203-C012,SAF-T1203-C014,SAF-T1203-C016; sources=SRC-nist-sp800-53r5.1 -->
14. **SRC-nist-code-signing-2018**: [Security Considerations for Code Signing](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.01262018.pdf) — David Cooper, Andrew Regenscheid, Murugiah Souppaya, Christopher Bean, Mike Boyle, Dorothy Cooley, and Michael Jenkins, 2018. <!-- SAF-TRACE: claims=SAF-T1203-C013; sources=SRC-nist-code-signing-2018 -->

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Initial independent clean-room draft | OpenAI Codex clean-room research agent | <!-- SAF-TRACE: claims=SAF-T1203-C004; sources=SRC-mcp-ts-stdio-v2 -->
