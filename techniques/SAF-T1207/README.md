# SAF-T1207: Hijack Update Mechanism

## Overview

- **Tactic**: Persistence (ATK-TA0003) <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C016; sources=SRC-mitre-ta0003,SRC-mitre-t1554 -->
- **Technique ID**: SAF-T1207
- **Research Packet**: [research/techniques/SAF-T1207](../../research/techniques/SAF-T1207/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1207/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Research-Derived
- **Severity**: High <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C010,SAF-T1207-C011; sources=SRC-mitre-ta0003,SRC-mandiant-solarwinds,SRC-mandiant-3cx -->
- **Severity Rationale**: High when a component activates the replacement with the agent's privileges and durable configuration; scope falls with isolation, digest pinning, and approval gates. <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C017; sources=SRC-mitre-ta0003,SRC-google-ai-blueprint -->
- **First Observed**: No qualifying direct production MCP or agentic-system incident identified through 2026-09-01. <!-- SAF-TRACE: claims=SAF-T1207-C006,SAF-T1207-C012; sources=SRC-google-ai-blueprint,SRC-google-supply-chain,SRC-socket-axios -->
- **Last Updated**: 2026-09-01

## Scope

SAF-T1207 covers an adversary causing the normal update path of an already trusted MCP or agentic component to accept and activate an attacker-selected replacement, preserving adversary-controlled code across restarts. <!-- SAF-TRACE: claims=SAF-T1207-C001; sources=SRC-vscode-agent-plugins,SRC-mitre-ta0003,SRC-mitre-t1554 -->

### In Scope

- Compromise or impersonation of an update source, release metadata, artifact store, publisher account, or signing authority after a component is trusted. <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C007; sources=SRC-tuf-security,SRC-tuf-metadata -->
- Acceptance and activation through a component manager's ordinary update or dynamic package-resolution behavior. <!-- SAF-TRACE: claims=SAF-T1207-C005,SAF-T1207-C012; sources=SRC-vscode-agent-plugins,SRC-socket-axios -->

### Out of Scope

- A malicious component selected during first installation; the defining precondition here is replacement of an already trusted installation. <!-- SAF-TRACE: claims=SAF-T1207-C001; sources=SRC-mitre-ta0003 -->
- Tool-description, prompt, response, or other runtime behavior drift without software replacement; those signals require a different analytic boundary. <!-- SAF-TRACE: claims=SAF-T1207-C006; sources=SRC-google-ai-blueprint -->
- Credential theft, lateral movement, or impact after execution except as follow-on activity. <!-- SAF-TRACE: claims=SAF-T1207-C010,SAF-T1207-C011; sources=SRC-mandiant-solarwinds,SRC-mandiant-3cx -->

### Distinguishing Characteristics

The analyst must establish a trusted prior version, a later replacement accepted through an update path, and activation of code or dependencies that do not match the approved release record. This distinguishes update hijacking from first-install poisoning and runtime-only mutation. <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C003,SAF-T1207-C017; sources=SRC-mcp-versioning,SRC-tuf-metadata,SRC-google-ai-blueprint -->

## Description

MCP and agentic components may be represented by registry metadata while executable packages remain in npm, PyPI, Docker Hub, or another package registry. The official MCP Registry maps server versions to package locations and delegates code scanning to upstream registries and downstream aggregators. <!-- SAF-TRACE: claims=SAF-T1207-C002,SAF-T1207-C004; sources=SRC-mcp-registry-about,SRC-mcp-registry-package-types -->

An updater, marketplace, package runner, or component manager can therefore become the activation boundary. VS Code, for example, periodically checks agent plugins for updates and pulls marketplace repositories or checks external versions; external npm and PyPI plugins require a manual update action. <!-- SAF-TRACE: claims=SAF-T1207-C005; sources=SRC-vscode-agent-plugins -->

This technique is Research-Derived. Current authoritative guidance expressly warns that a previously benign MCP integration can be silently updated with malicious dependencies, but the reviewed record did not establish a qualifying direct production incident that completed the full trusted-update-to-persistent-agent-control sequence. <!-- SAF-TRACE: claims=SAF-T1207-C006,SAF-T1207-C012; sources=SRC-google-ai-blueprint,SRC-google-supply-chain,SRC-socket-axios -->

## Attack Vectors

- **Primary Vector**: A compromised publisher, registry, repository, update service, metadata role, artifact store, or signing key supplies an attacker-selected later version. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C015; sources=SRC-tuf-security,SRC-tuf-metadata,SRC-mitre-t1195-002 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1207-C012,SAF-T1207-C013,SAF-T1207-C014; sources=SRC-socket-axios,SRC-electron-ghsa,SRC-sparkle-security -->
  - Dynamic dependency resolution admits a malicious transitive version during update or fresh execution. <!-- SAF-TRACE: claims=SAF-T1207-C012; sources=SRC-socket-axios -->
  - A verification flaw allows a replaced package to pass the updater's trust decision. <!-- SAF-TRACE: claims=SAF-T1207-C013,SAF-T1207-C014; sources=SRC-electron-ghsa,SRC-sparkle-security -->
- **Affected Components**: MCP servers and packages, agent plugins, extensions, component managers, registries, feeds, repositories, signing services, and artifact stores. <!-- SAF-TRACE: claims=SAF-T1207-C002,SAF-T1207-C005,SAF-T1207-C006; sources=SRC-mcp-registry-about,SRC-vscode-agent-plugins,SRC-google-ai-blueprint -->
- **Trust Boundary Crossed**: Update authority and distribution enter the local component manager, which decides whether to accept and activate the replacement. <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C007; sources=SRC-tuf-security,SRC-tuf-metadata -->

## Technical Details

### Prerequisites

- The victim already trusts and runs a component through a manager capable of update or dynamic resolution. <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C005; sources=SRC-vscode-agent-plugins,SRC-mitre-ta0003 -->
- The adversary controls, impersonates, or bypasses at least one accepted update authority or artifact path. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C013,SAF-T1207-C014; sources=SRC-tuf-security,SRC-electron-ghsa,SRC-sparkle-security -->
- Approval records, expected digests, provenance, signer identity, or version constraints are absent, bypassed, or not enforced at activation. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-google-ai-blueprint -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies a publisher, package, feed, repository, metadata role, or updater trusted by deployed components. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C015; sources=SRC-tuf-security,SRC-mitre-t1195-002 -->
2. **Delivery**: The controlled path presents a later version or dependency graph containing attacker-selected code. <!-- SAF-TRACE: claims=SAF-T1207-C003,SAF-T1207-C012; sources=SRC-mcp-versioning,SRC-socket-axios -->
3. **Trigger or Execution**: An automatic check, administrator update, restart, or dynamic runner resolves and activates the replacement. <!-- SAF-TRACE: claims=SAF-T1207-C005,SAF-T1207-C012; sources=SRC-vscode-agent-plugins,SRC-socket-axios -->
4. **Boundary Crossing**: The component manager accepts the release despite an unapproved digest, source, signer, version, or provenance record. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-google-ai-blueprint -->
5. **Objective**: The trusted component identity now launches adversary-controlled code with the component's privileges and integrations. <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C016; sources=SRC-mitre-ta0003,SRC-mitre-t1554 -->
6. **Follow-On Activity**: The replacement may access agent-connected data or services; such activity must be separately attributed from the update event. <!-- SAF-TRACE: claims=SAF-T1207-C006,SAF-T1207-C010,SAF-T1207-C011; sources=SRC-google-ai-blueprint,SRC-mandiant-solarwinds,SRC-mandiant-3cx -->

### Example Scenario

An organization has approved `example-mcp` version 2.4.1 and its digest. A compromised update source advertises 2.4.2; the component manager records activation from the expected source but the digest and signer do not match the approved release. The inert event below illustrates detection input, not exploit code. <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-google-ai-blueprint -->

```json
{"event.action":"component_update_activated","component.id":"example-mcp","component.version":"2.4.2","artifact.digest_matches_approved":false,"signer.matches_approved":false}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1207-C001 | A normal updater that activates an attacker-selected replacement can preserve adversary code across restarts. | Research-Derived | SRC-mitre-ta0003; SRC-mitre-t1554; SRC-vscode-agent-plugins | Framework and implementation sources support components, not a direct MCP incident. | <!-- SAF-TRACE: claims=SAF-T1207-C001; sources=SRC-mitre-ta0003,SRC-mitre-t1554,SRC-vscode-agent-plugins -->
| SAF-T1207-C002 | The MCP Registry stores metadata that maps server versions to external package locations. | Implementation fact | SRC-mcp-registry-about; SRC-mcp-registry-package-types | Host-specific consumption is outside the Registry contract. | <!-- SAF-TRACE: claims=SAF-T1207-C002; sources=SRC-mcp-registry-about,SRC-mcp-registry-package-types -->
| SAF-T1207-C003 | Published MCP server metadata uses unique immutable versions and latest-version ordering. | Implementation fact | SRC-mcp-versioning | Aggregators and hosts may apply additional policy. | <!-- SAF-TRACE: claims=SAF-T1207-C003; sources=SRC-mcp-versioning -->
| SAF-T1207-C004 | The MCP Registry delegates code scanning to package registries and downstream aggregators. | Implementation fact | SRC-mcp-registry-about | Delegation does not describe every downstream control. | <!-- SAF-TRACE: claims=SAF-T1207-C004; sources=SRC-mcp-registry-about -->
| SAF-T1207-C005 | VS Code agent-plugin update checks can pull marketplace repositories or inspect external versions. | Implementation fact | SRC-vscode-agent-plugins | One host implementation is not universal. | <!-- SAF-TRACE: claims=SAF-T1207-C005; sources=SRC-vscode-agent-plugins -->
| SAF-T1207-C006 | Mandiant guidance identifies silently updated malicious dependencies in previously benign MCP integrations as a supply-chain risk. | Research finding | SRC-google-ai-blueprint | Guidance states risk, not a named qualifying incident. | <!-- SAF-TRACE: claims=SAF-T1207-C006; sources=SRC-google-ai-blueprint -->
| SAF-T1207-C007 | Signed metadata, hashes, thresholds, expiry, and version/freshness checks constrain repository or key compromise. | Protocol normative | SRC-tuf-security; SRC-tuf-metadata | TUF controls apply only when implemented correctly. | <!-- SAF-TRACE: claims=SAF-T1207-C007; sources=SRC-tuf-security,SRC-tuf-metadata -->
| SAF-T1207-C008 | VS Code extension updates are automatically applied by default and marketplace signatures are verified on install. | Implementation fact | SRC-vscode-extension-marketplace; SRC-vscode-extension-security | Agent plugins and extensions have different update paths. | <!-- SAF-TRACE: claims=SAF-T1207-C008; sources=SRC-vscode-extension-marketplace,SRC-vscode-extension-security -->
| SAF-T1207-C009 | Enterprise policy can constrain extension versions, plugin marketplaces, and MCP sources. | Implementation fact | SRC-vscode-enterprise-extensions; SRC-vscode-ai-governance | Product-specific controls require correct policy distribution. | <!-- SAF-TRACE: claims=SAF-T1207-C009; sources=SRC-vscode-enterprise-extensions,SRC-vscode-ai-governance -->
| SAF-T1207-C010 | SolarWinds distributed digitally signed trojanized Orion updates that executed after installation. | Observed historical analogy | SRC-mandiant-solarwinds | Traditional software, not MCP or agentic software. | <!-- SAF-TRACE: claims=SAF-T1207-C010; sources=SRC-mandiant-solarwinds -->
| SAF-T1207-C011 | The 3CX compromise delivered a trojanized legitimate application after compromise of build environments. | Observed historical analogy | SRC-mandiant-3cx | Traditional software and a cascading supply-chain incident, not MCP. | <!-- SAF-TRACE: claims=SAF-T1207-C011; sources=SRC-mandiant-3cx -->
| SAF-T1207-C012 | Malicious Axios 1.14.1 could resolve through normal ranges used by sampled MCP servers. | Adjacent observed incident | SRC-google-supply-chain; SRC-socket-axios | Exposure was dependency resolution; the MCP servers themselves were not shown compromised. | <!-- SAF-TRACE: claims=SAF-T1207-C012; sources=SRC-google-supply-chain,SRC-socket-axios -->
| SAF-T1207-C013 | Electron's updater could accept a maliciously modified nested application under affected conditions. | Disclosed vulnerability | SRC-electron-ghsa | Updater flaw is non-MCP and no exploitation was established. | <!-- SAF-TRACE: claims=SAF-T1207-C013; sources=SRC-electron-ghsa -->
| SAF-T1207-C014 | Sparkle before 2.6.4 allowed replacement of a signed update in a way that bypassed EdDSA checks. | Disclosed vulnerability | SRC-sparkle-security | Non-MCP updater flaw; exploitation is not established here. | <!-- SAF-TRACE: claims=SAF-T1207-C014; sources=SRC-sparkle-security -->
| SAF-T1207-C015 | ATT&CK T1195.002 includes manipulation of software update and distribution mechanisms. | Framework inference | SRC-mitre-t1195-002 | ATT&CK maps supply-chain delivery under Initial Access, not this persistence-specific SAF boundary. | <!-- SAF-TRACE: claims=SAF-T1207-C015; sources=SRC-mitre-t1195-002 -->
| SAF-T1207-C016 | ATT&CK Persistence covers replacing or hijacking legitimate code, and T1554 covers persistent host-binary replacement. | Framework inference | SRC-mitre-ta0003; SRC-mitre-t1554 | T1554 emphasizes host modification rather than upstream update delivery. | <!-- SAF-TRACE: claims=SAF-T1207-C016; sources=SRC-mitre-ta0003,SRC-mitre-t1554 -->
| SAF-T1207-C017 | Comparing activation events with an approved digest, source, signer, version, and verification record is a feasible detection design. | Research finding | SRC-tuf-metadata; SRC-google-ai-blueprint; SRC-mitre-t1195-002 | Requires normalized lifecycle telemetry and an independent approved-release inventory. | <!-- SAF-TRACE: claims=SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-google-ai-blueprint,SRC-mitre-t1195-002 -->
| SAF-T1207-C018 | Investigation requires contemporaneous resolution/build logs, artifact snapshots, and network telemetry; recovery should restore vetted artifacts and harden the update path. | Research finding | SRC-socket-axios; SRC-google-supply-chain | Historical reconstruction may remain incomplete when transient state was not retained. | <!-- SAF-TRACE: claims=SAF-T1207-C018; sources=SRC-socket-axios,SRC-google-supply-chain -->

### Current State

- **Affected Environments**: Systems that update MCP packages, agent plugins, extensions, or dependencies from publisher-controlled repositories, registries, marketplaces, or feeds. <!-- SAF-TRACE: claims=SAF-T1207-C002,SAF-T1207-C005,SAF-T1207-C006; sources=SRC-mcp-registry-about,SRC-vscode-agent-plugins,SRC-google-ai-blueprint -->
- **Known Exploitation**: No qualifying direct production MCP or agentic-system example was identified; Axios/MCP exposure is adjacent evidence. <!-- SAF-TRACE: claims=SAF-T1207-C006,SAF-T1207-C012; sources=SRC-google-ai-blueprint,SRC-google-supply-chain,SRC-socket-axios -->
- **Available Protections**: Release pinning, signed metadata, digest and provenance verification, threshold keys, expiry/freshness checks, allowlists, and controlled marketplaces. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C009; sources=SRC-tuf-security,SRC-tuf-metadata,SRC-vscode-enterprise-extensions,SRC-vscode-ai-governance -->
- **Residual Risk**: Publisher or build compromise may still produce apparently legitimate releases, and dynamic resolution can change without local source changes. <!-- SAF-TRACE: claims=SAF-T1207-C010,SAF-T1207-C011,SAF-T1207-C012; sources=SRC-mandiant-solarwinds,SRC-mandiant-3cx,SRC-socket-axios -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Axios 1.14.1 supply-chain incident | 2026-03; npm consumers and sampled MCP-server dependency graphs | Malicious dependency delivered a backdoor; versions were removed rapidly, and deterministic installs/pinning reduce exposure. | Adjacent incident | Does not prove an installed MCP server was replaced and persistently activated. | <!-- SAF-TRACE: claims=SAF-T1207-C012; sources=SRC-google-supply-chain,SRC-socket-axios -->
| SolarWinds SUNBURST | 2020; Orion updates | Signed trojanized updates installed a backdoor; response required detection, containment, and rebuilding or updating affected software. | Historical analogy | Non-agentic enterprise software. | <!-- SAF-TRACE: claims=SAF-T1207-C010; sources=SRC-mandiant-solarwinds -->
| 3CX DesktopApp | 2023; Windows and macOS build/distribution environments | Trojanized application delivered a downloader; affected versions were replaced during incident response. | Historical analogy | Non-agentic software and not evidence of MCP persistence. | <!-- SAF-TRACE: claims=SAF-T1207-C011; sources=SRC-mandiant-3cx -->
| GHSA-77xc-hjv8-ww97 | 2022; Electron updater before fixed releases | A controlled update server/storage path could deliver a modified nested app; fixed in 15.5.0, 16.2.0, 17.2.0, and 18.0.0-beta.6. | Enabling vulnerability | Non-MCP; advisory does not establish exploitation. | <!-- SAF-TRACE: claims=SAF-T1207-C013; sources=SRC-electron-ghsa -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | An activated replacement inherits the component's access to agent-connected data when those permissions are broad. | <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C010; sources=SRC-mitre-ta0003,SRC-mandiant-solarwinds -->
| Integrity | High | The component identity and update path make attacker-controlled behavior appear to be a legitimate later release. | <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C011; sources=SRC-mitre-t1554,SRC-mandiant-3cx -->
| Availability | Medium | Disruption is possible but depends on replacement behavior and recovery controls. | <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C014; sources=SRC-mitre-t1554,SRC-sparkle-security -->
| Scope | Multi-System | A shared publisher or distribution path can affect multiple deployments, while pinning and staged rollout constrain reach. | <!-- SAF-TRACE: claims=SAF-T1207-C010,SAF-T1207-C011,SAF-T1207-C012; sources=SRC-mandiant-solarwinds,SRC-mandiant-3cx,SRC-google-supply-chain -->

### Severity Conditions

- **Severity increases when**: Updates activate automatically, publisher trust is broad, the component has durable startup and privileged integrations, or telemetry lacks release identity. <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C005,SAF-T1207-C008; sources=SRC-vscode-agent-plugins,SRC-vscode-extension-marketplace,SRC-mitre-ta0003 -->
- **Severity decreases when**: Exact versions and digests are approved, signatures and provenance are verified, releases are staged, and the component is isolated with scoped credentials. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C009; sources=SRC-tuf-security,SRC-tuf-metadata,SRC-vscode-enterprise-extensions -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Component-manager lifecycle log | Update selected, verified, installed, activated, rolled back | timestamp, component ID, old/new version, source, artifact digest, signer, verification result, actor, approval state | Retain across restarts and normalize before/after state. | <!-- SAF-TRACE: claims=SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-mitre-t1195-002 -->
| Approved-release inventory | Release approval or revocation | component ID, version, source, digest, signer, provenance, approval window | Keep independently from the mutable update source. | <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C017; sources=SRC-tuf-security,SRC-tuf-metadata -->
| Endpoint and network telemetry | First execution after activation and subsequent egress | process parent/child, image digest, signature status, destination, component ID, activation correlation ID | Correlate through the first post-update execution window. | <!-- SAF-TRACE: claims=SAF-T1207-C015,SAF-T1207-C018; sources=SRC-mitre-t1195-002,SRC-socket-axios -->

### Indicators of Compromise (IoCs)

- No universal durable IoC exists; release-specific digests, signer mismatches, unapproved source locations, and incident infrastructure must be taken from current incident records. <!-- SAF-TRACE: claims=SAF-T1207-C017,SAF-T1207-C018; sources=SRC-tuf-metadata,SRC-socket-axios -->

### Behavioral Indicators

- A component-update activation whose digest, source, signer, verification state, or version is absent from or conflicts with the approved-release inventory. <!-- SAF-TRACE: claims=SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-google-ai-blueprint -->
- An updater writes or replaces component files followed by unexpected child processes, signature anomalies, or egress to a non-approved destination. <!-- SAF-TRACE: claims=SAF-T1207-C015,SAF-T1207-C018; sources=SRC-mitre-t1195-002,SRC-socket-axios -->
- An update outside the authorized change window or a downgrade/rollback that cannot be justified by signed freshness metadata. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C017; sources=SRC-tuf-security,SRC-tuf-metadata -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Detect activation of a component release that fails one or more approved-release invariants. <!-- SAF-TRACE: claims=SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-google-ai-blueprint -->
- **Rule Status**: [Experimental](detection-rule.yml)
- **Detection Logic**: Select `component_update_activated` and alert unless approval, digest, source, signature, and signer all match the independent inventory. <!-- SAF-TRACE: claims=SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-google-ai-blueprint -->
- **Correlation Window**: The activation event and its attached verification record; first-run enrichment should follow the same update correlation ID. <!-- SAF-TRACE: claims=SAF-T1207-C015,SAF-T1207-C017; sources=SRC-mitre-t1195-002,SRC-tuf-metadata -->
- **Known False Positives**: Emergency or break-glass deployments and delayed inventory synchronization. <!-- SAF-TRACE: claims=SAF-T1207-C017; sources=SRC-tuf-metadata -->
- **Known Limitations**: The rule is blind when lifecycle logs omit immutable artifact identity or when the approved inventory shares the compromised authority. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C017,SAF-T1207-C018; sources=SRC-tuf-security,SRC-socket-axios -->
- **Tuning Guidance**: Populate environment-specific component aliases and formally approved emergency windows; do not allowlist a publisher without digest or provenance constraints. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C009,SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-vscode-enterprise-extensions,SRC-google-ai-blueprint -->

### Validation

- **Test Data**: [update-events.json](../../tests/fixtures/SAF-T1207/update-events.json)
- **Validation Script**: [test_saf_t1207_detection.py](../../tests/test_saf_t1207_detection.py)
- **Expected Result**: [Ten fixtures](../../tests/results/SAF-T1207-detection-results.json): six alerts, three benign cases, and one expected false positive; all classifications must match.
- **Last Validated**: [2026-09-01](../../tests/results/SAF-T1207-detection-results.json)
- **Feasibility Waiver**: [None](../../research/techniques/SAF-T1207/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. **[SAF-M-45: Tool Manifest Signing & Server Attestation](../../mitigations/SAF-M-45/README.md)**: Admit only releases whose component ID, version, source, digest, signer, provenance, and approval window match an independently governed inventory. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C017; sources=SRC-tuf-security,SRC-tuf-metadata -->
2. **[SAF-M-29: Explicit Privilege Boundaries](../../mitigations/SAF-M-29/README.md)**: Run components with scoped credentials, constrained filesystem and network access, and explicit re-approval after material change. <!-- SAF-TRACE: claims=SAF-T1207-C006,SAF-T1207-C009; sources=SRC-google-ai-blueprint,SRC-vscode-ai-governance -->
3. **Staged update policy**: Use version allowlists, controlled marketplaces, release cooldowns, deterministic dependency resolution, and rollback/freshness protection. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C009,SAF-T1207-C012; sources=SRC-tuf-security,SRC-vscode-enterprise-extensions,SRC-socket-axios -->

### Detective Controls

1. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Record verification evidence and alert on source, signer, digest, version, or approval mismatch at activation. <!-- SAF-TRACE: claims=SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-google-ai-blueprint -->
2. **[SAF-M-12: Audit Logging](../../mitigations/SAF-M-12/README.md)**: Correlate first-run process and egress telemetry with the activating update record. <!-- SAF-TRACE: claims=SAF-T1207-C015,SAF-T1207-C018; sources=SRC-mitre-t1195-002,SRC-socket-axios -->

### Response Procedures

#### Immediate Actions

- Disable the affected component and update channel, quarantine the activated artifact, and preserve manager, registry, build, endpoint, and network telemetry. <!-- SAF-TRACE: claims=SAF-T1207-C018; sources=SRC-google-supply-chain,SRC-socket-axios -->
- Revoke publisher or signing credentials if compromise is suspected, and rotate component-accessible credentials when execution occurred. <!-- SAF-TRACE: claims=SAF-T1207-C010,SAF-T1207-C011,SAF-T1207-C018; sources=SRC-mandiant-solarwinds,SRC-mandiant-3cx,SRC-google-supply-chain -->

#### Investigation Steps

- Reconstruct the selected version and dependency graph from contemporaneous logs and artifact snapshots rather than a current reinstall. <!-- SAF-TRACE: claims=SAF-T1207-C012,SAF-T1207-C018; sources=SRC-socket-axios -->
- Compare the active artifact, signer, source, and provenance with the last independent approval record and examine first-run children and egress. <!-- SAF-TRACE: claims=SAF-T1207-C015,SAF-T1207-C017; sources=SRC-tuf-metadata,SRC-mitre-t1195-002 -->

#### Remediation

- Restore a vetted artifact by immutable digest, rebuild affected environments when integrity cannot be established, and correct the compromised publisher, build, registry, or signing path. <!-- SAF-TRACE: claims=SAF-T1207-C007,SAF-T1207-C018; sources=SRC-tuf-security,SRC-google-supply-chain -->
- Add activation-time invariant checking and retain the regression fixtures used by the analytic. <!-- SAF-TRACE: claims=SAF-T1207-C017,SAF-T1207-C018; sources=SRC-tuf-metadata,SRC-socket-axios -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1003: Malicious MCP-Server Distribution](../SAF-T1003/README.md) | Alternative | First-install distribution has no trusted prior version; SAF-T1207 replaces an already trusted component through an update path. | <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C015; sources=SRC-mitre-t1195-002,SRC-mitre-ta0003 -->
| [SAF-T1201: Post-Approval Tool Mutation](../SAF-T1201/README.md) | Alternative | A rug pull changes a trusted tool definition or behavior without replacing software; SAF-T1207 requires a release or dependency replacement accepted by the component manager. | <!-- SAF-TRACE: claims=SAF-T1207-C001,SAF-T1207-C006; sources=SRC-google-ai-blueprint,SRC-mitre-t1554 -->

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Compromise Software Supply Chain | Analogous | It expressly includes update/distribution manipulation, but ATT&CK places delivery under Initial Access while SAF-T1207 requires persistence through an already trusted agentic component. | <!-- SAF-TRACE: claims=SAF-T1207-C015; sources=SRC-mitre-t1195-002 -->
| [T1554](https://attack.mitre.org/techniques/T1554/) | Compromise Host Software Binary | Analogous | Both preserve access through replacement of legitimate code; T1554 emphasizes modification on the host rather than upstream update authority. | <!-- SAF-TRACE: claims=SAF-T1207-C016; sources=SRC-mitre-t1554,SRC-mitre-ta0003 -->

## References

1. **SRC-mcp-registry-about**: [The MCP Registry](https://modelcontextprotocol.io/registry/about) - Registry/package boundary and scanning responsibility.
2. **SRC-mcp-registry-package-types**: [MCP Registry Package Types](https://modelcontextprotocol.io/registry/package-types) - Package identifiers, versions, and install mechanisms.
3. **SRC-mcp-versioning**: [Versioning Published MCP Servers](https://modelcontextprotocol.io/registry/versioning) - Immutable unique versions and latest ordering.
4. **SRC-vscode-agent-plugins**: [Agent Plugins in Visual Studio Code](https://code.visualstudio.com/docs/agent-customization/agent-plugins) - Plugin update behavior.
5. **SRC-vscode-extension-marketplace**: [Extension Marketplace](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace) - Extension update and signature behavior.
6. **SRC-vscode-extension-security**: [Extension Runtime Security](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security) - Marketplace scanning and signature verification.
7. **SRC-vscode-enterprise-extensions**: [Enterprise Extension Controls](https://code.visualstudio.com/docs/enterprise/extensions) - Version and publisher allowlisting.
8. **SRC-vscode-ai-governance**: [Enterprise AI Settings](https://code.visualstudio.com/docs/enterprise/ai-settings) - Plugin marketplace and MCP source controls.
9. **SRC-tuf-security**: [The Update Framework: Security](https://theupdateframework.io/docs/security/) - Compromise resilience, freshness, and rollback protection.
10. **SRC-tuf-metadata**: [The Update Framework: Metadata](https://theupdateframework.io/docs/metadata/) - Hash, signature, threshold, expiry, and version records.
11. **SRC-google-ai-blueprint**: [Demystifying AI Exploits: A Blueprint for AI-Assisted Vulnerability Management](https://cloud.google.com/blog/topics/threat-intelligence/ai-assisted-vulnerability-management/) - MCP supply-chain risk and integrity guidance.
12. **SRC-google-supply-chain**: [Batten Down Your Packages](https://cloud.google.com/blog/topics/threat-intelligence/mitigation-guidance-for-supply-chain-compromise) - 2026 incidents and mitigation guidance.
13. **SRC-mandiant-solarwinds**: [SolarWinds Supply Chain Attack Uses SUNBURST Backdoor](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor/) - Historical incident.
14. **SRC-mandiant-3cx**: [3CX Software Supply Chain Compromise](https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise) - Historical incident.
15. **SRC-socket-axios**: [The Hidden Blast Radius of the Axios Compromise](https://socket.dev/blog/hidden-blast-radius-of-the-axios-compromise) - Adjacent MCP dependency exposure and reconstruction limits.
16. **SRC-electron-ghsa**: [GHSA-77xc-hjv8-ww97](https://github.com/electron/electron/security/advisories/GHSA-77xc-hjv8-ww97) - Electron updater vulnerability; exact URL discovered through the reviewed NVD CVE-2022-29257 record.
17. **SRC-sparkle-security**: [Sparkle Security and Reliability](https://sparkle-project.org/documentation/security-and-reliability/) - CVE-2025-0509 fix and affected versions.
18. **SRC-mitre-t1195-002**: [ATT&CK T1195.002](https://attack.mitre.org/techniques/T1195/002/) - Supply-chain and update mechanism mapping.
19. **SRC-mitre-t1554**: [ATT&CK T1554](https://attack.mitre.org/techniques/T1554/) - Persistent legitimate-binary replacement mapping.
20. **SRC-mitre-ta0003**: [ATT&CK TA0003](https://attack.mitre.org/tactics/TA0003/) - Persistence tactic definition.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-01 | Clean-room research draft and tested experimental detection | OpenAI Codex clean-room generator |
