# SAF-T1002: Supply Chain Compromise

## Overview

- **Tactic**: Initial Access (ATK-TA0001)
- **Technique ID**: SAF-T1002
- **Research Packet**: [research/techniques/SAF-T1002](../../research/techniques/SAF-T1002/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1002/traceability-ledger.yml)
- **Documentation Status**: Draft
- **Evidence Status**: Observed
- **Severity**: High
- **Severity Rationale**: The altered artifact can execute with developer, CI/CD, agent-host, or production credentials and can affect every consumer that resolves the compromised version. <!-- SAF-TRACE: claims=SAF-T1002-C002,SAF-T1002-C003,SAF-T1002-C006; sources=SRC-unit42-tj-actions-agentkit,SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026 -->
- **First Observed**: 2025-03-14 in the reviewed agentic evidence, when malicious third-party action code executed in a Coinbase AgentKit workflow. <!-- SAF-TRACE: claims=SAF-T1002-C002; sources=SRC-unit42-tj-actions-agentkit -->
- **Last Updated**: 2026-09-01

## Scope

This technique covers an adversary altering a component or release path that consumers reasonably treat as the authentic upstream, then causing an MCP or agentic deployment to install, load, import, update, or execute the altered artifact. [MITRE ATT&CK T1195](https://attack.mitre.org/techniques/T1195/) <!-- SAF-TRACE: claims=SAF-T1002-C001; sources=SRC-mitre-attack-t1195 -->

### In Scope

- Compromise of trusted source, build output, publisher identity, package version, signed provenance-producing workflow, registry pointer, cache, or update channel. <!-- SAF-TRACE: claims=SAF-T1002-C001,SAF-T1002-C012; sources=SRC-mitre-attack-t1195,SRC-microsoft-asyncapi-2026 -->
- Acquisition through an expected channel followed by install-time, import-time, update-time, or first-run execution in an MCP client, MCP server host, agent framework, developer workstation, CI/CD runner, or production agent service. <!-- SAF-TRACE: claims=SAF-T1002-C001,SAF-T1002-C006; sources=SRC-mitre-attack-t1195,SRC-microsoft-axios-2026 -->

### Out of Scope

- A newly created typosquat or dependency-confusion package when no trusted producer or channel was compromised. [Microsoft typosquat analysis](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/) <!-- SAF-TRACE: claims=SAF-T1002-C010; sources=SRC-microsoft-typosquat-2026 -->
- A crafted one-click configuration, prompt or tool-metadata poisoning after an honest install, exploitation of an ordinary software vulnerability, and downstream credential theft, persistence, or exfiltration. [MCP client installation requirements](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) <!-- SAF-TRACE: claims=SAF-T1002-C011; sources=SRC-mcp-sep-1024 -->

### Distinguishing Characteristics

The trusted acquisition path is the discriminator: the consumer selects an identity or channel it already trusts, but the delivered bits or authorized release state have been changed. Masquerading persuades selection of a deceptive identity; tool poisoning changes runtime semantics; vulnerability exploitation abuses a defect in honestly distributed software. <!-- SAF-TRACE: claims=SAF-T1002-C001,SAF-T1002-C010; sources=SRC-mitre-attack-t1195,SRC-microsoft-typosquat-2026 -->

## Description

An adversary compromises an upstream producer, source repository, build or release workflow, publisher credential, registry path, artifact cache, or update mechanism. The expected channel then distributes an altered MCP server, client, SDK, agent tool, framework dependency, IDE extension, or CI/CD component, and a consumer executes it. <!-- SAF-TRACE: claims=SAF-T1002-C001,SAF-T1002-C012; sources=SRC-mitre-attack-t1195,SRC-microsoft-asyncapi-2026 -->

The official MCP Registry hosts discovery and execution metadata while pointing to artifacts in npm, PyPI, Cargo, OCI, or MCPB distribution paths. Namespace checks authenticate the claimed publisher namespace, but actual code scanning is delegated; MCPB hashes are supplied in metadata and validated by clients. [Registry architecture](https://modelcontextprotocol.io/registry/about) [Package types](https://modelcontextprotocol.io/registry/package-types) <!-- SAF-TRACE: claims=SAF-T1002-C007,SAF-T1002-C009; sources=SRC-mcp-registry-about,SRC-mcp-registry-package-types -->

The Registry moderation policy directs consumers to assume minimal-to-no moderation, removes malware when identified, and generally does not remove servers solely because they contain vulnerabilities. These conditions make downstream verification important but do not establish that the official Registry has distributed a compromised artifact. [Moderation policy](https://modelcontextprotocol.io/registry/moderation-policy) <!-- SAF-TRACE: claims=SAF-T1002-C008; sources=SRC-mcp-registry-moderation -->

## Attack Vectors

- **Primary Vector**: Abuse of a trusted source-to-build-to-publish or update path so an altered artifact resolves under the expected name and version channel. <!-- SAF-TRACE: claims=SAF-T1002-C001,SAF-T1002-C012; sources=SRC-mitre-attack-t1195,SRC-microsoft-asyncapi-2026 -->
- **Secondary Vectors**: <!-- SAF-TRACE: claims=SAF-T1002-C001; sources=SRC-mitre-attack-t1195 -->
  - Compromised maintainer or publisher credentials that authorize a malicious version. <!-- SAF-TRACE: claims=SAF-T1002-C003; sources=SRC-nx-s1ngularity-postmortem -->
  - Poisoned CI cache, mutable third-party action, transitive dependency, registry pointer, or automatic update. <!-- SAF-TRACE: claims=SAF-T1002-C002,SAF-T1002-C006,SAF-T1002-C012; sources=SRC-unit42-tj-actions-agentkit,SRC-microsoft-axios-2026,SRC-microsoft-asyncapi-2026 -->
- **Affected Components**: MCP clients and servers, registry metadata, package registries, SDKs, agent frameworks, agent tools, IDE extensions, CI/CD runners, and production agent hosts. <!-- SAF-TRACE: claims=SAF-T1002-C007,SAF-T1002-C009; sources=SRC-mcp-registry-about,SRC-mcp-registry-package-types -->
- **Trust Boundary Crossed**: The authenticity and integrity decision between an expected producer or channel and the consuming deployment. <!-- SAF-TRACE: claims=SAF-T1002-C001; sources=SRC-mitre-attack-t1195 -->

## Technical Details

### Prerequisites

- The adversary can alter trusted source, build state, publisher authorization, registry metadata, cached output, or update infrastructure. <!-- SAF-TRACE: claims=SAF-T1002-C001,SAF-T1002-C012; sources=SRC-mitre-attack-t1195,SRC-microsoft-asyncapi-2026 -->
- A consumer resolves the affected artifact or update through the expected channel. <!-- SAF-TRACE: claims=SAF-T1002-C006,SAF-T1002-C012; sources=SRC-microsoft-axios-2026,SRC-microsoft-asyncapi-2026 -->
- The consuming environment permits install hooks, import-time code, first-run code, or another executable artifact entry point. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C006,SAF-T1002-C012; sources=SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026,SRC-microsoft-asyncapi-2026 -->

### Attack Flow

1. **Reconnaissance or Setup**: The adversary identifies a trusted project, workflow, publisher identity, registry pointer, or update path with access to downstream consumers. <!-- SAF-TRACE: claims=SAF-T1002-C001; sources=SRC-mitre-attack-t1195 -->
2. **Delivery**: Unauthorized source or a malicious dependency is introduced and the legitimate release path publishes or serves the altered artifact. <!-- SAF-TRACE: claims=SAF-T1002-C006,SAF-T1002-C012; sources=SRC-microsoft-axios-2026,SRC-microsoft-asyncapi-2026 -->
3. **Trigger or Execution**: Installation, import, update, IDE activation, or first run activates the payload. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C006,SAF-T1002-C012; sources=SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026,SRC-microsoft-asyncapi-2026 -->
4. **Boundary Crossing**: The consumer accepts publisher identity, namespace, signature, provenance, version, or channel state without a policy join strong enough to detect the unauthorized source. <!-- SAF-TRACE: claims=SAF-T1002-C007,SAF-T1002-C017; sources=SRC-mcp-registry-about,SRC-slsa-v1.2-verification -->
5. **Objective**: Adversary-controlled code executes with the privileges and connectivity of the developer, runner, MCP host, or agent service. <!-- SAF-TRACE: claims=SAF-T1002-C002,SAF-T1002-C003; sources=SRC-unit42-tj-actions-agentkit,SRC-nx-s1ngularity-postmortem -->
6. **Follow-On Activity**: Credential access, collection, persistence, exfiltration, or further malicious publication may follow but is not part of this technique's defining boundary. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C006; sources=SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026 -->

### Example Scenario

An inert example is a trusted agent-tool package whose resolved digest no longer matches policy and which is imported by the same agent host within ten minutes; the bundled analytic alerts on that acquisition-to-execution join. [Detection fixture](tests/fixtures/cases.json)

```json
{
  "artifact_name": "example-agent-tool",
  "artifact_version": "2.4.0",
  "verification_status": "digest_mismatch",
  "event_sequence": ["artifact_acquired", "artifact_executed"]
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1002-C001, SAF-T1002-C005 | The contract maps trusted-path alteration and execution directly to ATT&CK T1195 and Initial Access. | Research-Derived | SRC-mitre-attack-t1195: [MITRE ATT&CK T1195](https://attack.mitre.org/techniques/T1195/) | ATT&CK is not MCP-specific. <!-- SAF-TRACE: claims=SAF-T1002-C001,SAF-T1002-C005; sources=SRC-mitre-attack-t1195 --> |
| SAF-T1002-C002, SAF-T1002-C003, SAF-T1002-C004 | AgentKit and Nx provide direct agentic-development-path observations with explicitly bounded downstream impact. | Observed | SRC-unit42-tj-actions-agentkit; SRC-nx-s1ngularity-postmortem | Neither establishes a production compromise of an official MCP Registry artifact. <!-- SAF-TRACE: claims=SAF-T1002-C002,SAF-T1002-C003,SAF-T1002-C004; sources=SRC-unit42-tj-actions-agentkit,SRC-nx-s1ngularity-postmortem --> |
| SAF-T1002-C006, SAF-T1002-C012 | Axios and AsyncAPI show install-time and import-time execution through trusted package paths. | Observed analogy | SRC-microsoft-axios-2026; SRC-microsoft-asyncapi-2026 | The sources do not identify MCP deployments among consumers. <!-- SAF-TRACE: claims=SAF-T1002-C006,SAF-T1002-C012; sources=SRC-microsoft-axios-2026,SRC-microsoft-asyncapi-2026 --> |
| SAF-T1002-C007, SAF-T1002-C008, SAF-T1002-C009, SAF-T1002-C011 | MCP primary documentation establishes registry, package-integrity, moderation, and local-install consent boundaries. | Research-Derived | SRC-mcp-registry-about; SRC-mcp-registry-moderation; SRC-mcp-registry-package-types; SRC-mcp-sep-1024 | The Registry remains in preview and consent is not artifact integrity. <!-- SAF-TRACE: claims=SAF-T1002-C007,SAF-T1002-C008,SAF-T1002-C009,SAF-T1002-C011; sources=SRC-mcp-registry-about,SRC-mcp-registry-moderation,SRC-mcp-registry-package-types,SRC-mcp-sep-1024 --> |
| SAF-T1002-C010, SAF-T1002-C013 | Typosquatting is excluded; controlled MCP research supports feasibility without a public-registry incident. | Demonstrated and Research-Derived | SRC-microsoft-typosquat-2026; SRC-mcp-ecosystem-dsn-2026 | The MCP experiments were local proofs of concept. <!-- SAF-TRACE: claims=SAF-T1002-C010,SAF-T1002-C013; sources=SRC-microsoft-typosquat-2026,SRC-mcp-ecosystem-dsn-2026 --> |
| SAF-T1002-C014, SAF-T1002-C015, SAF-T1002-C016, SAF-T1002-C017 | Artifact verification plus acquisition-to-execution behavior supports detection, with documented false-positive and provenance limits. | Research-Derived | SRC-mitre-attack-t1195; SRC-slsa-v1.2-verification; SRC-npm-provenance; SRC-donapi-usenix-2024; SRC-microsoft-asyncapi-2026 | No single telemetry source covers the complete join. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C015,SAF-T1002-C016,SAF-T1002-C017; sources=SRC-mitre-attack-t1195,SRC-slsa-v1.2-verification,SRC-npm-provenance,SRC-donapi-usenix-2024,SRC-microsoft-asyncapi-2026 --> |
| SAF-T1002-C018, SAF-T1002-C019, SAF-T1002-C020, SAF-T1002-C021 | CI pinning, staged updates, isolation, and incident response constrain the mechanism and blast radius. | Research-Derived | SRC-github-actions-secure-use; SRC-microsoft-asyncapi-2026; SRC-mcp-sep-1024; SRC-microsoft-axios-2026 | Controls reduce risk but cannot prove trusted source was authorized. <!-- SAF-TRACE: claims=SAF-T1002-C018,SAF-T1002-C019,SAF-T1002-C020,SAF-T1002-C021; sources=SRC-github-actions-secure-use,SRC-microsoft-asyncapi-2026,SRC-mcp-sep-1024,SRC-microsoft-axios-2026 --> |

### Current State

- **Affected Environments**: Developer workstations, CI/CD runners, IDEs, MCP local-server installations, agent frameworks, and production services that resolve executable components through package, image, bundle, or update channels. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C006,SAF-T1002-C009; sources=SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026,SRC-mcp-registry-package-types -->
- **Known Exploitation**: Production action and package incidents establish execution in agentic development contexts; MCP-specific research remains a controlled demonstration. <!-- SAF-TRACE: claims=SAF-T1002-C002,SAF-T1002-C003,SAF-T1002-C013; sources=SRC-unit42-tj-actions-agentkit,SRC-nx-s1ngularity-postmortem,SRC-mcp-ecosystem-dsn-2026 -->
- **Available Protections**: Publisher and namespace controls, artifact signatures, provenance, full-SHA action pins, exact dependency versions, isolation, and behavioral telemetry. <!-- SAF-TRACE: claims=SAF-T1002-C007,SAF-T1002-C014,SAF-T1002-C018; sources=SRC-mcp-registry-about,SRC-slsa-v1.2-verification,SRC-github-actions-secure-use -->
- **Residual Risk**: A trusted build can publish validly signed or provenance-bearing output from unauthorized source, and payloads can execute on import rather than through install hooks. <!-- SAF-TRACE: claims=SAF-T1002-C012,SAF-T1002-C017,SAF-T1002-C019; sources=SRC-microsoft-asyncapi-2026,SRC-slsa-v1.2-verification -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| CVE-2025-30066 / `tj-actions/changed-files` in AgentKit | March 2025; agentic CI workflow | Malicious action executed and obtained a write-capable token; tags were reverted and full-SHA pins are recommended. | Direct production incident | Coinbase reported no malicious package publication or known damage. <!-- SAF-TRACE: claims=SAF-T1002-C002,SAF-T1002-C018; sources=SRC-unit42-tj-actions-agentkit,SRC-github-actions-secure-use --> |
| Nx `s1ngularity` | August 2025; npm and developer/CI environments | Malicious versions ran during install, searched credentials, used local AI tools, and exfiltrated results; versions were removed and release controls hardened. | Direct production incident | General developer packages, not official MCP Registry artifacts. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C004; sources=SRC-nx-s1ngularity-postmortem --> |
| Axios 1.14.1 and 0.30.4 | March 2026; npm consumers | A malicious dependency fetched a second-stage payload; rollback, cache purge, credential rotation, and update restrictions were advised. | Historical analogy | No MCP consumer identified. <!-- SAF-TRACE: claims=SAF-T1002-C006,SAF-T1002-C021; sources=SRC-microsoft-axios-2026 --> |
| AsyncAPI compromised package versions | July 2026; npm consumers | Trusted OIDC publishing produced provenance-valid unauthorized packages that executed on import; known-good pins, cache purge, hunts, and rotation were advised. | Historical analogy | Credential-acquisition path was not conclusively established and no MCP consumer was identified. <!-- SAF-TRACE: claims=SAF-T1002-C012,SAF-T1002-C017,SAF-T1002-C019; sources=SRC-microsoft-asyncapi-2026,SRC-slsa-v1.2-verification --> |

### Real-World Incidents or Demonstrations

#### MCP Registry-Hijack Feasibility Study (DSN 2026)

Researchers analyzed 67,057 MCP servers across six registries and implemented MCPInspect, including local demonstrations of registry-entry hijack preconditions. They did not attack public registries or external users, so the work supports feasibility rather than a production compromise claim. [DSN 2026 study](https://arxiv.org/html/2510.16558) <!-- SAF-TRACE: claims=SAF-T1002-C013; sources=SRC-mcp-ecosystem-dsn-2026 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | High | Altered artifacts can read developer, CI/CD, cloud, or agent-host credentials when those values are present in the execution context. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C006; sources=SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026 --> |
| Integrity | High | A compromised release path can change code, workflows, artifacts, and further package versions under a trusted identity. <!-- SAF-TRACE: claims=SAF-T1002-C002,SAF-T1002-C012; sources=SRC-unit42-tj-actions-agentkit,SRC-microsoft-asyncapi-2026 --> |
| Availability | Medium | Disruption depends on payload capability and response actions; the selected sources primarily document execution, credential risk, and containment rather than sustained outage. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C006; sources=SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026 --> |
| Scope | Ecosystem-Wide | One trusted release can reach many downstream consumers, but actual scope depends on version resolution, cache state, activation, and credential exposure. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C006,SAF-T1002-C012; sources=SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026,SRC-microsoft-asyncapi-2026 --> |

### Severity Conditions

- **Severity increases when**: Updates are automatic, the artifact is transitive or widely reused, the host exposes broad credentials, egress is unrestricted, or trusted workflows can publish without independent source review. <!-- SAF-TRACE: claims=SAF-T1002-C003,SAF-T1002-C012,SAF-T1002-C017; sources=SRC-nx-s1ngularity-postmortem,SRC-microsoft-asyncapi-2026,SRC-slsa-v1.2-verification -->
- **Severity decreases when**: Exact versions, reviewed provenance expectations, staged activation, minimal tokens, isolation, and constrained egress limit acquisition or blast radius. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C018,SAF-T1002-C020; sources=SRC-slsa-v1.2-verification,SRC-github-actions-secure-use,SRC-mcp-sep-1024 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Package, registry, image, bundle, or update logs | Resolution, acquisition, verification, install, import, update | Artifact, version, source, digest, signature, provenance subject, builder, verification result, timestamp | Retain the resolved artifact identity rather than only the requested version range. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C015; sources=SRC-slsa-v1.2-verification,SRC-npm-provenance --> |
| Endpoint, CI/CD, IDE, MCP client, and agent-host logs | First execution, child process, file write, credential access, egress | Host, workload, artifact, version, parent, child, path, destination, timestamp | Normalize clocks and join by host, artifact, and version. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C016; sources=SRC-mitre-attack-t1195,SRC-donapi-usenix-2024 --> |

### Indicators of Compromise (IoCs)

- No technique-wide durable IoC exists; incident-specific versions, hashes, paths, publisher identities, and destinations should be taken from the applicable current advisory. <!-- SAF-TRACE: claims=SAF-T1002-C002,SAF-T1002-C003,SAF-T1002-C006,SAF-T1002-C012; sources=SRC-unit42-tj-actions-agentkit,SRC-nx-s1ngularity-postmortem,SRC-microsoft-axios-2026,SRC-microsoft-asyncapi-2026 -->

### Behavioral Indicators

- An expected-channel artifact has a missing or mismatched digest, invalid signature, unexpected source, or provenance builder outside consumer policy. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C015; sources=SRC-slsa-v1.2-verification,SRC-npm-provenance -->
- The same artifact version then produces a new child process, executable file, credential-store access, metadata-service access, or egress from a package-manager, build, IDE, MCP-host, or agent-framework parent. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C016; sources=SRC-mitre-attack-t1195,SRC-donapi-usenix-2024 -->
- Correlation between acquisition failure and first execution increases confidence; install-time behavior alone can be legitimate. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C016; sources=SRC-mitre-attack-t1195,SRC-donapi-usenix-2024 -->

### Detection Analytic

The standalone analytic is maintained in [detection-rule.yml](detection-rule.yml), a declared local research artifact.

- **Analytic Goal**: Detect expected-channel MCP or agentic artifacts with a failed or missing required integrity check that execute on the same host and version. [Detection rule](detection-rule.yml)
- **Rule Status**: Test. [Detection rule](detection-rule.yml)
- **Detection Logic**: Correlate acquisition and execution by host, artifact name, and version; suppress explicitly approved exceptions. [Detection rule](detection-rule.yml)
- **Correlation Window**: Ten minutes, inclusive. [Detection rule](detection-rule.yml)
- **Known False Positives**: Approved local-development builds and emergency internal artifacts whose verification record has not propagated. <!-- SAF-TRACE: claims=SAF-T1002-C016; sources=SRC-donapi-usenix-2024 -->
- **Known Limitations**: The rule can miss a compromised trusted pipeline that emits policy-valid provenance or execution outside the retained correlation window. <!-- SAF-TRACE: claims=SAF-T1002-C012,SAF-T1002-C017; sources=SRC-microsoft-asyncapi-2026,SRC-slsa-v1.2-verification -->
- **Tuning Guidance**: Require named, time-bounded exceptions and tune component types, expected builders, sources, and window length to the deployment. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C016; sources=SRC-slsa-v1.2-verification,SRC-donapi-usenix-2024 -->

### Validation

- **Test Data**: [cases.json](tests/fixtures/cases.json)
- **Validation Script**: [test_detection_rule.py](tests/test_detection_rule.py)
- **Expected Result**: Six of six positive, negative, boundary, and false-positive cases pass. [Detection results](tests/results/detection-test-results.json)
- **Last Validated**: 2026-09-01. [Quality review](../../research/techniques/SAF-T1002/quality-review.yml)
- **Feasibility Waiver**: None. [Quality review](../../research/techniques/SAF-T1002/quality-review.yml)

## Mitigation Strategies

### Preventive Controls

1. **Artifact and provenance policy**: Verify signature, subject digest, predicate type, builder identity, source, and recursively resolved dependencies where feasible. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C017; sources=SRC-slsa-v1.2-verification -->
2. **CI/CD trust reduction**: Pin third-party actions to full commit SHAs, minimize workflow token permissions, isolate untrusted pull-request execution, and review workflow changes. <!-- SAF-TRACE: claims=SAF-T1002-C018; sources=SRC-github-actions-secure-use -->
3. **Controlled updates and execution**: Use exact versions or lockfiles for critical components, stage updates, retain prior artifacts, test imports as well as install hooks, and isolate MCP or agentic processes with minimal credentials and egress. <!-- SAF-TRACE: claims=SAF-T1002-C019,SAF-T1002-C020; sources=SRC-microsoft-asyncapi-2026,SRC-mcp-sep-1024 -->

### Detective Controls

1. **Acquisition verification**: Record resolved source, digest, signature, provenance subject, builder, and policy result for every executable component. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C015; sources=SRC-slsa-v1.2-verification,SRC-npm-provenance -->
2. **Behavioral correlation**: Join verification failures to first execution, unexpected child processes, file writes, credential access, and egress. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C016; sources=SRC-mitre-attack-t1195,SRC-donapi-usenix-2024 -->

### Response Procedures

#### Immediate Actions

- Stop resolution and execution of affected versions, quarantine affected hosts or runners, and revoke publisher or workflow credentials that may be compromised. <!-- SAF-TRACE: claims=SAF-T1002-C021; sources=SRC-microsoft-axios-2026 -->
- Rotate every credential reachable from the affected installation or execution context. <!-- SAF-TRACE: claims=SAF-T1002-C021; sources=SRC-microsoft-axios-2026 -->

#### Investigation Steps

- Preserve package-manager, registry, endpoint, CI/CD, provenance, lockfile, cache, process, file, identity, and network evidence. <!-- SAF-TRACE: claims=SAF-T1002-C014,SAF-T1002-C021; sources=SRC-mitre-attack-t1195,SRC-microsoft-axios-2026 -->
- Determine the first unauthorized source change, every resolved artifact version, each execution context, accessible credential, generated output, and downstream publication. <!-- SAF-TRACE: claims=SAF-T1002-C012,SAF-T1002-C021; sources=SRC-microsoft-asyncapi-2026,SRC-microsoft-axios-2026 -->

#### Remediation

- Remove affected versions, purge package and build caches, rebuild outputs from known-good reviewed inputs, and validate clean deployment state. <!-- SAF-TRACE: claims=SAF-T1002-C021; sources=SRC-microsoft-axios-2026 -->
- Repair the compromised source, workflow, publisher, or registry path and add regression tests for acquisition integrity and first execution. <!-- SAF-TRACE: claims=SAF-T1002-C018,SAF-T1002-C021; sources=SRC-github-actions-secure-use,SRC-microsoft-axios-2026 -->

## Related Techniques

Repository neighbor IDs were initially selected only from the permitted Technique ID and Technique Name catalog columns, then registered in the shared framework model after the clean-room bundle was frozen. [Contract](../../research/techniques/SAF-T1002/technique-contract.yml)

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T1003: Malicious MCP-Server Distribution](../SAF-T1003/README.md) | Alternative | A malicious server may be distributed under a new or attacker-controlled identity; this technique requires compromise of a previously trusted producer or channel. [Contract](../../research/techniques/SAF-T1002/technique-contract.yml) |
| [SAF-T1004: Server Impersonation / Name-Collision](../SAF-T1004/README.md) | Alternative | Impersonation transfers trust to a deceptive identity; this technique preserves expected identity while altering its artifact or path. [Contract](../../research/techniques/SAF-T1002/technique-contract.yml) |
| [SAF-T1006: User-Social-Engineering Install](../SAF-T1006/README.md) | Alternative | Social engineering obtains consent to an attacker-selected install; this technique abuses an already trusted distribution path. [Contract](../../research/techniques/SAF-T1002/technique-contract.yml) |
| [SAF-T1203: Backdoored Server Binary](../SAF-T1203/README.md) | Overlapping outcome | A backdoored server binary can be the delivered artifact; this technique classifies how the trusted acquisition or update path was compromised. [Contract](../../research/techniques/SAF-T1002/technique-contract.yml) |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1195](https://attack.mitre.org/techniques/T1195/) | Supply Chain Compromise | Direct | Both behaviors manipulate dependencies, development tools, build or distribution mechanisms, or updates before consumer execution; SAF-T1002 narrows the boundary to MCP and agentic deployments. <!-- SAF-TRACE: claims=SAF-T1002-C001,SAF-T1002-C005; sources=SRC-mitre-attack-t1195 --> |

## References

1. **SRC-mitre-attack-t1195**: [MITRE ATT&CK T1195](https://attack.mitre.org/techniques/T1195/) — definition, tactic, and detection strategy.
2. **SRC-unit42-tj-actions-agentkit**: [Unit 42 tj-actions analysis](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/) — AgentKit incident and limitations.
3. **SRC-nx-s1ngularity-postmortem**: [Nx s1ngularity postmortem](https://nx.dev/blog/s1ngularity-postmortem) — malicious package execution and response.
4. **SRC-microsoft-axios-2026**: [Microsoft Axios analysis](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/) — install-time compromise and response.
5. **SRC-microsoft-asyncapi-2026**: [Microsoft AsyncAPI analysis](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/) — trusted workflow and import-time execution.
6. **SRC-mcp-registry-about**: [MCP Registry architecture](https://modelcontextprotocol.io/registry/about) — metadata, namespace, and scanning boundaries.
7. **SRC-mcp-registry-moderation**: [MCP Registry moderation policy](https://modelcontextprotocol.io/registry/moderation-policy) — moderation scope and limitations.
8. **SRC-mcp-registry-package-types**: [MCP Registry package types](https://modelcontextprotocol.io/registry/package-types) — artifact forms and verification responsibilities.
9. **SRC-mcp-sep-1024**: [SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-) — local-server installation consent requirements.
10. **SRC-microsoft-typosquat-2026**: [Microsoft typosquat analysis](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/) — adjacent package-identity mechanism.
11. **SRC-mcp-ecosystem-dsn-2026**: [DSN 2026 MCP ecosystem study](https://arxiv.org/html/2510.16558) — controlled registry-hijack feasibility.
12. **SRC-slsa-v1.2-verification**: [SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts) — provenance verification and limits.
13. **SRC-npm-provenance**: [npm provenance documentation](https://docs.npmjs.com/viewing-package-provenance/) — npm verification fields and behavior.
14. **SRC-donapi-usenix-2024**: [DONAPI](https://www.usenix.org/system/files/usenixsecurity24-huang-cheng.pdf) — malicious-package behavior detection and limitations.
15. **SRC-github-actions-secure-use**: [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use) — CI action pinning and token controls.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-01 | Clean-room rewrite with post-freeze source, framework, mitigation, and validation joins completed. | OpenAI Codex clean-room research agent |
