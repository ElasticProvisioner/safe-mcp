# SAF-T1915: Cross-Chain Laundering via Bridges/DEXs

## Overview

- **Tactic**: ATK-TA0010
- **Technique ID**: SAF-T1915
- **Research Packet**: [research/techniques/SAF-T1915](../../research/techniques/SAF-T1915/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T1915/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Research-Derived
- **Severity**: High
- **Severity Rationale**: Delegated authority can accelerate the dissipation of high-value stolen assets across networks, but the consequence depends on available value, transaction scope, and approval controls. <!-- SAF-TRACE: claims=SAF-T1915-C019; sources=SRC-fbi-bybit-2025,SRC-fatf-defi-2026 -->
- **First Observed**: No production MCP or agentic-system incident was identified in the [completed source-coverage review](../../research/techniques/SAF-T1915/source-coverage.yml).
- **Last Updated**: 2026-09-02

## Scope

This technique covers an adversary using an agent with delegated financial-tool authority to compose a bridge action and a decentralized-exchange swap into a multi-chain sequence intended to layer illicit proceeds. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C004; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026,SRC-treasury-defi-2023 -->

### In Scope

- An agent plans or executes at least one bridge leg and one DEX swap across two or more chains for funds with illicit provenance. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C004; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026,SRC-treasury-defi-2023 -->
- The crossed boundary is delegated transaction authority between an agentic host or tool and externally settled blockchain assets. <!-- SAF-TRACE: claims=SAF-T1915-C005,SAF-T1915-C017; sources=SRC-pace-defi-agents-2026 -->

### Out of Scope

- Theft, bridge exploitation, wallet compromise, and unauthorized transfer before laundering are adjacent enabling behavior, not this post-theft sequence. <!-- SAF-TRACE: claims=SAF-T1915-C010; sources=SRC-fbi-defi-2022 -->
- Mixer-only movement without both a bridge event and a DEX swap is outside this technique; no separate SAF mixer technique is currently cataloged. <!-- SAF-TRACE: claims=SAF-T1915-C001; sources=SRC-fatf-defi-2026 -->
- Legitimate treasury rebalancing, arbitrage, and ordinary cross-chain transfers are excluded unless evidence supports illicit provenance and the defined sequence. <!-- SAF-TRACE: claims=SAF-T1915-C014; sources=SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026 -->

### Distinguishing Characteristics

The technique requires provenance context plus a bridge-and-DEX sequence; bridge use or a DEX swap alone is neither unique to laundering nor sufficient for classification. <!-- SAF-TRACE: claims=SAF-T1915-C013,SAF-T1915-C014; sources=SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026 -->

## Description

FATF describes professional laundering networks fragmenting funds across wallets and routing value through DEXs, bridges, mixers, and swaps before consolidation or off-ramping. Those mechanics can increase investigative complexity without making public-chain tracing impossible. <!-- SAF-TRACE: claims=SAF-T1915-C001,SAF-T1915-C004,SAF-T1915-C015; sources=SRC-fatf-defi-2026,SRC-treasury-defi-2023,SRC-chainalysis-theft-2026 -->

Controlled research separately demonstrates that an LLM-based agent can create and submit swaps, approvals, and deposits under delegated DeFi authority. Combining that execution capability with the observed laundering pattern is a bounded inference; the reviewed corpus does not document an end-to-end agentic laundering incident. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C005; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026 -->

The security boundary fails when a transaction-capable agent receives authority broad enough to compose individually valid operations without a sequence-aware policy or human review. A per-transaction verifier can constrain individual calls while still missing a harmful composition of policy-valid legs. <!-- SAF-TRACE: claims=SAF-T1915-C017,SAF-T1915-C018; sources=SRC-pace-defi-agents-2026 -->

## Attack Vectors

- **Primary Vector**: Abuse of delegated DeFi transaction authority to submit a bridge action and DEX swap for illicitly sourced assets. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C005; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026 -->
- **Secondary Vectors**: Prompted or preconfigured multi-step execution, fragmented wallet routing, and rapid automated transactions that obscure common ownership. <!-- SAF-TRACE: claims=SAF-T1915-C004; sources=SRC-fatf-defi-2026,SRC-treasury-defi-2023 -->
- **Affected Components**: Agent or MCP host, financial tool or signer, bridge and DEX integrations, chain indexers, and provenance analytics. <!-- SAF-TRACE: claims=SAF-T1915-C003,SAF-T1915-C005,SAF-T1915-C011; sources=SRC-sok-cross-chain-2026,SRC-pace-defi-agents-2026 -->
- **Trust Boundary Crossed**: Intent and policy decisions in the agentic system become irreversible externally settled transactions on multiple networks. <!-- SAF-TRACE: claims=SAF-T1915-C005,SAF-T1915-C017; sources=SRC-pace-defi-agents-2026 -->

## Technical Details

### Prerequisites

- The adversary controls or influences a transaction-capable agent, its instructions, or an authorized workflow. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C005; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026 -->
- The delegated wallet or signer can access a bridge and a DEX on at least two supported chains. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C005; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026 -->
- Policy enforcement permits the combined route or evaluates its legs without sequence-level context. <!-- SAF-TRACE: claims=SAF-T1915-C017,SAF-T1915-C018; sources=SRC-pace-defi-agents-2026 -->

### Attack Flow

1. **Setup**: The adversary identifies illicitly sourced assets and accessible bridge, DEX, wallet, and chain routes. <!-- SAF-TRACE: claims=SAF-T1915-C004,SAF-T1915-C011; sources=SRC-fatf-defi-2026,SRC-treasury-defi-2023,SRC-sok-cross-chain-2026 -->
2. **Planning**: The agent constructs a multi-step route that fragments, swaps, or changes networks while remaining within its delegated transaction envelope. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C005; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026 -->
3. **Execution**: The agent submits a bridge action and DEX swap, potentially repeating the sequence across wallets or networks. <!-- SAF-TRACE: claims=SAF-T1915-C004,SAF-T1915-C005; sources=SRC-fatf-defi-2026,SRC-treasury-defi-2023,SRC-pace-defi-agents-2026 -->
4. **Boundary Crossing**: Valid signatures and contracts settle the legs even when their combined purpose violates policy. <!-- SAF-TRACE: claims=SAF-T1915-C017,SAF-T1915-C018; sources=SRC-pace-defi-agents-2026 -->
5. **Objective**: The sequence layers and commingles funds, broadens their network footprint, and delays attribution or recovery. <!-- SAF-TRACE: claims=SAF-T1915-C001,SAF-T1915-C019; sources=SRC-fatf-defi-2026,SRC-fbi-bybit-2025 -->
6. **Follow-On Activity**: The actor may consolidate, move to another chain, or seek an off-ramp; these outcomes are not guaranteed by the technique. <!-- SAF-TRACE: claims=SAF-T1915-C004,SAF-T1915-C019; sources=SRC-fatf-defi-2026,SRC-treasury-defi-2023,SRC-fbi-bybit-2025 -->

### Example Scenario

This inert example shows the minimum correlation shape; it is not a working transaction request or evidence of an observed agentic incident. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C011; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026 -->

```json
{
  "subject_id": "wallet-example",
  "agent_intent_id": "intent-example",
  "events": [
    {"event_type": "bridge_deposit", "chain": "chain-a", "usd_value": 15000},
    {"event_type": "dex_swap", "chain": "chain-b", "usd_value": 14500}
  ],
  "provenance_risk": "stolen_funds",
  "policy_decision": "review"
}
```

## Evidence and Current State

### Evidence Summary

| Claim ID | Claim | Evidence Status | Source ID and Source | Limitations |
| --- | --- | --- | --- | --- |
| SAF-T1915-C001 | FATF identifies bridges, DEXs, swaps, mixers, and chain-hopping as layering mechanisms. | Observed | SRC-fatf-defi-2026: [FATF DeFi report](https://www.fatf-gafi.org/content/dam/fatf-gafi/reports/targeted-report-decentralised-finance-2026.pdf.coredownload.pdf) | Not an agentic incident. |
| SAF-T1915-C002 | An agent can in principle compose the observed mechanics, but production agentic use is not documented. | Research-Derived | SRC-fatf-defi-2026; SRC-pace-defi-agents-2026; SRC-sok-cross-chain-2026 | Explicit synthesis, not an observed event. |
| SAF-T1915-C003 | Bridge and cross-ledger services expose different matching evidence. | Research-Derived | SRC-sok-cross-chain-2026: [cross-chain matching survey](https://arxiv.org/pdf/2608.17532) | Event names vary by protocol. |
| SAF-T1915-C004 | Professional networks fragment and automate multi-service laundering routes. | Observed | SRC-fatf-defi-2026; SRC-treasury-defi-2023 | Not a universal sequence. |
| SAF-T1915-C005 | Controlled research demonstrates agent-generated DeFi swaps, approvals, and deposits. | Demonstrated | SRC-pace-defi-agents-2026: [PACE paper](https://arxiv.org/pdf/2608.17220) | Simulator omits bridge laundering. |
| SAF-T1915-C006 | The Bybit theft used DEXs, bridges, and a no-KYC swap service during laundering. | Observed | SRC-fbi-bybit-2025; SRC-chainalysis-bybit-2025 | Not agent-mediated. |
| SAF-T1915-C007 | Ronin proceeds crossed Ethereum, BNB, and BitTorrent through swaps and bridges. | Observed | SRC-chainalysis-ronin-2022 | Underlying graph is not published on the page. |
| SAF-T1915-C008 | Atomic Wallet proceeds moved via bridges toward Bitcoin and Tron. | Observed | SRC-chainalysis-atomic-2024 | Some joins used off-chain intelligence. |
| SAF-T1915-C009 | FATF reports a Canadian DEX-and-wallet stablecoin laundering case. | Observed | SRC-fatf-stablecoins-2026 | The DEX leg is not stated to cross chains. |
| SAF-T1915-C010 | Bridge weaknesses can enable theft but are adjacent to post-theft laundering. | Observed | SRC-fbi-defi-2022 | Advisory anonymizes products and CVEs. |
| SAF-T1915-C011 | Hashes, event IDs, receiver, token, amount, time, ABI, platform records, and risk labels support matching. | Research-Derived | SRC-sok-cross-chain-2026 | Availability varies. |
| SAF-T1915-C012 | Deterministic bridge join evidence is stronger than time-and-value heuristics. | Research-Derived | SRC-sok-cross-chain-2026 | Official records may still be incomplete. |
| SAF-T1915-C013 | Missing counterparts and similarity heuristics are ambiguous. | Research-Derived | SRC-sok-cross-chain-2026 | Survey tests matching, not this detector. |
| SAF-T1915-C014 | Legitimate bridge use requires provenance and sequence context. | Research-Derived | SRC-chainalysis-ronin-2022; SRC-fatf-defi-2026 | No universal false-positive rate. |
| SAF-T1915-C015 | Unsupported chains, private transfers, pooling, keys, and OTC routes create blind spots. | Research-Derived | SRC-fatf-defi-2026; SRC-chainalysis-theft-2026 | Importance varies by investigation. |
| SAF-T1915-C016 | Real-time multi-chain tracing and pattern detection can prioritize investigations. | Research-Derived | SRC-fatf-defi-2026; SRC-fbi-defi-2022 | No universal thresholds. |
| SAF-T1915-C017 | Typed intents, allowlists, simulation, validity windows, and byte binding constrain agent transactions. | Demonstrated | SRC-pace-defi-agents-2026 | Benchmark evidence is not deployment assurance. |
| SAF-T1915-C018 | Individually valid legs may compose into a harmful multi-step sequence. | Research-Derived | SRC-pace-defi-agents-2026 | Production frequency is unknown. |
| SAF-T1915-C019 | Consequences include delayed recovery and broader dissipation; severity depends on value and speed. | Research-Derived | SRC-fbi-bybit-2025; SRC-fatf-defi-2026 | Cash-out or permanent loss is not proven. |
| SAF-T1915-C020 | ATT&CK Financial Theft is analogous, not equivalent. | Research-Derived | SRC-mitre-t1657-2026 | ATT&CK has no separate cross-chain laundering technique. |

### Current State

- **Affected Environments**: Agentic hosts or financial tools with delegated wallet or signer authority and bridge-plus-DEX reach across multiple chains. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C005; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026 -->
- **Known Exploitation**: Production bridge-and-DEX laundering is documented, but the [source-coverage review](../../research/techniques/SAF-T1915/source-coverage.yml) found no qualifying production MCP or agentic incident.
- **Available Protections**: Deterministic intent policies, contract and target allowlists, simulation, validity windows, execution binding, and real-time multi-chain analytics can constrain or surface the behavior. <!-- SAF-TRACE: claims=SAF-T1915-C016,SAF-T1915-C017; sources=SRC-fatf-defi-2026,SRC-fbi-defi-2022,SRC-pace-defi-agents-2026 -->
- **Residual Risk**: Multi-step composition and incomplete cross-chain data can defeat per-leg policy checks or correlation. <!-- SAF-TRACE: claims=SAF-T1915-C013,SAF-T1915-C015,SAF-T1915-C018; sources=SRC-sok-cross-chain-2026,SRC-fatf-defi-2026,SRC-chainalysis-theft-2026,SRC-pace-defi-agents-2026 -->

### Known Breaches and Vulnerabilities

| Event or Identifier | Date and Environment | Impact and Remediation | Relationship to This Technique | Evidence Limitation |
| --- | --- | --- | --- | --- |
| Bybit theft | 2025; multiple public chains and services | About $1.5 billion was stolen; service coordination froze some funds. | Direct production laundering through DEXs, bridges, and a swap service. | Not agent-mediated; recovery figures changed during reporting. <!-- SAF-TRACE: claims=SAF-T1915-C006; sources=SRC-fbi-bybit-2025,SRC-chainalysis-bybit-2025 --> |
| Ronin theft | 2022; Ethereum, BNB, and BitTorrent routes | More than $600 million was stolen and more than $30 million was later seized. | Direct production chain-hopping through bridges and swaps. | Not agent-mediated; public page omits the underlying address graph. <!-- SAF-TRACE: claims=SAF-T1915-C007; sources=SRC-chainalysis-ronin-2022 --> |
| Atomic Wallet theft | 2023; Avalanche Bridge, Bitcoin, and Tron routes | Stolen assets were dispersed through a multi-phase cross-chain route. | Direct production laundering through bridge-mediated chain changes. | Not agent-mediated; compromise method was unclear and some joins used off-chain intelligence. <!-- SAF-TRACE: claims=SAF-T1915-C008; sources=SRC-chainalysis-atomic-2024 --> |

The reviewed vulnerability advisories describe bridge and smart-contract flaws that enabled theft, but no CVE, government exploited-vulnerability entry, or product flaw was found whose vulnerable behavior is laundering itself. <!-- SAF-TRACE: claims=SAF-T1915-C010; sources=SRC-fbi-defi-2022 -->

## Impact Assessment

| Dimension | Rating | Rationale and Conditions |
| --- | --- | --- |
| Confidentiality | Low | The sequence moves value; disclosure is incidental unless transaction or identity telemetry exposes additional sensitive context. <!-- SAF-TRACE: claims=SAF-T1915-C019; sources=SRC-fbi-bybit-2025,SRC-fatf-defi-2026 --> |
| Integrity | High | Authorized agent actions can change asset ownership, chain, and token form when signer authority is broad. <!-- SAF-TRACE: claims=SAF-T1915-C005,SAF-T1915-C019; sources=SRC-pace-defi-agents-2026,SRC-fbi-bybit-2025,SRC-fatf-defi-2026 --> |
| Availability | Low | Service freezes or investigation may interrupt access, but disruption is not the primary objective. <!-- SAF-TRACE: claims=SAF-T1915-C006,SAF-T1915-C019; sources=SRC-fbi-bybit-2025,SRC-chainalysis-bybit-2025,SRC-fatf-defi-2026 --> |
| Scope | Multi-System | Each leg can cross an agent host, signer, bridge, DEX, and multiple independent networks. <!-- SAF-TRACE: claims=SAF-T1915-C003,SAF-T1915-C019; sources=SRC-sok-cross-chain-2026,SRC-fbi-bybit-2025,SRC-fatf-defi-2026 --> |

### Severity Conditions

- **Severity increases when**: Delegated value is high, automated execution is rapid, destination chains are weakly monitored, and approval gates do not evaluate the full sequence. <!-- SAF-TRACE: claims=SAF-T1915-C015,SAF-T1915-C018,SAF-T1915-C019; sources=SRC-fatf-defi-2026,SRC-chainalysis-theft-2026,SRC-pace-defi-agents-2026,SRC-fbi-bybit-2025 -->
- **Severity decreases when**: Signer scope, destination and contract allowlists, value limits, simulation, and sequence-aware approvals constrain execution. <!-- SAF-TRACE: claims=SAF-T1915-C017,SAF-T1915-C018; sources=SRC-pace-defi-agents-2026 -->

## Detection Methods

### Required Telemetry

| Source | Events or Actions | Required Fields | Collection Notes |
| --- | --- | --- | --- |
| Agent host, policy, and signer logs | Intent, policy decision, approval, and signed transaction | Subject, intent, policy decision, signer, timestamp, transaction hash | Preserve stable joins from intent through settlement. <!-- SAF-TRACE: claims=SAF-T1915-C005,SAF-T1915-C011,SAF-T1915-C017; sources=SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026 --> |
| Multi-chain indexers and bridge or DEX records | Deposit, withdrawal, claim, swap, transfer, and receipt | Chain, transaction hash, event ID, receiver, token, amount, timestamp, contract, service, bridge join | Prefer deterministic identifiers; normalize clocks, tokens, and addresses. <!-- SAF-TRACE: claims=SAF-T1915-C003,SAF-T1915-C011,SAF-T1915-C012; sources=SRC-sok-cross-chain-2026 --> |
| Provenance and entity analytics | Source-of-funds risk, service attribution, and related-wallet context | Subject, address, risk class, evidence, confidence, first seen, last seen | Retain provenance and confidence because rapid bridge use alone is ambiguous. <!-- SAF-TRACE: claims=SAF-T1915-C011,SAF-T1915-C013,SAF-T1915-C014; sources=SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026 --> |

### Indicators of Compromise (IoCs)

- No durable, technique-specific IoC is known; wallet addresses, contracts, and services change, and the technique is defined by behavior and provenance context. <!-- SAF-TRACE: claims=SAF-T1915-C011,SAF-T1915-C013,SAF-T1915-C014; sources=SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026 -->

### Behavioral Indicators

- A risky-provenance subject performs a bridge event and a DEX swap across at least two chains in a short interval while conserving most value. <!-- SAF-TRACE: claims=SAF-T1915-C004,SAF-T1915-C011,SAF-T1915-C014; sources=SRC-fatf-defi-2026,SRC-treasury-defi-2023,SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022 -->
- Fragmentation across wallets, repeated swaps, or rapid chain changes increases investigative priority when deterministic bridge evidence links the legs. <!-- SAF-TRACE: claims=SAF-T1915-C004,SAF-T1915-C012,SAF-T1915-C016; sources=SRC-fatf-defi-2026,SRC-treasury-defi-2023,SRC-sok-cross-chain-2026,SRC-fbi-defi-2022 -->
- Missing counterparts, similar time and value, or a bridge event without provenance must be treated as ambiguous rather than conclusive. <!-- SAF-TRACE: claims=SAF-T1915-C013,SAF-T1915-C014; sources=SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026 -->

### Detection Analytic

The standalone example analytic is maintained in [detection-rule.yml](detection-rule.yml).

- **Analytic Goal**: Triage risky-provenance subjects that combine bridge and DEX activity across chains within a bounded time and value-conservation window. <!-- SAF-TRACE: claims=SAF-T1915-C004,SAF-T1915-C011,SAF-T1915-C014; sources=SRC-fatf-defi-2026,SRC-treasury-defi-2023,SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022 -->
- **Rule Status**: Experimental, as recorded in [detection-rule.yml](detection-rule.yml).
- **Detection Logic**: Require risky provenance, at least one bridge event, at least one DEX swap, two chains, a value floor, and bounded time and value ratio. <!-- SAF-TRACE: claims=SAF-T1915-C002,SAF-T1915-C004,SAF-T1915-C014; sources=SRC-fatf-defi-2026,SRC-pace-defi-agents-2026,SRC-sok-cross-chain-2026,SRC-treasury-defi-2023,SRC-chainalysis-ronin-2022 -->
- **Correlation Window**: Thirty minutes inclusive in the example [detection rule](detection-rule.yml); operators must calibrate this unsourced engineering threshold.
- **Known False Positives**: Treasury rebalancing, recovery or seizure operations, stale risk labels, dusting, and address-poisoning can satisfy the shape. <!-- SAF-TRACE: claims=SAF-T1915-C013,SAF-T1915-C014; sources=SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026 -->
- **Known Limitations**: Split subject identifiers, missing counterpart events, pooled settlement, unsupported chains, private-key transfers, and OTC activity can evade correlation. <!-- SAF-TRACE: claims=SAF-T1915-C013,SAF-T1915-C015; sources=SRC-sok-cross-chain-2026,SRC-fatf-defi-2026,SRC-chainalysis-theft-2026 -->
- **Tuning Guidance**: Prefer deterministic bridge joins; tune values and time by service; baseline approved treasury and recovery workflows; preserve the provenance evidence behind each label. <!-- SAF-TRACE: claims=SAF-T1915-C011,SAF-T1915-C012,SAF-T1915-C013,SAF-T1915-C014; sources=SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026 -->

### Validation

- **Test Data**: [test-cases.json](../../tests/SAF-T1915/test-cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T1915/test_detection_rule.py)
- **Expected Result**: The [recorded test log](../../tests/SAF-T1915/test-logs.json) requires all 12 cases to match, including five alert and seven no-alert expectations.
- **Last Validated**: 2026-09-02 in the [quality review](../../research/techniques/SAF-T1915/quality-review.yml).
- **Canonical Validation Proof**: The passing destination detector and strict-validator results are recorded in [canonical-validation.txt](../../research/techniques/SAF-T1915/validation/canonical-validation.txt).
- **Feasibility Waiver**: None; the deterministic fixture suite covers positive, negative, boundary, malformed, expected-false-positive, normalization, and evasion cases in [test-cases.json](../../tests/SAF-T1915/test-cases.json).

## Mitigation Strategies

### Preventive Controls

1. Require typed intents, target and contract allowlists, validity windows, simulation, and byte-bound approvals before an agent signs a DeFi transaction. <!-- SAF-TRACE: claims=SAF-T1915-C017; sources=SRC-pace-defi-agents-2026 -->
2. Evaluate proposed transaction bundles and recent settled activity as a sequence, because individually policy-valid legs may compose into a harmful route. <!-- SAF-TRACE: claims=SAF-T1915-C018; sources=SRC-pace-defi-agents-2026 -->
3. Apply per-intent value, chain, asset, and service limits with human approval for cross-chain expansion or risky provenance. <!-- SAF-TRACE: claims=SAF-T1915-C017,SAF-T1915-C019; sources=SRC-pace-defi-agents-2026,SRC-fbi-bybit-2025,SRC-fatf-defi-2026 -->

### Detective Controls

1. Correlate real-time multi-chain traces through bridges and smart contracts and prioritize layering or peeling patterns for review. <!-- SAF-TRACE: claims=SAF-T1915-C016; sources=SRC-fatf-defi-2026,SRC-fbi-defi-2022 -->
2. Preserve deterministic bridge joins and supplement them with explicitly confidence-scored time, value, token, and address heuristics. <!-- SAF-TRACE: claims=SAF-T1915-C011,SAF-T1915-C012,SAF-T1915-C013; sources=SRC-sok-cross-chain-2026 -->

### Response Procedures

#### Immediate Actions

- Pause the agent's transaction capability and signer session while preserving intent, policy, transaction, bridge, DEX, and provenance records. <!-- SAF-TRACE: claims=SAF-T1915-C011,SAF-T1915-C016,SAF-T1915-C017; sources=SRC-sok-cross-chain-2026,SRC-fatf-defi-2026,SRC-fbi-defi-2022,SRC-pace-defi-agents-2026 -->
- Notify affected services with verified transaction hashes and destination addresses when lawful freezing or recovery coordination is available. <!-- SAF-TRACE: claims=SAF-T1915-C006,SAF-T1915-C007,SAF-T1915-C016; sources=SRC-fbi-bybit-2025,SRC-chainalysis-bybit-2025,SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026,SRC-fbi-defi-2022 -->

#### Investigation Steps

- Reconstruct source and destination legs using deterministic event identifiers first, then document the confidence and ambiguity of heuristic matches. <!-- SAF-TRACE: claims=SAF-T1915-C003,SAF-T1915-C011,SAF-T1915-C012,SAF-T1915-C013; sources=SRC-sok-cross-chain-2026 -->
- Review agent intent, policy decisions, signer use, wallet relationships, unsupported networks, pooled services, and possible off-chain conversion. <!-- SAF-TRACE: claims=SAF-T1915-C011,SAF-T1915-C015,SAF-T1915-C017; sources=SRC-sok-cross-chain-2026,SRC-fatf-defi-2026,SRC-chainalysis-theft-2026,SRC-pace-defi-agents-2026 -->

#### Remediation

- Reduce signer scope, revoke unsafe sessions, and add sequence-level policy constraints for bridge-plus-DEX routes. <!-- SAF-TRACE: claims=SAF-T1915-C017,SAF-T1915-C018; sources=SRC-pace-defi-agents-2026 -->
- Add the reconstructed route and legitimate lookalikes to regression tests, then tune correlation against local bridge and DEX baselines. <!-- SAF-TRACE: claims=SAF-T1915-C012,SAF-T1915-C013,SAF-T1915-C014; sources=SRC-sok-cross-chain-2026,SRC-chainalysis-ronin-2022,SRC-fatf-defi-2026 -->

## Related Techniques

| Technique | Relationship | Distinction |
| --- | --- | --- |
| [SAF-T2104: Fraudulent Transactions](../SAF-T2104/README.md) | Prerequisite or adjacent | Theft or unauthorized transfer obtains or moves assets without authority; this technique layers already illicit proceeds. <!-- SAF-TRACE: claims=SAF-T1915-C010; sources=SRC-fbi-defi-2022 --> |

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Mapping Type | Rationale |
| --- | --- | --- | --- |
| [T1657](https://attack.mitre.org/techniques/T1657/) | Financial Theft | Analogous | T1657 includes theft of cryptocurrency, while this SAF technique concerns post-theft layering and is not behaviorally equivalent. <!-- SAF-TRACE: claims=SAF-T1915-C020; sources=SRC-mitre-t1657-2026 --> |

## References

1. **SRC-fatf-defi-2026**: [Targeted Report on Regulatory Challenges from Decentralised Finance](https://www.fatf-gafi.org/content/dam/fatf-gafi/reports/targeted-report-decentralised-finance-2026.pdf.coredownload.pdf) — Financial Action Task Force, July 2026.
2. **SRC-fatf-stablecoins-2026**: [Targeted Report on Stablecoins and Unhosted Wallets](https://www.fatf-gafi.org/content/dam/fatf-gafi/publications/targeted-report-on-stablecoins-and-unhosted-wallets.pdf.coredownload.inline.pdf) — Financial Action Task Force, March 2026.
3. **SRC-treasury-defi-2023**: [Treasury Releases 2023 DeFi Illicit Finance Risk Assessment](https://home.treasury.gov/news/press-releases/jy1391) — Office of Terrorist Financing and Financial Crimes, U.S. Department of the Treasury, 2023.
4. **SRC-fbi-bybit-2025**: [North Korea Responsible for $1.5 Billion Bybit Hack](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack) — FBI Cyber Division, 2025.
5. **SRC-chainalysis-bybit-2025**: [Bybit Hack](https://www.chainalysis.com/blog/bybit-exchange-hack-february-2025-crypto-security-dprk/) — Chainalysis Team, updated 2025.
6. **SRC-chainalysis-ronin-2022**: [$30 Million Seized](https://www.chainalysis.com/blog/axie-infinity-ronin-bridge-dprk-hack-seizure/) — Erin Plante and the Chainalysis Crypto Incident Response Team, 2022.
7. **SRC-chainalysis-atomic-2024**: [Stolen Crypto Falls in 2023, but Hacking Remains a Threat](https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2024/) — Chainalysis Team, 2024.
8. **SRC-chainalysis-theft-2026**: [North Korea Drives Record Crypto Theft Year](https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2026/) — Chainalysis Team, 2025.
9. **SRC-fbi-defi-2022**: [Cyber Criminals Increasingly Exploit Vulnerabilities in DeFi Platforms](https://www.ic3.gov/PSA/2022/PSA220829) — FBI and Internet Crime Complaint Center, 2022.
10. **SRC-sok-cross-chain-2026**: [SoK: Cross-Chain Transaction Identification and Matching](https://arxiv.org/pdf/2608.17532) — Hang Zheng, Qishuang Fu, Joseph Liu, Qin Wang, Weiqing Wang, and Tsz Hon Yuen, 2026.
11. **SRC-pace-defi-agents-2026**: [Policy-Attested Contract Execution for Safe AI Agents in Decentralized Finance](https://arxiv.org/pdf/2608.17220) — Rabimba Karanjai, Yang Lu, Richard Williamson, Hemanth Hm, Prakhar Mehrotra, Lei Xu, and Weidong (Larry) Shi, 2026.
12. **SRC-mitre-t1657-2026**: [MITRE ATT&CK T1657 Financial Theft](https://attack.mitre.org/techniques/T1657/) — Blake Strom, Menachem Goldstein, Pawel Partyka, and the MITRE ATT&CK Team; version 1.2, 2026.

## Version History

| Version | Date | Changes | Author |
| --- | --- | --- | --- |
| 0.1 | 2026-09-02 | Initial clean-room draft | OpenAI Codex clean-room agent /root/cleanroom_saf_t1915 |
