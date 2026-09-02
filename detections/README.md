# SAF Detection Coverage Registry

This directory is the operational projection of the canonical
[`research/framework-model.yml`](../research/framework-model.yml) technique
catalog. It answers three bounded questions:

1. Which SAF technique does an analytic claim to address?
2. Which normalized observation modalities appear in its telemetry contract?
3. How mature and independently maintained is the mapping?

The generated [`COVERAGE.md`](COVERAGE.md) matrix is an inventory, not an
effectiveness claim. A mapped or fixture-tested rule is not proof that the rule
will detect every implementation of a technique, perform acceptably in
production, or remain compatible with an upstream project.

## Mapping semantics

Every native or external mapping has one relationship to a technique:

- `direct`: the analytic's required conditions represent the technique's full
  observable discriminator.
- `partial`: the analytic represents a bounded subset of the technique.
- `adjacent`: the analytic provides supporting context but does not by itself
  represent the technique.

The registry defaults native rules to `partial`. A stronger classification
requires review; validation maturity alone does not upgrade the relationship.

The normalized observation modalities are:

| Modality | Observation boundary |
| --- | --- |
| `content` | Model-visible text, metadata, schemas, responses, or other payload content |
| `static` | Artifacts examined without executing the target component |
| `runtime` | Agent, MCP host, server, tool, or application execution events |
| `gateway` | MCP, API, proxy, or policy-enforcement gateway events |
| `endpoint` | Operating-system process, file, memory, or configuration events |
| `identity` | Authentication, authorization, token, consent, or principal-binding events |
| `network` | Connection, protocol, routing, or egress events |
| `memory` | Persistent context, retrieval, vector-store, or shared-memory events |
| `multimodal` | Image, audio, video, OCR, transcription, or cross-modal events |
| `model-lifecycle` | Dataset, training, evaluation, model-registry, or promotion events |
| `on-chain` | Blockchain transaction, bridge, exchange, or ledger events |

Modalities are multi-valued. They describe observation surfaces represented in
the mapping, not product categories, universal requirements, or exclusive
deployment layers.

## Ownership boundary

SAF owns the canonical technique ID, mapping relationship, normalized
modalities, link integrity, review state, and the generated matrix. For native
rules in this repository, SAF also owns the rule and its fixture tests.

For external rules, the upstream provider owns rule content, release and engine
compatibility, licensing, tests, deployment guidance, and operational
correctness. SAF validation checks the mapping metadata and repository links;
it does not certify an upstream rule. External mappings count in the matrix
only when their status is `validated`.

## External contribution contract

Add a provider manifest under `providers/` and a mapping to
[`external-mappings.yml`](external-mappings.yml). A validated mapping requires:

- a current, active SAF technique ID;
- a stable provider and rule identifier;
- a rule URL and a declared upstream version;
- one mapping relationship and at least one normalized modality;
- an upstream maintainer and license recorded by the provider manifest;
- an evidence URL explaining the mapping;
- an ISO `YYYY-MM-DD` review date; and
- `status: validated` only after SAF review.

Use `candidate` while reconciliation is incomplete. Candidate and retired
mappings remain visible for provenance but do not contribute to coverage
counts. Deprecated SAF IDs cannot receive new validated mappings; map their
active replacements instead.

```yaml
- mapping_id: example-rule-to-saf-t1001
  technique_id: SAF-T1001
  provider_id: example
  rule_id: EXAMPLE-001
  rule_version: 1.2.0
  rule_url: https://example.org/rules/EXAMPLE-001
  evidence_url: https://example.org/mappings/EXAMPLE-001
  relationship: partial
  modalities: [content, runtime]
  status: candidate
  reviewed_on: 2026-09-02
```

Run:

```bash
python3 scripts/validate-detection-registry.py
python3 scripts/generate-detection-coverage.py --check
```

Run the generator without `--check` after an accepted registry change.
