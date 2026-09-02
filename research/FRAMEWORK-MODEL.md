# Secure Agentic Framework Model

`framework-model.yml` is the canonical registry for SAF technique identity,
lifecycle, profiles, tactics, relationships, evidence status, mitigations, and
detection maturity. Public catalogs must be generated from that registry rather
than maintained as a second hand-edited inventory.

## Technique admission

A proposed technique must satisfy every condition below.

1. **Atomic behavior:** it describes one adversary behavior, not a product,
   vulnerability, weakness, impact category, or complete attack chain.
2. **Agentic dependency:** the behavior materially depends on model-mediated
   decisions, delegated action, dynamic context or memory, agent coordination,
   or a named agent-protocol boundary. Generic behavior belongs in an external
   framework mapping unless an SAF profile supplies a narrower mechanism.
3. **Observable discriminator:** an analyst can distinguish the behavior from
   its nearest SAF neighbors using a boundary, event sequence, object, carrier,
   principal, or other reviewable observable.
4. **Non-duplication:** a different tactic or downstream outcome does not create
   a new technique when the mechanism is unchanged. One technique may map to
   several tactics and profiles.
5. **End-to-end evidence:** the evidence status describes the complete defined
   behavior rather than an analogy or one independently supported component.
6. **Operational boundary:** required telemetry and analytic limitations are
   stated even when detection is waived.

Technique identifiers are opaque and permanent. Deprecation never deletes or
reuses an identifier; a deprecated record names its replacement and remains
available as a compatibility page.

## Profiles

- **SAF Core:** mechanisms that materially depend on agentic behavior.
- **MCP Profile:** Model Context Protocol hosts, clients, servers, tools,
  resources, prompts, sampling, authorization, and transports.
- **Code-Agent Profile:** coding assistants, repositories, build systems,
  shells, and file-oriented agents.
- **RAG and Memory Profile:** retrieval, embeddings, persistent context, and
  shared memory.
- **Financial-Agent Profile:** payment, trading, blockchain, and other
  delegated financial authority.
- **Model-Lifecycle Profile:** training, adaptation, evaluation, promotion, and
  deployment of model artifacts.

Profiles are applicability views, not separate identifier namespaces. A
technique may appear in more than one profile.

## Relationships

Relationships are typed. `related_to`, `alternative_to`, and `overlaps_with`
are symmetric. Directional relationships must have their declared inverse:
`specialization_of`/`has_specialization`, `enables`/`enabled_by`,
`precedes`/`follows`, and `replaces`/`replaced_by`.

## Release gates

Every active technique must pass three independent gates:

1. **Evidence:** source-or-omit traceability, current research, evidence
   calibration, rights review, and safe publication.
2. **Taxonomy:** admission test, nearest-neighbor comparison, profile placement,
   tactic mapping, typed relationships, and non-duplication.
3. **Operational:** telemetry contract, analytic implementation, documented
   limitations, and an explicit detection-validation level.

Clean-room generation is followed by a cross-corpus ontology review after the
draft and evidence set are frozen. That review may merge, deprecate, profile, or
relate techniques without changing the frozen factual claims.

## Detection validation

Detection maturity is recorded independently of evidence maturity:

1. `proposed`
2. `syntax_validated`
3. `fixture_tested`
4. `telemetry_replay_tested`
5. `field_evaluated`

Passing synthetic positive, negative, boundary, and false-positive fixtures is
`fixture_tested`; it must not be represented as production effectiveness.

The [`detections/registry.yml`](../detections/registry.yml) operational
projection adds normalized observation modalities and a bounded semantic
relationship for each native analytic. The generated
[`detections/COVERAGE.md`](../detections/COVERAGE.md) matrix also distinguishes
SAF-owned analytics from externally maintained rules. Mapping presence and
validation maturity remain separate from production effectiveness.
