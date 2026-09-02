# Post-Freeze Framework Reconciliation

Run this stage only after the technique contract, evidence set, and clean-room
draft (when applicable) are frozen. Its purpose is ontology reconciliation, not
literature research or factual drafting.

## Admission decision

A candidate is admitted only when all four conditions hold:

1. It describes one atomic adversary behavior, not a product, weakness, impact,
   mitigation, or complete attack chain.
2. It materially depends on an agentic property, or it is explicitly scoped to
   a domain profile.
3. Its mechanism, trust-boundary crossing, initiating principal, or operational
   observables distinguish it from every active technique.
4. It provides operational value through defensible telemetry, analysis,
   prevention, response, or threat-model decisions.

If any condition fails, reject, reclassify as a procedure or profile example,
or consolidate into an existing technique. Do not assign a new ID merely to
preserve a draft.

## Reconciliation sequence

1. Compare the frozen contract with active techniques by mechanism, security
   boundary, initiating principal, immediate outcome, and observables.
2. Assign SAF Core only when the behavior materially depends on model-mediated
   decisions, delegated action, dynamic context, memory, or agent coordination.
3. Assign every applicable domain profile: MCP, Code-Agent, RAG and Memory,
   Financial-Agent, or Model-Lifecycle.
4. Map the unchanged mechanism to every applicable tactic. Do not create a
   second technique solely because the same mechanism serves another tactic.
5. Record typed relationships and their required inverse. Use `related_to` only
   when no more precise type applies.
6. Set detection maturity conservatively: `proposed`, `syntax_validated`,
   `fixture_tested`, `telemetry_replay_tested`, or `field_evaluated`.
7. Record the decision and evidence inputs in `research/taxonomy-review.yml`.
8. Preserve superseded IDs as deprecated compatibility records with explicit
   replacements. Never reuse an ID or discard its evidence packet.

## Clean-room boundary

The reconciliation stage may change taxonomy metadata, canonical naming,
profile placement, tactic mappings, or lifecycle. It must not use the existing
technique page to generate factual content, add unresearched claims, or alter
the frozen evidence status. If reconciliation reveals a factual gap, reopen a
separate research pass and re-freeze before publication.

## Release gates

Complete all three gates:

- **Evidence:** source-or-omit traceability, classification, saturation,
  publication rights, and author credit pass.
- **Taxonomy:** admission, profile placement, tactic mappings, canonical names,
  typed relationships, inverse edges, and deprecations pass.
- **Operational:** detection artifacts, maturity label, local links, generated
  catalog, and deterministic tests pass.

Run:

```bash
python3 scripts/validate-technique-research.py SAF-TXXXX
python3 scripts/validate-framework-model.py
python3 scripts/generate-technique-catalog.py --check
```
