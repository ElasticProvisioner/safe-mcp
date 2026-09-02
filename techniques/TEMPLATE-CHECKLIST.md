# SAF Technique Completion Checklist

Use this checklist with the [technique template](TEMPLATE.md) and the
[research protocol](../research/README.md). A polished README is necessary but
not sufficient: the research packet and its validation gates are part of a new
technique contribution.

## Contract and Classification

- [ ] `technique-contract.yml` defines one coherent adversary behavior.
- [ ] The adversary objective and crossed or abused trust boundary are explicit.
- [ ] In-scope and out-of-scope behavior is testable rather than aspirational.
- [ ] The closest existing SAF techniques were reviewed and distinguished.
- [ ] The candidate passes the admission rule: atomic behavior, agentic dependency or explicit profile, distinct boundary, and operational value.
- [ ] The proposed ID is unused, opaque, permanent, and its tactic assignment is justified.
- [ ] SAF Core and applicable domain profiles are assigned explicitly.
- [ ] Relationships use canonical types and have the required inverse records.
- [ ] The entry is present and consistent in `research/framework-model.yml`.

## Claims and Evidence

- [ ] Material claims were inventoried before or during research, not reconstructed only after drafting.
- [ ] Every material claim has a stable `claim_id`, class, materiality, limitations, and status.
- [ ] Every supporting source has a stable `source_id` in `research/source-manifest.yml`.
- [ ] Every source was opened and reviewed beyond a snippet, abstract, or generated summary.
- [ ] Exact sections, pages, paragraphs, commits, lines, advisories, or stable headings are recorded.
- [ ] Inference, historical analogy, and direct MCP evidence are kept distinct.
- [ ] Conflicting evidence and unsuccessful source access are recorded.
- [ ] Two consecutive no-change passes support the documented saturation decision.
- [ ] The technique-level evidence status is justified for the complete behavior.

## Technique Document

- [ ] **Overview** includes tactic, ID, research packet, documentation status, evidence status, severity rationale, observation status, and dates.
- [ ] **Overview** includes lifecycle status and applicable framework profiles.
- [ ] **Scope** defines the boundary, inclusions, exclusions, and distinguishing characteristics.
- [ ] **Description** states the objective, MCP-specific mechanism, boundary, and uncertainty.
- [ ] **Attack Vectors** identify delivery paths, affected components, and the boundary crossed.
- [ ] **Technical Details** include prerequisites, staged flow, and one safe end-to-end scenario.
- [ ] **Evidence and Current State** uses matching claim IDs and source IDs.
- [ ] **Impact Assessment** rates confidentiality, integrity, availability, and scope conditionally.
- [ ] **Detection Methods** name telemetry, fields, behavioral indicators, logic, false positives, limits, and tuning.
- [ ] **Mitigation Strategies** address the defining mechanism and link to valid SAF mitigation IDs.
- [ ] **Related Techniques** state both the relationship and the non-duplicate boundary.
- [ ] **MITRE ATT&CK Mapping** is labeled `Direct` or `Analogous` with a behavioral rationale.
- [ ] **References** contain every materially used source and its source ID.
- [ ] **Version History** records the contribution.

## Detection and Validation

- [ ] `detection-rule.yml` contains the complete example analytic and a unique UUID.
- [ ] The README does not duplicate the complete detection rule.
- [ ] The analytic uses only telemetry and fields named in the technique.
- [ ] Positive, negative, boundary, and expected false-positive cases are tested when feasible.
- [ ] Detection maturity is recorded without treating syntax validity as evidence of effectiveness.
- [ ] Test commands and outcomes are recorded in `quality-review.yml`.
- [ ] If testing is infeasible, the contract and README contain a specific, reviewer-approved waiver.
- [ ] Detection limitations do not claim prevention or comprehensive coverage.

## Rights, Safety, and Alignment

- [ ] `publication-rights.yml` covers every cited source and third-party artifact.
- [ ] Quotations, code, diagrams, datasets, trademarks, and adaptations have an explicit basis for use.
- [ ] Examples use inert domains, placeholder credentials, and non-destructive operations.
- [ ] Research-driven changes needed elsewhere are tracked in `research/alignment-ledger.yml`.
- [ ] No unresolved high-severity alignment or publication-rights issue remains.
- [ ] `quality-review.yml` records a passing result for every gate.
- [ ] `python3 scripts/validate-technique-research.py SAF-TXXXX` passes.
- [ ] `python3 scripts/validate-framework-model.py` passes the evidence, taxonomy, and operational release gates.
- [ ] `python3 scripts/generate-technique-catalog.py --check` confirms that the public catalog is current.

## Directory Structure

```text
techniques/
└── SAF-TXXXX/
    ├── README.md
    ├── detection-rule.yml
    ├── test-logs.json             # Required when representative testing is feasible
    └── test_detection_rule.py     # Or an equivalent validation command

research/
├── source-manifest.yml
├── framework-model.yml
├── alignment-ledger.yml
└── techniques/
    └── SAF-TXXXX/
        ├── technique-contract.yml
        ├── claim-inventory.yml
        ├── source-coverage.yml
        ├── publication-rights.yml
        └── quality-review.yml
```

## Style Rules

- Use objective, mechanism-specific language.
- Prefer current primary sources, specifications, advisories, implementation artifacts, and peer-reviewed research.
- State uncertainty and preconditions near the affected claim.
- Use canonical identifiers such as `SAF-T1001`, `SAF-M-1`, and `ATK-TA0001`.
- Use `Not observed in production` when no directly reviewed source establishes real-world MCP or agentic-system exploitation.
- Do not call generic behavior an indicator of compromise.
- Do not treat a valid Sigma document as proof that its analytic is effective.
