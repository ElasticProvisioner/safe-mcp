# SAF Technique Research Protocol

This directory contains the evidence model used to research, author, and review
SAF-MCP techniques. The publishable technique remains in
`techniques/SAF-TXXXX/README.md`; its research packet lives in
`research/techniques/SAF-TXXXX/`.

The model uses three stable join keys:

- `technique_id` connects the published technique, research packet, and
  framework model.
- `claim_id` connects prose and evidence-summary claims to the claim inventory.
- `source_id` connects claims and citations to a directly reviewed source in
  `source-manifest.yml`.

## Required Artifacts

Every new technique must include:

```text
techniques/SAF-TXXXX/
├── README.md
└── detection-rule.yml

research/techniques/SAF-TXXXX/
├── technique-contract.yml
├── claim-inventory.yml
├── source-coverage.yml
├── publication-rights.yml
└── quality-review.yml
```

Add `test-logs.json` and a validation script when a detection analytic can be
tested. If representative telemetry does not exist or the behavior is not
reliably detectable, record an explicit waiver in the technique contract and
describe the limitation in the technique.

Install the development dependency, then create the initial files from the
canonical templates:

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/new-technique.py SAF-TXXXX "Technique Name"
```

## Authoring Workflow

### 1. Establish the contract

Write `technique-contract.yml` before drafting prose. Bound the adversary
behavior, affected components, trust boundary, exclusions, nearest neighbors,
required evidence, and completion conditions. A technique should describe one
coherent adversary behavior rather than a product vulnerability, mitigation,
impact, or broad threat category.

Review the existing catalog before reserving an ID. A new entry must be
distinct from its nearest SAF techniques by mechanism, boundary crossing,
objective, or materially different observables.

### 2. Build the claim inventory

List material claims before writing the technique. Classify each claim as one
of:

- `protocol_normative`: a requirement or defined behavior in a current
  protocol, standard, or RFC.
- `observed_incident`: behavior documented in a real MCP or agentic-system
  incident.
- `demonstrated_exploit`: behavior reproduced in a public proof of concept,
  lab, or controlled evaluation.
- `research_finding`: a result supported by research with a reviewable method.
- `implementation_fact`: behavior established by first-party code,
  documentation, advisory, or release artifact.
- `historical_analogy`: analogous behavior outside MCP or agentic systems.
- `framework_inference`: an SAF synthesis derived from supported components.

Record materiality, exact source locators, limitations, conflicts, inference,
and validation status. A historical analogy cannot establish that an MCP
technique has been observed. An inference must be labeled even when all of its
premises are well supported.

### 3. Research in four passes

1. **Protocol and authority pass**: Find current MCP specifications, applicable
   RFCs, standards, and first-party security requirements. Record versions and
   precise sections.
2. **Incident and demonstration pass**: Find primary incident reports,
   advisories, CVEs, public demonstrations, reproducible artifacts, and source
   code that establish the behavior.
3. **Detection and defense pass**: Find the telemetry, observable sequences,
   platform controls, and mitigation limits needed to make detection and
   response claims operational.
4. **Gap and challenge pass**: Search for contrary evidence, fixed behavior,
   preconditions, false positives, failed detections, alternate explanations,
   and neighboring techniques that narrow the claim.

Search snippets, generated summaries, citation lists, and abstracts do not
count as reviewed sources. Open the complete relevant source and record exact
pages, paragraphs, sections, commits, line ranges, advisory revisions, or
stable headings.

### 4. Stop only at saturation

Continue with synonyms, narrower queries, official-site searches, citation
trails, and version variants until two consecutive passes add no new:

- controlling protocol requirement;
- material fact or incident evidence;
- independent corroboration;
- limitation, exception, or conflicting explanation;
- detection or mitigation constraint;
- source for an unsupported material claim; or
- distinction from a neighboring SAF technique.

Record the two no-change passes and the saturation rationale in
`source-coverage.yml`. A blocked source is a research gap, not evidence of
saturation.

### 5. Acquire and record sources

Add every consulted source to `source-manifest.yml`. Prefer sources in this
order:

1. Current protocols, standards, and RFCs.
2. Primary incident reports and official security advisories.
3. First-party implementation artifacts, source code, tests, and release notes.
4. Peer-reviewed or methodologically transparent empirical research.
5. Specific, technically reviewable practitioner analysis.
6. Secondary summaries, used only for context or independently corroborated
   claims.

For each source, record publisher, version or date, canonical URL, access and
review dates, review method, exact locators, and what was verified. Archive a
complete local copy and text extraction when lawful and practical; otherwise
record why it was directly reviewed but not archived. Use these archive states:

- `archived`: complete local copy and integrity metadata exist.
- `gated_not_archived`: authorized review occurred, but access terms or format
  prevent retaining a project copy.
- `remote_reviewed_not_archived`: a public official source was fully reviewed,
  but a complete snapshot could not practically be retained.
- `pending`: acquisition or review is incomplete and the source cannot support
  a completed technique.

Do not commit credentials, restricted source copies, or third-party material
that the project cannot redistribute.

### 6. Draft from validated claims

Use `techniques/TEMPLATE.md`. Put claim IDs and source IDs in the Evidence
Summary so reviewers can traverse from prose to the research packet. Cite
externally verifiable claims inline, state important uncertainty near the
claim, and keep historical analogy separate from MCP evidence.

The technique-level evidence status is the strongest label supported for the
core end-to-end adversary behavior:

- `Observed`: a directly reviewed source documents the behavior in a real MCP
  or agentic-system incident.
- `Demonstrated`: the end-to-end behavior was reproduced in a public proof of
  concept, lab, or controlled evaluation.
- `Research-Derived`: independently supported components justify the complete
  technique as an explicit inference.
- `Hypothesized`: the behavior is technically plausible, but direct public
  evidence or sufficient component evidence is not yet available.

Do not raise the label based on a historical analogy, marketing claim, or a
demonstration that omits the technique's defining boundary crossing.

### 7. Make detection testable

Tie every analytic to named telemetry and fields. Document its goal, logic,
correlation window, false positives, blind spots, and tuning assumptions. Keep
the complete analytic in `detection-rule.yml`, not duplicated in the README.

When testing is feasible, include representative positive, negative, boundary,
and false-positive cases. Record the command and result in
`quality-review.yml`. A syntactically valid rule without representative cases
is not a validated detection.

### 8. Reconcile the framework

Add the technique to `framework-model.yml`. Check identifiers, tactics,
neighbors, ATT&CK mapping type, mitigations, detection artifacts, and evidence
status. Record any change needed elsewhere in `alignment-ledger.yml`; high
severity alignment issues must be resolved before completion.

### 9. Review publication rights

Research access and publication rights are separate. For every cited source,
record whether the technique paraphrases, quotes, or adapts protected material.
Track third-party code, diagrams, datasets, trademarks, and permissions in
`publication-rights.yml`. Direct review permits citation; it does not itself
permit republication.

### 10. Pass the completion gates

Complete `quality-review.yml`, then run:

```bash
python3 scripts/validate-technique-research.py SAF-TXXXX
```

A technique is complete only when:

- its contract and scope are satisfied;
- all material claims are validated and traceable to reviewed sources;
- the evidence label matches the evidence for the end-to-end behavior;
- research is saturated and unresolved conflicts are disclosed;
- detection is tested or has a justified feasibility waiver;
- related techniques and framework mappings are distinguished, not merely
  listed;
- publication-rights review passes;
- no unresolved high-severity alignment issue remains; and
- the deterministic validator and recorded technique-specific tests pass.

## Shared Files

- `source-manifest.yml` is the source registry and acquisition record.
- `framework-model.yml` records techniques governed by this protocol and their
  key relationships.
- `alignment-ledger.yml` records discoveries that require changes across
  techniques, mitigations, mappings, or shared documentation.
- `templates/technique/` contains the reusable research packet.
