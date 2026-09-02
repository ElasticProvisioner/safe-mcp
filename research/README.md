# SAF Technique Research Protocol

This directory contains the evidence model used to research, author, and review
SAF-MCP techniques. The publishable technique remains in
`techniques/SAF-TXXXX/README.md`; its research packet lives in
`research/techniques/SAF-TXXXX/`.

The model uses four stable join keys:

- `technique_id` connects the published technique, research packet, and
  framework model.
- `claim_id` connects prose and evidence-summary claims to the claim inventory.
- `source_id` connects claims and citations to a directly reviewed source in
  `source-manifest.yml`.
- `exclusion_id` connects an unverified research lead to its source searches,
  exclusion reason, and prohibited publishable wording.

## Required Artifacts

Every new technique must include:

```text
techniques/SAF-TXXXX/
├── README.md
└── detection-rule.yml

research/techniques/SAF-TXXXX/
├── clean-room-attestation.yml
├── technique-contract.yml
├── claim-inventory.yml
├── source-coverage.yml
├── publication-rights.yml
├── quality-review.yml
└── traceability-ledger.yml
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

The canonical taxonomy and release contract is [Framework Model v2](FRAMEWORK-MODEL.md).
Technique IDs are opaque and permanent. Scope is expressed through SAF Core and
domain profiles rather than by encoding a tactic or technology into the ID.

When the user requires clean-room generation, set `generation_mode` to
`clean_room`, follow the isolated-input procedure in
`.agents/skills/author-saf-technique/references/clean-room-generation.md`, and
complete `clean-room-attestation.yml`. The generator must not inspect the
current or historical technique-specific artifacts before freezing an
independently researched draft. Any prohibited access contaminates the run and
requires a restart with a different fresh agent.

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

List every externally verifiable proposition before writing the technique;
low-severity and contextual prose are not exceptions. Classify each claim as
one of:

- `protocol_normative`: a requirement or defined behavior in a current
  protocol, standard, or RFC.
- `observed_incident`: behavior documented in a real MCP or agentic-system
  incident.
- `disclosed_vulnerability`: a published weakness whose affected and fixed
  states and relationship to the technique have been validated.
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
premises are well supported. Record unvalidated candidates in
`traceability-ledger.yml` and omit them from publishable prose.

### 3. Research in five passes

1. **Protocol and authority pass**: Find current MCP specifications, applicable
   RFCs, standards, and first-party security requirements. Record versions and
   precise sections.
2. **Known breach and vulnerability pass**: Search production incidents,
   postmortems, official advisories, CVEs, GitHub Security Advisories,
   maintainer fixes, affected versions, exploitation status, and authoritative
   government catalogs. Classify each candidate as direct, enabling, adjacent,
   analogous, or rejected. Select two to four of the highest-impact relevant
   examples when evidence supports them; explicitly record when none qualify.
3. **Demonstration and empirical-research pass**: Find public demonstrations,
   reproducible artifacts, source code, benchmarks, and methodologically
   reviewable studies that establish the behavior.
4. **Detection and defense pass**: Find the telemetry, observable sequences,
   platform controls, and mitigation limits needed to make detection and
   response claims operational.
5. **Gap and challenge pass**: Search for contrary evidence, fixed behavior,
   preconditions, false positives, failed detections, alternate explanations,
   and neighboring techniques that narrow the claim.

Search snippets, generated summaries, citation lists, and abstracts do not
count as reviewed sources. Open the complete relevant source and record exact
pages, paragraphs, sections, commits, line ranges, advisory revisions, or
stable headings.

Do not call a demonstration, scanner finding, vulnerable deployment, or public
advisory a breach. Verify whether exploitation is observed, attempted, unknown,
or explicitly absent. A severe or ecosystem-relevant CVE supports the technique
only when its root cause and attack path satisfy the technique contract.

### 4. Stop only at saturation

Continue with synonyms, narrower queries, official-site searches, citation
trails, and version variants until two consecutive passes add no new:

- controlling protocol requirement;
- material fact or incident evidence;
- independent corroboration;
- limitation, exception, or conflicting explanation;
- detection or mitigation constraint;
- source for an unsupported publishable proposition; or
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

For each source, record publisher, named authors or responsible team, version
or date, canonical URL, access and review dates, review method, exact locators,
and what was verified. Inspect bylines, author footers, acknowledgments,
advisory credits, and canonical citation metadata. Archive a complete local
copy and text extraction when lawful and practical; otherwise record why it
was directly reviewed but not archived. Use these archive states:

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

Apply **source or omit** to all substantive publishable content, not only claims
the author considers material. Every paragraph, list item, table row, diagram,
example, analytic choice, and response action must expose a validated claim ID
or link to a repository artifact declared in `traceability-ledger.yml`.
Headings and table labels are structural rather than factual assertions.

For new and substantively rewritten techniques, set
`trace_format: hidden_html_v1`. Keep normal prose readable by placing claim and
source joins in a same-line comment:

```markdown
Readable prose with a semantic [source title](URL). <!-- SAF-TRACE: claims=SAF-T1234-C001; sources=SRC-source-id -->
```

The rendered body hides the audit IDs, while the Evidence Summary and
References expose compact reviewer indexes. The validator resolves every
commented claim/source pair through the claim inventory and source manifest.

Keep unverified research leads out of the technique. Record them in the
technique's `traceability-ledger.yml` with their origin, attempted searches,
consulted sources, exclusion reason, prohibited publishable wording, and
`omitted_from_publishable_technique` disposition. The validator rejects an
unresolved ledger entry or prohibited wording that reappears in the README.

The Current State section must include a known-breaches-and-vulnerabilities
assessment. For each selected example, state the date, product or environment,
impact, remediation status, relationship to the technique, and evidence limit.
Credit named researchers or response teams. If no direct case qualifies, say
so rather than substituting an adjacent high-severity event.

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

After the evidence set and draft are frozen, run a separate ontology pass against
the complete catalog. Add the technique to `framework-model.yml`; check the
admission rule, lifecycle, SAF Core and domain profiles, tactics, typed
relationships and inverses, ATT&CK mapping type, mitigations, detection maturity,
and evidence status. This post-freeze pass may classify or consolidate the
independently researched behavior, but must not introduce new factual claims into
clean-room prose. Preserve superseded IDs as deprecated compatibility records.

Record corpus-wide decisions in `taxonomy-review.yml` and changes needed
elsewhere in `alignment-ledger.yml`. High-severity alignment issues must be
resolved before completion.

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
python3 scripts/validate-framework-model.py
python3 scripts/generate-technique-catalog.py --check
```

A technique is complete only when:

- its contract and scope are satisfied;
- its clean-room attestation passes when clean-room generation was requested;
- every substantive publishable unit is traceable to reviewed evidence or a
  declared repository artifact;
- unverified candidates are omitted from publishable prose and recorded in the
  traceability ledger;
- breach and vulnerability research is current, classified, and represented by
  the highest-impact qualifying examples or an explicit evidence gap;
- the evidence label matches the evidence for the end-to-end behavior;
- research is saturated and unresolved conflicts are disclosed;
- detection is tested or has a justified feasibility waiver;
- related techniques and framework mappings are distinguished, not merely
  listed;
- publication-rights review passes;
- no unresolved high-severity alignment issue remains; and
- the evidence, taxonomy, and operational release gates pass; and
- the deterministic validators, catalog check, and recorded technique-specific tests pass.

## Shared Files

- `source-manifest.yml` is the source registry and acquisition record.
- `framework-model.yml` is the canonical machine-readable catalog, including
  lifecycle, profiles, tactics, typed relationships, and detection maturity.
- `taxonomy-review.yml` records post-freeze admission, consolidation,
  reclassification, and profile decisions.
- `alignment-ledger.yml` records discoveries that require changes across
  techniques, mitigations, mappings, or shared documentation.
- `templates/technique/` contains the reusable research packet.
