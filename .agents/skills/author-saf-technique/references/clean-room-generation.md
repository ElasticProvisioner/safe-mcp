# Clean-Room Technique Generation

Use this mode only when the user asks for a technique to be generated without
consulting its current or historical content. The goal is independent
derivation from authoritative external evidence, not merely different wording.

## Isolation boundary

Before opening any technique-specific repository path, record the target ID and
a neutral name supplied by the user or a non-prose registry. A clean-room
generator may use only:

- this skill and its routed references, except
  `impact-classification-examples.md` before freeze;
- repository-wide instructions and the canonical `techniques/TEMPLATE.md`;
- the blank schemas under `research/templates/technique/` and the general
  research protocol in `research/README.md`;
- repository-wide framework identifiers needed to join the new work, provided
  they do not contain prior technique prose or technique-specific research
  leads; and
- external sources the generator independently searches for, opens, and
  reviews in full.

Until the independent draft and evidence set are frozen, the generator must not
open or derive information from:

- the target's current or historical `README.md`;
- the target's existing research packet, traceability ledger, detection rule,
  tests, test logs, source-coverage audit, or claim inventory;
- git history, diffs, blame, stashes, commits, branches, or review comments that
  expose any prior target artifact;
- a pull request, issue, cached page, conversation, summary, or agent context
  that contains prior technique content; or
- a source list copied from the prior target artifacts; or
- `impact-classification-examples.md` or any other methodology example that
  names the target technique or supplies candidate sources for it.

The shared source manifest may be consulted only after independent searches,
source opening, and the draft evidence set have been recorded. At that point it
may be used solely to reuse stable source IDs and avoid duplicate registry
entries; it is not evidence and must not introduce a new research lead.

Use whitelist-only discovery searches. Limit each query to one or more
standards-body, government, academic-publisher, or first-party vendor or
researcher domains that cannot host the prior SAF technique. Never use an
unrestricted web query in clean-room mode. Reject
`secureagenticframework.org`, `safemcp.org`, SAF-MCP repositories and forks,
and any result whose URL, title, or snippet contains the target SAF identifier
before inspecting its substantive content.

## Fresh-agent procedure

When the user requests a new agent, start an agent with no inherited
conversation turns. Give it only the target ID, neutral name, clean-room rules,
general templates, and authorized deliverables. The agent must read this skill
and all routed references itself. Do not send it prior conclusions, candidate
sources, intended classifications, existing prose, diffs, or summaries of the
old technique.

The generator must conduct all five research passes from scratch, including
separate searches for known production breaches, vulnerabilities, advisories,
exploitation status, demonstrations, detection, defenses, contrary evidence,
and neighboring behaviors. It must directly review sources, preserve named
authors and research teams, use exact locators, apply source-or-omit, and record
excluded leads.

Generate replacement artifacts without first reading their current contents.
Work in fresh temporary paths or replace whole target files atomically from
newly created content. Do not perform a content-preserving edit against a prior
target file.

## Contamination rule

If the generator opens any prohibited input before the independent draft is
frozen, it must stop immediately, mark the run contaminated, discard every
artifact produced by that run, and restart with a different fresh agent. A
warning, memory claim, or partial rewrite cannot cure contamination.

## Attestation and freeze

Create `research/techniques/SAF-TXXXX/clean-room-attestation.yml`. Record:

- the generation mode, target ID and neutral name, date, and fresh-agent
  identity;
- that no conversation history was inherited;
- allowed and prohibited input classes;
- exact independent search queries and the source IDs opened before manifest
  reconciliation;
- whether any prior artifact access was detected and details of any incident;
- that the independent draft and evidence set were frozen before integration;
- integration constraints; and
- unresolved integrity concerns.

The attestation may pass only when prior-artifact access is `false`, its details
are empty, the independent searches and reviewed source set are nonempty, the
draft was frozen before integration, and there are no unresolved concerns.

After the freeze, integration may mechanically replace target files, reconcile
stable source IDs, register framework joins, and run validators. Review the new
files and validation output directly. Do not inspect a diff that reveals the
old content, and do not use old prose to revise the new work. Record the passing
attestation in the `clean_room_integrity` quality gate.
