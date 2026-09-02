# Readable Trace Format

Use this format for every new or substantively rewritten SAF technique. It
keeps the rendered document readable without weakening source-or-omit.

## Human-facing presentation

Write ordinary prose without appending bare claim IDs or source IDs. Use a
descriptive citation label when a direct link helps the reader, for example
`[MCP Tools specification](URL)` rather than `[SRC-mcp-tools](URL)`.

Keep visible audit identifiers concentrated in:

- the Evidence Summary, where claim and source IDs are intentionally exposed;
- References, where source IDs join citations to `source-manifest.yml`; and
- the research packet itself.

## Machine-readable linkage

Set `trace_format: hidden_html_v1` in `technique-contract.yml`. Append one
single-line HTML comment to each externally supported paragraph, list item,
table row, or other substantive Markdown line:

```markdown
MCP hosts receive server-authored tool descriptions during discovery. [MCP Tools specification](URL) <!-- SAF-TRACE: claims=SAF-T1234-C001; sources=SRC-mcp-tools -->
```

Use comma-separated IDs when a unit relies on more than one claim or source:

```markdown
The behavior has been reproduced in controlled evaluations. <!-- SAF-TRACE: claims=SAF-T1234-C002,SAF-T1234-C003; sources=SRC-study-one,SRC-study-two -->
```

The comment must be on the same Markdown line as the unit it supports. In a
table, place it inside the final cell before the closing pipe. For a fenced
example or diagram, put the trace comment on the immediately preceding
explanatory line; do not place audit text inside the example. Repository-derived
status may instead use a visible link to a local artifact declared in
`traceability-ledger.yml`.

Every claim ID in a trace comment must resolve in `claim-inventory.yml`. Every
source ID must resolve in `source-manifest.yml`, appear in `sources_cited`, and
support at least one of the comment's claims. Exact source locators remain on
the claim-to-source relation in `claim-inventory.yml`.

Do not use footnote numbering as the authoritative join: numbering changes
during editing. Do not hide uncertainty or evidence limitations; only the audit
identifiers are hidden. The Evidence Summary remains a visible reviewer index.
