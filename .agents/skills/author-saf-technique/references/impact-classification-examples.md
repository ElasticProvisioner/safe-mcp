# High-Impact Classification Examples

Use these examples only to calibrate relationship and impact-selection logic in
standard authoring mode. They are not a substitute for a current search and
must not be copied into an unrelated technique. Do not read this reference
during a clean-room generation run before the independent draft and evidence
set are frozen.

- **Direct production report with disclosure limits:** Microsoft Defender
  Experts Cybersecurity Incident Response reported in June 2026 that MCP
  tool-poisoning techniques had been observed against enterprise agents and
  described a finance workflow ending in financial-data exfiltration. The
  report supports occurrence, while its withheld organizations, dates, counts,
  and telemetry limit prevalence and case-specific claims:
  <https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/>.

- **Direct demonstration, not a breach:** Luca Beurer-Kellner and Marc Fischer's
  April 2025 Invariant Labs work demonstrated that adversarial MCP tool
  descriptions could influence a tested agent and expose sensitive data. It is
  direct evidence for SAF-T1001, but the source describes experiments rather
  than a production compromise:
  <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>.
- **Observed malicious MCP package, adjacent to description poisoning:**
  Postmark reported in September 2025 that the impersonating `postmark-mcp`
  package added a backdoor that secretly BCC'd user emails. This is strong
  production evidence for malicious MCP supply-chain behavior, but it does not
  establish tool-description poisoning:
  <https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package>.
- **High-impact enabling vulnerability, not the semantic technique:** The
  GitHub-reviewed CVE-2026-55580 advisory reports that affected `mcp-shell`
  deployment paths exposed unrestricted or bypassable shell execution and
  identifies prompt injection or a poisoned tool description as a possible
  call-inducing vector. The affected implementation expands SAF-T1001's
  possible consequence, but it does not itself prove a production poisoned
  description; version 0.6.0 is patched:
  <https://github.com/advisories/GHSA-f5pj-2738-996m>.

The classification boundary is the lesson: severity and ecosystem relevance
do not make an example direct evidence for a specific SAF technique.
