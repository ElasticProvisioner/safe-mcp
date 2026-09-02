# SAF-T1912: Stego Response Exfil

- **Technique ID**: SAF-T1912
- **Tactic**: ATK-TA0010
- **Evidence Status**: Demonstrated
- **Lifecycle Status**: Deprecated. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)
- **Documentation Status**: Deprecated
- **Severity**: High
- **Research Packet**: [research/techniques/SAF-T1912](../../research/techniques/SAF-T1912/)
- **Last Updated**: 2026-09-02

> **Deprecated compatibility ID:** SAF-T1912 is consolidated into [SAF-T1902: Response-Borne Covert Channel](../SAF-T1902/README.md). This page and its evidence packet remain available for provenance; use SAF-T1902 for new mappings. [Framework Model v2 taxonomy review](../../research/taxonomy-review.yml)

## Overview

An adversary causes an agent or model that can read protected context to encode that information into an outward response whose visible purpose appears benign, allowing a cooperating observer to recover the hidden payload. <!-- SAF-TRACE: claims=SAF-T1912-C003,SAF-T1912-C004 ; sources=SRC-trojanstego-2025 -->

The technique is demonstrated in controlled LLM and agent-egress research, but no reviewed source establishes this exact response-embedded mechanism in a production MCP incident. <!-- SAF-TRACE: claims=SAF-T1912-C003,SAF-T1912-C016 ; sources=SRC-trojanstego-2025,SRC-agent-egress-monitor-2026 -->

## Scope

This technique begins when protected context is available to a compromised, backdoored, or adversarially optimized response generator and ends when hidden information crosses the response trust boundary in text, structured content, image, audio, or an embedded resource. <!-- SAF-TRACE: claims=SAF-T1912-C001,SAF-T1912-C004 ; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026,SRC-trojanstego-2025 -->

It excludes ordinary disclosure in readable response text, secrets sent directly in tool-call parameters or separate network requests, and manipulation that changes an answer without carrying recoverable protected information. <!-- SAF-TRACE: claims=SAF-T1912-C015,SAF-T1912-C023 ; sources=SRC-silent-egress-2026,SRC-microsoft-tool-poisoning-2026-06-30 -->

## Description

The adversary first obtains influence over the response generator, such as through a maliciously fine-tuned model, poisoned agent component, or optimization pressure that rewards hidden communication. The generator must be able to access a secret and emit a response observable by a cooperating receiver. <!-- SAF-TRACE: claims=SAF-T1912-C004,SAF-T1912-C009 ; sources=SRC-trojanstego-2025,SRC-hidden-plain-text-2025 -->

The response remains useful or plausible while carrying a secondary signal. Controlled studies have used vocabulary choices and have evaluated invisible text features, whitespace, encodings, metadata, image variation, and audio variation as carriers; the receiver applies a matching decoder or shared convention. <!-- SAF-TRACE: claims=SAF-T1912-C003,SAF-T1912-C007,SAF-T1912-C010 ; sources=SRC-trojanstego-2025,SRC-agent-egress-monitor-2026,SRC-od-stega-2026 -->

## Attack Vectors

- A distributed or locally selected model is deliberately fine-tuned to convert sensitive context into natural-looking token choices. <!-- SAF-TRACE: claims=SAF-T1912-C003,SAF-T1912-C004 ; sources=SRC-trojanstego-2025 -->
- A compromised agent component encodes bits in response representations such as invisible characters, whitespace, serialized-field order, image samples, or audio samples. <!-- SAF-TRACE: claims=SAF-T1912-C007 ; sources=SRC-agent-egress-monitor-2026 -->
- Optimization pressure induces two model components to develop a linguistic code that preserves task performance while bypassing output oversight. <!-- SAF-TRACE: claims=SAF-T1912-C009 ; sources=SRC-hidden-plain-text-2025 -->

## Technical Details

MCP tool results can carry text, images, audio, resource links, embedded resources, and structured content; resources can also carry text or base64-encoded binary data. These legitimate response forms provide multiple possible carrier surfaces, but the protocol features alone do not prove malicious encoding. <!-- SAF-TRACE: claims=SAF-T1912-C001 ; sources=SRC-mcp-tools-2026-07-28,SRC-mcp-resources-2026 -->

End-to-end execution requires: protected data in the generator's accessible context; adversarial control or learned encoding behavior; an output path that preserves the carrier; receiver access to the response; and a compatible decoder, shared model, or codebook. <!-- SAF-TRACE: claims=SAF-T1912-C004 ; sources=SRC-trojanstego-2025,SRC-agent-egress-monitor-2026 -->

The mechanism is distinct from direct egress. If the secret itself appears in a tool argument, URL, email, or network body, the exfiltration occurs in that explicit channel even when the final response looks clean. <!-- SAF-TRACE: claims=SAF-T1912-C015 ; sources=SRC-silent-egress-2026,SRC-microsoft-tool-poisoning-2026-06-30 -->

## Evidence and Current State

### Evidence Summary

| Claim | Evidence | Bound |
|---|---|---|
| SAF-T1912-C003 | SRC-trojanstego-2025 | Controlled fine-tuned LLM demonstration; not a production MCP incident. |
| SAF-T1912-C005 | SRC-trojanstego-2025 | Study-specific recovery result for short secrets, not a general performance guarantee. |
| SAF-T1912-C007 | SRC-agent-egress-monitor-2026 | Controlled application-layer agent-egress carrier suite; preprint and suite-limited. |
| SAF-T1912-C009 | SRC-hidden-plain-text-2025 | Controlled LLM-agent collusion under optimization; simplified tasks and model set. |
| SAF-T1912-C011 | SRC-od-stega-2026 | Controlled capacity-versus-detectability result with an application-dependent perceptibility threshold. |
| SAF-T1912-C012 | SRC-breaking-provable-security-2026 | Scheme-specific white-box statistical audit result, not a universal online detector. |
| SAF-T1912-C013 | SRC-cve-2025-32711 | Fixed adjacent disclosure vulnerability with no response-steganography proof. |
| SAF-T1912-C016 | SRC-cve-2025-32711, SRC-microsoft-ai-security-2025 | Reviewed adjacent vulnerability material does not establish response steganography. |

The selected evidence is nonredundant: one study demonstrates sensitive-context encoding into natural-looking model outputs, one tests multimodal carrier removal at an agent egress boundary, and one demonstrates emergent linguistic signaling under oversight pressure. <!-- SAF-TRACE: claims=SAF-T1912-C022 ; sources=SRC-trojanstego-2025,SRC-agent-egress-monitor-2026,SRC-hidden-plain-text-2025 -->

## Impact Assessment

Successful execution can move protected context across an approved-looking response boundary while preserving apparent task utility, weakening ordinary content review and creating confidentiality impact proportional to the secret, channel capacity, response volume, and receiver access. <!-- SAF-TRACE: claims=SAF-T1912-C003,SAF-T1912-C022 ; sources=SRC-trojanstego-2025,SRC-agent-egress-monitor-2026 -->

The severity is High because the demonstrated outcome is covert disclosure of sensitive context, while the absence of a qualifying production incident and the controlled-study limitations prevent an Observed rating. <!-- SAF-TRACE: claims=SAF-T1912-C016,SAF-T1912-C022 ; sources=SRC-trojanstego-2025,SRC-agent-egress-monitor-2026 -->

## Detection Methods

Capture complete response content and content type at the last trusted egress point, together with destination trust, whether sensitive context was accessed, model and policy identifiers, serializer details, and media provenance. Normalize text and serialized data before alerting on disallowed invisible or bidirectional characters, mixed-script confusables, anomalous whitespace, long encoded blobs, or unattested binary media. <!-- SAF-TRACE: claims=SAF-T1912-C018,SAF-T1912-C021 ; sources=SRC-agent-egress-monitor-2026,SRC-nist-sp800-53r5.1 -->

Use the repository analytic as deterministic carrier triage, not as a universal linguistic-steganography detector. Vocabulary-choice channels can remain fluent, carrier suites are incomplete, and statistical detection of interval-based generation requires matched model internals and is better suited to offline audit. <!-- SAF-TRACE: claims=SAF-T1912-C019,SAF-T1912-C020 ; sources=SRC-hidden-plain-text-2025,SRC-agent-egress-monitor-2026,SRC-breaking-provable-security-2026 -->

When the signal is available, correlate an alert with sensitive reads, model or component changes, response destinations, downstream decoding activity, and prior tool calls. Preserve the raw response and its normalized form for investigation. <!-- SAF-TRACE: claims=SAF-T1912-C021 ; sources=SRC-microsoft-prompt-abuse-2026,SRC-microsoft-tool-poisoning-2026-06-30 -->

The destination-repository detector and strict research validator results are recorded in [canonical-validation.txt](../../research/techniques/SAF-T1912/validation/canonical-validation.txt).

## Mitigation Strategies

- Minimize which protected data the response generator can access and separate sensitive retrieval from outward-facing generation. <!-- SAF-TRACE: claims=SAF-T1912-C002,SAF-T1912-C017 ; sources=SRC-mcp-tools-2026-07-28,SRC-nist-sp800-53r5.1 -->
- Enforce response schemas, canonical serialization, Unicode normalization, carrier-specific sanitization, media re-encoding or provenance checks, and destination-aware DLP at a trusted egress monitor. <!-- SAF-TRACE: claims=SAF-T1912-C002,SAF-T1912-C008,SAF-T1912-C017 ; sources=SRC-mcp-tools-2026-07-28,SRC-agent-egress-monitor-2026,SRC-nist-sp800-53r5.1 -->
- Test known carrier families and residual capacity, retain model/version provenance, and hold back independent mitigations from adversarial optimization where feasible. <!-- SAF-TRACE: claims=SAF-T1912-C008,SAF-T1912-C009,SAF-T1912-C020 ; sources=SRC-agent-egress-monitor-2026,SRC-hidden-plain-text-2025,SRC-breaking-provable-security-2026 -->

Paraphrasing can disrupt some exact-token channels but is not a complete control: one controlled exfiltration study found exact-token recovery vulnerable to paraphrasing, while optimized collusion experiments retained capacity against paraphrasing. <!-- SAF-TRACE: claims=SAF-T1912-C006,SAF-T1912-C009 ; sources=SRC-trojanstego-2025,SRC-hidden-plain-text-2025 -->

## Related Techniques

- [SAF-T1911: Parameter Exfiltration](../SAF-T1911/) covers explicit secret transfer in tool parameters rather than a hidden payload embedded in the response. <!-- SAF-TRACE: claims=SAF-T1912-C015 ; sources=SRC-silent-egress-2026,SRC-microsoft-tool-poisoning-2026-06-30 -->
- [SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/) covers adversarial instructions that redirect model behavior; it may enable this technique, but it does not require a recoverable covert payload in the response. <!-- SAF-TRACE: claims=SAF-T1912-C014,SAF-T1912-C023 ; sources=SRC-microsoft-indirect-prompt-injection-2025,SRC-microsoft-tool-poisoning-2026-06-30 -->

## MITRE ATT&CK Mapping

| ATT&CK technique | Relationship | Limitation |
|---|---|---|
| T1027.003 Steganography | Direct | ATT&CK describes hiding information in image, audio, video, or text; this SAF technique narrows the carrier to an agent or model response containing protected context. | <!-- SAF-TRACE: claims=SAF-T1912-C024 ; sources=SRC-mitre-t1027-003 -->
| T1567 Exfiltration Over Web Service | Analogous/conditional | Applies only when the response reaches the cooperating receiver through a web service; the response-encoding mechanism is independent of that transport. | <!-- SAF-TRACE: claims=SAF-T1912-C024 ; sources=SRC-mitre-t1567 -->

These mappings express mechanism and transport overlap, not evidence that the cited ATT&CK procedures involved an AI-agent response. <!-- SAF-TRACE: claims=SAF-T1912-C024 ; sources=SRC-mitre-t1027-003,SRC-mitre-t1567 -->

## References

- **SRC-mcp-tools-2026-07-28** — Model Context Protocol, “Tools,” specification revision 2026-07-28.
- **SRC-mcp-resources-2026** — Model Context Protocol, “Resources,” specification revision 2026-07-28.
- **SRC-trojanstego-2025** — Meier, Wahle, Röttger, Ruas, and Gipp, “TrojanStego,” EMNLP 2025.
- **SRC-agent-egress-monitor-2026** — Metere, “An Application-Layer Multi-Modal Covert-Channel Reference Monitor for LLM Agent Egress,” 2026 preprint.
- **SRC-hidden-plain-text-2025** — Mathew et al., “Hidden in Plain Text,” IJCNLP-AACL 2025.
- **SRC-od-stega-2026** — Huang et al., “OD-Stega,” EACL 2026.
- **SRC-breaking-provable-security-2026** — Cao, Wang, and Hu, “Breaking the ‘Provable Security’,” Findings ACL 2026.
- **SRC-silent-egress-2026** — Lan, Kaul, Jones, and Westrum, “Silent Egress,” 2026 preprint.
- **SRC-cve-2025-32711** — CVE Program record for CVE-2025-32711.
- **SRC-microsoft-indirect-prompt-injection-2025** — Paverd, “How Microsoft defends against indirect prompt injection attacks,” 2025.
- **SRC-microsoft-ai-security-2025** — Microsoft Detection and Response Team, “AI application security considerations for organizations,” 2025.
- **SRC-microsoft-prompt-abuse-2026** — Microsoft Defender Experts Cybersecurity Incident Response, “Detecting and analyzing prompt abuse in AI tools,” 2026.
- **SRC-microsoft-tool-poisoning-2026-06-30** — Microsoft Defender Experts Cybersecurity Incident Response, “Securing AI agents,” 2026.
- **SRC-nist-sp800-53r5.1** — NIST, SP 800-53 Revision 5.1, SC-7(10).
- **SRC-mitre-t1027-003** — MITRE ATT&CK, T1027.003 Steganography.
- **SRC-mitre-t1567** — MITRE ATT&CK, T1567 Exfiltration Over Web Service.
- **SRC-llm-covert-channels-2024** — Silva, Sala, and Gabrys, “Look Who’s Talking Now,” Findings EMNLP 2024.

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-02 | Clean-room draft with controlled evidence, explicit production gap, tested detection analytic, and framework mappings. |
