# SAF-T2105: Disinformation Output

- **Technique ID**: SAF-T2105
- **Tactic**: ATK-TA0040
- **Documentation Status**: Stable
- **Evidence Status**: Observed
- **Severity**: High
- **Last Updated**: 2026-09-02
- **Research Packet**: [research/techniques/SAF-T2105/](../../research/techniques/SAF-T2105/)
- **Traceability Ledger**: [traceability-ledger.yml](../../research/techniques/SAF-T2105/traceability-ledger.yml)

## Overview

Disinformation Output is deliberate use of an AI or agentic system to produce false or misleading factual, identity, provenance, or consensus representations intended to deceive a downstream person or system. <!-- SAF-TRACE: claims=SAF-T2105-C001,SAF-T2105-C003,SAF-T2105-C007; sources=SRC-openai-prc-io-2026,SRC-google-ai-misuse,SRC-nist-ai-600-1 -->

The technique is output-centered: it requires deceptive generated content, not merely a malicious prompt, poisoned context, or an accidental model error. <!-- SAF-TRACE: claims=SAF-T2105-C005,SAF-T2105-C007; sources=SRC-usenix-confundo-2026,SRC-nist-ai-600-1 -->

## Scope

In scope are deliberately misleading generated assertions, fabricated identities or provenance, simulated consensus, and attacker-directed false answers produced through manipulated retrieval context. <!-- SAF-TRACE: claims=SAF-T2105-C001,SAF-T2105-C002,SAF-T2105-C004,SAF-T2105-C005; sources=SRC-openai-prc-io-2026,SRC-openai-io-2024,SRC-usenix-poisonedrag-2025,SRC-usenix-confundo-2026 -->

Out of scope are unintentional confabulation, delivery-only prompt or context manipulation that yields no deceptive output, malware or credential theft, denial of service, and clearly disclosed satire or fiction. <!-- SAF-TRACE: claims=SAF-T2105-C005,SAF-T2105-C007; sources=SRC-usenix-confundo-2026,SRC-nist-ai-600-1 -->

## Description

An adversary supplies instructions, retrieved material, or production workflow inputs that cause a model to emit deceptive content; the content then reaches a user, platform, or automated decision path with enough apparent authority to be acted upon. <!-- SAF-TRACE: claims=SAF-T2105-C001,SAF-T2105-C003,SAF-T2105-C004,SAF-T2105-C006,SAF-T2105-C007; sources=SRC-openai-prc-io-2026,SRC-google-ai-misuse,SRC-usenix-poisonedrag-2025,SRC-mcp-resources-2025-06-18,SRC-nist-ai-600-1 -->

Automation bias can amplify the risk when recipients over-rely on generated output, but observed campaigns also show that generation does not guarantee meaningful reach or persuasion. <!-- SAF-TRACE: claims=SAF-T2105-C007,SAF-T2105-C010; sources=SRC-nist-ai-600-1,SRC-google-ai-misuse,SRC-openai-io-2024,SRC-openai-prc-io-2026 -->

## Attack Vectors

- **Direct content production**: operators generate deceptive comments, articles, images, personas, biographies, or engagement material for coordinated influence activity. <!-- SAF-TRACE: claims=SAF-T2105-C001,SAF-T2105-C002,SAF-T2105-C003; sources=SRC-openai-prc-io-2026,SRC-openai-io-2024,SRC-google-ai-misuse -->
- **Retrieval-mediated false answers**: attacker-controlled or manipulated material enters retrieval context and steers a model or agent toward an attacker-selected answer. <!-- SAF-TRACE: claims=SAF-T2105-C004,SAF-T2105-C005,SAF-T2105-C006; sources=SRC-usenix-poisonedrag-2025,SRC-usenix-confundo-2026,SRC-mcp-resources-2025-06-18 -->
- **Persona and provenance fabrication**: generated names, biographies, or apparently independent voices obscure the content's origin and simulate legitimacy or consensus. <!-- SAF-TRACE: claims=SAF-T2105-C002,SAF-T2105-C003; sources=SRC-openai-io-2024,SRC-google-ai-misuse -->

## Technical Details

MCP resources can expose server-controlled files or application data to model context; the protocol path is relevant when that context participates in generation, although the MCP specification does not itself claim that resource content is trustworthy or deceptive. <!-- SAF-TRACE: claims=SAF-T2105-C006; sources=SRC-mcp-resources-2025-06-18 -->

Controlled studies establish the retrieval-to-output mechanism: Wei Zou, Runpeng Geng, Binghui Wang, and Jinyuan Jia reported attacker-chosen answers in an agent evaluation, while Haoyang Hu, Zhejun Jiang, Yueming Lyu, Junyuan Zhang, Yi Liu, and Ka-Ho Chow demonstrated factual, opinion, and hallucination manipulation in more practical RAG pipelines. <!-- SAF-TRACE: claims=SAF-T2105-C004,SAF-T2105-C005; sources=SRC-usenix-poisonedrag-2025,SRC-usenix-confundo-2026 -->

These demonstrations are bounded laboratory results, not evidence that every model, pipeline, or poisoned item succeeds. <!-- SAF-TRACE: claims=SAF-T2105-C004,SAF-T2105-C005,SAF-T2105-C010; sources=SRC-usenix-poisonedrag-2025,SRC-usenix-confundo-2026,SRC-google-ai-misuse -->

## Evidence and Current State

The overall evidence label is **Observed** because first-party reports document production use of generative systems for covert influence activity, while independent experiments demonstrate attacker-directed output through retrieval manipulation. <!-- SAF-TRACE: claims=SAF-T2105-C001,SAF-T2105-C003,SAF-T2105-C004,SAF-T2105-C005; sources=SRC-openai-prc-io-2026,SRC-google-ai-misuse,SRC-usenix-poisonedrag-2025,SRC-usenix-confundo-2026 -->

Production evidence is materially constrained: providers reported refusals, failed basic jailbreak attempts, limited authentic engagement, and no meaningful breakout in the reviewed cases. <!-- SAF-TRACE: claims=SAF-T2105-C010; sources=SRC-google-ai-misuse,SRC-openai-io-2024,SRC-openai-prc-io-2026 -->

### Evidence Summary

| Claim | Evidence | Key limitation |
|---|---|---|
| SAF-T2105-C001 | OpenAI documented production generation supporting false compromise allegations. | No meaningful breakout was observed. |
| SAF-T2105-C002 | OpenAI disrupted five content-generating covert influence operations. | Not every item was demonstrably factually false. |
| SAF-T2105-C003 | Google GTIG observed government-linked content, persona, and messaging use. | The report found productivity gains, not novel capabilities. |
| SAF-T2105-C004 | PoisonedRAG demonstrated attacker-chosen answers in a ReAct agent. | Controlled results varied by dataset. |
| SAF-T2105-C005 | Confundo demonstrated factual, opinion, and hallucination manipulation. | Experiments were sandboxed. |
| SAF-T2105-C006 | MCP resources provide a path for application data to reach model context. | Protocol behavior alone does not establish deception. |
| SAF-T2105-C007 | NIST distinguishes deliberate disinformation and warns about automation bias. | NIST does not measure a specific campaign's harm. |
| SAF-T2105-C008 | NIST recommends ground-truth, provenance, fact-checking, and output controls. | Guidance does not guarantee detection efficacy. |
| SAF-T2105-C009 | Perplexity-only filtering showed material false-positive tradeoffs. | Results are configuration-specific. |
| SAF-T2105-C010 | Production reports document safety and engagement constraints. | Findings do not generalize to every provider or attacker. |
| SAF-T2105-C011 | The supplied analytic combines factual conflict with integrity or intent context. | It requires upstream telemetry and is experimental. |
| SAF-T2105-C012 | ATT&CK Data Manipulation is an integrity-impact analogy. | It does not define generative-model output abuse. |

## Impact Assessment

- **Integrity**: downstream users or systems may receive false assertions, fabricated provenance, or simulated consensus as if it were reliable information. <!-- SAF-TRACE: claims=SAF-T2105-C001,SAF-T2105-C007,SAF-T2105-C012; sources=SRC-openai-prc-io-2026,SRC-nist-ai-600-1,SRC-mitre-attack-t1565 -->
- **Decision quality**: automation bias can increase unwarranted reliance, but audience impact depends on distribution, credibility, and independent verification. <!-- SAF-TRACE: claims=SAF-T2105-C007,SAF-T2105-C010; sources=SRC-nist-ai-600-1,SRC-google-ai-misuse,SRC-openai-io-2024 -->
- **Severity rationale**: potential integrity and decision harm justify a High rating, while the evidence does not support universal success, novelty, or large-scale persuasion. <!-- SAF-TRACE: claims=SAF-T2105-C001,SAF-T2105-C004,SAF-T2105-C005,SAF-T2105-C010; sources=SRC-openai-prc-io-2026,SRC-usenix-poisonedrag-2025,SRC-usenix-confundo-2026,SRC-google-ai-misuse -->

## Detection Methods

The experimental [detection rule](detection-rule.yml) requires a factual AI-output event whose result conflicts with approved ground truth plus either anomalous retrieved context or a deception-intent signal. <!-- SAF-TRACE: claims=SAF-T2105-C008,SAF-T2105-C011; sources=SRC-nist-ai-600-1,SRC-usenix-poisonedrag-2025 -->

Collect output identifiers, task mode, factuality status, context-integrity status, deception-intent signals, source identifiers, actor or session identifiers, and model or application identifiers; retain the provenance needed to reproduce the comparison. <!-- SAF-TRACE: claims=SAF-T2105-C008,SAF-T2105-C011; sources=SRC-nist-ai-600-1,SRC-usenix-poisonedrag-2025 -->

Do not treat perplexity or anomaly scoring alone as conclusive: evaluated filters produced substantial clean-text false positives at stronger detection settings. <!-- SAF-TRACE: claims=SAF-T2105-C009; sources=SRC-usenix-poisonedrag-2025,SRC-usenix-confundo-2026 -->

### Validation

- **Test Data**: [cases.json](../../tests/SAF-T2105/cases.json)
- **Validation Script**: [test_detection_rule.py](../../tests/SAF-T2105/test_detection_rule.py)
- **Last Validated**: [2026-09-02 destination detector and strict-validator run](../../research/techniques/SAF-T2105/validation/canonical-validation.txt).
- **Expected Result**: [All six positive, negative, boundary, and malformed-event cases pass](../../research/techniques/SAF-T2105/validation/canonical-validation.txt).

## Mitigation Strategies

- Maintain approved ground-truth sets for high-impact factual tasks and verify generated assertions before release or action. <!-- SAF-TRACE: claims=SAF-T2105-C008; sources=SRC-nist-ai-600-1 -->
- Preserve content provenance and retrieved-source identifiers, monitor deployed outputs, and correlate output anomalies with account, session, and context-integrity telemetry. <!-- SAF-TRACE: claims=SAF-T2105-C008,SAF-T2105-C011; sources=SRC-nist-ai-600-1,SRC-usenix-poisonedrag-2025 -->
- Combine model-side safeguards, human moderation for consequential cases, and behavioral investigation; no reviewed control is a complete standalone defense. <!-- SAF-TRACE: claims=SAF-T2105-C008,SAF-T2105-C009,SAF-T2105-C010; sources=SRC-nist-ai-600-1,SRC-usenix-poisonedrag-2025,SRC-usenix-confundo-2026,SRC-google-ai-misuse -->

## Related Techniques

- **[SAF-T2106: Context Memory Poisoning via Vector Store Contamination](../SAF-T2106/README.md)** compromises stored input or retrieval context; this technique begins when that influence produces deceptive output. <!-- SAF-TRACE: claims=SAF-T2105-C005,SAF-T2105-C006; sources=SRC-usenix-confundo-2026,SRC-mcp-resources-2025-06-18 -->
- **[SAF-T1102: Prompt Injection (Multiple Vectors)](../SAF-T1102/README.md)** changes instruction following; this technique is distinguished by the false or materially misleading informational outcome. <!-- SAF-TRACE: claims=SAF-T2105-C005,SAF-T2105-C007; sources=SRC-usenix-confundo-2026,SRC-nist-ai-600-1 -->

## MITRE ATT&CK Mapping

- **T1565 — Data Manipulation (analogous)**: both concern compromised information integrity used to affect understanding or decisions, but T1565 addresses manipulated data on enterprise platforms rather than generative-model output. <!-- SAF-TRACE: claims=SAF-T2105-C012; sources=SRC-mitre-attack-t1565 -->

## References

- `SRC-google-ai-misuse` — [Google Threat Intelligence Group, “Adversarial Misuse of Generative AI”](https://cloud.google.com/blog/topics/threat-intelligence/adversarial-misuse-generative-ai)
- `SRC-mcp-resources-2025-06-18` — [Model Context Protocol, “Resources” specification](https://modelcontextprotocol.io/specification/2025-06-18/server/resources)
- `SRC-mitre-attack-t1565` — [MITRE ATT&CK, “Data Manipulation: T1565”](https://attack.mitre.org/techniques/T1565/)
- `SRC-nist-ai-600-1` — [Autio et al., NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- `SRC-openai-io-2024` — [OpenAI, “Disrupting deceptive uses of AI by covert influence operations”](https://openai.com/index/disrupting-deceptive-uses-of-ai-by-covert-influence-operations/)
- `SRC-openai-prc-io-2026` — [OpenAI, “Disrupting PRC-linked influence operations targeting AI debates”](https://openai.com/index/prc-linked-influence-operations-ai-debates/)
- `SRC-usenix-confundo-2026` — [Hu et al., “Confundo”](https://www.usenix.org/system/files/usenixsecurity26-hu-haoyang.pdf)
- `SRC-usenix-poisonedrag-2025` — [Zou et al., “PoisonedRAG”](https://www.usenix.org/system/files/usenixsecurity25-zou-poisonedrag.pdf)

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-02 | Independent clean-room draft with observed evidence, tested experimental detection, and complete research packet. |
