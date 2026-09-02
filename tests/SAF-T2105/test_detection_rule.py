#!/usr/bin/env python3
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "techniques" / "SAF-T2105" / "detection-rule.yml"
CASES_PATH = Path(__file__).with_name("cases.json")


def matches_mapping(event, selection):
    return all(event.get(key) == value for key, value in selection.items())


def detect(event):
    output = matches_mapping(event, {"event_type": "ai_output", "task_mode": "factual", "factuality_status": "contradicted"})
    context = matches_mapping(event, {"context_integrity_status": "anomalous"})
    intent = matches_mapping(event, {"deception_intent_flag": True})
    return output and (context or intent)


def main():
    rule_text = RULE_PATH.read_text(encoding="utf-8")
    required_fragments = [
        "event_type: ai_output",
        "task_mode: factual",
        "factuality_status: contradicted",
        "context_integrity_status: anomalous",
        "deception_intent_flag: true",
        "condition: selection_output and (selection_context or selection_intent)",
    ]
    for fragment in required_fragments:
        assert fragment in rule_text, f"rule is missing {fragment}"
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    failures = []
    for case in cases:
        actual = detect(case["event"])
        if actual != case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']}, got {actual}")
    if failures:
        raise AssertionError("; ".join(failures))
    print(f"PASS: {len(cases)} detection cases")


if __name__ == "__main__":
    main()
