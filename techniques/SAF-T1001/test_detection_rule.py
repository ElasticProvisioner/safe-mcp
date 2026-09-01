#!/usr/bin/env python3
"""Validate the SAF-T1001 triage analytic with adversarial and boundary cases."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).parent


def load_cases() -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (ROOT / "test-logs.json").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def contains_any(text: str, patterns: list[str], *, casefold: bool) -> bool:
    if casefold:
        text = text.casefold()
        patterns = [pattern.casefold() for pattern in patterns]
    return any(pattern in text for pattern in patterns)


def evaluate(rule: dict[str, object], description: str) -> bool:
    detection = rule["detection"]
    instructions = detection["selection_instruction"]["tool_description|contains"]
    actions = detection["selection_sensitive_action"]["tool_description|contains"]
    controls = detection["selection_format_control"]["tool_description|contains"]
    lexical = contains_any(description, instructions, casefold=True) and contains_any(
        description, actions, casefold=True
    )
    format_control = contains_any(description, controls, casefold=False)
    return lexical or format_control


def main() -> int:
    rule = yaml.safe_load((ROOT / "detection-rule.yml").read_text(encoding="utf-8"))
    cases = load_cases()
    failures: list[str] = []
    observed_alerts = 0
    classifications = {case["classification"] for case in cases}

    required_classes = {"adversarial", "benign", "boundary", "expected_false_positive"}
    if not required_classes <= classifications:
        failures.append(
            f"missing case classes: {sorted(required_classes - classifications)}"
        )

    for case in cases:
        actual = evaluate(rule, str(case["tool_description"]))
        expected = bool(case["expected_alert"])
        observed_alerts += int(actual)
        outcome = "PASS" if actual == expected else "FAIL"
        print(
            f"{outcome} {case['case_id']}: alert={actual} "
            f"expected={expected} class={case['classification']}"
        )
        if actual != expected:
            failures.append(str(case["case_id"]))

    false_positive_cases = [
        case
        for case in cases
        if case["classification"] == "expected_false_positive"
    ]
    if not false_positive_cases or not all(
        evaluate(rule, str(case["tool_description"])) for case in false_positive_cases
    ):
        failures.append("expected false-positive behavior was not exercised")

    expected_alerts = sum(bool(case["expected_alert"]) for case in cases)
    print(
        f"SUMMARY {len(cases)} cases; {observed_alerts} alerts; "
        f"{len(cases) - observed_alerts} non-alerts"
    )
    if observed_alerts != expected_alerts:
        failures.append(
            f"alert total {observed_alerts} did not match expected {expected_alerts}"
        )

    if failures:
        print("FAILED: " + ", ".join(failures))
        return 1
    print("PASS SAF-T1001 detection validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
