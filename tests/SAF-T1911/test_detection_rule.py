#!/usr/bin/env python3
"""Deterministically validate SAF-T1911's enriched event analytic."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml


TEST_DIR = Path(__file__).resolve().parent
BUNDLE_ROOT = TEST_DIR.parents[1]
RULE_PATH = BUNDLE_ROOT / "techniques" / "SAF-T1911" / "detection-rule.yml"
EVENTS_PATH = TEST_DIR / "events.json"


def matches(selection: dict[str, object], event: dict[str, object]) -> bool:
    return all(event.get(field) == expected for field, expected in selection.items())


def evaluate(rule: dict[str, object], event: dict[str, object]) -> bool:
    detection = rule["detection"]
    assert isinstance(detection, dict)
    selection = detection["selection_parameter_exfiltration"]
    authorized = detection["filter_authorized_exception"]
    assert isinstance(selection, dict)
    assert isinstance(authorized, dict)
    return matches(selection, event) and not matches(authorized, event)


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    corpus = json.loads(EVENTS_PATH.read_text(encoding="utf-8"))
    expected_condition = (
        "selection_parameter_exfiltration and not filter_authorized_exception"
    )
    if rule.get("detection", {}).get("condition") != expected_condition:
        print("FAIL rule condition differs from the tested analytic")
        return 1

    failures: list[str] = []
    categories: dict[str, int] = {}
    for case in corpus["cases"]:
        actual = evaluate(rule, case["event"])
        expected = case["expected_alert"]
        categories[case["category"]] = categories.get(case["category"], 0) + 1
        if actual != expected:
            failures.append(
                f"{case['name']}: expected {expected}, observed {actual}"
            )

    if failures:
        print(f"FAIL {len(failures)}/{len(corpus['cases'])} cases")
        for failure in failures:
            print(f"  {failure}")
        return 1

    category_summary = ", ".join(
        f"{name}={categories[name]}" for name in sorted(categories)
    )
    print(f"PASS {len(corpus['cases'])}/{len(corpus['cases'])} cases")
    print(f"CATEGORIES {category_summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
