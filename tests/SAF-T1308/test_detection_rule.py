#!/usr/bin/env python3
"""Deterministic test harness for SAF-T1308's portable YAML analytic."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]


def dotted_get(record: dict, key: str):
    value = record
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def selection_matches(selection: dict, record: dict) -> bool:
    return all(dotted_get(record, key) == expected for key, expected in selection.items())


def main() -> int:
    rule = yaml.safe_load(
        (REPOSITORY_ROOT / "techniques" / "SAF-T1308" / "detection-rule.yml").read_text(
            encoding="utf-8"
        )
    )
    fixture = json.loads((HERE / "test-logs.json").read_text(encoding="utf-8"))
    detection = rule["detection"]
    expected_condition = "selection_grant_resource or selection_audience or selection_scope"
    if detection.get("condition") != expected_condition:
        raise AssertionError("unexpected condition; test harness requires the documented three-way OR")

    names = ["selection_grant_resource", "selection_audience", "selection_scope"]
    failures = []
    matched = 0
    for case in fixture["cases"]:
        actual = any(selection_matches(detection[name], case) for name in names)
        matched += int(actual)
        if actual != case["expected_match"]:
            failures.append(f"{case['case_id']}: expected {case['expected_match']}, got {actual}")

    if failures:
        raise AssertionError("; ".join(failures))
    print(f"PASS SAF-T1308 detection: {len(fixture['cases'])}/{len(fixture['cases'])} cases; {matched} matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
