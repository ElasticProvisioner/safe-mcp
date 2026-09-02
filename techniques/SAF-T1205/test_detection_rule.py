#!/usr/bin/env python3
"""Deterministic synthetic test for SAF-T1205's example analytic."""

import json
from pathlib import Path


def matches(event):
    required = {
        "event_type",
        "identity_stable",
        "definition_hash_changed",
        "approval_for_current_hash",
    }
    if not required.issubset(event):
        return False
    return (
        event["event_type"] in {"tool_definition_observed", "tools_list_changed"}
        and event["identity_stable"] is True
        and event["definition_hash_changed"] is True
        and event["approval_for_current_hash"] is False
    )


def main():
    cases = json.loads(Path(__file__).with_name("test-logs.json").read_text())
    failures = []
    positives = 0
    for case in cases:
        actual = matches(case)
        positives += int(actual)
        if actual is not case["expected"]:
            failures.append(f"{case['case']}: expected {case['expected']}, got {actual}")
    if failures:
        raise SystemExit("FAIL\n" + "\n".join(failures))
    print(f"PASS: {len(cases)} cases; {positives} positive; {len(cases)-positives} negative/boundary")


if __name__ == "__main__":
    main()
