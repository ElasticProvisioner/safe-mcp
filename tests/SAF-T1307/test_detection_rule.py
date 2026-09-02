#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1307 normalized-event analytic."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent
TECHNIQUE_RULE = ROOT.parents[1] / "techniques" / "SAF-T1307" / "detection-rule.yml"


def detects(event: dict) -> bool:
    allowed_actions = {
        "oauth_code_issued",
        "downstream_api_call",
        "tool_execution",
        "process_launch",
    }
    return (
        event.get("event", {}).get("category") == "authorization"
        and event.get("event", {}).get("action") in allowed_actions
        and event.get("deputy", {}).get("allowed") is True
        and event.get("initiator", {}).get("allowed") is False
        and event.get("binding", {}).get("valid") is False
        and event.get("delegation", {}).get("valid") is not True
    )


def main() -> int:
    rule = yaml.safe_load(TECHNIQUE_RULE.read_text(encoding="utf-8"))
    expected_condition = "selection_deputy_action and not filter_valid_delegation"
    assert rule["detection"]["condition"] == expected_condition
    assert "saf.t1307" in rule["tags"]

    corpus = json.loads((ROOT / "test-logs.json").read_text(encoding="utf-8"))
    failures = []
    positives = 0
    negatives = 0
    for case in corpus["cases"]:
        actual = detects(case["event"])
        if actual:
            positives += 1
        else:
            negatives += 1
        if actual is not case["expected_alert"]:
            failures.append(
                {"name": case["name"], "expected": case["expected_alert"], "actual": actual}
            )

    assert positives == corpus["expected_summary"]["alerts"]
    assert negatives == corpus["expected_summary"]["non_alerts"]
    assert not failures, json.dumps(failures, sort_keys=True)
    print(
        f"PASS SAF-T1307 detection tests: {len(corpus['cases'])} cases; "
        f"{positives} alerts; {negatives} non-alerts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
