#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1407 example analytic."""

from __future__ import annotations

import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CASES_PATH = HERE / "cases.json"
RULE_PATH = ROOT / "techniques" / "SAF-T1407" / "detection-rule.yml"
REQUIRED_CLASSES = {"positive", "negative", "boundary", "malformed", "expected_false_positive"}
EXPECTED_CONDITION = "selection_identity and selection_relay and not filter_approved_gateway"


def evaluate(event: object) -> bool:
    """Apply the documented boolean correlation to a normalized event."""
    if not isinstance(event, dict):
        return False
    required = (
        "approved_identity_mismatch",
        "relay_association_signal",
        "approved_gateway",
    )
    if any(type(event.get(field)) is not bool for field in required):
        return False
    return (
        event["approved_identity_mismatch"]
        and event["relay_association_signal"]
        and not event["approved_gateway"]
    )


def main() -> None:
    fixture = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    rule_text = RULE_PATH.read_text(encoding="utf-8")
    assert fixture["schema_version"] == 1
    assert fixture["technique_id"] == "SAF-T1407"
    assert f"  condition: {EXPECTED_CONDITION}" in rule_text
    assert "status: experimental" in rule_text

    cases = fixture["cases"]
    observed_classes = {case["classification"] for case in cases}
    assert observed_classes == REQUIRED_CLASSES
    assert len(cases) == 9

    passed = 0
    alerts = 0
    for case in cases:
        actual = evaluate(case.get("event"))
        expected = case["expected_alert"]
        assert actual is expected, f"{case['id']}: expected {expected}, got {actual}"
        passed += 1
        alerts += int(actual)

    assert alerts == 4
    print(f"PASS SAF-T1407 detection: {passed}/9 cases; alerts={alerts}; no_alerts={passed-alerts}")


if __name__ == "__main__":
    main()
