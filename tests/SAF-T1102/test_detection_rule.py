#!/usr/bin/env python3
"""Deterministic synthetic test for the SAF-T1102 correlation analytic."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


HERE = Path(__file__).resolve().parent
RULE = HERE.parents[1] / "techniques" / "SAF-T1102" / "detection-rule.yml"
WINDOW_SECONDS = 300


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def matches(events: list[dict]) -> bool:
    sources = []
    for event in sorted(events, key=lambda item: timestamp(item["timestamp"])):
        if event.get("event_type") == "model_content_received":
            signaled = event.get("detector_verdict") == "suspicious" or bool(
                event.get("instruction_indicators")
            )
            if event.get("trust_label") == "untrusted" and signaled:
                sources.append(event)
            continue
        if event.get("event_type") != "tool_call":
            continue
        consequential = event.get("action_risk") == "high" or bool(
            event.get("crosses_trust_boundary")
        )
        unapproved = event.get("approval_state") in {"missing", "bypassed"}
        if not (consequential and unapproved):
            continue
        for source in sources:
            delta = (timestamp(event["timestamp"]) - timestamp(source["timestamp"])).total_seconds()
            if (
                source.get("session_id") == event.get("session_id")
                and 0 <= delta <= WINDOW_SECONDS
            ):
                return True
    return False


def main() -> None:
    fixtures = json.loads((HERE / "detection-fixtures.json").read_text())
    expected_doc = json.loads((HERE / "expected-results.json").read_text())
    expected = expected_doc["expected"]
    actual = {case["id"]: matches(case["events"]) for case in fixtures["cases"]}
    assert actual == expected, f"case mismatch: expected={expected!r} actual={actual!r}"
    assert sum(actual.values()) == expected_doc["positive_count"]
    assert len(actual) - sum(actual.values()) == expected_doc["negative_count"]
    rule_text = RULE.read_text()
    assert "be4b6164-79f7-4f72-9d50-48e8f5b61617" in rule_text
    assert "saf.t1102" in rule_text
    assert "within 5m" in rule_text
    for case_id, result in actual.items():
        print(f"{'ALERT' if result else 'CLEAR'} {case_id}")
    print("PASS: 7 cases (3 positive, 4 negative)")


if __name__ == "__main__":
    main()
