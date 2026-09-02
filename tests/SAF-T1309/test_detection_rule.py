#!/usr/bin/env python3
"""Deterministic synthetic validation for SAF-T1309 detection logic."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "techniques" / "SAF-T1309" / "detection-rule.yml"
CASES_PATH = Path(__file__).with_name("test-logs.json")


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def matches(events: list[dict[str, object]]) -> bool:
    attack_events = []
    tool_events = []
    for event in events:
        when = parse_time(event.get("timestamp"))
        if when is None:
            continue
        if (
            event.get("event_type") in {"prompt_guardrail", "content_guardrail"}
            and event.get("source_trust") == "untrusted"
            and event.get("attack_detected") is True
        ):
            attack_events.append((when, event))
        if (
            event.get("event_type") == "tool_call"
            and event.get("risk_tier") in {"high", "critical"}
            and event.get("approval_state") in {"missing", "denied", "not_requested"}
            and event.get("outcome") in {"attempted", "executed"}
        ):
            tool_events.append((when, event))
    for attack_time, attack in attack_events:
        for tool_time, tool in tool_events:
            same_context = (
                attack.get("session_id") == tool.get("session_id")
                and attack.get("actor_id") == tool.get("actor_id")
            )
            delta = (tool_time - attack_time).total_seconds()
            if same_context and 0 <= delta <= 300:
                return True
    return False


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    if rule["detection"]["timeframe"] != "5m":
        raise AssertionError("rule timeframe must remain 5m for these fixtures")
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))["cases"]
    failures = []
    matched = 0
    nonmatched = 0
    for case in cases:
        actual = matches(case["events"])
        expected = case["expected_detection"]
        if actual:
            matched += 1
        else:
            nonmatched += 1
        if actual != expected:
            failures.append(f"{case['id']}: expected {expected}, got {actual}")
    if failures:
        print("FAIL SAF-T1309 detection tests")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"PASS SAF-T1309 detection tests: {len(cases)} cases, {matched} matched, {nonmatched} nonmatched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
