#!/usr/bin/env python3
"""Deterministic representative tests for SAF-T1104's analytic."""

from __future__ import annotations

import json
from pathlib import Path


def matches(event: dict[str, object]) -> bool:
    """Return True only for executed high-risk calls with both rule predicates."""
    if event.get("event_type") != "mcp_tool_call":
        return False
    if event.get("decision") != "executed":
        return False
    if event.get("tool_risk") not in {"high", "critical"}:
        return False
    excess = event.get("scope_excess_count")
    if not isinstance(excess, int) or isinstance(excess, bool) or excess <= 0:
        return False
    approval_gap = event.get("approval_state") in {"absent", "denied", "stale"}
    intent_gap = event.get("intent_match") is False
    return approval_gap or intent_gap


def main() -> int:
    path = Path(__file__).with_name("test-logs.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for case in data["cases"]:
        actual = matches(case["event"])
        if actual is not case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']}, got {actual}")
    if failures:
        print("FAIL SAF-T1104 detection tests")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"PASS SAF-T1104 detection tests ({len(data['cases'])} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
