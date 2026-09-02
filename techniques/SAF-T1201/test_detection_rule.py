#!/usr/bin/env python3
"""Deterministic tests for SAF-T1201's definition-mutation analytic."""

from __future__ import annotations

import json
from pathlib import Path


REQUIRED = {
    "event_type",
    "server_id",
    "tool_name",
    "approved_definition_hash",
    "observed_definition_hash",
    "definition_hash_match",
    "reapproval_status",
}


def matches(event: dict[str, object]) -> bool:
    if not REQUIRED.issubset(event):
        return False
    return (
        event["event_type"] == "mcp_tool_definition_observed"
        and event["definition_hash_match"] is False
        and event["approved_definition_hash"] != event["observed_definition_hash"]
        and event["reapproval_status"] == "absent"
    )


def main() -> int:
    cases = json.loads(Path(__file__).with_name("test-logs.json").read_text())
    failures: list[str] = []
    for case in cases:
        actual = matches(case["event"])
        if actual is not case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']}, got {actual}")
    if failures:
        print("FAIL SAF-T1201 detection")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    counts: dict[str, int] = {}
    for case in cases:
        counts[case["class"]] = counts.get(case["class"], 0) + 1
    print(f"PASS SAF-T1201 detection: {len(cases)} cases {json.dumps(counts, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
