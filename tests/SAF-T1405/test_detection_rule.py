#!/usr/bin/env python3
"""Deterministic test for the SAF-T1405 discovery-drift analytic."""

from __future__ import annotations

import json
from pathlib import Path


BASE = Path(__file__).resolve().parent


def matches(event: dict[str, object]) -> bool:
    lifecycle = event.get("event_type") in {"tool_discovered", "tool_updated"}
    unapproved = event.get("approval_state") == "unapproved"
    drift = event.get("tool_name_changed") is True
    mismatch = event.get("definition_hash_matches_approved") is False
    collision = event.get("cross_server_name_collision") is True
    return lifecycle and unapproved and (drift or mismatch or collision)


def main() -> int:
    events = json.loads((BASE / "test-logs.json").read_text(encoding="utf-8"))
    expected = json.loads((BASE / "expected-results.json").read_text(encoding="utf-8"))
    actual = {event["case_id"]: matches(event) for event in events}
    if actual != expected:
        print(json.dumps({"status": "failed", "actual": actual, "expected": expected}, sort_keys=True))
        return 1
    positives = sum(actual.values())
    negatives = len(actual) - positives
    print(json.dumps({"status": "passed", "cases": len(actual), "positives": positives, "negatives": negatives}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
