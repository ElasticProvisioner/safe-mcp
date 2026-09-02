#!/usr/bin/env python3
"""Deterministic SAF-T1003 normalized-event detection test."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EVENTS = ROOT / "fixtures" / "events.ndjson"
EXPECTED = ROOT / "fixtures" / "expected.json"
RESULT = ROOT / "results" / "test-results.json"
THRESHOLD = 4


def nested(event: dict, *parts: str, default=None):
    value = event
    for part in parts:
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def score(event: dict) -> int:
    total = 0
    total += 5 if nested(event, "artifact", "digest_status") == "mismatch" else 0
    total += 5 if nested(event, "artifact", "signature_status") == "invalid" else 0
    total += 4 if nested(event, "provenance", "status") == "invalid" else 0
    total += 2 if nested(event, "source", "policy_status") == "unapproved" else 0
    total += 2 if nested(event, "version", "policy_status") == "unapproved" else 0
    return total


def evaluate(event: dict) -> dict:
    is_mcp = nested(event, "event", "category") == "mcp_server_lifecycle"
    action = str(nested(event, "event", "action", default="")).lower()
    is_activation = action in {"install", "update", "configure", "activate"}
    completed = nested(event, "activation", "status") == "completed"
    value = score(event)
    return {"alert": bool(is_mcp and is_activation and completed and value >= THRESHOLD), "score": value}


def main() -> int:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    actual = {}
    failures = []
    for line in EVENTS.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        case = event["case"]
        outcome = evaluate(event)
        actual[case] = {**outcome, "classification": expected[case]["classification"]}
        if actual[case] != expected[case]:
            failures.append(case)

    summary = {
        "rule_id": "4b058998-b350-55b8-a077-e639bc023432",
        "test_date": "2026-09-01",
        "deterministic": True,
        "total_cases": len(actual),
        "alerts": sum(1 for item in actual.values() if item["alert"]),
        "non_alerts": sum(1 for item in actual.values() if not item["alert"]),
        "expected_false_positives": sum(
            1 for item in actual.values() if item["classification"] == "expected_false_positive" and item["alert"]
        ),
        "failures": failures,
        "passed": not failures and set(actual) == set(expected),
        "cases": actual,
    }
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
