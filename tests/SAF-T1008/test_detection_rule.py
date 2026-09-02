#!/usr/bin/env python3
"""Fixture test for the SAF-T1008 experimental descriptor analytic."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "events.json"
RESULTS = ROOT / "results.json"


def matches(event: dict) -> bool:
    score = event.get("descriptor.directive_score")
    return bool(
        event.get("event.action") == "tools_list_snapshot"
        and event.get("descriptor.references_foreign_tool") is True
        and isinstance(score, (int, float))
        and not isinstance(score, bool)
        and score >= 2
        and event.get("descriptor.cross_server_contract_approved") is not True
    )


def main() -> int:
    cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
    outcomes = []
    for case in cases:
        actual = matches(case["event"])
        outcomes.append(
            {
                "case": case["case"],
                "expected": case["expected"],
                "actual": actual,
                "passed": actual == case["expected"],
            }
        )
    summary = {
        "technique_id": "SAF-T1008",
        "validated_on": "2026-09-01",
        "total": len(outcomes),
        "positive_cases": sum(1 for item in outcomes if item["expected"]),
        "negative_cases": sum(1 for item in outcomes if not item["expected"]),
        "passed": sum(1 for item in outcomes if item["passed"]),
        "failed": sum(1 for item in outcomes if not item["passed"]),
        "outcomes": outcomes,
    }
    RESULTS.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
