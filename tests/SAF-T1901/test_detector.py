#!/usr/bin/env python3
"""Deterministic fixture checks for the SAF-T1901 detector."""

from __future__ import annotations

import json
from pathlib import Path

from detector import detect


def main() -> int:
    fixture_path = Path(__file__).with_name("fixtures.json")
    document = json.loads(fixture_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    totals = {"cases": 0, "alerts": 0, "expected_false_positive_alerts": 0}

    for case in document["cases"]:
        totals["cases"] += 1
        alerts = detect(case["events"])
        totals["alerts"] += len(alerts)
        expected = case["expected_alerts"]
        if case.get("classification") == "expected_false_positive":
            totals["expected_false_positive_alerts"] += len(alerts)
        if len(alerts) != expected:
            failures.append(
                f"{case['name']}: expected {expected} alert(s), got {len(alerts)}"
            )

    if failures:
        print("FAIL SAF-T1901 detector")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        "PASS SAF-T1901 detector: "
        f"{totals['cases']} cases, {totals['alerts']} expected alerts, "
        f"{totals['expected_false_positive_alerts']} expected-false-positive alert"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
