#!/usr/bin/env python3
"""Validate the SAF-T1603 synthetic detection corpus."""

import json
from pathlib import Path


def matches(event: dict) -> bool:
    response = (
        event.get("event.name") == "gen_ai.client.inference.operation.details"
        and bool(event.get("gen_ai.output.messages"))
    )
    evidence = (
        int(event.get("saf.system_prompt.overlap_count", 0)) >= 2
        or event.get("saf.system_prompt.canary_match") is True
    )
    return response and evidence and event.get("saf.disclosure.authorized") is not True


def main() -> None:
    cases = json.loads(Path(__file__).with_name("test-logs.json").read_text())
    failures = []
    alerts = 0
    for case in cases:
        actual = matches(case)
        alerts += int(actual)
        if actual != case["expected_alert"]:
            failures.append(f"{case['name']}: expected {case['expected_alert']}, got {actual}")
    if failures:
        raise SystemExit("\n".join(failures))
    if alerts != 2 or len(cases) != 8:
        raise SystemExit(f"unexpected corpus totals: alerts={alerts}, cases={len(cases)}")
    print("PASS: 8 synthetic cases; 2 alerts; 6 negative/boundary cases")


if __name__ == "__main__":
    main()
