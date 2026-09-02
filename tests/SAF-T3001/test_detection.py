#!/usr/bin/env python3
"""Deterministic semantic test for the SAF-T3001 candidate analytic."""

from __future__ import annotations

import json
from pathlib import Path


def matches(event: dict[str, object]) -> bool:
    returned = (
        event.get("event.action") == "rag_retrieval"
        and event.get("retrieval.returned") is True
    )
    policy_failure = (
        event.get("document.source_approved") is False
        or event.get("document.integrity_verified") is False
    )
    suppressed = event.get("deployment.environment") == "test"
    return returned and policy_failure and not suppressed


def main() -> None:
    fixture_path = Path(__file__).with_name("test-logs.json")
    fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for fixture in fixtures:
        actual = matches(fixture["event"])
        if actual is not fixture["expected"]:
            failures.append(f"{fixture['name']}: expected={fixture['expected']} actual={actual}")
    if failures:
        raise SystemExit("FAIL\n" + "\n".join(failures))
    print(f"PASS SAF-T3001 detection semantic tests: {len(fixtures)} fixtures")


if __name__ == "__main__":
    main()
