#!/usr/bin/env python3
"""Deterministic, inert test harness for the SAF-T2102 analytic."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def norm(value: object) -> str:
    return str(value).strip().casefold() if value is not None else ""


def truthy(value: object) -> bool:
    return value is True or norm(value) == "true"


def number(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def matches(event: dict[str, object]) -> bool:
    if norm(event.get("actor_role")) == "approved_operator":
        return False

    cross_cancel = (
        norm(event.get("method")) == "tasks/cancel"
        and truthy(event.get("task_owner_mismatch"))
        and norm(event.get("outcome")) in {"success", "cancelled"}
    )
    crash = (
        norm(event.get("event_type")) == "mcp_server_error"
        and norm(event.get("error_name")) == "closedresourceerror"
        and norm(event.get("service_status")) == "unavailable"
    )
    count = number(event.get("actor_request_count_60s"))
    ratio = number(event.get("concurrent_tasks_ratio"))
    pressure = (
        norm(event.get("event_type")) == "mcp_metric"
        and norm(event.get("service_status")) in {"degraded", "unavailable"}
        and count is not None
        and ratio is not None
        and count >= 100
        and ratio >= 0.9
    )
    return cross_cancel or crash or pressure


def main() -> int:
    cases_path = Path(__file__).with_name("test-logs.json")
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for case in cases:
        actual = matches(case["event"])
        if actual is not case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']}, got {actual}")
    if failures:
        print(f"FAIL {len(failures)}/{len(cases)}")
        print("\n".join(failures))
        return 1
    print(f"PASS {len(cases)}/{len(cases)} cases")
    print("Covered positive, negative, boundaries, malformed/missing fields, expected false positive, normalization/evasion, and a documented distributed-evasion limit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
