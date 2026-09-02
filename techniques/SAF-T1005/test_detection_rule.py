#!/usr/bin/env python3
"""Deterministically validate the SAF-T1005 example analytic."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def is_exposure(event: dict[str, object], endpoints: set[str]) -> bool:
    accepted = event.get("http_status") in {200, 202}
    untrusted = event.get("source_zone") in {"internet", "browser_untrusted"}
    missing_access = event.get("auth_result") in {"missing", "invalid"}
    invalid_origin = (
        event.get("source_zone") == "browser_untrusted"
        and event.get("origin_verdict") == "invalid"
    )
    return bool(
        accepted
        and untrusted
        and event.get("endpoint") in endpoints
        and event.get("action_class") == "endpoint_access"
        and (missing_access or invalid_origin)
    )


def is_sensitive(event: dict[str, object]) -> bool:
    return bool(
        event.get("action_class")
        in {"tool_invoke", "resource_read", "process_spawn"}
        and event.get("outcome") == "success"
    )


def evaluate(events: list[dict[str, object]], window_seconds: int, endpoints: set[str]) -> bool:
    for first in events:
        first_time = parse_time(first.get("timestamp"))
        if first_time is None or not is_exposure(first, endpoints):
            continue
        for second in events:
            second_time = parse_time(second.get("timestamp"))
            if second_time is None or not is_sensitive(second):
                continue
            same_join = (
                first.get("correlation_id") == second.get("correlation_id")
                and first.get("server_address") == second.get("server_address")
            )
            delta = (second_time - first_time).total_seconds()
            if same_join and 0 <= delta <= window_seconds:
                return True
    return False


def main() -> int:
    rule = yaml.safe_load((ROOT / "detection-rule.yml").read_text(encoding="utf-8"))
    fixture = json.loads((ROOT / "test-logs.json").read_text(encoding="utf-8"))
    timeframe = str(rule["detection"]["timeframe"])
    if not timeframe.endswith("s"):
        raise SystemExit("timeframe must use seconds")
    window_seconds = int(timeframe[:-1])
    endpoints = set(rule["detection"]["selection_untrusted_accept"]["endpoint"])
    results = []
    for case in fixture["cases"]:
        observed = evaluate(case["events"], window_seconds, endpoints)
        expected = bool(case["expected_alert"])
        results.append(
            {
                "category": case["category"],
                "expected_alert": expected,
                "name": case["name"],
                "observed_alert": observed,
                "passed": observed == expected,
            }
        )
    passed = sum(1 for item in results if item["passed"])
    output = {
        "passed": passed,
        "results": results,
        "status": "passed" if passed == len(results) else "failed",
        "technique_id": fixture["technique_id"],
        "total": len(results),
        "window_seconds": window_seconds,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
