#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1602 experimental analytic."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def alerts(events: list[dict], threshold: int, window_seconds: int) -> bool:
    relevant: list[dict] = []
    for event in events:
        if event.get("rpc.method") != "tools/list":
            continue
        if not all(event.get(field) for field in ("timestamp", "actor.id", "server.address")):
            continue
        if event.get("authorization.decision") in {"denied", "unapproved"}:
            return True
        relevant.append(event)

    groups: dict[tuple[str, str], list[datetime]] = {}
    for event in relevant:
        if not event.get("mcp.cursor"):
            continue
        key = (event["actor.id"], event["server.address"])
        groups.setdefault(key, []).append(parse_time(event["timestamp"]))

    for times in groups.values():
        times.sort()
        for index, start in enumerate(times):
            count = sum(
                1
                for candidate in times[index:]
                if 0 <= (candidate - start).total_seconds() <= window_seconds
            )
            if count >= threshold:
                return True
    return False


def main() -> int:
    data = json.loads((ROOT / "test-logs.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    type_counts: dict[str, int] = {}
    for case in data["cases"]:
        actual = alerts(case["events"], data["threshold"], data["window_seconds"])
        type_counts[case["case_type"]] = type_counts.get(case["case_type"], 0) + 1
        result = "PASS" if actual is case["expected_alert"] else "FAIL"
        print(f"{result} {case['name']} expected={case['expected_alert']} actual={actual}")
        if result == "FAIL":
            failures.append(case["name"])
    required = {"positive", "positive_boundary", "negative", "negative_boundary", "malformed", "expected_false_positive"}
    missing = sorted(required - set(type_counts))
    if missing:
        failures.append("missing case types: " + ", ".join(missing))
    if failures:
        print("FAILURES " + "; ".join(failures))
        return 1
    print(f"PASS summary cases={len(data['cases'])} case_types={len(type_counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
