#!/usr/bin/env python3
"""Deterministic fixture test for the SAF-T1804 example analytic."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DISCOVERY = {"resources/list", "tools/list", "schema/list"}
COLLECTION = {"resources/read", "tools/call"}


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def detects(events: list[dict[str, object]]) -> bool:
    valid = [event for event in events if event.get("session_id") and event.get("actor_id") and parse_time(event.get("timestamp"))]
    if not valid or all(event.get("workload_class") == "approved_bulk_job" for event in valid):
        return False
    keys = {(str(event["actor_id"]), str(event["session_id"])) for event in valid}
    for actor_id, session_id in keys:
        scoped = [event for event in valid if str(event["actor_id"]) == actor_id and str(event["session_id"]) == session_id]
        discoveries = [event for event in scoped if event.get("action") in DISCOVERY]
        collections = [event for event in scoped if event.get("action") in COLLECTION and event.get("workload_class") != "approved_bulk_job"]
        if not discoveries or not collections:
            continue
        first_discovery = min(parse_time(event["timestamp"]) for event in discoveries)
        last_collection = max(parse_time(event["timestamp"]) for event in collections)
        if first_discovery is None or last_collection is None or not (0 <= (last_collection - first_discovery).total_seconds() <= 900):
            continue
        targets = {str(event.get("target_id")) for event in collections if event.get("target_id")}
        max_page_count = max((int(event.get("page_index", -1)) + 1 for event in collections), default=0)
        records = sum(max(0, int(event.get("record_count", 0))) for event in collections)
        response_bytes = sum(max(0, int(event.get("response_bytes", 0))) for event in collections)
        if len(targets) >= 3 and (max_page_count >= 20 or records >= 5000 or response_bytes >= 52_428_800):
            return True
    return False


def main() -> int:
    rule_text = (HERE / "detection-rule.yml").read_text(encoding="utf-8")
    assert "- saf.t1804" in rule_text
    cases = [json.loads(line) for line in (HERE / "test-logs.json").read_text(encoding="utf-8").splitlines() if line.strip()]
    failures: list[str] = []
    for case in cases:
        actual = detects(case["events"])
        if actual != case["expected"]:
            failures.append(f"{case['case']}: expected={case['expected']} actual={actual}")
    if failures:
        print("FAIL")
        for failure in failures:
            print(failure)
        return 1
    positives = sum(1 for case in cases if case["expected"])
    negatives = len(cases) - positives
    print(f"PASS: {len(cases)} cases ({positives} positive, {negatives} negative)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
