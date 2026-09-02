#!/usr/bin/env python3
"""Deterministic, non-destructive tests for SAF-T1706 normalized telemetry."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path


WINDOW_SECONDS = 600
REQUIRED = {"timestamp", "event_action", "auth_result", "token_fingerprint", "presenter_id", "resource_id", "audience_match"}


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalized(event: object) -> tuple[datetime, dict] | None:
    if not isinstance(event, dict) or not REQUIRED.issubset(event):
        return None
    timestamp = parse_time(event["timestamp"])
    if timestamp is None or event["event_action"] != "oauth_token_use":
        return None
    if not all(isinstance(event[key], str) and event[key] for key in ("token_fingerprint", "presenter_id", "resource_id")):
        return None
    if not isinstance(event["audience_match"], bool):
        return None
    return timestamp, event


def alerts(events: list[object]) -> bool:
    accepted: list[tuple[datetime, dict]] = []
    for raw in events:
        item = normalized(raw)
        if item is None:
            continue
        timestamp, event = item
        if event["auth_result"] != "success":
            continue
        if event["audience_match"] is False:
            return True
        accepted.append((timestamp, event))

    accepted.sort(key=lambda item: item[0])
    for left_index, (left_time, left) in enumerate(accepted):
        for right_time, right in accepted[left_index + 1 :]:
            delta = (right_time - left_time).total_seconds()
            if delta > WINDOW_SECONDS:
                break
            if left["token_fingerprint"] != right["token_fingerprint"]:
                continue
            different_context = left["presenter_id"] != right["presenter_id"] or left["resource_id"] != right["resource_id"]
            if not different_context:
                continue
            if left.get("approved_handoff") is True or right.get("approved_handoff") is True:
                continue
            left_group = left.get("client_instance_group")
            right_group = right.get("client_instance_group")
            if left_group and left_group == right_group:
                continue
            return True
    return False


def main() -> int:
    cases_path = Path(__file__).with_name("test-cases.json")
    payload = json.loads(cases_path.read_text(encoding="utf-8"))
    failures = []
    results = []
    for case in payload["cases"]:
        actual = alerts(case["events"])
        passed = actual is case["expected_alert"]
        results.append({"name": case["name"], "expected_alert": case["expected_alert"], "actual_alert": actual, "passed": passed})
        if not passed:
            failures.append(case["name"])
    print(json.dumps({"technique_id": payload["technique_id"], "total": len(results), "passed": len(results) - len(failures), "failed": len(failures), "results": results}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
