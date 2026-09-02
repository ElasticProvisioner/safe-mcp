#!/usr/bin/env python3
"""Deterministically validate the SAF-T1801 distinct-object read heuristic."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
RULE_PATH = HERE / "detection-rule.yml"
CASES_PATH = HERE / "test-logs.json"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def expand_case(case: dict) -> list[dict]:
    if "events" in case:
        return case["events"]
    spec = case["generator"]
    base = datetime(2026, 9, 2, tzinfo=timezone.utc)
    events = []
    for index in range(spec["count"]):
        events.append(
            {
                "event.timestamp": (base + timedelta(seconds=index * spec["interval_seconds"])).isoformat().replace("+00:00", "Z"),
                "event.action": spec["action"],
                "event.outcome": spec["outcome"],
                "session.id": "session-test",
                "actor.id": "actor-test",
                "server.id": "server-test",
                "data.object.id": f"object-{index % spec['distinct_objects']:03d}",
                "data.access_mode": spec["access_mode"],
                "approval.state": spec["approval_state"],
                "approval.scope": spec["approval_scope"],
            }
        )
    return events


def eligible(event: dict, allowed_actions: set[str]) -> bool:
    required = {
        "event.timestamp",
        "event.action",
        "event.outcome",
        "session.id",
        "actor.id",
        "server.id",
        "data.object.id",
        "data.access_mode",
    }
    if not required <= event.keys():
        return False
    if event["event.action"] not in allowed_actions:
        return False
    if event["event.outcome"] != "success" or event["data.access_mode"] != "read":
        return False
    return not (
        event.get("approval.state") == "approved"
        and event.get("approval.scope") == "bulk_export"
    )


def alerts(events: list[dict], threshold: int, window_seconds: int, allowed_actions: set[str]) -> bool:
    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for event in events:
        if eligible(event, allowed_actions):
            key = (event["session.id"], event["actor.id"], event["server.id"])
            grouped[key].append(event)
    for group in grouped.values():
        ordered = sorted(group, key=lambda item: parse_time(item["event.timestamp"]))
        for start in range(len(ordered)):
            start_time = parse_time(ordered[start]["event.timestamp"])
            objects = set()
            for event in ordered[start:]:
                if parse_time(event["event.timestamp"]) - start_time > timedelta(seconds=window_seconds):
                    break
                objects.add(event["data.object.id"])
                if len(objects) >= threshold:
                    return True
    return False


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    corpus = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    allowed_actions = set(rule["detection"]["collection_action"]["event.action"])
    failures = []
    for case in corpus["cases"]:
        actual = alerts(expand_case(case), corpus["threshold"], corpus["window_seconds"], allowed_actions)
        if actual != case["expected_alert"]:
            failures.append(f"{case['name']}: expected {case['expected_alert']}, got {actual}")
        else:
            print(f"PASS {case['name']} alert={actual}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print(f"PASS SAF-T1801 detector cases={len(corpus['cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
