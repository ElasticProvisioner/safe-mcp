#!/usr/bin/env python3
"""Deterministic validation for SAF-T1502's normalized correlation rule."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "techniques" / "SAF-T1502" / "detection-rule.yml"
DATA_PATH = ROOT / "tests" / "SAF-T1502" / "test-logs.json"


def normalized(value: object) -> str:
    return str(value).strip().casefold()


def timestamp(event: dict[str, object]) -> datetime | None:
    raw = event.get("event.timestamp")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def is_mcp_read(event: dict[str, object], actions: set[str]) -> bool:
    return (
        normalized(event.get("event.kind")) == "mcp_operation"
        and normalized(event.get("event.action")) in actions
        and normalized(event.get("event.outcome")) == "success"
        and normalized(event.get("tool.category")) == "filesystem"
        and normalized(event.get("file.sensitivity")) == "credential"
        and event.get("context.approved_maintenance") is not True
    )


def is_os_read(event: dict[str, object]) -> bool:
    return (
        normalized(event.get("event.kind")) == "file_access"
        and normalized(event.get("event.action")) == "read"
        and normalized(event.get("event.outcome")) == "success"
        and normalized(event.get("file.sensitivity")) == "credential"
    )


def alerts(events: list[dict[str, object]], actions: set[str], maxspan: int) -> bool:
    for first_index, first in enumerate(events):
        if not is_mcp_read(first, actions):
            continue
        first_time = timestamp(first)
        if first_time is None:
            continue
        for second in events[first_index + 1 :]:
            if not is_os_read(second):
                continue
            second_time = timestamp(second)
            if second_time is None:
                continue
            same_host = first.get("host.id") == second.get("host.id")
            same_process = first.get("process.pid") == second.get("process.pid")
            delta = (second_time - first_time).total_seconds()
            if same_host and same_process and 0 <= delta <= maxspan:
                return True
    return False


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    corpus = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    detection = rule["detection"]
    required = {
        "selection_mcp_read",
        "selection_os_read",
        "filter_approved_maintenance",
        "correlation",
        "condition",
    }
    missing = required - set(detection)
    if missing:
        raise AssertionError(f"rule missing detection components: {sorted(missing)}")
    actions = {
        normalized(item)
        for item in detection["selection_mcp_read"]["event.action"]
    }
    maxspan = detection["correlation"]["maxspan_seconds"]
    if actions != {"read_file", "read_resource", "resources_read"}:
        raise AssertionError(f"unexpected action set: {sorted(actions)}")
    if maxspan != 300:
        raise AssertionError(f"unexpected maxspan_seconds: {maxspan}")

    failures: list[str] = []
    positive = 0
    negative = 0
    for case in corpus["cases"]:
        actual = alerts(case["events"], actions, maxspan)
        expected = case["expected_alert"]
        positive += int(expected)
        negative += int(not expected)
        if actual is not expected:
            failures.append(f"{case['name']}: expected {expected}, got {actual}")
    if failures:
        raise AssertionError("; ".join(failures))
    print(
        f"PASS SAF-T1502 detection: {len(corpus['cases'])} cases "
        f"({positive} positive, {negative} negative)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
