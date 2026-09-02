#!/usr/bin/env python3
"""Deterministic validation for the SAF-T1403 experimental analytic."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RULE_PATH = ROOT / "techniques" / "SAF-T1403" / "detection-rule.yml"
CASES_PATH = HERE / "cases.json"


def norm(value: object) -> str:
    return str(value).strip().casefold()


def parse_time(value: object) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def window_seconds(text: str) -> int:
    if text.endswith("m"):
        return int(text[:-1]) * 60
    if text.endswith("s"):
        return int(text[:-1])
    raise ValueError(f"unsupported timeframe: {text}")


def detect(events: list[dict[str, object]], rule: dict[str, object]) -> bool:
    detection = rule["detection"]
    assert isinstance(detection, dict)
    threshold = int(detection["threshold"])
    limit = window_seconds(str(detection["timeframe"]))
    group_fields = detection["group_by"]
    assert isinstance(group_fields, list)
    required = {"event_time", "event_type", "decision", *group_fields}
    groups: dict[tuple[str, ...], list[tuple[datetime, str]]] = defaultdict(list)

    for event in events:
        if not required <= set(event):
            continue
        if norm(event["event_type"]) != "approval_request":
            continue
        if event.get("user_initiated") is True:
            continue
        timestamp = parse_time(event["event_time"])
        if timestamp is None:
            continue
        key = tuple(norm(event[field]) for field in group_fields)
        if any(not part for part in key):
            continue
        groups[key].append((timestamp, norm(event["decision"])))

    for records in groups.values():
        records.sort(key=lambda item: item[0])
        for start in range(len(records)):
            window = [
                item
                for item in records[start:]
                if (item[0] - records[start][0]).total_seconds() <= limit
            ]
            if len(window) < threshold:
                continue
            for index, (_, decision) in enumerate(window):
                if decision != "approved":
                    continue
                earlier = {prior for _, prior in window[:index]}
                if earlier & {"denied", "cancelled"} and index + 1 >= threshold:
                    return True
    return False


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    if len(cases) != 10:
        print(f"FAIL expected 10 cases, found {len(cases)}")
        return 1
    failures: list[str] = []
    for case in cases:
        actual = detect(case["events"], rule)
        if actual is not case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']} got {actual}")
    if failures:
        print("FAIL SAF-T1403 detector")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS SAF-T1403 detector: 10/10 cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
