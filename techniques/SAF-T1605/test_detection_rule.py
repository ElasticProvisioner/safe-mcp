#!/usr/bin/env python3
"""Deterministic validation for the SAF-T1605 example analytic."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import yaml


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def alerts(events: list[dict], rule: dict) -> bool:
    detection = rule["detection"]
    list_methods = set(detection["capability_lists"]["method"])
    approved = set(detection["approved_inventory_suppression"]["purpose"])
    groups: dict[tuple[str, str], list[tuple[datetime, str, str | None]]] = defaultdict(list)

    for event in events:
        actor = event.get("actor_id")
        server = event.get("server_id")
        method = event.get("method")
        timestamp = parse_time(event.get("timestamp"))
        if not all((actor, server, method, timestamp)) or event.get("result_status") != "success":
            continue
        groups[(actor, server)].append((timestamp, method, event.get("purpose")))

    for group_events in groups.values():
        group_events.sort()
        for discovery_time, method, _ in group_events:
            if method != "server/discover":
                continue
            window = [event for event in group_events if 0 <= (event[0] - discovery_time).total_seconds() <= 120]
            if any(purpose in approved for _, _, purpose in window):
                continue
            distinct = {listed_method for _, listed_method, _ in window if listed_method in list_methods}
            if len(distinct) >= 3:
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rule", type=Path, default=Path(__file__).with_name("detection-rule.yml"))
    parser.add_argument("--logs", type=Path, default=Path(__file__).with_name("test-logs.json"))
    args = parser.parse_args()

    rule = yaml.safe_load(args.rule.read_text(encoding="utf-8"))
    cases = json.loads(args.logs.read_text(encoding="utf-8"))["cases"]
    failures = []
    classes: dict[str, int] = defaultdict(int)
    for case in cases:
        classes[case["class"]] += 1
        actual = alerts(case["events"], rule)
        if actual != case["expected_alert"]:
            failures.append(f"{case['name']}: expected {case['expected_alert']}, got {actual}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    class_summary = ", ".join(f"{count} {name}" for name, count in sorted(classes.items()))
    print(f"PASS {len(cases)}/{len(cases)} cases ({class_summary}); expected false-positive modeled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
