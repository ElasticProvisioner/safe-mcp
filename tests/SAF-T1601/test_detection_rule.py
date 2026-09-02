#!/Users/fkautz/anaconda3/bin/python3
"""Deterministic tests for the SAF-T1601 example analytic."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
BUNDLE = HERE.parents[1]
RULE_PATH = BUNDLE / "techniques" / "SAF-T1601" / "detection-rule.yml"
DATA_PATH = HERE / "test-logs.json"
DISCOVERY_METHODS = {"server/discover", "initialize"}
WINDOW_SECONDS = 300
THRESHOLD = 3


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def event_is_eligible(event: object) -> bool:
    if not isinstance(event, dict):
        return False
    required = ("actor_id", "session_id", "server_id", "method", "result")
    if any(not event.get(field) for field in required):
        return False
    if parse_time(event.get("timestamp")) is None:
        return False
    if event["method"] not in DISCOVERY_METHODS or event["result"] != "success":
        return False
    if event.get("approved_context") is True:
        return False
    return event.get("process_role") not in {"startup", "health_check", "administrator_inspector"}


def detected(events: list[object]) -> bool:
    groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for event in events:
        if event_is_eligible(event):
            assert isinstance(event, dict)
            groups[(str(event["actor_id"]), str(event["session_id"]))].append(event)

    for group in groups.values():
        ordered = sorted(group, key=lambda item: parse_time(item["timestamp"]))
        for left, first in enumerate(ordered):
            start = parse_time(first["timestamp"])
            assert start is not None
            distinct: set[str] = set()
            for event in ordered[left:]:
                current = parse_time(event["timestamp"])
                assert current is not None
                if (current - start).total_seconds() > WINDOW_SECONDS:
                    break
                distinct.add(str(event["server_id"]))
                if len(distinct) >= THRESHOLD:
                    return True
    return False


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    assert "count_distinct(server_id)" in rule["detection"]["condition"]
    assert "within 5m" in rule["detection"]["condition"]

    corpus = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    required_classes = {"positive", "negative", "boundary", "false_positive", "malformed"}
    seen_classes = {case["class"] for case in corpus["cases"]}
    assert required_classes <= seen_classes

    failures: list[str] = []
    positives = 0
    negatives = 0
    for case in corpus["cases"]:
        actual = detected(case["events"])
        expected = bool(case["expected"])
        positives += int(expected)
        negatives += int(not expected)
        if actual != expected:
            failures.append(f"{case['name']}: expected {expected}, got {actual}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print(
        f"PASS {len(corpus['cases'])}/{len(corpus['cases'])} cases; "
        f"positive={positives}; negative={negatives}; "
        f"classes={','.join(sorted(seen_classes))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
