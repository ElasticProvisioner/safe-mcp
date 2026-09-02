#!/usr/bin/env python3
"""Deterministic tests for SAF-T1206's configuration-change analytic."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
RULE = HERE.parents[1] / "techniques" / "SAF-T1206" / "detection-rule.yml"
EVENTS = HERE / "test-events.json"


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").casefold()


def detects(rule: dict, event: dict) -> bool:
    selections = rule["detection"]
    suffixes = selections["selection_config_path"]["file_path|endswith"]
    allowed_changes = selections["selection_change_type"]["change_type"]
    key_fragments = selections["selection_credential_key"]["changed_keys|contains"]
    path_match = any(normalize_path(event["file_path"]).endswith(normalize_path(item)) for item in suffixes)
    change_match = event["change_type"].casefold() in {item.casefold() for item in allowed_changes}
    keys = [item.casefold() for item in event.get("changed_keys", [])]
    key_match = any(fragment.casefold() in key for fragment in key_fragments for key in keys)
    return path_match and change_match and key_match


def main() -> int:
    rule = yaml.safe_load(RULE.read_text(encoding="utf-8"))
    events = json.loads(EVENTS.read_text(encoding="utf-8"))
    failures = []
    alerts = 0
    for event in events:
        actual = detects(rule, event)
        alerts += int(actual)
        if actual is not event["expected"]:
            failures.append(f"{event['name']}: expected={event['expected']} actual={actual}")
    if failures:
        print("FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    false_positive_count = sum(item["category"] == "expected_false_positive" for item in events)
    print(f"PASS {len(events)} cases ({alerts} alerts, {len(events) - alerts} non-alerts; includes {false_positive_count} expected false positive)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
