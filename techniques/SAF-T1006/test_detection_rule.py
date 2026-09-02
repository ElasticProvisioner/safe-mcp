#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1006 experimental sequence analytic."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


HERE = Path(__file__).resolve().parent
INSTALL_ACTIONS = {
    "mcp_server.add",
    "mcp_server.config_write",
    "mcp_deeplink.accepted",
}
UNTRUSTED_STATES = {"unknown", "untrusted"}
MAXSPAN_SECONDS = 900
JOIN_FIELDS = ("user.id", "host.id", "server.id")


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def join_key(event: dict[str, Any]) -> tuple[str, str, str] | None:
    values = tuple(event.get(field) for field in JOIN_FIELDS)
    if not all(isinstance(value, str) and value for value in values):
        return None
    return values  # type: ignore[return-value]


def evaluate(events: list[dict[str, Any]]) -> bool:
    installs: list[tuple[datetime, tuple[str, str, str]]] = []
    starts: list[tuple[datetime, tuple[str, str, str]]] = []
    for event in events:
        timestamp = parse_time(event.get("@timestamp"))
        key = join_key(event)
        if timestamp is None or key is None:
            continue
        action = event.get("event.action")
        if action in INSTALL_ACTIONS and event.get("event.initiator") == "user":
            installs.append((timestamp, key))
        if (
            action == "mcp_server.process_start"
            and event.get("server.source_trust") in UNTRUSTED_STATES
        ):
            starts.append((timestamp, key))
    return any(
        install_key == start_key
        and 0 <= (start_time - install_time).total_seconds() <= MAXSPAN_SECONDS
        for install_time, install_key in installs
        for start_time, start_key in starts
    )


def validate_rule(rule: dict[str, Any]) -> None:
    assert rule["status"] == "experimental"
    assert "saf.t1006" in rule["tags"]
    detection = rule["detection"]
    assert detection["timeframe"] == "15m"
    assert set(detection["selection_install"]["event.action"]) == INSTALL_ACTIONS
    assert detection["selection_install"]["event.initiator"] == "user"
    assert set(detection["selection_start"]["server.source_trust"]) == UNTRUSTED_STATES


def main() -> int:
    rule = yaml.safe_load((HERE / "detection-rule.yml").read_text(encoding="utf-8"))
    data = json.loads((HERE / "test-logs.json").read_text(encoding="utf-8"))
    validate_rule(rule)
    results = []
    for case in data["cases"]:
        actual = evaluate(case["events"])
        expected = case["expected_alert"]
        results.append(
            {
                "name": case["name"],
                "classification": case["classification"],
                "expected_alert": expected,
                "actual_alert": actual,
                "passed": actual is expected,
            }
        )
    passed = sum(item["passed"] for item in results)
    summary = {
        "technique_id": data["technique_id"],
        "rule_id": data["rule_id"],
        "passed": passed,
        "total": len(results),
        "results": results,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
