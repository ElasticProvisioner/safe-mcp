#!/usr/bin/env python3
"""Deterministic behavioral tests for SAF-T1701."""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

import yaml


INDICATOR = re.compile(
    r"\b(ignore|must|send|upload|publish|execute|secret|credential|do not tell)\b",
    re.IGNORECASE,
)
HIGH_IMPACT = {"read_sensitive", "write", "execute", "external_send"}
WINDOW_SECONDS = 600


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detect(events: list[dict]) -> list[dict]:
    alerts: list[dict] = []
    sources: list[dict] = []
    for event in sorted(events, key=lambda item: item.get("timestamp", "")):
        try:
            when = timestamp(event["timestamp"])
        except (KeyError, TypeError, ValueError):
            continue
        if (
            event.get("event_type") == "tool_result"
            and event.get("result_trust") == "untrusted"
            and INDICATOR.search(str(event.get("result_text", "")))
        ):
            sources.append({**event, "_when": when})
            continue
        if (
            event.get("event_type") != "tool_call"
            or event.get("impact_class") not in HIGH_IMPACT
            or (event.get("user_requested") is True and event.get("approved") is True)
        ):
            continue
        for source in reversed(sources):
            if source.get("session_id") != event.get("session_id"):
                continue
            elapsed = (when - source["_when"]).total_seconds()
            if elapsed < 0 or elapsed > WINDOW_SECONDS:
                continue
            different_tool = source.get("tool_id") != event.get("tool_id")
            different_server = source.get("server_id") != event.get("server_id")
            if not (different_tool or different_server):
                continue
            alerts.append(
                {
                    "session_id": event.get("session_id"),
                    "source_event_id": source.get("event_id"),
                    "target_event_id": event.get("event_id"),
                }
            )
            break
    return alerts


def main() -> int:
    here = Path(__file__).resolve().parent
    cases = yaml.safe_load((here / "test-cases.yml").read_text())["cases"]
    expected = yaml.safe_load((here / "expected-results.yml").read_text())["results"]
    expected_by_id = {item["case_id"]: item for item in expected}
    failures: list[str] = []
    total_alerts = 0
    for case in cases:
        actual = detect(case["events"])
        total_alerts += len(actual)
        wanted = expected_by_id[case["id"]]
        if len(actual) != wanted["alert_count"]:
            failures.append(
                f"{case['id']}: expected {wanted['alert_count']} alert(s), got {len(actual)}"
            )
    if failures:
        print("FAIL")
        print("\n".join(failures))
        return 1
    print(f"PASS: {len(cases)} cases, {total_alerts} expected alerts, 0 mismatches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
