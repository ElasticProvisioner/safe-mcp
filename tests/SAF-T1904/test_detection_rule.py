#!/usr/bin/env python3
"""Deterministic tests for SAF-T1904's normalized correlation analytic."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path


HERE = Path(__file__).resolve().parent
RULE_PATH = HERE.parents[1] / "techniques" / "SAF-T1904" / "detection-rule.yml"
CASES_PATH = HERE / "test-cases.json"

COMMON = ("timestamp", "event_type", "service", "tenant_id", "app_id", "conversation_id", "session_id")
REQUIRED = {
    "chat.message.received": COMMON + ("message_id", "sender_id", "sender_authorized", "conversation_authorized", "identity_binding"),
    "agent.tool.invoked": COMMON + ("tool_name", "result", "approval_state"),
    "chat.message.sent": COMMON + ("message_id", "reply_to"),
}


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def valid_event(event: object) -> bool:
    if not isinstance(event, dict):
        return False
    required = REQUIRED.get(event.get("event_type"))
    if required is None or any(field not in event for field in required):
        return False
    if parse_time(event.get("timestamp")) is None:
        return False
    if any(not isinstance(event.get(field), str) or not event.get(field) for field in ("service", "tenant_id", "app_id", "conversation_id", "session_id")):
        return False
    return True


def same_group(left: dict, right: dict) -> bool:
    return all(left.get(field) == right.get(field) for field in ("tenant_id", "app_id", "conversation_id", "session_id"))


def is_unapproved(event: dict) -> bool:
    return (
        event.get("sender_authorized") is False
        or event.get("conversation_authorized") is False
        or event.get("identity_binding") != "immutable"
    )


def detects(events: list[object], window_seconds: int) -> bool:
    normalized = [event for event in events if valid_event(event)]
    inbound = [event for event in normalized if event["event_type"] == "chat.message.received" and is_unapproved(event)]
    tools = [event for event in normalized if event["event_type"] == "agent.tool.invoked"]
    outbound = [event for event in normalized if event["event_type"] == "chat.message.sent"]
    for start in inbound:
        start_time = parse_time(start["timestamp"])
        assert start_time is not None
        for tool in tools:
            tool_time = parse_time(tool["timestamp"])
            assert tool_time is not None
            if not same_group(start, tool) or tool_time < start_time:
                continue
            for reply in outbound:
                reply_time = parse_time(reply["timestamp"])
                assert reply_time is not None
                elapsed = (reply_time - start_time).total_seconds()
                if (
                    same_group(start, reply)
                    and reply_time >= tool_time
                    and 0 <= elapsed <= window_seconds
                    and reply.get("reply_to") == start.get("message_id")
                ):
                    return True
    return False


def main() -> int:
    rule_text = RULE_PATH.read_text(encoding="utf-8")
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    window_match = re.search(r"(?m)^\s*timespan_seconds:\s*(\d+)\s*$", rule_text)
    window = int(window_match.group(1)) if window_match else None
    if window != 300:
        print(f"FAIL rule timespan_seconds: expected 300, got {window}")
        return 1
    expected_types = set(re.findall(r"(?m)^\s+event_type:\s*([^\s]+)\s*$", rule_text))
    if expected_types != set(REQUIRED):
        print(f"FAIL rule event selections: {sorted(expected_types)}")
        return 1
    failures = 0
    for case in cases:
        actual = detects(case["events"], window)
        expected = case["expected_alert"]
        if actual == expected:
            print(f"PASS {case['name']}: alert={str(actual).lower()}")
        else:
            failures += 1
            print(f"FAIL {case['name']}: expected={expected} actual={actual}")
    print(f"SUMMARY passed={len(cases) - failures} failed={failures} total={len(cases)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
