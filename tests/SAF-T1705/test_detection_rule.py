#!/usr/bin/env python3
"""Deterministic tests for SAF-T1705's inert correlation analytic."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURES = json.loads((HERE / "fixtures.yml").read_text(encoding="utf-8"))
RULE_TEXT = (ROOT / "techniques" / "SAF-T1705" / "detection-rule.yml").read_text(
    encoding="utf-8"
)
WINDOW_MATCH = re.search(r"^\s*window_seconds:\s*(\d+)\s*$", RULE_TEXT, re.MULTILINE)
if WINDOW_MATCH is None:
    raise RuntimeError("detection rule is missing correlation.window_seconds")


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def detect(events: object, window_seconds: int) -> bool:
    if not isinstance(events, list):
        return False
    messages = []
    actions = []
    for event in events:
        if not isinstance(event, dict):
            continue
        timestamp = parse_time(event.get("timestamp"))
        if timestamp is None:
            continue
        if (
            event.get("event_type") == "inter_agent_message"
            and event.get("provenance_trust") in {"untrusted", "mixed"}
            and event.get("instruction_signal") is True
        ):
            messages.append((event, timestamp))
        if (
            event.get("event_type") == "agent_action"
            and event.get("authority_inherited_from_message") is True
            and event.get("approval_state") == "none"
        ):
            actions.append((event, timestamp))

    for message, message_time in messages:
        required_message = (
            message.get("run_id"),
            message.get("message_id"),
            message.get("receiver_agent"),
        )
        if not all(isinstance(value, str) and value for value in required_message):
            continue
        for action, action_time in actions:
            delta = (action_time - message_time).total_seconds()
            if not 0 <= delta <= window_seconds:
                continue
            if action.get("run_id") != message.get("run_id"):
                continue
            if action.get("agent_id") != message.get("receiver_agent"):
                continue
            if action.get("causal_message_id") != message.get("message_id"):
                continue
            return True
    return False


class DetectionCases(unittest.TestCase):
    pass


def make_test(case: dict):
    def test(self: DetectionCases) -> None:
        rule_window = int(WINDOW_MATCH.group(1))
        self.assertEqual(rule_window, FIXTURES["window_seconds"])
        self.assertEqual(detect(case.get("events"), rule_window), case["expected"])

    return test


for case_record in FIXTURES["cases"]:
    setattr(
        DetectionCases,
        f"test_{case_record['name']}",
        make_test(case_record),
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
