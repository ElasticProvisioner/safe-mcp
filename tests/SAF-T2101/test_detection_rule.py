#!/usr/bin/env python3
"""Deterministic, inert validation for SAF-T2101 detection logic."""

from __future__ import annotations

import collections
import datetime as dt
import json
import pathlib
import re
import unicodedata
import unittest


DESTRUCTIVE = {"delete", "destroy", "drop", "purge", "remove", "terminate", "truncate"}
REQUIRED = {"timestamp", "event_type", "session_id", "actor_id", "server_id", "tool_name"}


def normalize(value: object) -> str:
    if not isinstance(value, str):
        return ""
    value = unicodedata.normalize("NFKC", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    value = value.casefold()
    return " ".join(part for part in re.split(r"[^a-z0-9]+", value) if part)


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


class Detector:
    def __init__(self) -> None:
        self.recent: dict[tuple[str, str, str], collections.deque[tuple[dt.datetime, str]]] = collections.defaultdict(collections.deque)
        self.invalid_events = 0

    def process(self, event: object) -> dict[str, object] | None:
        if not isinstance(event, dict) or not REQUIRED.issubset(event):
            self.invalid_events += 1
            return None
        if not isinstance(event.get("arguments", {}), dict):
            self.invalid_events += 1
            return None
        try:
            timestamp = parse_time(str(event["timestamp"]))
        except (TypeError, ValueError):
            self.invalid_events += 1
            return None
        if event.get("event_type") != "mcp_tool_call":
            return None

        arguments = event.get("arguments") or {}
        operation = normalize(event.get("tool_name")) + " " + normalize(arguments.get("action"))
        if not (set(operation.split()) & DESTRUCTIVE):
            return None
        if event.get("decision") != "allow" or event.get("result_status") != "success":
            return None

        target = event.get("target") if isinstance(event.get("target"), dict) else {}
        target_id = str(target.get("id", ""))
        protected = target.get("environment") == "production" or target.get("criticality") in {"high", "critical"}
        approval = event.get("approval") if isinstance(event.get("approval"), dict) else {}
        approval_failed = approval.get("status", "missing") not in {"approved", "matched"}

        key = (str(event["actor_id"]), str(event["server_id"]), str(event["session_id"]))
        window = self.recent[key]
        cutoff = timestamp - dt.timedelta(minutes=5)
        while window and window[0][0] < cutoff:
            window.popleft()
        if target_id:
            window.append((timestamp, target_id))
        burst = len({item[1] for item in window if item[1]}) >= 3

        if not ((protected and approval_failed) or burst):
            return None
        return {
            "case": event.get("case"),
            "protected_without_approval": protected and approval_failed,
            "destructive_burst": burst,
            "normalized_operation": operation.strip(),
        }


def load_events() -> list[dict[str, object]]:
    path = pathlib.Path(__file__).with_name("test-events.jsonl")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


EVENTS = load_events()
BY_CASE = {str(event["case"]): event for event in EVENTS}


class DetectionTests(unittest.TestCase):
    def test_positive_protected_target(self) -> None:
        self.assertIsNotNone(Detector().process(BY_CASE["positive_unapproved"]))

    def test_negative_read_denied_and_non_mcp(self) -> None:
        detector = Detector()
        for name in ("negative_read", "negative_denied", "negative_non_mcp"):
            self.assertIsNone(detector.process(BY_CASE[name]), name)

    def test_boundary_alerts_at_three_distinct_targets(self) -> None:
        detector = Detector()
        self.assertIsNone(detector.process(BY_CASE["boundary_1"]))
        self.assertIsNone(detector.process(BY_CASE["boundary_2"]))
        alert = detector.process(BY_CASE["boundary_3"])
        self.assertIsNotNone(alert)
        self.assertTrue(alert["destructive_burst"])

    def test_malformed_and_missing_fields_fail_closed_without_crash(self) -> None:
        detector = Detector()
        self.assertIsNone(detector.process(BY_CASE["malformed_missing_tool"]))
        self.assertIsNone(detector.process(BY_CASE["malformed_arguments"]))
        self.assertEqual(detector.invalid_events, 2)

    def test_expected_false_positive_is_explicit(self) -> None:
        detector = Detector()
        for name in ("expected_false_positive_1", "expected_false_positive_2"):
            self.assertIsNone(detector.process(BY_CASE[name]))
        alert = detector.process(BY_CASE["expected_false_positive_3"])
        self.assertIsNotNone(alert)
        self.assertTrue(BY_CASE["expected_false_positive_3"]["expected_false_positive"])

    def test_normalization_and_untrusted_annotations(self) -> None:
        normalized = Detector().process(BY_CASE["normalization_evasion"])
        action_field = Detector().process(BY_CASE["action_field_evasion"])
        self.assertIsNotNone(normalized)
        self.assertIn("delete record", normalized["normalized_operation"])
        self.assertIsNotNone(action_field)
        self.assertIn("terminate instance", action_field["normalized_operation"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
