#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1303 boundary-mismatch analytic."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


DATA = Path(__file__).with_name("test-logs.json")


def detect(event: dict[str, object]) -> bool:
    required = {
        "mcp_method",
        "sandbox_expected",
        "privileged_approval",
        "request_id",
        "process_request_id",
        "delta_seconds",
        "parent_role",
        "event_category",
        "event_type",
        "expected_context",
        "observed_context",
    }
    if not required.issubset(event):
        return False
    return bool(
        event["mcp_method"] == "tools/call"
        and event["sandbox_expected"] is True
        and event["privileged_approval"] is False
        and event["request_id"] == event["process_request_id"]
        and isinstance(event["delta_seconds"], (int, float))
        and 0 <= event["delta_seconds"] <= 60
        and event["parent_role"] == "mcp_server"
        and event["event_category"] == "process"
        and event["event_type"] == "start"
        and event["expected_context"] != event["observed_context"]
    )


class DetectionTests(unittest.TestCase):
    def test_all_cases(self) -> None:
        payload = json.loads(DATA.read_text(encoding="utf-8"))
        self.assertEqual(payload["technique_id"], "SAF-T1303")
        self.assertEqual(len(payload["cases"]), 8)
        for case in payload["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(detect(case["event"]), case["expected"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
