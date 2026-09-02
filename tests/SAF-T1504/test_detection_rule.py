#!/Users/fkautz/anaconda3/bin/python3
"""Deterministic tests for the SAF-T1504 response-token analytic."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


RESULT_ACTIONS = {"tool_result", "tool_error"}
RESULT_CHANNELS = {"content", "structuredContent", "embedded_resource", "error_detail"}
TOKEN_TYPES = {"access_token", "bearer_token", "refresh_token", "session_token"}


def matches(event: dict[str, object]) -> bool:
    """Apply the detection-rule condition without reading or storing a raw token."""

    action_ok = event.get("event.action") in RESULT_ACTIONS
    channel_ok = event.get("mcp.response.channel") in RESULT_CHANNELS
    count = event.get("mcp.response.secret_count")
    count_ok = isinstance(count, int) and not isinstance(count, bool) and count >= 1
    types = event.get("mcp.response.secret_types")
    type_ok = isinstance(types, list) and bool(TOKEN_TYPES.intersection(types))
    unauthorized = event.get("mcp.response.recipient_authorized") is False
    not_redacted = event.get("mcp.response.redacted") is not True
    return action_ok and channel_ok and count_ok and type_ok and unauthorized and not_redacted


class DetectionRuleCases(unittest.TestCase):
    def test_cases(self) -> None:
        cases_path = Path(__file__).with_name("cases.json")
        cases = json.loads(cases_path.read_text(encoding="utf-8"))
        self.assertEqual(10, len(cases))
        actual_alerts = 0
        for case in cases:
            with self.subTest(case=case["name"]):
                actual = matches(case["event"])
                self.assertIs(actual, case["expected"])
                actual_alerts += int(actual)
        self.assertEqual(4, actual_alerts)
        self.assertEqual(6, len(cases) - actual_alerts)


if __name__ == "__main__":
    unittest.main(verbosity=2)
