#!/usr/bin/env python3
"""Regression tests for the SAF-T1902 standalone detector."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from detect_covert_response import analyze, canonical_url, load_events  # noqa: E402


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = HERE / "fixtures" / "events.jsonl"
        cls.events = load_events(cls.fixture)

    def test_fixture_case_outcomes(self) -> None:
        expected: dict[str, bool] = {}
        for event in self.events:
            case_id = str(event["case_id"])
            value = bool(event["expected_alert"])
            if case_id in expected:
                self.assertEqual(expected[case_id], value)
            expected[case_id] = value

        alerts = analyze(self.events)
        alerted_cases = {str(item["case_id"]) for item in alerts}
        actual = {case_id: case_id in alerted_cases for case_id in expected}
        self.assertEqual(expected, actual)
        self.assertEqual(3, sum(actual.values()))
        self.assertEqual(5, len(actual) - sum(actual.values()))

    def test_alert_reasons_cover_both_carriers(self) -> None:
        reasons = {item["reason"] for item in analyze(self.events)}
        self.assertEqual(
            {"encoded_response_url_followed_by_fetch", "unexplained_unicode_tag_run"},
            reasons,
        )

    def test_malformed_or_incomplete_events_do_not_alert(self) -> None:
        malformed = [
            {"event_type": "agent_response", "response_text": "\udb40\udc61\udb40\udc62\udb40\udc63\udb40\udc64"},
            {"event_type": "agent_response", "session_id": "x", "response_text": 7},
            {"event_type": "network_request", "session_id": "x", "destination_url": None},
        ]
        self.assertEqual([], analyze(malformed))

    def test_url_canonicalization_removes_default_port_and_fragment(self) -> None:
        self.assertEqual(
            "https://collector.invalid/pixel?id=abc",
            canonical_url("HTTPS://COLLECTOR.INVALID:443/pixel?id=abc#fragment"),
        )


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DetectorTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "result": "passed" if result.wasSuccessful() else "failed",
    }
    print("SAF_T1902_TEST_SUMMARY=" + json.dumps(summary, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
