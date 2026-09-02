#!/usr/bin/env python3
"""Representative validation for the SAF-T1913 normalized-event detector."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from detect_http_post_exfil import evaluate_event  # noqa: E402


class DetectionFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.records = []
        for line in (HERE / "fixtures.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                cls.records.append(json.loads(line))

    def test_all_fixture_expectations(self) -> None:
        for record in self.records:
            with self.subTest(case=record["id"]):
                result = evaluate_event(record.get("event"))
                self.assertEqual(record["expected_alert"], result["alert"])

    def test_fixture_classes_present(self) -> None:
        classes = {record["class"] for record in self.records}
        self.assertTrue(
            {"positive", "negative", "boundary", "malformed", "false_positive"}
            <= classes
        )

    def test_normalization_case_alerts(self) -> None:
        record = next(item for item in self.records if item["id"] == "positive_normalized_case")
        self.assertTrue(evaluate_event(record["event"])["alert"])

    def test_malformed_scalar_dlp_is_not_alerted(self) -> None:
        record = next(item for item in self.records if item["id"] == "malformed_dlp_scalar")
        result = evaluate_event(record["event"])
        self.assertFalse(result["alert"])
        self.assertEqual("missing_or_malformed_dlp_classification", result["reason"])

    def test_suppression_requires_both_controls(self) -> None:
        for case_id in ("boundary_trusted_unapproved", "boundary_approved_untrusted"):
            record = next(item for item in self.records if item["id"] == case_id)
            self.assertTrue(evaluate_event(record["event"])["alert"])


if __name__ == "__main__":
    unittest.main()
