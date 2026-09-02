from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from detect_context_snapshot_capture import detect, evaluate_event, read_jsonl


HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "events.jsonl"
EXPECTED = HERE / "expected_alerts.json"
DETECTOR = HERE / "detect_context_snapshot_capture.py"


class ContextSnapshotDetectorTests(unittest.TestCase):
    def test_fixture_matches_expected_alerts(self) -> None:
        expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
        self.assertEqual(detect(read_jsonl(FIXTURE)), expected)

    def test_positive_reason_order_and_projection(self) -> None:
        alert = evaluate_event(read_jsonl(FIXTURE)[0])
        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["reasons"],
            [
                "authorization_not_allowed",
                "tenant_boundary_mismatch",
                "owner_mismatch_without_approved_delegation",
            ],
        )
        self.assertNotIn("destination", alert)
        self.assertNotIn("bytes", alert)

    def test_invalid_and_nonqualifying_events_are_suppressed(self) -> None:
        records = read_jsonl(FIXTURE)
        self.assertTrue(all(evaluate_event(event) is None for event in records[4:]))

    def test_cli_emits_canonical_json_lines(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(DETECTOR), str(FIXTURE)],
            check=True,
            capture_output=True,
            text=True,
        )
        emitted = [json.loads(line) for line in completed.stdout.splitlines()]
        expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
        self.assertEqual(emitted, expected)


if __name__ == "__main__":
    unittest.main()
