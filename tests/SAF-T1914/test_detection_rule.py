#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "techniques" / "SAF-T1914" / "detect_tool_to_tool_exfil.py"
FIXTURE_PATH = Path(__file__).with_name("fixtures.json")

SPEC = importlib.util.spec_from_file_location("saf_t1914_detector", DETECTOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load SAF-T1914 detector")
DETECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECTOR)


class ToolToToolExfilDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))["cases"]

    def test_all_declared_cases(self) -> None:
        for case in self.cases:
            with self.subTest(case=case["name"]):
                alerts = DETECTOR.detect(case["events"])
                self.assertEqual(case["expected_alerts"], len(alerts))
                for alert in alerts:
                    self.assertEqual("SAF-T1914", alert["technique_id"])
                    self.assertTrue(alert["matched_lineage_tokens"])
                    self.assertLessEqual(alert["elapsed_seconds"], 120)
                    self.assertNotEqual(
                        (alert["source_server_id"], alert["source_tool_name"]),
                        (alert["sink_server_id"], alert["sink_tool_name"]),
                    )

    def test_window_can_be_tuned(self) -> None:
        boundary = next(
            case for case in self.cases if case["name"] == "boundary_exactly_120_seconds"
        )
        self.assertEqual([], DETECTOR.detect(boundary["events"], window_seconds=119))


if __name__ == "__main__":
    unittest.main()
