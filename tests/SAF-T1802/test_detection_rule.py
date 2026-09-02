#!/usr/bin/env python3
"""Executable SAF-T1802 detector validation."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent


def main() -> int:
    completed = subprocess.run(
        [sys.executable, str(HERE / "detect_file_collection.py"), str(HERE / "fixtures.jsonl")],
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    alert_ids = [item["fixture_id"] for item in result["alerts"]]
    assert alert_ids == ["P1-outside-root", "P2-sensitive-no-approval", "B4-burst-threshold"], alert_ids
    assert result["alerts"][0]["reasons"] == ["resolved_path_outside_approved_roots"]
    assert result["alerts"][1]["reasons"] == ["sensitive_file_without_approval"]
    assert result["alerts"][2]["reasons"] == ["distinct_file_read_burst"]
    assert result["summary"] == {"events_loaded": 16, "records_skipped": 1, "alerts": 3}
    print("PASS SAF-T1802 detector: 16 valid events, 1 malformed record skipped, 3 expected alerts, 0 unexpected alerts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
