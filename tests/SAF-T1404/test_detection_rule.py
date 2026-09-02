#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1404 paired-digest analytic."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


CORRELATION_FIELDS = ("trace_id", "request_id", "server_id", "tool_name")


def canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evaluate(case: dict[str, object]) -> str:
    receipt = case.get("receipt")
    consumption = case.get("consumption")
    if not isinstance(receipt, dict) or not isinstance(consumption, dict):
        return "insufficient_telemetry"
    if any(receipt.get(field) != consumption.get(field) for field in CORRELATION_FIELDS):
        return "insufficient_telemetry"
    receipt_digest = canonical_digest(receipt.get("result"))
    consumption_digest = canonical_digest(consumption.get("result"))
    if receipt_digest != consumption_digest and not case.get("transform_authorized"):
        return "alert"
    return "no_alert"


def main() -> int:
    fixture_path = Path(__file__).with_name("test-logs.json")
    cases = json.loads(fixture_path.read_text(encoding="utf-8"))["cases"]
    failures: list[str] = []
    for case in cases:
        actual = evaluate(case)
        expected = case["expected"]
        print(f"{case['name']}: expected={expected} actual={actual}")
        if actual != expected:
            failures.append(case["name"])
    print(f"RESULT: {'PASS' if not failures else 'FAIL'} ({len(cases) - len(failures)}/{len(cases)} cases)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
