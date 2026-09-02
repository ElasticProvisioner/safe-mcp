#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1204 lifecycle correlation."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


WINDOW = timedelta(days=7)


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def risky_write(event: dict[str, object]) -> bool:
    flags = event.get("semantic_flags")
    return (
        event.get("event_type") == "memory_write"
        and event.get("memory_scope") == "persistent"
        and bool(event.get("memory_id"))
        and (
            event.get("source_trust") in {"untrusted", "unknown"}
            or event.get("user_approved") is False
            or (isinstance(flags, list) and "memory_instruction" in flags)
        )
    )


def alerts(events: list[dict[str, object]]) -> bool:
    writes = [event for event in events if risky_write(event)]
    for write in writes:
        write_time = parse_time(write.get("timestamp"))
        if write_time is None:
            continue
        for event in events:
            retrieval_time = parse_time(event.get("timestamp"))
            if (
                event.get("event_type") == "memory_retrieval"
                and event.get("memory_id") == write.get("memory_id")
                and event.get("session_id") != write.get("session_id")
                and retrieval_time is not None
                and timedelta(0) <= retrieval_time - write_time <= WINDOW
            ):
                return True
    return False


def main() -> int:
    data_path = Path(__file__).with_name("test-logs.json")
    cases = json.loads(data_path.read_text(encoding="utf-8"))["cases"]
    failures: list[str] = []
    positives = negatives = 0
    for case in cases:
        actual = alerts(case["events"])
        expected = case["expected_alert"]
        positives += int(expected)
        negatives += int(not expected)
        if actual != expected:
            failures.append(f"{case['name']}: expected {expected}, got {actual}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print(f"PASS {len(cases)} cases ({positives} positive, {negatives} negative)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
