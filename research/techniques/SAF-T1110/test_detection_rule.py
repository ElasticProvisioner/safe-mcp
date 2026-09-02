#!/usr/bin/env python3
"""Deterministic unit test for SAF-T1110's event-sequence analytic."""

import json
import sys
from datetime import datetime
from pathlib import Path


WINDOW_SECONDS = 120
MEDIA_TYPES = {"image", "audio"}
SENSITIVE_ACTIONS = {"external_send", "state_change", "credential_access", "file_write"}


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def matches(events):
    precursors = []
    for event in sorted(events, key=lambda item: item.get("timestamp", "")):
        session = event.get("session_id")
        timestamp = event.get("timestamp")
        if not session or not timestamp:
            continue
        if (
            event.get("event_type") == "multimodal_input"
            and event.get("media_type") in MEDIA_TYPES
            and event.get("media_source_trust") == "untrusted"
            and event.get("instruction_detected") is True
        ):
            precursors.append((session, parse_time(timestamp)))
            continue
        if (
            event.get("event_type") == "tool_call"
            and event.get("action_type") in SENSITIVE_ACTIONS
            and event.get("approval_state") != "approved"
        ):
            action_time = parse_time(timestamp)
            for precursor_session, precursor_time in precursors:
                delta = (action_time - precursor_time).total_seconds()
                if precursor_session == session and 0 <= delta <= WINDOW_SECONDS:
                    return True
    return False


def main():
    data_path = Path(__file__).with_name("test-logs.json")
    cases = json.loads(data_path.read_text(encoding="utf-8"))["cases"]
    failures = []
    for case in cases:
        actual = matches(case["events"])
        result = "PASS" if actual == case["expected"] else "FAIL"
        print(f"{result} {case['name']}: expected={case['expected']} actual={actual}")
        if result == "FAIL":
            failures.append(case["name"])
    print(f"SUMMARY passed={len(cases) - len(failures)} failed={len(failures)} total={len(cases)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
