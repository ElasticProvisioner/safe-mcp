#!/usr/bin/env python3
"""Deterministic inert tests for SAF-T1106's correlation analytic."""

from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import sys


WINDOW_SECONDS = 300


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def alerts(events):
    valid = [e for e in events if e.get("event_type") == "tool_call" and e.get("session_id") and e.get("tool_name")]
    by_session = {}
    for event in valid:
        by_session.setdefault(event["session_id"], []).append(event)
    found = set()
    for session_id, session_events in by_session.items():
        session_events.sort(key=lambda e: parse_time(e["timestamp"]))
        for start in range(len(session_events)):
            window = []
            start_time = parse_time(session_events[start]["timestamp"])
            for event in session_events[start:]:
                if (parse_time(event["timestamp"]) - start_time).total_seconds() <= WINDOW_SECONDS:
                    window.append(event)
            if len(window) < 6 or any(e.get("approval_state") == "approved_long_running" for e in window):
                continue
            if any(e.get("completion_state") == "terminal" for e in window):
                continue
            tools = Counter(e["tool_name"] for e in window)
            args = Counter(e.get("normalized_argument_hash") for e in window if e.get("normalized_argument_hash"))
            progress = Counter(e.get("progress_fingerprint") for e in window if e.get("progress_fingerprint"))
            if max(tools.values(), default=0) >= 4 and (max(args.values(), default=0) >= 3 or max(progress.values(), default=0) >= 3):
                found.add(session_id)
    return sorted(found)


def main():
    cases_path = Path(__file__).with_name("test-logs.json")
    cases = json.loads(cases_path.read_text(encoding="utf-8"))["cases"]
    failures = []
    for case in cases:
        actual = alerts(case["events"])
        if actual != case["expected_alert_sessions"]:
            failures.append({"case": case["name"], "expected": case["expected_alert_sessions"], "actual": actual})
    if failures:
        print(json.dumps({"status": "FAIL", "failures": failures}, sort_keys=True))
        return 1
    print(json.dumps({"status": "PASS", "cases": len(cases)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
