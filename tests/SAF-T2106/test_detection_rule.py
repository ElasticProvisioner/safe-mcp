#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
CASES = json.loads((Path(__file__).with_name("test-cases.json")).read_text())

def parse_ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)

def detects(events):
    writes = []
    for event in events:
        if event.get("event_type") == "memory_write" and event.get("record_id") and event.get("approval_state") == "unapproved" and event.get("source_trust") == "untrusted":
            writes.append(event)
        if event.get("event_type") != "memory_retrieval" or not event.get("record_id"):
            continue
        for write in writes:
            delta = (parse_ts(event["timestamp"]) - parse_ts(write["timestamp"])).total_seconds()
            if write["record_id"] == event["record_id"] and write.get("session_id") != event.get("session_id") and 0 <= delta <= 7 * 86400:
                return True
    return False

def main():
    failed = []
    for case in CASES:
        actual = detects(case["events"])
        if actual != case["expected"]:
            failed.append((case["name"], case["expected"], actual))
    print(f"SAF-T2106 detection tests: {len(CASES) - len(failed)}/{len(CASES)} passed")
    if failed:
        for name, expected, actual in failed:
            print(f"FAIL {name}: expected={expected} actual={actual}")
        raise SystemExit(1)
    print("RESULT: passed")

if __name__ == "__main__":
    main()
