#!/usr/bin/env python3
"""Deterministic behavioral test for SAF-T1703's normalized-event analytic."""

import json
import sys
from datetime import datetime
from pathlib import Path


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def alerts(events):
    results = []
    sources = {
        event["event_id"]: event
        for event in events
        if event.get("event_type") == "tool_result"
        and event.get("trust_label") in {"untrusted", "unknown"}
    }
    for event in events:
        if event.get("event_type") != "tool_call":
            continue
        source = sources.get(event.get("caused_by_event_id"))
        if not source or source.get("trace_id") != event.get("trace_id"):
            continue
        delta = (parse_time(event["timestamp"]) - parse_time(source["timestamp"])).total_seconds()
        if not 0 <= delta <= 300:
            continue
        if source.get("source_server_id") == event.get("target_server_id"):
            continue
        if event.get("user_intent_supported") is not False:
            continue
        if event.get("approval_state") not in {"absent", "bypassed"}:
            continue
        if event.get("action_class") not in {"privileged_read", "external_write", "code_execution"}:
            continue
        results.append(event["event_id"])
    return results


def main(path):
    fixture = json.loads(Path(path).read_text(encoding="utf-8"))
    observed = alerts(fixture["events"])
    expected = fixture["expected_alert_event_ids"]
    assert observed == expected, f"expected {expected}, observed {observed}"
    all_calls = [e["event_id"] for e in fixture["events"] if e.get("event_type") == "tool_call"]
    expected_nonalerts = fixture["expected_nonalert_event_ids"]
    observed_nonalerts = [event_id for event_id in all_calls if event_id not in observed]
    assert observed_nonalerts == expected_nonalerts, (
        f"expected nonalerts {expected_nonalerts}, observed {observed_nonalerts}"
    )
    print(f"PASS SAF-T1703: {len(observed)} alerts, {len(observed_nonalerts)} non-alerts")
    print("alerts=" + ",".join(observed))
    print("nonalerts=" + ",".join(observed_nonalerts))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_detection_rule.py test-logs.json")
    main(sys.argv[1])
