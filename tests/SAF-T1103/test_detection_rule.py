#!/usr/bin/env python3
"""Deterministic fixture test for SAF-T1103 provenance correlation."""

from __future__ import annotations

import json
from pathlib import Path


WINDOW_SECONDS = 300


def alerts(events: list[dict]) -> bool:
    lifecycle: dict[tuple[str, str], dict] = {}
    for event in events:
        event_type = event.get("event_type")
        run_id = event.get("run_id")
        call_id = event.get("tool_call_id")
        key = (run_id, call_id)
        if event_type == "agent.tool.call.start" and call_id:
            lifecycle[key] = {
                "start": event["timestamp"],
                "name": event.get("tool_name"),
                "origin": event.get("call_origin"),
                "args": False,
                "end": None,
            }
        elif event_type == "agent.tool.call.args" and key in lifecycle:
            lifecycle[key]["args"] = True
        elif event_type == "agent.tool.call.end" and key in lifecycle:
            lifecycle[key]["end"] = event["timestamp"]
            lifecycle[key]["end_name"] = event.get("tool_name")
        elif event_type in {"agent.tool.execution.started", "agent.tool.execution.allowed"}:
            approved_manual = (
                event.get("call_origin") == "human_manual"
                and event.get("approval_state") == "approved"
                and event.get("approver_recorded") is True
            )
            if approved_manual:
                continue
            record = lifecycle.get(key)
            complete = bool(
                record
                and record.get("origin") == "trusted_model"
                and record.get("args")
                and record.get("end") is not None
                and record.get("name") == event.get("tool_name")
                and record.get("end_name") == event.get("tool_name")
                and 0 <= event["timestamp"] - record["end"] <= WINDOW_SECONDS
            )
            if (
                not call_id
                or event.get("tool_registered") is not True
                or event.get("provenance_verified") is not True
                or not complete
            ):
                return True
    return False


def main() -> int:
    fixtures = json.loads(Path(__file__).with_name("test-events.json").read_text())
    failures = []
    positives = 0
    negatives = 0
    for fixture in fixtures:
        actual = alerts(fixture["events"])
        positives += int(actual)
        negatives += int(not actual)
        if actual != fixture["expected_alert"]:
            failures.append((fixture["case"], fixture["expected_alert"], actual))
    if failures:
        for case, expected, actual in failures:
            print(f"FAIL {case}: expected={expected} actual={actual}")
        return 1
    print(f"PASS 9 cases: positives={positives} negatives={negatives}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
