#!/usr/bin/env python3
"""Deterministic behavioral tests for the SAF-T1702 correlation."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


WRITE_MAX_SECONDS = 86_400
ACTION_MAX_SECONDS = 300


def seconds(left: str, right: str) -> float:
    return (datetime.fromisoformat(right.replace("Z", "+00:00")) - datetime.fromisoformat(left.replace("Z", "+00:00"))).total_seconds()


def detects(events: list[dict]) -> bool:
    writes: dict[str, dict] = {}
    reads: list[dict] = []
    actions: list[dict] = []
    for event in events:
        event_type = event.get("event_type")
        if event_type == "memory_write" and event.get("memory_id"):
            writes[event["memory_id"]] = event
        elif event_type == "memory_read":
            reads.append(event)
        elif event_type == "agent_action":
            actions.append(event)

    for read in reads:
        for memory_id in read.get("memory_ids", []):
            write = writes.get(memory_id)
            if not write:
                continue
            if write.get("source_trust") not in {"untrusted", "unknown"}:
                continue
            if write.get("review_status") == "approved" or write.get("writer_role") == "trusted_curator":
                continue
            required = (
                write.get("timestamp"),
                read.get("timestamp"),
                write.get("writer_principal_id"),
                write.get("writer_session_id"),
                read.get("reader_principal_id"),
                read.get("reader_session_id"),
                write.get("tenant_id"),
                read.get("tenant_id"),
                write.get("namespace"),
                read.get("namespace"),
            )
            if any(value in (None, "") for value in required):
                continue
            if write["tenant_id"] != read["tenant_id"] or write["namespace"] != read["namespace"]:
                continue
            if write["writer_principal_id"] == read["reader_principal_id"] and write["writer_session_id"] == read["reader_session_id"]:
                continue
            write_age = seconds(write["timestamp"], read["timestamp"])
            if write_age < 0 or write_age > WRITE_MAX_SECONDS:
                continue
            for action in actions:
                if action.get("principal_id") != read["reader_principal_id"] or action.get("session_id") != read["reader_session_id"]:
                    continue
                if action.get("risk") not in {"high", "critical"} or memory_id not in action.get("context_memory_ids", []):
                    continue
                action_age = seconds(read["timestamp"], action.get("timestamp", ""))
                if 0 <= action_age <= ACTION_MAX_SECONDS:
                    return True
    return False


def main() -> int:
    fixture_path = Path(__file__).with_name("fixtures.json")
    cases = json.loads(fixture_path.read_text(encoding="utf-8"))["cases"]
    results = []
    for case in cases:
        actual = detects(case["events"])
        results.append({"name": case["name"], "expected": case["expected"], "actual": actual, "passed": actual == case["expected"]})
    output = {"technique_id": "SAF-T1702", "total": len(results), "passed": sum(item["passed"] for item in results), "failed": sum(not item["passed"] for item in results), "results": results}
    print(f"PASS {output['passed']}/{output['total']} cases" if output["failed"] == 0 else f"FAIL {output['failed']}/{output['total']} cases")
    return 0 if output["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
