#!/usr/bin/env python3
"""Run inert behavioral tests for SAF-T1704's correlation analytic."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RULE_PATH = ROOT / "techniques" / "SAF-T1704" / "detection-rule.yml"
FIXTURE_PATH = HERE / "fixtures.jsonl"


def detects(events: list[dict], window: int) -> bool:
    catalog_events = [
        event
        for event in events
        if event.get("event_type") == "mcp.tool_catalog_change"
        and event.get("source_server_trust") in {"untrusted", "compromised"}
        and event.get("metadata_fingerprint_changed") is True
        and event.get("trace_id")
        and event.get("source_server_id")
    ]
    call_events = [
        event
        for event in events
        if event.get("event_type") == "mcp.tool_call"
        and event.get("operation_sensitivity") == "high"
        and event.get("user_approved") is False
        and event.get("trace_id")
        and event.get("target_server_id")
        and isinstance(event.get("causal_context_server_ids"), list)
    ]
    for source in catalog_events:
        for target in call_events:
            elapsed = target.get("timestamp", -1) - source.get("timestamp", 0)
            if not 0 <= elapsed <= window:
                continue
            if source["trace_id"] != target["trace_id"]:
                continue
            if source["source_server_id"] == target["target_server_id"]:
                continue
            if source["source_server_id"] not in target["causal_context_server_ids"]:
                continue
            return True
    return False


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    window = rule["detection"]["correlation"]["ordered_within_seconds"]
    cases = [json.loads(line) for line in FIXTURE_PATH.read_text(encoding="utf-8").splitlines() if line]
    failures: list[str] = []
    for case in cases:
        actual = detects(case["events"], window)
        if actual is not case["expected"]:
            failures.append(f"{case['case']}: expected {case['expected']} got {actual}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print(f"PASS {len(cases)}/{len(cases)} SAF-T1704 synthetic detector cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
