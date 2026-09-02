#!/usr/bin/env python3
"""Deterministic synthetic validation for SAF-T1803's normalized analytic."""

import json
from pathlib import Path


THRESHOLD_BYTES = 10_485_760
DUMP_OPERATIONS = {"dump", "export", "bulk_read"}


def detects(event):
    operation = event.get("database.operation")
    result_bytes = event.get("result.bytes")
    return (
        event.get("mcp.method") == "tools/call"
        and isinstance(operation, str)
        and operation.lower() in DUMP_OPERATIONS
        and isinstance(result_bytes, int)
        and not isinstance(result_bytes, bool)
        and result_bytes >= THRESHOLD_BYTES
        and event.get("approval.state") != "approved"
        and event.get("actor.is_approved_backup") is not True
    )


def main():
    cases = json.loads(Path(__file__).with_name("test-logs.json").read_text(encoding="utf-8"))
    failures = []
    for case in cases:
        actual = detects(case["event"])
        if actual is not case["expected"]:
            failures.append(f'{case["name"]}: expected {case["expected"]}, got {actual}')
    if failures:
        raise SystemExit("FAIL\n" + "\n".join(failures))
    alerts = sum(1 for case in cases if case["expected"])
    print(f"PASS {len(cases)} cases ({alerts} alerts, {len(cases) - alerts} non-alerts)")


if __name__ == "__main__":
    main()
