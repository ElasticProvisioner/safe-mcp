#!/usr/bin/env python3
"""Deterministic synthetic validation for SAF-T1105."""

import json
import os
from pathlib import Path


FILE_OPERATIONS = {"read_file", "write_file", "copy_file", "move_file", "delete_file"}


def contained(path: str, roots: list[str]) -> bool:
    if not path or not roots:
        return False
    canonical = os.path.realpath(path)
    for root in roots:
        canonical_root = os.path.realpath(root)
        try:
            if os.path.commonpath([canonical, canonical_root]) == canonical_root:
                return True
        except ValueError:
            continue
    return False


def alerts(event: dict) -> bool:
    if event.get("event_type") != "mcp_tool_call":
        return False
    if event.get("operation") not in FILE_OPERATIONS:
        return False
    if event.get("approved_override") is True:
        return False
    resolved = event.get("resolved_path")
    if not resolved:
        return False
    if event.get("access_mode") == "no_access":
        return True
    declared_scope = event.get("path_scope")
    if declared_scope in {"outside_allowed_root", "no_access_violation"}:
        return True
    roots = event.get("allowed_roots") or []
    return bool(roots) and not contained(resolved, roots)


def main() -> int:
    cases = json.loads(Path(__file__).with_name("test-logs.json").read_text())
    failures = []
    alerts_expected = 0
    for case in cases:
        actual = alerts(case["event"])
        expected = case["expected_alert"]
        alerts_expected += int(expected)
        if actual != expected:
            failures.append(f"{case['name']}: expected {expected}, got {actual}")
    if failures:
        print("FAIL")
        print("\n".join(failures))
        return 1
    nonalerts = len(cases) - alerts_expected
    print(f"PASS {len(cases)}/{len(cases)} cases: {alerts_expected} alerts and {nonalerts} non-alerts matched expectations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
