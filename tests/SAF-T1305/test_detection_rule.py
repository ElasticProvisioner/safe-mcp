#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1305 normalized-event analytic."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SHELL_SUFFIXES = (
    "/sh",
    "/bash",
    "/zsh",
    "/python",
    "/python3",
    "\\cmd.exe",
    "\\powershell.exe",
    "\\pwsh.exe",
)


def matches(event: dict) -> bool:
    required = ("parent_role", "process_image", "seconds_since_mcp_event")
    if any(key not in event for key in required):
        return False
    delta = event["seconds_since_mcp_event"]
    if not isinstance(delta, (int, float)):
        return False
    image = str(event["process_image"]).lower()
    return (
        event["parent_role"] == "mcp_runtime"
        and image.endswith(SHELL_SUFFIXES)
        and 0 <= delta <= 60
        and event.get("expected_tool_child") is not True
    )


def main() -> int:
    here = Path(__file__).resolve().parent
    fixture = json.loads((here / "test-logs.json").read_text(encoding="utf-8"))
    bundle_root = here.parents[1]
    rule_path = bundle_root / "techniques" / "SAF-T1305" / "detection-rule.yml"
    rule_text = rule_path.read_text(encoding="utf-8")
    assert "selection_window:" in rule_text and "seconds_since_mcp_event|lte: 60" in rule_text
    failures = []
    for case in fixture["cases"]:
        actual = matches(case["event"])
        if actual != case["expected_match"]:
            failures.append({"id": case["id"], "expected": case["expected_match"], "actual": actual})
    if failures:
        print(json.dumps({"status": "failed", "failures": failures}, indent=2))
        return 1
    print(f"PASS {len(fixture['cases'])} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
