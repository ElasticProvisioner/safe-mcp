#!/usr/bin/env python3
"""Evaluate SAF-T1101 synthetic fixtures without executing commands."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


WINDOW_SECONDS = 10.0
MCP_ACTIONS = {"tool_call", "server_launch", "authorization_launch", "proxy_call"}
SHELLS = {"sh", "bash", "zsh", "powershell.exe", "pwsh.exe", "cmd.exe"}
CONTROL_TOKENS = (" ; ", " && ", " || ", " | ")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detect(events: list[dict]) -> bool:
    mcp_events = [
        item
        for item in events
        if item.get("event", {}).get("category") == "mcp"
        and item.get("event", {}).get("action") in MCP_ACTIONS
        and item.get("mcp", {}).get("input_trust") == "untrusted"
    ]
    process_events = [
        item
        for item in events
        if item.get("event", {}).get("category") == "process"
        and item.get("event", {}).get("type") == "start"
        and item.get("process", {}).get("parent", {}).get("entity_id")
    ]
    for mcp_event in mcp_events:
        mcp = mcp_event["mcp"]
        approved = (
            mcp.get("approval_state") == "approved"
            and mcp.get("command_policy_match") is True
        )
        if approved:
            continue
        for process_event in process_events:
            process = process_event["process"]
            if process_event.get("mcp", {}).get("correlation_id") != mcp.get("correlation_id"):
                continue
            if process.get("parent", {}).get("entity_id") != mcp.get("component", {}).get("entity_id"):
                continue
            elapsed = (parse_time(process_event["@timestamp"]) - parse_time(mcp_event["@timestamp"])).total_seconds()
            if elapsed < 0 or elapsed > WINDOW_SECONDS:
                continue
            name = str(process.get("name", "")).lower()
            command_line = str(process.get("command_line", ""))
            shell_control = name in SHELLS and any(token in command_line for token in CONTROL_TOKENS)
            if shell_control or mcp.get("requested_executable_changed") is True:
                return True
    return False


def main() -> int:
    fixture_path = Path(__file__).with_name("test-logs.json")
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    results = []
    for case in payload["cases"]:
        actual = detect(case["events"])
        results.append(
            {
                "name": case["name"],
                "expected_alert": case["expected_alert"],
                "actual_alert": actual,
                "passed": actual == case["expected_alert"],
            }
        )
    summary = {
        "technique_id": payload["technique_id"],
        "total": len(results),
        "passed": sum(item["passed"] for item in results),
        "failed": sum(not item["passed"] for item in results),
        "results": results,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
