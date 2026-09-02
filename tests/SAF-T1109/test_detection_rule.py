#!/usr/bin/env python3
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
CASES = json.loads((BASE / "test-cases.json").read_text())

def detect(events):
    controls = []
    for event in events:
        if event.get("event_type") == "control_request":
            if (event.get("destination_scope") == "loopback"
                and event.get("endpoint_kind") in {"mcp_debug", "mcp_inspector", "agent_prototype"}
                and event.get("authentication_result") in {"missing", "bypassed"}
                and event.get("caller_trust") == "untrusted"
                and all(key in event for key in ("timestamp", "device_id", "session_id"))):
                controls.append(event)
            continue
        if (event.get("event_type") == "process_start"
            and event.get("parent_role") in {"mcp_inspector", "agent_prototype", "debug_proxy"}
            and event.get("child_allowed") is False
            and all(key in event for key in ("timestamp", "device_id", "session_id"))):
            for control in controls:
                if (control["device_id"] == event["device_id"]
                    and control["session_id"] == event["session_id"]
                    and 0 <= event["timestamp"] - control["timestamp"] <= 300):
                    return True
    return False

def main():
    results = []
    for case in CASES:
        actual = detect(case["events"])
        results.append({"name": case["name"], "expected": case["expected"], "actual": actual, "passed": actual == case["expected"]})
    print(json.dumps({"passed": sum(r["passed"] for r in results), "total": len(results), "results": results}, sort_keys=True))
    raise SystemExit(0 if all(r["passed"] for r in results) else 1)

if __name__ == "__main__":
    main()
