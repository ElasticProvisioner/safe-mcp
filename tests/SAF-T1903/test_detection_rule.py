#!/usr/bin/env python3
"""Deterministic inert validation for SAF-T1903."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def norm(value: object) -> str:
    return str(value or "").strip().casefold()


def norm_host(value: object) -> str:
    return norm(value).rstrip(".")


def when(event: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return None


def key(event: dict) -> tuple[str, str, str] | None:
    values = tuple(norm(event.get(field)) for field in ("host_id", "process_id", "server_id"))
    return values if all(values) else None


def evaluate(events: list[dict], window: int) -> tuple[bool, int]:
    valid: list[dict] = []
    invalid = 0
    for raw in events:
        event = dict(raw)
        event["event_type"] = norm(event.get("event_type"))
        event["direction"] = norm(event.get("direction"))
        event["role"] = norm(event.get("role"))
        event["semantic"] = norm(event.get("semantic"))
        event["child_category"] = norm(event.get("child_category"))
        event["destination"] = norm_host(event.get("destination"))
        event["_time"] = when(event)
        event["_key"] = key(event)
        if not event["_time"] or not event["_key"]:
            invalid += 1
            continue
        if event["event_type"] == "network_connection" and not event["destination"]:
            invalid += 1
            continue
        valid.append(event)

    for start in valid:
        if start["event_type"] != "mcp_server_start" or start["role"] not in {"mcp_server", "server"}:
            continue
        allow = {norm_host(item) for item in start.get("approved_destinations", [])}
        related = [
            item for item in valid
            if item["_key"] == start["_key"]
            and 0 <= (item["_time"] - start["_time"]).total_seconds() <= window
        ]
        egress = any(
            item["event_type"] == "network_connection"
            and item["direction"] == "outbound"
            and item["destination"] not in allow
            and item["destination"] not in {"localhost", "127.0.0.1", "::1"}
            for item in related
        )
        interactive = any(
            item["event_type"] == "child_process_start"
            and item.get("interactive") is True
            and item["child_category"] in {"shell", "command_interpreter"}
            for item in related
        )
        inbound = {
            norm(item.get("channel_id")) for item in related
            if item["event_type"] == "channel_message"
            and item["direction"] == "inbound"
            and item["semantic"] == "remote_command"
            and norm(item.get("channel_id"))
        }
        outbound = {
            norm(item.get("channel_id")) for item in related
            if item["event_type"] == "channel_message"
            and item["direction"] == "outbound"
            and item["semantic"] == "command_result"
            and norm(item.get("channel_id"))
        }
        if egress and (interactive or bool(inbound & outbound)):
            return True, invalid
    return False, invalid


def main() -> int:
    payload = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
    results = []
    failures = []
    for case in payload["cases"]:
        actual, invalid = evaluate(case["events"], payload["window_seconds"])
        ok = actual is case["expected_alert"] and invalid >= case.get("minimum_invalid_events", 0)
        result = {"id": case["id"], "expected_alert": case["expected_alert"], "actual_alert": actual, "invalid_events": invalid, "passed": ok}
        results.append(result)
        if not ok:
            failures.append(case["id"])
    output = {"schema_version": 1, "technique_id": "SAF-T1903", "passed": not failures, "case_count": len(results), "results": results}
    (ROOT / "test-results.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failures:
        print("FAIL " + ",".join(failures))
        return 1
    print(f"PASS {len(results)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
