#!/usr/bin/env python3
"""Deterministic representative tests for SAF-T1604's example analytic."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


WINDOW_SECONDS = 300
DISTINCT_SERVER_THRESHOLD = 5
EVENT_TYPES = {
    "mcp_server_discover_response",
    "mcp_unsupported_protocol_version_error",
}


def normalized(value: Any) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def has_version_value(event: dict[str, Any]) -> bool:
    if normalized(event.get("server_info_version")):
        return True
    versions = event.get("supported_versions")
    return isinstance(versions, list) and any(normalized(item) for item in versions)


def should_alert(events: list[dict[str, Any]]) -> bool:
    by_actor: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for event in events:
        actor = normalized(event.get("actor_id"))
        server = normalized(event.get("server_id"))
        event_type = normalized(event.get("event_type"))
        timestamp = parse_timestamp(event.get("timestamp"))
        if (
            not actor
            or not server
            or timestamp is None
            or event_type not in EVENT_TYPES
            or normalized(event.get("actor_class")) == "approved_inventory"
            or not has_version_value(event)
        ):
            continue
        by_actor[actor].append((timestamp, server))

    for actor_events in by_actor.values():
        actor_events.sort()
        start = 0
        for end, (end_time, _) in enumerate(actor_events):
            while (end_time - actor_events[start][0]).total_seconds() > WINDOW_SECONDS:
                start += 1
            distinct_servers = {server for _, server in actor_events[start : end + 1]}
            if len(distinct_servers) >= DISTINCT_SERVER_THRESHOLD:
                return True
    return False


def main() -> int:
    fixture_path = Path(__file__).with_name("test-logs.json")
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for case in payload["cases"]:
        actual = should_alert(case["events"])
        expected = bool(case["expected_alert"])
        if actual != expected:
            failures.append(f"{case['name']}: expected {expected}, got {actual}")
        else:
            print(f"PASS {case['name']}: alert={actual}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print(f"PASS SAF-T1604 detection tests: {len(payload['cases'])} of {len(payload['cases'])} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
