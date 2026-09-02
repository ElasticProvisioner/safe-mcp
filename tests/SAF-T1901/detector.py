#!/usr/bin/env python3
"""Detect repeated unapproved webhook traffic correlated to MCP tool calls."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


WINDOW_SECONDS = 600
MIN_EVENTS = 3
MIN_DISTINCT_INVOCATIONS = 2


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalized_endpoint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or not parts.hostname:
        return None
    host = parts.hostname.lower()
    port = parts.port
    netloc = f"{host}:{port}" if port and port != 443 else host
    path = parts.path or "/"
    return urlunsplit(("https", netloc, path, "", ""))


def eligible(event: dict[str, Any]) -> tuple[datetime, tuple[str, str, str], str] | None:
    if event.get("event.kind") != "http.client":
        return None
    if event.get("http.request.method") != "POST":
        return None
    if event.get("mcp.invocation.mode") != "model":
        return None
    if event.get("saf.webhook.destination_approved") is not False:
        return None
    if not isinstance(event.get("http.request.body.size"), int) or event["http.request.body.size"] <= 0:
        return None
    if event.get("saf.webhook.response_consumed") is not True:
        return None

    timestamp = parse_timestamp(event.get("timestamp"))
    session = event.get("mcp.session.id")
    tool = event.get("mcp.tool.name")
    invocation = event.get("mcp.invocation.id")
    server = event.get("server.address")
    endpoint = normalized_endpoint(event.get("url.full"))
    if not all(isinstance(item, str) and item for item in (session, tool, invocation, server)):
        return None
    if timestamp is None or endpoint is None:
        return None
    if urlsplit(endpoint).hostname != server.lower():
        return None
    return timestamp, (session, tool, endpoint), invocation


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[tuple[datetime, str]]] = defaultdict(list)
    for event in events:
        if not isinstance(event, dict):
            continue
        candidate = eligible(event)
        if candidate is None:
            continue
        timestamp, key, invocation = candidate
        grouped[key].append((timestamp, invocation))

    alerts: list[dict[str, Any]] = []
    for (session, tool, endpoint), values in sorted(grouped.items()):
        values.sort()
        left = 0
        for right, (right_time, _) in enumerate(values):
            while (right_time - values[left][0]).total_seconds() > WINDOW_SECONDS:
                left += 1
            window = values[left : right + 1]
            invocations = {item[1] for item in window}
            if len(window) >= MIN_EVENTS and len(invocations) >= MIN_DISTINCT_INVOCATIONS:
                alerts.append(
                    {
                        "session_id": session,
                        "tool_name": tool,
                        "endpoint": endpoint,
                        "event_count": len(window),
                        "distinct_invocations": len(invocations),
                        "window_start": window[0][0].isoformat(),
                        "window_end": window[-1][0].isoformat(),
                        "classification": "suspected_outbound_webhook_c2",
                    }
                )
                break
    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    document = json.loads(args.fixture.read_text(encoding="utf-8"))
    results = []
    for case in document.get("cases", []):
        alerts = detect(case.get("events", []))
        results.append({"name": case.get("name"), "alerts": alerts})
    print(json.dumps({"results": results}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
