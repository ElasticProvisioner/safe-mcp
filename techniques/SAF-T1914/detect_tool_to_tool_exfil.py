#!/usr/bin/env python3
"""Reference detector for SAF-T1914 over normalized, synthetic-safe audit events."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SENSITIVE_LABELS = {"confidential", "restricted", "secret"}
DEFAULT_WINDOW_SECONDS = 120


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _strings(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str) and item}


def _is_sensitive(event: dict[str, Any]) -> bool:
    return bool(_strings(event.get("sensitivity")) & SENSITIVE_LABELS)


def _lineage_tokens(event: dict[str, Any]) -> set[str]:
    return _strings(event.get("data_refs")) | _strings(
        event.get("content_fingerprints")
    )


def detect(
    events: Iterable[dict[str, Any]], window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> list[dict[str, Any]]:
    """Return alerts for sensitive source results reused in unauthorized sink calls."""
    normalized: list[tuple[datetime, dict[str, Any]]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        parsed = _timestamp(event.get("timestamp"))
        if parsed is None or not isinstance(event.get("session_id"), str):
            continue
        normalized.append((parsed, event))
    normalized.sort(key=lambda item: item[0])

    sources_by_session: dict[str, list[tuple[datetime, dict[str, Any]]]] = {}
    alerts: list[dict[str, Any]] = []

    for when, event in normalized:
        session_id = event["session_id"]
        event_type = event.get("event_type")
        role = event.get("tool_role")

        if event_type == "tool_result" and role == "source" and _is_sensitive(event):
            if _lineage_tokens(event):
                sources_by_session.setdefault(session_id, []).append((when, event))
            continue

        if not (
            event_type == "tool_call"
            and role == "sink"
            and event.get("outbound_capable") is True
        ):
            continue

        if (
            event.get("authorized_transfer") is True
            and event.get("approval_state") == "approved"
            and event.get("destination_allowed") is True
        ):
            continue

        sink_tokens = _lineage_tokens(event)
        if not sink_tokens:
            continue

        for source_when, source in reversed(sources_by_session.get(session_id, [])):
            elapsed = (when - source_when).total_seconds()
            if elapsed < 0:
                continue
            if elapsed > window_seconds:
                break
            distinct = (
                source.get("server_id") != event.get("server_id")
                or source.get("tool_name") != event.get("tool_name")
            )
            matched = _lineage_tokens(source) & sink_tokens
            if distinct and matched:
                alerts.append(
                    {
                        "technique_id": "SAF-T1914",
                        "session_id": session_id,
                        "source_call_id": source.get("call_id"),
                        "source_server_id": source.get("server_id"),
                        "source_tool_name": source.get("tool_name"),
                        "sink_call_id": event.get("call_id"),
                        "sink_server_id": event.get("server_id"),
                        "sink_tool_name": event.get("tool_name"),
                        "destination": event.get("destination"),
                        "approval_state": event.get("approval_state"),
                        "elapsed_seconds": int(elapsed),
                        "matched_lineage_tokens": sorted(matched),
                    }
                )
                break

    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="JSON array of normalized events")
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    args = parser.parse_args()
    data = json.loads(args.events.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit("events file must contain a JSON array")
    print(json.dumps(detect(data, args.window_seconds), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
