#!/usr/bin/env python3
"""Deterministic reference detector for normalized SAF-T1802 events."""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict, deque
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any


READ_ACTIONS = {"read_file", "get_file", "upload_attachment", "send_media", "convert_file"}
WINDOW_SECONDS = 300
DISTINCT_FILE_THRESHOLD = 4


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_successful_file_read(event: dict[str, Any]) -> bool:
    if event.get("result_status") != "success" or int(event.get("bytes_read", 0)) <= 0:
        return False
    if event.get("method") == "resources/read":
        return True
    return event.get("method") == "tools/call" and event.get("tool_action") in READ_ACTIONS


def normalized_posix(value: str) -> str:
    text = str(PurePosixPath(value))
    return text if text.startswith("/") else f"/{text}"


def outside_approved_roots(event: dict[str, Any]) -> bool:
    resolved = event.get("resolved_path")
    roots = event.get("approved_roots")
    if not resolved or not isinstance(roots, list) or not roots:
        return False
    resolved_norm = normalized_posix(str(resolved))
    for root in roots:
        root_norm = normalized_posix(str(root))
        try:
            if os.path.commonpath([resolved_norm, root_norm]) == root_norm:
                return False
        except ValueError:
            continue
    return True


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    windows: dict[tuple[str, str, str], deque[tuple[datetime, str]]] = defaultdict(deque)

    for event in sorted(events, key=lambda item: (parse_time(item["timestamp"]), item["fixture_id"])):
        if not is_successful_file_read(event):
            continue

        reasons: list[str] = []
        if outside_approved_roots(event):
            reasons.append("resolved_path_outside_approved_roots")
        if event.get("sensitive") is True and event.get("approval_state") != "approved":
            reasons.append("sensitive_file_without_approval")

        if not event.get("allowlisted_workload", False):
            key = (str(event.get("actor_id")), str(event.get("session_id")), str(event.get("server_id")))
            event_time = parse_time(event["timestamp"])
            window = windows[key]
            while window and (event_time - window[0][0]).total_seconds() > WINDOW_SECONDS:
                window.popleft()
            window.append((event_time, str(event.get("resolved_path") or event.get("requested_path"))))
            if len({path for _, path in window}) >= DISTINCT_FILE_THRESHOLD:
                reasons.append("distinct_file_read_burst")

        if reasons:
            alerts.append(
                {
                    "fixture_id": event["fixture_id"],
                    "timestamp": event["timestamp"],
                    "actor_id": event.get("actor_id"),
                    "session_id": event.get("session_id"),
                    "server_id": event.get("server_id"),
                    "requested_path": event.get("requested_path"),
                    "resolved_path": event.get("resolved_path"),
                    "reasons": reasons,
                }
            )
    return alerts


def load_events(path: str) -> tuple[list[dict[str, Any]], int]:
    events: list[dict[str, Any]] = []
    skipped = 0
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            try:
                value = json.loads(raw)
                if not isinstance(value, dict) or not value.get("timestamp") or not value.get("fixture_id"):
                    raise ValueError("normalized event fields missing")
                parse_time(str(value["timestamp"]))
                events.append(value)
            except (json.JSONDecodeError, TypeError, ValueError):
                skipped += 1
    return events, skipped


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture_path")
    args = parser.parse_args()
    events, skipped = load_events(args.fixture_path)
    alerts = detect(events)
    print(
        json.dumps(
            {
                "technique_id": "SAF-T1802",
                "alerts": alerts,
                "summary": {"events_loaded": len(events), "records_skipped": skipped, "alerts": len(alerts)},
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
