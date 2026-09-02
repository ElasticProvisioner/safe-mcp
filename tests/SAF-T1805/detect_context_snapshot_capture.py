#!/usr/bin/env python3
"""Detect suspicious successful reads or exports of active agent context.

The detector consumes normalized JSON Lines. It intentionally evaluates only
metadata and content classifications; it never requires captured context bodies.
Malformed records are ignored so one partial audit event does not fail a batch.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


CAPTURE_EVENTS = {
    "context_snapshot_read",
    "context_snapshot_export",
    "checkpoint_history_read",
    "trace_export",
}

SENSITIVE_CONTEXT_CLASSES = {
    "system_prompt",
    "conversation_turn",
    "tool_result",
    "resource_content",
    "checkpoint_state",
    "trace_input",
    "trace_output",
}

REQUIRED_FIELDS = {
    "timestamp",
    "event_id",
    "event_type",
    "result",
    "actor_id",
    "owner_id",
    "authorization_decision",
    "approval_status",
    "content_classes",
    "item_count",
    "bytes",
}


def _valid_event(event: Any) -> bool:
    if not isinstance(event, dict) or not REQUIRED_FIELDS <= set(event):
        return False
    if not all(isinstance(event[name], str) and event[name] for name in (
        "timestamp", "event_id", "event_type", "result", "actor_id", "owner_id",
        "authorization_decision", "approval_status"
    )):
        return False
    if not isinstance(event["content_classes"], list):
        return False
    if not all(isinstance(item, str) for item in event["content_classes"]):
        return False
    if not isinstance(event["item_count"], int) or isinstance(event["item_count"], bool):
        return False
    if not isinstance(event["bytes"], int) or isinstance(event["bytes"], bool):
        return False
    return event["item_count"] >= 0 and event["bytes"] >= 0


def evaluate_event(event: Any) -> dict[str, Any] | None:
    """Return a canonical alert for a qualifying normalized event."""

    if not _valid_event(event):
        return None
    if event["event_type"] not in CAPTURE_EVENTS or event["result"] != "success":
        return None
    if event["item_count"] == 0:
        return None
    sensitive = sorted(set(event["content_classes"]) & SENSITIVE_CONTEXT_CLASSES)
    if not sensitive:
        return None

    reasons: list[str] = []
    if event["authorization_decision"] != "allow":
        reasons.append("authorization_not_allowed")

    actor_tenant = event.get("actor_tenant_id")
    owner_tenant = event.get("owner_tenant_id")
    if actor_tenant and owner_tenant and actor_tenant != owner_tenant:
        reasons.append("tenant_boundary_mismatch")

    if event["actor_id"] != event["owner_id"] and event["approval_status"] != "approved":
        reasons.append("owner_mismatch_without_approved_delegation")

    if not reasons:
        return None

    alert = {
        "event_id": event["event_id"],
        "event_type": event["event_type"],
        "reasons": reasons,
        "sensitive_content_classes": sensitive,
        "actor_id": event["actor_id"],
        "owner_id": event["owner_id"],
    }
    for key in ("actor_tenant_id", "owner_tenant_id", "snapshot_id", "thread_id", "trace_id"):
        if event.get(key):
            alert[key] = event[key]
    return alert


def detect(events: Iterable[Any]) -> list[dict[str, Any]]:
    return [alert for event in events if (alert := evaluate_event(event)) is not None]


def read_jsonl(path: Path) -> list[Any]:
    records: list[Any] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(None)
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="Normalized JSONL audit events")
    args = parser.parse_args()
    for alert in detect(read_jsonl(args.events)):
        print(json.dumps(alert, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
