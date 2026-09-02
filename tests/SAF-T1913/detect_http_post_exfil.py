#!/usr/bin/env python3
"""Evaluate normalized outbound MCP events without inspecting raw secret values."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TRUSTED_DESTINATIONS = {"trusted", "partner_allowlisted"}


def _text(value: Any) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


def evaluate_event(event: Any) -> dict[str, Any]:
    """Return a deterministic alert decision for one normalized event."""

    if not isinstance(event, dict):
        return {"alert": False, "reason": "malformed_event"}

    method = _text(event.get("http.request.method")).upper()
    mcp_method = _text(event.get("mcp.method"))
    data_classes = event.get("dlp.data_classes")
    if not isinstance(data_classes, list):
        return {"alert": False, "reason": "missing_or_malformed_dlp_classification"}

    sensitive_classes = sorted(
        {_text(item) for item in data_classes if _text(item)}
    )
    is_transport = method == "POST" and mcp_method == "tools/call"
    if not is_transport:
        return {"alert": False, "reason": "outside_transport_scope"}
    if not sensitive_classes:
        return {"alert": False, "reason": "no_sensitive_classification"}

    approval = _text(event.get("approval.state"))
    destination_trust = _text(event.get("destination.trust"))
    authorized = approval == "approved" and destination_trust in TRUSTED_DESTINATIONS
    if authorized:
        return {
            "alert": False,
            "reason": "approved_trusted_transfer",
            "data_classes": sensitive_classes,
        }

    return {
        "alert": True,
        "reason": "sensitive_tools_call_post_without_complete_authorization",
        "data_classes": sensitive_classes,
        "request_id": event.get("request.id"),
        "server_address": event.get("server.address"),
        "tool_name": event.get("mcp.name"),
    }


def evaluate_fixture_file(path: Path) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        result = evaluate_event(record.get("event"))
        results.append(
            {
                "id": record.get("id"),
                "line": line_number,
                "expected_alert": record.get("expected_alert"),
                **result,
            }
        )
    mismatches = [item for item in results if item["alert"] != item["expected_alert"]]
    return {
        "cases": len(results),
        "alerts": sum(1 for item in results if item["alert"]),
        "mismatches": len(mismatches),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path)
    args = parser.parse_args()
    summary = evaluate_fixture_file(args.fixtures)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if summary["mismatches"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
