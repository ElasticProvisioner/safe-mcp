#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1707 correlation analytic."""

from __future__ import annotations

import json
from pathlib import Path


WINDOW = 600


def detect(events: list[dict]) -> bool:
    starts: dict[tuple[str, str, str], list[dict]] = {}
    successes: dict[tuple[str, str, str], list[dict]] = {}
    for event in sorted(events, key=lambda item: item.get("timestamp", -1)):
        required = ("timestamp", "state_digest", "client_id", "redirect_uri")
        if any(field not in event for field in required):
            continue
        key = tuple(event[field] for field in required[1:])
        if event.get("event_type") == "authorization_request_started" and event.get("initiating_session_binding"):
            starts.setdefault(key, []).append(event)
        if event.get("event_type") == "authorization_callback_accepted" and event.get("outcome") == "success" and event.get("callback_session_binding"):
            successes.setdefault(key, []).append(event)

    for key, callbacks in successes.items():
        if len(callbacks) > 1 and callbacks[-1]["timestamp"] - callbacks[0]["timestamp"] <= WINDOW:
            return True
        for callback in callbacks:
            for start in starts.get(key, []):
                delta = callback["timestamp"] - start["timestamp"]
                if 0 <= delta <= WINDOW and callback["callback_session_binding"] != start["initiating_session_binding"]:
                    return True
    return False


def main() -> int:
    path = Path(__file__).with_name("events.json")
    cases = json.loads(path.read_text(encoding="utf-8"))
    failures = []
    for case in cases:
        actual = detect(case["events"])
        print(f"{case['name']}: expected={case['expected']} actual={actual}")
        if actual != case["expected"]:
            failures.append(case["name"])
    print(f"cases={len(cases)} failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
