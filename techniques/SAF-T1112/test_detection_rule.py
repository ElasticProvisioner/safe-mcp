#!/usr/bin/env python3
"""Deterministic, inert tests for the SAF-T1112 experimental analytic."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


WINDOW_SECONDS = 300
COUNT_THRESHOLD = 5
TOKEN_THRESHOLD = 16384
UNSAFE_APPROVAL = {"absent", "auto_approved"}


def parse_event(event: object) -> tuple[dict[str, object] | None, bool]:
    if not isinstance(event, dict):
        return None, True
    required = ("timestamp", "server_id", "session_id", "direction", "method", "requested_max_tokens", "approval_state")
    if any(key not in event for key in required):
        return None, True
    try:
        timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    except ValueError:
        return None, True
    tokens = event["requested_max_tokens"]
    if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
        return None, True
    normalized = dict(event)
    normalized["parsed_timestamp"] = timestamp
    return normalized, False


def evaluate(events: list[object]) -> tuple[bool, int]:
    malformed = 0
    relevant: list[dict[str, object]] = []
    for raw in events:
        event, bad = parse_event(raw)
        malformed += int(bad)
        if event is None:
            continue
        if event["direction"] != "server_to_client" or event["method"] != "sampling/createMessage":
            continue
        if event["approval_state"] in UNSAFE_APPROVAL:
            return True, malformed
        relevant.append(event)

    groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for event in relevant:
        groups[(str(event["server_id"]), str(event["session_id"]))].append(event)

    for grouped in groups.values():
        grouped.sort(key=lambda item: item["parsed_timestamp"])
        for start in range(len(grouped)):
            window = []
            for event in grouped[start:]:
                elapsed = (event["parsed_timestamp"] - grouped[start]["parsed_timestamp"]).total_seconds()
                if elapsed > WINDOW_SECONDS:
                    break
                window.append(event)
            token_sum = sum(int(item["requested_max_tokens"]) for item in window)
            if len(window) >= COUNT_THRESHOLD and token_sum >= TOKEN_THRESHOLD:
                return True, malformed
    return False, malformed


def main() -> None:
    payload = json.loads(Path(__file__).with_name("test-logs.json").read_text(encoding="utf-8"))
    cases = payload["cases"]
    alerting = 0
    categories = set()
    for case in cases:
        actual_alert, actual_malformed = evaluate(case["events"])
        assert actual_alert is case["expected_alert"], f"{case['id']}: alert={actual_alert}"
        assert actual_malformed == case.get("expected_malformed", 0), f"{case['id']}: malformed={actual_malformed}"
        alerting += int(actual_alert)
        categories.add(case["category"])
    required = {"positive", "negative", "boundary", "malformed", "legitimate-lookalike"}
    assert required <= categories, f"missing categories: {sorted(required - categories)}"
    print(
        f"PASS SAF-T1112 detection tests: {len(cases)} cases, {alerting} alerting, "
        f"{len(cases) - alerting} non-alerting; categories=" + ",".join(sorted(categories))
    )


if __name__ == "__main__":
    main()
