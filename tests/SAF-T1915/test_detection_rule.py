#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1915 correlation rule."""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
RULE_PATH = BASE.parents[1] / "techniques" / "SAF-T1915" / "detection-rule.yml"
CASES_PATH = BASE / "test-cases.json"


def normalize(value: object) -> str:
    return str(value).strip().casefold().replace("-", "_").replace(" ", "_")


def load_parameters(path: Path) -> dict:
    """Read this rule's deliberately simple scalar/list parameter block."""
    text = path.read_text(encoding="utf-8")
    parameters: dict[str, object] = {}
    for key in (
        "window_minutes",
        "min_bridge_events",
        "min_dex_swaps",
        "min_distinct_chains",
        "min_usd_value",
        "value_ratio_min",
        "value_ratio_max",
    ):
        match = re.search(rf"^    {key}: ([0-9.]+)$", text, re.MULTILINE)
        if match is None:
            raise ValueError(f"missing rule parameter: {key}")
        value = float(match.group(1))
        parameters[key] = int(value) if value.is_integer() else value
    risk_block = re.search(
        r"^    risky_origins:\n(?P<items>(?:      - [^\n]+\n?)+)", text, re.MULTILINE
    )
    if risk_block is None:
        raise ValueError("missing rule parameter: risky_origins")
    parameters["risky_origins"] = [
        line.removeprefix("      - ").strip()
        for line in risk_block.group("items").splitlines()
    ]
    return parameters


def parse_time(value: object) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def classify_event(value: object) -> str:
    event_type = normalize(value)
    if event_type in {"bridge_deposit", "bridge_withdrawal", "bridge_out", "bridge_in"}:
        return "bridge"
    if event_type in {"dex_swap", "swap"}:
        return "dex"
    return "other"


def valid_event(raw: dict) -> dict | None:
    required = ("subject_id", "event_time", "chain", "event_type", "usd_value", "provenance_risk")
    if any(raw.get(field) in (None, "") for field in required):
        return None
    try:
        event_time = parse_time(raw["event_time"])
        usd_value = float(raw["usd_value"])
    except (TypeError, ValueError):
        return None
    return {
        "subject_id": normalize(raw["subject_id"]),
        "event_time": event_time,
        "chain": normalize(raw["chain"]),
        "kind": classify_event(raw["event_type"]),
        "usd_value": usd_value,
        "provenance_risk": normalize(raw["provenance_risk"]),
    }


def alert(events: list[dict], parameters: dict) -> bool:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for raw in events:
        event = valid_event(raw)
        if event is not None:
            grouped[event["subject_id"]].append(event)

    risky = {normalize(value) for value in parameters["risky_origins"]}
    for group in grouped.values():
        ordered = sorted(group, key=lambda event: event["event_time"])
        if len(ordered) < 2:
            continue
        kinds = [event["kind"] for event in ordered]
        chains = {event["chain"] for event in ordered}
        if sum(kind == "bridge" for kind in kinds) < parameters["min_bridge_events"]:
            continue
        if sum(kind == "dex" for kind in kinds) < parameters["min_dex_swaps"]:
            continue
        if len(chains) < parameters["min_distinct_chains"]:
            continue
        if not any(event["provenance_risk"] in risky for event in ordered):
            continue
        if max(event["usd_value"] for event in ordered) < parameters["min_usd_value"]:
            continue
        elapsed = (ordered[-1]["event_time"] - ordered[0]["event_time"]).total_seconds() / 60
        if elapsed > parameters["window_minutes"]:
            continue
        first_value = ordered[0]["usd_value"]
        if first_value <= 0:
            continue
        ratio = ordered[-1]["usd_value"] / first_value
        if parameters["value_ratio_min"] <= ratio <= parameters["value_ratio_max"]:
            return True
    return False


def main() -> int:
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))["cases"]
    parameters = load_parameters(RULE_PATH)
    failures = []
    for case in cases:
        actual = alert(case["events"], parameters)
        if actual != case["expected_alert"]:
            failures.append(f"{case['id']}: expected={case['expected_alert']} actual={actual}")
    if failures:
        print(f"FAIL: {len(failures)}/{len(cases)} cases failed")
        print("\n".join(failures))
        return 1
    print(f"PASS: {len(cases)}/{len(cases)} cases matched expected outcomes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
