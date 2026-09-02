#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1408 experimental analytic."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RULE_PATH = ROOT / "techniques" / "SAF-T1408" / "detection-rule.yml"
CASES_PATH = HERE / "test-cases.json"
WINDOW_SECONDS = 600


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def method(event: dict[str, object]) -> str:
    value = event.get("code_challenge_method")
    if value in (None, ""):
        return "missing"
    return str(value).casefold()


def complete(event: dict[str, object]) -> bool:
    return all(event.get(field) not in (None, "") for field in ("client_id", "session_id", "event_type", "outcome")) and parse_time(event.get("timestamp")) is not None


def detect(events: list[dict[str, object]]) -> bool:
    scoped = [event for event in events if complete(event) and str(event.get("protocol", "")).casefold() == "mcp"]
    for event in scoped:
        if event.get("legacy_pkce_plain_approved") is True:
            continue
        event_type = event["event_type"]
        if event_type == "oauth_authorization_request" and event["outcome"] == "success":
            if event.get("code_challenge_present") is False or method(event) in {"plain", "missing"}:
                return True
        if event_type == "oauth_token_request" and event["outcome"] == "success":
            if event.get("code_verifier_present") is True and event.get("original_code_challenge_present") is False:
                return True

    ordered = sorted(scoped, key=lambda event: parse_time(event["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc))
    for first in ordered:
        if not (first["event_type"] == "oauth_authorization_request" and first["outcome"] == "failure" and method(first) == "s256"):
            continue
        for second in ordered:
            if second.get("legacy_pkce_plain_approved") is True:
                continue
            if second.get("client_id") != first.get("client_id") or second.get("session_id") != first.get("session_id"):
                continue
            if not (second["event_type"] == "oauth_client_retry" and second["outcome"] == "success" and method(second) in {"plain", "missing"}):
                continue
            delta = (parse_time(second["timestamp"]) - parse_time(first["timestamp"])).total_seconds()
            if 0 <= delta <= WINDOW_SECONDS:
                return True
    return False


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    required = {"selection_weak_authorization", "selection_absent_challenge", "selection_inconsistent_exchange", "correlation_s256_to_weaker", "condition"}
    missing = sorted(required - set(rule.get("detection", {})))
    if missing:
        raise AssertionError(f"rule is missing detection components: {missing}")

    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    failures: list[str] = []
    for case in cases:
        actual = detect(case["events"])
        if actual is not case["expected_alert"]:
            failures.append(f"{case['name']}: expected {case['expected_alert']}, got {actual}")
    if failures:
        print(f"FAIL {len(failures)}/{len(cases)}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"PASS {len(cases)}/{len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
