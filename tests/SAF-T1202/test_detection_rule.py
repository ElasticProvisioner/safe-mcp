#!/usr/bin/env python3
"""Deterministic evaluator for the inert SAF-T1202 example analytic."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "techniques" / "SAF-T1202" / "detection-rule.yml"
LOG_PATH = Path(__file__).with_name("test-logs.json")


def matches(event: dict[str, object]) -> bool:
    refresh_success = (
        event.get("event.action") == "oauth.token.refresh"
        and event.get("oauth.grant_type") == "refresh_token"
        and event.get("event.outcome") == "success"
    )
    disabled = event.get("user.account_status") in {"disabled", "deactivated"}
    reuse = event.get("oauth.refresh_token_reuse_detected") is True
    return refresh_success and (disabled or reuse)


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    expected_condition = "selection_refresh and (selection_disabled or selection_reuse)"
    if rule.get("detection", {}).get("condition") != expected_condition:
        print("FAIL: detection condition differs from deterministic evaluator")
        return 1

    cases = json.loads(LOG_PATH.read_text(encoding="utf-8"))
    failures: list[str] = []
    alert_count = 0
    for case in cases:
        actual = matches(case.get("event", {}))
        expected = case.get("expected_alert")
        alert_count += int(actual)
        if actual is not expected:
            failures.append(f"{case.get('case')}: expected {expected}, got {actual}")

    if failures:
        print("FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"PASS: {len(cases)} cases; {alert_count} expected alerts; {len(cases) - alert_count} expected non-alerts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
