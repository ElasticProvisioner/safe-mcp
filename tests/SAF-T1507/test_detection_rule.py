#!/Users/fkautz/anaconda3/bin/python3
"""Deterministic tests for the SAF-T1507 experimental analytic."""

from __future__ import annotations

import json
from pathlib import Path


def alerts(event: dict[str, object]) -> bool:
    """Apply the normalized logic documented in detection-rule.yml."""
    if event.get("known_client_retry") is True:
        return False

    event_type = event.get("event_type")
    if event_type == "oauth_authorization_request":
        if event.get("redirect_uri_match") is False:
            return True
        if event.get("pkce_required") is True and event.get("code_challenge_method") != "S256":
            return True
        return False

    if event_type == "oauth_token_exchange":
        if event.get("pkce_verifier_valid") is False:
            return True
        count = event.get("code_exchange_count")
        return isinstance(count, int) and not isinstance(count, bool) and count >= 2

    return False


def main() -> int:
    cases_path = Path(__file__).with_name("test-cases.json")
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    required_categories = {"positive", "negative", "boundary", "malformed", "expected_false_positive"}
    present_categories = {case["category"] for case in cases}
    if not required_categories <= present_categories:
        missing = sorted(required_categories - present_categories)
        raise AssertionError(f"missing categories: {missing}")

    failures: list[str] = []
    alert_count = 0
    for case in cases:
        actual = alerts(case["event"])
        alert_count += int(actual)
        if actual is not case["expected_alert"]:
            failures.append(f"{case['name']}: expected {case['expected_alert']}, got {actual}")

    if failures:
        print(f"FAIL {len(failures)} of {len(cases)} cases")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"PASS {len(cases)} cases: {alert_count} alert, {len(cases) - alert_count} no-alert")
    print("PASS categories: boundary, expected_false_positive, malformed, negative, positive")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
