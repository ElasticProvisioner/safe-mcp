#!/usr/bin/env python3
"""Deterministic tests for the defensive SAF-T1009 issuer-binding analytic."""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def alerts(event: dict) -> bool:
    """Evaluate only fail-closed defensive states; never transmit a credential."""
    event_type = event.get("event_type")
    flow_id = event.get("flow_id")
    if not isinstance(flow_id, str) or not flow_id:
        return False

    if event_type == "authorization_callback_validation":
        if event.get("metadata_validated") is False:
            return True
        expected = event.get("recorded_expected_issuer")
        returned = event.get("response_iss")
        if event.get("authorization_response_iss_parameter_supported") is True and returned is None:
            return True
        if isinstance(expected, str) and isinstance(returned, str):
            return expected != returned
        return False

    if event_type == "outbound_token_request":
        return event.get("code_forwarded") is True and event.get(
            "prior_validation_outcome"
        ) in {"rejected", "failed", "missing"}

    return False


def main() -> None:
    rule_text = (HERE / "detection-rule.yml").read_text(encoding="utf-8")
    assert "status: experimental" in rule_text
    assert "- saf.t1009" in rule_text

    fixtures = json.loads((HERE / "test-logs.json").read_text(encoding="utf-8"))
    assert len(fixtures) == 8
    failures = []
    alert_count = 0
    for fixture in fixtures:
        actual = alerts(fixture["event"])
        alert_count += int(actual)
        if actual is not fixture["expected_alert"]:
            failures.append(
                f"{fixture['name']}: expected {fixture['expected_alert']}, got {actual}"
            )
    if failures:
        raise AssertionError("; ".join(failures))
    print(f"PASS 8 fixtures ({alert_count} alerts, {8 - alert_count} non-alerts)")


if __name__ == "__main__":
    main()
