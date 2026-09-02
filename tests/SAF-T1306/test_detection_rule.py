#!/usr/bin/env python3
"""Exercise the SAF-T1306 example analytic against inert synthetic events."""

from __future__ import annotations

import json
from pathlib import Path


def alerts(event: dict) -> bool:
    error_signal = (
        event.get("outcome") == "rejected"
        and event.get("error_code") in {"issuer_mismatch", "issuer_missing"}
    )
    mismatch_signal = event.get("issuer_match") is False
    required_missing = (
        event.get("authorization_response_iss_parameter_supported") is True
        and event.get("received_issuer") is None
    )
    return error_signal or mismatch_signal or required_missing


def main() -> int:
    path = Path(__file__).with_name("test-logs.json")
    events = json.loads(path.read_text(encoding="utf-8"))
    failures: list[str] = []
    alert_count = 0
    negative_count = 0
    documented_false_positive_count = 0
    for event in events:
        observed = alerts(event)
        expected = bool(event["expected_alert"])
        if observed:
            alert_count += 1
        else:
            negative_count += 1
        if event.get("expected_false_positive"):
            documented_false_positive_count += 1
        if observed != expected:
            failures.append(
                f"{event['name']}: expected alert={expected}, observed={observed}"
            )
    if failures:
        print("FAIL")
        for failure in failures:
            print(failure)
        return 1
    print(
        "PASS: "
        f"{len(events)} cases; {alert_count} alerts; {negative_count} negatives; "
        f"{documented_false_positive_count} documented maintenance false positive"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
