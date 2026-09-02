#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def alerts(event):
    observed = event.get("observed_sha256")
    approved = event.get("approved_sha256")
    return bool(
        event.get("event_type") == "mcp_server_process_start"
        and event.get("server_registered") is True
        and event.get("change_approved") is False
        and isinstance(observed, str)
        and isinstance(approved, str)
        and SHA256.fullmatch(observed)
        and SHA256.fullmatch(approved)
        and observed.lower() != approved.lower()
    )


def main():
    base = Path(__file__).resolve().parent
    rule_text = (base / "detection-rule.yml").read_text()
    assert "condition: selection and digest_mismatch" in rule_text
    fixtures = json.loads((base / "test-logs.json").read_text())
    failures = []
    for fixture in fixtures:
        actual = alerts(fixture["event"])
        if actual != fixture["expected_alert"]:
            failures.append(f"{fixture['name']}: expected {fixture['expected_alert']}, got {actual}")
    positives = sum(1 for fixture in fixtures if fixture["expected_alert"])
    negatives = len(fixtures) - positives
    if failures:
        print("FAIL")
        print("\n".join(failures))
        return 1
    print(f"PASS: {len(fixtures)} fixtures ({positives} alerts, {negatives} non-alerts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
