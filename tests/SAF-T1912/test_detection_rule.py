#!/usr/bin/env python3
"""Deterministic synthetic tests for SAF-T1912 response carrier triage."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "techniques" / "SAF-T1912" / "detection-rule.yml"


def matches(event: dict) -> bool:
    context = (
        event.get("event_type") == "agent_response"
        and event.get("sensitive_context_accessed") is True
        and event.get("destination_trust") in {"external", "untrusted"}
    )
    anomaly = any(
        (
            event.get("invisible_unicode_count", 0) > 0,
            event.get("bidi_control_count", 0) > 0,
            event.get("mixed_script_confusable_count", 0) > 0,
            event.get("max_unexpected_whitespace_run", 0) >= 3,
            event.get("encoded_blob_length", 0) >= 32,
            event.get("media_attested") is False,
        )
    )
    return context and anomaly


CASES = [
    ("positive-invisible", {"event_type": "agent_response", "sensitive_context_accessed": True, "destination_trust": "external", "invisible_unicode_count": 1, "media_attested": True}, True),
    ("positive-media", {"event_type": "agent_response", "sensitive_context_accessed": True, "destination_trust": "untrusted", "media_attested": False}, True),
    ("boundary-blob-31", {"event_type": "agent_response", "sensitive_context_accessed": True, "destination_trust": "external", "encoded_blob_length": 31, "media_attested": True}, False),
    ("boundary-blob-32", {"event_type": "agent_response", "sensitive_context_accessed": True, "destination_trust": "external", "encoded_blob_length": 32, "media_attested": True}, True),
    ("negative-no-sensitive-read", {"event_type": "agent_response", "sensitive_context_accessed": False, "destination_trust": "external", "bidi_control_count": 1, "media_attested": True}, False),
    ("negative-trusted-destination", {"event_type": "agent_response", "sensitive_context_accessed": True, "destination_trust": "trusted", "max_unexpected_whitespace_run": 9, "media_attested": True}, False),
    ("negative-clean", {"event_type": "agent_response", "sensitive_context_accessed": True, "destination_trust": "external", "media_attested": True}, False),
    ("expected-false-positive-encoded-business-data", {"event_type": "agent_response", "sensitive_context_accessed": True, "destination_trust": "external", "encoded_blob_length": 80, "media_attested": True}, True),
]


def main() -> int:
    rule_text = RULE_PATH.read_text(encoding="utf-8")
    assert "id: 118d8725-3f36-4cd7-9d84-60baccc304b7" in rule_text
    assert "condition: sensitive_egress and carrier_anomaly" in rule_text
    failures = []
    for name, event, expected in CASES:
        actual = matches(event)
        if actual != expected:
            failures.append(f"{name}: expected {expected}, got {actual}")
    if failures:
        print("FAIL SAF-T1912 detection tests")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"PASS SAF-T1912 detection tests: {len(CASES)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
