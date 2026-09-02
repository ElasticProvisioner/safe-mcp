#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

ALLOWED_FINDINGS = {
    "default_ignorable",
    "bidi_control",
    "confusable",
    "encoded_payload",
    "fragmented_instruction",
    "opaque_state",
    "image_instruction",
}


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def alerts(events: list[dict[str, object]], window_seconds: int) -> bool:
    for ingest in events:
        findings = ingest.get("representation_findings")
        session = ingest.get("session_id")
        start = parse_time(ingest.get("timestamp"))
        if (
            ingest.get("event_type") != "content_ingest"
            or ingest.get("trust") != "untrusted"
            or not isinstance(session, str)
            or start is None
            or ingest.get("origin_allowlisted") is True
            or not isinstance(findings, list)
            or not any(item in ALLOWED_FINDINGS for item in findings)
        ):
            continue
        for follow_on in events:
            end = parse_time(follow_on.get("timestamp"))
            if follow_on.get("session_id") != session or end is None or end < start:
                continue
            if (end - start).total_seconds() > window_seconds:
                continue
            event_type = follow_on.get("event_type")
            sensitive = event_type == "tool_call" and follow_on.get("sensitivity") == "high"
            interpretive = event_type == "decode_or_interpret"
            if not (sensitive or interpretive):
                continue
            if follow_on.get("approval_state") == "approved":
                continue
            return True
    return False


def main() -> int:
    here = Path(__file__).resolve().parent
    root = here.parents[1]
    rule_text = (root / "techniques" / "SAF-T1402" / "detection-rule.yml").read_text()
    cases = json.loads((here / "cases.json").read_text())
    match = re.search(r"^  timeframe: ([0-9]+)s$", rule_text, re.MULTILINE)
    if not match:
        print("FAIL: detection-rule.yml lacks an integer-second timeframe")
        return 1
    window = int(match.group(1))
    failures: list[str] = []
    alert_count = 0
    for case in cases:
        actual = alerts(case["events"], window)
        alert_count += int(actual)
        if actual != case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']}, got {actual}")
    if failures:
        print("FAIL")
        print("\n".join(failures))
        return 1
    print(f"PASS: {len(cases)}/{len(cases)} cases; alerts={alert_count}; suppressed={len(cases)-alert_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
