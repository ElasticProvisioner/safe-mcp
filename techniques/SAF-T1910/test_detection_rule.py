#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1910 experimental correlation analytic."""

from __future__ import annotations

import json
import re
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

HERE = Path(__file__).resolve().parent


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value))
    for _ in range(2):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text.casefold()


def detects(events: list[dict[str, object]], window_seconds: int) -> bool:
    reads: list[tuple[datetime, str, list[str]]] = []
    for event in events:
        timestamp = parse_time(event.get("timestamp"))
        session = event.get("session.id")
        event_type = event.get("event.type")
        if timestamp is None or not isinstance(session, str) or not session:
            continue
        if event_type == "saf.sensitive_read":
            fingerprints = event.get("source.fingerprints")
            if isinstance(fingerprints, list):
                normalized = [normalize(item) for item in fingerprints if str(item)]
                if normalized:
                    reads.append((timestamp, session, normalized))
            continue
        if event_type not in {"mcp.tool_call", "network.http_request"}:
            continue
        if event.get("destination.trust") != "external":
            continue
        if event.get("destination.approved") is not False:
            continue
        payload = normalize(event.get("event.payload", ""))
        for read_time, read_session, fingerprints in reads:
            delta = (timestamp - read_time).total_seconds()
            if read_session != session or delta < 0 or delta > window_seconds:
                continue
            if any(fingerprint in payload for fingerprint in fingerprints):
                return True
    return False


def main() -> int:
    rule_text = (HERE / "detection-rule.yml").read_text(encoding="utf-8")
    corpus = json.loads((HERE / "test-logs.json").read_text(encoding="utf-8"))
    window_match = re.search(r"^\s*window_seconds:\s*([0-9]+)\s*$", rule_text, re.MULTILINE)
    if not window_match:
        print("FAIL SAF-T1910 detection tests: rule has no window_seconds")
        return 1
    window = int(window_match.group(1))
    failures: list[str] = []
    class_counts: dict[str, int] = {}
    for case in corpus["cases"]:
        actual = detects(case["events"], window)
        expected = bool(case["expected_alert"])
        case_class = str(case["case_class"])
        class_counts[case_class] = class_counts.get(case_class, 0) + 1
        if actual != expected:
            failures.append(f"{case['name']}: expected {expected}, got {actual}")
    required = {"positive", "negative", "boundary", "malformed", "normalization", "expected_false_positive"}
    missing = sorted(required - set(class_counts))
    if missing:
        failures.append(f"missing case classes: {', '.join(missing)}")
    if failures:
        print(f"FAIL SAF-T1910 detection tests: {len(failures)} failure(s)")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"PASS SAF-T1910 detection tests: {len(corpus['cases'])} cases; classes={json.dumps(class_counts, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
