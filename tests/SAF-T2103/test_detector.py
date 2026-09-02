#!/usr/bin/env python3
"""Deterministic, inert validator for the SAF-T2103 example analytic."""

from __future__ import annotations

import json
import sys
import unicodedata
from pathlib import Path

AGENT_TYPES = {"ai_agent", "coding_agent", "automation_agent"}
ACTIONS = {"file_write", "commit", "push", "pull_request_update"}
RISK = {
    "test_disabled",
    "security_check_removed",
    "build_guard_weakened",
    "unauthorized_config_change",
    "opaque_behavior_change",
}
WEAK_APPROVAL = {"missing", "denied", "bypassed"}
PREFIXES = ("src/", "lib/", "app/", "test/", "tests/", ".github/workflows/")


def normalize(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.casefold().replace("\\", "/").replace("-", "_").replace(" ", "_")


def get(record: dict, *path: str, default=None):
    current = record
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def detect(event: dict) -> bool:
    actor = normalize(get(event, "actor", "type", default=""))
    action = normalize(event.get("action", ""))
    paths = event.get("changed_paths")
    indicators = get(event, "change", "indicators", default=[])
    if not isinstance(paths, list) or not isinstance(indicators, list):
        return False
    normalized_paths = []
    for path in paths:
        normalized = normalize(path)
        while normalized.startswith("./"):
            normalized = normalized[2:]
        normalized_paths.append(normalized)
    sensitive = any(
        path.startswith(PREFIXES) or "security" in path or "build" in path
        for path in normalized_paths
    )
    risky = any(normalize(indicator) in RISK for indicator in indicators)
    approval = normalize(get(event, "approval", "status", default="missing"))
    weak_context = approval in WEAK_APPROVAL or get(
        event, "context", "untrusted_content", default=False
    ) is True
    return actor in AGENT_TYPES and action in ACTIONS and sensitive and risky and weak_context


def main() -> int:
    cases_path = Path(__file__).with_name("cases.json")
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    failures = []
    for case in cases:
        actual = detect(case.get("event", {}))
        if actual is not case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']}, got {actual}")
    if failures:
        print("FAIL")
        print("\n".join(failures))
        return 1
    alerts = sum(bool(case["expected"]) for case in cases)
    expected_fp = sum(bool(case.get("expected_false_positive")) for case in cases)
    print(f"PASS cases={len(cases)} alerts={alerts} expected_false_positives={expected_fp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
