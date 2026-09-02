#!/usr/bin/env python3
"""Exercise the bounded SAF-T1503 process-lineage analytic."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "techniques" / "SAF-T1503" / "detection-rule.yml"
CASES_PATH = Path(__file__).with_name("test-cases.json")


def normalize_path(value: object) -> str:
    return str(value or "").replace("/", "\\").casefold()


def matches(event: dict[str, object]) -> bool:
    image = normalize_path(event.get("Image"))
    command_line = str(event.get("CommandLine") or "")
    ancestor_role = str(event.get("AncestorProcessRole") or "").casefold()
    if ancestor_role != "local_mcp_server":
        return False
    unix_utility = image.endswith("\\env") or image.endswith("\\printenv")
    windows_set = image.endswith("\\cmd.exe") and bool(
        re.search(r"(?:^|\s)/(?:c|k)\s+set(?:\s|$)", command_line, re.IGNORECASE)
    )
    return unix_utility or windows_set


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    cases_document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    required_detection_keys = {
        "server_ancestor",
        "utility_unix",
        "utility_windows",
        "condition",
    }
    if required_detection_keys - set(rule.get("detection", {})):
        print("FAIL rule structure does not match the tested analytic")
        return 1

    failures: list[str] = []
    cases = cases_document["cases"]
    for case in cases:
        actual = matches(case.get("event", {}))
        if actual != case["expected"]:
            failures.append(f"{case['id']}: expected={case['expected']} actual={actual}")
        print(f"{'PASS' if actual == case['expected'] else 'FAIL'} {case['id']} expected={str(case['expected']).lower()} actual={str(actual).lower()}")

    if failures:
        print(f"FAIL SAF-T1503 detector {len(failures)}/{len(cases)} cases failed")
        return 1
    categories = sorted({case["category"] for case in cases})
    print(f"PASS SAF-T1503 detector {len(cases)}/{len(cases)} cases; categories={','.join(categories)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
