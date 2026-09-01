#!/usr/bin/env python3
"""Deterministic validation for the SAF-T1001 experimental analytic."""

from __future__ import annotations

import json
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def nested(record: dict, dotted: str):
    value = record
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def normalized(value: object) -> str:
    return unicodedata.normalize("NFKC", str(value or "")).casefold()


def extract_block(text: str, name: str, next_name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  {re.escape(next_name)}:)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise ValueError(f"missing detection block: {name}")
    return match.group(1)


def list_values(block: str) -> list[str]:
    return [normalized(item) for item in re.findall(r"^      - (.+)$", block, re.MULTILINE)]


def load_rule_config(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    actions = list_values(extract_block(text, "selection_event", "selection_unapproved"))
    controls = list_values(extract_block(text, "keywords_control", "keywords_sensitive"))
    sensitive = list_values(extract_block(text, "keywords_sensitive", "keywords_cross_tool"))
    cross_block = extract_block(text, "keywords_cross_tool", "condition")
    cross_match = re.search(r"tool\.description\|re:\s*'([^']+)'", cross_block)
    if not cross_match:
        raise ValueError("missing cross-tool regular expression")
    return {
        "actions": actions,
        "controls": controls,
        "sensitive": sensitive,
        "cross_pattern": cross_match.group(1),
    }


def alerts(rule: dict, event: dict) -> bool:
    action = nested(event, "event.action")
    if normalized(action) not in rule["actions"]:
        return False
    if nested(event, "tool.definition.approved") is not False:
        return False
    current_hash = nested(event, "tool.definition.current_hash")
    approved_hash = nested(event, "tool.definition.approved_hash")
    if not current_hash or current_hash == approved_hash:
        return False

    description = normalized(nested(event, "tool.description"))
    if not description:
        return False
    has_control = any(term in description for term in rule["controls"])
    has_sensitive = any(term in description for term in rule["sensitive"])
    has_cross_tool = bool(re.search(rule["cross_pattern"], description, flags=re.IGNORECASE))
    return (has_control and has_sensitive) or has_cross_tool


def main() -> int:
    rule = load_rule_config(ROOT / "detection-rule.yml")
    fixture = json.loads((ROOT / "test-logs.json").read_text(encoding="utf-8"))
    results = []
    for case in fixture["cases"]:
        actual = alerts(rule, case["event"])
        results.append(
            {
                "id": case["id"],
                "category": case["category"],
                "expected_alert": case["expected_alert"],
                "actual_alert": actual,
                "passed": actual == case["expected_alert"],
            }
        )

    passed = all(item["passed"] for item in results)
    alerts_observed = sum(1 for item in results if item["actual_alert"])
    summary = {
        "schema_version": 1,
        "technique_id": "SAF-T1001",
        "validated_on": "2026-09-01",
        "status": "passed" if passed else "failed",
        "case_count": len(results),
        "alerts_observed": alerts_observed,
        "expected_alerts": 4,
        "results": results,
    }
    (ROOT / "test-results.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if passed and alerts_observed == 4 else 1


if __name__ == "__main__":
    sys.exit(main())
