#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1302 example analytic."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "techniques" / "SAF-T1302" / "detection-rule.yml"
CASES_PATH = Path(__file__).with_name("test-logs.json")


def matches(event: dict) -> bool:
    """Evaluate the normalized semantic condition represented by the YAML rule."""

    required = {
        "event_type",
        "tool_risk",
        "outcome",
        "requestor_privilege",
        "tool_effective_privilege",
        "approval_status",
        "breakglass_authorized",
    }
    if not required.issubset(event):
        return False
    return (
        event["event_type"] == "tool_call"
        and event["tool_risk"] == "high"
        and event["outcome"] == "success"
        and event["requestor_privilege"] in {"low", "external", "untrusted"}
        and event["tool_effective_privilege"]
        in {"elevated", "admin", "root", "cross_tenant"}
        and event["approval_status"] in {"missing", "bypassed", "not_required"}
        and event["breakglass_authorized"] is not True
    )


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    assert rule["detection"]["condition"] == (
        "selection_high_risk_success and selection_authority_gap and "
        "selection_approval_gap and not filter_authorized_breakglass"
    )
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))["cases"]
    failures = []
    category_counts: dict[str, int] = {}
    for case in cases:
        actual = matches(case["event"])
        category_counts[case["category"]] = category_counts.get(case["category"], 0) + 1
        if actual != case["expected_alert"]:
            failures.append({"id": case["id"], "expected": case["expected_alert"], "actual": actual})
    if failures:
        print(json.dumps({"status": "FAIL", "failures": failures}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "status": "PASS",
                "cases": len(cases),
                "alerts": sum(matches(case["event"]) for case in cases),
                "categories": category_counts,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
