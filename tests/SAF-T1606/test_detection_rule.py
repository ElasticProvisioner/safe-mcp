#!/usr/bin/env python3
"""Deterministic tests for the SAF-T1606 experimental MCP audit analytic."""

from __future__ import annotations

import json
import posixpath
from pathlib import Path
from typing import Any

import yaml


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RULE_PATH = ROOT / "techniques" / "SAF-T1606" / "detection-rule.yml"
FIXTURE_PATH = HERE / "test-logs.json"


def nested(record: dict[str, Any], *keys: str) -> Any:
    value: Any = record
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def normalize_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip().replace("\\", "/")
    normalized = posixpath.normpath(candidate)
    return normalized if normalized.startswith("/") else "/" + normalized


def path_is_sensitive(path: str | None) -> bool:
    if path is None:
        return False
    fixed_roots = ("/etc", "/root", "/var/lib")
    if any(path == root or path.startswith(root + "/") for root in fixed_roots):
        return True
    return any(component in {".ssh", ".config"} for component in path.split("/"))


def detect(event: dict[str, Any], rule: dict[str, Any]) -> bool:
    documented_tools = set(rule["detection"]["selection_tool"]["tool.name"])
    recursive_tools = set(
        rule["detection"]["selection_recursive_tool"]["tool.name"]
    )
    method = nested(event, "rpc", "method")
    tool_name = nested(event, "tool", "name")
    path = normalize_path(nested(event, "tool", "arguments", "path"))
    approved_allowlisted = (
        nested(event, "approval", "state") == "approved"
        and nested(event, "session", "allowlisted") is True
    )
    return bool(
        method == "tools/call"
        and tool_name in documented_tools
        and (tool_name in recursive_tools or path_is_sensitive(path))
        and not approved_allowlisted
    )


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    cases = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    failures: list[str] = []
    counts: dict[str, int] = {}
    for case in cases:
        observed = detect(case["event"], rule)
        counts[case["case_type"]] = counts.get(case["case_type"], 0) + 1
        if observed is not case["expected"]:
            failures.append(
                f"{case['name']}: expected {case['expected']}, observed {observed}"
            )
    if failures:
        print(f"FAIL SAF-T1606 detection tests: {len(failures)}/{len(cases)} failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    summary = ", ".join(f"{name}={counts[name]}" for name in sorted(counts))
    print(f"PASS SAF-T1606 detection tests: {len(cases)}/{len(cases)} passed")
    print(f"Case coverage: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
