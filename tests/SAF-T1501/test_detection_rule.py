#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RULE_PATH = ROOT / "techniques" / "SAF-T1501" / "detection-rule.yml"
CASES_PATH = HERE / "cases.json"
DIRECTIVE = re.compile(
    r"\b(?:ignore\s+(?:prior|previous)|override|bypass|must\s+use|always\s+mark|prefer\s+the\s+value|send\s+to|forward\s+to)\b",
    re.IGNORECASE,
)


def canonical_digest(definition: dict) -> str:
    payload = json.dumps(
        definition,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def string_leaves(value, path=()):
    if isinstance(value, dict):
        for key in sorted(value):
            yield from string_leaves(value[key], path + (str(key),))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from string_leaves(item, path + (str(index),))
    elif isinstance(value, str):
        yield path, unicodedata.normalize("NFKC", value).casefold()


def detects(event: dict) -> bool:
    if event.get("event_type") != "mcp_tool_definition_observed":
        return False
    if event.get("source_trust") != "untrusted":
        return False
    if event.get("lifecycle_event") == "explicit_reapproval":
        return False
    definition = event.get("definition")
    if not isinstance(definition, dict):
        return False

    observed = canonical_digest(definition)
    approved = event.get("approved_schema_sha256")
    schema_changed = isinstance(approved, str) and len(approved) == 64 and observed != approved

    suspicious_paths = []
    suspicious_schema_paths = []
    for path, text in string_leaves(definition):
        if DIRECTIVE.search(text):
            suspicious_paths.append(path)
            if path and path[0] in {"inputSchema", "outputSchema"}:
                suspicious_schema_paths.append(path)
    distributed = len(set(suspicious_paths)) >= 2 and bool(suspicious_schema_paths)
    return schema_changed or distributed


def main() -> int:
    rule_text = RULE_PATH.read_text(encoding="utf-8")
    required = (
        "  selection_context:",
        "  selection_schema_change:",
        "  selection_distributed_directives:",
        "  filter_explicit_reapproval:",
        "  condition:",
    )
    if any(item not in rule_text for item in required):
        raise AssertionError("detection-rule.yml is missing executable-profile selections")

    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    alerts = 0
    for case in cases:
        event = copy.deepcopy(case["event"])
        if event.get("approved_schema_sha256") == "__MATCH_CURRENT__":
            event["approved_schema_sha256"] = canonical_digest(event["definition"])
        actual = detects(event)
        if actual:
            alerts += 1
        if actual is not case["expected"]:
            raise AssertionError(f"{case['name']}: expected {case['expected']}, got {actual}")

    print(f"PASS SAF-T1501 detection profile: {len(cases)}/{len(cases)} cases; alerts={alerts}; non_alerts={len(cases) - alerts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
