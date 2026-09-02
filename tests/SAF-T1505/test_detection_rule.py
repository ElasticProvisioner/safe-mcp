#!/Users/fkautz/anaconda3/bin/python3
"""Deterministic tests for the SAF-T1505 synthetic analytic."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml


SECRET_NAME = re.compile(
    r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH|COOKIE|SESSION|PRIVATE)(?:_|$)",
    re.IGNORECASE,
)


def has_secret_name(value: object) -> bool:
    return isinstance(value, list) and any(
        isinstance(item, str) and SECRET_NAME.search(item) for item in value
    )


def matches(event: object) -> bool:
    if not isinstance(event, dict):
        return False
    remote = (
        event.get("event_type") == "mcp_server_config_validation"
        and event.get("input_trust") == "untrusted"
        and event.get("destination_trust") == "external"
        and has_secret_name(event.get("referenced_env_names"))
    )
    child = (
        event.get("event_type") == "mcp_server_process_start"
        and event.get("child_trust") in {"untrusted", "unknown"}
        and event.get("allowlist_decision") == "not_explicitly_allowed"
        and has_secret_name(event.get("inherited_env_names"))
    )
    identifier = event.get("secret_identifier")
    cross_session = (
        event.get("event_type") == "runtime_secret_access"
        and event.get("same_session_owner") is False
        and event.get("authorization_result") == "not_allowed"
        and isinstance(identifier, str)
        and bool(SECRET_NAME.search(identifier))
    )
    return remote or child or cross_session


def main() -> int:
    test_dir = Path(__file__).resolve().parent
    bundle_root = test_dir.parents[1]
    rule_path = bundle_root / "techniques" / "SAF-T1505" / "detection-rule.yml"
    data_path = test_dir / "test-logs.json"
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    required = {
        "selection_remote_environment_resolution",
        "selection_untrusted_child_inheritance",
        "selection_cross_session_access",
        "condition",
    }
    if not required.issubset(rule.get("detection", {})):
        print("FAIL rule is missing required detection components")
        return 1
    cases = json.loads(data_path.read_text(encoding="utf-8"))["cases"]
    failures = []
    class_counts: dict[str, int] = {}
    for case in cases:
        result = matches(case.get("event"))
        class_counts[case["class"]] = class_counts.get(case["class"], 0) + 1
        if result is not case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']}, got {result}")
    if failures:
        print(f"FAIL {len(failures)}/{len(cases)} cases")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    summary = ", ".join(f"{key}={class_counts[key]}" for key in sorted(class_counts))
    print(f"PASS {len(cases)}/{len(cases)} cases ({summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
