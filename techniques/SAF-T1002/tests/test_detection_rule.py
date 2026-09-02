#!/usr/bin/env python3
"""Deterministic test runner for SAF-T1002 detection-rule.yml."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "detection-rule.yml"
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "cases.json"
RESULT_PATH = Path(__file__).resolve().parent / "results" / "detection-test-results.json"
LOG_PATH = Path(__file__).resolve().parent / "logs" / "test-run.log"


def load_yaml(path: Path) -> dict:
    command = [
        "ruby",
        "-ryaml",
        "-rjson",
        "-e",
        "puts JSON.generate(YAML.load(File.read(ARGV[0])))",
        str(path),
    ]
    return json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evaluate(case: dict, rule: dict) -> bool:
    detection = rule["detection"]
    acquisition_rule = detection["acquisition"]
    component_types = set(acquisition_rule["component_type"])
    failure_states = set(acquisition_rule["verification_status"])
    window = int(rule["correlation"]["window_seconds"])
    group_fields = tuple(rule["correlation"]["group_by"])

    acquisitions = []
    executions = []
    for event in case["events"]:
        if event.get("approved_exception") is True:
            continue
        if (
            event.get("event_type") == acquisition_rule["event_type"]
            and event.get("component_type") in component_types
            and event.get("expected_channel") is True
            and event.get("verification_status") in failure_states
        ):
            acquisitions.append(event)
        elif event.get("event_type") == detection["execution"]["event_type"]:
            executions.append(event)

    for acquired in acquisitions:
        for executed in executions:
            if any(acquired.get(field) != executed.get(field) for field in group_fields):
                continue
            delta = (parse_time(executed["timestamp"]) - parse_time(acquired["timestamp"])).total_seconds()
            if 0 <= delta <= window:
                return True
    return False


def main() -> int:
    rule = load_yaml(RULE_PATH)
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    results = []
    for case in fixtures["cases"]:
        observed = evaluate(case, rule)
        passed = observed == case["expected_alert"]
        results.append(
            {
                "name": case["name"],
                "kind": case["kind"],
                "expected_alert": case["expected_alert"],
                "observed_alert": observed,
                "passed": passed,
            }
        )

    payload = {
        "technique_id": "SAF-T1002",
        "rule_id": rule["id"],
        "deterministic_clock": "fixture_timestamps_only",
        "passed": all(item["passed"] for item in results),
        "cases": results,
    }
    RESULT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"{item['name']} kind={item['kind']} expected={item['expected_alert']} observed={item['observed_alert']} passed={item['passed']}"
        for item in results
    ]
    lines.append(f"overall_passed={payload['passed']}")
    LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
