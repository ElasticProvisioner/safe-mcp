#!/usr/bin/env python3
import json
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
RULE = HERE.parents[1] / "techniques" / "SAF-T1301" / "detection-rule.yml"


def matches(event, selection):
    return all(event.get(key) == value for key, value in selection.items())


def main():
    rule = yaml.safe_load(RULE.read_text(encoding="utf-8"))
    cases = json.loads((HERE / "test-logs.json").read_text(encoding="utf-8"))
    selection = rule["detection"]["selection"]
    failures = []
    for case in cases:
        actual = matches(case["event"], selection)
        if actual != case["expected"]:
            failures.append(f"{case['name']}: expected {case['expected']}, got {actual}")
    if failures:
        raise SystemExit("FAIL\n" + "\n".join(failures))
    positives = sum(1 for case in cases if case["expected"])
    print(f"PASS {len(cases)} cases ({positives} positive, {len(cases) - positives} negative)")


if __name__ == "__main__":
    main()
