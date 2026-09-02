#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def matches(event: dict, detection: dict) -> bool:
    failed_states = set(detection["selection_provenance"]["provenance.status"])
    return (
        event.get("event.action")
        == detection["selection_action"]["event.action"]
        and event.get("sample.origin")
        == detection["selection_origin"]["sample.origin"]
        and event.get("provenance.status") in failed_states
        and event.get("sample.disposition")
        != detection["filter_quarantine"]["sample.disposition"]
    )


def main() -> int:
    here = Path(__file__).resolve().parent
    rule_path = here.parents[1] / "techniques" / "SAF-T2107" / "detection-rule.yml"
    if not rule_path.is_file():
        rule_path = Path(sys.argv[1]) if len(sys.argv) > 1 else rule_path
    rule = json.loads(rule_path.read_text(encoding="utf-8"))
    events = json.loads((here / "test-logs.json").read_text(encoding="utf-8"))
    expected = json.loads((here / "expected-results.json").read_text(encoding="utf-8"))
    actual = {item["case_id"]: matches(item["event"], rule["detection"]) for item in events}
    if actual != expected:
        print(json.dumps({"expected": expected, "actual": actual}, indent=2))
        return 1
    print("PASS: 2 positive and 4 negative/boundary cases behaved as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
