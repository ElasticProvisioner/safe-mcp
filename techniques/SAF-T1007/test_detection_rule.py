#!/usr/bin/env python3
import json
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent


def evaluate(record: dict) -> bool:
    completed = (
        record.get("event") == "oauth_callback"
        and record.get("outcome") == "completed"
        and record.get("token_stored") is True
        and isinstance(record.get("elapsed_seconds"), int)
        and 0 <= record["elapsed_seconds"] <= 600
    )
    callback_subject = record.get("callback_subject")
    mismatch = callback_subject is None or callback_subject != record.get("initiator_subject")
    return completed and mismatch


def main() -> int:
    rule = yaml.safe_load((HERE / "detection-rule.yml").read_text(encoding="utf-8"))
    assert rule["detection"]["timeframe"] == "10m"
    cases = json.loads((HERE / "test-logs.json").read_text(encoding="utf-8"))
    failures = []
    for case in cases:
        actual = evaluate(case)
        if actual != case["expected_alert"]:
            failures.append(f"{case['name']}: expected={case['expected_alert']} actual={actual}")
    if failures:
        print("FAIL")
        print("\n".join(failures))
        return 1
    print(f"PASS {len(cases)}/{len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
