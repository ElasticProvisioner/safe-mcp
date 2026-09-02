#!/usr/bin/env python3
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "SAF-T1207" / "update-events.json"
RESULTS = ROOT / "tests" / "results" / "SAF-T1207-detection-results.json"


def get(event, dotted):
    return event.get(dotted)


def alerts(event):
    if get(event, "event.action") != "component_update_activated":
        return False
    approved = (
        get(event, "update.approval_state") == "approved"
        and get(event, "artifact.digest_matches_approved") is True
        and get(event, "update.source_matches_approved") is True
        and get(event, "signature.verification") == "valid"
        and get(event, "signer.matches_approved") is True
    )
    return not approved


def main():
    cases = json.loads(FIXTURES.read_text())
    outcomes = []
    for case in cases:
        actual = alerts(case["event"])
        outcomes.append({"name": case["name"], "expected": case["expected"], "actual": actual, "passed": actual == case["expected"]})
    passed = sum(item["passed"] for item in outcomes)
    result = {"technique_id": "SAF-T1207", "validated_on": "2026-09-01", "total": len(outcomes), "passed": passed, "failed": len(outcomes) - passed, "outcomes": outcomes}
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(result, indent=2) + "\n")
    print(f"SAF-T1207 detection: {passed}/{len(outcomes)} cases passed")
    return 0 if passed == len(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
