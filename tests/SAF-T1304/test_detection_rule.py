#!/usr/bin/env python3
import json
from datetime import datetime
from pathlib import Path

WINDOW_SECONDS = 600


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detect(events):
    reasons = []
    seen = {}
    for event in sorted(events, key=lambda item: item.get("timestamp", "")):
        resource = event.get("expected_resource")
        audience = event.get("token_audience")
        principal = event.get("principal_id")
        upstream = event.get("upstream_principal_id")
        fingerprint = event.get("token_fingerprint")
        exchanged = event.get("token_exchange_validated") is True
        if resource and audience and resource != audience:
            reasons.append("audience_mismatch")
        if principal and upstream and principal != upstream:
            reasons.append("principal_mismatch")
        if fingerprint and resource and event.get("timestamp"):
            current_time = parse_time(event["timestamp"])
            for prior_time, prior_resource in seen.get(fingerprint, []):
                delta = (current_time - prior_time).total_seconds()
                if 0 <= delta <= WINDOW_SECONDS and prior_resource != resource and not exchanged:
                    reasons.append("cross_resource_reuse")
            seen.setdefault(fingerprint, []).append((current_time, resource))
    return sorted(set(reasons))


def main():
    data_path = Path(__file__).with_name("test-logs.json")
    payload = json.loads(data_path.read_text(encoding="utf-8"))
    failures = []
    counts = {"alert": 0, "no_alert": 0, "expected_false_positive": 0}
    results = []
    for case in payload["cases"]:
        reasons = detect(case["events"])
        actual_alert = bool(reasons)
        if actual_alert:
            counts["alert"] += 1
        else:
            counts["no_alert"] += 1
        if case["classification"] == "expected_false_positive" and actual_alert:
            counts["expected_false_positive"] += 1
        passed = actual_alert == case["expected_alert"]
        if not passed:
            failures.append(case["id"])
        results.append({"id": case["id"], "passed": passed, "alert": actual_alert, "reasons": reasons})
    assert len(payload["cases"]) == 10
    assert counts == {"alert": 6, "no_alert": 4, "expected_false_positive": 1}
    assert not failures, f"failed cases: {failures}"
    print(json.dumps({"status": "passed", "technique_id": payload["technique_id"], "counts": counts, "cases": results}, sort_keys=True))


if __name__ == "__main__":
    main()
