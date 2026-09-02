#!/usr/bin/env python3
"""Deterministic tests for the canonical SAF-T1004 detection rule."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
ACTIONS = {"configure", "connect", "install", "resolve"}
BAD_BINDINGS = {"failed", "skipped", "unknown"}


def canonical(value: str) -> str:
    return " ".join(value.casefold().split())


def endpoint_host(uri: str) -> str:
    return (urlparse(uri).hostname or "").casefold()


def identity_tuple(event: dict) -> tuple[str, str, str, str]:
    return (
        event.get("server_name", ""),
        event.get("registry_url", ""),
        event.get("package_identifier", ""),
        endpoint_host(event.get("endpoint_uri", "")),
    )


def approved_tuple(approved: dict) -> tuple[str, str, str, str]:
    return (
        approved.get("server_name", ""),
        approved.get("registry_url", ""),
        approved.get("package_identifier", ""),
        approved.get("endpoint_host", "").casefold(),
    )


def evaluate(event: dict) -> list[str]:
    if event.get("action") not in ACTIONS:
        return []

    reasons: list[str] = []
    if (
        event.get("publisher_namespace_verified") is not True
        or event.get("package_binding_status") in BAD_BINDINGS
    ):
        reasons.append("unverified_binding")

    approved = event.get("approved_identity") or {}
    if (
        canonical(event.get("alias", "")) == canonical(approved.get("alias", ""))
        and identity_tuple(event) != approved_tuple(approved)
    ):
        reasons.append("approved_alias_tuple_mismatch")

    if event.get("tls_identity_status") == "mismatch":
        reasons.append("tls_identity_mismatch")
    return reasons


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-results", action="store_true")
    args = parser.parse_args()
    cases = json.loads((ROOT / "fixtures" / "detection-events.json").read_text())
    results = []
    failures = []
    for case in cases:
        actual = evaluate(case["event"])
        expected = case["expected_reasons"]
        passed = actual == expected and bool(actual) is case["expected_alert"]
        result = {
            "case_id": case["case_id"],
            "expected_alert": case["expected_alert"],
            "actual_alert": bool(actual),
            "expected_reasons": expected,
            "actual_reasons": actual,
            "passed": passed,
        }
        if case.get("expected_false_positive"):
            result["expected_false_positive"] = True
        results.append(result)
        if not passed:
            failures.append(case["case_id"])

    output = {
        "technique_id": "SAF-T1004",
        "rule_id": "a69cd1e5-b4ea-5eb9-be7a-186912acc2af",
        "fixture_count": len(cases),
        "passed": not failures,
        "failed_cases": failures,
        "results": results,
    }
    if args.write_results:
        (ROOT / "test-results.json").write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n"
        )
        (ROOT / "test-log.jsonl").write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in results)
        )
    print(json.dumps(output, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
