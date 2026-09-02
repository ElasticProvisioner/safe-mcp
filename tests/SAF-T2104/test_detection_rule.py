#!/usr/bin/env python3
"""Deterministic inert fixture test for SAF-T2104."""
from __future__ import annotations
import json
import unicodedata
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

FINANCIAL_ACTIONS = {"payment.initiate", "purchase.commit", "refund.issue", "sale.commit", "trade.submit", "transfer.submit"}
BOUND_FIELDS = ("tool_name", "action", "amount", "currency", "destination")

def normalize_text(value: object) -> str:
    return unicodedata.normalize("NFKC", str(value)).casefold().strip()

def normalize_amount(value: object) -> Decimal:
    return Decimal(str(value)).normalize()

def parse_time(value: object) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))

def detect(event: dict[str, object]) -> tuple[bool, list[str]]:
    try:
        action = normalize_text(event["action"])
    except (KeyError, TypeError):
        return True, ["malformed_event"]
    if action not in FINANCIAL_ACTIONS:
        return False, []
    required = ("timestamp", "tool_name", "amount", "currency", "destination")
    if any(field not in event or event[field] in (None, "") for field in required):
        return True, ["malformed_event"]
    try:
        event_time = parse_time(event["timestamp"])
        normalize_amount(event["amount"])
    except (ValueError, TypeError, InvalidOperation):
        return True, ["malformed_event"]
    approval = event.get("approval")
    if not isinstance(approval, dict):
        return True, ["approval_missing"]
    if normalize_text(approval.get("state", "")) != "approved":
        return True, ["approval_not_approved"]
    try:
        issued = parse_time(approval["issued_at"])
        expires = parse_time(approval["expires_at"])
    except (KeyError, ValueError, TypeError):
        return True, ["malformed_event"]
    if not issued <= event_time <= expires:
        return True, ["approval_time_invalid"]
    mismatches: list[str] = []
    for field in BOUND_FIELDS:
        if field not in approval:
            return True, ["malformed_event"]
        try:
            actual = normalize_amount(event[field]) if field == "amount" else normalize_text(event[field])
            allowed = normalize_amount(approval[field]) if field == "amount" else normalize_text(approval[field])
        except (InvalidOperation, TypeError):
            return True, ["malformed_event"]
        if actual != allowed:
            mismatches.append(field)
    return bool(mismatches), ["binding_mismatch"] if mismatches else []

def main() -> None:
    fixtures = json.loads(Path(__file__).with_name("fixtures.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    class_counts: dict[str, int] = {}
    for fixture in fixtures:
        matched, reasons = detect(fixture["event"])
        class_counts[fixture["class"]] = class_counts.get(fixture["class"], 0) + 1
        if matched is not fixture["expected"]:
            failures.append(f"{fixture['name']}: expected={fixture['expected']} actual={matched} reasons={reasons}")
    if failures:
        raise SystemExit("FAIL\n" + "\n".join(failures))
    print(f"PASS: {len(fixtures)} fixtures")
    for name in sorted(class_counts):
        print(f"{name}: {class_counts[name]}")

if __name__ == "__main__":
    main()
