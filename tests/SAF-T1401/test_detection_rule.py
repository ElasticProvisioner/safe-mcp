#!/usr/bin/env python3
"""Deterministic checks for the SAF-T1401 example analytic."""

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "techniques" / "SAF-T1401" / "detection-rule.yml"
FIXTURE_PATH = Path(__file__).with_name("test-logs.json")


def dotted(event: dict[str, Any], field: str) -> Any:
    value: Any = event
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def matches(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    return all(dotted(event, field) == expected for field, expected in selection.items())


SELECTIONS = {
    "selection_collision": {"action": "register", "collision": True, "disambiguated": False, "outcome": "success"},
    "selection_unauthorized_global_mutation": {"action": "mutate", "object.scope": "global", "actor.is_admin": False, "outcome": "success"},
    "selection_untrusted_winner": {"action": "resolve", "collision": True, "winner.trust": "untrusted", "competitor.trust": "trusted", "outcome": "success"},
}
APPROVED_FILTER = {"change.approved": True}


def detect(event: Any) -> bool:
    if not isinstance(event, dict):
        return False
    selected = any(matches(event, criteria) for criteria in SELECTIONS.values())
    approved = matches(event, APPROVED_FILTER)
    return selected and not approved


def main() -> int:
    rule_text = RULE_PATH.read_text(encoding="utf-8")
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert "condition: 1 of selection_* and not filter_approved_change" in rule_text
    assert "  - saf.t1401" in rule_text
    for name in [*SELECTIONS, "filter_approved_change"]:
        assert f"  {name}:" in rule_text
    failures: list[str] = []
    for fixture in fixtures:
        actual = detect(fixture.get("event"))
        if actual is not fixture["expected"]:
            failures.append(f"{fixture['name']}: expected {fixture['expected']}, got {actual}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    classes = {name: sum(item["class"] == name for item in fixtures) for name in {item["class"] for item in fixtures}}
    assert classes == {"positive": 3, "negative_or_boundary": 4, "malformed": 1, "expected_false_positive": 1}
    print("PASS 9 cases: 3 positive, 4 negative/boundary, 1 malformed, 1 expected-false-positive")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
