#!/usr/bin/env python3
"""Test harness for the SAF-T1002 Sigma rules.

There are two rules because no single log source carries both package-registry
metadata and endpoint telemetry:
  - detection-rule.yml                 (product: mcp / service: package_manager)
  - detection-rule-host-telemetry.yml  (product: windows / service: sysmon)

Each line in test-logs.json names the rule it targets ("package" or "host"),
the raw event fields, and whether the rule should fire. The evaluator below
implements just enough Sigma semantics to validate these rules: field/value
matching with the |contains, |endswith, |startswith and numeric |lt/|lte/|gt/
|gte modifiers, list values as OR, fields within a selection as AND, and a
condition expression over selection names using and/or/parentheses.
"""

import json
import re
import yaml
from pathlib import Path

HERE = Path(__file__).parent
RULE_FILES = {
    "package": HERE / "detection-rule.yml",
    "host": HERE / "detection-rule-host-telemetry.yml",
}


def match_value(modifier, event_value, rule_value):
    """Match a single event value against a single rule value under a modifier."""
    if modifier in ("lt", "lte", "gt", "gte"):
        try:
            ev, rv = float(event_value), float(rule_value)
        except (TypeError, ValueError):
            return False
        return {
            "lt": ev < rv, "lte": ev <= rv, "gt": ev > rv, "gte": ev >= rv,
        }[modifier]

    if event_value is None:
        return False
    ev, rv = str(event_value), str(rule_value)
    if modifier == "contains":
        return rv in ev
    if modifier == "endswith":
        return ev.endswith(rv)
    if modifier == "startswith":
        return ev.startswith(rv)
    # No modifier: exact match (numbers compared loosely so EventID 3 == "3").
    if isinstance(event_value, (int, float)) or (isinstance(rule_value, (int, float))):
        try:
            return float(event_value) == float(rule_value)
        except (TypeError, ValueError):
            return False
    return ev == rv


def match_field(field_spec, rule_value, event):
    """Match one 'field|modifier: value(s)' entry against the event."""
    if "|" in field_spec:
        field, modifier = field_spec.split("|", 1)
    else:
        field, modifier = field_spec, ""
    event_value = event.get(field)
    values = rule_value if isinstance(rule_value, list) else [rule_value]
    return any(match_value(modifier, event_value, v) for v in values)


def match_selection(selection, event):
    """A selection matches when every field entry matches (AND)."""
    return all(match_field(fs, rv, event) for fs, rv in selection.items())


def eval_condition(condition, selection_results):
    """Evaluate a Sigma condition over selection booleans (and/or/parentheses)."""
    tokens = re.findall(r"\(|\)|\w+", condition)
    allowed = {"and", "or", "(", ")"}
    expr_parts = []
    for tok in tokens:
        if tok in allowed:
            expr_parts.append(tok)
        elif tok in selection_results:
            expr_parts.append(str(selection_results[tok]))
        else:
            raise ValueError(f"Unknown token in condition: {tok!r}")
    return eval(" ".join(expr_parts), {"__builtins__": {}}, {})  # noqa: S307 (sanitized)


def evaluate_rule(rule, event):
    """Return (fired: bool, {selection_name: matched_bool})."""
    detection = rule["detection"]
    condition = detection["condition"]
    selection_results = {
        name: match_selection(sel, event)
        for name, sel in detection.items()
        if name != "condition"
    }
    return eval_condition(condition, selection_results), selection_results


def load_rules():
    return {key: yaml.safe_load(open(path)) for key, path in RULE_FILES.items()}


def main():
    rules = load_rules()
    logs = []
    with open(HERE / "test-logs.json") as f:
        for line in f:
            line = line.strip()
            if line:
                logs.append(json.loads(line))

    print("SAF-T1002 Detection Rule Test Results")
    print("=" * 60)

    total = correct = 0
    coverage = {key: {name: False for name in r["detection"] if name != "condition"}
                for key, r in rules.items()}

    for log in logs:
        rule_key = log["rule"]
        rule = rules[rule_key]
        should_fire = log["should_fire"]
        fired, sel_results = evaluate_rule(rule, log["event"])

        for name, matched in sel_results.items():
            if matched:
                coverage[rule_key][name] = True

        total += 1
        ok = fired == should_fire
        correct += ok
        status = "PASS" if ok else "FAIL"
        matched_sels = [n for n, m in sel_results.items() if m] or ["<none>"]
        print(f"{status} [{rule_key}] {log['name']}: fired={fired} expected={should_fire}")
        print(f"       matched selections: {', '.join(matched_sels)}")

    print("\n" + "=" * 60)
    print(f"Test Summary: {correct}/{total} tests passed ({correct/total*100:.1f}%)")

    print("\n" + "=" * 60)
    print("Selection Coverage:")
    all_covered = True
    for rule_key, sels in coverage.items():
        for name, covered in sels.items():
            status = "PASS" if covered else "FAIL"
            if not covered:
                all_covered = False
            print(f"{status} [{rule_key}] {name} - {'exercised' if covered else 'never matched'}")

    return correct == total and all_covered


if __name__ == "__main__":
    exit(0 if main() else 1)
