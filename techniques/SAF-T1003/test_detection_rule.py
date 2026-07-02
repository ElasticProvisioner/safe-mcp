#!/usr/bin/env python3
"""Test harness for the SAF-T1003 Sigma rules.

Two rules, because no single log source carries both MCP-level events and OS
endpoint telemetry:
  - detection-rule.yml                 (product: mcp / service: server_runtime)
  - detection-rule-host-telemetry.yml  (product: windows / service: sysmon)

Each line in test-logs.json names the rule it targets ("mcp" or "host"), the
raw event fields, and whether the rule should fire. The evaluator implements
just enough Sigma semantics to validate these rules: field/value matching with
|contains, |endswith, |startswith and numeric |lt/|lte/|gt/|gte modifiers,
exact matches (including booleans), list values as OR, fields within a selection
as AND, and a condition expression over selection names using and/or/not/parens.
"""

import json
import re
import yaml
from pathlib import Path

HERE = Path(__file__).parent
RULE_FILES = {
    "mcp": HERE / "detection-rule.yml",
    "host": HERE / "detection-rule-host-telemetry.yml",
}


def match_value(modifier, event_value, rule_value):
    if modifier in ("lt", "lte", "gt", "gte"):
        try:
            ev, rv = float(event_value), float(rule_value)
        except (TypeError, ValueError):
            return False
        return {"lt": ev < rv, "lte": ev <= rv, "gt": ev > rv, "gte": ev >= rv}[modifier]

    if event_value is None:
        return False
    if modifier == "contains":
        return str(rule_value) in str(event_value)
    if modifier == "endswith":
        return str(event_value).endswith(str(rule_value))
    if modifier == "startswith":
        return str(event_value).startswith(str(rule_value))
    # No modifier: exact match. Handle booleans and numbers before strings
    # (bool is a subclass of int, so isinstance covers True/False too).
    if isinstance(event_value, bool) or isinstance(rule_value, bool):
        return bool(event_value) == bool(rule_value)
    if isinstance(event_value, (int, float)) or isinstance(rule_value, (int, float)):
        try:
            return float(event_value) == float(rule_value)
        except (TypeError, ValueError):
            return False
    return str(event_value) == str(rule_value)


def match_field(field_spec, rule_value, event):
    field, modifier = (field_spec.split("|", 1) + [""])[:2]
    event_value = event.get(field)
    values = rule_value if isinstance(rule_value, list) else [rule_value]
    return any(match_value(modifier, event_value, v) for v in values)


def match_selection(selection, event):
    return all(match_field(fs, rv, event) for fs, rv in selection.items())


def eval_condition(condition, selection_results):
    tokens = re.findall(r"\(|\)|\w+", condition)
    allowed = {"and", "or", "not", "(", ")"}
    parts = []
    for tok in tokens:
        if tok in allowed:
            parts.append(tok)
        elif tok in selection_results:
            parts.append(str(selection_results[tok]))
        else:
            raise ValueError(f"Unknown token in condition: {tok!r}")
    return eval(" ".join(parts), {"__builtins__": {}}, {})  # noqa: S307 (sanitized)


def evaluate_rule(rule, event):
    detection = rule["detection"]
    results = {name: match_selection(sel, event)
               for name, sel in detection.items() if name != "condition"}
    return eval_condition(detection["condition"], results), results


def main():
    rules = {k: yaml.safe_load(open(p)) for k, p in RULE_FILES.items()}
    logs = [json.loads(l) for l in open(HERE / "test-logs.json") if l.strip()]

    print("SAF-T1003 Detection Rule Test Results")
    print("=" * 60)

    total = correct = 0
    # Only count real selections (not allowlist filters) toward coverage.
    coverage = {k: {n: False for n in r["detection"]
                    if n != "condition" and not n.startswith("filter_")}
                for k, r in rules.items()}

    for log in logs:
        rule = rules[log["rule"]]
        fired, results = evaluate_rule(rule, log["event"])
        for name, matched in results.items():
            if matched and name in coverage[log["rule"]]:
                coverage[log["rule"]][name] = True
        total += 1
        ok = fired == log["should_fire"]
        correct += ok
        matched = [n for n, m in results.items() if m] or ["<none>"]
        print(f"{'PASS' if ok else 'FAIL'} [{log['rule']}] {log['name']}: "
              f"fired={fired} expected={log['should_fire']}")
        print(f"       matched: {', '.join(matched)}")

    print("\n" + "=" * 60)
    print(f"Test Summary: {correct}/{total} tests passed ({correct/total*100:.1f}%)")

    print("\n" + "=" * 60)
    print("Selection Coverage:")
    all_covered = True
    for rk, sels in coverage.items():
        for name, covered in sels.items():
            all_covered = all_covered and covered
            print(f"{'PASS' if covered else 'FAIL'} [{rk}] {name} - "
                  f"{'exercised' if covered else 'never matched'}")

    return correct == total and all_covered


if __name__ == "__main__":
    exit(0 if main() else 1)
