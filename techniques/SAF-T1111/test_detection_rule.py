#!/usr/bin/env python3
import json
import ntpath
import posixpath
import sys
from pathlib import Path

AGENTS = {"claude", "codex", "gemini"}
SHELLS = {"bash", "sh", "zsh", "cmd.exe", "powershell.exe", "pwsh"}
MARKERS = {
    "--dangerously-skip-permissions",
    "--dangerously-bypass-approvals-and-sandbox",
    "--yolo",
}


def basename(value):
    text = str(value or "").strip().replace("\\", "/")
    name = posixpath.basename(text).lower()
    return ntpath.basename(name)


def detects(event):
    parent = basename(event.get("parent_process_name"))
    if parent.endswith(".exe"):
        parent = parent[:-4]
    child = basename(event.get("process_name"))
    command = str(event.get("parent_command_line") or "").casefold()
    return parent in AGENTS and child in SHELLS and any(marker in command for marker in MARKERS)


def main():
    data = json.loads(Path(__file__).with_name("test-logs.json").read_text(encoding="utf-8"))
    failures = []
    alerts = 0
    for case in data["cases"]:
        actual = detects(case["event"])
        alerts += int(actual)
        if actual is not case["expected"]:
            failures.append({"name": case["name"], "expected": case["expected"], "actual": actual})
    result = {"cases": len(data["cases"]), "alerts": alerts, "failures": failures, "status": "passed" if not failures else "failed"}
    print(json.dumps(result, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
