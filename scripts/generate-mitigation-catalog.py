#!/usr/bin/env python3
"""Generate the mitigation catalog from the mitigation documents on disk."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


BEGIN = "<!-- BEGIN GENERATED SAF MITIGATION CATALOG -->"
END = "<!-- END GENERATED SAF MITIGATION CATALOG -->"
TITLE = re.compile(r"^# (SAF-M-(\d+)):\s+(.+)$")


def collect(root: Path) -> list[tuple[int, str, str, str]]:
    records: list[tuple[int, str, str, str]] = []
    for path in (root / "mitigations").glob("SAF-M-*/README.md"):
        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        match = TITLE.fullmatch(first_line)
        if not match:
            raise ValueError(f"{path.relative_to(root)} has an invalid title")
        mitigation_id, number, name = match.groups()
        if path.parent.name != mitigation_id:
            raise ValueError(f"{path.relative_to(root)} title and directory ID differ")
        records.append((int(number), mitigation_id, name.strip(), path.relative_to(root).as_posix()))
    return sorted(records)


def build(root: Path) -> str:
    records = collect(root)
    lines = [
        BEGIN,
        "## Mitigation Catalog",
        "",
        "This generated inventory lists the mitigation documents that exist in the repository. "
        "It does not independently validate the effectiveness claims within those documents.",
        "",
        "| Mitigation ID | Document title |",
        "| --- | --- |",
    ]
    for _, mitigation_id, name, path in records:
        lines.append(f"| [{mitigation_id}]({path}) | {name.replace('|', '&#124;')} |")
    lines.extend(
        [
            "",
            f"**Total mitigation documents:** {len(records)}",
            END,
            "",
            "",
        ]
    )
    return "\n".join(lines)


def replace(document: str, generated: str) -> str:
    if BEGIN in document and END in document:
        before, rest = document.split(BEGIN, 1)
        _, after = rest.split(END, 1)
        return before + generated.rstrip("\n") + "\n\n" + after.lstrip("\n")
    start = document.index("## Mitigation Overview")
    end = document.index("## Implementation Guidance")
    return document[:start] + generated + document[end:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output_path = root / "MITIGATIONS.md"
    current = output_path.read_text(encoding="utf-8")
    generated = replace(current, build(root))
    if args.check:
        if generated != current:
            raise SystemExit("mitigation catalog is stale; run scripts/generate-mitigation-catalog.py")
        print("PASS: mitigation catalog is current")
        return 0
    output_path.write_text(generated, encoding="utf-8")
    print("Updated MITIGATIONS.md from mitigation documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
