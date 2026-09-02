#!/usr/bin/env python3
"""Generate the public SAF technique catalog from Framework Model v2."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import re

import yaml


BEGIN = "<!-- BEGIN GENERATED SAF TECHNIQUE CATALOG -->"
END = "<!-- END GENERATED SAF TECHNIQUE CATALOG -->"


def compact(value: object) -> str:
    return " ".join(str(value or "").split()).replace("|", "\\|")


def catalog_summary(value: object) -> str:
    """Project one readable scope sentence without citation-label debris."""
    summary = compact(value)
    summary = re.sub(r"^-\s+\*\*In scope\*\*:\s*", "", summary)
    summary = summary.split(" - **Out of scope**", 1)[0]
    summary = summary.split(" - ", 1)[0].lstrip("- ")
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", summary, maxsplit=1)
    summary = sentences[0]
    summary = summary.replace("**", "").replace("`", "")
    if len(summary) > 360:
        summary = summary[:357].rsplit(" ", 1)[0] + "..."
    return summary


def build_catalog(model: dict) -> str:
    tactics = model["tactics"]
    profiles = model["profiles"]
    techniques = model["techniques"]
    active = [item for item in techniques if item["lifecycle_status"] == "active"]
    deprecated = [item for item in techniques if item["lifecycle_status"] == "deprecated"]
    tactic_counts = Counter(tactic for item in active for tactic in item["tactics"])
    profile_counts = Counter(profile for item in active for profile in item["profiles"])

    lines = [
        BEGIN,
        "## SAF Tactics",
        "",
        "SAF uses 14 ATT&CK-aligned adversary objectives. The canonical machine-readable catalog is "
        "[`research/framework-model.yml`](research/framework-model.yml); its admission and lifecycle rules are "
        "defined in [Framework Model v2](research/FRAMEWORK-MODEL.md).",
        "",
        "| Tactic ID | Tactic | Active Techniques | Description |",
        "| --- | --- | ---: | --- |",
    ]
    for tactic in tactics:
        lines.append(
            f"| {tactic['id']} | {compact(tactic['name'])} | {tactic_counts[tactic['id']]} | "
            f"{compact(tactic['description'])} |"
        )

    lines.extend(
        [
            "",
            "## SAF Profiles",
            "",
            "Profiles scope an atomic technique without changing its permanent ID. A technique may appear in more than one profile.",
            "",
            "| Profile | Active Techniques | Scope |",
            "| --- | ---: | --- |",
        ]
    )
    for profile in profiles:
        lines.append(
            f"| {compact(profile['name'])} | {profile_counts[profile['id']]} | {compact(profile['description'])} |"
        )

    lines.extend(
        [
            "",
            "## Active Technique Catalog",
            "",
            "Techniques are listed under every applicable tactic; counts therefore represent tactic mappings, not unique IDs.",
            "",
            "| Tactic | Technique | Name | Profiles | Description |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    by_tactic = {tactic["id"]: [] for tactic in tactics}
    for item in active:
        for tactic_id in item["tactics"]:
            by_tactic[tactic_id].append(item)
    profile_names = {profile["id"]: profile["name"] for profile in profiles}
    tactic_names = {tactic["id"]: tactic["name"] for tactic in tactics}
    for tactic in tactics:
        records = sorted(by_tactic[tactic["id"]], key=lambda item: item["technique_id"])
        if not records:
            lines.append(f"| {compact(tactic['name'])} | — | — | — | No active techniques currently admitted. |")
            continue
        for item in records:
            profile_text = ", ".join(profile_names[value] for value in item["profiles"])
            path = item["technique_path"]
            lines.append(
                f"| {compact(tactic_names[tactic['id']])} | [{item['technique_id']}]({path}) | "
                f"{compact(item['name'])} | {compact(profile_text)} | {catalog_summary(item['summary'])} |"
            )

    lines.extend(
        [
            "",
            "## Deprecated Compatibility IDs",
            "",
            "Deprecated IDs remain permanent and navigable for provenance. Use their active replacements for new mappings.",
            "",
            "| Deprecated ID | Historical Name | Replacement |",
            "| --- | --- | --- |",
        ]
    )
    records_by_id = {item["technique_id"]: item for item in techniques}
    for item in sorted(deprecated, key=lambda value: value["technique_id"]):
        replacements = []
        for replacement_id in item.get("replaced_by") or []:
            replacement = records_by_id[replacement_id]
            replacements.append(
                f"[{replacement_id}]({replacement['technique_path']}) — {compact(replacement['name'])}"
            )
        lines.append(
            f"| [{item['technique_id']}]({item['technique_path']}) | {compact(item['name'])} | "
            f"{'<br>'.join(replacements)} |"
        )

    lines.extend(
        [
            "",
            "## Catalog Statistics",
            "",
            f"- **Tactics**: {len(tactics)}",
            f"- **Registered technique IDs**: {len(techniques)}",
            f"- **Active techniques**: {len(active)}",
            f"- **Deprecated compatibility IDs**: {len(deprecated)}",
            f"- **Active technique-to-tactic mappings**: {sum(tactic_counts.values())}",
            "",
            "| Tactic | Active Technique Mappings |",
            "| --- | ---: |",
        ]
    )
    for tactic in tactics:
        lines.append(f"| {compact(tactic['name'])} | {tactic_counts[tactic['id']]} |")
    lines.extend([END, ""])
    return "\n".join(lines)


def replace_catalog(readme: str, generated: str) -> str:
    if BEGIN in readme and END in readme:
        before, rest = readme.split(BEGIN, 1)
        _, after = rest.split(END, 1)
        return before + generated.rstrip("\n") + after
    start = readme.index("## SAF-MCP Tactics")
    finish = readme.index("## Usage Guidelines")
    return readme[:start] + generated + "\n" + readme[finish:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    model = yaml.safe_load((root / "research/framework-model.yml").read_text(encoding="utf-8"))
    if model.get("version") != 2:
        raise SystemExit("framework model must use version 2")
    readme_path = root / "README.md"
    current = readme_path.read_text(encoding="utf-8")
    updated = replace_catalog(current, build_catalog(model))
    if args.check:
        if updated != current:
            raise SystemExit("README technique catalog is stale; run scripts/generate-technique-catalog.py")
        print("PASS: README technique catalog is current")
        return 0
    readme_path.write_text(updated, encoding="utf-8")
    print("Updated README.md from research/framework-model.yml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
