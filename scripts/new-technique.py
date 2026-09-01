#!/usr/bin/env python3
"""Create a SAF technique and its research packet from the canonical templates."""

from __future__ import annotations

import argparse
import re
import sys
import uuid
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover - depends on contributor environment
    raise SystemExit("PyYAML is required: python3 -m pip install PyYAML") from exc


TECHNIQUE_ID = re.compile(r"SAF-T[1-9][0-9]{3}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scaffold a publishable SAF technique and evidence packet."
    )
    parser.add_argument("technique_id", help="Canonical ID, for example SAF-T1234")
    parser.add_argument("name", help="Human-readable technique name")
    return parser.parse_args()


def render(text: str, technique_id: str, name: str, today: str) -> str:
    return (
        text.replace("__TECHNIQUE_ID__", technique_id)
        .replace("__TECHNIQUE_ID_LOWER__", technique_id.lower().replace("-", "."))
        .replace("__TECHNIQUE_NAME__", name)
        .replace("__DATE__", today)
    )


def main() -> int:
    args = parse_args()
    technique_id = args.technique_id.strip().upper()
    name = args.name.strip()
    if not TECHNIQUE_ID.fullmatch(technique_id):
        raise SystemExit("technique_id must use the form SAF-T1234")
    if not name or "\n" in name:
        raise SystemExit("name must be a non-empty single line")

    root = Path(__file__).resolve().parents[1]
    technique_dir = root / "techniques" / technique_id
    packet_dir = root / "research" / "techniques" / technique_id
    if technique_dir.exists() or packet_dir.exists():
        raise SystemExit(f"refusing to overwrite existing files for {technique_id}")

    model_path = root / "research" / "framework-model.yml"
    model = yaml.safe_load(model_path.read_text(encoding="utf-8")) or {}
    records = model.setdefault("techniques", [])
    if any(record.get("technique_id") == technique_id for record in records):
        raise SystemExit(f"{technique_id} already exists in {model_path}")

    today = date.today().isoformat()
    readme = (root / "techniques" / "TEMPLATE.md").read_text(encoding="utf-8")
    readme = readme.replace(
        "# SAF-T[XXXX]: [Technique Name]", f"# {technique_id}: {name}", 1
    )
    readme = readme.replace(
        "- **Technique ID**: SAF-T[XXXX]", f"- **Technique ID**: {technique_id}", 1
    )
    readme = readme.replace(
        "[research/techniques/SAF-TXXXX](../../research/techniques/SAF-TXXXX/)",
        f"[research/techniques/{technique_id}]"
        f"(../../research/techniques/{technique_id}/)",
        1,
    )
    readme = readme.replace(
        "[traceability-ledger.yml]"
        "(../../research/techniques/SAF-TXXXX/traceability-ledger.yml)",
        f"[traceability-ledger.yml]"
        f"(../../research/techniques/{technique_id}/traceability-ledger.yml)",
        1,
    )
    readme = readme.replace(
        "- **Last Updated**: [YYYY-MM-DD]", f"- **Last Updated**: {today}", 1
    )
    readme = readme.replace("SAF-T[XXXX]-C001", f"{technique_id}-C001", 1)

    rule_template = (root / "techniques" / "DETECTION-RULE-TEMPLATE.yml").read_text(
        encoding="utf-8"
    )
    rule = render(rule_template, technique_id, name, today).replace(
        "00000000-0000-0000-0000-000000000000", str(uuid.uuid4()), 1
    )

    packet_template_dir = root / "research" / "templates" / "technique"
    packet_files = {
        source.name: render(
            source.read_text(encoding="utf-8"), technique_id, name, today
        )
        for source in sorted(packet_template_dir.iterdir())
        if source.is_file()
    }

    technique_dir.mkdir(parents=True)
    packet_dir.mkdir(parents=True)
    (technique_dir / "README.md").write_text(readme, encoding="utf-8")
    (technique_dir / "detection-rule.yml").write_text(rule, encoding="utf-8")
    for filename, content in packet_files.items():
        (packet_dir / filename).write_text(content, encoding="utf-8")

    records.append(
        {
            "technique_id": technique_id,
            "name": name,
            "documentation_status": "draft",
            "evidence_status": "hypothesized",
            "tactics": ["ATK-TAXXXX"],
            "technique_path": f"techniques/{technique_id}/README.md",
            "research_packet": f"research/techniques/{technique_id}",
            "related_techniques": [],
            "mitigations": [],
            "detection": {
                "rule": f"techniques/{technique_id}/detection-rule.yml",
                "test_status": "pending",
                "test_artifacts": [],
            },
        }
    )
    model_path.write_text(
        yaml.safe_dump(model, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )

    print(f"Created {technique_dir.relative_to(root)}")
    print(f"Created {packet_dir.relative_to(root)}")
    print(f"Registered {technique_id} in research/framework-model.yml")
    print("Next: write the contract and claim inventory before drafting the README.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
