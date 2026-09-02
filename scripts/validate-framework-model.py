#!/usr/bin/env python3
"""Validate SAF Framework Model v2 and its repository projections."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

import yaml


TECHNIQUE_ID = re.compile(r"^SAF-T\d{4}$")
TITLE = re.compile(r"^# (SAF-T\d{4}): (.+)$", re.MULTILINE)
LABELED_TECHNIQUE_LINK = re.compile(r"\[(SAF-T\d{4}): ([^\]]+)\]\([^)]+\)")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


def normalize_status(value: str) -> str:
    return value.strip().lower().replace(" ", "_")


def load_yaml(path: Path, errors: list[str]) -> dict:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - diagnostic boundary
        errors.append(f"{path}: invalid YAML: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{path}: expected a mapping")
        return {}
    return value


def unique_by_id(records: object, key: str, label: str, errors: list[str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    if not isinstance(records, list):
        errors.append(f"framework model: {label} must be a list")
        return result
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not record.get(key):
            errors.append(f"framework model: {label}[{index}] requires {key}")
            continue
        identifier = record[key]
        if identifier in result:
            errors.append(f"framework model: duplicate {label} ID {identifier}")
        result[identifier] = record
    return result


def validate_local_links(path: Path, root: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for raw_target in MARKDOWN_LINK.findall(text):
        target = raw_target.strip().split(" ", 1)[0].strip("<>")
        if not target or target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = unquote(target.split("#", 1)[0])
        if not target:
            continue
        resolved = root / target.lstrip("/") if target.startswith("/") else path.parent / target
        if not resolved.resolve().exists():
            errors.append(f"{path.relative_to(root)}: broken local link {raw_target}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    model = load_yaml(root / "research/framework-model.yml", errors)
    if model.get("version") != 2:
        errors.append("framework model: version must be 2")
    framework = model.get("framework") or {}
    if framework.get("name") != "Secure Agentic Framework" or framework.get("short_name") != "SAF":
        errors.append("framework model: canonical framework name must be Secure Agentic Framework (SAF)")
    if framework.get("technique_ids_are_opaque") is not True:
        errors.append("framework model: technique IDs must be declared opaque")
    if model.get("release_gates") != ["evidence", "taxonomy", "operational"]:
        errors.append("framework model: release_gates must be evidence, taxonomy, operational")

    tactics = unique_by_id(model.get("tactics"), "id", "tactic", errors)
    profiles = unique_by_id(model.get("profiles"), "id", "profile", errors)
    relationship_types = unique_by_id(
        model.get("relationship_types"), "id", "relationship type", errors
    )
    techniques = unique_by_id(model.get("techniques"), "technique_id", "technique", errors)
    allowed_lifecycle = set((model.get("statuses") or {}).get("lifecycle") or [])
    allowed_documentation = set((model.get("statuses") or {}).get("documentation") or [])
    allowed_evidence = set((model.get("statuses") or {}).get("evidence") or [])
    allowed_detection = set(model.get("detection_validation_levels") or [])

    active_names: dict[str, str] = {}
    edges: set[tuple[str, str, str]] = set()
    for technique_id, record in techniques.items():
        prefix = f"framework model: {technique_id}"
        if not TECHNIQUE_ID.fullmatch(technique_id):
            errors.append(f"{prefix}: invalid permanent ID format")
        name = record.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{prefix}: name is required")
        if record.get("lifecycle_status") == "active" and name in active_names:
            errors.append(f"{prefix}: active name duplicates {active_names[name]}: {name}")
        elif record.get("lifecycle_status") == "active":
            active_names[name] = technique_id
        if record.get("lifecycle_status") not in allowed_lifecycle:
            errors.append(f"{prefix}: invalid lifecycle_status")
        if record.get("documentation_status") not in allowed_documentation:
            errors.append(f"{prefix}: invalid documentation_status")
        if record.get("evidence_status") not in allowed_evidence:
            errors.append(f"{prefix}: invalid evidence_status")
        if not record.get("summary"):
            errors.append(f"{prefix}: summary is required")

        record_profiles = record.get("profiles") or []
        if not record_profiles:
            errors.append(f"{prefix}: at least one framework profile is required")
        for profile in record_profiles:
            if profile not in profiles:
                errors.append(f"{prefix}: unknown profile {profile}")
        record_tactics = record.get("tactics") or []
        if not record_tactics:
            errors.append(f"{prefix}: at least one tactic is required")
        for tactic in record_tactics:
            if tactic not in tactics:
                errors.append(f"{prefix}: unknown tactic {tactic}")

        readme_path = root / str(record.get("technique_path", ""))
        contract_path = root / str(record.get("research_packet", "")) / "technique-contract.yml"
        if not readme_path.is_file():
            errors.append(f"{prefix}: missing technique_path {record.get('technique_path')}")
        else:
            readme = readme_path.read_text(encoding="utf-8")
            title = TITLE.search(readme)
            if not title or title.group(1) != technique_id or title.group(2) != name:
                errors.append(f"{prefix}: README title does not match canonical ID and name")
            documentation = re.search(r"^- \*\*Documentation Status\*\*: ([^\n]+)$", readme, re.MULTILINE)
            evidence = re.search(r"^- \*\*Evidence Status\*\*: ([^\n]+)$", readme, re.MULTILINE)
            if not documentation or normalize_status(documentation.group(1)) != record.get("documentation_status"):
                errors.append(f"{prefix}: README documentation status differs")
            if not evidence or normalize_status(evidence.group(1)).replace("_", "-") != record.get("evidence_status"):
                errors.append(f"{prefix}: README evidence status differs")
            forbidden = ("synthetic neighbor", "pending mechanical", "proposed neighbor")
            for phrase in forbidden:
                if phrase in readme.lower():
                    errors.append(f"{prefix}: publishable README contains internal marker {phrase!r}")
            for linked_id, linked_name in LABELED_TECHNIQUE_LINK.findall(readme):
                if linked_id in techniques and linked_name != techniques[linked_id]["name"]:
                    errors.append(
                        f"{prefix}: link label for {linked_id} is {linked_name!r}, expected {techniques[linked_id]['name']!r}"
                    )

        if not contract_path.is_file():
            errors.append(f"{prefix}: missing technique contract")
        else:
            contract = load_yaml(contract_path, errors)
            if contract.get("technique_id") != technique_id or contract.get("name") != name:
                errors.append(f"{prefix}: technique contract ID or name differs")
            if contract.get("tactics") != record_tactics:
                errors.append(f"{prefix}: technique contract tactics differ")

        relationships = record.get("relationships") or []
        seen_relationships: set[tuple[str, str]] = set()
        for relationship in relationships:
            if not isinstance(relationship, dict):
                errors.append(f"{prefix}: relationship must be a mapping")
                continue
            target = relationship.get("target")
            relation = relationship.get("type")
            if target == technique_id:
                errors.append(f"{prefix}: self relationship is not allowed")
            if target not in techniques:
                errors.append(f"{prefix}: unknown relationship target {target}")
            if relation not in relationship_types:
                errors.append(f"{prefix}: unknown relationship type {relation}")
            if (target, relation) in seen_relationships:
                errors.append(f"{prefix}: duplicate {relation} relationship to {target}")
            seen_relationships.add((target, relation))
            edges.add((technique_id, target, relation))

        for mitigation in record.get("mitigations") or []:
            if not (root / "mitigations" / mitigation / "README.md").is_file():
                errors.append(f"{prefix}: unknown mitigation {mitigation}")
        detection = record.get("detection") or {}
        level = detection.get("validation_level")
        if level not in allowed_detection:
            errors.append(f"{prefix}: invalid detection validation_level {level}")
        rule = root / str(detection.get("rule", ""))
        if not rule.is_file():
            errors.append(f"{prefix}: detection rule is missing")
        artifacts = detection.get("test_artifacts") or []
        if level in {"fixture_tested", "telemetry_replay_tested", "field_evaluated"}:
            if detection.get("test_status") != "passed" or not artifacts:
                errors.append(f"{prefix}: {level} detection requires passed test artifacts")
        for artifact in artifacts:
            if not (root / artifact).is_file():
                errors.append(f"{prefix}: missing detection test artifact {artifact}")

        replacements = record.get("replaced_by") or []
        if record.get("lifecycle_status") == "deprecated":
            if record.get("documentation_status") != "deprecated" or not replacements or not record.get("deprecation"):
                errors.append(f"{prefix}: deprecated records require documentation status, replacements, and rationale")
            for replacement in replacements:
                if replacement not in techniques or techniques[replacement].get("lifecycle_status") != "active":
                    errors.append(f"{prefix}: replacement {replacement} is not active")
                if (replacement, "replaced_by") not in seen_relationships:
                    errors.append(f"{prefix}: replacement {replacement} lacks replaced_by relationship")
        elif replacements or record.get("deprecation"):
            errors.append(f"{prefix}: active records cannot carry deprecation metadata")

    for source, target, relation in edges:
        relation_record = relationship_types.get(relation, {})
        inverse = relation if relation_record.get("symmetric") else relation_record.get("inverse")
        if not inverse or (target, source, inverse) not in edges:
            errors.append(f"framework model: {source} {relation} {target} lacks inverse {inverse}")

    taxonomy = load_yaml(root / "research/taxonomy-review.yml", errors)
    if taxonomy.get("status") != "implemented" or taxonomy.get("unresolved"):
        errors.append("taxonomy review: must be implemented with no unresolved decisions")
    for decision in taxonomy.get("decisions") or []:
        canonical = decision.get("canonical")
        if canonical and decision.get("canonical_name") != techniques.get(canonical, {}).get("name"):
            errors.append(f"taxonomy review: {decision.get('id')} canonical name differs")
        for deprecated in decision.get("deprecated") or []:
            if techniques.get(deprecated, {}).get("lifecycle_status") != "deprecated":
                errors.append(f"taxonomy review: {deprecated} is not deprecated in the model")
        technique = decision.get("technique")
        if technique and decision.get("profiles") and techniques.get(technique, {}).get("profiles") != decision["profiles"]:
            errors.append(f"taxonomy review: {technique} profile decision differs")
        if decision.get("type") == "profile_reconciliation":
            active_records = [
                item for item in techniques.values() if item.get("lifecycle_status") == "active"
            ]
            actual_core = sum("core" in (item.get("profiles") or []) for item in active_records)
            actual_mcp = sum("mcp" in (item.get("profiles") or []) for item in active_records)
            if decision.get("saf_core_count") != actual_core:
                errors.append("taxonomy review: SAF Core reconciliation count differs")
            if decision.get("mcp_profile_count") != actual_mcp:
                errors.append("taxonomy review: MCP profile reconciliation count differs")

    validate_local_links(root / "README.md", root, errors)
    for path in sorted((root / "techniques").glob("SAF-T*/README.md")):
        validate_local_links(path, root, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"FAIL: {len(errors)} framework validation error(s)")
        return 1
    print(
        f"PASS: Framework Model v2 ({len(techniques)} registered IDs; "
        f"{sum(1 for item in techniques.values() if item['lifecycle_status'] == 'active')} active)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
