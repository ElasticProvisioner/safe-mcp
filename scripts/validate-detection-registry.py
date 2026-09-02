#!/usr/bin/env python3
"""Validate the SAF detection coverage registry and external mappings."""

from __future__ import annotations

from datetime import date
from pathlib import Path
import sys
from urllib.parse import urlparse

import yaml


RELATIONSHIPS = {"direct", "partial", "adjacent"}
MODALITIES = {
    "content",
    "static",
    "runtime",
    "gateway",
    "endpoint",
    "identity",
    "network",
    "memory",
    "multimodal",
    "model-lifecycle",
    "on-chain",
}
MAPPING_STATUSES = {"candidate", "validated", "retired"}
CANDIDATE_SOURCE_STATUSES = {"pending_reconciliation", "ready"}


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


def valid_https_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def valid_date(value: object) -> bool:
    try:
        date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return False
    return len(str(value)) == 10


def validate_modalities(value: object, prefix: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{prefix}: modalities must be a non-empty list")
        return
    if len(value) != len(set(value)):
        errors.append(f"{prefix}: modalities must not contain duplicates")
    unknown = sorted(set(value) - MODALITIES)
    if unknown:
        errors.append(f"{prefix}: unknown modalities {', '.join(unknown)}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []

    model_path = root / "research/framework-model.yml"
    registry_path = root / "detections/registry.yml"
    mappings_path = root / "detections/external-mappings.yml"
    model = load_yaml(model_path, errors)
    registry = load_yaml(registry_path, errors)
    mappings_document = load_yaml(mappings_path, errors)

    if registry.get("version") != 1:
        errors.append("detection registry: version must be 1")
    if registry.get("framework_model") != "research/framework-model.yml":
        errors.append("detection registry: framework_model path differs")
    if registry.get("generated_matrix") != "detections/COVERAGE.md":
        errors.append("detection registry: generated_matrix path differs")

    records = model.get("techniques") or []
    model_by_id = {
        item.get("technique_id"): item
        for item in records
        if isinstance(item, dict) and item.get("technique_id")
    }
    active_ids = {
        identifier
        for identifier, item in model_by_id.items()
        if item.get("lifecycle_status") == "active"
    }
    technique_mappings = registry.get("techniques")
    if not isinstance(technique_mappings, dict):
        errors.append("detection registry: techniques must be a mapping")
        technique_mappings = {}

    registered_ids = set(technique_mappings)
    for identifier in sorted(active_ids - registered_ids):
        errors.append(f"detection registry: active technique {identifier} is missing")
    for identifier in sorted(registered_ids - active_ids):
        errors.append(f"detection registry: {identifier} is not an active technique")

    native = registry.get("native_mapping") or {}
    default_relationship = native.get("default_relationship")
    if default_relationship not in RELATIONSHIPS:
        errors.append("detection registry: invalid native default_relationship")

    for identifier, mapping in technique_mappings.items():
        prefix = f"detection registry: {identifier}"
        if not isinstance(mapping, dict):
            errors.append(f"{prefix}: entry must be a mapping")
            continue
        relationship = mapping.get("relationship", default_relationship)
        if relationship not in RELATIONSHIPS:
            errors.append(f"{prefix}: invalid relationship {relationship}")
        validate_modalities(mapping.get("modalities"), prefix, errors)

        model_record = model_by_id.get(identifier) or {}
        detection = model_record.get("detection") or {}
        rule = detection.get("rule")
        if not rule or not (root / str(rule)).is_file():
            errors.append(f"{prefix}: canonical native rule is missing")
        for artifact in detection.get("test_artifacts") or []:
            if not (root / str(artifact)).is_file():
                errors.append(f"{prefix}: canonical test artifact is missing: {artifact}")

    providers: dict[str, dict] = {}
    provider_dir = root / "detections/providers"
    for path in sorted(provider_dir.glob("*.yml")):
        provider = load_yaml(path, errors)
        prefix = f"provider {path.name}"
        if provider.get("version") != 1:
            errors.append(f"{prefix}: version must be 1")
        identifier = provider.get("provider_id")
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"{prefix}: provider_id is required")
            continue
        if identifier in providers:
            errors.append(f"{prefix}: duplicate provider_id {identifier}")
        providers[identifier] = provider
        if not provider.get("name") or not provider.get("maintainer"):
            errors.append(f"{prefix}: name and maintainer are required")
        if not valid_https_url(provider.get("repository")):
            errors.append(f"{prefix}: repository must be an HTTPS URL")
        license_record = provider.get("license") or {}
        if not license_record.get("spdx") or not valid_https_url(license_record.get("url")):
            errors.append(f"{prefix}: license SPDX identifier and HTTPS URL are required")
        source = provider.get("candidate_source")
        if source is not None:
            if not isinstance(source, dict):
                errors.append(f"{prefix}: candidate_source must be a mapping")
            else:
                if not valid_https_url(source.get("mapping_url")):
                    errors.append(f"{prefix}: candidate mapping_url must be an HTTPS URL")
                if source.get("status") not in CANDIDATE_SOURCE_STATUSES:
                    errors.append(f"{prefix}: invalid candidate source status")
                if not valid_date(source.get("reviewed_on")):
                    errors.append(f"{prefix}: candidate source reviewed_on must be YYYY-MM-DD")
                if not source.get("exclusion_reason"):
                    errors.append(f"{prefix}: candidate source exclusion_reason is required")

    if mappings_document.get("version") != 1:
        errors.append("external mappings: version must be 1")
    external_mappings = mappings_document.get("mappings")
    if not isinstance(external_mappings, list):
        errors.append("external mappings: mappings must be a list")
        external_mappings = []

    seen_mapping_ids: set[str] = set()
    seen_rule_targets: set[tuple[str, str, str]] = set()
    for index, mapping in enumerate(external_mappings):
        prefix = f"external mappings: entry {index}"
        if not isinstance(mapping, dict):
            errors.append(f"{prefix}: must be a mapping")
            continue
        mapping_id = mapping.get("mapping_id")
        if not isinstance(mapping_id, str) or not mapping_id:
            errors.append(f"{prefix}: mapping_id is required")
        elif mapping_id in seen_mapping_ids:
            errors.append(f"{prefix}: duplicate mapping_id {mapping_id}")
        else:
            seen_mapping_ids.add(mapping_id)

        technique_id = mapping.get("technique_id")
        provider_id = mapping.get("provider_id")
        rule_id = mapping.get("rule_id")
        if technique_id not in model_by_id:
            errors.append(f"{prefix}: unknown technique_id {technique_id}")
        if provider_id not in providers:
            errors.append(f"{prefix}: unknown provider_id {provider_id}")
        if not isinstance(rule_id, str) or not rule_id:
            errors.append(f"{prefix}: rule_id is required")
        target = (str(provider_id), str(rule_id), str(technique_id))
        if target in seen_rule_targets:
            errors.append(f"{prefix}: duplicate provider rule and technique target")
        seen_rule_targets.add(target)

        if mapping.get("relationship") not in RELATIONSHIPS:
            errors.append(f"{prefix}: invalid relationship")
        validate_modalities(mapping.get("modalities"), prefix, errors)
        status = mapping.get("status")
        if status not in MAPPING_STATUSES:
            errors.append(f"{prefix}: invalid status {status}")
        if status == "validated" and technique_id not in active_ids:
            errors.append(f"{prefix}: validated mappings require an active technique")
        if not isinstance(mapping.get("rule_version"), str) or not mapping.get("rule_version"):
            errors.append(f"{prefix}: rule_version is required")
        if not valid_https_url(mapping.get("rule_url")):
            errors.append(f"{prefix}: rule_url must be an HTTPS URL")
        if not valid_https_url(mapping.get("evidence_url")):
            errors.append(f"{prefix}: evidence_url must be an HTTPS URL")
        if not valid_date(mapping.get("reviewed_on")):
            errors.append(f"{prefix}: reviewed_on must be YYYY-MM-DD")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"FAIL: {len(errors)} detection registry validation error(s)")
        return 1

    validated = sum(item.get("status") == "validated" for item in external_mappings)
    print(
        f"PASS: detection registry ({len(active_ids)} active native mappings; "
        f"{validated} validated external mappings; {len(providers)} providers)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
