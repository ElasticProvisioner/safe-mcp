#!/usr/bin/env python3
"""Isolated validator that never reads repository target or shared registry files."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TECH = ROOT / "techniques" / "SAF-T1002"
PACKET = ROOT / "research" / "techniques" / "SAF-T1002"
TRACE = re.compile(r"<!-- SAF-TRACE: claims=([^;]+); sources=([^ ]+) -->")
REQUIRED_NEGATIVES = ('-"SAF-T1002"', '-"SAFE-T1002"', '-"SAF-MCP"', '-"SAFE-MCP"')


def load_yaml(path: Path):
    command = [
        "ruby",
        "-ryaml",
        "-rjson",
        "-e",
        "puts JSON.generate(YAML.load(File.read(ARGV[0])))",
        str(path),
    ]
    return json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)


def main() -> int:
    checks = []

    def check(name: str, condition: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(condition), "detail": detail})

    required = [
        TECH / "README.md",
        TECH / "detection-rule.yml",
        TECH / "tests" / "test_detection_rule.py",
        TECH / "tests" / "fixtures" / "cases.json",
        TECH / "tests" / "results" / "detection-test-results.json",
        TECH / "tests" / "logs" / "test-run.log",
        PACKET / "technique-contract.yml",
        PACKET / "claim-inventory.yml",
        PACKET / "source-coverage.yml",
        PACKET / "publication-rights.yml",
        PACKET / "quality-review.yml",
        PACKET / "traceability-ledger.yml",
        PACKET / "clean-room-attestation.yml",
        ROOT / "source-manifest-fragment.yml",
        ROOT / "framework-fragment.yml",
        ROOT / "integration-notes.yml",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    check("required_files", not missing, f"missing={missing}")

    yaml_paths = [path for path in required if path.suffix in {".yml", ".yaml"} and path.is_file()]
    yaml_errors = []
    documents = {}
    for path in yaml_paths:
        try:
            documents[path] = load_yaml(path)
        except Exception as exc:  # pragma: no cover - diagnostic path
            yaml_errors.append(f"{path.relative_to(ROOT)}: {exc}")
    check("yaml_syntax", not yaml_errors, f"errors={yaml_errors}")

    json_errors = []
    for path in [TECH / "tests" / "fixtures" / "cases.json", TECH / "tests" / "results" / "detection-test-results.json"]:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            json_errors.append(f"{path.relative_to(ROOT)}: {exc}")
    check("json_syntax", not json_errors, f"errors={json_errors}")

    contract = documents.get(PACKET / "technique-contract.yml", {})
    inventory = documents.get(PACKET / "claim-inventory.yml", {})
    coverage = documents.get(PACKET / "source-coverage.yml", {})
    rights = documents.get(PACKET / "publication-rights.yml", {})
    attestation = documents.get(PACKET / "clean-room-attestation.yml", {})
    manifest = documents.get(ROOT / "source-manifest-fragment.yml", {})
    rule = documents.get(TECH / "detection-rule.yml", {})

    id_docs = [contract, inventory, coverage, rights, attestation]
    check(
        "technique_id_consistency",
        all(doc.get("technique_id") == "SAF-T1002" for doc in id_docs),
        "all packet IDs equal SAF-T1002; rule identity is validated by saf.t1002 tag",
    )
    check("trace_format", contract.get("trace_format") == "hidden_html_v1", str(contract.get("trace_format")))

    claim_ids = {item["id"] for item in inventory.get("claims", [])}
    source_ids = {item["id"] for item in manifest.get("sources", [])}
    cited = set(coverage.get("sources_cited", []))
    consulted = set(coverage.get("sources_consulted", []))
    check("claim_count", len(claim_ids) == 21, f"count={len(claim_ids)}")
    check("source_count", len(source_ids) == 22, f"count={len(source_ids)}")
    check("consulted_sources_resolve", consulted <= source_ids, f"unresolved={sorted(consulted - source_ids)}")
    check("cited_sources_resolve", cited <= source_ids, f"unresolved={sorted(cited - source_ids)}")

    claim_source_errors = []
    for claim in inventory.get("claims", []):
        if claim.get("status") != "validated":
            claim_source_errors.append(f"{claim.get('id')}: status={claim.get('status')}")
        for relation in claim.get("sources", []):
            if relation.get("source_id") not in source_ids:
                claim_source_errors.append(f"{claim.get('id')}: unresolved {relation.get('source_id')}")
            if not relation.get("exact_locators"):
                claim_source_errors.append(f"{claim.get('id')}: missing locator")
    check("claim_source_relations", not claim_source_errors, f"errors={claim_source_errors}")

    readme = (TECH / "README.md").read_text(encoding="utf-8")
    trace_errors = []
    traces = TRACE.findall(readme)
    for claim_text, source_text in traces:
        trace_claims = {value.strip() for value in claim_text.split(",")}
        trace_sources = {value.strip() for value in source_text.split(",")}
        if not trace_claims <= claim_ids:
            trace_errors.append(f"unknown claims {sorted(trace_claims - claim_ids)}")
        if not trace_sources <= cited:
            trace_errors.append(f"uncited sources {sorted(trace_sources - cited)}")
    check("readme_trace_resolution", len(traces) >= 35 and not trace_errors, f"trace_count={len(traces)} errors={trace_errors}")
    check("visible_bare_trace_ids_limited", "[SRC-" not in readme and "[SAF-T1002-C" not in readme, "no audit IDs used as citation labels")

    passes = coverage.get("saturation", {}).get("passes", [])
    all_queries = [query for item in passes for query in item.get("queries", [])]
    query_errors = [query for query in all_queries if not all(term in query for term in REQUIRED_NEGATIVES)]
    check("query_count", len(all_queries) == coverage.get("search_controls", {}).get("total_queries") == 53, f"actual={len(all_queries)}")
    check("query_negative_terms", not query_errors, f"nonconforming={len(query_errors)}")
    check(
        "saturation",
        coverage.get("saturation", {}).get("reached") is True
        and coverage.get("saturation", {}).get("consecutive_no_change_passes") >= 2
        and not passes[-1].get("material_changes")
        and not passes[-2].get("material_changes"),
        "two terminal no-change passes",
    )

    rights_ids = {item["source_id"] for item in rights.get("source_uses", [])}
    check("publication_rights", rights.get("review_status") == "passed" and cited <= rights_ids, f"missing={sorted(cited - rights_ids)}")
    check("no_quotations_or_artifacts", rights.get("quotations") == [] and rights.get("third_party_artifacts") == [], "paraphrase-only")

    detection_results = json.loads((TECH / "tests" / "results" / "detection-test-results.json").read_text(encoding="utf-8"))
    kinds = {item["kind"] for item in detection_results.get("cases", [])}
    check("detection_tests", detection_results.get("passed") is True, f"cases={len(detection_results.get('cases', []))}")
    check("detection_test_classes", {"positive", "negative", "boundary", "false_positive"} <= kinds, f"kinds={sorted(kinds)}")
    check("detection_rule_tag", "saf.t1002" in rule.get("tags", []), str(rule.get("tags")))

    check(
        "clean_room_attestation",
        attestation.get("generation_mode") == "clean_room"
        and attestation.get("status") == "passed"
        and attestation.get("generator", {}).get("type") == "fresh_agent"
        and attestation.get("generator", {}).get("inherited_context") is False
        and attestation.get("prior_artifact_access", {}).get("detected") is False
        and attestation.get("prohibited_result_exposure", {}).get("detected") is False
        and attestation.get("draft_frozen_before_integration") is True,
        f"status={attestation.get('status')} frozen={attestation.get('draft_frozen_before_integration')}",
    )

    payload = {
        "technique_id": "SAF-T1002",
        "scope": "isolated_bundle_only",
        "repository_target_or_shared_registry_accessed": False,
        "passed": all(item["passed"] for item in checks),
        "checks": checks,
    }
    result_path = ROOT / "validation" / "validation-results.json"
    result_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
