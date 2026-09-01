#!/usr/bin/env python3
"""Regression tests for the SAF technique research validator."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

import yaml


MODULE_PATH = Path(__file__).with_name("validate-technique-research.py")
SPEC = importlib.util.spec_from_file_location(
    "validate_technique_research", MODULE_PATH
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class TechniqueResearchValidatorTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.technique_id = "SAF-T9999"
        self.packet = self.root / "research" / "techniques" / self.technique_id
        self.technique = self.root / "techniques" / self.technique_id
        self.packet.mkdir(parents=True)
        self.technique.mkdir(parents=True)
        (self.root / "mitigations").mkdir()
        neighbor = self.root / "techniques" / "SAF-T1001"
        neighbor.mkdir()
        (neighbor / "README.md").write_text("# SAF-T1001: Neighbor\n", encoding="utf-8")
        self.write_valid_fixture()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def dump(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    def write_valid_fixture(self) -> None:
        headings = "\n\n".join(VALIDATOR.REQUIRED_HEADINGS)
        readme = f"""# {self.technique_id}: Test Technique

{headings}

- **Technique ID**: {self.technique_id}
- **Research Packet**: [packet](../../research/techniques/{self.technique_id}/)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated

{self.technique_id}-C001 and SRC-test-source
"""
        (self.technique / "README.md").write_text(readme, encoding="utf-8")
        self.dump(
            self.technique / "detection-rule.yml",
            {
                "title": "Test",
                "id": "454ff680-8c07-4d89-9c39-507a53f35262",
                "status": "test",
                "description": "Detect the test behavior.",
                "logsource": {"product": "mcp"},
                "detection": {
                    "selection": {"event.action": "test"},
                    "condition": "selection",
                },
                "falsepositives": ["Authorized test"],
                "level": "medium",
                "tags": ["saf.t9999"],
            },
        )
        (self.technique / "test-logs.json").write_text("{}\n", encoding="utf-8")
        self.dump(
            self.packet / "technique-contract.yml",
            {
                "version": 1,
                "technique_id": self.technique_id,
                "name": "Test Technique",
                "status": "ready_for_review",
                "tactics": ["ATK-TA0001"],
                "adversary_objective": "Test the validator.",
                "scope": {
                    "security_boundary": "Test boundary",
                    "in_scope": ["Test mechanism"],
                    "out_of_scope": ["Other mechanism"],
                    "affected_components": ["MCP host"],
                },
                "nearest_neighbors": [
                    {"technique_id": "SAF-T1001", "distinction": "Different mechanism"}
                ],
                "required_evidence": ["A demonstration"],
                "detection": {
                    "expectation": "required",
                    "waiver_rationale": None,
                    "required_telemetry": ["MCP audit event"],
                },
                "safe_example_constraints": ["Inert data"],
                "completion_evidence": ["Validator passes"],
            },
        )
        self.dump(
            self.packet / "claim-inventory.yml",
            {
                "version": 1,
                "technique_id": self.technique_id,
                "claims": [
                    {
                        "id": f"{self.technique_id}-C001",
                        "statement": "The end-to-end behavior was demonstrated.",
                        "class": "demonstrated_exploit",
                        "materiality": "high",
                        "evidence_status": "demonstrated",
                        "sources": [
                            {
                                "source_id": "SRC-test-source",
                                "support": "direct",
                                "exact_locators": ["Section 2"],
                            }
                        ],
                        "corroboration": "Direct primary demonstration",
                        "limitations": ["Controlled environment only"],
                        "conflicts": [],
                        "inference": {"is_inference": False, "rationale": None},
                        "status": "validated",
                    }
                ],
            },
        )
        self.dump(
            self.packet / "source-coverage.yml",
            {
                "version": 1,
                "technique_id": self.technique_id,
                "research_status": "saturated",
                "saturation": {
                    "reached": True,
                    "consecutive_no_change_passes": 2,
                    "passes": [
                        {
                            "pass": name,
                            "completed_on": "2026-08-31",
                            "material_changes": []
                            if name.startswith("saturation_")
                            else ["Reviewed"],
                        }
                        for name in (
                            "protocol_and_authority",
                            "incident_and_demonstration",
                            "detection_and_defense",
                            "gap_and_challenge",
                            "saturation_follow_up_1",
                            "saturation_follow_up_2",
                        )
                    ],
                    "rationale": "Two follow-up passes found no material changes.",
                },
                "sources_consulted": ["SRC-test-source"],
                "sources_cited": ["SRC-test-source"],
                "sources_rejected": [],
                "sources_blocked": [],
                "conflicts": [],
                "evidence_assessment": {
                    "overall_status": "demonstrated",
                    "core_claim_ids": [f"{self.technique_id}-C001"],
                    "rationale": "A primary artifact demonstrates the complete flow.",
                },
                "source_archive": {
                    "manifest": "../../source-manifest.yml",
                    "validation_status": "passed",
                },
                "rights_review": {
                    "audit": "publication-rights.yml",
                    "status": "passed",
                },
            },
        )
        self.dump(
            self.packet / "publication-rights.yml",
            {
                "version": 1,
                "technique_id": self.technique_id,
                "review_status": "passed",
                "reviewed_on": "2026-08-31",
                "source_uses": [
                    {
                        "source_id": "SRC-test-source",
                        "rights_owner": "Test Publisher",
                        "access_status": "public",
                        "rights_status": "all_rights_reserved",
                        "use_mode": "paraphrase",
                        "protected_expression_used": False,
                        "basis": "reference_only",
                        "permission_required": False,
                        "permission_status": "not_needed",
                        "attribution": "Inline citation",
                        "notes": "No protected expression reproduced.",
                    }
                ],
                "quotations": [],
                "third_party_artifacts": [],
                "trademarks": [],
                "unresolved": [],
            },
        )
        gates = {
            name: {"status": "passed", "notes": "Reviewed."}
            for name in (
                "contract_and_scope",
                "technical_accuracy",
                "claim_traceability",
                "evidence_classification",
                "research_saturation",
                "detection_quality",
                "mitigation_quality",
                "framework_alignment",
                "publication_rights",
                "safe_publication",
            )
        }
        self.dump(
            self.packet / "quality-review.yml",
            {
                "version": 1,
                "technique_id": self.technique_id,
                "review_status": "passed",
                "reviewed_on": "2026-08-31",
                "reviewer": "Test Reviewer",
                "gates": gates,
                "validation": {
                    "commands": [
                        {
                            "command": "python3 scripts/validate-technique-research.py SAF-T9999",
                            "result": "passed",
                        }
                    ],
                    "detection_tests": {
                        "status": "passed",
                        "command": "test detector",
                        "result": "4/4 passed",
                        "waiver": None,
                    },
                },
                "unresolved": [],
            },
        )
        self.dump(
            self.root / "research" / "source-manifest.yml",
            {
                "version": 1,
                "sources": [
                    {
                        "id": "SRC-test-source",
                        "title": "Test Source",
                        "publisher": "Test Publisher",
                        "version_or_date": "1.0",
                        "source_class": "implementation_artifact",
                        "official_url": "https://example.com/source",
                        "access_status": "public",
                        "accessed_on": "2026-08-31",
                        "review_status": "opened_reviewed",
                        "reviewed_on": "2026-08-31",
                        "review_method": "browser",
                        "locators": ["Section 2"],
                        "review_notes": "Verified the complete flow.",
                        "archive": {
                            "status": "remote_reviewed_not_archived",
                            "reason": "Test fixture has no archive.",
                            "review_evidence": {
                                "access_method": "Official page",
                                "notes": "Complete source reviewed.",
                            },
                        },
                    }
                ],
            },
        )
        self.dump(
            self.root / "research" / "framework-model.yml",
            {
                "version": 1,
                "techniques": [
                    {
                        "technique_id": self.technique_id,
                        "name": "Test Technique",
                        "documentation_status": "under_review",
                        "evidence_status": "demonstrated",
                        "tactics": ["ATK-TA0001"],
                        "technique_path": f"techniques/{self.technique_id}/README.md",
                        "research_packet": f"research/techniques/{self.technique_id}",
                        "related_techniques": ["SAF-T1001"],
                        "mitigations": [],
                        "detection": {
                            "rule": f"techniques/{self.technique_id}/detection-rule.yml",
                            "test_status": "passed",
                            "test_artifacts": ["techniques/SAF-T9999/test-logs.json"],
                        },
                    }
                ],
            },
        )
        self.dump(
            self.root / "research" / "alignment-ledger.yml",
            {"version": 1, "issues": []},
        )

    def test_complete_packet_passes(self) -> None:
        self.assertEqual(
            VALIDATOR.validate_technique(self.root, self.technique_id, strict=True), []
        )

    def test_missing_exact_locator_fails(self) -> None:
        inventory_path = self.packet / "claim-inventory.yml"
        inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
        inventory["claims"][0]["sources"][0]["exact_locators"] = []
        self.dump(inventory_path, inventory)
        errors = VALIDATOR.validate_technique(self.root, self.technique_id, strict=True)
        self.assertTrue(
            any("exact locators required" in error for error in errors), errors
        )

    def test_inflated_evidence_label_fails(self) -> None:
        coverage_path = self.packet / "source-coverage.yml"
        coverage = yaml.safe_load(coverage_path.read_text(encoding="utf-8"))
        coverage["evidence_assessment"]["overall_status"] = "observed"
        self.dump(coverage_path, coverage)
        errors = VALIDATOR.validate_technique(self.root, self.technique_id, strict=True)
        self.assertTrue(any("statuses differ" in error for error in errors), errors)
        self.assertTrue(any("observed_incident" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
