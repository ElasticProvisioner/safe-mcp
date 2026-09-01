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
        headings = "\n\n".join(
            heading
            for heading in VALIDATOR.REQUIRED_HEADINGS
            if heading not in {"## Overview", "## Scope"}
        )
        readme = f"""# {self.technique_id}: Test Technique

## Overview

- **Technique ID**: {self.technique_id}
- **Research Packet**: [packet](../../research/techniques/{self.technique_id}/)
- **Traceability Ledger**: [ledger](../../research/techniques/{self.technique_id}/traceability-ledger.yml)
- **Documentation Status**: Under Review
- **Evidence Status**: Demonstrated

## Scope

{self.technique_id}-C001 and SRC-test-source

{headings}
"""
        (self.technique / "README.md").write_text(readme, encoding="utf-8")
        self.dump(
            self.technique / "detection-rule.yml",
            {
                "title": "Test",
                "id": "454ff680-8c07-4d89-9c39-507a53f35262",
                "status": "test",
                "description": "Detect the test behavior.",
                "traceability": {
                    "policy": "source_or_omit",
                    "design_claim_ids": [f"{self.technique_id}-C001"],
                    "telemetry_claim_ids": [f"{self.technique_id}-C001"],
                    "limitation_claim_ids": [f"{self.technique_id}-C001"],
                    "validation_artifacts": [
                        f"techniques/{self.technique_id}/test-logs.json"
                    ],
                    "components": {
                        "selection": {
                            "claim_ids": [f"{self.technique_id}-C001"],
                            "rationale": "The source supports the selection.",
                        },
                        "condition": {
                            "claim_ids": [f"{self.technique_id}-C001"],
                            "rationale": "The source supports the condition.",
                        },
                        "logsource": {
                            "claim_ids": [f"{self.technique_id}-C001"],
                            "rationale": "The source supports the event source.",
                        },
                        "falsepositives": {
                            "claim_ids": [f"{self.technique_id}-C001"],
                            "rationale": "The source bounds the result.",
                        },
                    },
                },
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
                "generation_mode": "standard",
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
            self.packet / "clean-room-attestation.yml",
            {
                "version": 1,
                "technique_id": self.technique_id,
                "generation_mode": "standard",
                "status": "not_applicable",
                "generated_on": "2026-08-31",
                "generator": {"type": "author", "inherited_context": None},
                "target": {
                    "id": self.technique_id,
                    "neutral_name": "Test Technique",
                },
                "allowed_inputs": ["Standard generation."],
                "prohibited_inputs": ["Not applicable."],
                "independent_research": {"searches": [], "opened_source_ids": []},
                "prior_artifact_access": {"detected": None, "details": []},
                "draft_frozen_before_integration": None,
                "integration_constraints": [],
                "attestation": "Clean-room generation was not requested.",
                "unresolved": [],
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
                            "known_breaches_and_vulnerabilities",
                            "demonstration_and_empirical_research",
                            "detection_and_defense",
                            "gap_and_challenge",
                            "saturation_follow_up_1",
                            "saturation_follow_up_2",
                        )
                    ],
                    "rationale": "Two follow-up passes found no material changes.",
                },
                "breach_and_vulnerability_assessment": {
                    "searched_on": "2026-08-31",
                    "candidate_count": 1,
                    "selected_examples": [],
                    "no_qualifying_examples_rationale": "No direct example qualified.",
                    "candidates": [
                        {
                            "source_id": "SRC-test-source",
                            "identifier": "TEST-ADVISORY",
                            "relationship": "rejected",
                            "exploitation_status": "not observed",
                            "impact": "No demonstrated impact.",
                            "remediation": "Not applicable.",
                            "selected": False,
                            "rationale": "The source is outside the contract.",
                        }
                    ],
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
        self.dump(
            self.packet / "traceability-ledger.yml",
            {
                "version": 1,
                "technique_id": self.technique_id,
                "policy": "source_or_omit",
                "review_status": "passed",
                "reviewed_on": "2026-08-31",
                "publishable_artifact": f"techniques/{self.technique_id}/README.md",
                "coverage": "all_substantive_publishable_content",
                "repository_sources": [
                    {
                        "id": "LOCAL-quality-review",
                        "path": f"research/techniques/{self.technique_id}/quality-review.yml",
                        "supports": "Validation results.",
                    },
                    {
                        "id": "LOCAL-detection-rule",
                        "path": f"techniques/{self.technique_id}/detection-rule.yml",
                        "supports": "Detection logic.",
                    },
                    {
                        "id": "LOCAL-detection-tests",
                        "path": f"techniques/{self.technique_id}/test-logs.json",
                        "supports": "Synthetic validation cases.",
                    },
                ],
                "repository_history": [
                    {
                        "commit": "a" * 40,
                        "supports": "Version-history provenance.",
                    }
                ],
                "excluded_items": [],
                "unresolved": [],
            },
        )
        gates = {
            name: {"status": "passed", "notes": "Reviewed."}
            for name in (
                "clean_room_integrity",
                "contract_and_scope",
                "technical_accuracy",
                "claim_traceability",
                "source_or_omit",
                "evidence_classification",
                "research_saturation",
                "breach_and_vulnerability_coverage",
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
                        "authors": ["Test Author"],
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

    def test_untraced_publishable_line_fails(self) -> None:
        readme_path = self.technique / "README.md"
        readme = readme_path.read_text(encoding="utf-8").replace(
            "## Scope\n\n",
            "## Scope\n\nThis unsupported sentence has no trace.\n\n",
            1,
        )
        readme_path.write_text(readme, encoding="utf-8")
        errors = VALIDATOR.validate_technique(self.root, self.technique_id, strict=True)
        self.assertTrue(
            any("substantive content without" in error for error in errors), errors
        )

    def test_excluded_wording_cannot_reappear(self) -> None:
        ledger_path = self.packet / "traceability-ledger.yml"
        ledger = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
        ledger["excluded_items"] = [
            {
                "id": f"{self.technique_id}-X001",
                "candidate": "Unsupported production claim.",
                "origin": "Prior draft.",
                "attempted_searches": ["test incident search"],
                "consulted_source_ids": ["SRC-test-source"],
                "reason": "The source does not establish production use.",
                "prohibited_publishable_text": ["unsupported production claim"],
                "disposition": "omitted_from_publishable_technique",
                "status": "excluded",
            }
        ]
        self.dump(ledger_path, ledger)
        readme_path = self.technique / "README.md"
        readme = readme_path.read_text(encoding="utf-8").replace(
            f"{self.technique_id}-C001 and SRC-test-source",
            f"Unsupported production claim. {self.technique_id}-C001 and SRC-test-source",
            1,
        )
        readme_path.write_text(readme, encoding="utf-8")
        errors = VALIDATOR.validate_technique(self.root, self.technique_id, strict=True)
        self.assertTrue(any("prohibited text appears" in error for error in errors), errors)

    def test_untraced_detection_component_fails(self) -> None:
        rule_path = self.technique / "detection-rule.yml"
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        del rule["traceability"]["components"]["condition"]
        self.dump(rule_path, rule)
        errors = VALIDATOR.validate_technique(self.root, self.technique_id, strict=True)
        self.assertTrue(
            any("every detection component" in error for error in errors), errors
        )

    def test_clean_room_requires_isolated_fresh_agent_attestation(self) -> None:
        contract_path = self.packet / "technique-contract.yml"
        contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
        contract["generation_mode"] = "clean_room"
        self.dump(contract_path, contract)
        attestation_path = self.packet / "clean-room-attestation.yml"
        attestation = yaml.safe_load(attestation_path.read_text(encoding="utf-8"))
        attestation["generation_mode"] = "clean_room"
        attestation["status"] = "passed"
        attestation["generator"] = {"type": "fresh_agent", "inherited_context": True}
        attestation["allowed_inputs"] = ["Canonical blank template."]
        attestation["prohibited_inputs"] = [
            f"techniques/{self.technique_id}/README.md",
            f"research/techniques/{self.technique_id}/",
            f"techniques/{self.technique_id}/detection-rule.yml",
            "git history",
            "pull request",
            "previous conversation",
        ]
        attestation["independent_research"] = {
            "searches": ["independent test query"],
            "opened_source_ids": ["SRC-test-source"],
        }
        attestation["prior_artifact_access"] = {"detected": False, "details": []}
        attestation["draft_frozen_before_integration"] = True
        attestation["integration_constraints"] = ["Do not inspect prior prose."]
        self.dump(attestation_path, attestation)
        errors = VALIDATOR.validate_technique(self.root, self.technique_id, strict=True)
        self.assertTrue(any("must not inherit" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
