#!/usr/bin/env python3
"""Regression tests for the SAF technique scaffolder."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

import yaml


class NewTechniqueTests(unittest.TestCase):
    def test_scaffolds_joined_artifacts_without_overwrite(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "techniques").mkdir()
            (root / "research" / "templates").mkdir(parents=True)
            shutil.copy2(source_root / "scripts" / "new-technique.py", root / "scripts")
            shutil.copy2(
                source_root / "techniques" / "TEMPLATE.md", root / "techniques"
            )
            shutil.copy2(
                source_root / "techniques" / "DETECTION-RULE-TEMPLATE.yml",
                root / "techniques",
            )
            shutil.copytree(
                source_root / "research" / "templates" / "technique",
                root / "research" / "templates" / "technique",
            )
            shutil.copy2(
                source_root / "research" / "framework-model.yml",
                root / "research" / "framework-model.yml",
            )

            command = [
                sys.executable,
                str(root / "scripts" / "new-technique.py"),
                "SAF-T9998",
                "Test Technique",
            ]
            first = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertTrue((root / "techniques" / "SAF-T9998" / "README.md").is_file())
            packet = root / "research" / "techniques" / "SAF-T9998"
            self.assertTrue((packet / "claim-inventory.yml").is_file())
            generated_readme = (
                root / "techniques" / "SAF-T9998" / "README.md"
            ).read_text(encoding="utf-8")
            self.assertIn("SAF-T9998-C001", generated_readme)

            rule = yaml.safe_load(
                (root / "techniques" / "SAF-T9998" / "detection-rule.yml").read_text(
                    encoding="utf-8"
                )
            )
            self.assertNotEqual(uuid.UUID(rule["id"]).int, 0)
            self.assertIn("saf.t9998", rule["tags"])

            model = yaml.safe_load(
                (root / "research" / "framework-model.yml").read_text(encoding="utf-8")
            )
            generated_record = next(
                record
                for record in model["techniques"]
                if record["technique_id"] == "SAF-T9998"
            )
            self.assertEqual(generated_record["name"], "Test Technique")

            original = generated_readme
            second = subprocess.run(
                command, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("refusing to overwrite", second.stderr)
            self.assertEqual(
                (root / "techniques" / "SAF-T9998" / "README.md").read_text(
                    encoding="utf-8"
                ),
                original,
            )


if __name__ == "__main__":
    unittest.main()
