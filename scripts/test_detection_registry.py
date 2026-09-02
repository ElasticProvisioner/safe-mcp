#!/usr/bin/env python3
"""Integration tests for the detection coverage registry."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest


class DetectionRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]

    def run_script(self, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.root / "scripts" / script), *arguments],
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_registry_is_valid(self) -> None:
        result = self.run_script("validate-detection-registry.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_generated_coverage_is_current(self) -> None:
        result = self.run_script("generate-detection-coverage.py", "--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_generated_mitigation_catalog_is_current(self) -> None:
        result = self.run_script("generate-mitigation-catalog.py", "--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
