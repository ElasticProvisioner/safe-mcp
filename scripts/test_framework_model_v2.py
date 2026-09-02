import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


catalog = load_script("generate_technique_catalog", "generate-technique-catalog.py")


class FrameworkModelV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = yaml.safe_load(
            (ROOT / "research/framework-model.yml").read_text(encoding="utf-8")
        )

    def test_catalog_is_model_driven_and_exposes_lifecycle(self):
        rendered = catalog.build_catalog(self.model)
        active = sum(
            item["lifecycle_status"] == "active" for item in self.model["techniques"]
        )
        deprecated = sum(
            item["lifecycle_status"] == "deprecated" for item in self.model["techniques"]
        )
        self.assertIn(catalog.BEGIN, rendered)
        self.assertIn(f"- **Active techniques**: {active}", rendered)
        self.assertIn(f"- **Deprecated compatibility IDs**: {deprecated}", rendered)
        self.assertIn("SAF-T1301", rendered)
        self.assertIn("SAF-T1008", rendered)

    def test_repository_passes_framework_validator(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/validate-framework-model.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
