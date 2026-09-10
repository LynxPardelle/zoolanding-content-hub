"""Immutable workflow tool inventory must execute independently of a checkout."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class ReleaseArtifactTests(unittest.TestCase):
    def test_standalone_package_contains_every_imported_tool_and_help_is_offline(self):
        workflow = (ROOT / ".github/workflows/deploy-thn-test.yml").read_text()
        tools = ("__init__.py", "thn_test_release.py", "prepare_test_parameters.py", "review_test_change_set.py", "thn_api_boundary.py", "thn_registry_provision.py")
        with tempfile.TemporaryDirectory(prefix="thn-release-contract-") as temporary:
            target = Path(temporary)
            (target / "tools").mkdir()
            for name in tools:
                self.assertIn("tools/" + name, workflow)
                shutil.copyfile(ROOT / "tools" / name, target / "tools" / name)
            result = subprocess.run([sys.executable, str(target / "tools/thn_test_release.py"), "--help"],
                                    cwd=temporary, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--operation", result.stdout)

    def test_manifest_verification_precedes_credentials_and_register_is_credential_free(self):
        workflow = (ROOT / ".github/workflows/deploy-thn-test.yml").read_text()
        jobs = yaml.safe_load(workflow)["jobs"]
        register = jobs["register"]
        self.assertEqual(register["permissions"], {"contents": "read"})
        self.assertNotIn("environment", register)
        self.assertTrue(all("uses" not in step and set(step) == {"run"} for step in register["steps"]))
        self.assertIn("No checkout, environment, artifact or AWS credentials", register["steps"][0]["run"])

    def test_exact_inventory_and_both_required_suites_are_pinned(self):
        workflow = (ROOT / ".github/workflows/deploy-thn-test.yml").read_text()
        deploy = workflow.split("\n  deploy:\n", 1)[1]
        self.assertNotIn("actions/checkout", deploy)
        self.assertLess(deploy.index("cmp --silent"), deploy.index("configure-aws-credentials@"))
        for marker in ("artifact-ids:", "EXPECTED_MANIFEST_DIGEST", "find .aws-sam -type l", "source_sha", "run_attempt",
                       "unittest discover -s tests ", "unittest discover -s tests_release "):
            self.assertIn(marker, workflow)
        ci = (ROOT / ".github/workflows/validate-thn-release.yml").read_text()
        self.assertIn("pull_request:", ci)
        self.assertIn("-r requirements-release.txt", ci)
        self.assertNotIn("id-token: write", ci)


if __name__ == "__main__":
    unittest.main()
