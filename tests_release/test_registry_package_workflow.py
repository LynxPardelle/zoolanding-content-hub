"""The registry operation carries only its own code through SAM packaging."""

import inspect
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml

from tools import thn_test_release as release
from tools import thn_registry_provision as registry

ROOT = Path(__file__).resolve().parents[1]


class RegistryPackageWorkflowTests(unittest.TestCase):
    def test_operation_is_dispatchable_only_through_the_verified_dedicated_workflow(self):
        workflow = (ROOT / ".github/workflows/deploy-thn-test.yml").read_text()
        self.assertIn("registry-provision", workflow, "Registry bootstrap is not wired into the dedicated workflow")
        self.assertIn("THN_REGISTRY_OPERATOR_ROLE_ARN", workflow)
        self.assertIn("tools/thn_registry_provision.py", workflow)
        self.assertEqual(workflow.count("configure-aws-credentials@"), 1)
        self.assertNotIn("inline-session-policy", workflow)
        self.assertNotIn("managed-session-policies", workflow)
        result = subprocess.run([sys.executable, str(ROOT / "tools/thn_test_release.py"), "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("registry-provision", result.stdout)

    def test_registry_sam_package_projection_excludes_every_other_lambda(self):
        self.assertIn("registry_only", inspect.signature(release._package_template).parameters, "Registry-only packaging is missing")
        candidate = yaml.safe_load((ROOT / "template.yaml").read_text())
        candidate["Resources"][registry.FUNCTION]["Properties"]["CodeUri"] = registry.FUNCTION
        with tempfile.TemporaryDirectory(prefix="thn-registry-package-") as temporary:
            build = Path(temporary)
            (build / registry.FUNCTION).mkdir()
            (build / "template.yaml").write_text(json.dumps(candidate))
            calls = []
            def package(arguments, **kwargs):
                projected = json.loads(Path(arguments[arguments.index("--template-file") + 1]).read_text())
                self.assertEqual(set(projected["Resources"]), set(registry.RESOURCE_TYPES))
                self.assertEqual(projected["Resources"][registry.FUNCTION]["Properties"]["CodeUri"], str((build / registry.FUNCTION).resolve()))
                Path(arguments[arguments.index("--output-template-file") + 1]).write_text(json.dumps(projected))
                calls.append(arguments)
                return SimpleNamespace(returncode=0)
            with patch.object(release.subprocess, "run", side_effect=package):
                packaged = release._package_template(build, "example-artifacts", "reviewed-prefix", registry_only=True)
            self.assertEqual(set(packaged["Resources"]), set(registry.RESOURCE_TYPES))
            self.assertEqual(len(calls), 1)
            candidate["Resources"][registry.FUNCTION]["Properties"]["CodeUri"] = "../other-function"
            (build / "template.yaml").write_text(json.dumps(candidate))
            with patch.object(release.subprocess, "run") as command, self.assertRaises(release.ReleaseBlocked):
                release._package_template(build, "example-artifacts", "reviewed-prefix", registry_only=True)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
