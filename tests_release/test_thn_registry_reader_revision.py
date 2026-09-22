"""A THN runtime reader revision must touch one registry policy only."""

from copy import deepcopy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

from tools import thn_registry_reader_revision as revision


ROOT = Path(__file__).resolve().parents[1]


class RegistryReaderRevisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.desired = yaml.safe_load((ROOT / "template.yaml").read_text())

    def previous(self):
        live = deepcopy(self.desired)
        table = live["Resources"][revision.TABLE]
        table["Metadata"] = {"SamResourceId": revision.TABLE}
        approved = revision.reader_list(table)
        approved.remove(revision.runtime_role_intrinsic())
        return live

    def test_preserves_every_other_live_field(self):
        previous = self.previous()
        previous["Resources"]["ContentHubApi"]["Metadata"] = {"SamResourceId": "ContentHubApi"}
        composed = revision.compose_revision(previous, self.desired)
        expected = deepcopy(previous)
        desired_position = revision.reader_list(self.desired["Resources"][revision.TABLE]).index(
            revision.runtime_role_intrinsic())
        revision.reader_list(expected["Resources"][revision.TABLE]).insert(
            desired_position, revision.runtime_role_intrinsic())
        self.assertEqual(composed, expected)
        self.assertEqual(revision.reader_list(composed["Resources"][revision.TABLE]).count(
            revision.runtime_role_intrinsic()), 1)

    def test_rejects_unrelated_table_change_and_duplicate_reader(self):
        previous = self.previous()
        previous["Resources"][revision.TABLE]["Properties"]["DeletionProtectionEnabled"] = False
        with self.assertRaises(revision.RevisionBlocked):
            revision.compose_revision(previous, self.desired)
        duplicate = self.previous()
        revision.reader_list(duplicate["Resources"][revision.TABLE]).append(revision.runtime_role_intrinsic())
        with self.assertRaises(revision.RevisionBlocked):
            revision.compose_revision(duplicate, self.desired)

    def test_accepts_only_single_nonreplacing_table_policy_modify(self):
        target = {"Attribute": "Properties", "Name": "ResourcePolicy", "RequiresRecreation": "Never"}
        change = {"Type": "Resource", "ResourceChange": {"Action": "Modify", "LogicalResourceId": revision.TABLE,
                  "ResourceType": "AWS::DynamoDB::Table", "Replacement": "False", "Scope": ["Properties"],
                  "Details": [{"Target": target}]}}
        revision.review_changes([change])
        for invalid in ([change, change], [{**change, "ResourceChange": {**change["ResourceChange"],
                        "Replacement": "True"}}], [{**change, "ResourceChange": {**change["ResourceChange"],
                        "LogicalResourceId": "ContentHubApi"}}]):
            with self.assertRaises(revision.RevisionBlocked):
                revision.review_changes(invalid)

    def test_effective_policy_hash_ignores_only_order_of_two_known_deployment_roles(self):
        account = "123456789012"
        hub = f"arn:aws:iam::{account}:role/zoolanding-content-hub-test-deploy"
        image = f"arn:aws:iam::{account}:role/zoolanding-deployer-image-upload-test-github-deploy"
        sids = revision.DEPLOYMENT_READER_SIDS
        first = {"Statement": [{"Sid": sid, "Principal": {"AWS": [hub, image]}} for sid in sids]}
        second = {"Statement": [{"Sid": sid, "Principal": {"AWS": [image, hub]}} for sid in sids]}
        self.assertEqual(revision.normalized_policy(first, account), revision.normalized_policy(second, account))
        second["Statement"][0]["Principal"]["AWS"][0] = "arn:aws:iam::123456789012:role/unrelated"
        with self.assertRaises(revision.RevisionBlocked):
            revision.normalized_policy(second, account)

    def test_registered_private_workflow_packages_and_dispatches_policy_revision(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy-thn-test.yml").read_text()
        self.assertIn("registry-reader-revise", workflow)
        self.assertIn("cp template.yaml .aws-sam/build/release-tools/", workflow)
        self.assertIn("tools/thn_registry_reader_revision.py", workflow)
        self.assertIn("--operation apply", workflow)

    def test_revision_tool_imports_from_immutable_release_layout(self):
        names = ("__init__.py", "thn_test_release.py", "thn_api_boundary.py", "thn_registry_provision.py",
                 "thn_registry_reader_revision.py", "prepare_test_parameters.py", "review_test_change_set.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            for name in names:
                shutil.copy2(ROOT / "tools" / name, tools / name)
            shutil.copy2(ROOT / "template.yaml", root / "template.yaml")
            result = subprocess.run([sys.executable, str(tools / "thn_registry_reader_revision.py"), "--help"],
                                    cwd=root, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--operation", result.stdout)


if __name__ == "__main__":
    unittest.main()
