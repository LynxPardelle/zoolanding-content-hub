"""Guard a code-only patch of the already provisioned TEST authoring Lambda."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from tools import thn_authoring_patch as patch


ROOT = Path(__file__).resolve().parents[1]
OLD = patch.VERSION_PREFIX + "1111111111"
NEW = patch.VERSION_PREFIX + "2222222222"


def snapshots():
    live = {"Resources": {
        patch.FUNCTION: {"Type": "AWS::Lambda::Function", "Properties": {"Code": {"S3Bucket": "old", "S3Key": "old"}, "Handler": "handler"}},
        OLD: {"Type": "AWS::Lambda::Version", "DeletionPolicy": "Retain", "Properties": {"FunctionName": {"Ref": patch.FUNCTION}}},
        patch.ALIAS: {"Type": "AWS::Lambda::Alias", "Properties": {"FunctionName": {"Ref": patch.FUNCTION}, "FunctionVersion": {"Fn::GetAtt": [OLD, "Version"]}}},
        "ContentHubApi": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {"Name": "shared"}},
    }}
    candidate = deepcopy(live)
    candidate["Resources"][patch.FUNCTION]["Properties"]["Code"] = {"S3Bucket": "new", "S3Key": "new"}
    candidate["Resources"].pop(OLD)
    candidate["Resources"][NEW] = {"Type": "AWS::Lambda::Version", "DeletionPolicy": "Retain", "Properties": {"FunctionName": {"Ref": patch.FUNCTION}}}
    candidate["Resources"][patch.ALIAS]["Properties"]["FunctionVersion"] = {"Fn::GetAtt": [NEW, "Version"]}
    return live, candidate


def change(logical, kind, action, **extra):
    return {"Type": "Resource", "ResourceChange": {"LogicalResourceId": logical, "ResourceType": kind, "Action": action, **extra}}


def allowed_changes():
    return [
        change(patch.FUNCTION, "AWS::Lambda::Function", "Modify", Replacement="False", Scope=["Properties"], Details=[{"Target": {"Attribute": "Properties", "Name": "Code", "RequiresRecreation": "Never"}}]),
        change(NEW, "AWS::Lambda::Version", "Add"),
        change(patch.ALIAS, "AWS::Lambda::Alias", "Modify", Replacement="False", Scope=["Properties"], Details=[{"Target": {"Attribute": "Properties", "Name": "FunctionVersion", "RequiresRecreation": "Never"}}]),
        change(OLD, "AWS::Lambda::Version", "Remove", PolicyAction="Retain"),
    ]


class AuthoringPatchTests(unittest.TestCase):
    def test_composer_changes_only_code_uri(self):
        live = {"Resources": {patch.FUNCTION: {"Type": "AWS::Serverless::Function", "Properties": {"CodeUri": "s3://old/key", "Role": "same"}}, "ContentHubApi": {"Properties": {"Name": "shared"}}}}
        result = patch.compose_template(live, "s3://new/key")
        self.assertEqual(result["Resources"][patch.FUNCTION]["Properties"]["CodeUri"], "s3://new/key")
        self.assertEqual(live["Resources"][patch.FUNCTION]["Properties"]["CodeUri"], "s3://old/key")
        expected = deepcopy(live)
        expected["Resources"][patch.FUNCTION]["Properties"]["CodeUri"] = "s3://new/key"
        self.assertEqual(result, expected)
        with self.assertRaises(patch.PatchBlocked):
            patch.compose_template(live, "https://other/key")

    def test_processed_delta_accepts_only_authoring_code_and_version(self):
        live, candidate = snapshots()
        self.assertEqual(patch.review_processed(live, candidate), (OLD, NEW))
        for mutate in (
            lambda c: c["Resources"]["ContentHubApi"]["Properties"].update(Name="changed"),
            lambda c: c["Resources"][patch.FUNCTION]["Properties"].update(Handler="changed"),
            lambda c: c["Resources"][NEW].update(DeletionPolicy="Delete"),
            lambda c: c["Resources"][NEW]["Properties"].update(ProvisionedConcurrencyConfig={"ProvisionedConcurrentExecutions": 1}),
            lambda c: c["Resources"][patch.ALIAS]["Properties"].update(FunctionName="wrong"),
            lambda c: c.update(Outputs={"Changed": True}),
        ):
            altered = deepcopy(candidate)
            mutate(altered)
            with self.assertRaises(patch.PatchBlocked):
                patch.review_processed(live, altered)

    def test_change_set_rejects_unrelated_resource_and_replacement(self):
        patch.review_changes(allowed_changes(), OLD, NEW)
        patch.review_changes(allowed_changes()[:-1], OLD, NEW)
        for altered in (
            allowed_changes() + [change("ContentHubApi", "AWS::ApiGatewayV2::Api", "Modify")],
            allowed_changes()[:1] + [allowed_changes()[0]],
            [*allowed_changes()[:3], change(OLD, "AWS::Lambda::Version", "Remove", PolicyAction="Delete")],
        ):
            with self.assertRaises(patch.PatchBlocked):
                patch.review_changes(altered, OLD, NEW)
        replacing = allowed_changes()
        replacing[0]["ResourceChange"]["Replacement"] = "True"
        with self.assertRaises(patch.PatchBlocked):
            patch.review_changes(replacing, OLD, NEW)

    def test_private_workflow_dispatches_from_verified_artifact(self):
        workflow = (ROOT / ".github/workflows/deploy-thn-test.yml").read_text()
        self.assertIn("authoring-patch", workflow)
        self.assertIn("tools/thn_authoring_patch.py", workflow)
        self.assertLess(workflow.index("Verify exact artifact before credentials"), workflow.index("configure-aws-credentials"))

    def test_package_contains_only_authoring_build_and_binds_source_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            target = build / patch.FUNCTION
            target.mkdir()
            (target / "content_hub_v2_authoring_handler.py").write_text("handler = True")
            (target / "lambda_function.py").write_text("entry = True")
            (build / "unrelated.py").write_text("must not ship")
            data, key, code_sha = patch.package_code(build, "bucket", "stack/run/sha")
            self.assertTrue(key.startswith("stack/run/sha/authoring-"))
            self.assertEqual(len(code_sha), 44)
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                self.assertEqual(set(archive.namelist()), {"content_hub_v2_authoring_handler.py", "lambda_function.py"})
            again = patch.package_code(build, "bucket", "stack/run/sha")
            self.assertEqual(again, (data, key, code_sha))

    def test_pre_execution_snapshot_drift_is_detected(self):
        before = {"stack": {"StackId": "a"}, "original": {"Resources": {}}, "processed": {},
                  "inventory": {}, "routes": {}, "alias": {"FunctionVersion": "2"}, "version": {}}
        self.assertTrue(patch._same_before(before, deepcopy(before)))
        changed = deepcopy(before)
        changed["alias"]["FunctionVersion"] = "3"
        self.assertFalse(patch._same_before(before, changed))

    def test_pre_execution_snapshot_ignores_lambda_request_metadata_only(self):
        before = {"stack": {"StackId": "a"}, "original": {}, "processed": {},
                  "inventory": {}, "routes": {},
                  "alias": {"FunctionVersion": "2", "ResponseMetadata": {"RequestId": "first"}},
                  "version": {"CodeSha256": "unchanged", "ResponseMetadata": {"RequestId": "first"}}}
        reread = deepcopy(before)
        reread["alias"]["ResponseMetadata"]["RequestId"] = "second"
        reread["version"]["ResponseMetadata"]["RequestId"] = "third"
        self.assertTrue(patch._same_before(before, reread))
        reread["version"]["CodeSha256"] = "changed"
        self.assertFalse(patch._same_before(before, reread))

    def test_artifact_identity_requires_matching_source_and_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            build.mkdir()
            sha = "a" * 40
            manifest = b"sample manifest\n"
            (root / "build-manifest.sha256").write_bytes(manifest)
            (build / "release-metadata.json").write_text(json.dumps({
                "schema": "zoolanding-thn-test-release/v1", "service": "zoolanding-content-hub",
                "source_sha": sha, "run_id": "123", "run_attempt": "1"}))
            env = {"GITHUB_SHA": sha, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                   "EXPECTED_MANIFEST_DIGEST": hashlib.sha256(manifest).hexdigest()}
            patch.verify_artifact_identity(build, env)
            env["GITHUB_SHA"] = "b" * 40
            with self.assertRaises(patch.PatchBlocked):
                patch.verify_artifact_identity(build, env)

    def test_runner_imports_from_standalone_release_layout(self):
        names = ("__init__.py", "thn_test_release.py", "thn_api_boundary.py", "thn_registry_provision.py",
                 "thn_registry_reader_revision.py", "thn_authoring_patch.py", "prepare_test_parameters.py",
                 "review_test_change_set.py")
        with tempfile.TemporaryDirectory() as temporary:
            tools = Path(temporary) / "build" / "release-tools" / "tools"
            tools.mkdir(parents=True)
            for name in names:
                shutil.copy2(ROOT / "tools" / name, tools / name)
            result = subprocess.run([sys.executable, str(tools / "thn_authoring_patch.py"), "--help"],
                                    cwd=temporary, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--operation", result.stdout)

    def test_rollback_record_keeps_old_package_and_version_private(self):
        before = {"original": {"Resources": {patch.FUNCTION: {"Properties": {"CodeUri": "s3://old/package.zip"}}}},
                  "inventory": {OLD: {"PhysicalResourceId": "arn:aws:lambda:us-east-1:123456789012:function:authoring:2"}},
                  "alias": {"FunctionVersion": "2"}, "version": {"CodeSha256": "old-sha"}}
        record = patch.rollback_record(before, OLD, "s3://new/package.zip", "a" * 40)
        self.assertEqual(record["previous_code_uri"], "s3://old/package.zip")
        self.assertEqual(record["previous_alias_version"], "2")
        self.assertEqual(record["new_code_uri"], "s3://new/package.zip")


if __name__ == "__main__":
    unittest.main()
