"""Review must fingerprint the live baseline before sealing recovery code."""

import base64
import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from collections import OrderedDict
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tools import run_thn_production_release as driver
from tools import thn_production_release as release


class RecoverySnapshotTests(unittest.TestCase):
    def test_recovery_sealing_does_not_change_reviewed_baseline(self):
        original = OrderedDict(Resources=OrderedDict(ContentHubFunction={
            "Type": "AWS::Serverless::Function",
            "Properties": {"CodeUri": "s3://historical/function.zip"}}))
        stack_id = ("arn:aws:cloudformation:us-east-1:765932874577:stack/"
                    "zoolanding-content-hub-prod/id")
        baseline = {"stackId": stack_id, "original": original,
                    "processed": {"Resources": {}}, "parameters": [], "tags": [],
                    "resources": [{"LogicalResourceId": "ContentHubFunction",
                                   "ResourceType": "AWS::Lambda::Function",
                                   "PhysicalResourceId": "historical-function"}],
                    "postImportTargets": {"policyDocument": {}}}
        original_baseline_sha = release.sha(copy.deepcopy(baseline))
        candidate = {"Resources": {
            "ServiceBindingRegistryV2MutationRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"RoleName": "zoolanding-thn-registry-production-mutation"}},
            "ServiceBindingRegistryV2Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {"ResourcePolicy": {"PolicyDocument": {
                    "Statement": [{"Sid": "Transition"}]}}}}}}
        body = b"historical lambda package"
        code_sha = base64.b64encode(hashlib.sha256(body).digest()).decode()
        change_set = ("arn:aws:cloudformation:us-east-1:765932874577:changeSet/"
                      "thn-production-hub-state-1-1/id")
        coordinate = {"bucket": "private-release", "key": "recovery/previous.zip",
                      "versionId": "v1", "sha256": release.sha(body)}
        processed_template = {"Resources": {"ServiceBindingRegistryV2Table": {
            "Properties": {"ResourcePolicy": {"PolicyDocument": {}}}}}}
        cf, s3, lam = Mock(), Mock(), Mock()
        cf.create_change_set.return_value = {"Id": change_set}
        cf.get_template.return_value = {"TemplateBody": processed_template}
        s3.get_object.side_effect = lambda **_: {"Body": io.BytesIO(body)}
        lam.get_function.return_value = {
            "Code": {"Location": "https://example.invalid/old.zip"},
            "Configuration": {"CodeSha256": code_sha}}
        session = Mock()
        session.client.side_effect = lambda service: {
            "cloudformation": cf, "s3": s3, "lambda": lam}[service]
        source = {"sourceSha": "a" * 40}
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "template.json"
            record_path = Path(directory) / "record.json"
            template.write_text(json.dumps(candidate))
            args = SimpleNamespace(purpose="state", template=str(template),
                                   record=str(record_path))
            with ExitStack() as patches:
                patches.enter_context(patch.dict(os.environ, {
                    "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
                    "THN_PRODUCTION_PARAMETERS_JSON": "{}"}))
                capture = patches.enter_context(patch.object(
                    driver, "captured_baseline",
                    side_effect=lambda _: copy.deepcopy(baseline)))
                patches.enter_context(patch.object(driver, "sealed_packages",
                                                   return_value=[]))
                patches.enter_context(patch.object(driver, "candidate_for_scope",
                                                   side_effect=lambda value, *_: value))
                patches.enter_context(patch.object(driver.release, "select_parameters",
                                                   return_value=[]))
                patches.enter_context(patch.object(driver.imported,
                    "validate_registry_policy_transition"))
                patches.enter_context(patch.object(driver.imported,
                    "validate_post_import_state_inventory"))
                patches.enter_context(patch.object(driver.release, "seal_object",
                                                   return_value=coordinate))
                patches.enter_context(patch.object(driver.urllib.request, "urlopen",
                                                   return_value=io.BytesIO(body)))
                patches.enter_context(patch.object(driver, "source_selection",
                                                   return_value=source))
                patches.enter_context(patch.object(driver.release, "describe_preview",
                    return_value={"Changes": [], "StackId": stack_id}))
                patches.enter_context(patch.object(driver.release, "review_inventory"))
                patches.enter_context(patch.object(driver, "identity_and_permissions",
                                                   return_value=({}, {})))
                with redirect_stdout(io.StringIO()):
                    driver.review(session, args, source, {}, {})
            record = json.loads(record_path.read_text())
        preview = {"Changes": [], "StackId": stack_id, "Parameters": []}
        with (patch.object(driver.release, "describe_preview", return_value=preview),
              patch.object(driver, "captured_baseline",
                           side_effect=lambda _: copy.deepcopy(baseline)),
              patch.object(driver, "source_selection", return_value=source),
              patch.object(driver, "identity_and_permissions", return_value=({}, {})),
              patch.object(driver.imported, "validate_post_import_state_inventory"),
              patch.object(driver.imported, "validate_registry_policy_transition")):
            driver.release.execute_retained(
                cf, s3, record, approved_digest=record["digest"],
                source_sha=source["sourceSha"], service=driver.CONFIG["service"],
                baseline=copy.deepcopy(baseline), permissions={}, identity={},
                source_package=source,
                authority_check=lambda: driver.fresh_execute_authority(
                    session, record, source, "state", preview, processed_template))
        cf.execute_change_set.assert_called_once_with(
            ChangeSetName=change_set, StackName=stack_id)
        self.assertEqual(record["baselineSha256"], original_baseline_sha)
        self.assertEqual(release.sha(baseline), original_baseline_sha)
        self.assertEqual(capture.call_count, 2)


if __name__ == "__main__":
    unittest.main()
