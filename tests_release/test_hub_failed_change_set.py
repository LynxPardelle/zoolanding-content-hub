"""A failed THN plan must remain inspectable without leaking provider details."""
from copy import deepcopy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError
import yaml
from tools import thn_test_release as release
from test_thn_test_release import ACCOUNT, stack


class Cloud:
    def __init__(self):
        self.calls = []
        self.stack = stack()
        self.source = yaml.safe_load((Path(__file__).resolve().parents[1] / "template.yaml").read_text())
        self.original = deepcopy(self.source)
        for section in ("Resources", "Parameters", "Conditions", "Rules", "Outputs"):
            self.original[section] = {key: value for key, value in self.original.get(section, {}).items()
                                      if "ThnContentHubV2" not in key}
        self.processed = deepcopy(self.original)
        self.processed["Resources"]["ContentHubApi"] = {"Type": "AWS::ApiGatewayV2::Api",
            "Properties": {"Body": {"openapi": "3.0.1", "paths": {}}}}
        self.change_id = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:changeSet/thn-123-1/example"
        self.status = "FAILED"
        self.execution_status = "UNAVAILABLE"
        self.reason = "provider-private-sentinel https://example.invalid/private"
        self.changed_identity = False
        self.omit_parameters = False

    def client(self, *_args, **_kwargs):
        return self

    def get_caller_identity(self):
        return {"Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/zoolanding-content-hub-test-deploy/release-123"}

    def describe_stacks(self, **_kwargs):
        return {"Stacks": [deepcopy(self.stack)]}

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        if "ChangeSetName" in kwargs:
            raise ClientError({"Error": {"Code": "ValidationException", "Message": self.reason}}, "GetTemplate")
        return {"TemplateBody": deepcopy(self.original if kwargs["TemplateStage"] == "Original" else self.processed)}

    def list_stack_resources(self, **_kwargs):
        resources = {"ServiceBindingRegistryV2Table": ("AWS::DynamoDB::Table", release.REGISTRY_TABLE),
            "ContentHubMetadataTable": ("AWS::DynamoDB::Table", "example-metadata"),
            "ContentHubPackagesBucket": ("AWS::S3::Bucket", "example-packages"),
            "ContentHubApi": ("AWS::ApiGatewayV2::Api", "abcde12345")}
        return {"StackResourceSummaries": [{"LogicalResourceId": key, "ResourceType": kind,
            "PhysicalResourceId": physical, "ResourceStatus": "CREATE_COMPLETE"}
            for key, (kind, physical) in resources.items()]}

    def get_routes(self, **_kwargs):
        return {"Items": []}

    def put_object(self, **_kwargs):
        pass

    def create_change_set(self, **kwargs):
        composed = release.compose_template(self.source, self.original, "provision", self.processed)
        self.expected = release.effective_parameters(composed, release._parameters(self.stack), kwargs["Parameters"])
        return {"Id": self.change_id, "StackId": self.stack["StackId"]}

    def describe_change_set(self, **_kwargs):
        return {"ChangeSetId": self.change_id + ("-other" if self.changed_identity else ""),
            "ChangeSetName": "thn-123-1", "StackId": self.stack["StackId"], "StackName": release.STACK,
            "Status": self.status, "ExecutionStatus": self.execution_status, "StatusReason": self.reason,
            "Changes": [], "Parameters": [] if self.omit_parameters else
            [{"ParameterKey": key, "ParameterValue": value} for key, value in self.expected.items()]}

    def delete_change_set(self, **kwargs):
        self.calls.append(("delete_change_set", kwargs))

    def execute_change_set(self, **_kwargs):
        raise AssertionError("A rejected plan must never execute")


class HubFailedChangeSetTests(unittest.TestCase):
    def setUp(self):
        self.cloud = Cloud()
        self.env = {"GITHUB_REPOSITORY": "LynxPardelle/zoolanding-content-hub", "GITHUB_REF": "refs/heads/test",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": "a" * 40, "EXPECTED_SOURCE_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "AWS_REGION": "us-east-1",
            "AWS_DEFAULT_REGION": "us-east-1", "ARTIFACTS_BUCKET": "example-artifacts"}

    def run_plan(self):
        with patch.object(release, "ACCOUNT_HASH", hashlib.sha256(ACCOUNT.encode()).hexdigest()), \
                patch.object(release, "_package_template", return_value=self.cloud.source), \
                patch.object(release.time, "sleep"):
            return release.run_release(self.cloud, self.env, Path("unused-build"), "provision")

    def test_failed_plan_retained_before_template_reads_without_provider_output(self):
        failure = None
        try:
            self.run_plan()
        except Exception as error:
            failure = error
        self.assertIsInstance(failure, release.ReleaseBlocked)
        self.assertEqual(str(failure), "change_set_creation_failed; diagnostic_retained")
        self.assertFalse(any(name == "delete_change_set" or (name == "get_template" and "ChangeSetName" in args)
                             for name, args in self.cloud.calls))

    def test_failed_plan_without_parameters_still_preserves_diagnostic(self):
        self.cloud.omit_parameters = True
        self.test_failed_plan_retained_before_template_reads_without_provider_output()

    def test_other_change_set_identity_is_rejected_and_only_owned_plan_cleaned(self):
        self.cloud.changed_identity = True
        failure = None
        try:
            self.run_plan()
        except Exception as error:
            failure = error
        self.assertIsInstance(failure, release.ReleaseBlocked)
        self.assertEqual(str(failure), "change_set_response_identity_mismatch")
        deleted = [args for name, args in self.cloud.calls if name == "delete_change_set"]
        self.assertEqual(deleted, [{"StackName": release.STACK, "ChangeSetName": self.cloud.change_id}])

    def test_available_plan_keeps_template_checks_and_cleanup(self):
        self.cloud.status, self.cloud.execution_status = "CREATE_COMPLETE", "AVAILABLE"
        with self.assertRaises(ClientError):
            self.run_plan()
        self.assertTrue(any(name == "delete_change_set" for name, _ in self.cloud.calls))

    def test_exact_noop_keeps_existing_review_path_and_cleanup(self):
        self.cloud.reason = release.ordinary_review._NO_CHANGE_REASON
        with self.assertRaises(ClientError):
            self.run_plan()
        self.assertTrue(any(name == "delete_change_set" for name, _ in self.cloud.calls))


if __name__ == "__main__":
    unittest.main()
