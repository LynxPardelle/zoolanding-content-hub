"""Registry bootstrap is an exact five-resource extension, not THN activation."""

from copy import deepcopy
import importlib
import importlib.util
from pathlib import Path
import unittest
import yaml

from tools import thn_test_release as release

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:role/zoolanding-thn-registry-test-operator"
REGISTRY = {"ServiceBindingRegistryV2Table": "AWS::DynamoDB::Table",
            "ServiceBindingRegistryV2MutationRole": "AWS::IAM::Role",
            "ServiceBindingRegistryV2MutationFunction": "AWS::Serverless::Function",
            "ServiceBindingRegistryOperatorInvokePolicy": "AWS::IAM::Policy",
            "ServiceBindingRegistryOperatorInvokePermission": "AWS::Lambda::Permission"}


def fixture():
    """Synthetic immutable shared baseline; real SAM translation is audited separately."""
    candidate = yaml.safe_load((ROOT / "template.yaml").read_text())
    live = {"AWSTemplateFormatVersion": "2010-09-09", "Transform": candidate["Transform"],
            "Globals": deepcopy(candidate["Globals"]), "Description": "Unchanged v1 fixture",
            "Parameters": {"EnvironmentName": {"Type": "String"}, "FunctionMemorySize": {"Type": "Number", "Default": 512},
                           "SharedSecret": {"Type": "String", "NoEcho": True}},
            "Resources": {"ContentHubApi": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {"Body": {"openapi": "3.0.1", "paths": {"/v1": {"post": {}}}}}},
                          "ContentHubMetadataTable": {"Type": "AWS::DynamoDB::Table", "Properties": {"TableName": "v1-metadata"}},
                          "ContentHubPackagesBucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "v1-packages"}}}}
    live["Resources"].update({f"SharedFixture{index}": {"Type": "AWS::IAM::Role", "Properties": {"RoleName": f"shared-fixture-{index}"}}
                             for index in range(14)})
    processed = deepcopy(live)
    processed.pop("Transform")
    processed.pop("Globals")
    inventory = {key: {"ResourceType": item["Type"], "PhysicalResourceId": "physical-" + key}
                 for key, item in processed["Resources"].items()}
    return candidate, live, processed, inventory


def processed_candidate(source):
    result = deepcopy(source)
    result.pop("Transform", None)
    result.pop("Globals", None)
    function = result["Resources"]["ServiceBindingRegistryV2MutationFunction"]
    function["Type"] = "AWS::Lambda::Function"
    function["Properties"].pop("CodeUri")
    function["Properties"]["Code"] = {"S3Bucket": "example-artifacts", "S3Key": "registry.zip"}
    return result


class RegistryProvisionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("tools.thn_registry_provision"), "Separate registry bootstrap is missing")
        self.subject = importlib.import_module("tools.thn_registry_provision")
        self.candidate, self.live, self.processed, self.inventory = fixture()

    def compose(self):
        return self.subject.compose(self.candidate, self.live, self.processed, self.inventory)

    def test_composer_preserves_every_live_resource_and_adds_exact_five_with_no_runtime(self):
        result = self.compose()
        self.assertEqual(set(result["Resources"]), set(self.live["Resources"]) | set(REGISTRY))
        for key, value in self.live["Resources"].items():
            self.assertEqual(result["Resources"][key], value)
        self.assertFalse(any(key.startswith("Thn") for key in result["Resources"]))
        self.assertEqual(set(result["Parameters"]), set(self.live["Parameters"]) | {"ServiceBindingRegistryOperatorRoleArn"})
        self.assertEqual(set(result["Conditions"]), {"IsTestEnvironment", "HasServiceBindingRegistryOperatorRole"})
        for section in ("Globals", "Description", "Transform"):
            self.assertEqual(result[section], self.live[section])

    def test_all_existing_parameters_use_previous_and_only_operator_is_new(self):
        stack = {"StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/{release.STACK}/example",
                 "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in
                                {"EnvironmentName": "test", "FunctionMemorySize": "512", "SharedSecret": "****"}.items()]}
        values = self.subject.parameters(stack, OPERATOR)
        self.assertEqual([entry for entry in values if "ParameterValue" in entry],
                         [{"ParameterKey": "ServiceBindingRegistryOperatorRoleArn", "ParameterValue": OPERATOR}])
        self.assertTrue(all(entry.get("UsePreviousValue") is True for entry in values if entry["ParameterKey"] != "ServiceBindingRegistryOperatorRoleArn"))
        for invalid in ("", OPERATOR.replace("test", "prod"), OPERATOR.replace(ACCOUNT, "999999999999")):
            with self.subTest(invalid=invalid), self.assertRaises(release.ReleaseBlocked):
                self.subject.parameters(stack, invalid)

    def test_missing_snapshot_inventory_count_types_or_preexisting_thn_are_denied(self):
        for mutation in ("missing", "count", "type", "thn", "registry"):
            candidate, live, processed, inventory = fixture()
            if mutation == "missing":
                processed = None
            elif mutation == "count":
                inventory.pop(next(iter(inventory)))
            elif mutation == "type":
                inventory["ContentHubMetadataTable"]["ResourceType"] = "AWS::S3::Bucket"
            elif mutation == "thn":
                live["Resources"]["ThnContentHubV2AuthoringFunction"] = {"Type": "AWS::Serverless::Function"}
            else:
                live["Parameters"]["ServiceBindingRegistryOperatorRoleArn"] = {"Type": "String"}
            with self.subTest(mutation=mutation), self.assertRaises(release.ReleaseBlocked):
                self.subject.compose(candidate, live, processed, inventory)

    def test_processed_snapshot_accepts_only_seventeen_identical_plus_five_exact_resources(self):
        composed = self.compose()
        self.subject.verify_processed(self.processed, processed_candidate(composed), self.inventory)
        for mutation in ("v1", "api", "extra", "missing", "global", "parameter", "condition", "public-mediator"):
            altered = processed_candidate(composed)
            if mutation == "v1":
                altered["Resources"]["ContentHubMetadataTable"]["Properties"]["TableName"] = "other"
            elif mutation == "api":
                altered["Resources"]["ContentHubApi"]["Properties"]["Body"]["paths"]["/v1"]["post"]["security"] = []
            elif mutation == "extra":
                altered["Resources"]["Extra"] = {"Type": "AWS::Lambda::Function"}
            elif mutation == "missing":
                altered["Resources"].pop("ServiceBindingRegistryV2MutationRole")
            elif mutation == "global":
                altered["Description"] = "different"
            elif mutation == "parameter":
                altered["Parameters"]["SharedSecret"]["Default"] = "changed"
            elif mutation == "condition":
                altered["Conditions"]["IsTestEnvironment"] = {"Fn::Equals": [1, 1]}
            else:
                altered["Resources"]["ServiceBindingRegistryV2MutationFunction"]["Properties"]["FunctionUrlConfig"] = {"AuthType": "NONE"}
            with self.subTest(mutation=mutation), self.assertRaises(release.ReleaseBlocked):
                self.subject.verify_processed(self.processed, altered, self.inventory)

    def test_change_review_accepts_only_five_unique_additions_and_no_replacement(self):
        changes = [{"Type": "Resource", "ResourceChange": {"Action": "Add", "LogicalResourceId": key,
            "ResourceType": "AWS::Lambda::Function" if kind == "AWS::Serverless::Function" else kind}}
                   for key, kind in REGISTRY.items()]
        self.subject.review_changes(changes)
        mutations = [changes[:-1], changes + [changes[0]]]
        for field, value in (("Action", "Modify"), ("Action", "Remove"), ("Replacement", "True"),
                             ("LogicalResourceId", "ContentHubApi"), ("ResourceType", "AWS::Lambda::Function")):
            altered = deepcopy(changes)
            altered[0]["ResourceChange"][field] = value
            mutations.append(altered)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(release.ReleaseBlocked):
                self.subject.review_changes(changed)

    def test_packaging_projection_contains_only_registry_code_and_legal_dependencies(self):
        projected = self.subject.packaging_source(self.candidate)
        self.assertEqual(set(projected["Resources"]), set(REGISTRY))
        self.assertEqual(set(projected["Parameters"]), {"EnvironmentName", "FunctionMemorySize", "ServiceBindingRegistryOperatorRoleArn"})
        self.assertFalse(any(key.startswith("Thn") for key in projected["Parameters"]))
        self.assertEqual([key for key, item in projected["Resources"].items() if item["Type"] == "AWS::Serverless::Function"],
                         ["ServiceBindingRegistryV2MutationFunction"])

    def test_missing_resource_retention_or_added_entrypoint_is_rejected(self):
        for mutation in ("missing", "retention", "url", "event", "alias", "globals"):
            candidate = deepcopy(self.candidate)
            if mutation == "missing":
                candidate["Resources"].pop("ServiceBindingRegistryOperatorInvokePolicy")
            elif mutation == "retention":
                candidate["Resources"]["ServiceBindingRegistryV2Table"]["DeletionPolicy"] = "Delete"
            elif mutation == "globals":
                candidate["Globals"]["Function"]["Timeout"] = 100
            else:
                field = {"url": "FunctionUrlConfig", "event": "Events", "alias": "AutoPublishAlias"}[mutation]
                candidate["Resources"]["ServiceBindingRegistryV2MutationFunction"]["Properties"][field] = "unexpected"
            with self.subTest(mutation=mutation), self.assertRaises(release.ReleaseBlocked):
                self.subject.compose(candidate, self.live, self.processed, self.inventory)


if __name__ == "__main__":
    unittest.main()
