"""Release-only suite: Hub lifecycle preserves the shared base and seven pairs."""

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
ENABLE = "EnableThnContentHubV2"
STATE = "ProvisionThnContentHubV2State"
GATE = "ThnContentHubV2TerminationProtectionGate"


def stack(enabled=False, state=False):
    values = {"EnvironmentName": "test", "ContentHubConfigJsonBase64": "****", "AuthSessionTableName": "shared-session",
              "AuthUserStateTableName": "shared-user-state", "LogLevel": "INFO", "FunctionMemorySize": "512",
              "ServiceBindingRegistryOperatorRoleArn": f"arn:aws:iam::{ACCOUNT}:role/zoolanding-thn-registry-test-operator",
              ENABLE: str(enabled).lower(), STATE: str(state).lower()}
    return {"StackName": "zoolanding-content-hub-test", "StackStatus": "UPDATE_COMPLETE", "EnableTerminationProtection": True,
            "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/zoolanding-content-hub-test/example",
            "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in values.items()]}


def selection():
    from tools.prepare_test_parameters import _thn_defaults
    values = {**_thn_defaults(), ENABLE: "true", STATE: "true", GATE: "CONFIRMED_ENABLED",
        "ServiceBindingRegistryOperatorRoleArn": f"arn:aws:iam::{ACCOUNT}:role/zoolanding-thn-registry-test-operator",
        "ThnContentHubV2EmergencyOperatorRoleArn": f"arn:aws:iam::{ACCOUNT}:role/zoolanding-thn-content-hub-test-operator",
        "ThnContentHubV2PublicDistributionId": "EXAMPLETEST123", "ThnContentHubV2DescriptorVersionId": "reviewed-v1",
        "ThnContentHubV2DescriptorSha256": "a" * 64, "ThnContentHubV2AuthPolicyVersion": "reviewed-policy-v1"}
    return json.dumps({"schemaVersion": 1, "environment": "test", "parameters": values})


class HubReleaseTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "tools/thn_test_release.py"
        self.assertTrue(path.is_file(), "Dedicated Hub lifecycle tool is missing")
        spec = importlib.util.spec_from_file_location("hub_thn_release", path)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self.template = yaml.safe_load((ROOT / "template.yaml").read_text())
        self.processed = {"Resources": {"ContentHubApi": json.loads((ROOT / "tests/fixtures/thn_release_api_baseline.json").read_text())["api"]}}

    def test_provision_needs_no_auth_image_or_descriptor_selection(self):
        values = self.tool.lifecycle_parameters(stack(), "provision", None)
        actual = {p["ParameterKey"]: p for p in values}
        self.assertEqual(actual[ENABLE]["ParameterValue"], "false")
        self.assertEqual(actual[STATE]["ParameterValue"], "true")
        for field in ("ContentHubConfigJsonBase64", "AuthSessionTableName", "ServiceBindingRegistryOperatorRoleArn"):
            self.assertEqual(actual[field], {"ParameterKey": field, "UsePreviousValue": True})
        self.assertNotIn("****", str(values))

    def test_enable_cannot_change_registry_operator_or_missing_shared_boundary(self):
        self.tool.lifecycle_parameters(stack(state=True), "enable", selection())
        altered = stack(state=True)
        altered["Parameters"] = [p for p in altered["Parameters"] if p["ParameterKey"] != "ServiceBindingRegistryOperatorRoleArn"]
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.lifecycle_parameters(altered, "enable", selection())
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.lifecycle_parameters(stack(), "enable", selection())

    def test_composer_preserves_v1_and_uses_verified_processed_body(self):
        candidate = deepcopy(self.template)
        candidate["Resources"]["ContentHubFunction"]["Properties"]["Timeout"] = 999
        result = self.tool.compose_template(candidate, self.template, "provision", self.processed)
        self.assertEqual(result["Resources"]["ContentHubFunction"], self.template["Resources"]["ContentHubFunction"])
        for name in ("ServiceBindingRegistryV2Table", "ServiceBindingRegistryV2MutationFunction", "ContentHubMetadataTable", "ContentHubPackagesBucket"):
            self.assertEqual(result["Resources"][name], self.template["Resources"][name])
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.compose_template(candidate, self.template, "provision", None)

    def test_shared_api_stage_cors_or_registry_resource_changes_cannot_sneak_in(self):
        candidate = deepcopy(self.template)
        candidate["Resources"]["ContentHubApi"]["Properties"]["CorsConfiguration"] = {"AllowOrigins": ["*"]}
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.compose_template(candidate, self.template, "provision", self.processed)

    def test_composer_preserves_the_exact_live_sam_api_annotation_when_source_omits_it(self):
        previous = deepcopy(self.template)
        previous["Resources"]["ContentHubApi"]["Metadata"] = {"SamResourceId": "ContentHubApi"}
        candidate = deepcopy(self.template)
        snapshots = (deepcopy(previous), deepcopy(candidate))
        try:
            result = self.tool.compose_template(candidate, previous, "provision", self.processed)
        except self.tool.ReleaseBlocked:
            self.fail("The exact live SAM annotation must be retained when absent from source")
        self.assertEqual(result["Resources"]["ContentHubApi"]["Metadata"], {"SamResourceId": "ContentHubApi"})
        self.assertEqual((previous, candidate), snapshots, "Composer must not mutate either input")

    def test_sam_annotation_equivalence_rejects_other_live_or_candidate_metadata(self):
        invalid = ({"SamResourceId": "AnotherApi"}, {"SamResourceId": "ContentHubApi", "Other": "value"},
                   {"Other": "value"}, {}, None)
        for metadata in invalid:
            with self.subTest(side="live", metadata=metadata):
                previous = deepcopy(self.template)
                previous["Resources"]["ContentHubApi"]["Metadata"] = metadata
                with self.assertRaises(self.tool.ReleaseBlocked):
                    self.tool.compose_template(self.template, previous, "provision", self.processed)
            with self.subTest(side="candidate", metadata=metadata):
                previous = deepcopy(self.template)
                previous["Resources"]["ContentHubApi"]["Metadata"] = {"SamResourceId": "ContentHubApi"}
                candidate = deepcopy(self.template)
                candidate["Resources"]["ContentHubApi"]["Metadata"] = metadata
                with self.assertRaises(self.tool.ReleaseBlocked):
                    self.tool.compose_template(candidate, previous, "provision", self.processed)

    def test_exact_sam_annotation_does_not_admit_api_properties_globals_or_body_drift(self):
        for field in ("StageName", "CorsConfiguration", "Globals", "DefinitionBody"):
            with self.subTest(field=field):
                previous = deepcopy(self.template)
                previous["Resources"]["ContentHubApi"]["Metadata"] = {"SamResourceId": "ContentHubApi"}
                candidate = deepcopy(self.template)
                properties = candidate["Resources"]["ContentHubApi"]["Properties"]
                if field == "StageName":
                    properties[field] = "another-stage"
                elif field == "CorsConfiguration":
                    properties[field] = {"AllowOrigins": ["*"]}
                elif field == "Globals":
                    candidate["Globals"]["Function"]["Timeout"] = 999
                else:
                    properties[field]["paths"]["/unreviewed"] = {"get": {}}
                with self.assertRaises(self.tool.ReleaseBlocked):
                    self.tool.compose_template(candidate, previous, "provision", self.processed)

    def test_processed_snapshot_validator_is_mandatory_before_execute(self):
        self.assertTrue(hasattr(self.tool, "verify_processed"), "Processed-template validation is missing")
        for live, candidate in ((None, self.processed), (self.processed, None)):
            with self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.verify_processed(live, candidate, {})

    def test_exact_seven_pair_allowlist_rejects_eighth_or_shared_role(self):
        self.assertEqual(len(self.tool.PAIRS), 7)
        for logical in ("ThnContentHubV2UnexpectedFunction", "ServiceBindingRegistryV2MutationRole", "ContentHubFunction"):
            change = {"Type": "Resource", "ResourceChange": {"LogicalResourceId": logical, "ResourceType": "AWS::Lambda::Function", "Action": "Modify"}}
            with self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.review_resources([change], "enable")

    def test_disable_cannot_delete_any_function_role_alias_or_state(self):
        for logical, kind in (("ThnContentHubV2AuthoringFunction", "AWS::Lambda::Function"),
                              ("ThnContentHubV2AuthoringRole", "AWS::IAM::Role"),
                              ("ThnContentHubV2PublisherFunctionAliastest", "AWS::Lambda::Alias"),
                              ("ThnContentHubV2PrivateStore", "AWS::S3::Bucket")):
            with self.assertRaises(self.tool.ReleaseBlocked):
                self.tool.review_resources([{"Type": "Resource", "ResourceChange": {"LogicalResourceId": logical, "ResourceType": kind, "Action": "Remove"}}], "disable")

    def test_previous_versions_require_explicit_retain(self):
        resource = {"LogicalResourceId": "ThnContentHubV2PublisherFunctionVersiona1b2c3d4e5", "ResourceType": "AWS::Lambda::Version", "Action": "Remove"}
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.review_resources([{"Type": "Resource", "ResourceChange": resource}], "enable")
        resource["PolicyAction"] = "Retain"
        self.tool.review_resources([{"Type": "Resource", "ResourceChange": resource}], "enable")

    def test_account_and_test_environment_are_both_required(self):
        self.tool.validate_stack(stack(), ACCOUNT, expected_account_hash=hashlib.sha256(ACCOUNT.encode()).hexdigest())
        wrong = stack()
        wrong["Parameters"][0]["ParameterValue"] = "prod"
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.validate_stack(wrong, ACCOUNT, expected_account_hash=hashlib.sha256(ACCOUNT.encode()).hexdigest())

    def test_provision_rejects_missing_shared_registry_not_missing_consumers(self):
        self.assertTrue(hasattr(self.tool, "verify_shared_base"), "Shared base verification is missing")
        inventory = {"ServiceBindingRegistryV2Table": {"PhysicalResourceId": "zoolanding-content-hub-test-ServiceBindingRegistryV2", "ResourceType": "AWS::DynamoDB::Table"},
                     "ContentHubMetadataTable": {"PhysicalResourceId": "existing-metadata", "ResourceType": "AWS::DynamoDB::Table"},
                     "ContentHubPackagesBucket": {"PhysicalResourceId": "existing-packages", "ResourceType": "AWS::S3::Bucket"},
                     "ContentHubApi": {"PhysicalResourceId": "abc123tes0", "ResourceType": "AWS::ApiGatewayV2::Api"}}
        self.tool.verify_shared_base(inventory)
        del inventory["ServiceBindingRegistryV2Table"]
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.verify_shared_base(inventory)

    def test_runtime_readback_demands_all_seven_exact_functions_roles_and_aliases(self):
        self.assertTrue(hasattr(self.tool, "verify_runtime"), "Runtime verification is missing")
        from types import SimpleNamespace
        resources = self.template["Resources"]
        role_by_name = {resources["ThnContentHubV2" + pair + "Function"]["Properties"]["FunctionName"]:
                        resources["ThnContentHubV2" + pair + "Role"]["Properties"]["RoleName"] for pair in self.tool.PAIRS}
        client = SimpleNamespace(
            get_alias=lambda **request: {"AliasArn": request["FunctionName"] + ":test", "Name": "test", "FunctionVersion": "3"},
            get_function_configuration=lambda **request: {"State": "Active", "LastUpdateStatus": "Successful",
                "Role": f"arn:aws:iam::{ACCOUNT}:role/" + role_by_name[request["FunctionName"].split(":")[-1]]})
        inventory = {}
        for pair in self.tool.PAIRS:
            prefix = "ThnContentHubV2" + pair
            inventory[prefix + "Function"] = {"PhysicalResourceId": resources[prefix + "Function"]["Properties"]["FunctionName"], "ResourceType": "AWS::Lambda::Function"}
            inventory[prefix + "Role"] = {"PhysicalResourceId": resources[prefix + "Role"]["Properties"]["RoleName"], "ResourceType": "AWS::IAM::Role"}
        session = SimpleNamespace(client=lambda *args, **kwargs: client)
        self.tool.verify_runtime(session, inventory, self.template, ACCOUNT)
        del inventory["ThnContentHubV2PublisherRole"]
        with self.assertRaises(self.tool.ReleaseBlocked):
            self.tool.verify_runtime(session, inventory, self.template, ACCOUNT)


if __name__ == "__main__":
    unittest.main()
