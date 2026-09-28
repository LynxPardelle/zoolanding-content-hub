"""Release-only activation proofs for the retained Image TEST boundary."""

from copy import deepcopy
from decimal import Decimal
import json
from types import SimpleNamespace
import unittest

from boto3.dynamodb.types import TypeSerializer
from tools import thn_test_release as subject
from test_thn_test_release import ACCOUNT, selection


def binding():
    owner = {"environment": "test", "domain": "thehairnarrative.com", "serviceBindingId": "thn-journal-test-v2",
             "hubId": "thehairnarrative-com-journal", "tenantId": "thehairnarrative-com", "authProfileId": "journal-owner"}
    return {**owner, "pk": "SERVICE_BINDING#test#thn-journal-test-v2", "sk": "REGISTRY#V2",
        "recordType": "service-binding-registry-v2", "schemaVersion": 2,
        "descriptorVersionId": "reviewed-v1", "descriptorSha256": "a" * 64,
        "authPolicyVersion": "reviewed-policy-v1", "activationStatus": "active", "writerMode": "disabled",
        "writerEpoch": 2, "registryRevision": 3, "adminOrigin": "https://admin-test.thehairnarrative.com",
        "cookieNamespace": "endefiz7dkk635k6di6k", "reservationOwner": owner,
        "resourceBindings": {"authoringFunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:zoolanding-content-hub-test-ThnContentHubV2Authoring",
                             "metadataTableArn": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/zoolanding-content-hub-test-ThnContentHubV2Metadata"}}


class ReadOnlyServices:
    def __init__(self):
        self.row = binding()
        self.auth_enabled = "true"
        self.auth_descriptor = "reviewed-v1"
        self.concurrency = 2
        self.image_enabled = "true"
        self.reads = []

    def client(self, name, **kwargs):
        return self

    def get_item(self, **kwargs):
        self.reads.append(("get_item", deepcopy(kwargs)))
        return {"Item": {k: TypeSerializer().serialize(v) for k, v in self.row.items()}}

    def describe_stacks(self, **kwargs):
        self.reads.append(("describe_stacks", deepcopy(kwargs)))
        if kwargs["StackName"] == "zoolanding-image-upload-test":
            return {"Stacks": [{"StackName": "zoolanding-image-upload-test",
                "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/zoolanding-image-upload-test/example",
                "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True,
                "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in {
                    "EnableThnPrivateUploadV2": self.image_enabled, "ProvisionThnPrivateUploadV2State": "true",
                    "ThnContentHubV2DescriptorVersionId": "reviewed-v1", "ThnContentHubV2DescriptorSha256": "a" * 64,
                    "ThnContentHubV2AuthPolicyVersion": "reviewed-policy-v1"}.items()]}]}
        return {"Stacks": [{"StackName": "zoolanding-auth-admin-test",
            "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/zoolanding-auth-admin-test/example",
            "StackStatus": "UPDATE_COMPLETE", "EnableTerminationProtection": True,
            "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in {
                "EnvironmentName": "test", "EnableThnAuthAdminV2": self.auth_enabled,
                "ThnAuthAdminV2DescriptorVersionId": self.auth_descriptor,
                "ThnAuthAdminV2DescriptorSha256": "a" * 64,
                "ThnAuthAdminV2AuthPolicyVersion": "reviewed-policy-v1",
                "ThnAuthAdminV2OriginHeaderSha256Current": "****"}.items()]}]}

    def get_role(self, **kwargs):
        return {"Role": {"RoleName": kwargs["RoleName"], "Arn": f"arn:aws:iam::{ACCOUNT}:role/" + kwargs["RoleName"]}}

    def list_stack_resources(self, **kwargs):
        return {"StackResourceSummaries": [{"LogicalResourceId": "ThnContentHubV2AuthoringRole",
            "ResourceType": "AWS::IAM::Role", "PhysicalResourceId": "zlp-thn-ch-test-authoring", "ResourceStatus": "CREATE_COMPLETE"}]}

    def get_function_concurrency(self, **kwargs):
        return {"ReservedConcurrentExecutions": self.concurrency}

    def get_alias(self, **kwargs):
        return {"AliasArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:zoolanding-image-upload-test-ThnImageUploadV2:test",
                "Name": "test", "FunctionVersion": "3"}

    def get_function_configuration(self, **kwargs):
        return {"State": "Active", "LastUpdateStatus": "Successful",
                "Role": f"arn:aws:iam::{ACCOUNT}:role/zoolanding-image-upload-test-ThnImageUploadV2Role"}


class HubReleaseGuardTests(unittest.TestCase):
    def setUp(self):
        self.session = ReadOnlyServices()
        self.values = json.loads(selection())["parameters"]

    def test_enable_checks_exact_strong_registry_origin_descriptor_and_auth(self):
        self.assertTrue(hasattr(subject, "verify_dependencies"), "Deployment dependency checks are missing")
        proof = subject.verify_dependencies(self.session, "enable", self.values, ACCOUNT)
        self.assertRegex(proof, r"^[a-f0-9]{64}$")
        request = self.session.reads[0][1]
        self.assertEqual(request["TableName"], "zoolanding-content-hub-test-ServiceBindingRegistryV2")
        self.assertTrue(request["ConsistentRead"])
        self.assertEqual(request["Key"]["pk"], {"S": "SERVICE_BINDING#test#thn-journal-test-v2"})

    def test_enable_and_disable_refuse_open_writers_invalid_epoch_or_crossed_origin(self):
        self.assertTrue(hasattr(subject, "verify_dependencies"), "Deployment dependency checks are missing")
        for field, value in (("writerMode", "qa-only"), ("writerEpoch", 0), ("writerEpoch", True),
                             ("adminOrigin", "https://different.example.test"), ("descriptorSha256", "b" * 64)):
            for operation in ("enable", "disable"):
                self.session.row = {**binding(), field: value}
                with self.subTest(field=field, operation=operation), self.assertRaises(subject.ReleaseBlocked):
                    subject.verify_dependencies(self.session, operation, self.values, ACCOUNT)

    def test_enable_refuses_inactive_or_mismatched_auth(self):
        self.assertTrue(hasattr(subject, "verify_dependencies"), "Deployment dependency checks are missing")
        self.session.auth_enabled = "false"
        with self.assertRaises(subject.ReleaseBlocked):
            subject.verify_dependencies(self.session, "enable", self.values, ACCOUNT)
        self.session.auth_enabled = "true"
        self.session.auth_descriptor = "other-v1"
        with self.assertRaises(subject.ReleaseBlocked):
            subject.verify_dependencies(self.session, "enable", self.values, ACCOUNT)

    def test_registry_unknown_fields_or_extra_resource_binding_are_rejected(self):
        for nested in (False, True):
            self.session.row = binding()
            if nested:
                self.session.row["resourceBindings"]["extra"] = "arn:aws:lambda:us-east-1:123456789012:function:other"
            else:
                self.session.row["extra"] = "unexpected"
            with self.subTest(nested=nested), self.assertRaises(subject.ReleaseBlocked):
                subject.verify_dependencies(self.session, "enable", self.values, ACCOUNT)
    def test_disable_does_not_need_auth_runtime_but_requires_closed_ledger(self):
        self.assertTrue(hasattr(subject, "verify_dependencies"), "Deployment dependency checks are missing")
        self.session.auth_enabled = "false"
        subject.verify_dependencies(self.session, "disable", self.values, ACCOUNT)
        self.assertEqual([name for name, _ in self.session.reads], ["get_item"])

    def test_hub_enable_requires_previously_enabled_private_image(self):
        self.assertTrue(hasattr(subject, "verify_dependencies"), "Deployment dependency checks are missing")
        for field, value in (("image_enabled", "false"), ("concurrency", 0)):
            self.session = ReadOnlyServices()
            setattr(self.session, field, value)
            with self.subTest(field=field), self.assertRaises(subject.ReleaseBlocked):
                subject.verify_dependencies(self.session, "enable", self.values, ACCOUNT)


if __name__ == "__main__":
    unittest.main()
