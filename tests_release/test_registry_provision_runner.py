"""SDK boundary tests for the separately reviewed exact registry bootstrap."""

from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import thn_registry_provision as subject
from tools import thn_test_release as release
from test_registry_provision import ACCOUNT, OPERATOR, REGISTRY, fixture, processed_candidate


class Services:
    def __init__(self):
        self.candidate, self.original, self.processed, self.inventory = fixture()
        self.stack_id = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/{release.STACK}/example"
        self.change_id = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:changeSet/thn-registry-123-1/example"
        self.previous = {"EnvironmentName": "test", "FunctionMemorySize": "512", "SharedSecret": "****"}
        self.effective = dict(self.previous)
        self.calls = []
        self.executed = False
        self.bad_operator = self.bad_change_stack = self.bad_processed = self.changed_live = False
        self.post_variant = None
        self.original_reads = 0

    def client(self, service, **kwargs):
        self.calls.append(("client", service))
        return self

    def get_caller_identity(self):
        return {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/zoolanding-content-hub-test-deploy/release-123"}

    def describe_stacks(self, **kwargs):
        self.calls.append(("describe_stacks", kwargs))
        return {"Stacks": [{"StackId": self.stack_id, "StackName": release.STACK,
            "StackStatus": "UPDATE_COMPLETE", "EnableTerminationProtection": True,
            "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in self.effective.items()]}]}

    def get_role(self, **kwargs):
        self.calls.append(("get_role", kwargs))
        return {"Role": {"RoleName": subject.OPERATOR, "Arn": OPERATOR + ("-wrong" if self.bad_operator else "")}}

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        transformed = kwargs["TemplateStage"] == "Processed"
        if kwargs.get("ChangeSetName") or self.executed:
            result = processed_candidate(self.composed) if transformed else deepcopy(self.composed)
            if self.bad_processed and transformed:
                result["Resources"]["ContentHubApi"]["Properties"]["Body"]["host"] = "other.example.test"
            return {"TemplateBody": result}
        self.original_reads += not transformed
        result = deepcopy(self.processed if transformed else self.original)
        if self.changed_live and self.original_reads > 1:
            result["Description"] = "concurrent change"
        return {"TemplateBody": result}

    def list_stack_resources(self, **kwargs):
        self.calls.append(("inventory", kwargs))
        inventory = deepcopy(self.inventory)
        if self.executed:
            physical = {"ServiceBindingRegistryV2Table": release.REGISTRY_TABLE,
                        subject.FUNCTION: subject.FUNCTION_NAME, subject.ROLE: subject.ROLE_NAME}
            inventory.update({key: {"ResourceType": "AWS::Lambda::Function" if kind == "AWS::Serverless::Function" else kind,
                "PhysicalResourceId": physical.get(key, "physical-" + key)} for key, kind in REGISTRY.items()})
            if self.post_variant == "missing":
                inventory.pop(subject.ROLE)
            elif self.post_variant == "substitute":
                inventory[subject.ROLE]["ResourceType"] = "AWS::IAM::Policy"
            elif self.post_variant == "extra":
                inventory["Extra"] = {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "extra"}
            elif self.post_variant == "legacy-id":
                inventory["ContentHubApi"]["PhysicalResourceId"] = "replacement"
        rows = [{"LogicalResourceId": key, "ResourceStatus": "CREATE_COMPLETE", **item} for key, item in inventory.items()]
        if self.executed and self.post_variant == "duplicate":
            rows.append(rows[0])
        return {"StackResourceSummaries": rows}

    def put_object(self, **kwargs):
        self.calls.append(("put_object", {key: value for key, value in kwargs.items() if key != "Body"}))
        self.composed = json.loads(kwargs["Body"])

    def create_change_set(self, **kwargs):
        self.calls.append(("create_change_set", kwargs))
        self.pending_parameters = kwargs["Parameters"]
        self.requested = {**self.previous, **{entry["ParameterKey"]: entry["ParameterValue"] for entry in kwargs["Parameters"] if "ParameterValue" in entry}}
        return {"Id": self.change_id, "StackId": self.stack_id + ("-wrong" if self.bad_change_stack else "")}

    def describe_change_set(self, **kwargs):
        self.calls.append(("describe_change_set", kwargs))
        return {"ChangeSetId": self.change_id, "ChangeSetName": "thn-registry-123-1", "StackId": self.stack_id,
            "StackName": release.STACK, "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
            "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in self.requested.items()],
            "Changes": [{"Type": "Resource", "ResourceChange": {"Action": "Add", "LogicalResourceId": key,
                "ResourceType": "AWS::Lambda::Function" if kind == "AWS::Serverless::Function" else kind}} for key, kind in REGISTRY.items()]}

    def execute_change_set(self, **kwargs):
        self.calls.append(("execute_change_set", kwargs))
        self.executed = True
        self.effective = self.requested

    def delete_change_set(self, **kwargs):
        self.calls.append(("delete_change_set", kwargs))

    def get_waiter(self, name):
        return self

    def wait(self, **kwargs):
        pass

    def describe_table(self, **kwargs):
        self.calls.append(("describe_table", kwargs))
        return {"Table": {"TableName": release.REGISTRY_TABLE, "TableStatus": "ACTIVE",
            "DeletionProtectionEnabled": True, "SSEDescription": {"Status": "ENABLED"}}}

    def describe_continuous_backups(self, **kwargs):
        return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}}}

    def get_function_configuration(self, **kwargs):
        return {"FunctionName": subject.FUNCTION_NAME, "State": "Active", "LastUpdateStatus": "Successful",
                "Role": f"arn:aws:iam::{ACCOUNT}:role/{subject.ROLE_NAME}"}


class RegistryProvisionRunnerTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(subject, "run"), "The registry bootstrap runner is missing")
        self.session = Services()
        self.env = {"GITHUB_REPOSITORY": "LynxPardelle/zoolanding-content-hub", "GITHUB_REF": "refs/heads/test",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": "a" * 40, "EXPECTED_SOURCE_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "us-east-1",
            "ARTIFACTS_BUCKET": "example-artifacts", "THN_REGISTRY_OPERATOR_ROLE_ARN": OPERATOR}

    def run_bootstrap(self):
        with patch.object(release, "ACCOUNT_HASH", hashlib.sha256(ACCOUNT.encode()).hexdigest()), \
                patch.object(release, "_package_template", return_value=self.session.candidate), patch.object(subject.time, "sleep"):
            return subject.run(self.session, self.env, Path("example-build"))

    def test_exact_update_preserves_seventeen_and_observes_five_retained_private_additions_twice(self):
        result = self.run_bootstrap()
        self.assertEqual((result["preserved_resource_count"], result["new_resource_count"]), (17, 5))
        request = next(value for name, value in self.session.calls if name == "create_change_set")
        self.assertEqual(request["ChangeSetType"], "UPDATE")
        self.assertNotIn("RoleARN", request)
        self.assertEqual(request["StackName"], self.session.stack_id)
        self.assertEqual([entry["ParameterKey"] for entry in request["Parameters"] if "ParameterValue" in entry], [subject.PARAMETER])
        self.assertEqual(sum(name == "describe_table" for name, _ in self.session.calls), 2)
        self.assertFalse(any(name in {"get_item", "invoke", "delete_stack", "update_termination_protection"} for name, _ in self.session.calls))

    def test_sdk_processed_map_order_allows_only_the_reviewed_five_additions(self):
        original_get_template = self.session.get_template
        def sdk_get_template(**kwargs):
            response = original_get_template(**kwargs)
            if kwargs["TemplateStage"] == "Processed":
                reverse = bool(kwargs.get("ChangeSetName") or self.session.executed)
                response["TemplateBody"] = json.loads(json.dumps(response["TemplateBody"]),
                    object_pairs_hook=lambda pairs: OrderedDict(reversed(pairs) if reverse else pairs))
            return response
        with patch.object(self.session, "get_template", side_effect=sdk_get_template):
            outcome = None
            try:
                outcome = self.run_bootstrap()
            except release.ReleaseBlocked:
                pass
            self.assertIsNotNone(outcome, "Order-only SDK output must pass unchanged-content checks")
        self.assertEqual((outcome["preserved_resource_count"], outcome["new_resource_count"]), (17, 5))
        self.assertEqual(sum(name == "describe_table" for name, _ in self.session.calls), 2)
        self.assertFalse(any(name in {"get_item", "invoke", "delete_stack", "update_termination_protection"}
                             for name, _ in self.session.calls))

    def test_request_metadata_changes_do_not_block_the_unchanged_registry_payload(self):
        describe = self.session.describe_change_set
        responses = []
        snapshots = []
        def sdk_describe(**kwargs):
            response = describe(**kwargs)
            index = len(responses) + 1
            response["ResponseMetadata"] = {"RequestId": f"synthetic-request-{index}",
                "HTTPStatusCode": 200, "RetryAttempts": index - 1,
                "HTTPHeaders": {"date": f"synthetic-date-{index}"}}
            response["AdditionalResult"] = {"ResponseMetadata": {"Value": "stable"}}
            responses.append(response)
            snapshots.append(deepcopy(response))
            return response
        with patch.object(self.session, "describe_change_set", side_effect=sdk_describe):
            outcome = None
            try:
                outcome = self.run_bootstrap()
            except release.ReleaseBlocked:
                pass
            self.assertIsNotNone(outcome, "Request-only SDK metadata must not block an unchanged change set")
        self.assertEqual((outcome["preserved_resource_count"], outcome["new_resource_count"]), (17, 5))
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses, snapshots, "Comparisons must not mutate the SDK responses")
        self.assertEqual(sum(name == "describe_table" for name, _ in self.session.calls), 2)
        self.assertFalse(any(name in {"get_item", "invoke", "delete_stack", "update_termination_protection"}
                             for name, _ in self.session.calls))

    def test_second_read_payload_drift_still_blocks_execution_and_cleans_own_change_set(self):
        mutations = [
            (("ChangeSetId",), "different-change-set"),
            (("ChangeSetName",), "different-name"),
            (("StackId",), "different-stack"),
            (("StackName",), "different-stack-name"),
            (("Status",), "FAILED"),
            (("ExecutionStatus",), "UNAVAILABLE"),
            (("Parameters", 0, "ParameterValue"), "different-value"),
            (("Changes", 0, "ResourceChange", "Action"), "Modify"),
            (("Changes", 0, "ResourceChange", "Replacement"), "True"),
            (("Changes",), []),
            (("AdditionalResult", "ResponseMetadata", "Value"), "different-nested-value"),
            (("UnknownField",), "new-payload-field"),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                self.session = Services()
                describe = self.session.describe_change_set
                reads = 0
                def sdk_describe(**kwargs):
                    nonlocal reads
                    reads += 1
                    response = describe(**kwargs)
                    response["ResponseMetadata"] = {"RequestId": f"synthetic-request-{reads}"}
                    response["AdditionalResult"] = {"ResponseMetadata": {"Value": "stable"}}
                    if reads == 2:
                        target = response
                        for key in path[:-1]:
                            target = target[key]
                        target[path[-1]] = value
                    return response
                with patch.object(self.session, "describe_change_set", side_effect=sdk_describe), \
                        self.assertRaisesRegex(release.ReleaseBlocked, "^registry_bootstrap_changed_during_review$"):
                    self.run_bootstrap()
                self.assertEqual(reads, 2)
                self.assertFalse(self.session.executed)
                self.assertEqual([value for name, value in self.session.calls if name == "delete_change_set"],
                    [{"StackName": self.session.stack_id, "ChangeSetName": self.session.change_id}])

    def test_missing_human_operator_stops_before_packaging_or_changeset(self):
        self.session.bad_operator = True
        with self.assertRaises(release.ReleaseBlocked):
            self.run_bootstrap()
        self.assertNotIn("put_object", [name for name, _ in self.session.calls])

    def test_returned_stack_confusion_or_processed_v1_change_never_executes(self):
        for field in ("bad_change_stack", "bad_processed", "changed_live"):
            self.session = Services()
            setattr(self.session, field, True)
            with self.subTest(field=field), self.assertRaises(release.ReleaseBlocked):
                self.run_bootstrap()
            self.assertFalse(self.session.executed)

    def test_duplicate_substitution_missing_extra_and_changed_legacy_identity_fail_readback(self):
        for variant in ("missing", "duplicate", "substitute", "extra", "legacy-id"):
            self.session = Services()
            self.session.post_variant = variant
            with self.subTest(variant=variant), self.assertRaises(release.ReleaseBlocked):
                self.run_bootstrap()

    def test_processed_diagnostic_keeps_rejection_and_own_changeset_cleanup(self):
        self.session.bad_processed = True
        with self.assertRaises(release.ReleaseBlocked) as raised:
            self.run_bootstrap()
        self.assertIn('"differences"', str(raised.exception))
        self.assertNotIn("other.example.test", str(raised.exception))
        self.assertFalse(self.session.executed)
        deleted = [value for name, value in self.session.calls if name == "delete_change_set"]
        self.assertEqual(deleted, [{"StackName": self.session.stack_id, "ChangeSetName": self.session.change_id}])

    def test_retry_after_bootstrap_cannot_recreate_or_modify_the_registry(self):
        self.run_bootstrap()
        self.session.calls.clear()
        with self.assertRaises(release.ReleaseBlocked):
            self.run_bootstrap()
        self.assertNotIn("put_object", [name for name, _ in self.session.calls])


if __name__ == "__main__":
    unittest.main()
