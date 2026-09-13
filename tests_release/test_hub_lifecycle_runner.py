"""Exercise the real lifecycle/review/readbacks with an in-memory AWS boundary.

The fixture models SDK responses, not SAM/provider semantics; native translation
and a provider-accepted change set remain separate deployment checks.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import thn_test_release as release
import test_hub_failed_change_set as failed
from test_thn_test_release import ACCOUNT


class LifecycleCloud(failed.Cloud):
    def __init__(self):
        super().__init__()
        self.status, self.execution_status = "CREATE_COMPLETE", "AVAILABLE"
        self.executed = False
        self.noop = False
        self.corrupt_runtime = False
        self.corrupt_shared = False
        self.retention_reads = 0
        self.alias_reads = 0
        self.noop_described = False
        self.drift_on_noop = False
        self.current_inventory = super().list_stack_resources()["StackResourceSummaries"]

    def native(self, template):
        result = deepcopy(template)
        result["Resources"]["ContentHubApi"] = deepcopy(self.processed["Resources"]["ContentHubApi"])
        result["Resources"]["ContentHubApi"]["Properties"]["Body"] = deepcopy(
            template["Resources"]["ContentHubApi"]["Properties"]["DefinitionBody"])
        for pair in release.PAIRS:
            function = release.PREFIX + pair + "Function"
            result["Resources"][function]["Type"] = "AWS::Lambda::Function"
            result["Resources"][function + "Aliastest"] = {"Type": "AWS::Lambda::Alias",
                "Condition": "IsThnContentHubV2StateProvisioned", "Properties": {"Name": "test"}}
            result["Resources"][function + "Version0123456789"] = {"Type": "AWS::Lambda::Version",
                "Condition": "IsThnContentHubV2StateProvisioned", "DeletionPolicy": "Retain"}
        for resource in result["Resources"].values():
            if resource["Type"] == "AWS::Lambda::Permission":
                reference = resource["Properties"].get("FunctionName", {}).get("Ref", "")
                if reference.endswith(".Alias"):
                    resource["Properties"]["FunctionName"] = {"Ref": reference.replace(".Alias", "Aliastest")}
        return result

    def create_change_set(self, **kwargs):
        result = super().create_change_set(**kwargs)
        self.planned_native = self.native(self.uploaded_template)
        if self.corrupt_shared:
            self.planned_native["Resources"]["ContentHubFunction"]["Properties"]["Timeout"] = 999
        return result

    def describe_change_set(self, **kwargs):
        result = super().describe_change_set(**kwargs)
        if self.noop:
            result.update(Status="FAILED", ExecutionStatus="UNAVAILABLE", StatusReason=release.ordinary_review._NO_CHANGE_REASON)
            self.noop_described = True
        else:
            result["Changes"] = [{"Type": "Resource", "ResourceChange": {"Action": "Add",
                "LogicalResourceId": release.PREFIX + "AuthoringFunction", "ResourceType": "AWS::Lambda::Function",
                "Replacement": "False"}}]
        return result

    def describe_stacks(self, **kwargs):
        result = super().describe_stacks(**kwargs)
        if self.noop_described and self.drift_on_noop:
            result["Stacks"][0]["Parameters"][0]["ParameterValue"] = "changed"
        return result

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        if kwargs.get("ChangeSetName"):
            if self.noop:
                return super().get_template(**kwargs)  # Failed no-op has no Processed template.
            return {"TemplateBody": deepcopy(self.uploaded_template if kwargs["TemplateStage"] == "Original" else self.planned_native)}
        return {"TemplateBody": deepcopy(self.original if kwargs["TemplateStage"] == "Original" else self.processed)}

    def list_stack_resources(self, **_kwargs):
        return {"StackResourceSummaries": deepcopy(self.current_inventory)}

    def install(self):
        self.original, self.processed = deepcopy(self.uploaded_template), deepcopy(self.planned_native)
        self.stack["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in self.expected.items()]
        for logical, resource in self.processed["Resources"].items():
            if not logical.startswith(release.PREFIX) or resource["Type"] not in release.STATE_TYPES | release.PERSISTENT_RUNTIME_TYPES | {"AWS::Lambda::Version"}:
                continue
            props = resource.get("Properties", {})
            physical = next((props[k] for k in ("FunctionName", "RoleName", "TableName") if k in props), "synthetic-" + logical)
            self.current_inventory.append({"LogicalResourceId": logical, "PhysicalResourceId": physical,
                "ResourceType": resource["Type"], "ResourceStatus": "CREATE_COMPLETE"})

    def execute_change_set(self, **kwargs):
        self.calls.append(("execute_change_set", kwargs))
        self.executed = True
        self.install()

    def get_waiter(self, name):
        assert name == "stack_update_complete"
        return self

    def wait(self, **_kwargs):
        assert self.executed

    def get_function_configuration(self, FunctionName):
        for pair in release.PAIRS:
            props = self.original["Resources"][release.PREFIX + pair + "Function"]["Properties"]
            if FunctionName.endswith(":" + props["FunctionName"]):
                role = self.original["Resources"][release.PREFIX + pair + "Role"]["Properties"]["RoleName"]
                return {"State": "Failed" if self.corrupt_runtime else "Active", "LastUpdateStatus": "Successful",
                    "Role": f"arn:aws:iam::{ACCOUNT}:role/{role}"}
        raise AssertionError("Unexpected function")

    def get_alias(self, FunctionName, Name):
        self.alias_reads += 1
        return {"Name": Name, "AliasArn": FunctionName + ":" + Name, "FunctionVersion": "1"}

    def describe_table(self, **_kwargs):
        self.retention_reads += 1
        return {"Table": {"TableStatus": "ACTIVE", "DeletionProtectionEnabled": True, "SSEDescription": {"Status": "ENABLED"}}}

    def describe_continuous_backups(self, **_kwargs):
        return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}}}

    def get_bucket_versioning(self, **_kwargs):
        return {"Status": "Enabled"}

    def get_public_access_block(self, **_kwargs):
        return {"PublicAccessBlockConfiguration": {k: True for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")}}

    def get_bucket_encryption(self, **_kwargs):
        return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}


class HubLifecycleRunnerTests(unittest.TestCase):
    def setUp(self):
        seed = failed.HubFailedChangeSetTests(); seed.setUp()
        self.env = seed.env
        self.cloud = LifecycleCloud()

    def run_release(self):
        with patch.object(release, "ACCOUNT_HASH", hashlib.sha256(ACCOUNT.encode()).hexdigest()), \
                patch.object(release, "_package_template", return_value=self.cloud.source), patch.object(release.time, "sleep"):
            return release.run_release(self.cloud, self.env, Path("unused-build"), "provision")

    def test_successful_provision_executes_exact_plan_and_checks_retention_twice(self):
        result = self.run_release()
        self.assertEqual(result["decision"], "executed")
        self.assertEqual(self.cloud.alias_reads, 14)
        self.assertEqual(self.cloud.retention_reads, 4)
        self.assertEqual([args["ChangeSetName"] for name, args in self.cloud.calls if name == "execute_change_set"], [self.cloud.change_id])
        self.assertFalse(any(name == "delete_change_set" for name, _ in self.cloud.calls))

    def test_shared_processed_drift_stops_before_execution(self):
        self.cloud.corrupt_shared = True
        with self.assertRaisesRegex(release.ReleaseBlocked, "processed_shared_resource_drift"):
            self.run_release()
        self.assertFalse(self.cloud.executed)

    def test_failed_runtime_readback_does_not_claim_success(self):
        self.cloud.corrupt_runtime = True
        with self.assertRaisesRegex(release.ReleaseBlocked, "retained_runtime_readback_mismatch"):
            self.run_release()
        self.assertTrue(self.cloud.executed)

    def test_true_noop_checks_live_state_without_reading_unavailable_plan_template(self):
        self.run_release()
        self.cloud.calls.clear(); self.cloud.noop = True; self.cloud.executed = False
        self.cloud.alias_reads = self.cloud.retention_reads = 0
        result = self.run_release()
        self.assertEqual(result["decision"], "noop")
        self.assertFalse(self.cloud.executed)
        self.assertEqual(self.cloud.alias_reads, 7)
        self.assertFalse(any(name == "get_template" and "ChangeSetName" in args for name, args in self.cloud.calls))

    def test_noop_rechecks_concurrent_stack_drift_before_claiming_success(self):
        self.run_release()
        self.cloud.noop = self.cloud.drift_on_noop = True
        with self.assertRaises(release.ReleaseBlocked):
            self.run_release()


if __name__ == "__main__":
    unittest.main()
