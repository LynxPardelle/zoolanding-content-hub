"""The first Hub state release must preserve the four imported identities."""

import copy
import os
import unittest
from unittest.mock import Mock, patch

from tools import run_thn_production_release as driver
from tools import thn_production_import as imported
from tools.thn_production_release import review_inventory


def post_import_baseline():
    old = {f"Legacy{i:02d}": {"Type": "AWS::IAM::Role"} for i in range(17)}
    original = {f"Legacy{i:02d}": old[f"Legacy{i:02d}"] for i in range(10)}
    targets = {}
    resources = [
        {"LogicalResourceId": name, "PhysicalResourceId": f"legacy-{name}",
         "ResourceType": value["Type"]} for name, value in old.items()
    ]
    for logical, (kind, physical) in imported.TARGETS.items():
        property_name = "BucketName" if kind == "AWS::S3::Bucket" else "TableName"
        target = {"Type": kind, "DeletionPolicy": "Retain",
                  "UpdateReplacePolicy": "Retain",
                  "Properties": {property_name: physical}}
        targets[logical] = target
        original[logical] = copy.deepcopy(target)
        old[logical] = copy.deepcopy(target)
        resources.append({"LogicalResourceId": logical,
                          "PhysicalResourceId": physical, "ResourceType": kind})
    return {"stackId": "arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/id",
            "status": "IMPORT_COMPLETE", "terminationProtection": True,
            "roleArn": "arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec",
            "tags": [], "parameters": [],
            "original": {"Transform": "AWS::Serverless-2016-10-31",
                         "Parameters": {}, "Resources": original},
            "processed": {"Resources": old}, "resources": resources}, targets


class PostImportStateTests(unittest.TestCase):
    def test_release_failure_code_reports_only_closed_guard_reasons(self):
        self.assertEqual(driver.safe_failure_code(imported.ImportError(
            "production_post_import_registry_policy_changed")),
            "production_post_import_registry_policy_changed")
        self.assertEqual(driver.safe_failure_code(imported.ImportError(
            "unsafe provider text\nsecret")), "ImportError")
        self.assertEqual(driver.safe_failure_code(ValueError("sensitive detail")),
                         "ValueError")

    def test_registry_transition_rebinds_only_four_allows_and_preserves_denies(self):
        role_arn = "arn:aws:iam::765932874577:role/zoolanding-thn-registry-production-mutation"
        old_id = "AROA3EVJIFNI4YJ2FP2VF"
        allowed = (
            "AllowRegistryMutationFunctionDescribe",
            "AllowRegistryMutationFunctionExactRead",
            "AllowRegistryMutationFunctionAtomicPut",
            "AllowRegistryMutationFunctionAtomicConditionCheck",
        )
        live = {"Version": "2012-10-17", "Statement": [
            {"Sid": sid, "Effect": "Allow", "Principal": {"AWS": old_id},
             "Action": "dynamodb:DescribeTable", "Resource": "arn:aws:dynamodb:us-east-1:765932874577:table/registry"}
            for sid in allowed
        ] + [
            {"Sid": f"DenyOther{i:02d}", "Effect": "Deny", "Principal": "*",
             "Action": ["dynamodb:DeleteItem"], "Resource": "arn:aws:dynamodb:us-east-1:765932874577:table/registry"}
            for i in range(22)
        ]}
        proposed = copy.deepcopy(live)
        proposed["Statement"].reverse()
        for statement in proposed["Statement"]:
            statement["Action"] = ([statement["Action"]] if isinstance(statement["Action"], str)
                                    else statement["Action"][0])
            statement["Resource"] = {"Fn::Sub": "arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/registry"}
            if statement["Sid"] in allowed:
                statement["Principal"]["AWS"] = {"Fn::GetAtt": ["ServiceBindingRegistryV2MutationRole", "Arn"]}
        proof = imported.validate_registry_policy_transition(live, proposed, role_arn)
        self.assertEqual(proof["reboundSids"], sorted(allowed))
        self.assertNotEqual(proof["beforeSemanticSha256"], proof["targetSemanticSha256"])
        weakened = copy.deepcopy(proposed)
        next(item for item in weakened["Statement"] if item["Sid"] == "DenyOther00")["Action"] = "dynamodb:Scan"
        with self.assertRaises(imported.ImportError):
            imported.validate_registry_policy_transition(live, weakened, role_arn)
        wrong_role = copy.deepcopy(live)
        wrong_role["Statement"][0]["Principal"]["AWS"] = "AROAOTHER"
        with self.assertRaises(imported.ImportError):
            imported.validate_registry_policy_transition(wrong_role, proposed, role_arn)

    def test_completed_registry_policy_binds_new_role_without_losing_denies(self):
        role_arn = imported.MUTATION_ROLE_ARN
        new_id = "AROANEWROLEID"
        allowed = sorted(imported.MUTATION_ALLOW_SIDS)
        target = {"Version": "2012-10-17", "Statement": [
            {"Sid": sid, "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "dynamodb:DescribeTable", "Resource": "registry"}
            for sid in allowed
        ] + [
            {"Sid": f"DenyOther{i:02d}", "Effect": "Deny", "Principal": "*",
             "Action": "dynamodb:DeleteItem", "Resource": "registry"}
            for i in range(22)
        ]}
        live = copy.deepcopy(target)
        for statement in live["Statement"][:4]:
            statement["Principal"]["AWS"] = new_id
        imported.validate_completed_registry_policy(live, target, role_arn)
        with self.assertRaises(imported.ImportError):
            imported.validate_completed_registry_policy(live, target, role_arn,
                                                       imported.ORPHAN_MUTATION_ROLE_ID)
        weakened = copy.deepcopy(live)
        weakened["Statement"][-1]["Action"] = "dynamodb:Scan"
        with self.assertRaises(imported.ImportError):
            imported.validate_completed_registry_policy(weakened, target, role_arn)
        inconsistent = copy.deepcopy(live)
        inconsistent["Statement"][0]["Principal"]["AWS"] = "AROADIFFERENT"
        with self.assertRaises(imported.ImportError):
            imported.validate_completed_registry_policy(inconsistent, target, role_arn)

    def test_state_baseline_fingerprints_live_imported_resources_and_policy(self):
        baseline, _ = post_import_baseline()
        session = Mock()
        live = {"policyRevision": "1790716784435",
                "policySemanticSha256": "746729dad0f26e808c342c6c07fdc055a99ff197e43f7e8d1249d663985dbaf8",
                "policyDocument": {"Version": "2012-10-17", "Statement": []},
                "identities": {"stable": True}, "tables": {}, "bucket": {}}
        with patch.dict(os.environ, {"THN_PRODUCTION_SELECTED_PURPOSE": "state"}), \
                patch.object(driver.release, "snapshot", return_value=baseline), \
                patch("tools.run_thn_production_import.read_targets", return_value=live) as capture:
            result = driver.captured_baseline(session)
        capture.assert_called_once()
        self.assertEqual(result["postImportTargets"], live)
        changed = {**live, "policySemanticSha256": "0" * 64}
        with patch.dict(os.environ, {"THN_PRODUCTION_SELECTED_PURPOSE": "state"}), \
                patch.object(driver.release, "snapshot", return_value=baseline), \
                patch("tools.run_thn_production_import.read_targets", return_value=changed):
            with self.assertRaises(imported.ImportError):
                driver.captured_baseline(session)

    def test_state_baseline_requires_all_four_imported_identities(self):
        baseline, _ = post_import_baseline()
        imported.validate_post_import_state_baseline(baseline)
        intrinsic = copy.deepcopy(baseline)
        intrinsic["original"]["Resources"]["ThnContentHubV2PrivateStore"]["Properties"]["BucketName"] = {
            "Fn::Sub": "zlp-thn-ch-production-private-${AWS::AccountId}-${AWS::Region}"}
        imported.validate_post_import_state_baseline(intrinsic)
        for mutation in ("missing", "replaced", "unprotected"):
            changed = copy.deepcopy(baseline)
            if mutation == "missing":
                changed["resources"].pop()
            elif mutation == "replaced":
                changed["resources"][-1]["PhysicalResourceId"] = "other-bucket"
            else:
                changed["terminationProtection"] = False
            with self.subTest(mutation=mutation), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_baseline(changed)

    def test_state_candidate_preserves_other_imported_declarations_and_public_api(self):
        baseline, targets = post_import_baseline()
        baseline["original"]["Resources"]["ContentHubApi"] = {"Type": "AWS::Serverless::HttpApi", "Properties": {"StageName": "prod"}}
        baseline["original"]["Resources"]["ContentHubFunction"] = {
            "Type": "AWS::Serverless::Function",
            "Properties": {"CodeUri": "s3://historical/function.zip"}}
        baseline["original"]["Parameters"]["LegacySetting"] = {
            "Type": "String", "Default": "historical"}
        registry = copy.deepcopy(targets["ServiceBindingRegistryV2Table"])
        registry["Condition"] = "ProvisionRegistry"
        registry["Properties"]["ResourcePolicy"] = {"PolicyDocument": {"Statement": [
            {"Sid": "DenyUnapproved", "Effect": "Deny"}]}}
        candidate = {"Parameters": {"LegacySetting": {"Type": "String", "Default": "new"}}, "Resources": {
            **{name: {**value, "Condition": "ProvisionState", "Properties": {"changed": True}}
               for name, value in targets.items()},
            "ServiceBindingRegistryV2Table": registry,
            "ContentHubApi": {"Type": "AWS::Serverless::HttpApi", "Properties": {"StageName": "other"}},
            "ContentHubFunction": {"Type": "AWS::Serverless::Function",
                                   "Properties": {"CodeUri": "s3://new/function.zip"}},
            "ServiceBindingRegistryV2MutationRole": {"Type": "AWS::IAM::Role"},
            "ThnContentHubV2AuthoringRole": {"Type": "AWS::IAM::Role"},
        }}
        selected = driver.candidate_for_scope(candidate, baseline, "state")
        for logical in (*[name for name in targets if name != "ServiceBindingRegistryV2Table"], "ContentHubApi"):
            self.assertEqual(selected["Resources"][logical], baseline["original"]["Resources"][logical])
        expected = copy.deepcopy(registry)
        expected.pop("Condition")
        self.assertEqual(selected["Resources"]["ServiceBindingRegistryV2Table"], expected)
        self.assertIn("ThnContentHubV2AuthoringRole", selected["Resources"])
        baseline["original"]["Resources"]["ContentHubFunction"]["Properties"]["CodeUri"] = {
            "Bucket": "recovery", "Key": "previous.zip", "Version": "v1"}
        baseline["original"]["Resources"]["ContentHubApi"]["Properties"]["StageName"] = "recovery"
        baseline["original"]["Resources"]["ThnContentHubV2AuditTable"]["Properties"]["changed"] = True
        baseline["original"]["Parameters"]["LegacySetting"]["Default"] = "recovery"
        self.assertEqual(selected["Resources"]["ContentHubFunction"]["Properties"]["CodeUri"],
                         "s3://historical/function.zip")
        self.assertEqual(selected["Resources"]["ContentHubApi"]["Properties"]["StageName"], "prod")
        self.assertNotIn("changed", selected["Resources"]["ThnContentHubV2AuditTable"]["Properties"])
        self.assertEqual(selected["Parameters"]["LegacySetting"]["Default"], "historical")

    def test_state_candidate_restores_only_registry_policy(self):
        baseline, targets = post_import_baseline()
        baseline["original"]["Resources"]["ContentHubApi"] = {
            "Type": "AWS::Serverless::HttpApi", "Properties": {"StageName": "prod"}}
        registry = copy.deepcopy(targets["ServiceBindingRegistryV2Table"])
        registry["Properties"]["ResourcePolicy"] = {
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Sid": "DenyUnapproved", "Effect": "Deny", "Principal": "*",
                 "Action": "dynamodb:DeleteItem", "Resource": "registry"}]}}
        candidate = {"Parameters": {}, "Resources": {
            **{name: {**value, "Properties": {"changed": True}}
               for name, value in targets.items()},
            "ServiceBindingRegistryV2Table": registry,
            "ServiceBindingRegistryV2MutationRole": {"Type": "AWS::IAM::Role"},
        }}
        selected = driver.candidate_for_scope(candidate, baseline, "state")
        self.assertEqual(selected["Resources"]["ServiceBindingRegistryV2Table"], registry)
        for logical in set(targets) - {"ServiceBindingRegistryV2Table"}:
            self.assertEqual(selected["Resources"][logical], baseline["original"]["Resources"][logical])

    def test_state_inventory_accepts_only_nonreplacing_registry_policy_modify(self):
        baseline, _ = post_import_baseline()
        registry = {"ResourceChange": {"Action": "Modify",
                    "LogicalResourceId": "ServiceBindingRegistryV2Table",
                    "ResourceType": "AWS::DynamoDB::Table", "Replacement": "False",
                    "Details": [{"Target": {"Attribute": "Properties", "Name": "ResourcePolicy"},
                                 "Evaluation": "Static", "ChangeSource": "DirectModification"}]}}
        imported.validate_post_import_state_inventory([registry], baseline)
        with self.assertRaises(imported.ImportError):
            imported.validate_post_import_state_inventory([], baseline)
        for change in (
            {**registry["ResourceChange"], "Replacement": "Conditional"},
            {**registry["ResourceChange"], "Details": [{"Target": {
                "Attribute": "Properties", "Name": "DeletionProtectionEnabled"}}]},
            {**registry["ResourceChange"], "LogicalResourceId": "ThnContentHubV2AuditTable"},
        ):
            with self.subTest(change=change), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_inventory(
                    [{"ResourceChange": change}], baseline)

    def test_state_completion_accepts_new_role_and_preserves_imported_identities(self):
        before, _ = post_import_baseline()
        after = copy.deepcopy(before)
        after["status"] = "UPDATE_COMPLETE"
        after["original"]["Resources"]["ServiceBindingRegistryV2Table"]["Properties"]["ResourcePolicy"] = {
            "PolicyDocument": {"Statement": [{"Sid": "DenyUnapproved"}]}}
        after["original"]["Resources"]["ServiceBindingRegistryV2MutationRole"] = {"Type": "AWS::IAM::Role"}
        after["processed"]["Resources"]["ServiceBindingRegistryV2MutationRole"] = {"Type": "AWS::IAM::Role"}
        after["resources"].append({"LogicalResourceId": "ServiceBindingRegistryV2MutationRole",
                                   "PhysicalResourceId": "zoolanding-thn-registry-production-mutation",
                                   "ResourceType": "AWS::IAM::Role"})
        changes = [{"ResourceChange": {"Action": "Add", "Replacement": None,
                    "LogicalResourceId": "ServiceBindingRegistryV2MutationRole",
                    "ResourceType": "AWS::IAM::Role"}},
                   {"ResourceChange": {"Action": "Modify", "Replacement": "False",
                    "LogicalResourceId": "ServiceBindingRegistryV2Table",
                    "ResourceType": "AWS::DynamoDB::Table", "Details": [{"Target": {
                        "Attribute": "Properties", "Name": "ResourcePolicy"}}]}}]
        imported.validate_post_import_state_completion(before, after, changes)
        with_dormant_condition = copy.deepcopy(after)
        with_dormant_condition["processed"]["Resources"]["InactiveOptionalRole"] = {
            "Type": "AWS::IAM::Role", "Condition": "OptionalRoleEnabled"}
        imported.validate_post_import_state_completion(before, with_dormant_condition, changes)
        for mutation in ("replacement", "unexpected", "unconditional_missing", "status", "opened_routes"):
            invalid = copy.deepcopy(after)
            if mutation == "replacement":
                next(row for row in invalid["resources"] if row["LogicalResourceId"] ==
                     "ServiceBindingRegistryV2Table")["PhysicalResourceId"] = "replacement"
            elif mutation == "unexpected":
                invalid["resources"].append({"LogicalResourceId": "Unknown",
                                             "PhysicalResourceId": "unknown", "ResourceType": "AWS::IAM::Role"})
            elif mutation == "unconditional_missing":
                invalid["processed"]["Resources"]["MissingRole"] = {"Type": "AWS::IAM::Role"}
            elif mutation == "status":
                invalid["status"] = "UPDATE_ROLLBACK_COMPLETE"
            else:
                invalid["parameters"] = [{"ParameterKey": "EnableThnContentHubV2",
                                          "ParameterValue": "true"}]
            with self.subTest(mutation=mutation), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_completion(before, invalid, changes)

    def test_state_inventory_rejects_existing_resource_modification(self):
        baseline, _ = post_import_baseline()
        added = [{"ResourceChange": {"Action": "Add", "LogicalResourceId": "ThnContentHubV2AuthoringRole",
                                      "ResourceType": "AWS::IAM::Role", "Replacement": "False"}}]
        registry = {"ResourceChange": {"Action": "Modify",
                    "LogicalResourceId": "ServiceBindingRegistryV2Table",
                    "ResourceType": "AWS::DynamoDB::Table", "Replacement": "False",
                    "Details": [{"Target": {"Attribute": "Properties", "Name": "ResourcePolicy"}}]}}
        imported.validate_post_import_state_inventory(added + [registry], baseline)
        nullable = copy.deepcopy(added)
        nullable[0]["ResourceChange"]["Replacement"] = None
        review_inventory(nullable, baseline["processed"],
                         {"Resources": {"ThnContentHubV2AuthoringRole": {"Type": "AWS::IAM::Role"}}},
                         scope="state")
        imported.validate_post_import_state_inventory(nullable + [registry], baseline)
        for logical in ("ThnContentHubV2PrivateStore", "Legacy00"):
            changed = added + [registry, {"ResourceChange": {"Action": "Modify", "LogicalResourceId": logical,
                                               "ResourceType": "AWS::S3::Bucket", "Replacement": "False"}}]
            with self.subTest(logical=logical), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_inventory(changed, baseline)


if __name__ == "__main__":
    unittest.main()
