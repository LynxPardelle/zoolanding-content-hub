"""Closed production Registry policy revision for the API deployment role."""

import copy
import unittest

from tools import thn_production_release as release
from tools import run_thn_production_release as driver
from unittest.mock import patch
from unittest.mock import Mock
import os
import json
from pathlib import Path
import yaml


API_ROLE = "arn:aws:iam::765932874577:role/zoolanding-deployer-thn-auth-runtime-production-github-deploy"
HUB_ROLE = "arn:aws:iam::765932874577:role/zoolanding-content-hub-production-deploy"
IMAGE_ROLE = "arn:aws:iam::765932874577:role/zoolanding-deployer-image-upload-production-github-deploy"
TABLE = "ServiceBindingRegistryV2Table"


def fixture():
    statements = [
        {"Sid": "DenyRegistryGetItemOutsideApprovedConsumers", "Effect": "Deny",
         "Principal": "*", "Action": ["dynamodb:GetItem"], "Resource": "registry",
         "Condition": {"ArnNotEquals": {"aws:PrincipalArn": [
             "arn:aws:iam::765932874577:role/existing-%02d" % i for i in range(13)
         ]}}},
    ]
    statements.extend(
        {"Sid": sid, "Effect": "Deny", "Principal": {"AWS": [HUB_ROLE, IMAGE_ROLE]},
         "Action": ["dynamodb:GetItem"], "Resource": "registry",
         "Condition": {condition: {"dynamodb:LeadingKeys": value}}}
        for sid, condition, value in (
            ("DenyRegistryDeploymentReadOutsideBinding", "ForAnyValue:StringNotEquals",
             ["SERVICE_BINDING#production#thn-journal-production-v2"]),
            ("DenyRegistryDeploymentReadMissingKeys", "Null", "true"),
        )
    )
    return {"Parameters": {"EnableThnContentHubV2": {"Default": "false"}},
            "Resources": {TABLE: {"Type": "AWS::DynamoDB::Table",
                                  "Properties": {"ResourcePolicy": {"PolicyDocument": {
                                      "Version": "2012-10-17", "Statement": statements}}}},
                          "Other": {"Type": "AWS::IAM::Role"}}}


def native_change():
    return {"Type": "Resource", "ResourceChange": {
        "Action": "Modify", "LogicalResourceId": TABLE,
        "PhysicalResourceId": "zoolanding-content-hub-prod-ServiceBindingRegistryV2",
        "ResourceType": "AWS::DynamoDB::Table", "Replacement": "False",
        "Scope": ["Properties"], "Details": [{"Target": {
            "Attribute": "Properties", "Name": "ResourcePolicy",
            "RequiresRecreation": "Never"}, "ChangeSource": "DirectModification"}]}}


class RegistryReaderPatchTests(unittest.TestCase):
    def test_workflow_keeps_protected_release_and_skips_repackaging(self):
        workflow=yaml.safe_load((Path(__file__).resolve().parents[1]/
            '.github/workflows/deploy-thn-production.yml').read_text())
        self.assertIn('registry-reader-patch',workflow[True]['workflow_dispatch']['inputs']['purpose']['options'])
        steps={step['name']:step for step in workflow['jobs']['release']['steps'] if 'name' in step}
        for name in ('Set up SAM for review only','Validate and build closed production source',
                     'Package new candidate only for review'):
            self.assertIn("inputs.purpose != 'registry-reader-patch'",steps[name]['if'])
        self.assertEqual(workflow['jobs']['release']['environment'],'production')
        self.assertIn('test_thn_production_registry_reader_patch.py',
            next(step['run'] for step in workflow['jobs']['validate']['steps']
                 if step.get('name')=='Run offline guards'))

    def test_candidate_changes_only_three_exact_principal_lists(self):
        old = fixture()
        proposed = release.registry_reader_candidate_template(old)
        self.assertEqual(old, fixture())
        self.assertEqual(proposed["Parameters"], old["Parameters"])
        self.assertEqual(proposed["Resources"]["Other"], old["Resources"]["Other"])
        statements = {row["Sid"]: row for row in proposed["Resources"][TABLE]
                      ["Properties"]["ResourcePolicy"]["PolicyDocument"]["Statement"]}
        self.assertEqual(statements["DenyRegistryGetItemOutsideApprovedConsumers"]
                         ["Condition"]["ArnNotEquals"]["aws:PrincipalArn"][-1], API_ROLE)
        for sid in ("DenyRegistryDeploymentReadOutsideBinding",
                    "DenyRegistryDeploymentReadMissingKeys"):
            self.assertEqual(statements[sid]["Principal"]["AWS"], [HUB_ROLE, IMAGE_ROLE, API_ROLE])
        self.assertEqual(release.PURPOSES.intersection({"registry-reader-patch"}),
                         {"registry-reader-patch"})

    def test_candidate_rejects_duplicate_missing_and_changed_readers(self):
        for mutation in ("duplicate", "missing", "extra", "other-statement"):
            old = fixture()
            statements = old["Resources"][TABLE]["Properties"]["ResourcePolicy"]["PolicyDocument"]["Statement"]
            if mutation == "duplicate":
                statements[0]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"].append(API_ROLE)
            elif mutation == "missing":
                statements.pop(1)
            elif mutation == "extra":
                statements[1]["Principal"]["AWS"].append("arn:aws:iam::765932874577:role/other")
            else:
                statements[2]["Action"] = ["dynamodb:Scan"]
            with self.subTest(mutation=mutation), self.assertRaises(release.ReleaseError):
                release.registry_reader_candidate_template(old)

    def test_inventory_accepts_only_exact_nonreplacing_policy_modify(self):
        old = fixture()
        proposed = release.registry_reader_candidate_template(old)
        self.assertEqual(release.review_inventory([native_change()], old, proposed,
                                                  scope="registry-reader-patch"), [native_change()])
        invalid = [
            [], [native_change(), {"ResourceChange": {"Action": "Add", "LogicalResourceId": "Other"}}],
            [{**native_change(), "ResourceChange": {**native_change()["ResourceChange"],
                "Replacement": "Conditional"}}],
            [{**native_change(), "ResourceChange": {**native_change()["ResourceChange"],
                "Scope": ["Properties", "Tags"]}}],
            [{**native_change(), "ResourceChange": {**native_change()["ResourceChange"],
                "Details": [{"Target": {"Attribute": "Properties", "Name": "BillingMode"}}]}}],
            [{**native_change(), "ResourceChange": {**native_change()["ResourceChange"],
                "Details": [{"Target": {"Attribute": "Properties", "Name": "ResourcePolicy"},
                             "ChangeSource": "ResourceReference"}]}}],
        ]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(release.ReleaseError):
                release.review_inventory(changes, old, proposed, scope="registry-reader-patch")
        altered = copy.deepcopy(proposed)
        altered["Resources"]["Other"]["Metadata"] = {"unreviewed": True}
        with self.assertRaises(release.ReleaseError):
            release.review_inventory([native_change()], old, altered,
                                     scope="registry-reader-patch")

    def test_patch_preserves_all_parameters_without_secret_override(self):
        definitions = {"Secret": {"NoEcho": True}, "EnableThnContentHubV2": {"Default": "false"}}
        current = [{"ParameterKey": "Secret", "ParameterValue": "****"},
                   {"ParameterKey": "EnableThnContentHubV2", "ParameterValue": "false"}]
        self.assertEqual(release.select_parameters(definitions, current, {},
                                                   purpose="registry-reader-patch"),
                         [{"ParameterKey": key, "UsePreviousValue": True} for key in definitions])
        with self.assertRaises(release.ReleaseError):
            release.select_parameters(definitions, current,
                                      {"EnableThnContentHubV2": "true"},
                                      purpose="registry-reader-patch")

    def test_driver_uses_live_template_and_ignores_state_parameter_secret(self):
        old = fixture()
        resources = [{"LogicalResourceId": TABLE,
                      "PhysicalResourceId": "zoolanding-content-hub-prod-ServiceBindingRegistryV2",
                      "ResourceType": "AWS::DynamoDB::Table"}]
        resources += [{"LogicalResourceId": "Other%02d" % i,
                       "PhysicalResourceId": "other-%02d" % i,
                       "ResourceType": "AWS::IAM::Role"} for i in range(58)]
        baseline = {"original": old, "processed": old, "absent": False,
                    "status": "UPDATE_COMPLETE", "terminationProtection": True,
                    "roleArn": "arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec",
                    "resources": resources,
                    "parameters": [{"ParameterKey": key, "ParameterValue": value} for key,value in (
                        ("ProvisionThnServiceBindingRegistryV2State", "true"),
                        ("ProvisionThnContentHubV2State", "true"),
                        ("ProvisionThnProductionRegistryOperator", "true"),
                        ("EnableThnContentHubV2", "false"))]}
        with patch.dict(os.environ, {"THN_PRODUCTION_PARAMETERS_JSON": "{invalid"}):
            self.assertEqual(driver.selected_parameter_overrides("registry-reader-patch"), {})
        self.assertEqual(driver.candidate_for_scope({"Resources": {"Unrelated": {}}},
                                                    baseline, "registry-reader-patch"),
                         release.registry_reader_candidate_template(old))

    def test_driver_rejects_wrong_live_inventory_before_review(self):
        baseline = {"absent": False, "status": "UPDATE_COMPLETE",
                    "terminationProtection": True,
                    "roleArn": "arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec",
                    "resources": [{"LogicalResourceId": "Other", "PhysicalResourceId": str(i),
                                   "ResourceType": "AWS::IAM::Role"} for i in range(59)],
                    "parameters": [{"ParameterKey": "EnableThnContentHubV2", "ParameterValue": "false"}],
                    "original": fixture(), "processed": fixture()}
        with self.assertRaises(release.ReleaseError):
            driver.validate_registry_reader_patch_baseline(baseline)

    def test_preview_must_preserve_all_parameter_values(self):
        previous = [{"ParameterKey": "EnableThnContentHubV2", "ParameterValue": "false"},
                    {"ParameterKey": "Secret", "ParameterValue": "****"}]
        selected = [{"ParameterKey": row["ParameterKey"], "UsePreviousValue": True}
                    for row in previous]
        driver.validate_registry_reader_patch_preview_parameters(selected, previous)
        for invalid in (selected[:1],
                        [{**selected[0], "ParameterValue": "true", "UsePreviousValue": False}, selected[1]],
                        selected + [selected[1]]):
            with self.subTest(invalid=invalid), self.assertRaises(release.ReleaseError):
                driver.validate_registry_reader_patch_preview_parameters(invalid, previous)

    def test_completion_preserves_59_identities_and_only_policy_template_delta(self):
        old = fixture()
        before = {"status": "UPDATE_COMPLETE", "terminationProtection": True,
                  "stackId": "arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/id",
                  "roleArn": "arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec",
                  "resources": [{"LogicalResourceId": TABLE,
                                 "PhysicalResourceId": "zoolanding-content-hub-prod-ServiceBindingRegistryV2",
                                 "ResourceType": "AWS::DynamoDB::Table"}] + [
                      {"LogicalResourceId": "Other%02d" % i, "PhysicalResourceId": str(i),
                       "ResourceType": "AWS::IAM::Role"} for i in range(58)],
                  "parameters": [{"ParameterKey": "EnableThnContentHubV2", "ParameterValue": "false"}],
                  "tags": [{"Key": "thn:environment", "Value": "production"}],
                  "outputs": [{"OutputKey": "Existing", "OutputValue": "same"}],
                  "original": old, "processed": old}
        after = copy.deepcopy(before)
        after["original"] = release.registry_reader_candidate_template(old)
        after["processed"] = release.registry_reader_candidate_template(old)
        driver.validate_registry_reader_patch_completion(before, after)
        for mutation in ("identity", "parameter", "template", "tag", "output"):
            changed = copy.deepcopy(after)
            if mutation == "identity":
                changed["resources"][0]["PhysicalResourceId"] = "replacement"
            elif mutation == "parameter":
                changed["parameters"][0]["ParameterValue"] = "true"
            elif mutation == "tag":
                changed["tags"][0]["Value"] = "other"
            elif mutation == "output":
                changed["outputs"][0]["OutputValue"] = "other"
            else:
                changed["original"]["Resources"]["Other"]["Metadata"] = {"changed": True}
            with self.subTest(mutation=mutation), self.assertRaises(release.ReleaseError):
                driver.validate_registry_reader_patch_completion(before, changed)

    def test_post_execution_snapshot_does_not_require_old_registry_policy(self):
        session = Mock()
        current = {"status": "UPDATE_COMPLETE", "resources": []}
        with patch.object(driver.release, "snapshot", return_value=current) as snapshot, \
                patch.object(driver, "captured_baseline") as capture:
            self.assertIs(driver.post_execution_snapshot(session, "registry-reader-patch"), current)
        snapshot.assert_called_once_with(session.client("cloudformation"), driver.CONFIG["stack"])
        capture.assert_not_called()

    def test_full_policy_simulation_requires_exact_allow_and_two_explicit_denies(self):
        iam = Mock()
        iam.simulate_principal_policy.side_effect = [
            {"EvaluationResults": [{"EvalActionName": "dynamodb:GetItem",
                                     "EvalResourceName": driver.REGISTRY_READER_ARN,
                                     "EvalDecision": decision}]}
            for decision in ("allowed", "explicitDeny", "explicitDeny")]
        self.assertEqual(driver.simulate_registry_reader_policy(iam, {"Version": "2012-10-17",
                                                                  "Statement": []}),
                         {"binding": "allowed", "other": "explicitDeny", "missing": "explicitDeny"})
        self.assertEqual(iam.simulate_principal_policy.call_count, 3)
        first = iam.simulate_principal_policy.call_args_list[0].kwargs
        self.assertEqual(first["PolicySourceArn"], API_ROLE)
        self.assertIn("ResourcePolicy", first)
        iam.reset_mock()
        iam.simulate_principal_policy.side_effect = [
            {"EvaluationResults": [{"EvalActionName": "dynamodb:GetItem",
                                     "EvalResourceName": driver.REGISTRY_READER_ARN,
                                     "EvalDecision": "allowed"}]},
            {"EvaluationResults": [{"EvalActionName": "dynamodb:GetItem",
                                     "EvalResourceName": driver.REGISTRY_READER_ARN,
                                     "EvalDecision": "implicitDeny"}]},
        ]
        with self.assertRaises(release.ReleaseError):
            driver.simulate_registry_reader_policy(iam, {"Version": "2012-10-17",
                                                         "Statement": []})

    def test_live_completion_requires_deployed_policy_and_unchanged_binding(self):
        old = fixture()
        candidate = release.registry_reader_candidate_template(old)
        policy = candidate["Resources"][TABLE]["Properties"]["ResourcePolicy"]["PolicyDocument"]
        binding = {"pk": {"S": "SERVICE_BINDING#production#thn-journal-production-v2"}}
        before = {"registryReaderPolicy": {"bindingSha256": release.sha(binding),
                                           "revision": "100"},
                  "original": old}
        after = {"original": candidate}
        session = Mock()
        session.client("dynamodb").get_resource_policy.return_value = {
            "Policy": json.dumps(policy), "RevisionId": "123"}
        session.client("dynamodb").get_item.return_value = {"Item": binding}
        with patch.object(driver.imported, "normalize_registry_policy", side_effect=lambda value: value), \
                patch.object(driver.imported, "resolve_registry_policy", side_effect=lambda value, role: value), \
                patch.object(driver, "simulate_registry_reader_policy", return_value={"binding": "allowed"}):
            driver.verify_registry_reader_patch_live_policy(session, before, after)
            session.client("dynamodb").get_resource_policy.return_value["RevisionId"] = ""
            with self.assertRaises(release.ReleaseError):
                driver.verify_registry_reader_patch_live_policy(session, before, after)
            session.client("dynamodb").get_resource_policy.return_value["RevisionId"] = "123"
            session.client("dynamodb").get_item.return_value = {"Item": {"changed": {"S": "yes"}}}
            with self.assertRaises(release.ReleaseError):
                driver.verify_registry_reader_patch_live_policy(session, before, after)

    def test_live_completion_tolerates_one_stale_dynamodb_policy_read(self):
        old = fixture()
        candidate = release.registry_reader_candidate_template(old)
        old_policy = old["Resources"][TABLE]["Properties"]["ResourcePolicy"]["PolicyDocument"]
        new_policy = candidate["Resources"][TABLE]["Properties"]["ResourcePolicy"]["PolicyDocument"]
        binding = {"pk": {"S": "SERVICE_BINDING#production#thn-journal-production-v2"}}
        before = {"registryReaderPolicy": {"revision": "100",
                                           "bindingSha256": release.sha(binding)},
                  "original": old}
        after = {"original": candidate}
        session = Mock()
        session.client("dynamodb").get_resource_policy.side_effect = [
            {"Policy": json.dumps(old_policy), "RevisionId": "100"},
            {"Policy": json.dumps(new_policy), "RevisionId": "101"},
        ]
        session.client("dynamodb").get_item.return_value = {"Item": binding}
        with patch.object(driver.imported, "normalize_registry_policy", side_effect=lambda value: value), \
                patch.object(driver.imported, "resolve_registry_policy", side_effect=lambda value, role: value), \
                patch.object(driver, "simulate_registry_reader_policy", return_value={"binding": "allowed"}), \
                patch.object(driver.time, "sleep") as sleep:
            driver.verify_registry_reader_patch_live_policy(session, before, after)
        self.assertEqual(session.client("dynamodb").get_resource_policy.call_count, 2)
        sleep.assert_called_once()


if __name__ == "__main__":
    unittest.main()
