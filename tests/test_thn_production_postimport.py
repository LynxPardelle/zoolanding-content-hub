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
    def test_state_baseline_fingerprints_live_imported_resources_and_policy(self):
        baseline, _ = post_import_baseline()
        session = Mock()
        live = {"policyRevision": "1790716784435",
                "policySha256": "7a879e95713300b080111e7bf59aa81f550c6bed3dfc530a8b67ca857de5f54f",
                "identities": {"stable": True}, "tables": {}, "bucket": {}}
        with patch.dict(os.environ, {"THN_PRODUCTION_SELECTED_PURPOSE": "state"}), \
                patch.object(driver.release, "snapshot", return_value=baseline), \
                patch("tools.run_thn_production_import.read_targets", return_value=live) as capture:
            result = driver.captured_baseline(session)
        capture.assert_called_once()
        self.assertEqual(result["postImportTargets"], live)
        changed = {**live, "policySha256": "0" * 64}
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

    def test_state_candidate_preserves_imported_declarations_and_public_api(self):
        baseline, targets = post_import_baseline()
        baseline["original"]["Resources"]["ContentHubApi"] = {"Type": "AWS::Serverless::HttpApi", "Properties": {"StageName": "prod"}}
        candidate = {"Parameters": {}, "Resources": {
            **{name: {**value, "Condition": "ProvisionState", "Properties": {"changed": True}}
               for name, value in targets.items()},
            "ContentHubApi": {"Type": "AWS::Serverless::HttpApi", "Properties": {"StageName": "other"}},
            "ThnContentHubV2AuthoringRole": {"Type": "AWS::IAM::Role"},
        }}
        selected = driver.candidate_for_scope(candidate, baseline, "state")
        for logical in (*targets, "ContentHubApi"):
            self.assertEqual(selected["Resources"][logical], baseline["original"]["Resources"][logical])
        self.assertIn("ThnContentHubV2AuthoringRole", selected["Resources"])

    def test_state_inventory_rejects_existing_resource_modification(self):
        baseline, _ = post_import_baseline()
        added = [{"ResourceChange": {"Action": "Add", "LogicalResourceId": "ThnContentHubV2AuthoringRole",
                                      "ResourceType": "AWS::IAM::Role", "Replacement": "False"}}]
        imported.validate_post_import_state_inventory(added, baseline)
        nullable = copy.deepcopy(added)
        nullable[0]["ResourceChange"]["Replacement"] = None
        review_inventory(nullable, baseline["processed"],
                         {"Resources": {"ThnContentHubV2AuthoringRole": {"Type": "AWS::IAM::Role"}}},
                         scope="state")
        imported.validate_post_import_state_inventory(nullable, baseline)
        for logical in ("ThnContentHubV2PrivateStore", "Legacy00"):
            changed = added + [{"ResourceChange": {"Action": "Modify", "LogicalResourceId": logical,
                                               "ResourceType": "AWS::S3::Bucket", "Replacement": "False"}}]
            with self.subTest(logical=logical), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_inventory(changed, baseline)


if __name__ == "__main__":
    unittest.main()
