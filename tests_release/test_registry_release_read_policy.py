"""Exact partition-only deployment reads; not an IAM sort-key restriction."""

import json
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
READERS = ("zoolanding-content-hub-test-deploy", "zoolanding-deployer-image-upload-test-github-deploy")
PRINCIPALS = [{"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" + role} for role in READERS]
KEY = "SERVICE_BINDING#test#thn-journal-test-v2"
TABLE = {"Fn::Sub": "arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/zoolanding-content-hub-test-ServiceBindingRegistryV2"}


class RegistryReleaseReadPolicyTests(unittest.TestCase):
    def setUp(self):
        template = yaml.safe_load((ROOT / "template.yaml").read_text())
        statements = template["Resources"]["ServiceBindingRegistryV2Table"]["Properties"]["ResourcePolicy"]["PolicyDocument"]["Statement"]
        self.statements = {item["Sid"]: item for item in statements}

    def statement(self, name):
        self.assertTrue(name in self.statements, "The exact deployment-reader resource policy is missing: " + name)
        return self.statements[name]

    def test_only_two_exact_existing_roles_receive_get_item_on_the_fixed_partition(self):
        statement = self.statement("AllowRegistryDeploymentBindingRead")
        self.assertEqual(statement, {"Sid": "AllowRegistryDeploymentBindingRead", "Effect": "Allow",
            "Principal": {"AWS": PRINCIPALS}, "Action": ["dynamodb:GetItem"], "Resource": TABLE,
            "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [KEY]},
                          "Null": {"dynamodb:LeadingKeys": "false"}}})
        # No purported sort-key IAM condition: the runtime tool fixes PK and SK.
        self.assertNotIn("sk", json.dumps(statement["Condition"]))

    def test_missing_or_other_partition_has_an_explicit_deny_for_both_readers(self):
        for name, condition in (
            ("DenyRegistryDeploymentReadMissingKeys", {"Null": {"dynamodb:LeadingKeys": "true"}}),
            ("DenyRegistryDeploymentReadOutsideBinding", {"ForAnyValue:StringNotEquals": {"dynamodb:LeadingKeys": [KEY]}}),
        ):
            statement = self.statement(name)
            self.assertEqual(statement, {"Sid": name, "Effect": "Deny", "Principal": {"AWS": PRINCIPALS},
                                        "Action": ["dynamodb:GetItem"], "Resource": TABLE, "Condition": condition})

    def test_reader_exceptions_do_not_reach_mutation_reservation_audit_or_listing(self):
        reader_deny = self.statements["DenyRegistryGetItemOutsideApprovedConsumers"]
        allowed = reader_deny["Condition"]["ArnNotEquals"]["aws:PrincipalArn"]
        for principal in PRINCIPALS:
            self.assertIn(principal, allowed)
        reader_sids = {"AllowRegistryDeploymentBindingRead", "DenyRegistryDeploymentReadMissingKeys",
                       "DenyRegistryDeploymentReadOutsideBinding", "DenyRegistryGetItemOutsideApprovedConsumers",
                       "DenyRegistryDescribeOutsideMutationAndHubDeployment"}
        for sid, statement in self.statements.items():
            if sid not in reader_sids:
                for reader in READERS:
                    self.assertNotIn(reader, json.dumps(statement), sid)
        unsupported = self.statements["DenyRegistryUnsupportedReads"]
        self.assertEqual(unsupported["Effect"], "Deny")
        self.assertTrue({"dynamodb:Query", "dynamodb:Scan", "dynamodb:PartiQLSelect"}.issubset(unsupported["Action"]))
        self.assertEqual(self.statement("DenyRegistryTransactionalReads"), {
            "Sid": "DenyRegistryTransactionalReads", "Effect": "Deny", "Principal": "*",
            "Action": ["dynamodb:GetItem"], "Resource": TABLE,
            "Condition": {"StringEquals": {"dynamodb:EnclosingOperation": "TransactGetItems"}},
        })
        for sid in ("DenyRegistryReservationReadOutsideMutationFunction", "DenyRegistryAuditRead",
                    "DenyRegistryDeleteAndBatchWrite", "DenyRegistryUpdateItem", "DenyRegistryPutOutsideTransaction"):
            self.assertEqual(self.statements[sid]["Effect"], "Deny")

    def test_principals_cannot_be_replaced_by_prod_other_account_or_user_context(self):
        statement = self.statement("AllowRegistryDeploymentBindingRead")
        rendered = {entry["Fn::Sub"].replace("${AWS::Partition}", "aws").replace("${AWS::AccountId}", "123456789012")
                    for entry in statement["Principal"]["AWS"]}
        self.assertEqual(len(rendered), 2)
        for principal in ("arn:aws:iam::123456789012:role/zoolanding-thn-registry-test-operator",
                          "arn:aws:iam::123456789012:role/zoolanding-content-hub-prod-deploy",
                          "arn:aws:iam::999999999999:role/zoolanding-content-hub-test-deploy",
                          "arn:aws:iam::123456789012:role/fake-context-reader"):
            self.assertNotIn(principal, rendered)
        self.assertNotIn("aws:PrincipalArn", statement.get("Condition", {}))

    def test_describe_exception_is_only_mediator_and_exact_hub_stack_caller(self):
        statement = self.statement("DenyRegistryDescribeOutsideMutationAndHubDeployment")
        approved = [{"Fn::GetAtt": ["ServiceBindingRegistryV2MutationRole", "Arn"]}, PRINCIPALS[0]]
        self.assertEqual(statement, {"Sid": "DenyRegistryDescribeOutsideMutationAndHubDeployment", "Effect": "Deny",
            "Principal": "*", "Action": ["dynamodb:DescribeTable"], "Resource": TABLE,
            "Condition": {"ArnNotEquals": {"aws:PrincipalArn": approved}}})
        common = self.statements["DenyRegistryAccessOutsideMutationFunction"]
        self.assertEqual(common["Action"], ["dynamodb:" + action for action in (
            "BatchGetItem", "BatchWriteItem", "DeleteItem",
            "PartiQLDelete", "PartiQLInsert", "PartiQLSelect", "PartiQLUpdate", "PutItem", "Query", "Scan",
            "UpdateItem")])
        self.assertEqual(common["Condition"], {"ArnNotEquals": {"aws:PrincipalArn": approved[0]}})
        # These exact principals already need an identity DescribeTable grant. This
        # proves only the resource-policy explicit-deny boundary, not SCP/session IAM.
        rendered = {"arn:aws:iam::123456789012:role/zoolanding-thn-registry-test-mutation",
                    "arn:aws:iam::123456789012:role/" + READERS[0]}
        for role in ("zoolanding-thn-registry-test-operator", READERS[1], "zoolanding-content-hub-prod-deploy",
                     "unrelated-role"):
            self.assertNotIn("arn:aws:iam::123456789012:role/" + role, rendered)
        self.assertNotIn("arn:aws:iam::999999999999:role/" + READERS[0], rendered)

    def test_no_remaining_resource_deny_blocks_the_required_metadata_readbacks(self):
        allowed_context = {"Fn::GetAtt": ["ServiceBindingRegistryV2MutationRole", "Arn"]}
        for action in ("dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups", "dynamodb:GetResourcePolicy"):
            for statement in self.statements.values():
                if statement["Effect"] != "Deny" or action not in statement.get("Action", []):
                    continue
                self.assertEqual(action, "dynamodb:DescribeTable")
                self.assertEqual(statement["Condition"], {"ArnNotEquals": {"aws:PrincipalArn": [allowed_context, PRINCIPALS[0]]}})


if __name__ == "__main__":
    unittest.main()
