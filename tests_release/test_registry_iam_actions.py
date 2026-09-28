"""Registry policies use IAM actions, not similarly named DynamoDB APIs."""

from pathlib import Path
import unittest
import yaml


class RegistryIamActionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        template = yaml.safe_load(Path(__file__).resolve().parents[1].joinpath("template.yaml").read_text())
        cls.table = template["Resources"]["ServiceBindingRegistryV2Table"]
        cls.statements = {item["Sid"]: item for item in cls.table["Properties"]["ResourcePolicy"]["PolicyDocument"]["Statement"]}

    def test_registry_policy_uses_only_reviewed_dynamodb_iam_actions(self):
        # AWS service authorization reference: API names are not IAM actions.
        # https://docs.aws.amazon.com/service-authorization/latest/reference/list_dynamodb.html
        supported = {"BatchGetItem", "BatchWriteItem", "ConditionCheckItem", "DeleteItem", "DescribeTable",
            "GetItem", "PartiQLDelete", "PartiQLInsert", "PartiQLSelect", "PartiQLUpdate", "PutItem", "Query", "Scan", "UpdateItem"}
        actions = {action for statement in self.statements.values() for action in statement["Action"]}
        self.assertEqual(actions, {"dynamodb:" + action for action in supported})

    def test_transactional_reads_remain_denied_without_blocking_normal_get_item(self):
        # https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html
        self.assertTrue("DenyRegistryTransactionalReads" in self.statements, "Missing explicit transactional GetItem denial")
        statement = self.statements["DenyRegistryTransactionalReads"]
        self.assertEqual(statement, {
            "Sid": "DenyRegistryTransactionalReads", "Effect": "Deny", "Principal": "*",
            "Action": ["dynamodb:GetItem"],
            "Resource": self.statements["DenyRegistryUnsupportedReads"]["Resource"],
            "Condition": {"StringEquals": {"dynamodb:EnclosingOperation": "TransactGetItems"}},
        })
        # Missing/nonmatching EnclosingOperation does not satisfy StringEquals;
        # never use an IfExists/Null/missing-condition denial for ordinary reads.
        self.assertNotIn("NotAction", statement)
        self.assertNotIn("NotPrincipal", statement)

    def test_partiql_and_batch_operations_still_have_unconditional_denials(self):
        for sid, expected in (
            ("DenyRegistryUnsupportedReads", {"dynamodb:BatchGetItem", "dynamodb:PartiQLSelect", "dynamodb:Query", "dynamodb:Scan"}),
            ("DenyRegistryDeleteAndBatchWrite", {"dynamodb:BatchWriteItem", "dynamodb:DeleteItem",
                "dynamodb:PartiQLDelete", "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate"}),
        ):
            with self.subTest(sid=sid):
                statement = self.statements[sid]
                self.assertEqual(statement["Effect"], "Deny")
                self.assertEqual(statement["Principal"], "*")
                self.assertEqual(set(statement["Action"]), expected)
                self.assertNotIn("Condition", statement)
                self.assertNotIn("NotPrincipal", statement)


if __name__ == "__main__":
    unittest.main()
