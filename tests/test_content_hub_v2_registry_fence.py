import copy
import unittest

from tests.test_service_binding_registry_v2 import build_record, registry_definition

try:
    import content_hub_v2_registry_fence as fence
except ModuleNotFoundError:
    fence = None


class InMemoryTransactionalDynamo:
    def __init__(self, record):
        self.record = copy.deepcopy(record)
        self.get_calls = []
        self.transact_calls = []
        self.before_condition_check = None
        self.applied = []

    def get_item(self, **kwargs):
        self.get_calls.append(kwargs)
        return {"Item": fence.marshal_item(self.record)}

    def transact_write_items(self, **kwargs):
        self.transact_calls.append(copy.deepcopy(kwargs))
        if self.before_condition_check:
            self.before_condition_check(self)

        condition = kwargs["TransactItems"][0]["ConditionCheck"]
        values = {
            name: fence.unmarshal_item({"value": value})["value"]
            for name, value in condition["ExpressionAttributeValues"].items()
        }
        expected = {
            "activationStatus": values[":activationStatus"],
            "writerMode": values[":writerMode"],
            "writerEpoch": values[":writerEpoch"],
            "registryRevision": values[":registryRevision"],
            "environment": values[":environment"],
            "domain": values[":domain"],
            "authProfileId": values[":authProfileId"],
            "tenantId": values[":tenantId"],
            "hubId": values[":hubId"],
        }
        if any(self.record.get(key) != value for key, value in expected.items()):
            raise RuntimeError("private-transaction-cancel-reason")

        self.applied.extend(copy.deepcopy(kwargs["TransactItems"][1:]))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class RegistryFenceExistenceTests(unittest.TestCase):
    def test_registry_fence_module_exists(self):
        self.assertIsNotNone(fence)


@unittest.skipIf(fence is None, "registry transaction fence is not implemented")
class RegistryFenceTests(unittest.TestCase):
    def setUp(self):
        self.record = build_record(
            registry_definition(
                activationStatus="active",
                writerMode="client-owner",
                writerEpoch=7,
                registryRevision=3,
            )
        )
        self.client = InMemoryTransactionalDynamo(self.record)
        self.expected_descriptor = {
            "descriptorVersionId": self.record["descriptorVersionId"],
            "descriptorSha256": self.record["descriptorSha256"],
            "authPolicyVersion": self.record["authPolicyVersion"],
        }
        self.scope = {
            "partition": "aws",
            "accountId": "123456789012",
            "region": "us-east-1",
        }
        self.mutation = {
            "Put": {
                "TableName": "zoolanding-content-hub-test-ThnContentHubV2Metadata",
                "Item": {"pk": {"S": "ARTICLE#safe"}, "sk": {"S": "STATE"}},
            }
        }

    def execute(self, mutation_items=None):
        return fence.execute_registry_fenced_transaction(
            self.client,
            mutation_items=mutation_items or [self.mutation],
            expected_descriptor=self.expected_descriptor,
            expected_registry_revision=3,
            expected_writer_mode="client-owner",
            trusted_resource_scope=self.scope,
        )

    def test_prepends_exact_registry_condition_to_final_mutations(self):
        result = self.execute()

        self.assertEqual(result["ResponseMetadata"]["HTTPStatusCode"], 200)
        self.assertEqual(len(self.client.get_calls), 1)
        self.assertTrue(self.client.get_calls[0]["ConsistentRead"])
        self.assertEqual(len(self.client.transact_calls), 1)
        transaction = self.client.transact_calls[0]["TransactItems"]
        self.assertEqual(transaction[1:], [self.mutation])
        check = transaction[0]["ConditionCheck"]
        self.assertEqual(check["TableName"], fence.APPROVED_TABLE_NAME)
        self.assertEqual(
            fence.unmarshal_item(check["Key"]),
            {
                "pk": "SERVICE_BINDING#test#thn-journal-test-v2",
                "sk": "REGISTRY#V2",
            },
        )
        for field in (
            "activationStatus",
            "writerMode",
            "writerEpoch",
            "environment",
            "domain",
            "authProfileId",
            "tenantId",
            "hubId",
        ):
            self.assertIn(f"#{field}", check["ExpressionAttributeNames"])

    def test_writer_disable_between_read_and_commit_applies_nothing(self):
        def disable_writers(client):
            client.record["writerMode"] = "disabled"
            client.record["writerEpoch"] = 8
            client.record["registryRevision"] = 4

        self.client.before_condition_check = disable_writers

        with self.assertRaisesRegex(
            fence.RegistryFenceError,
            "service binding changed before commit",
        ) as caught:
            self.execute()

        self.assertEqual(self.client.applied, [])
        self.assertNotIn("private-transaction-cancel-reason", str(caught.exception))

    def test_disabled_or_wrong_writer_mode_never_starts_a_transaction(self):
        for record_mode, expected_mode in (
            ("disabled", "client-owner"),
            ("qa-only", "client-owner"),
        ):
            with self.subTest(record_mode=record_mode):
                record = copy.deepcopy(self.record)
                record["writerMode"] = record_mode
                client = InMemoryTransactionalDynamo(record)
                with self.assertRaises(fence.RegistryFenceError):
                    fence.execute_registry_fenced_transaction(
                        client,
                        mutation_items=[self.mutation],
                        expected_descriptor=self.expected_descriptor,
                        expected_registry_revision=3,
                        expected_writer_mode=expected_mode,
                        trusted_resource_scope=self.scope,
                    )
                self.assertEqual(client.transact_calls, [])

    def test_rejects_empty_oversized_or_registry_targeting_mutations(self):
        invalid_sets = [
            [],
            [self.mutation] * 100,
            [{"ConditionCheck": {"TableName": "another-table"}}],
            [{"Put": {"TableName": fence.APPROVED_TABLE_NAME, "Item": {}}}],
            [{"Put": {"TableName": "safe"}, "Delete": {"TableName": "safe"}}],
        ]

        for mutation_items in invalid_sets:
            with self.subTest(size=len(mutation_items)):
                with self.assertRaises(fence.RegistryFenceError):
                    fence.execute_registry_fenced_transaction(
                        self.client,
                        mutation_items=mutation_items,
                        expected_descriptor=self.expected_descriptor,
                        expected_registry_revision=3,
                        expected_writer_mode="client-owner",
                        trusted_resource_scope=self.scope,
                    )
                self.assertEqual(self.client.get_calls, [])
                self.assertEqual(self.client.transact_calls, [])


if __name__ == "__main__":
    unittest.main()
