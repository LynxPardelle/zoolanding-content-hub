import unittest

from tests.test_service_binding_registry_v2 import build_record, registry_definition

try:
    import service_binding_registry_operator_lambda as mutation_lambda
except ModuleNotFoundError:
    mutation_lambda = None


class RecordingDynamoClient:
    def __init__(self):
        self.calls = []
        self.items = {}
        self.fail_put = False
        self.table_arn = (
            "arn:aws:dynamodb:us-east-1:123456789012:"
            "table/zoolanding-content-hub-test-ServiceBindingRegistryV2"
        )

    def describe_table(self, **kwargs):
        self.calls.append(("describe_table", kwargs))
        return {"Table": {"TableArn": self.table_arn}}

    def get_item(self, **kwargs):
        self.calls.append(("get_item", kwargs))
        key = mutation_lambda.unmarshal_item(kwargs["Key"])
        item = self.items.get((key["pk"], key["sk"]))
        return {"Item": mutation_lambda.marshal_item(item)} if item else {}

    def put_item(self, **kwargs):
        self.calls.append(("put_item", kwargs))
        if self.fail_put:
            raise FakeAwsError("ConditionalCheckFailedException")
        item = mutation_lambda.unmarshal_item(kwargs["Item"])
        key = (item["pk"], item["sk"])
        if "attribute_not_exists" in kwargs["ConditionExpression"] and key in self.items:
            raise FakeAwsError("ConditionalCheckFailedException")
        self.items[key] = item


class FakeAwsError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


@unittest.skipIf(mutation_lambda is None, "private registry mutation Lambda is not implemented")
class RegistryMutationStoreTests(unittest.TestCase):
    def setUp(self):
        self.client = RecordingDynamoClient()
        self.store = mutation_lambda.DynamoDbRegistryStore(self.client)
        self.record = build_record()

    def test_store_uses_exact_table_and_strongly_consistent_exact_key_read(self):
        self.client.items[(self.record["pk"], self.record["sk"])] = self.record

        loaded = self.store.get_binding({"pk": self.record["pk"], "sk": self.record["sk"]})

        self.assertEqual(loaded, self.record)
        operation, request = self.client.calls[-1]
        self.assertEqual(operation, "get_item")
        self.assertEqual(request["TableName"], mutation_lambda.APPROVED_TABLE_NAME)
        self.assertTrue(request["ConsistentRead"])

    def test_store_rejects_every_noncanonical_partition_or_sort_key_before_dynamodb(self):
        invalid_keys = (
            {"pk": "SERVICE_BINDING#test#zoosite-v2", "sk": "REGISTRY#V2"},
            {"pk": self.record["pk"], "sk": "REGISTRY#V1"},
        )

        for key in invalid_keys:
            with self.subTest(key=key):
                self.client.calls.clear()
                with self.assertRaises(mutation_lambda.RegistryMutationInputError):
                    self.store.get_binding(key)
                self.assertEqual(self.client.calls, [])

        mutated = dict(self.record)
        mutated["sk"] = "REGISTRY#V1"
        with self.assertRaises(mutation_lambda.RegistryMutationInputError):
            self.store.create_binding(mutated)
        self.assertEqual(self.client.calls, [])

    def test_reservation_and_update_are_conditional_puts(self):
        self.store.create_binding(self.record)
        create_request = self.client.calls[-1][1]
        self.assertEqual(
            create_request["ConditionExpression"],
            "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
        )

        expected = {
            "registryRevision": 1,
            "writerEpoch": 1,
            "environment": "test",
            "domain": "thehairnarrative.com",
            "serviceBindingId": "thn-journal-test-v2",
            "hubId": "thehairnarrative-com-journal",
            "tenantId": "thehairnarrative-com",
            "authProfileId": "journal-owner",
        }
        self.store.replace_binding(self.record, expected)
        update_request = self.client.calls[-1][1]
        self.assertIn("#registryRevision = :registryRevision", update_request["ConditionExpression"])
        self.assertIn("#writerEpoch = :writerEpoch", update_request["ConditionExpression"])
        self.assertNotIn("UpdateExpression", update_request)


@unittest.skipIf(mutation_lambda is None, "private registry mutation Lambda is not implemented")
class RegistryMutationHandlerTests(unittest.TestCase):
    def setUp(self):
        self.client = RecordingDynamoClient()

    def test_closed_payload_rejects_unknown_fields_before_dynamodb_and_does_not_reflect_them(self):
        event = {
            "operation": "reserve",
            "definition": registry_definition(),
            "private-sentinel-field": "private-sentinel-value",
        }

        result = mutation_lambda.handle_registry_request(event, self.client)

        self.assertEqual(result, {"ok": False, "error": "registry request rejected"})
        self.assertEqual(self.client.calls, [])
        self.assertNotIn("private-sentinel", repr(result))

    def test_reserve_uses_registry_contract_and_returns_only_public_safe_summary(self):
        result = mutation_lambda.handle_registry_request(
            {"operation": "reserve", "definition": registry_definition()},
            self.client,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["operation"], "reserve")
        self.assertEqual(result["domain"], "thehairnarrative.com")
        self.assertEqual(result["registryRevision"], 1)
        self.assertTrue(result["created"])
        self.assertEqual(
            set(result),
            {
                "ok",
                "operation",
                "environment",
                "domain",
                "serviceBindingId",
                "descriptorVersionId",
                "registryRevision",
                "created",
            },
        )
        serialized = repr(result)
        for private_field in (
            "tenantId",
            "cookieNamespace",
            "resourceBindings",
            "authPolicyVersion",
            "adminOrigin",
            "reservationOwner",
            "activationStatus",
            "writerMode",
            "writerEpoch",
            "descriptorSha256",
        ):
            self.assertNotIn(private_field, serialized)
        self.assertEqual([call[0] for call in self.client.calls], ["describe_table", "get_item", "put_item"])

    def test_update_requires_closed_concurrency_fields_and_uses_registry_transition(self):
        current = build_record()
        self.client.items[(current["pk"], current["sk"])] = current
        desired = registry_definition(
            descriptorVersionId="test-v2",
            registryRevision=2,
            activationStatus="active",
        )

        result = mutation_lambda.handle_registry_request(
            {
                "operation": "update",
                "definition": desired,
                "expectedRegistryRevision": 1,
                "expectedWriterEpoch": 1,
            },
            self.client,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["operation"], "update")
        self.assertEqual(result["registryRevision"], 2)
        put_request = [request for operation, request in self.client.calls if operation == "put_item"][-1]
        self.assertIn("#registryRevision = :registryRevision", put_request["ConditionExpression"])
        self.assertIn("#writerEpoch = :writerEpoch", put_request["ConditionExpression"])

    def test_conditional_conflicts_and_provider_details_are_sanitized(self):
        self.client.fail_put = True

        result = mutation_lambda.handle_registry_request(
            {"operation": "reserve", "definition": registry_definition()},
            self.client,
        )

        self.assertEqual(result, {"ok": False, "error": "registry request conflict"})
        self.assertNotIn("ConditionalCheckFailedException", repr(result))


class RegistryMutationLambdaExistenceTests(unittest.TestCase):
    def test_private_registry_mutation_lambda_module_exists(self):
        self.assertIsNotNone(mutation_lambda)


if __name__ == "__main__":
    unittest.main()
