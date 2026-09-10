import copy
import re
import unittest

import service_binding_registry_v2 as registry
from tests.test_service_binding_registry_v2 import build_record, registry_definition

try:
    import service_binding_registry_operator_lambda as mutation_lambda
except ModuleNotFoundError:
    mutation_lambda = None


AUDIT_CONTEXT = {
    "occurredAt": "2026-08-31T12:00:01.000Z",
    "requestId": "123e4567-e89b-12d3-a456-426614174001",
}


class RecordingDynamoClient:
    def __init__(self):
        self.calls = []
        self.items = {}
        self.fail_put = False
        self.transaction_tokens = {}
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

    def _matches(self, request, current):
        if current is None:
            return False
        names = request.get("ExpressionAttributeNames", {})
        values = request.get("ExpressionAttributeValues", {})
        for name_token, value_token in re.findall(
            r"(#[A-Za-z0-9]+) = (:[A-Za-z0-9]+)",
            request.get("ConditionExpression", ""),
        ):
            field = names[name_token]
            expected = mutation_lambda.unmarshal_value(values[value_token])
            if current.get(field) != expected:
                return False
        return True

    def transact_write_items(self, **kwargs):
        self.calls.append(("transact_write_items", kwargs))
        token = kwargs["ClientRequestToken"]
        items = copy.deepcopy(kwargs["TransactItems"])
        if token in self.transaction_tokens:
            if self.transaction_tokens[token] == items:
                return {}
            raise FakeAwsError("IdempotentParameterMismatchException")
        if self.fail_put:
            raise FakeAwsError(
                "TransactionCanceledException",
                cancellation_reasons=[{"Code": "ConditionalCheckFailed"}],
            )

        pending = []
        for action in items:
            if "ConditionCheck" in action:
                request = action["ConditionCheck"]
                key = mutation_lambda.unmarshal_item(request["Key"])
                current = self.items.get((key["pk"], key["sk"]))
                if not self._matches(request, current):
                    raise FakeAwsError(
                        "TransactionCanceledException",
                        cancellation_reasons=[{"Code": "ConditionalCheckFailed"}],
                    )
            elif "Put" in action:
                request = action["Put"]
                item = mutation_lambda.unmarshal_item(request["Item"])
                key = (item["pk"], item["sk"])
                if "attribute_not_exists" in request["ConditionExpression"]:
                    if key in self.items:
                        raise FakeAwsError(
                            "TransactionCanceledException",
                            cancellation_reasons=[{"Code": "ConditionalCheckFailed"}],
                        )
                elif not self._matches(request, self.items.get(key)):
                    raise FakeAwsError(
                        "TransactionCanceledException",
                        cancellation_reasons=[{"Code": "ConditionalCheckFailed"}],
                    )
                pending.append((key, item))
            else:
                raise AssertionError("unexpected transaction action")

        for key, item in pending:
            self.items[key] = item
        self.transaction_tokens[token] = items
        return {}


class FakeAwsError(RuntimeError):
    def __init__(self, code, cancellation_reasons=None):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}
        if cancellation_reasons is not None:
            self.response["CancellationReasons"] = cancellation_reasons


@unittest.skipIf(mutation_lambda is None, "private registry mutation Lambda is not implemented")
class RegistryMutationStoreTests(unittest.TestCase):
    def setUp(self):
        self.client = RecordingDynamoClient()
        self.store = mutation_lambda.DynamoDbRegistryStore(self.client)
        self.record = build_record()
        self.reservation = registry.build_global_hub_reservation(self.record)
        self.audit = registry.build_registry_audit_record(
            self.record,
            operation="reserve",
            outcome="created",
            audit_context=AUDIT_CONTEXT,
        )

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
            self.store.transact_create_binding(mutated, self.reservation, self.audit)
        self.assertEqual(self.client.calls, [])

    def test_reservation_and_update_are_atomic_conditioned_transactions(self):
        self.store.transact_create_binding(self.record, self.reservation, self.audit)
        create_request = self.client.calls[-1][1]
        self.assertEqual(
            [next(iter(action)) for action in create_request["TransactItems"]],
            ["Put", "Put", "Put"],
        )
        self.assertTrue(
            all(
                action["Put"]["ConditionExpression"]
                == "attribute_not_exists(#pk) AND attribute_not_exists(#sk)"
                for action in create_request["TransactItems"]
            )
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
        updated = dict(self.record)
        updated["registryRevision"] = 2
        update_audit = registry.build_registry_audit_record(
            updated,
            operation="update",
            outcome="updated",
            audit_context={
                "occurredAt": "2026-08-31T12:00:02.000Z",
                "requestId": "123e4567-e89b-12d3-a456-426614174002",
            },
        )
        self.store.transact_replace_binding(
            updated,
            self.reservation,
            expected,
            update_audit,
        )
        update_request = self.client.calls[-1][1]
        self.assertEqual(
            [next(iter(action)) for action in update_request["TransactItems"]],
            ["ConditionCheck", "Put", "Put"],
        )
        binding_put = update_request["TransactItems"][1]["Put"]
        self.assertIn("#registryRevision = :registryRevision", binding_put["ConditionExpression"])
        self.assertIn("#writerEpoch = :writerEpoch", binding_put["ConditionExpression"])
        self.assertNotIn("UpdateExpression", binding_put)


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

        result = mutation_lambda.handle_registry_request(
            event,
            self.client,
            audit_context=AUDIT_CONTEXT,
        )

        self.assertEqual(result, {"ok": False, "error": "registry request rejected"})
        self.assertEqual(self.client.calls, [])
        self.assertNotIn("private-sentinel", repr(result))

    def test_reserve_uses_registry_contract_and_returns_only_public_safe_summary(self):
        result = mutation_lambda.handle_registry_request(
            {"operation": "reserve", "definition": registry_definition()},
            self.client,
            audit_context=AUDIT_CONTEXT,
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
        self.assertEqual(
            [call[0] for call in self.client.calls],
            ["describe_table", "get_item", "get_item", "transact_write_items"],
        )

    def test_update_requires_closed_concurrency_fields_and_uses_registry_transition(self):
        current = build_record()
        self.client.items[(current["pk"], current["sk"])] = current
        reservation = registry.build_global_hub_reservation(current)
        self.client.items[(reservation["pk"], reservation["sk"])] = reservation
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
            audit_context=AUDIT_CONTEXT,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["operation"], "update")
        self.assertEqual(result["registryRevision"], 2)
        transaction = [
            request
            for operation, request in self.client.calls
            if operation == "transact_write_items"
        ][-1]
        put_request = transaction["TransactItems"][1]["Put"]
        self.assertIn("#registryRevision = :registryRevision", put_request["ConditionExpression"])
        self.assertIn("#writerEpoch = :writerEpoch", put_request["ConditionExpression"])

    def test_conditional_conflicts_and_provider_details_are_sanitized(self):
        self.client.fail_put = True

        result = mutation_lambda.handle_registry_request(
            {"operation": "reserve", "definition": registry_definition()},
            self.client,
            audit_context=AUDIT_CONTEXT,
        )

        self.assertEqual(result, {"ok": False, "error": "registry request conflict"})
        self.assertNotIn("ConditionalCheckFailedException", repr(result))


class RegistryMutationLambdaExistenceTests(unittest.TestCase):
    def test_private_registry_mutation_lambda_module_exists(self):
        self.assertIsNotNone(mutation_lambda)


if __name__ == "__main__":
    unittest.main()
