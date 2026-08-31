import copy
import unittest

import service_binding_registry_operator_lambda as mutation_lambda
import service_binding_registry_v2 as registry

from tests.test_service_binding_registry_v2 import build_record


AUDIT_CONTEXT = {
    "occurredAt": "2026-08-31T12:00:01.000Z",
    "requestId": "123e4567-e89b-12d3-a456-426614174001",
}


class TransactionRecorder:
    def __init__(self):
        self.calls = []

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)


class FakeAwsError(RuntimeError):
    def __init__(self, code, cancellation_reasons=None):
        super().__init__("private-provider-detail")
        self.response = {"Error": {"Code": code}}
        if cancellation_reasons is not None:
            self.response["CancellationReasons"] = cancellation_reasons


def records(*, outcome="created"):
    binding = build_record()
    reservation = registry.build_global_hub_reservation(binding)
    audit = registry.build_registry_audit_record(
        binding,
        operation="reserve" if outcome != "updated" else "update",
        outcome=outcome,
        audit_context=AUDIT_CONTEXT,
    )
    return binding, reservation, audit


class RegistryAtomicStoreContractTests(unittest.TestCase):
    def test_full_binding_record_with_noncanonical_key_is_rejected_before_transaction(self):
        client = TransactionRecorder()
        store = mutation_lambda.DynamoDbRegistryStore(client)
        binding, reservation, audit = records()
        poisoned = copy.deepcopy(binding)
        poisoned["pk"] = "SERVICE_BINDING#test#other"

        with self.assertRaises(mutation_lambda.RegistryMutationInputError):
            store.transact_create_binding(poisoned, reservation, audit)

        self.assertEqual(client.calls, [])

    def test_create_is_one_three_put_transaction_with_append_only_guards(self):
        client = TransactionRecorder()
        store = mutation_lambda.DynamoDbRegistryStore(client)
        binding, reservation, audit = records()

        store.transact_create_binding(binding, reservation, audit)

        self.assertEqual(len(client.calls), 1)
        request = client.calls[0]
        self.assertRegex(request["ClientRequestToken"], r"^thn-[a-f0-9]{32}$")
        self.assertEqual(len(request["TransactItems"]), 3)
        self.assertTrue(all(set(item) == {"Put"} for item in request["TransactItems"]))
        self.assertTrue(
            all(
                item["Put"]["ConditionExpression"]
                == "attribute_not_exists(#pk) AND attribute_not_exists(#sk)"
                for item in request["TransactItems"]
            )
        )

    def test_audit_record_with_extra_or_inconsistent_fields_is_rejected_before_transaction(self):
        invalid_audits = []
        binding, reservation, audit = records()
        with_private_field = copy.deepcopy(audit)
        with_private_field["tenantId"] = "private-tenant"
        invalid_audits.append(with_private_field)

        inconsistent_sort_key = copy.deepcopy(audit)
        inconsistent_sort_key["requestId"] = "different-request"
        invalid_audits.append(inconsistent_sort_key)

        wrong_actor = copy.deepcopy(audit)
        wrong_actor["actorType"] = "browser"
        invalid_audits.append(wrong_actor)

        for invalid_audit in invalid_audits:
            with self.subTest(invalid_audit=invalid_audit):
                client = TransactionRecorder()
                store = mutation_lambda.DynamoDbRegistryStore(client)

                with self.assertRaises(mutation_lambda.RegistryMutationInputError):
                    store.transact_create_binding(binding, reservation, invalid_audit)

                self.assertEqual(client.calls, [])

    def test_update_conditions_reservation_replaces_binding_and_appends_audit(self):
        client = TransactionRecorder()
        store = mutation_lambda.DynamoDbRegistryStore(client)
        binding, reservation, _ = records()
        updated = copy.deepcopy(binding)
        updated["registryRevision"] = 2
        audit = registry.build_registry_audit_record(
            updated,
            operation="update",
            outcome="updated",
            audit_context=AUDIT_CONTEXT,
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

        store.transact_replace_binding(updated, reservation, expected, audit)

        actions = client.calls[0]["TransactItems"]
        self.assertEqual([next(iter(action)) for action in actions], ["ConditionCheck", "Put", "Put"])
        self.assertIn("#registryRevision = :registryRevision", actions[1]["Put"]["ConditionExpression"])
        self.assertEqual(
            actions[2]["Put"]["ConditionExpression"],
            "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
        )

    def test_only_true_transaction_condition_failures_are_classified_as_registry_conflicts(self):
        conditional = FakeAwsError(
            "TransactionCanceledException",
            [{"Code": "ConditionalCheckFailed"}, {"Code": "None"}],
        )
        with self.assertRaises(registry.RegistryConditionalWriteFailed):
            mutation_lambda._raise_registry_service_error(conditional)

        for cancellation_reason in (
            "ProvisionedThroughputExceeded",
            "ThrottlingError",
            "TransactionConflict",
            "ValidationError",
        ):
            with self.subTest(cancellation_reason=cancellation_reason):
                provider_error = FakeAwsError(
                    "TransactionCanceledException",
                    [{"Code": cancellation_reason}],
                )
                with self.assertRaisesRegex(
                    mutation_lambda.RegistryMutationServiceError,
                    "registry service request failed",
                ) as caught:
                    mutation_lambda._raise_registry_service_error(provider_error)
                self.assertNotIn("private-provider-detail", str(caught.exception))

        without_reasons = FakeAwsError("TransactionCanceledException")
        with self.assertRaises(mutation_lambda.RegistryMutationServiceError):
            mutation_lambda._raise_registry_service_error(without_reasons)


if __name__ == "__main__":
    unittest.main()
