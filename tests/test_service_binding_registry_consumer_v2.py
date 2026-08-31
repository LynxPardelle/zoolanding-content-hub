import copy
import unittest

from tests.test_service_binding_registry_v2 import build_record, registry_definition

try:
    import service_binding_registry_consumer_v2 as consumer
except ModuleNotFoundError:
    consumer = None


class RecordingDynamoClient:
    def __init__(self, item=None, error=None):
        self.item = copy.deepcopy(item)
        self.error = error
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        if self.item is None:
            return {}
        return {"Item": consumer.marshal_item(self.item)}


class ServiceBindingRegistryConsumerExistenceTests(unittest.TestCase):
    def test_consumer_module_exists(self):
        self.assertIsNotNone(consumer)


@unittest.skipIf(consumer is None, "registry consumer v2 is not implemented")
class ServiceBindingRegistryConsumerTests(unittest.TestCase):
    def setUp(self):
        self.record = build_record(registry_definition(activationStatus="active"))
        self.expected_descriptor = {
            "descriptorVersionId": self.record["descriptorVersionId"],
            "descriptorSha256": self.record["descriptorSha256"],
            "authPolicyVersion": self.record["authPolicyVersion"],
        }
        self.trusted_scope = {
            "partition": "aws",
            "accountId": "123456789012",
            "region": "us-east-1",
        }

    def read(self, client):
        return consumer.load_active_service_binding(
            client,
            expected_descriptor=self.expected_descriptor,
            expected_registry_revision=self.record["registryRevision"],
            trusted_resource_scope=self.trusted_scope,
        )

    def test_reads_only_the_exact_registry_key_strongly_consistently(self):
        client = RecordingDynamoClient(self.record)

        loaded = self.read(client)

        self.assertEqual(loaded, self.record)
        self.assertIsNot(loaded, self.record)
        self.assertEqual(len(client.calls), 1)
        request = client.calls[0]
        self.assertEqual(request["TableName"], consumer.APPROVED_TABLE_NAME)
        self.assertTrue(request["ConsistentRead"])
        self.assertEqual(
            consumer.unmarshal_item(request["Key"]),
            {
                "pk": "SERVICE_BINDING#test#thn-journal-test-v2",
                "sk": "REGISTRY#V2",
            },
        )
        self.assertNotIn("ScanIndexForward", request)
        self.assertNotIn("IndexName", request)

    def test_missing_inactive_or_malformed_rows_fail_closed(self):
        candidates = [
            None,
            {**self.record, "activationStatus": "inactive"},
            {**self.record, "domain": "zoositioweb.com.mx"},
            {**self.record, "unexpected": "private-value"},
            {key: value for key, value in self.record.items() if key != "reservationOwner"},
        ]

        for candidate in candidates:
            with self.subTest(candidate="missing" if candidate is None else "invalid"):
                client = RecordingDynamoClient(candidate)
                with self.assertRaisesRegex(
                    consumer.RegistryConsumerError,
                    "service binding is unavailable",
                ) as caught:
                    self.read(client)
                self.assertNotIn("private-value", str(caught.exception))

    def test_descriptor_version_hash_and_auth_policy_must_match_exactly(self):
        for field, value in self.expected_descriptor.items():
            with self.subTest(field=field):
                expected = dict(self.expected_descriptor)
                expected[field] = f"{value}-other"
                client = RecordingDynamoClient(self.record)
                with self.assertRaisesRegex(
                    consumer.RegistryConsumerError,
                    "service binding is unavailable",
                ):
                    consumer.load_active_service_binding(
                        client,
                        expected_descriptor=expected,
                        expected_registry_revision=self.record["registryRevision"],
                        trusted_resource_scope=self.trusted_scope,
                    )

    def test_registry_revision_must_be_the_expected_positive_integer(self):
        for revision in (0, -1, True, "1", self.record["registryRevision"] + 1):
            with self.subTest(revision=revision):
                client = RecordingDynamoClient(self.record)
                with self.assertRaisesRegex(
                    consumer.RegistryConsumerError,
                    "service binding is unavailable",
                ):
                    consumer.load_active_service_binding(
                        client,
                        expected_descriptor=self.expected_descriptor,
                        expected_registry_revision=revision,
                        trusted_resource_scope=self.trusted_scope,
                    )

                if type(revision) is not int or revision < 1:
                    self.assertEqual(client.calls, [])

    def test_expected_descriptor_and_resource_scope_are_closed_inputs(self):
        invalid_inputs = [
            ({**self.expected_descriptor, "extra": "value"}, self.trusted_scope),
            (self.expected_descriptor, {**self.trusted_scope, "extra": "value"}),
            ({**self.expected_descriptor, "descriptorSha256": "not-a-digest"}, self.trusted_scope),
        ]

        for expected, scope in invalid_inputs:
            with self.subTest(expected=expected, scope=scope):
                client = RecordingDynamoClient(self.record)
                with self.assertRaisesRegex(
                    consumer.RegistryConsumerError,
                    "service binding is unavailable",
                ):
                    consumer.load_active_service_binding(
                        client,
                        expected_descriptor=expected,
                        expected_registry_revision=self.record["registryRevision"],
                        trusted_resource_scope=scope,
                    )
                self.assertEqual(client.calls, [])

    def test_provider_errors_are_sanitized(self):
        client = RecordingDynamoClient(error=RuntimeError("private-provider-sentinel"))

        with self.assertRaisesRegex(
            consumer.RegistryConsumerError,
            "service binding is unavailable",
        ) as caught:
            self.read(client)

        self.assertNotIn("private-provider-sentinel", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
