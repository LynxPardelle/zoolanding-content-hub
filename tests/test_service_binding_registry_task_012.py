import copy
import unittest

import service_binding_registry_v2 as registry

from tests.test_service_binding_registry_v2 import (
    TRUSTED_RESOURCE_SCOPE,
    build_record,
    registry_definition,
)


def audit_context(sequence=1):
    return {
        "occurredAt": f"2026-08-31T12:00:0{sequence}.000Z",
        "requestId": f"123e4567-e89b-12d3-a456-42661417400{sequence}",
    }


class AtomicRegistryStore:
    def __init__(self):
        self.items = {}
        self.transactions = []
        self.fail_next_transaction = False
        self.concurrent_item = None

    def get_trusted_resource_scope(self):
        return dict(TRUSTED_RESOURCE_SCOPE)

    def get_binding(self, key):
        item = self.items.get((key["pk"], key["sk"]))
        return copy.deepcopy(item) if item else None

    def get_global_reservation(self, key):
        item = self.items.get((key["pk"], key["sk"]))
        return copy.deepcopy(item) if item else None

    def _begin(self, operation, binding, reservation, audit):
        self.transactions.append(
            {
                "operation": operation,
                "binding": copy.deepcopy(binding),
                "reservation": copy.deepcopy(reservation),
                "audit": copy.deepcopy(audit),
            }
        )
        if self.fail_next_transaction:
            self.fail_next_transaction = False
            if self.concurrent_item:
                item = copy.deepcopy(self.concurrent_item)
                self.items[(item["pk"], item["sk"])] = item
            raise registry.RegistryConditionalWriteFailed()

    def transact_create_binding(self, binding, reservation, audit):
        self._begin("create", binding, reservation, audit)
        keys = [
            (binding["pk"], binding["sk"]),
            (reservation["pk"], reservation["sk"]),
            (audit["pk"], audit["sk"]),
        ]
        if (
            self.items.get(keys[0]) == binding
            and self.items.get(keys[1]) == reservation
            and self.items.get(keys[2]) == audit
        ):
            return
        if any(key in self.items for key in keys):
            raise registry.RegistryConditionalWriteFailed()
        for item in (binding, reservation, audit):
            self.items[(item["pk"], item["sk"])] = copy.deepcopy(item)

    def transact_confirm_reservation(self, binding, reservation, audit):
        self._begin("idempotent", binding, reservation, audit)
        binding_key = (binding["pk"], binding["sk"])
        reservation_key = (reservation["pk"], reservation["sk"])
        audit_key = (audit["pk"], audit["sk"])
        if (
            self.items.get(binding_key) != binding
            or self.items.get(reservation_key) != reservation
            or audit_key in self.items
        ):
            raise registry.RegistryConditionalWriteFailed()
        self.items[audit_key] = copy.deepcopy(audit)

    def transact_replace_binding(self, binding, reservation, expected, audit):
        self._begin("update", binding, reservation, audit)
        binding_key = (binding["pk"], binding["sk"])
        reservation_key = (reservation["pk"], reservation["sk"])
        audit_key = (audit["pk"], audit["sk"])
        current = self.items.get(binding_key)
        if (
            current is None
            or self.items.get(reservation_key) != reservation
            or audit_key in self.items
            or any(current.get(field) != value for field, value in expected.items())
        ):
            raise registry.RegistryConditionalWriteFailed()
        self.items[binding_key] = copy.deepcopy(binding)
        self.items[audit_key] = copy.deepcopy(audit)


class GlobalReservationAndAuditTests(unittest.TestCase):
    def test_first_reservation_atomically_creates_binding_reservation_and_safe_audit(self):
        store = AtomicRegistryStore()

        result = registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=audit_context(1),
        )

        self.assertTrue(result["created"])
        self.assertEqual([call["operation"] for call in store.transactions], ["create"])
        self.assertEqual(len(store.items), 3)

        transaction = store.transactions[0]
        reservation = transaction["reservation"]
        audit = transaction["audit"]
        self.assertEqual(
            (reservation["pk"], reservation["sk"]),
            ("HUB_RESERVATION#thehairnarrative-com-journal", "GLOBAL"),
        )
        self.assertEqual(reservation["reservationOwner"], result["record"]["reservationOwner"])
        self.assertEqual(
            set(audit),
            {
                "pk",
                "sk",
                "recordType",
                "schemaVersion",
                "operation",
                "outcome",
                "occurredAt",
                "requestId",
                "registryRevision",
                "writerEpoch",
                "ownerDigest",
                "actorType",
            },
        )
        self.assertEqual(audit["operation"], "reserve")
        self.assertEqual(audit["outcome"], "created")
        self.assertEqual(audit["actorType"], "registry-operator")
        serialized = repr(audit)
        for private_field in (
            "tenantId",
            "reservationOwner",
            "resourceBindings",
            "descriptorSha256",
            "cookieNamespace",
            "articleBody",
        ):
            self.assertNotIn(private_field, serialized)
        for private_value in (
            "thehairnarrative-com",
            "endefiz7dkk635k6di6k",
            "arn:aws:",
            "a" * 64,
        ):
            self.assertNotIn(private_value, serialized)

    def test_exact_same_owner_is_idempotent_and_appends_guarded_audit(self):
        store = AtomicRegistryStore()
        first = registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=audit_context(1),
        )

        second = registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=audit_context(2),
        )

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(
            [call["operation"] for call in store.transactions],
            ["create", "create", "idempotent"],
        )
        audits = [
            item
            for item in store.items.values()
            if item.get("recordType") == "service-binding-registry-audit-v2"
        ]
        self.assertEqual([item["outcome"] for item in audits], ["created", "idempotent"])

    def test_same_request_retry_replays_without_new_or_changed_audit(self):
        store = AtomicRegistryStore()
        context = audit_context(1)
        first = registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=context,
        )
        before = copy.deepcopy(store.items)

        retry = registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=context,
        )

        self.assertTrue(first["created"])
        self.assertFalse(retry["created"])
        self.assertEqual(store.items, before)

    def test_cross_domain_profile_or_tenant_global_owner_is_denied(self):
        for field, value in (
            ("domain", "other.example.com"),
            ("authProfileId", "other-profile"),
            ("tenantId", "other-tenant"),
        ):
            with self.subTest(field=field):
                store = AtomicRegistryStore()
                record = build_record()
                reservation = registry.build_global_hub_reservation(record)
                reservation["reservationOwner"][field] = value
                store.items[(reservation["pk"], reservation["sk"])] = reservation

                with self.assertRaises(registry.RegistryConflictError):
                    registry.reserve_service_binding(
                        store,
                        registry_definition(),
                        audit_context=audit_context(1),
                    )

                self.assertEqual(store.transactions, [])

    def test_coherent_cross_domain_profile_or_tenant_reservation_is_denied(self):
        for field, value in (
            ("domain", "other.example.com"),
            ("authProfileId", "other-profile"),
            ("tenantId", "other-tenant"),
        ):
            with self.subTest(field=field):
                store = AtomicRegistryStore()
                conflicting_record = build_record()
                conflicting_record[field] = value
                conflicting_record["reservationOwner"][field] = value
                reservation = registry.build_global_hub_reservation(conflicting_record)
                store.items[(reservation["pk"], reservation["sk"])] = reservation

                with self.assertRaises(registry.RegistryConflictError):
                    registry.reserve_service_binding(
                        store,
                        registry_definition(),
                        audit_context=audit_context(1),
                    )

                self.assertEqual(store.transactions, [])

    def test_concurrent_conflict_leaves_no_partial_binding_or_audit(self):
        store = AtomicRegistryStore()
        poisoned = registry.build_global_hub_reservation(build_record())
        poisoned["reservationOwner"]["tenantId"] = "concurrent-owner"
        store.fail_next_transaction = True
        store.concurrent_item = poisoned

        with self.assertRaises(registry.RegistryConflictError):
            registry.reserve_service_binding(
                store,
                registry_definition(),
                audit_context=audit_context(1),
            )

        self.assertEqual(
            [item.get("recordType") for item in store.items.values()],
            ["global-hub-reservation-v2"],
        )

    def test_deactivation_retains_byte_identical_reservation_and_appends_audit(self):
        store = AtomicRegistryStore()
        registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=audit_context(1),
        )
        registry.update_service_binding(
            store,
            registry_definition(
                registryRevision=2,
                activationStatus="active",
                writerMode="client-owner",
                writerEpoch=2,
            ),
            expected_registry_revision=1,
            expected_writer_epoch=1,
            audit_context=audit_context(2),
        )
        reservation_key = (
            "HUB_RESERVATION#thehairnarrative-com-journal",
            "GLOBAL",
        )
        before = copy.deepcopy(store.items[reservation_key])

        result = registry.update_service_binding(
            store,
            registry_definition(
                registryRevision=3,
                activationStatus="inactive",
                writerMode="disabled",
                writerEpoch=3,
            ),
            expected_registry_revision=2,
            expected_writer_epoch=2,
            audit_context=audit_context(3),
        )

        self.assertEqual(result["activationStatus"], "inactive")
        self.assertEqual(store.items[reservation_key], before)
        audits = [
            item
            for item in store.items.values()
            if item.get("recordType") == "service-binding-registry-audit-v2"
        ]
        self.assertEqual(len(audits), 3)

    def test_audit_key_collision_rolls_back_the_binding_update(self):
        store = AtomicRegistryStore()
        registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=audit_context(1),
        )
        before = copy.deepcopy(store.items)

        with self.assertRaises(registry.RegistryConflictError):
            registry.update_service_binding(
                store,
                registry_definition(
                    descriptorVersionId="test-v2",
                    registryRevision=2,
                ),
                expected_registry_revision=1,
                expected_writer_epoch=1,
                audit_context=audit_context(1),
            )

        self.assertEqual(store.items, before)

    def test_concurrent_stale_update_changes_neither_binding_nor_audit_from_this_request(self):
        store = AtomicRegistryStore()
        registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=audit_context(1),
        )
        binding_key = ("SERVICE_BINDING#test#thn-journal-test-v2", "REGISTRY#V2")
        concurrent = copy.deepcopy(store.items[binding_key])
        concurrent["descriptorVersionId"] = "concurrent-v2"
        concurrent["registryRevision"] = 2
        concurrent["writerEpoch"] = 2
        store.fail_next_transaction = True
        store.concurrent_item = concurrent

        with self.assertRaises(registry.RegistryConflictError):
            registry.update_service_binding(
                store,
                registry_definition(
                    descriptorVersionId="requested-v2",
                    registryRevision=2,
                    activationStatus="active",
                    writerMode="client-owner",
                    writerEpoch=2,
                ),
                expected_registry_revision=1,
                expected_writer_epoch=1,
                audit_context=audit_context(2),
            )

        self.assertEqual(store.items[binding_key], concurrent)
        audits = [
            item
            for item in store.items.values()
            if item.get("recordType") == registry.AUDIT_RECORD_TYPE
        ]
        self.assertEqual(len(audits), 1)

    def test_invalid_audit_context_fails_before_any_storage_write(self):
        store = AtomicRegistryStore()

        for invalid in (
            {},
            {"occurredAt": "not-a-time", "requestId": "request"},
            {
                "occurredAt": "2026-08-31T12:00:01.000Z",
                "requestId": "private/request?value",
            },
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(registry.RegistryValidationError):
                    registry.reserve_service_binding(
                        store,
                        registry_definition(),
                        audit_context=invalid,
                    )
                self.assertEqual(store.transactions, [])


if __name__ == "__main__":
    unittest.main()
