"""The existing private mediator can inspect, but inspection cannot mutate."""

from copy import deepcopy
import hashlib
import json
import unittest

import service_binding_registry_operator_lambda as subject
import service_binding_registry_v2 as registry
from tests.test_service_binding_registry_operator_lambda import AUDIT_CONTEXT, RecordingDynamoClient
from tests.test_service_binding_registry_v2 import build_record


NONCE = "1" * 32


class RegistryInspectionTests(unittest.TestCase):
    def setUp(self):
        self.client = RecordingDynamoClient()
        self.record = build_record()
        self.reservation = registry.build_global_hub_reservation(self.record)
        for row in (self.record, self.reservation):
            self.client.items[(row["pk"], row["sk"])] = deepcopy(row)

    def inspect(self, event=None):
        return subject.handle_registry_request(
            event if event is not None else {"operation": "inspect", "nonce": NONCE},
            self.client,
            audit_context=AUDIT_CONTEXT,
        )

    def test_inspection_returns_closed_safe_proof_from_three_strong_reads_without_writes(self):
        before = deepcopy(self.client.items)
        result = self.inspect()
        self.assertTrue(result.get("ok"), "The fixed read-only inspect operation is missing")
        self.assertEqual(set(result), {"ok", "operation", "schemaVersion", "nonce", "scopeVerified", "bindingsVerified",
            "descriptorVersionId", "descriptorSha256", "authPolicyVersion", "activationStatus", "writerMode",
            "writerEpoch", "registryRevision", "registrySha256"})
        self.assertEqual(result["operation"], "inspect")
        self.assertEqual(result["schemaVersion"], 1)
        self.assertEqual(result["nonce"], NONCE)
        self.assertIs(result["scopeVerified"], True)
        self.assertIs(result["bindingsVerified"], True)
        expected = hashlib.sha256(json.dumps({"binding": self.record, "reservation": self.reservation},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        self.assertEqual(result["registrySha256"], expected)
        self.assertEqual(self.client.items, before)
        self.assertEqual([name for name, _ in self.client.calls], ["describe_table", "get_item", "get_item", "get_item"])
        reads = [request for name, request in self.client.calls if name == "get_item"]
        self.assertTrue(all(request["ConsistentRead"] is True for request in reads))
        self.assertTrue(all(request["TableName"] == subject.APPROVED_TABLE_NAME for request in reads))
        self.assertEqual(reads[0]["Key"], reads[2]["Key"])
        self.assertNotEqual(reads[0]["Key"], reads[1]["Key"])
        encoded = json.dumps(result)
        for forbidden in ("arn:", "reservationOwner", "resourceBindings", "cookieNamespace", "tenantId", "pk", "sk"):
            self.assertNotIn('"' + forbidden + '"' if forbidden != "arn:" else forbidden, encoded)

    def test_noncanonical_nonce_extra_selectors_and_http_events_fail_before_storage(self):
        events = [{"operation": "inspect", "nonce": nonce} for nonce in (None, True, "", "a" * 31, "A" * 32, "a" * 33)]
        events += [{"operation": "inspect", "nonce": NONCE, key: value} for key, value in
                   (("tableName", "other"), ("definition", {}), ("requestContext", {}), ("expectedWriterEpoch", 1))]
        for event in events:
            with self.subTest(event=event):
                self.client.calls.clear()
                self.assertFalse(self.inspect(event)["ok"])
                self.assertEqual(self.client.calls, [])

    def test_absent_or_crossed_reservation_is_not_created_or_repaired(self):
        key = (self.reservation["pk"], self.reservation["sk"])
        for replacement in (None, {**self.reservation, "ownerDigest": "b" * 64}):
            with self.subTest(replacement=replacement):
                if replacement is None:
                    self.client.items.pop(key, None)
                else:
                    self.client.items[key] = replacement
                before = deepcopy(self.client.items)
                self.assertFalse(self.inspect()["ok"])
                self.assertEqual(self.client.items, before)
                self.assertTrue(all(name in {"describe_table", "get_item"} for name, _ in self.client.calls))

    def test_malformed_scope_bindings_and_unknown_fields_fail_closed(self):
        mutations = [dict(self.record, **{field: value}) for field, value in
                     (("writerEpoch", 0), ("writerEpoch", True), ("tenantId", "other"), ("extra", "private-sentinel"),
                      ("adminOrigin", "https://other.example.test"), ("reservationOwner", {}))]
        mutations.append({**self.record, "resourceBindings": {**self.record["resourceBindings"], "extra": "private-sentinel"}})
        mutations.append({**self.record, "resourceBindings": {**self.record["resourceBindings"],
                          "metadataTableArn": "arn:aws:dynamodb:us-east-1:999999999999:table/other"}})
        for row in mutations:
            with self.subTest(row=row):
                self.client.items[(self.record["pk"], self.record["sk"])] = row
                result = self.inspect()
                self.assertFalse(result["ok"])
                self.assertEqual(set(result), {"ok", "error"})
                self.assertNotIn("private-sentinel", json.dumps(result))

    def test_binding_changed_between_strong_reads_is_rejected(self):
        original = self.client.get_item
        calls = 0
        def changing_read(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                self.client.items[(self.record["pk"], self.record["sk"])]["registryRevision"] += 1
            return original(**kwargs)
        self.client.get_item = changing_read
        self.assertFalse(self.inspect()["ok"])

    def test_provider_errors_are_sanitized_and_never_retried_as_reserve(self):
        def denied(**kwargs):
            raise RuntimeError("private-provider-sentinel")
        self.client.get_item = denied
        result = self.inspect()
        self.assertFalse(result["ok"])
        self.assertNotIn("private-provider-sentinel", json.dumps(result))
        self.assertFalse(any(name.startswith("transact") for name, _ in self.client.calls))


if __name__ == "__main__":
    unittest.main()
