import base64
import hashlib
import re
import unittest
from pathlib import Path

import service_binding_registry_v2 as registry
import content_hub_v2_registry_fence as registry_fence


TRUSTED_RESOURCE_SCOPE = {
    "partition": "aws",
    "accountId": "123456789012",
    "region": "us-east-1",
}


def registry_definition(**overrides):
    definition = {
        "schemaVersion": 2,
        "environment": "test",
        "domain": "thehairnarrative.com",
        "serviceBindingId": "thn-journal-test-v2",
        "descriptorVersionId": "test-v1",
        "descriptorSha256": "a" * 64,
        "registryRevision": 1,
        "activationStatus": "inactive",
        "writerMode": "disabled",
        "writerEpoch": 1,
        "hubId": "thehairnarrative-com-journal",
        "tenantId": "thehairnarrative-com",
        "cookieNamespace": "endefiz7dkk635k6di6k",
        "authProfileId": "journal-owner",
        "authPolicyVersion": "journal-owner-v1",
        "adminOrigin": "https://admin-test.thehairnarrative.com",
        "resourceBindings": {
            "authoringFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:zoolanding-content-hub-test-ThnContentHubV2Authoring",
            "metadataTableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/zoolanding-content-hub-test-ThnContentHubV2Metadata",
        },
    }
    definition.update(overrides)
    return definition


def build_record(definition=None):
    return registry.build_registry_record(
        definition or registry_definition(),
        trusted_resource_scope=TRUSTED_RESOURCE_SCOPE,
    )


def audit_context(sequence=1):
    return {
        "occurredAt": f"2026-08-31T12:00:0{sequence}.000Z",
        "requestId": f"123e4567-e89b-12d3-a456-42661417400{sequence}",
    }


class ServiceBindingRegistryRecordTests(unittest.TestCase):
    def test_build_record_contains_versioned_coordinates_and_reservation_owner(self):
        record = build_record()

        self.assertEqual(record["pk"], "SERVICE_BINDING#test#thn-journal-test-v2")
        self.assertEqual(record["sk"], "REGISTRY#V2")
        self.assertEqual(record["recordType"], "service-binding-registry-v2")
        self.assertEqual(record["schemaVersion"], 2)
        self.assertEqual(record["descriptorVersionId"], "test-v1")
        self.assertEqual(record["descriptorSha256"], "a" * 64)
        self.assertEqual(record["registryRevision"], 1)
        self.assertEqual(record["writerEpoch"], 1)
        self.assertEqual(
            record["reservationOwner"],
            {
                "environment": "test",
                "domain": "thehairnarrative.com",
                "serviceBindingId": "thn-journal-test-v2",
                "hubId": "thehairnarrative-com-journal",
                "tenantId": "thehairnarrative-com",
                "authProfileId": "journal-owner",
            },
        )

    def test_record_rejects_non_integer_schema_and_non_string_switches(self):
        for field, value in (("schemaVersion", 2.0), ("activationStatus", []), ("writerMode", {})):
            with self.subTest(field=field):
                with self.assertRaises(registry.RegistryValidationError):
                    build_record(registry_definition(**{field: value}))

    def test_record_rejects_every_unapproved_fixed_coordinate(self):
        invalid_coordinates = {
            "environment": "prod",
            "domain": "other.example.com",
            "serviceBindingId": "another-binding",
            "hubId": "another-hub",
            "authProfileId": "another-profile",
            "adminOrigin": "https://other.thehairnarrative.com",
        }

        for field, value in invalid_coordinates.items():
            with self.subTest(field=field):
                with self.assertRaises(registry.RegistryValidationError):
                    build_record(registry_definition(**{field: value}))

    def test_tenant_is_fixed_by_server_contract_not_record_input(self):
        with self.assertRaises(registry.RegistryValidationError):
            build_record(registry_definition(tenantId="operator-poisoned-tenant"))

    def test_cookie_namespace_is_the_canonical_sec_001_derivation(self):
        material = "test|thehairnarrative.com|journal-owner|thehairnarrative-com-journal"
        expected = base64.b32encode(hashlib.sha256(material.encode("utf-8")).digest()).decode("ascii")
        expected = expected.lower()[:20]

        self.assertEqual(expected, "endefiz7dkk635k6di6k")
        self.assertEqual(build_record()["cookieNamespace"], expected)
        with self.assertRaises(registry.RegistryValidationError):
            build_record(registry_definition(cookieNamespace="zoosite-cookie-namespace"))

    def test_admin_origin_must_match_the_exact_approved_string(self):
        for origin in (
            "https://admin-test.thehairnarrative.com/",
            "https://ADMIN-TEST.thehairnarrative.com",
        ):
            with self.subTest(origin=origin):
                with self.assertRaises(registry.RegistryValidationError):
                    build_record(registry_definition(adminOrigin=origin))

    def test_resource_bindings_must_be_exact_arns_without_wildcards(self):
        wildcard = registry_definition(
            resourceBindings={
                "metadataTableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/*",
            }
        )

        with self.assertRaises(registry.RegistryValidationError):
            build_record(wildcard)

    def test_resource_bindings_require_the_closed_task_008_allowlist_and_services(self):
        invalid_bindings = (
            {
                "authoringFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:thn-authoring",
            },
            {
                "authoringFunctionArn": "arn:aws:dynamodb:us-east-1:123456789012:table/not-lambda",
                "metadataTableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/thn-metadata",
            },
            {
                "authoringFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:thn-authoring",
                "metadataTableArn": "arn:aws:lambda:us-east-1:123456789012:function:not-dynamodb",
            },
            {
                "authoringFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:thn-authoring",
                "metadataTableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/thn-metadata",
                "privateSentinelArn": "arn:aws:s3:us-east-1:123456789012:private-sentinel-value",
            },
        )

        for bindings in invalid_bindings:
            with self.subTest(bindings=tuple(bindings)):
                with self.assertRaises(registry.RegistryValidationError) as caught:
                    build_record(registry_definition(resourceBindings=bindings))
                self.assertNotIn("privateSentinelArn", str(caught.exception))
                self.assertNotIn("private-sentinel-value", str(caught.exception))

    def test_resource_bindings_reject_same_scope_zoosite_resources(self):
        zoosite_bindings = (
            (
                "authoringFunctionArn",
                "arn:aws:lambda:us-east-1:123456789012:function:zoolanding-content-hub-test-Authoring",
            ),
            (
                "metadataTableArn",
                "arn:aws:dynamodb:us-east-1:123456789012:table/zoolanding-content-hub-test-Metadata",
            ),
        )
        for field, arn in zoosite_bindings:
            bindings = dict(registry_definition()["resourceBindings"])
            bindings[field] = arn
            with self.subTest(field=field):
                with self.assertRaises(registry.RegistryValidationError):
                    build_record(registry_definition(resourceBindings=bindings))

    def test_resource_bindings_match_trusted_partition_account_and_region(self):
        for field, arn in (
            ("authoringFunctionArn", "arn:aws-cn:lambda:us-east-1:123456789012:function:thn-authoring"),
            ("authoringFunctionArn", "arn:aws:lambda:us-west-2:123456789012:function:thn-authoring"),
            ("metadataTableArn", "arn:aws:dynamodb:us-east-1:999999999999:table/thn-metadata"),
        ):
            bindings = dict(registry_definition()["resourceBindings"])
            bindings[field] = arn
            with self.subTest(field=field, arn=arn):
                with self.assertRaises(registry.RegistryValidationError):
                    build_record(registry_definition(resourceBindings=bindings))

    def test_malformed_admin_origin_ports_fail_as_validation_errors(self):
        with self.assertRaises(registry.RegistryValidationError):
            build_record(
                registry_definition(adminOrigin="https://admin-test.thehairnarrative.com:not-a-port")
            )

    def test_field_mismatch_errors_do_not_reflect_unknown_private_input(self):
        definition = registry_definition()
        definition["private-sentinel-do-not-log"] = "value"

        with self.assertRaises(registry.RegistryValidationError) as caught:
            build_record(definition)

        self.assertNotIn("private-sentinel-do-not-log", str(caught.exception))


class FakeRegistryStore:
    def __init__(self):
        self.bindings = {}
        self.create_calls = 0
        self.transactions = []

    def get_trusted_resource_scope(self):
        return dict(TRUSTED_RESOURCE_SCOPE)

    def get_binding(self, key):
        item = self.bindings.get((key["pk"], key["sk"]))
        return dict(item) if item else None

    def get_global_reservation(self, key):
        item = self.bindings.get((key["pk"], key["sk"]))
        return dict(item) if item else None

    def transact_create_binding(self, binding, reservation, audit):
        self.create_calls += 1
        self.transactions.append("create")
        keys = [
            (binding["pk"], binding["sk"]),
            (reservation["pk"], reservation["sk"]),
            (audit["pk"], audit["sk"]),
        ]
        if any(key in self.bindings for key in keys):
            raise registry.RegistryConditionalWriteFailed()
        for item in (binding, reservation, audit):
            self.bindings[(item["pk"], item["sk"])] = dict(item)

    def transact_confirm_reservation(self, binding, reservation, audit):
        self.transactions.append("idempotent")
        binding_key = (binding["pk"], binding["sk"])
        reservation_key = (reservation["pk"], reservation["sk"])
        audit_key = (audit["pk"], audit["sk"])
        if (
            self.bindings.get(binding_key) != binding
            or self.bindings.get(reservation_key) != reservation
            or audit_key in self.bindings
        ):
            raise registry.RegistryConditionalWriteFailed()
        self.bindings[audit_key] = dict(audit)

    def transact_replace_binding(self, binding, reservation, expected, audit):
        self.transactions.append("update")
        key = (binding["pk"], binding["sk"])
        current = self.bindings.get(key)
        reservation_key = (reservation["pk"], reservation["sk"])
        audit_key = (audit["pk"], audit["sk"])
        if (
            not current
            or self.bindings.get(reservation_key) != reservation
            or audit_key in self.bindings
        ):
            raise registry.RegistryConditionalWriteFailed()
        for field, value in expected.items():
            if current.get(field) != value:
                raise registry.RegistryConditionalWriteFailed()
        self.bindings[key] = dict(binding)
        self.bindings[audit_key] = dict(audit)


class ServiceBindingReservationTests(unittest.TestCase):
    def test_reserve_creates_one_binding_with_embedded_reservation_owner(self):
        store = FakeRegistryStore()

        result = registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=audit_context(1),
        )

        self.assertTrue(result["created"])
        self.assertEqual(store.create_calls, 1)
        self.assertEqual(result["record"]["activationStatus"], "inactive")
        self.assertEqual(len(store.bindings), 3)
        self.assertEqual(
            result["record"]["reservationOwner"],
            store.bindings[(result["record"]["pk"], result["record"]["sk"])][
                "reservationOwner"
            ],
        )

    def test_reserve_is_idempotent_for_the_exact_same_owner_and_definition(self):
        store = FakeRegistryStore()
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
        self.assertEqual(store.transactions, ["create", "create", "idempotent"])
        self.assertEqual(second["record"], first["record"])

    def test_reserve_denies_an_unapproved_domain_before_storage(self):
        store = FakeRegistryStore()
        registry.reserve_service_binding(
            store,
            registry_definition(),
            audit_context=audit_context(1),
        )
        conflicting = registry_definition(
            domain="other.example.com",
            adminOrigin="https://admin-test.other.example.com",
        )

        with self.assertRaises(registry.RegistryValidationError):
            registry.reserve_service_binding(
                store,
                conflicting,
                audit_context=audit_context(2),
            )

    def test_initial_reservation_is_fail_closed_until_explicit_activation(self):
        store = FakeRegistryStore()

        for field, value in (
            ("activationStatus", "active"),
            ("writerMode", "qa-only"),
            ("writerEpoch", 2),
            ("registryRevision", 2),
        ):
            with self.subTest(field=field):
                with self.assertRaises(registry.RegistryValidationError):
                    registry.reserve_service_binding(
                        store,
                        registry_definition(**{field: value}),
                        audit_context=audit_context(1),
                    )


class ServiceBindingTransitionTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeRegistryStore()
        registry.reserve_service_binding(
            self.store,
            registry_definition(),
            audit_context=audit_context(1),
        )

    def test_activation_increments_revision_without_changing_writer_epoch(self):
        desired = registry_definition(
            registryRevision=2,
            activationStatus="active",
            writerEpoch=1,
        )

        result = registry.update_service_binding(
            self.store,
            desired,
            expected_registry_revision=1,
            expected_writer_epoch=1,
            audit_context=audit_context(2),
        )

        self.assertEqual(result["registryRevision"], 2)
        self.assertEqual(result["activationStatus"], "active")
        self.assertEqual(result["writerMode"], "disabled")
        self.assertEqual(result["writerEpoch"], 1)

    def test_writer_mode_transition_must_increment_epoch_exactly_once(self):
        desired = registry_definition(
            registryRevision=2,
            writerMode="qa-only",
            writerEpoch=2,
        )

        result = registry.update_service_binding(
            self.store,
            desired,
            expected_registry_revision=1,
            expected_writer_epoch=1,
            audit_context=audit_context(2),
        )

        self.assertEqual(result["writerMode"], "qa-only")
        self.assertEqual(result["writerEpoch"], 2)

    def test_writer_epoch_cannot_change_without_a_writer_mode_transition(self):
        desired = registry_definition(registryRevision=2, writerEpoch=2)

        with self.assertRaises(registry.RegistryValidationError):
            registry.update_service_binding(
                self.store,
                desired,
                expected_registry_revision=1,
                expected_writer_epoch=1,
                audit_context=audit_context(2),
            )

    def test_stale_revision_or_epoch_is_denied(self):
        desired = registry_definition(registryRevision=2, activationStatus="active")

        for revision, epoch in ((2, 1), (1, 2)):
            with self.subTest(revision=revision, epoch=epoch):
                with self.assertRaises(registry.RegistryConflictError):
                    registry.update_service_binding(
                        self.store,
                        desired,
                        expected_registry_revision=revision,
                        expected_writer_epoch=epoch,
                        audit_context=audit_context(2),
                    )

    def test_expected_revision_and_epoch_must_be_positive_integers(self):
        desired = registry_definition(registryRevision=2, activationStatus="active")

        for revision, epoch in ((True, 1), (1, True), (0, 1), (1, 0)):
            with self.subTest(revision=revision, epoch=epoch):
                store = FakeRegistryStore()
                registry.reserve_service_binding(
                    store,
                    registry_definition(),
                    audit_context=audit_context(1),
                )
                with self.assertRaises(registry.RegistryValidationError):
                    registry.update_service_binding(
                        store,
                        desired,
                        expected_registry_revision=revision,
                        expected_writer_epoch=epoch,
                        audit_context=audit_context(2),
                    )

    def test_transition_denies_reservation_owner_changes(self):
        desired = registry_definition(
            registryRevision=2,
            tenantId="another-tenant",
        )

        with self.assertRaises(registry.RegistryValidationError):
            registry.update_service_binding(
                self.store,
                desired,
                expected_registry_revision=1,
                expected_writer_epoch=1,
                audit_context=audit_context(2),
            )


class ServiceBindingRegistryTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = Path(__file__).resolve().parents[1].joinpath("template.yaml").read_text(encoding="utf-8")

    def test_registry_table_is_private_retained_encrypted_and_recoverable(self):
        self.assertIn("ServiceBindingRegistryV2Table:", self.template)
        match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2Table:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(match)
        block = match.group(0)

        self.assertIn("DeletionPolicy: Retain", block)
        self.assertIn("UpdateReplacePolicy: Retain", block)
        self.assertIn("PointInTimeRecoveryEnabled: true", block)
        self.assertIn("SSEEnabled: true", block)
        self.assertIn("DeletionProtectionEnabled: true", block)
        self.assertIn("BillingMode: PAY_PER_REQUEST", block)
        self.assertIn("TableName: zoolanding-content-hub-test-ServiceBindingRegistryV2", block)
        self.assertIn(
            "Fn::Sub: arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/zoolanding-content-hub-test-ServiceBindingRegistryV2",
            block,
        )
        self.assertNotIn("${AWS::StackName}-ServiceBindingRegistryV2", block)
        self.assertNotIn("- ServiceBindingRegistryV2Table\n                      - Arn", block)
        allow_statements = re.findall(
            r"(?ms)- Sid: Allow.*?(?=\n\s+- Sid:|\Z)",
            block,
        )
        self.assertTrue(allow_statements)
        self.assertTrue(all("dynamodb:TransactWriteItems" not in statement for statement in allow_statements))

    def test_operator_invokes_private_lambda_and_has_no_direct_registry_access(self):
        self.assertIn("ServiceBindingRegistryOperatorRoleArn:", self.template)
        self.assertIn("HasServiceBindingRegistryOperatorRole:", self.template)
        self.assertIn("zoolanding-thn-registry-test-operator", self.template)
        self.assertIn("ServiceBindingRegistryV2MutationFunction:", self.template)
        self.assertIn(
            "FunctionName: zoolanding-content-hub-test-ThnServiceBindingRegistryV2Mutation",
            self.template,
        )
        self.assertIn("Handler: service_binding_registry_operator_lambda.lambda_handler", self.template)
        self.assertIn("ServiceBindingRegistryOperatorInvokePolicy:", self.template)
        invoke_policy = re.search(
            r"(?ms)^  ServiceBindingRegistryOperatorInvokePolicy:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(invoke_policy)
        self.assertIn("lambda:InvokeFunction", invoke_policy.group(0))
        self.assertNotIn("dynamodb:", invoke_policy.group(0))

        table_match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2Table:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(table_match)
        table_block = table_match.group(0)
        self.assertNotIn("Ref: ServiceBindingRegistryOperatorRoleArn", table_block)
        self.assertNotIn("AllowNamedTestOperatorExactBinding", table_block)
        self.assertIn("Sid: AllowRegistryMutationFunctionDescribe", table_block)
        self.assertIn("Sid: AllowRegistryMutationFunctionExactRead", table_block)
        self.assertIn("Sid: AllowRegistryMutationFunctionAtomicPut", table_block)
        self.assertIn("Sid: AllowRegistryMutationFunctionAtomicConditionCheck", table_block)
        self.assertIn("Sid: DenyRegistryAccessOutsideMutationFunction", table_block)
        self.assertIn("Sid: DenyRegistryPutOutsideApprovedKeys", self.template)
        self.assertIn("Sid: DenyRegistryPutMissingLeadingKeys", self.template)
        self.assertIn("Sid: DenyRegistryUpdateItem", self.template)
        self.assertIn("Sid: DenyRegistryPutOutsideTransaction", self.template)
        self.assertIn("Sid: DenyRegistryPutFailureValues", self.template)
        self.assertIn("Sid: DenyRegistryDeleteAndBatchWrite", self.template)
        self.assertIn("aws:PrincipalArn", self.template)
        self.assertIn("dynamodb:LeadingKeys", self.template)
        self.assertIn("ForAnyValue:StringNotEquals", self.template)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", self.template)
        self.assertIn("dynamodb:EnclosingOperation", self.template)
        self.assertIn("TransactWriteItems", self.template)
        self.assertIn("dynamodb:PutItem", self.template)
        self.assertIn("dynamodb:UpdateItem", self.template)
        self.assertIn("dynamodb:DeleteItem", self.template)
        self.assertIn("dynamodb:BatchWriteItem", self.template)
        for denied_read in (
            "dynamodb:BatchGetItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:PartiQLSelect",
            "dynamodb:TransactGetItems",
        ):
            self.assertIn(denied_read, table_block)
        deny_key_match = re.search(
            r"(?ms)Sid: DenyRegistryPutOutsideApprovedKeys.*?(?=\n\s+- Sid:)",
            self.template,
        )
        self.assertIsNotNone(deny_key_match)
        deny_key_block = deny_key_match.group(0)
        self.assertIn("dynamodb:PutItem", deny_key_block)
        self.assertIn("ForAnyValue:StringNotEquals", deny_key_block)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", deny_key_block)

    def test_operator_invocation_resources_are_fail_closed_outside_test(self):
        condition_match = re.search(
            r"(?ms)^  HasServiceBindingRegistryOperatorRole:.*?(?=^  [A-Za-z0-9]+:|^Resources:)",
            self.template,
        )
        self.assertIsNotNone(condition_match)
        self.assertIn("Condition: IsTestEnvironment", condition_match.group(0))

    def test_operator_parameter_must_equal_the_exact_local_test_role_arn(self):
        condition_match = re.search(
            r"(?ms)^  HasServiceBindingRegistryOperatorRole:.*?(?=^  [A-Za-z0-9]+:|^Resources:)",
            self.template,
        )
        self.assertIsNotNone(condition_match)
        condition_block = condition_match.group(0)
        self.assertIn("Ref: ServiceBindingRegistryOperatorRoleArn", condition_block)
        self.assertIn(
            "Fn::Sub: arn:${AWS::Partition}:iam::${AWS::AccountId}:role/zoolanding-thn-registry-test-operator",
            condition_block,
        )
        self.assertNotIn("- ''", condition_block)

    def test_lambda_permission_derives_the_operator_from_the_deployment_account(self):
        permission_match = re.search(
            r"(?ms)^  ServiceBindingRegistryOperatorInvokePermission:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(permission_match)
        permission_block = permission_match.group(0)
        self.assertIn(
            "Fn::Sub: arn:${AWS::Partition}:iam::${AWS::AccountId}:role/zoolanding-thn-registry-test-operator",
            permission_block,
        )
        self.assertNotIn("Ref: ServiceBindingRegistryOperatorRoleArn", permission_block)

    def test_only_mutation_lambda_execution_role_has_exact_table_permissions(self):
        role_match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2MutationRole:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(role_match)
        role_block = role_match.group(0)
        self.assertIn("lambda.amazonaws.com", role_block)
        self.assertIn("dynamodb:DescribeTable", role_block)
        self.assertIn("dynamodb:GetItem", role_block)
        self.assertIn("dynamodb:PutItem", role_block)
        self.assertIn("dynamodb:LeadingKeys", role_block)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", role_block)
        self.assertIn(
            "table/zoolanding-content-hub-test-ServiceBindingRegistryV2",
            role_block,
        )
        for forbidden in (
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:TransactWriteItems",
        ):
            self.assertNotIn(forbidden, role_block)

    def test_exact_registry_readers_are_exempted_only_from_get_item_deny(self):
        table_match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2Table:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(table_match)
        table_block = table_match.group(0)
        reader_deny = re.search(
            r"(?ms)- Sid: DenyRegistryGetItemOutsideApprovedConsumers.*?(?=\n\s+- Sid:|\Z)",
            table_block,
        )
        self.assertIsNotNone(reader_deny)
        reader_block = reader_deny.group(0)
        self.assertIn("- dynamodb:GetItem", reader_block)
        self.assertIn("ArnNotEquals:", reader_block)
        exact_roles = (
            "zoolanding-image-upload-test-ThnImageUploadV2Role",
            "zoolanding-content-hub-test-ThnContentHubV2AuthoringRole",
            "zoolanding-content-hub-test-ThnContentHubV2PrivateAssetCollectorRole",
            "zoolanding-content-hub-test-ThnContentHubV2PublisherRole",
            "zoolanding-content-hub-test-ThnContentHubV2PublicMediaRole",
            "zoolanding-content-hub-test-ThnContentHubV2InvalidationWorkerRole",
            "zoolanding-content-hub-test-ThnContentHubV2EmergencyWithdrawRole",
            "zoolanding-content-hub-test-ThnContentHubV2PreparedOrphanCollectorRole",
        )
        for role_name in exact_roles:
            self.assertIn(f"role/{role_name}", reader_block)
        self.assertNotIn("role/*", reader_block)
        self.assertNotIn("dynamodb:PutItem", reader_block)
        self.assertNotIn("dynamodb:TransactWriteItems", reader_block)

        broad_deny = re.search(
            r"(?ms)- Sid: DenyRegistryAccessOutsideMutationFunction.*?(?=\n\s+- Sid:|\Z)",
            table_block,
        )
        self.assertIsNotNone(broad_deny)
        self.assertNotIn("dynamodb:GetItem", broad_deny.group(0))

    def test_shared_v1_roles_receive_no_registry_authority(self):
        self.assertNotIn("ApiProxyRegistryV2ReaderRoleArn", self.template)
        self.assertNotIn("zoolanding-api-proxy-test-", self.template)
        self.assertNotIn("zoolanding-auth-admin-test-FunctionRole", self.template)

        table_match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2Table:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(table_match)
        table_block = table_match.group(0)
        self.assertNotIn("ApiProxyRegistryV2ReaderRoleArn", table_block)
        self.assertNotIn("zoolanding-api-proxy-test-", table_block)
        self.assertNotIn("zoolanding-auth-admin-test-FunctionRole", table_block)

    def test_condition_check_is_limited_to_exact_mutation_roles_key_and_transaction(self):
        table_match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2Table:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(table_match)
        table_block = table_match.group(0)

        allow_match = re.search(
            r"(?ms)- Sid: AllowRegistryConditionCheckForMutationRoles.*?(?=\n\s+- Sid:|\Z)",
            table_block,
        )
        self.assertIsNotNone(allow_match)
        allow_block = allow_match.group(0)
        self.assertIn("- dynamodb:ConditionCheckItem", allow_block)
        self.assertIn(registry_fence.APPROVED_PARTITION_KEY, allow_block)
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", allow_block)
        self.assertIn("dynamodb:ReturnValues: NONE", allow_block)

        exact_mutation_roles = (
            "zoolanding-image-upload-test-ThnImageUploadV2Role",
            "zoolanding-content-hub-test-ThnContentHubV2AuthoringRole",
            "zoolanding-content-hub-test-ThnContentHubV2PrivateAssetCollectorRole",
            "zoolanding-content-hub-test-ThnContentHubV2PublisherRole",
            "zoolanding-content-hub-test-ThnContentHubV2InvalidationWorkerRole",
            "zoolanding-content-hub-test-ThnContentHubV2EmergencyWithdrawRole",
            "zoolanding-content-hub-test-ThnContentHubV2PreparedOrphanCollectorRole",
        )
        for role_name in exact_mutation_roles:
            self.assertIn(f"role/{role_name}", allow_block)
        for read_only_role in (
            "zoolanding-auth-admin-test-FunctionRole",
            "zoolanding-content-hub-test-ThnContentHubV2PublicMediaRole",
            "zoolanding-api-proxy-test-",
        ):
            self.assertNotIn(read_only_role, allow_block)

        for sid in (
            "DenyRegistryConditionCheckOutsideApprovedMutationRoles",
            "DenyRegistryConditionCheckOutsideApprovedKeys",
            "DenyRegistryConditionCheckMissingLeadingKeys",
            "DenyRegistryConditionCheckOutsideTransaction",
            "DenyRegistryConditionCheckFailureValues",
        ):
            deny_match = re.search(
                rf"(?ms)- Sid: {sid}.*?(?=\n\s+- Sid:|\Z)",
                table_block,
            )
            self.assertIsNotNone(deny_match, sid)
            self.assertIn("- dynamodb:ConditionCheckItem", deny_match.group(0))

        self.assertNotIn("dynamodb:TransactWriteItems", table_block)

    def test_registry_has_no_http_mutation_route(self):
        self.assertNotIn("/service-binding-registry", self.template)
        self.assertNotIn("/registry-v2", self.template)
        function_match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2MutationFunction:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            self.template,
        )
        self.assertIsNotNone(function_match)
        self.assertNotIn("Events:", function_match.group(0))
        self.assertNotIn("FunctionUrl", function_match.group(0))


if __name__ == "__main__":
    unittest.main()
