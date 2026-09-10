import re
import unittest
from pathlib import Path


class RegistryTask012TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = Path(__file__).resolve().parents[1].joinpath("template.yaml").read_text(
            encoding="utf-8"
        )
        table_match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2Table:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            cls.template,
        )
        role_match = re.search(
            r"(?ms)^  ServiceBindingRegistryV2MutationRole:.*?(?=^  [A-Za-z0-9]+:|\Z)",
            cls.template,
        )
        if table_match is None or role_match is None:
            raise AssertionError("registry table or mutation role is missing")
        cls.table_block = table_match.group(0)
        cls.role_block = role_match.group(0)

    @staticmethod
    def statement(block, sid):
        match = re.search(
            rf"(?ms)- Sid: {re.escape(sid)}.*?(?=\n\s+- Sid:|\Z)",
            block,
        )
        if match is None:
            raise AssertionError(f"missing IAM statement: {sid}")
        return match.group(0)

    def test_mutation_role_separates_read_put_and_condition_check_authority(self):
        read = self.statement(self.role_block, "ReadExactThnRegistryState")
        atomic_put = self.statement(self.role_block, "AtomicPutExactRegistryRows")
        condition_check = self.statement(
            self.role_block,
            "AtomicConditionCheckExactRegistryState",
        )

        self.assertIn("- dynamodb:GetItem", read)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", read)
        self.assertIn("HUB_RESERVATION#thehairnarrative-com-journal", read)
        self.assertNotIn("REGISTRY_AUDIT#test#thn-journal-test-v2", read)
        self.assertNotIn("dynamodb:PutItem", read)
        self.assertNotIn("dynamodb:ConditionCheckItem", read)

        self.assertIn("- dynamodb:PutItem", atomic_put)
        self.assertIn("ForAllValues:StringEquals", atomic_put)
        for partition_key in (
            "SERVICE_BINDING#test#thn-journal-test-v2",
            "HUB_RESERVATION#thehairnarrative-com-journal",
            "REGISTRY_AUDIT#test#thn-journal-test-v2",
        ):
            self.assertIn(partition_key, atomic_put)
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", atomic_put)
        self.assertIn("dynamodb:ReturnValues: NONE", atomic_put)
        self.assertNotIn("dynamodb:GetItem", atomic_put)
        self.assertNotIn("dynamodb:ConditionCheckItem", atomic_put)

        self.assertIn("- dynamodb:ConditionCheckItem", condition_check)
        self.assertIn("ForAllValues:StringEquals", condition_check)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", condition_check)
        self.assertIn("HUB_RESERVATION#thehairnarrative-com-journal", condition_check)
        self.assertNotIn("REGISTRY_AUDIT#test#thn-journal-test-v2", condition_check)
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", condition_check)
        self.assertIn("dynamodb:ReturnValues: NONE", condition_check)
        self.assertNotIn("dynamodb:GetItem", condition_check)
        self.assertNotIn("dynamodb:PutItem", condition_check)

        for forbidden in (
            "dynamodb:TransactWriteItems",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:PartiQLInsert",
            "dynamodb:PartiQLUpdate",
            "dynamodb:PartiQLDelete",
            "dynamodb:Query",
            "dynamodb:Scan",
        ):
            self.assertNotIn(forbidden, self.role_block)

    def test_resource_policy_atomic_allows_are_exact_and_separated(self):
        exact_read = self.statement(self.table_block, "AllowRegistryMutationFunctionExactRead")
        atomic_put = self.statement(self.table_block, "AllowRegistryMutationFunctionAtomicPut")
        condition_check = self.statement(
            self.table_block,
            "AllowRegistryMutationFunctionAtomicConditionCheck",
        )

        self.assertIn("- dynamodb:GetItem", exact_read)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", exact_read)
        self.assertIn("HUB_RESERVATION#thehairnarrative-com-journal", exact_read)
        self.assertNotIn("REGISTRY_AUDIT#test#thn-journal-test-v2", exact_read)
        self.assertNotIn("dynamodb:PutItem", exact_read)
        self.assertNotIn("dynamodb:ConditionCheckItem", exact_read)

        self.assertIn("- dynamodb:PutItem", atomic_put)
        self.assertIn("ForAllValues:StringEquals", atomic_put)
        for partition_key in (
            "SERVICE_BINDING#test#thn-journal-test-v2",
            "HUB_RESERVATION#thehairnarrative-com-journal",
            "REGISTRY_AUDIT#test#thn-journal-test-v2",
        ):
            self.assertIn(partition_key, atomic_put)
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", atomic_put)
        self.assertIn("dynamodb:ReturnValues: NONE", atomic_put)

        self.assertIn("- dynamodb:ConditionCheckItem", condition_check)
        self.assertIn("ForAllValues:StringEquals", condition_check)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", condition_check)
        self.assertIn("HUB_RESERVATION#thehairnarrative-com-journal", condition_check)
        self.assertNotIn("REGISTRY_AUDIT#test#thn-journal-test-v2", condition_check)
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", condition_check)
        self.assertIn("dynamodb:ReturnValues: NONE", condition_check)

    def test_mixed_or_missing_keys_are_explicitly_denied(self):
        condition_keys = self.statement(
            self.table_block,
            "DenyRegistryConditionCheckOutsideApprovedKeys",
        )
        put_keys = self.statement(self.table_block, "DenyRegistryPutOutsideApprovedKeys")
        for statement in (condition_keys, put_keys):
            self.assertIn("ForAnyValue:StringNotEquals", statement)
            self.assertNotIn("ForAllValues:StringNotEquals", statement)

        missing_condition_keys = self.statement(
            self.table_block,
            "DenyRegistryConditionCheckMissingLeadingKeys",
        )
        missing_put_keys = self.statement(
            self.table_block,
            "DenyRegistryPutMissingLeadingKeys",
        )
        for statement in (missing_condition_keys, missing_put_keys):
            self.assertRegex(statement, r"['\"]?Null['\"]?:")
            self.assertRegex(statement, r"dynamodb:LeadingKeys:\s+'?true'?")

        def deny_matches(outside_statement, missing_statement, requested_keys):
            if not requested_keys:
                return bool(re.search(r"['\"]?Null['\"]?:", missing_statement))
            allowed = set(
                re.findall(
                    r"(?m)^\s+- ((?:SERVICE_BINDING|HUB_RESERVATION|REGISTRY_AUDIT)#[^\s]+)$",
                    outside_statement,
                )
            )
            return any(key not in allowed for key in requested_keys)

        binding_key = "SERVICE_BINDING#test#thn-journal-test-v2"
        reservation_key = "HUB_RESERVATION#thehairnarrative-com-journal"
        audit_key = "REGISTRY_AUDIT#test#thn-journal-test-v2"
        foreign_key = "SERVICE_BINDING#test#foreign"

        self.assertFalse(deny_matches(condition_keys, missing_condition_keys, [binding_key]))
        self.assertFalse(deny_matches(condition_keys, missing_condition_keys, [reservation_key]))
        self.assertTrue(deny_matches(condition_keys, missing_condition_keys, [foreign_key]))
        self.assertTrue(
            deny_matches(condition_keys, missing_condition_keys, [binding_key, foreign_key])
        )
        self.assertTrue(deny_matches(condition_keys, missing_condition_keys, []))

        self.assertFalse(deny_matches(put_keys, missing_put_keys, [binding_key]))
        self.assertFalse(deny_matches(put_keys, missing_put_keys, [reservation_key, audit_key]))
        self.assertTrue(deny_matches(put_keys, missing_put_keys, [foreign_key]))
        self.assertTrue(deny_matches(put_keys, missing_put_keys, [audit_key, foreign_key]))
        self.assertTrue(deny_matches(put_keys, missing_put_keys, []))

    def test_direct_writes_and_failure_value_disclosure_are_denied(self):
        direct_put = self.statement(self.table_block, "DenyRegistryPutOutsideTransaction")
        self.assertIn("- dynamodb:PutItem", direct_put)
        self.assertIn("StringNotEqualsIfExists:", direct_put)
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", direct_put)

        put_failure = self.statement(self.table_block, "DenyRegistryPutFailureValues")
        condition_failure = self.statement(
            self.table_block,
            "DenyRegistryConditionCheckFailureValues",
        )
        for action, statement in (
            ("dynamodb:PutItem", put_failure),
            ("dynamodb:ConditionCheckItem", condition_failure),
        ):
            self.assertIn(f"- {action}", statement)
            self.assertIn("dynamodb:ReturnValues: ALL_OLD", statement)

    def test_audit_partition_is_append_only_and_not_readable(self):
        audit_read = self.statement(self.table_block, "DenyRegistryAuditRead")
        reservation_read = self.statement(
            self.table_block,
            "DenyRegistryReservationReadOutsideMutationFunction",
        )
        update_deny = self.statement(self.table_block, "DenyRegistryUpdateItem")
        delete_deny = self.statement(self.table_block, "DenyRegistryDeleteAndBatchWrite")

        self.assertIn("- dynamodb:GetItem", audit_read)
        self.assertIn("REGISTRY_AUDIT#test#thn-journal-test-v2", audit_read)
        self.assertIn("- dynamodb:GetItem", reservation_read)
        self.assertIn("HUB_RESERVATION#thehairnarrative-com-journal", reservation_read)
        self.assertIn("ArnNotEquals:", reservation_read)
        self.assertIn("ServiceBindingRegistryV2MutationRole", reservation_read)
        self.assertIn("dynamodb:UpdateItem", update_deny)
        self.assertIn("dynamodb:DeleteItem", delete_deny)

    def test_shared_v1_and_read_only_roles_receive_no_mutation_authority(self):
        mutation_allows = "\n".join(
            self.statement(self.table_block, sid)
            for sid in (
                "AllowRegistryMutationFunctionAtomicPut",
                "AllowRegistryMutationFunctionAtomicConditionCheck",
                "AllowRegistryConditionCheckForMutationRoles",
            )
        )
        for forbidden_role in (
            "zoolanding-auth-admin-test-FunctionRole",
            "zlp-thn-ch-test-public-media",
            "zoolanding-api-proxy-test-",
        ):
            self.assertNotIn(forbidden_role, mutation_allows)
        self.assertNotIn("dynamodb:TransactWriteItems", self.table_block)


if __name__ == "__main__":
    unittest.main()
