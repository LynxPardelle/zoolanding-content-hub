"""Compile the single unsupported Rules substitution without relaxing equality."""
from copy import deepcopy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import yaml
from tools import thn_test_release as release

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/zoolanding-thn-content-hub-test-operator"


class RuleAccountBindingTests(unittest.TestCase):
    def setUp(self):
        self.source = yaml.safe_load((Path(__file__).resolve().parents[1] / "template.yaml").read_text())

    def bind(self, source=None, account=ACCOUNT):
        self.assertTrue(hasattr(release, "bind_test_rule_account"), "Rules substitution must be compiled before AWS submission")
        with patch.object(release, "ACCOUNT_HASH", hashlib.sha256(ACCOUNT.encode()).hexdigest()):
            return release.bind_test_rule_account(source or self.source, account)

    @staticmethod
    def equality(template):
        return template["Rules"]["ThnContentHubV2ActivationRule"]["Assertions"][3]["Assert"]["Fn::Equals"]

    def test_exact_substitution_becomes_literal_and_all_other_nodes_are_unchanged(self):
        snapshot = deepcopy(self.source)
        expected = deepcopy(self.source)
        self.equality(expected)[1] = ROLE
        self.assertEqual(self.bind(), expected)
        self.assertEqual(self.source, snapshot)

    def test_all_composed_rules_use_only_supported_rule_functions(self):
        supported = {"Fn::And", "Fn::Contains", "Fn::EachMemberEquals", "Fn::EachMemberIn",
                     "Fn::Equals", "Fn::Not", "Fn::Or", "Fn::RefAll", "Fn::ValueOf", "Fn::ValueOfAll"}
        def inspect(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.startswith("Fn::"):
                        self.assertIn(key, supported)
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)
        inspect(self.bind()["Rules"])

    def test_already_bound_disable_template_is_idempotent(self):
        bound = self.bind()
        self.assertEqual(self.bind(bound), bound)

    def test_unreviewed_account_and_unknown_rule_operand_are_rejected(self):
        for account in ("999999999999", "123", "", None):
            with self.subTest(account=account), self.assertRaises(release.ReleaseBlocked):
                self.bind(account=account)
        for operand in ("*", ROLE.replace(ACCOUNT, "999999999999"),
                        {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/other"}):
            source = deepcopy(self.source)
            self.equality(source)[1] = operand
            with self.subTest(operand=operand), self.assertRaises(release.ReleaseBlocked):
                self.bind(source)

    def test_missing_or_changed_operator_reference_is_rejected(self):
        for changed in ([], [{"Ref": "DifferentOperator"}, self.equality(self.source)[1]]):
            source = deepcopy(self.source)
            source["Rules"]["ThnContentHubV2ActivationRule"]["Assertions"][3]["Assert"]["Fn::Equals"] = changed
            with self.subTest(changed=changed), self.assertRaises(release.ReleaseBlocked):
                self.bind(source)


if __name__ == "__main__":
    unittest.main()
