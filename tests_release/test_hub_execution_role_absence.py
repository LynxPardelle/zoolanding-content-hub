"""The verified no-CFN-role Hub baseline cannot silently adopt a new role."""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import thn_test_release as release
from tools import thn_registry_provision as registry
import test_registry_provision_runner as fixtures
from test_registry_provision import ACCOUNT
from test_thn_test_release import stack


class HubExecutionRoleAbsenceTests(unittest.TestCase):
    def setUp(self):
        self.session = fixtures.Services()
        fixture = fixtures.RegistryProvisionRunnerTests()
        fixture.setUp()
        self.env = fixture.env
        self.role = f"arn:aws:iam::{ACCOUNT}:role/unreviewed-cfn-execution"
        self.account_hash = hashlib.sha256(ACCOUNT.encode()).hexdigest()

    def test_shared_stack_validator_rejects_any_role_field_in_every_observation(self):
        release.validate_stack(stack(), ACCOUNT, expected_account_hash=self.account_hash)
        for value in (self.role, "", None):
            with self.subTest(value=value), self.assertRaises(release.ReleaseBlocked):
                release.validate_stack({**stack(), "RoleARN": value}, ACCOUNT, expected_account_hash=self.account_hash)

    def test_consistent_new_role_blocks_both_runners_before_package_or_aws_write(self):
        for operation in ("registry-provision", "provision", "enable", "disable"):
            self.session = fixtures.Services()
            describe = self.session.describe_stacks
            def changed(**kwargs):
                result = describe(**kwargs)
                result["Stacks"][0]["RoleARN"] = self.role
                return result
            with self.subTest(operation=operation), patch.object(self.session, "describe_stacks", side_effect=changed), \
                    patch.object(release, "ACCOUNT_HASH", self.account_hash), \
                    patch.object(release, "_package_template", return_value=self.session.candidate) as package, \
                    patch.object(registry.time, "sleep"):
                with self.assertRaisesRegex(release.ReleaseBlocked, "hub_execution_role_must_remain_absent"):
                    release.run_release(self.session, self.env, Path("unused-build"), operation)
                package.assert_not_called()
            self.assertFalse(any(name in {"put_object", "create_change_set", "execute_change_set", "delete_change_set"}
                                 for name, _ in self.session.calls))

    def test_role_appearing_at_each_registry_reread_is_rejected(self):
        for at_read in (2, 3, 4):
            self.session = fixtures.Services()
            describe = self.session.describe_stacks
            calls = 0
            def changed(**kwargs):
                nonlocal calls
                calls += 1
                result = describe(**kwargs)
                if calls >= at_read:
                    result["Stacks"][0]["RoleARN"] = self.role
                return result
            with patch.object(self.session, "describe_stacks", side_effect=changed), \
                    patch.object(release, "ACCOUNT_HASH", self.account_hash), \
                    patch.object(release, "_package_template", return_value=self.session.candidate), \
                    patch.object(registry.time, "sleep"):
                with self.subTest(at_read=at_read), self.assertRaises(release.ReleaseBlocked):
                    registry.run(self.session, self.env, Path("unused-build"))
            self.assertEqual(self.session.executed, at_read >= 3)


if __name__ == "__main__":
    unittest.main()
