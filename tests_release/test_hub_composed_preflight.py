"""Check the actual composed template, not only the source template."""
from copy import deepcopy
import hashlib
import unittest
from unittest.mock import patch
from tools import thn_test_release as release
from test_hub_failed_change_set import Cloud
from test_thn_test_release import ACCOUNT


class ComposedPreflightTests(unittest.TestCase):
    def setUp(self):
        cloud = Cloud()
        with patch.object(release, "ACCOUNT_HASH", hashlib.sha256(ACCOUNT.encode()).hexdigest()):
            self.template = release.bind_test_rule_account(
                release.compose_template(cloud.source, cloud.original, "provision", cloud.processed), ACCOUNT)

    def validate(self, template):
        self.assertTrue(hasattr(release, "validate_composed_template"), "Final artifact needs a pre-upload validation")
        release.validate_composed_template(template)

    def test_supported_composed_artifact_is_unchanged(self):
        before = deepcopy(self.template)
        self.validate(self.template)
        self.assertEqual(self.template, before)

    def test_unsupported_rule_function_is_rejected(self):
        for function in ["Fn::Sub", "Fn::If", "Fn::Join", "Fn::GetAtt"]:
            with self.subTest(function=function):
                bad = deepcopy(self.template)
                bad["Rules"]["ThnContentHubV2ActivationRule"]["Assertions"].append({"Assert": {"Fn::Equals": [{function: "invalid"}, "value"]}})
                with self.assertRaises(release.ReleaseBlocked):
                    self.validate(bad)

    def test_missing_composed_condition_is_rejected(self):
        del self.template["Conditions"]["HasThnContentHubV2EmergencyOperatorRole"]
        with self.assertRaises(release.ReleaseBlocked):
            self.validate(self.template)
