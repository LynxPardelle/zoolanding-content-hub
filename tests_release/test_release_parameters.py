"""UsePrevious is verified against the complete DescribeChangeSet readback."""

import unittest
from tools import thn_test_release as subject


class EffectiveParametersTests(unittest.TestCase):
    def test_resolves_previous_masked_shared_values_and_new_defaults_without_reemission(self):
        self.assertTrue(hasattr(subject, "effective_parameters"), "Complete parameter readback validation is missing")
        template = {"Parameters": {"SharedSecret": {"NoEcho": True}, "Enable": {"Default": "false"}, "NewClosed": {"Default": "BLOCKED"}}}
        parameters = [{"ParameterKey": "SharedSecret", "UsePreviousValue": True}, {"ParameterKey": "Enable", "ParameterValue": "true"}]
        result = subject.effective_parameters(template, {"SharedSecret": "****"}, parameters)
        self.assertEqual(result, {"SharedSecret": "****", "Enable": "true", "NewClosed": "BLOCKED"})
        self.assertNotIn("****", str(parameters))

    def test_missing_required_parameter_or_unknown_override_is_rejected(self):
        self.assertTrue(hasattr(subject, "effective_parameters"), "Complete parameter readback validation is missing")
        with self.assertRaises(subject.ReleaseBlocked):
            subject.effective_parameters({"Parameters": {"Required": {}}}, {}, [])
        with self.assertRaises(subject.ReleaseBlocked):
            subject.effective_parameters({"Parameters": {}}, {}, [{"ParameterKey": "Extra", "ParameterValue": "x"}])


if __name__ == "__main__":
    unittest.main()
