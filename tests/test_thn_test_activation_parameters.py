"""The TEST delivery workflow must honor only an exact, isolated v2 selection."""
import copy
import json
import subprocess
import unittest
from unittest import mock

from tools import prepare_test_parameters as subject


BASE = {
    "CONTENT_HUB_CONFIG_READY": "true", "CONTENT_HUB_CONFIG_JSON_BASE64": "e30=",
    "AUTH_SESSION_TABLE_NAME": "sessions-test", "AUTH_USER_STATE_TABLE_NAME": "users-test",
}
ROLE = "arn:aws:iam::123456789012:role/zoolanding-content-hub-test-deploy"
V2 = {
    "ServiceBindingRegistryOperatorRoleArn": "arn:aws:iam::123456789012:role/zoolanding-thn-registry-test-operator",
    "EnableThnContentHubV2": "true", "ProvisionThnContentHubV2State": "true",
    "ThnContentHubV2TerminationProtectionGate": "CONFIRMED_ENABLED",
    "ThnContentHubV2EmergencyOperatorRoleArn": "arn:aws:iam::123456789012:role/zoolanding-thn-content-hub-test-operator",
    "ThnContentHubV2PublicDistributionId": "E1234567890TEST",
    "ThnContentHubV2DescriptorVersionId": "reviewed-version-1",
    "ThnContentHubV2DescriptorSha256": "a" * 64,
    "ThnContentHubV2AuthPolicyVersion": "reviewed-policy-1",
}


def environment(parameters=None, **envelope_overrides):
    envelope = {"schemaVersion": 1, "environment": "test", "parameters": copy.deepcopy(V2 if parameters is None else parameters)}
    envelope.update(envelope_overrides)
    return {**BASE, "AWS_ROLE_ARN": ROLE, "THN_V2_TEST_PARAMETERS_JSON": json.dumps(envelope)}


class ThnTestActivationParametersTests(unittest.TestCase):
    def test_selection_contract_is_reported_without_cloud_or_parameter_files(self):
        with mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("sys.argv", ["prepare_test_parameters.py", "--thn-selection-contract"]), \
                mock.patch("builtins.print") as output, \
                mock.patch.object(subject, "verify_cloud_guards", side_effect=AssertionError("No cloud")), \
                mock.patch.object(subject, "build_parameters", side_effect=AssertionError("No files")):
            self.assertEqual(subject.main(), 0)
            output.assert_called_once_with("thn-test-selection/v1")

    def test_exact_selection_is_not_silently_disabled(self):
        parameters, sensitive = subject.build_parameters(environment())
        for key, value in V2.items():
            self.assertEqual(parameters[key], value)
        legacy, legacy_sensitive = subject.build_parameters(BASE)
        self.assertEqual({k: v for k, v in parameters.items() if k not in V2},
                         {k: v for k, v in legacy.items() if k not in V2})
        self.assertEqual(sensitive, legacy_sensitive)

    def test_default_remains_disabled(self):
        parameters, _ = subject.build_parameters(BASE)
        self.assertEqual(parameters["EnableThnContentHubV2"], "false")
        self.assertEqual(parameters["ProvisionThnContentHubV2State"], "false")

    def test_retained_state_and_operator_can_remain_when_runtime_disabled(self):
        values = {**V2, "EnableThnContentHubV2": "false"}
        parameters, _ = subject.build_parameters(environment(values))
        self.assertEqual(parameters["EnableThnContentHubV2"], "false")
        self.assertEqual(parameters["ProvisionThnContentHubV2State"], "true")
        self.assertEqual(parameters["ServiceBindingRegistryOperatorRoleArn"], V2["ServiceBindingRegistryOperatorRoleArn"])

    def test_envelope_is_closed_and_test_only(self):
        for changes in ({"environment": "prod"}, {"schemaVersion": 2}, {"schemaVersion": True},
                        {"writerMode": "client-owner"}, {"parameters": []}):
            with self.subTest(changes=changes), self.assertRaises(subject.ParameterPreparationError):
                subject.build_parameters(environment(**changes))

    def test_missing_unknown_or_shared_keys_fail(self):
        missing = dict(V2)
        missing.pop("ThnContentHubV2DescriptorSha256")
        for values in (missing, {**V2, "ContentHubConfigJsonBase64": "e30="},
                       {**V2, "writerEpoch": "8"}, {**V2, "EnvironmentName": "prod"}):
            with self.subTest(keys=sorted(values)), self.assertRaises(subject.ParameterPreparationError):
                subject.build_parameters(environment(values))

    def test_activation_requires_state_protection_and_real_binding(self):
        for field, value in (("ProvisionThnContentHubV2State", "false"),
                             ("EnableThnContentHubV2", True),
                             ("ThnContentHubV2TerminationProtectionGate", "BLOCKED"),
                             ("ThnContentHubV2DescriptorSha256", "0" * 64),
                             ("ThnContentHubV2DescriptorVersionId", "BLOCKED"),
                             ("ThnContentHubV2AuthPolicyVersion", "BLOCKED"),
                             ("ThnContentHubV2PublicDistributionId", "BLOCKED"),
                             ("ThnContentHubV2EmergencyOperatorRoleArn", "")):
            with self.subTest(field=field, value=value), self.assertRaises(subject.ParameterPreparationError):
                subject.build_parameters(environment({**V2, field: value}))

    def test_operator_scope_cannot_be_broadened(self):
        for role in (ROLE, V2["ThnContentHubV2EmergencyOperatorRoleArn"].replace("test", "prod"),
                     V2["ThnContentHubV2EmergencyOperatorRoleArn"].replace("123456789012", "999999999999"), "*"):
            with self.subTest(role=role), self.assertRaises(subject.ParameterPreparationError):
                subject.build_parameters(environment({**V2, "ThnContentHubV2EmergencyOperatorRoleArn": role}))

    def test_duplicate_keys_and_invalid_json_fail_without_echoing_input(self):
        for raw in ('{"schemaVersion":1,"environment":"test","parameters":{},"parameters":{}}',
                    "not-json-private-sentinel", "[]", " " * 70000):
            env = {**BASE, "AWS_ROLE_ARN": ROLE, "THN_V2_TEST_PARAMETERS_JSON": raw}
            with self.subTest(length=len(raw)):
                with self.assertRaises(subject.ParameterPreparationError) as error:
                    subject.build_parameters(env)
                self.assertNotIn(raw, str(error.exception))

    def test_live_termination_protection_and_account_are_checked_read_only(self):
        cloud = mock.Mock()
        cloud.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
        cloud.client.return_value.describe_stacks.return_value = {"Stacks": [{
            "StackName": "zoolanding-content-hub-test", "StackStatus": "UPDATE_COMPLETE", "EnableTerminationProtection": True,
        }]}
        subject.verify_cloud_guards(environment(), session=cloud)
        cloud.client.return_value.describe_stacks.assert_called_once_with(StackName="zoolanding-content-hub-test")
        for value in (False, None):
            cloud.client.return_value.describe_stacks.return_value["Stacks"][0]["EnableTerminationProtection"] = value
            with self.assertRaises(subject.ParameterPreparationError):
                subject.verify_cloud_guards(environment(), session=cloud)
        cloud.client.return_value.get_caller_identity.return_value = {"Account": "999999999999"}
        with self.assertRaises(subject.ParameterPreparationError):
            subject.verify_cloud_guards(environment(), session=cloud)
        self.assertEqual({call[0] for call in cloud.client.return_value.method_calls},
                         {"get_caller_identity", "describe_stacks"})

    def test_wrong_region_is_denied_before_any_cloud_read(self):
        cloud = mock.Mock()
        for field in ("AWS_REGION", "AWS_DEFAULT_REGION"):
            with self.subTest(field=field), self.assertRaises(subject.ParameterPreparationError):
                subject.verify_cloud_guards({**environment(), field: "us-west-2"}, session=cloud)
        cloud.client.assert_not_called()

    def test_nested_json_has_a_safe_error(self):
        with self.assertRaises(subject.ParameterPreparationError):
            subject.build_parameters({**BASE, "THN_V2_TEST_PARAMETERS_JSON": "[" * 1500 + "0" + "]" * 1500})

    def test_deployment_preflight_uses_available_cli_not_an_uninstalled_sdk(self):
        replies = [
            subprocess.CompletedProcess([], 0, '{"Account":"123456789012"}', ''),
            subprocess.CompletedProcess([], 0, '[{"StackName":"zoolanding-content-hub-test","StackStatus":"UPDATE_COMPLETE","EnableTerminationProtection":true}]', ''),
        ]
        with mock.patch.dict('sys.modules', {'boto3': None}), mock.patch('subprocess.run', side_effect=replies) as command:
            subject.verify_cloud_guards(environment())
        self.assertEqual(command.call_count, 2)
        for call in command.call_args_list:
            args = call.args[0]
            self.assertEqual(args[0], 'aws')
            self.assertIn('--query', args)
            self.assertIn('--no-cli-pager', args)
            self.assertEqual(args[args.index('--region') + 1], 'us-east-1')
            self.assertNotIn('shell', call.kwargs)
        self.assertIn('describe-stacks', command.call_args_list[1].args[0])


if __name__ == "__main__":
    unittest.main()
