"""Operator inspection keeps existing IAM authority and uses no data client."""

import io
import json
import unittest

from tools import service_binding_registry_operator as subject
from tests.test_service_binding_registry_operator import RecordingLambdaClient, RecordingSession, RecordingStsClient

NONCE = "a" * 32


def proof():
    return {"ok": True, "operation": "inspect", "schemaVersion": 1, "nonce": NONCE,
            "scopeVerified": True, "bindingsVerified": True, "descriptorVersionId": "reviewed-v1",
            "descriptorSha256": "b" * 64, "authPolicyVersion": "policy-v1", "activationStatus": "inactive",
            "writerMode": "disabled", "writerEpoch": 2, "registryRevision": 3, "registrySha256": "c" * 64}


def session(payload):
    return RecordingSession(lambda_client=RecordingLambdaClient(
        {"StatusCode": 200, "Payload": io.BytesIO(json.dumps(payload).encode())}))


class RegistryOperatorInspectionTests(unittest.TestCase):
    def test_inspect_command_has_no_resource_or_record_file_selector(self):
        self.assertIn("inspect", subject.build_parser().format_help(), "The inspect CLI command is missing")
        args = subject.build_parser().parse_args(["inspect"])
        self.assertEqual(set(vars(args)), {"region", "operation"})
        self.assertEqual(args.operation, "inspect")

    def test_inspection_invokes_exact_existing_private_function_without_data_or_cfn_client(self):
        self.assertTrue(hasattr(subject, "execute_inspection"), "The inspection client is missing")
        client = session(proof())
        result = subject.execute_inspection(client, nonce=NONCE)
        self.assertEqual(result, proof())
        self.assertEqual(client.client_names, ["sts", "lambda"])
        request = client.lambda_client.calls[0]
        self.assertEqual(request["FunctionName"], subject.APPROVED_FUNCTION_NAME)
        self.assertEqual(request["InvocationType"], "RequestResponse")
        self.assertEqual(json.loads(request["Payload"]), {"operation": "inspect", "nonce": NONCE})
        self.assertNotIn("LogType", request)

    def test_unknown_principal_cannot_invoke_inspection(self):
        self.assertTrue(hasattr(subject, "execute_inspection"), "The inspection client is missing")
        client = RecordingSession(sts_client=RecordingStsClient(arn="arn:aws:iam::123456789012:role/deployment"))
        with self.assertRaises(subject.OperatorAuthorizationError):
            subject.execute_inspection(client, nonce=NONCE)
        self.assertEqual(client.client_names, ["sts"])

    def test_nonce_crossing_open_shape_invalid_boolean_and_invalid_epoch_fail_closed(self):
        self.assertTrue(hasattr(subject, "execute_inspection"), "The inspection client is missing")
        for key, value in (("nonce", "b" * 32), ("extra", "private-sentinel"), ("scopeVerified", 1),
                           ("writerEpoch", True), ("registryRevision", 0), ("registrySha256", "0"),
                           ("writerMode", "other"), ("descriptorVersionId", "private sentinel")):
            with self.subTest(key=key), self.assertRaises(subject.OperatorServiceError) as caught:
                subject.execute_inspection(session({**proof(), key: value}), nonce=NONCE)
            self.assertNotIn("private-sentinel", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
