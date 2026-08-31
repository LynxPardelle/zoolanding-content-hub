import io
import json
import unittest

from tests.test_service_binding_registry_v2 import registry_definition
from tools import service_binding_registry_operator as operator


class RecordingLambdaClient:
    def __init__(self, response=None):
        self.calls = []
        self.response = response or {
            "StatusCode": 200,
            "Payload": io.BytesIO(
                json.dumps(
                    {
                        "ok": True,
                        "operation": "reserve",
                        "environment": "test",
                        "domain": "thehairnarrative.com",
                        "serviceBindingId": "thn-journal-test-v2",
                        "descriptorVersionId": "test-v1",
                        "registryRevision": 1,
                        "created": True,
                    }
                ).encode("utf-8")
            ),
        }

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class RecordingStsClient:
    def __init__(self, arn=None, account="123456789012"):
        self.arn = arn or (
            "arn:aws:sts::123456789012:assumed-role/"
            "zoolanding-thn-registry-test-operator/github-actions"
        )
        self.account = account

    def get_caller_identity(self):
        return {"Arn": self.arn, "Account": self.account}


class RecordingSession:
    def __init__(self, lambda_client=None, sts_client=None):
        self.lambda_client = lambda_client or RecordingLambdaClient()
        self.sts_client = sts_client or RecordingStsClient()
        self.client_names = []

    def client(self, service_name):
        self.client_names.append(service_name)
        if service_name == "sts":
            return self.sts_client
        if service_name == "lambda":
            return self.lambda_client
        raise AssertionError(f"unexpected service client: {service_name}")


class RegistryOperatorIdentityTests(unittest.TestCase):
    def test_named_role_and_its_oidc_session_are_accepted(self):
        expected = "arn:aws:iam::123456789012:role/zoolanding-thn-registry-test-operator"

        self.assertEqual(operator.require_named_operator(expected, "123456789012"), expected)
        self.assertEqual(
            operator.require_named_operator(
                "arn:aws:sts::123456789012:assumed-role/zoolanding-thn-registry-test-operator/github-actions",
                "123456789012",
            ),
            expected,
        )

    def test_unknown_role_user_and_cross_account_session_are_denied(self):
        callers = (
            "arn:aws:iam::123456789012:role/other-role",
            "arn:aws:iam::123456789012:user/operator",
            "arn:aws:sts::999999999999:assumed-role/zoolanding-thn-registry-test-operator/session",
        )

        for caller in callers:
            with self.subTest(caller=caller):
                with self.assertRaises(operator.OperatorAuthorizationError):
                    operator.require_named_operator(caller, "123456789012")

    def test_parser_exposes_no_table_or_arbitrary_function_selector(self):
        help_text = operator.build_parser().format_help()

        self.assertNotIn("--table-name", help_text)
        self.assertNotIn("--function-name", help_text)
        self.assertNotIn("--operator-role-arn", help_text)
        self.assertNotIn("--tenant", help_text)


class RegistryOperatorInvocationTests(unittest.TestCase):
    def test_unknown_operator_is_denied_before_lambda_client_construction(self):
        session = RecordingSession(
            sts_client=RecordingStsClient(
                arn="arn:aws:iam::123456789012:role/other-role",
            )
        )

        with self.assertRaises(operator.OperatorAuthorizationError):
            operator.execute_operation(
                session,
                operation="reserve",
                definition=registry_definition(),
            )

        self.assertEqual(session.client_names, ["sts"])
        self.assertEqual(session.lambda_client.calls, [])

    def test_exact_operator_invokes_only_the_exact_private_lambda_request_response(self):
        session = RecordingSession()

        summary = operator.execute_operation(
            session,
            operation="reserve",
            definition=registry_definition(),
        )

        self.assertEqual(session.client_names, ["sts", "lambda"])
        self.assertNotIn("dynamodb", session.client_names)
        self.assertTrue(summary["ok"])
        request = session.lambda_client.calls[-1]
        self.assertEqual(
            request["FunctionName"],
            "zoolanding-content-hub-test-ThnServiceBindingRegistryV2Mutation",
        )
        self.assertEqual(request["InvocationType"], "RequestResponse")
        payload = json.loads(request["Payload"].decode("utf-8"))
        self.assertEqual(set(payload), {"operation", "definition"})
        self.assertEqual(payload["operation"], "reserve")
        self.assertEqual(payload["definition"]["domain"], "thehairnarrative.com")

    def test_update_payload_contains_only_closed_concurrency_fields(self):
        session = RecordingSession(
            lambda_client=RecordingLambdaClient(
                {
                    "StatusCode": 200,
                    "Payload": io.BytesIO(
                        json.dumps(
                            {
                                "ok": True,
                                "operation": "update",
                                "environment": "test",
                                "domain": "thehairnarrative.com",
                                "serviceBindingId": "thn-journal-test-v2",
                                "descriptorVersionId": "test-v2",
                                "registryRevision": 2,
                            }
                        ).encode("utf-8")
                    ),
                }
            )
        )

        operator.execute_operation(
            session,
            operation="update",
            definition=registry_definition(descriptorVersionId="test-v2", registryRevision=2),
            expected_registry_revision=1,
            expected_writer_epoch=1,
        )

        payload = json.loads(session.lambda_client.calls[-1]["Payload"].decode("utf-8"))
        self.assertEqual(
            set(payload),
            {"operation", "definition", "expectedRegistryRevision", "expectedWriterEpoch"},
        )
        self.assertEqual(payload["expectedRegistryRevision"], 1)
        self.assertEqual(payload["expectedWriterEpoch"], 1)

    def test_client_projects_a_safe_summary_even_if_lambda_response_contains_private_fields(self):
        private_response = {
            "ok": True,
            "operation": "reserve",
            "environment": "test",
            "domain": "thehairnarrative.com",
            "serviceBindingId": "thn-journal-test-v2",
            "descriptorVersionId": "test-v1",
            "registryRevision": 1,
            "created": True,
            "tenantId": "private-tenant-sentinel",
            "cookieNamespace": "private-cookie-sentinel",
            "resourceBindings": {"privateArn": "private-arn-sentinel"},
            "writerMode": "private-mode-sentinel",
        }
        session = RecordingSession(
            lambda_client=RecordingLambdaClient(
                {
                    "StatusCode": 200,
                    "Payload": io.BytesIO(json.dumps(private_response).encode("utf-8")),
                }
            )
        )

        summary = operator.execute_operation(
            session,
            operation="reserve",
            definition=registry_definition(),
        )
        serialized = json.dumps(summary, sort_keys=True)

        self.assertEqual(
            set(summary),
            {
                "ok",
                "operation",
                "environment",
                "domain",
                "serviceBindingId",
                "descriptorVersionId",
                "registryRevision",
                "created",
            },
        )
        for sentinel in (
            "private-tenant-sentinel",
            "private-cookie-sentinel",
            "private-arn-sentinel",
            "private-mode-sentinel",
        ):
            self.assertNotIn(sentinel, serialized)

    def test_lambda_function_errors_are_sanitized_without_reading_private_payload(self):
        session = RecordingSession(
            lambda_client=RecordingLambdaClient(
                {
                    "StatusCode": 200,
                    "FunctionError": "Unhandled",
                    "Payload": io.BytesIO(b'{"errorMessage":"private-provider-sentinel"}'),
                }
            )
        )

        with self.assertRaisesRegex(operator.OperatorServiceError, "registry service request failed") as caught:
            operator.execute_operation(
                session,
                operation="reserve",
                definition=registry_definition(),
            )

        self.assertNotIn("private-provider-sentinel", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
