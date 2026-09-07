import copy
import hashlib
import json
import os
import pathlib
import unittest
from unittest import mock

import content_hub_v2_authorization as authorization
import content_hub_v2_authoring_handler as authoring
import lambda_function as content_hub


def event_for(
    path,
    operation_name,
    *,
    request_id="task-021-request",
    session_token=None,
    csrf_token=None,
):
    operation_key = "read" if path.endswith("/read") else "action"
    event = {
        "version": "2.0",
        "rawPath": path,
        "headers": {
            "content-type": "application/json",
            "x-zlp-domain": "thehairnarrative.com",
            "x-zlp-auth-profile-id": "journal-owner",
            "x-zlp-content-hub-id": "thehairnarrative-com-journal",
        },
        "requestContext": {
            "requestId": request_id,
            "http": {"method": "POST", "path": path},
        },
        "body": json.dumps(
            {
                "domain": "thehairnarrative.com",
                "input": {
                    "contentHub": {
                        operation_key: operation_name,
                        "hubId": "thehairnarrative-com-journal",
                    }
                },
            }
        ),
    }
    if session_token is not None:
        event["cookies"] = [
            f"__Host-zlp_session_endefiz7dkk635k6di6k={session_token}"
        ]
    if csrf_token is not None:
        event.setdefault("cookies", []).append(
            f"zlp_csrf_endefiz7dkk635k6di6k={csrf_token}"
        )
        event["headers"]["x-zlp-csrf"] = csrf_token
    return event


SCOPE = {
    "environment": "test",
    "domain": "thehairnarrative.com",
    "tenantId": "thehairnarrative-com",
    "hubId": "thehairnarrative-com-journal",
    "authProfileId": "journal-owner",
    "serviceBindingId": "thn-journal-test-v2",
}

REGISTRY = {
    "activationStatus": "active",
    "writerMode": "client-owner",
    "writerEpoch": 7,
    "cookieNamespace": "endefiz7dkk635k6di6k",
    **SCOPE,
}


def session_record(**overrides):
    value = {
        "recordType": "authSessionV2",
        "sessionIdHash": "a" * 64,
        "csrfHash": "b" * 64,
        "scope": dict(SCOPE),
        "subject": "owner-subject",
        "accountHash": "c" * 64,
        "accountPurpose": "client-owner",
        "cognitoUsername": "owner@example.test",
        "sessionVersion": 4,
        "roles": ["journal-owner"],
        "createdAt": 900,
        "lastSeenAt": 950,
        "idleExpiresAt": 1_500,
        "absoluteExpiresAt": 2_000,
        "expiresAt": 2_000,
        "revokedAt": None,
    }
    value.update(overrides)
    return value


def current_user_record(**overrides):
    value = {
        "pk": "CURRENT_USER#test#thn-journal-test-v2",
        "sk": "SUBJECT#owner-subject",
        "contractVersion": 1,
        "scope": dict(SCOPE),
        "subject": "owner-subject",
        "accountPurpose": "client-owner",
        "sessionVersion": 4,
        "enabled": True,
    }
    value.update(overrides)
    return value


class AuthAdminV2Store:
    def __init__(self):
        self.session = session_record()
        self.user = current_user_record()
        self.calls = []

    def get_session(self, session_id_hash, *, consistent_read):
        self.calls.append(("session", session_id_hash, consistent_read))
        return dict(self.session)

    def get_current_user(self, subject, *, consistent_read):
        self.calls.append(("current-user", subject, consistent_read))
        return dict(self.user)


class FakeAuthoringRuntime(AuthAdminV2Store):
    def __init__(self, *, writer_mode="client-owner"):
        super().__init__()
        self.registry = {**REGISTRY, "writerMode": writer_mode}

    def load_registry(self, context):
        del context
        self.calls.append(("registry",))
        return copy.deepcopy(self.registry)

    def now_epoch(self):
        return 1_000


class ThnContentHubV2Task021DispatchTests(unittest.TestCase):
    def test_operation_allowlists_are_exact(self):
        self.assertEqual(
            authoring.ALLOWED_READS,
            {
                "articleList",
                "articleDetail",
                "taxonomyList",
                "assetList",
                "publicBundlePreview",
            },
        )
        self.assertEqual(
            authoring.ALLOWED_ACTIONS,
            {
                "createArticle",
                "updatePackage",
                "uploadAsset",
                "validate",
                "publish",
                "unpublishArticle",
            },
        )

    def test_unknown_operation_returns_closed_v2_error(self):
        response = content_hub.thn_content_hub_v2_handler(
            event_for("/features/content-hub-v2/read", "revisionList"),
            object(),
        )

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertFalse(body["ok"])
        self.assertEqual(body["code"], "unsupported_operation")
        self.assertNotIn("revisionList", response["body"])
        self.assertEqual(response["headers"]["x-content-type-options"], "nosniff")

    def test_non_mapping_event_returns_a_closed_error(self):
        runtime = FakeAuthoringRuntime()

        response = authoring.handle_request([], object(), runtime=runtime)

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(json.loads(response["body"])["code"], "invalid_request")
        self.assertEqual(runtime.calls, [])

    def test_unknown_operation_is_rejected_before_private_runtime_access(self):
        runtime = FakeAuthoringRuntime()

        response = authoring.handle_request(
            event_for("/features/content-hub-v2/action", "archiveArticle"),
            object(),
            runtime=runtime,
        )

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(json.loads(response["body"])["code"], "unsupported_operation")
        self.assertEqual(runtime.calls, [])

    def test_ambiguous_read_and_action_binding_is_rejected_before_runtime_access(self):
        runtime = FakeAuthoringRuntime()
        event = event_for("/features/content-hub-v2/read", "articleList")
        body = json.loads(event["body"])
        body["input"]["contentHub"]["action"] = "publish"
        event["body"] = json.dumps(body)

        response = authoring.handle_request(event, object(), runtime=runtime)

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(json.loads(response["body"])["code"], "invalid_request")
        self.assertEqual(runtime.calls, [])

    def test_browser_scope_mismatch_is_rejected_before_runtime_access(self):
        mutations = (
            lambda event: event["headers"].update({"x-zlp-domain": "other.example"}),
            lambda event: event["headers"].update(
                {"x-zlp-auth-profile-id": "other-profile"}
            ),
            lambda event: event["headers"].update(
                {"x-zlp-content-hub-id": "other-hub"}
            ),
            lambda event: _replace_body_domain(event, "other.example"),
            lambda event: _replace_body_hub(event, "other-hub"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                runtime = FakeAuthoringRuntime()
                event = event_for("/features/content-hub-v2/read", "articleList")
                mutate(event)

                response = authoring.handle_request(event, object(), runtime=runtime)

                self.assertEqual(response["statusCode"], 403)
                self.assertEqual(
                    json.loads(response["body"])["code"], "binding_mismatch"
                )
                self.assertEqual(runtime.calls, [])

    def test_valid_read_requires_the_namespaced_session_cookie(self):
        runtime = FakeAuthoringRuntime()

        response = authoring.handle_request(
            event_for("/features/content-hub-v2/read", "articleList"),
            object(),
            runtime=runtime,
        )

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(json.loads(response["body"])["code"], "auth_required")
        self.assertEqual(runtime.calls, [("registry",)])

    def test_duplicate_namespaced_session_cookie_is_rejected(self):
        runtime = FakeAuthoringRuntime()
        event = event_for(
            "/features/content-hub-v2/read",
            "articleList",
            session_token="first-token",
        )
        event["cookies"].append(
            "__Host-zlp_session_endefiz7dkk635k6di6k=second-token"
        )

        response = authoring.handle_request(event, object(), runtime=runtime)

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(json.loads(response["body"])["code"], "auth_required")
        self.assertEqual(runtime.calls, [("registry",)])

    def test_valid_read_loads_fresh_session_and_current_user_state(self):
        raw_session = "owner-session-token"
        runtime = FakeAuthoringRuntime()
        runtime.session["sessionIdHash"] = hashlib.sha256(
            raw_session.encode("utf-8")
        ).hexdigest()

        response = authoring.handle_request(
            event_for(
                "/features/content-hub-v2/read",
                "articleList",
                session_token=raw_session,
            ),
            object(),
            runtime=runtime,
        )

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(json.loads(response["body"])["code"], "feature_not_ready")
        self.assertEqual(
            [call[0] for call in runtime.calls],
            ["registry", "session", "current-user"],
        )

    def test_mutation_requires_matching_cookie_header_and_stored_csrf_hash(self):
        raw_session = "owner-session-token"
        raw_csrf = "owner-csrf-token"
        runtime = FakeAuthoringRuntime()
        runtime.session.update(
            {
                "sessionIdHash": hashlib.sha256(raw_session.encode("utf-8")).hexdigest(),
                "csrfHash": hashlib.sha256(raw_csrf.encode("utf-8")).hexdigest(),
            }
        )

        missing = authoring.handle_request(
            event_for(
                "/features/content-hub-v2/action",
                "createArticle",
                session_token=raw_session,
            ),
            object(),
            runtime=runtime,
        )
        mismatch = event_for(
            "/features/content-hub-v2/action",
            "createArticle",
            session_token=raw_session,
            csrf_token="wrong-csrf-token",
        )
        mismatched = authoring.handle_request(
            mismatch,
            object(),
            runtime=runtime,
        )

        self.assertEqual(json.loads(missing["body"])["code"], "csrf_denied")
        self.assertEqual(json.loads(mismatched["body"])["code"], "csrf_denied")
        self.assertEqual(missing["statusCode"], 403)
        self.assertEqual(mismatched["statusCode"], 403)

    def test_disabled_writer_mode_rejects_every_allowed_mutation(self):
        raw_session = "owner-session-token"
        raw_csrf = "owner-csrf-token"
        runtime = FakeAuthoringRuntime(writer_mode="disabled")
        runtime.session.update(
            {
                "sessionIdHash": hashlib.sha256(raw_session.encode("utf-8")).hexdigest(),
                "csrfHash": hashlib.sha256(raw_csrf.encode("utf-8")).hexdigest(),
            }
        )

        for operation in authoring.ALLOWED_ACTIONS:
            with self.subTest(operation=operation):
                response = authoring.handle_request(
                    event_for(
                        "/features/content-hub-v2/action",
                        operation,
                        session_token=raw_session,
                        csrf_token=raw_csrf,
                    ),
                    object(),
                    runtime=runtime,
                )
                self.assertEqual(response["statusCode"], 403)
                self.assertEqual(
                    json.loads(response["body"])["code"],
                    "writer_disabled",
                )

    def test_authorization_accepts_the_actual_auth_admin_v2_storage_contract(self):
        store = AuthAdminV2Store()

        context = authorization.load_authorization_context(
            store,
            session_id_hash="a" * 64,
            registry_record=REGISTRY,
            now_epoch=1_000,
        )

        self.assertEqual(context.subject, "owner-subject")
        self.assertEqual(context.account_purpose, "client-owner")
        self.assertEqual(context.session_version, 4)
        self.assertEqual(context.writer_epoch, 7)
        self.assertEqual(
            store.calls,
            [
                ("session", "a" * 64, True),
                ("current-user", "owner-subject", True),
            ],
        )

    def test_template_pins_the_immutable_descriptor_coordinates_in_authoring(self):
        template = (
            pathlib.Path(__file__).resolve().parents[1] / "template.yaml"
        ).read_text(encoding="utf-8")
        authoring_block = template.split(
            "  ThnContentHubV2AuthoringFunction:\n", 1
        )[1].split("\n  ThnContentHubV2PrivateAssetCollectorRole:", 1)[0]

        for parameter, environment_name in (
            ("ThnContentHubV2DescriptorVersionId", "THN_CONTENT_HUB_DESCRIPTOR_VERSION_ID"),
            ("ThnContentHubV2DescriptorSha256", "THN_CONTENT_HUB_DESCRIPTOR_SHA256"),
            ("ThnContentHubV2AuthPolicyVersion", "THN_CONTENT_HUB_AUTH_POLICY_VERSION"),
        ):
            with self.subTest(parameter=parameter):
                self.assertIn(f"  {parameter}:\n", template)
                self.assertIn(f"          {environment_name}:\n", authoring_block)
                self.assertIn(f"            Ref: {parameter}", authoring_block)

    def test_activation_rule_blocks_placeholder_descriptor_coordinates(self):
        template = (
            pathlib.Path(__file__).resolve().parents[1] / "template.yaml"
        ).read_text(encoding="utf-8")
        rule = template.split("  ThnContentHubV2ActivationRule:\n", 1)[1].split(
            "\nGlobals:\n", 1
        )[0]

        self.assertIn("Ref: ThnContentHubV2DescriptorVersionId", rule)
        self.assertIn("Ref: ThnContentHubV2DescriptorSha256", rule)
        self.assertIn("Ref: ThnContentHubV2AuthPolicyVersion", rule)
        self.assertGreaterEqual(rule.count("- BLOCKED"), 3)
        self.assertIn("- '0000000000000000000000000000000000000000000000000000000000000000'", rule)

    def test_aws_runtime_uses_trusted_arn_and_server_owned_descriptor_coordinates(self):
        runtime = authoring.AwsAuthoringRuntime()
        dynamodb = object()
        runtime._client = dynamodb
        environment = {
            "CONTENT_HUB_ENVIRONMENT": "test",
            "CONTENT_HUB_DOMAIN": "thehairnarrative.com",
            "CONTENT_HUB_ID": "thehairnarrative-com-journal",
            "CONTENT_HUB_OWNER_ID": "journal-owner",
            "AUTH_SESSION_TABLE_NAME": authoring.SESSION_TABLE_NAME,
            "AUTH_USER_STATE_TABLE_NAME": authoring.CURRENT_USER_TABLE_NAME,
            "SERVICE_BINDING_REGISTRY_TABLE_NAME": authoring.REGISTRY_TABLE_NAME,
            authoring.DESCRIPTOR_VERSION_ENV: "descriptor-version-1",
            authoring.DESCRIPTOR_SHA256_ENV: "d" * 64,
            authoring.AUTH_POLICY_VERSION_ENV: "auth-policy-1",
        }
        context = type(
            "Context",
            (),
            {
                "invoked_function_arn": (
                    "arn:aws:lambda:us-east-1:123456789012:function:"
                    "zoolanding-content-hub-test-ThnContentHubV2Authoring:test"
                )
            },
        )()

        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            authoring,
            "load_active_service_binding",
            return_value=copy.deepcopy(REGISTRY),
        ) as load:
            record = runtime.load_registry(context)

        self.assertEqual(record, REGISTRY)
        load.assert_called_once_with(
            dynamodb,
            expected_descriptor={
                "descriptorVersionId": "descriptor-version-1",
                "descriptorSha256": "d" * 64,
                "authPolicyVersion": "auth-policy-1",
            },
            trusted_resource_scope={
                "partition": "aws",
                "region": "us-east-1",
                "accountId": "123456789012",
            },
        )

    def test_aws_runtime_rejects_missing_or_blocked_descriptor_coordinates(self):
        valid = {
            "CONTENT_HUB_ENVIRONMENT": "test",
            "CONTENT_HUB_DOMAIN": "thehairnarrative.com",
            "CONTENT_HUB_ID": "thehairnarrative-com-journal",
            "CONTENT_HUB_OWNER_ID": "journal-owner",
            "AUTH_SESSION_TABLE_NAME": authoring.SESSION_TABLE_NAME,
            "AUTH_USER_STATE_TABLE_NAME": authoring.CURRENT_USER_TABLE_NAME,
            "SERVICE_BINDING_REGISTRY_TABLE_NAME": authoring.REGISTRY_TABLE_NAME,
            authoring.DESCRIPTOR_VERSION_ENV: "descriptor-version-1",
            authoring.DESCRIPTOR_SHA256_ENV: "d" * 64,
            authoring.AUTH_POLICY_VERSION_ENV: "auth-policy-1",
        }
        invalid_values = (
            ("CONTENT_HUB_ENVIRONMENT", "prod"),
            ("CONTENT_HUB_DOMAIN", "another.example"),
            ("CONTENT_HUB_ID", "another-hub"),
            ("CONTENT_HUB_OWNER_ID", "another-profile"),
            ("SERVICE_BINDING_REGISTRY_TABLE_NAME", "another-table"),
            (authoring.DESCRIPTOR_VERSION_ENV, ""),
            (authoring.DESCRIPTOR_VERSION_ENV, "BLOCKED"),
            (authoring.DESCRIPTOR_SHA256_ENV, "0" * 64),
            (authoring.AUTH_POLICY_VERSION_ENV, ""),
            (authoring.AUTH_POLICY_VERSION_ENV, "BLOCKED"),
        )
        for key, value in invalid_values:
            with self.subTest(key=key, value=value):
                environment = {**valid, key: value}
                with mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaises(authoring.AuthoringRuntimeError):
                        authoring.AwsAuthoringRuntime._expected_descriptor()

    def test_aws_runtime_accepts_only_the_exact_authoring_function_arn(self):
        invalid_arns = (
            "",
            "arn:aws:lambda:us-east-1:123456789012:role:not-a-function",
            "arn:aws:lambda:us-east-1:123456789012:function:another-function",
            (
                "arn:aws:lambda:us-east-1:123456789012:function:"
                "zoolanding-content-hub-test-ThnContentHubV2Authoring:prod"
            ),
            (
                "arn:aws:lambda:us-east-1:123456789012:function:"
                "zoolanding-content-hub-test-ThnContentHubV2Authoring:test:extra"
            ),
        )
        for arn in invalid_arns:
            with self.subTest(arn=arn):
                context = type("Context", (), {"invoked_function_arn": arn})()
                with self.assertRaises(authoring.AuthoringRuntimeError):
                    authoring.AwsAuthoringRuntime._trusted_resource_scope(context)

    def test_aws_runtime_strongly_reads_only_the_exact_auth_admin_v2_keys(self):
        raw_session = session_record()
        raw_user = current_user_record()
        client = mock.Mock()
        client.get_item.side_effect = [
            {"Item": authoring._marshal_dynamodb_item(raw_session)},
            {"Item": authoring._marshal_dynamodb_item(raw_user)},
        ]
        runtime = authoring.AwsAuthoringRuntime()
        runtime._client = client

        self.assertEqual(runtime.get_session("a" * 64, consistent_read=True), raw_session)
        self.assertEqual(
            runtime.get_current_user("owner-subject", consistent_read=True), raw_user
        )
        self.assertEqual(
            client.get_item.call_args_list,
            [
                mock.call(
                    TableName=authoring.SESSION_TABLE_NAME,
                    Key=authoring._marshal_dynamodb_item(
                        {"sessionIdHash": "a" * 64}
                    ),
                    ConsistentRead=True,
                ),
                mock.call(
                    TableName=authoring.CURRENT_USER_TABLE_NAME,
                    Key=authoring._marshal_dynamodb_item(
                        {
                            "pk": authoring.CURRENT_USER_PARTITION_KEY,
                            "sk": "SUBJECT#owner-subject",
                        }
                    ),
                    ConsistentRead=True,
                ),
            ],
        )

    def test_aws_runtime_commits_mutations_behind_the_registry_epoch_fence(self):
        runtime = authoring.AwsAuthoringRuntime()
        dynamodb = object()
        runtime._client = dynamodb
        environment = {
            "CONTENT_HUB_ENVIRONMENT": "test",
            "CONTENT_HUB_DOMAIN": "thehairnarrative.com",
            "CONTENT_HUB_ID": "thehairnarrative-com-journal",
            "CONTENT_HUB_OWNER_ID": "journal-owner",
            "AUTH_SESSION_TABLE_NAME": authoring.SESSION_TABLE_NAME,
            "AUTH_USER_STATE_TABLE_NAME": authoring.CURRENT_USER_TABLE_NAME,
            "SERVICE_BINDING_REGISTRY_TABLE_NAME": authoring.REGISTRY_TABLE_NAME,
            authoring.DESCRIPTOR_VERSION_ENV: "descriptor-version-1",
            authoring.DESCRIPTOR_SHA256_ENV: "d" * 64,
            authoring.AUTH_POLICY_VERSION_ENV: "auth-policy-1",
        }
        context = type(
            "Context",
            (),
            {
                "invoked_function_arn": (
                    "arn:aws:lambda:us-east-1:123456789012:function:"
                    "zoolanding-content-hub-test-ThnContentHubV2Authoring:test"
                )
            },
        )()
        authorization_context = authorization.AuthorizationContext(
            subject="owner-subject",
            account_purpose="client-owner",
            session_version=4,
            csrf_hash="b" * 64,
            roles=("journal-owner",),
            writer_mode="client-owner",
            writer_epoch=7,
            environment="test",
            domain="thehairnarrative.com",
            service_binding_id="thn-journal-test-v2",
            auth_profile_id="journal-owner",
            tenant_id="thehairnarrative-com",
            hub_id="thehairnarrative-com-journal",
        )
        mutations = [
            {
                "Put": {
                    "TableName": "zoolanding-content-hub-test-ThnContentHubV2Metadata",
                    "Item": {"pk": {"S": "THN#safe"}},
                }
            }
        ]

        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            authoring,
            "execute_registry_fenced_transaction",
            return_value={"ResponseMetadata": {"HTTPStatusCode": 200}},
        ) as execute:
            result = runtime.commit_mutation(
                context,
                authorization_context=authorization_context,
                mutation_items=mutations,
            )

        self.assertEqual(result["ResponseMetadata"]["HTTPStatusCode"], 200)
        execute.assert_called_once_with(
            dynamodb,
            mutation_items=mutations,
            expected_descriptor={
                "descriptorVersionId": "descriptor-version-1",
                "descriptorSha256": "d" * 64,
                "authPolicyVersion": "auth-policy-1",
            },
            expected_writer_mode="client-owner",
            expected_writer_epoch=7,
            trusted_resource_scope={
                "partition": "aws",
                "region": "us-east-1",
                "accountId": "123456789012",
            },
        )


def _replace_body_domain(event, domain):
    body = json.loads(event["body"])
    body["domain"] = domain
    event["body"] = json.dumps(body)


def _replace_body_hub(event, hub_id):
    body = json.loads(event["body"])
    body["input"]["contentHub"]["hubId"] = hub_id
    event["body"] = json.dumps(body)


if __name__ == "__main__":
    unittest.main()
