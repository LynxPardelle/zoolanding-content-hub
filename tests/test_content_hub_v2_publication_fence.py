"""THN-only final-session permission; no live IAM or table access."""
import importlib
import re
import unittest

from test_thn_content_hub_v2_task_019_template import _template, _resource
from test_content_hub_v2_authorization import FakeAuthorizationStore, REGISTRY
from content_hub_v2_authorization import load_authorization_context
from content_hub_v2_editor_model import EditorValidationError


class PublicationFenceTests(unittest.TestCase):
    def test_session_permission_is_only_an_in_transaction_condition_without_returned_values(self):
        role = _resource(_template(), "ThnContentHubV2PublisherRole")
        matching = [s for s in re.split(r"(?m)^\s+- Sid: ", role)
                    if "table/zoolanding-auth-admin-test-ThnSessionV2" in s]
        self.assertEqual(len(matching), 1)
        statement = matching[0]
        self.assertEqual(re.findall(r"- (dynamodb:[A-Za-z*]+)", statement), ["dynamodb:ConditionCheckItem"])
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", statement)
        self.assertIn("dynamodb:ReturnValues: NONE", statement)
        self.assertNotIn("ThnCurrentUserStateV2", statement)
        self.assertNotIn("Resource: '*'", statement)

    def test_shared_actor_fence_binds_subject_purpose_scope_version_expiry_and_revocation(self):
        fence = importlib.import_module("content_hub_v2_actor_fence")
        auth = load_authorization_context(FakeAuthorizationStore(), session_id_hash="a"*64,
                                           registry_record=REGISTRY, now_epoch=1000)
        checks = fence.actor_condition_checks(auth, "a"*64, 1000)
        self.assertEqual(len(checks), 2)
        session = checks[1]["ConditionCheck"]
        self.assertEqual(session["TableName"], "zoolanding-auth-admin-test-ThnSessionV2")
        self.assertEqual(session["Key"], {"sessionIdHash":{"S":"a"*64}})
        for expression in ("#subject = :subject", "#purpose = :purpose", "#version = :version",
                           "#scope = :scope", "idleExpiresAt > :now", "absoluteExpiresAt > :now",
                           "attribute_not_exists(revokedAt)", "attribute_type(revokedAt, :nullType)"):
            self.assertIn(expression, session["ConditionExpression"])
        self.assertNotIn("ReturnValuesOnConditionCheckFailure", session)
        self.assertEqual(session["ExpressionAttributeValues"][":nullType"], {"S":"NULL"})

    def test_malformed_session_or_authority_is_rejected_before_any_transaction(self):
        fence = importlib.import_module("content_hub_v2_actor_fence")
        auth = load_authorization_context(FakeAuthorizationStore(), session_id_hash="a"*64,
                                           registry_record=REGISTRY, now_epoch=1000)
        for session_hash,now in [("",1000),("plaintext-session",1000),("a"*64,True),("a"*64,-1)]:
            with self.assertRaises(EditorValidationError):
                fence.actor_condition_checks(auth,session_hash,now)
        from dataclasses import replace
        for overrides in ({"account_purpose":"admin"},{"session_version":True},
                          {"domain":"zoositioweb.com.mx"},{"subject":""}):
            with self.assertRaises(EditorValidationError):
                fence.actor_condition_checks(replace(auth,**overrides),"a"*64,1000)

    def test_editor_retains_the_exact_shared_fence(self):
        fence = importlib.import_module("content_hub_v2_actor_fence")
        editor = importlib.import_module("content_hub_v2_editor_store")
        self.assertIs(editor.actor_condition_checks,fence.actor_condition_checks)


if __name__ == "__main__": unittest.main()
