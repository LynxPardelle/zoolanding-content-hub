import copy
import pathlib
import unittest


try:
    import content_hub_v2_authorization as authorization
except ModuleNotFoundError:
    authorization = None


REGISTRY = {
    "activationStatus": "active",
    "writerMode": "client-owner",
    "writerEpoch": 7,
    "environment": "test",
    "domain": "thehairnarrative.com",
    "serviceBindingId": "thn-journal-test-v2",
    "authProfileId": "journal-owner",
    "tenantId": "thehairnarrative-com",
    "hubId": "thehairnarrative-com-journal",
}


def scope_key():
    return (
        "CURRENT_USER#test#thehairnarrative.com#thn-journal-test-v2#journal-owner#"
        "thehairnarrative-com#thehairnarrative-com-journal"
    )


def session(*, purpose="client-owner", version=4, **overrides):
    value = {
        "scopeKey": scope_key(),
        "subject": "owner-subject",
        "accountPurpose": purpose,
        "sessionVersion": version,
        "environment": "test",
        "domain": "thehairnarrative.com",
        "serviceBindingId": "thn-journal-test-v2",
        "authProfileId": "journal-owner",
        "tenantId": "thehairnarrative-com",
        "hubId": "thehairnarrative-com-journal",
        "expiresAt": 2_000,
        "revoked": False,
    }
    value.update(overrides)
    return value


def current_user(*, purpose="client-owner", version=4, **overrides):
    value = {
        "scopeKey": scope_key(),
        "userKey": "USER#owner-subject",
        "recordType": "thn-current-user-v2",
        "subject": "owner-subject",
        "accountPurpose": purpose,
        "sessionVersion": version,
        "environment": "test",
        "domain": "thehairnarrative.com",
        "serviceBindingId": "thn-journal-test-v2",
        "authProfileId": "journal-owner",
        "tenantId": "thehairnarrative-com",
        "hubId": "thehairnarrative-com-journal",
        "enabled": True,
    }
    value.update(overrides)
    return value


class FakeAuthorizationStore:
    def __init__(self, *, session_record=None, user_record=None):
        self.session_record = copy.deepcopy(session_record or session())
        self.user_record = copy.deepcopy(user_record or current_user())
        self.calls = []

    def get_session(self, session_id_hash, *, consistent_read):
        self.calls.append(("session", session_id_hash, consistent_read))
        return copy.deepcopy(self.session_record)

    def get_current_user(self, requested_scope_key, user_key, *, consistent_read):
        self.calls.append(
            ("current-user", requested_scope_key, user_key, consistent_read)
        )
        return copy.deepcopy(self.user_record)


class ContentHubV2AuthorizationExistenceTests(unittest.TestCase):
    def test_authorization_module_exists(self):
        self.assertIsNotNone(authorization)


@unittest.skipIf(authorization is None, "v2 authorization is not implemented")
class ContentHubV2AuthorizationTests(unittest.TestCase):
    def context(self, *, purpose="client-owner", writer_mode=None):
        registry = copy.deepcopy(REGISTRY)
        registry["writerMode"] = writer_mode or purpose
        store = FakeAuthorizationStore(
            session_record=session(purpose=purpose),
            user_record=current_user(purpose=purpose),
        )
        result = authorization.load_authorization_context(
            store,
            session_id_hash="a" * 64,
            registry_record=registry,
            now_epoch=1_000,
        )
        return result, store

    def test_loads_session_and_current_user_strongly_before_authorizing(self):
        context, store = self.context()

        self.assertEqual(context.account_purpose, "client-owner")
        self.assertEqual(context.session_version, 4)
        self.assertEqual(context.writer_mode, "client-owner")
        self.assertEqual(context.writer_epoch, 7)
        self.assertEqual(
            store.calls,
            [
                ("session", "a" * 64, True),
                ("current-user", scope_key(), "USER#owner-subject", True),
            ],
        )

    def test_stale_session_version_denies_before_authorization(self):
        store = FakeAuthorizationStore(
            session_record=session(version=3),
            user_record=current_user(version=4),
        )

        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.load_authorization_context(
                store,
                session_id_hash="a" * 64,
                registry_record=REGISTRY,
                now_epoch=1_000,
            )

        self.assertEqual(len(store.calls), 2)

    def test_missing_mismatched_or_expired_session_fields_fail_closed(self):
        invalid_sessions = [
            session(accountPurpose=None),
            session(purpose="qa"),
            session(scopeKey="CURRENT_USER#other"),
            session(expiresAt=1_000),
            session(revoked=True),
            session(sessionVersion=True),
        ]
        for invalid in invalid_sessions:
            with self.subTest(invalid=invalid):
                store = FakeAuthorizationStore(session_record=invalid)
                with self.assertRaises(authorization.ContentHubV2AuthorizationError):
                    authorization.load_authorization_context(
                        store,
                        session_id_hash="a" * 64,
                        registry_record=REGISTRY,
                        now_epoch=1_000,
                    )

    def test_disabled_or_mismatched_current_user_fails_closed(self):
        invalid_users = [
            current_user(enabled=False),
            current_user(accountPurpose=None),
            current_user(purpose="qa"),
            current_user(version=5),
            current_user(subject="other"),
            current_user(sessionVersion=True),
        ]
        for invalid in invalid_users:
            with self.subTest(invalid=invalid):
                store = FakeAuthorizationStore(user_record=invalid)
                with self.assertRaises(authorization.ContentHubV2AuthorizationError):
                    authorization.load_authorization_context(
                        store,
                        session_id_hash="a" * 64,
                        registry_record=REGISTRY,
                        now_epoch=1_000,
                    )

    def test_writer_mode_matrix_is_exact(self):
        allowed = {("qa-only", "qa"), ("client-owner", "client-owner")}
        for writer_mode in ("disabled", "qa-only", "client-owner"):
            for purpose in ("qa", "client-owner"):
                with self.subTest(writer_mode=writer_mode, purpose=purpose):
                    context, _ = self.context(
                        purpose=purpose,
                        writer_mode=writer_mode,
                    )
                    if (writer_mode, purpose) in allowed:
                        self.assertEqual(
                            authorization.authorize_mutation(
                                context,
                                operation="createArticle",
                            ),
                            purpose,
                        )
                    else:
                        with self.assertRaises(
                            authorization.ContentHubV2AuthorizationError
                        ):
                            authorization.authorize_mutation(
                                context,
                                operation="createArticle",
                            )

    def test_disabled_mode_allows_valid_reads_but_no_mutation(self):
        context, _ = self.context(writer_mode="disabled")
        records = [{"recordPurpose": "client-owner", "articleId": "article-1"}]

        self.assertEqual(
            authorization.authorize_final_read(
                context,
                operation="articleList",
                records=records,
            ),
            records,
        )
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_mutation(context, operation="createArticle")

    def test_list_reads_filter_the_other_purpose_symmetrically(self):
        records = [
            {"recordPurpose": "client-owner", "articleId": "client"},
            {"recordPurpose": "qa", "articleId": "qa"},
        ]
        for purpose in ("qa", "client-owner"):
            with self.subTest(purpose=purpose):
                context, _ = self.context(purpose=purpose, writer_mode="disabled")
                for operation in ("articleList", "assetList"):
                    visible = authorization.authorize_final_read(
                        context,
                        operation=operation,
                        records=records,
                    )
                    self.assertEqual(
                        [record["recordPurpose"] for record in visible],
                        [purpose],
                    )

    def test_missing_record_purpose_fails_the_whole_list_closed(self):
        context, _ = self.context(writer_mode="disabled")

        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_final_read(
                context,
                operation="articleList",
                records=[{"articleId": "unclassified"}],
            )

    def test_direct_detail_and_preview_deny_foreign_purpose(self):
        context, _ = self.context(writer_mode="disabled")
        qa_record = {"recordPurpose": "qa", "articleId": "qa-record"}

        for operation in ("articleDetail", "publicBundlePreview"):
            with self.subTest(operation=operation):
                with self.assertRaises(authorization.ContentHubV2NotFoundError):
                    authorization.authorize_final_read(
                        context,
                        operation=operation,
                        record=qa_record,
                    )

    def test_update_asset_validate_publish_and_unpublish_deny_qa_record(self):
        context, _ = self.context()
        qa_record = {"recordPurpose": "qa", "articleId": "qa-record"}

        for operation in (
            "updatePackage",
            "uploadAsset",
            "validate",
            "publish",
            "unpublishArticle",
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(authorization.ContentHubV2NotFoundError):
                    authorization.authorize_mutation(
                        context,
                        operation=operation,
                        record=qa_record,
                    )

    def test_create_stamps_server_purpose_and_rejects_record_override(self):
        context, _ = self.context()

        self.assertEqual(
            authorization.authorize_mutation(
                context,
                operation="createArticle",
            ),
            "client-owner",
        )
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_mutation(
                context,
                operation="createArticle",
                record={"recordPurpose": "client-owner"},
            )

    def test_epoch_mode_or_scope_change_before_finalization_denies(self):
        context, _ = self.context()
        changes = [
            {"writerEpoch": 8},
            {"writerMode": "disabled"},
            {"activationStatus": "inactive"},
            {"tenantId": "another-tenant"},
        ]

        for change in changes:
            with self.subTest(change=change):
                current = copy.deepcopy(REGISTRY)
                current.update(change)
                with self.assertRaises(authorization.ContentHubV2AuthorizationError):
                    authorization.assert_writer_epoch_current(context, current)

    def test_unknown_operations_and_ambiguous_arguments_fail_closed(self):
        context, _ = self.context(writer_mode="disabled")
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_final_read(context, operation="revisionList", records=[])
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_mutation(context, operation="archiveArticle")

    def test_v1_dispatch_does_not_import_or_reference_v2_authorization(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        handler = (root / "lambda_function.py").read_text(encoding="utf-8")
        template = (root / "template.yaml").read_text(encoding="utf-8")

        self.assertNotIn("content_hub_v2_authorization", handler)
        self.assertNotIn("ContentHubV2Authorization", template)


if __name__ == "__main__":
    unittest.main()
