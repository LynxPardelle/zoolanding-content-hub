import ast
import copy
import pathlib
import traceback
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


def auth_scope():
    return {
        "environment": "test",
        "domain": "thehairnarrative.com",
        "tenantId": "thehairnarrative-com",
        "hubId": "thehairnarrative-com-journal",
        "authProfileId": "journal-owner",
        "serviceBindingId": "thn-journal-test-v2",
    }


def session(*, purpose="client-owner", version=4, **overrides):
    value = {
        "recordType": "authSessionV2",
        "sessionIdHash": "a" * 64,
        "csrfHash": "b" * 64,
        "scope": auth_scope(),
        "subject": "owner-subject",
        "accountHash": "c" * 64,
        "accountPurpose": purpose,
        "sessionVersion": version,
        "roles": ["journal-owner"],
        "cognitoUsername": "owner@example.test",
        "createdAt": 900,
        "lastSeenAt": 950,
        "idleExpiresAt": 1_500,
        "absoluteExpiresAt": 2_000,
        "expiresAt": 2_000,
        "revokedAt": None,
    }
    value.update(overrides)
    return value


def current_user(*, purpose="client-owner", version=4, **overrides):
    value = {
        "pk": "CURRENT_USER#test#thn-journal-test-v2",
        "sk": "SUBJECT#owner-subject",
        "contractVersion": 1,
        "scope": auth_scope(),
        "subject": "owner-subject",
        "accountPurpose": purpose,
        "sessionVersion": version,
        "enabled": True,
    }
    value.update(overrides)
    return value


def scoped_record(*, purpose="client-owner", article_id="article-1", **overrides):
    value = {
        **{field: REGISTRY[field] for field in authorization.THN_CURRENT_USER_SCOPE},
        "recordPurpose": purpose,
        "articleId": article_id,
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

    def get_current_user(self, subject, *, consistent_read):
        self.calls.append(("current-user", subject, consistent_read))
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
        return result, store, registry

    def final_kwargs(self, store, registry):
        return {
            "store": store,
            "session_id_hash": "a" * 64,
            "current_registry_record": registry,
            "now_epoch": 1_000,
        }

    def test_loads_session_and_current_user_strongly_before_authorizing(self):
        context, store, _ = self.context()

        self.assertEqual(context.account_purpose, "client-owner")
        self.assertEqual(context.session_version, 4)
        self.assertEqual(context.writer_mode, "client-owner")
        self.assertEqual(context.writer_epoch, 7)
        self.assertEqual(
            store.calls,
            [
                ("session", "a" * 64, True),
                ("current-user", "owner-subject", True),
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

    def test_provider_failures_are_not_chained_into_authorization_tracebacks(self):
        class ExplodingStore:
            def get_session(self, session_id_hash, *, consistent_read):
                raise RuntimeError("PRIVATE_PROVIDER_SENTINEL")

        with self.assertRaises(
            authorization.ContentHubV2AuthorizationError
        ) as caught:
            authorization.load_authorization_context(
                ExplodingStore(),
                session_id_hash="a" * 64,
                registry_record=REGISTRY,
                now_epoch=1_000,
            )

        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertNotIn("PRIVATE_PROVIDER_SENTINEL", rendered)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_session_version_change_after_context_load_denies_final_access(self):
        context, store, registry = self.context()
        store.user_record["sessionVersion"] = 5

        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_final_read(
                context,
                operation="articleList",
                records=[scoped_record()],
                **self.final_kwargs(store, registry),
            )
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_mutation(
                context,
                operation="createArticle",
                **self.final_kwargs(store, registry),
            )

        self.assertEqual(
            [call[0] for call in store.calls],
            ["session", "current-user"] * 3,
        )

    def test_missing_mismatched_or_expired_session_fields_fail_closed(self):
        invalid_sessions = [
            session(recordType="legacySession"),
            session(sessionIdHash="d" * 64),
            session(accountPurpose=None),
            session(purpose="qa"),
            session(scope={**auth_scope(), "tenantId": "other-tenant"}),
            session(createdAt=951),
            session(idleExpiresAt=2_751),
            session(absoluteExpiresAt=44_101, expiresAt=44_101),
            session(expiresAt=1_000),
            session(revokedAt=999),
            session(sessionVersion=True),
            session(roles=[]),
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
            current_user(pk="CURRENT_USER#test#another-binding"),
            current_user(sk="SUBJECT#other"),
            current_user(contractVersion=2),
            current_user(scope={**auth_scope(), "hubId": "another-hub"}),
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
                    context, store, registry = self.context(
                        purpose=purpose,
                        writer_mode=writer_mode,
                    )
                    if (writer_mode, purpose) in allowed:
                        self.assertEqual(
                            authorization.authorize_mutation(
                                context,
                                operation="createArticle",
                                **self.final_kwargs(store, registry),
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
                                **self.final_kwargs(store, registry),
                            )

    def test_disabled_mode_allows_valid_reads_but_no_mutation(self):
        context, store, registry = self.context(writer_mode="disabled")
        records = [scoped_record()]

        self.assertEqual(
            authorization.authorize_final_read(
                context,
                operation="articleList",
                records=records,
                **self.final_kwargs(store, registry),
            ),
            records,
        )
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_mutation(
                context,
                operation="createArticle",
                **self.final_kwargs(store, registry),
            )

    def test_list_reads_filter_the_other_purpose_symmetrically(self):
        records = [
            scoped_record(purpose="client-owner", article_id="client"),
            scoped_record(purpose="qa", article_id="qa"),
        ]
        for purpose in ("qa", "client-owner"):
            with self.subTest(purpose=purpose):
                context, store, registry = self.context(
                    purpose=purpose,
                    writer_mode="disabled",
                )
                for operation in ("articleList", "assetList"):
                    visible = authorization.authorize_final_read(
                        context,
                        operation=operation,
                        records=records,
                        **self.final_kwargs(store, registry),
                    )
                    self.assertEqual(
                        [record["recordPurpose"] for record in visible],
                        [purpose],
                    )

    def test_missing_record_purpose_fails_the_whole_list_closed(self):
        context, store, registry = self.context(writer_mode="disabled")

        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_final_read(
                context,
                operation="articleList",
                records=[scoped_record(recordPurpose=None)],
                **self.final_kwargs(store, registry),
            )

    def test_taxonomy_reference_read_rejects_a_non_record_candidate(self):
        context, store, registry = self.context(writer_mode="disabled")

        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_final_read(
                context,
                operation="taxonomyList",
                records=[{"taxonomyId": "category"}, "invalid"],
                **self.final_kwargs(store, registry),
            )

    def test_direct_detail_and_preview_deny_foreign_purpose(self):
        context, store, registry = self.context(writer_mode="disabled")
        qa_record = scoped_record(purpose="qa", article_id="qa-record")

        for operation in ("articleDetail", "publicBundlePreview"):
            with self.subTest(operation=operation):
                with self.assertRaises(authorization.ContentHubV2NotFoundError):
                    authorization.authorize_final_read(
                        context,
                        operation=operation,
                        record=qa_record,
                        record_id="qa-record",
                        **self.final_kwargs(store, registry),
                    )

    def test_update_asset_validate_publish_and_unpublish_deny_qa_record(self):
        context, store, registry = self.context()
        qa_record = scoped_record(purpose="qa", article_id="qa-record")

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
                        record_id="qa-record",
                        **self.final_kwargs(store, registry),
                    )

    def test_same_purpose_record_from_another_scope_is_denied(self):
        context, store, registry = self.context()
        foreign_record = scoped_record(tenantId="another-tenant")

        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_final_read(
                context,
                operation="articleDetail",
                record=foreign_record,
                record_id="article-1",
                **self.final_kwargs(store, registry),
            )
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_mutation(
                context,
                operation="publish",
                record=foreign_record,
                record_id="article-1",
                **self.final_kwargs(store, registry),
            )

    def test_direct_id_mismatch_is_not_authorized(self):
        context, store, registry = self.context(writer_mode="disabled")

        with self.assertRaises(authorization.ContentHubV2NotFoundError):
            authorization.authorize_final_read(
                context,
                operation="articleDetail",
                record=scoped_record(article_id="article-2"),
                record_id="article-1",
                **self.final_kwargs(store, registry),
            )

    def test_create_stamps_server_purpose_and_rejects_record_override(self):
        context, store, registry = self.context()

        self.assertEqual(
            authorization.authorize_mutation(
                context,
                operation="createArticle",
                **self.final_kwargs(store, registry),
            ),
            "client-owner",
        )
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_mutation(
                context,
                operation="createArticle",
                record=scoped_record(),
                **self.final_kwargs(store, registry),
            )

    def test_epoch_mode_or_scope_change_before_finalization_denies(self):
        context, _, _ = self.context()
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
        context, store, registry = self.context(writer_mode="disabled")
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_final_read(
                context,
                operation="revisionList",
                records=[],
                **self.final_kwargs(store, registry),
            )
        with self.assertRaises(authorization.ContentHubV2AuthorizationError):
            authorization.authorize_mutation(
                context,
                operation="archiveArticle",
                **self.final_kwargs(store, registry),
            )

    def test_v1_dispatch_does_not_import_or_reference_v2_authorization(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        handler = (root / "lambda_function.py").read_text(encoding="utf-8")
        tree = ast.parse(handler)
        legacy_handler = next(
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "lambda_handler"
        )
        legacy_source = ast.unparse(legacy_handler)
        template = (root / "template.yaml").read_text(encoding="utf-8")
        legacy_function = template.split("  ContentHubFunction:\n", 1)[1].split(
            "\n  DueSchedulesRule:", 1
        )[0]

        self.assertNotIn("content_hub_v2", legacy_source)
        self.assertNotIn("content_hub_v2_authorization", template)
        self.assertNotIn("Path: /features/content-hub-v2", legacy_function)


if __name__ == "__main__":
    unittest.main()
