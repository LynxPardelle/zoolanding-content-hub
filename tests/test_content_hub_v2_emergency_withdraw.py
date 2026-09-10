import copy
import pathlib
import re
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import content_hub_v2_projection_manifest as projection
import content_hub_v2_registry_fence as registry_fence
import emergency_withdraw_lambda as emergency
from tests.test_content_hub_v2_registry_fence import InMemoryTransactionalDynamo
from tests.test_service_binding_registry_v2 import build_record, registry_definition

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
WRITER_EPOCH = 8


def _binding(**overrides):
    definition = registry_definition(
        activationStatus="active",
        writerMode="disabled",
        writerEpoch=WRITER_EPOCH,
        registryRevision=4,
    )
    definition.update(overrides)
    return build_record(definition)


def _article_pointer(article_id="article-1", locale="en", revision_id="revision-1"):
    return {
        "pointerType": "article",
        "pk": "HUB#thehairnarrative-com-journal",
        "sk": f"ARTICLE#{article_id}",
        "articleId": article_id,
        "locale": locale,
        "revisionId": revision_id,
        "invalidationPaths": [],
    }


def _locale_pointer(article_id="article-1", locale="en", revision_id="revision-1"):
    path = "/the-journal/observations/article-one"
    return {
        "pointerType": "locale-path",
        "pk": f"SLUG#test#thehairnarrative.com#{locale}",
        "sk": f"PATH#{path}",
        "articleId": article_id,
        "locale": locale,
        "revisionId": revision_id,
        "path": path,
        "invalidationPaths": [path],
    }


def _category_pointer(article_id="article-1", locale="en", revision_id="revision-1"):
    category_slug = "observations"
    return {
        "pointerType": "category-index",
        "pk": "HUB#thehairnarrative-com-journal",
        "sk": f"CATEGORY#{locale}#{category_slug}#ARTICLE#{article_id}",
        "articleId": article_id,
        "locale": locale,
        "revisionId": revision_id,
        "categorySlug": category_slug,
        "invalidationPaths": [f"/the-journal/{category_slug}"],
    }


def _media_pointer(article_id="article-1", locale="en", revision_id="revision-1"):
    path = (
        "/features/content-hub-v2/public-media/"
        f"{article_id}/{locale}/{revision_id}/cover-1/w768"
    )
    return {
        "pointerType": "public-media",
        "pk": (
            "LIVE_MEDIA#test#thehairnarrative.com#"
            f"thehairnarrative-com-journal#{article_id}#{locale}#{revision_id}"
        ),
        "sk": "MANIFEST#V1",
        "articleId": article_id,
        "locale": locale,
        "revisionId": revision_id,
        "invalidationPaths": [path],
    }


def _page(page_id, pointers, next_page_id=""):
    return projection.seal_projection_page(
        manifest_id="withdrawal-fixture-1",
        page_id=page_id,
        next_page_id=next_page_id,
        live_pointers=pointers,
    )


def _manifest(*, head_page_id="page-1", page_count=1, pointer_count=4):
    return projection.seal_projection_manifest(
        manifest_id="withdrawal-fixture-1",
        projection_digest="b" * 64,
        publication_writer_epoch=7,
        head_page_id=head_page_id,
        page_count=page_count,
        pointer_count=pointer_count,
    )


def _event(**overrides):
    event = {
        "schemaVersion": 1,
        "operation": "withdrawHub",
        "writerEpoch": WRITER_EPOCH,
    }
    event.update(overrides)
    return event


class FakeRuntime:
    def __init__(self, *, manifest=None, pages=None, binding=None, checkpoint=None):
        self.binding = copy.deepcopy(binding or _binding())
        self.manifest = copy.deepcopy(manifest)
        self.pages = copy.deepcopy(pages or {})
        self.checkpoint = copy.deepcopy(checkpoint)
        self.calls = []
        self.commits = []

    def load_closed_binding(self, writer_epoch):
        self.calls.append(("binding", writer_epoch))
        return copy.deepcopy(self.binding)

    def load_projection_manifest(self):
        self.calls.append(("manifest",))
        return copy.deepcopy(self.manifest)

    def load_projection_page(self, page_id):
        self.calls.append(("page", page_id))
        return copy.deepcopy(self.pages.get(page_id))

    def load_checkpoint(self, writer_epoch):
        self.calls.append(("checkpoint", writer_epoch))
        return copy.deepcopy(self.checkpoint)

    def commit_batch(self, batch):
        self.calls.append(("commit", batch.batch_number))
        self.commits.append(copy.deepcopy(batch))
        self.manifest = copy.deepcopy(batch.manifest_after)
        if batch.page_after is not None:
            self.pages[batch.page_after["pageId"]] = copy.deepcopy(batch.page_after)
        self.checkpoint = copy.deepcopy(batch.checkpoint_after)


class RecordingDynamo:
    def __init__(self):
        self.reads = []
        self.transactions = []

    def get_item(self, **kwargs):
        self.reads.append(copy.deepcopy(kwargs))
        return {}

    def transact_write_items(self, **kwargs):
        self.transactions.append(copy.deepcopy(kwargs))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class EmergencyWithdrawalContractTests(unittest.TestCase):
    def test_manifest_rejects_impossible_page_and_pointer_counts(self):
        with self.assertRaises(projection.ProjectionManifestError):
            _manifest(page_count=2, pointer_count=1)

    def test_exact_direct_invocation_event_is_required_before_io(self):
        invalid_events = (
            {},
            {"schemaVersion": 1, "operation": "withdrawHub"},
            _event(extra="not-allowed"),
            _event(schemaVersion=True),
            _event(operation="publish"),
            _event(writerEpoch=0),
            _event(writerEpoch=True),
            _event(writerEpoch="8"),
        )

        for event in invalid_events:
            with self.subTest(event=event):
                runtime = FakeRuntime()
                with self.assertRaisesRegex(
                    emergency.EmergencyWithdrawalError,
                    "emergency withdrawal is unavailable",
                ):
                    emergency.handle_withdrawal(event, runtime=runtime)
                self.assertEqual(runtime.calls, [])

    def test_writer_must_already_be_disabled_at_the_requested_epoch(self):
        cases = (
            _binding(writerMode="client-owner"),
            _binding(writerEpoch=9, registryRevision=5),
            _binding(activationStatus="inactive"),
        )

        for binding in cases:
            with self.subTest(mode=binding["writerMode"], epoch=binding["writerEpoch"]):
                runtime = FakeRuntime(binding=binding)
                with self.assertRaises(emergency.EmergencyWithdrawalError):
                    emergency.handle_withdrawal(_event(), runtime=runtime)
                self.assertEqual(runtime.calls, [("binding", WRITER_EPOCH)])
                self.assertEqual(runtime.commits, [])

    def test_one_bounded_manifest_page_is_removed_and_checkpointed(self):
        first_pointers = [
            _media_pointer(article_id=f"article-{index}")
            for index in range(1, projection.MAX_POINTERS_PER_PAGE + 1)
        ]
        page_one = _page("page-1", first_pointers, next_page_id="page-2")
        page_two = _page("page-2", [_article_pointer(article_id="article-20")])
        runtime = FakeRuntime(
            manifest=_manifest(
                page_count=2,
                pointer_count=projection.MAX_POINTERS_PER_PAGE + 1,
            ),
            pages={"page-1": page_one, "page-2": page_two},
        )

        response = emergency.handle_withdrawal(_event(), runtime=runtime)

        self.assertEqual(
            response,
            {
                "ok": True,
                "status": "in_progress",
                "writerEpoch": WRITER_EPOCH,
                "processedPointers": projection.MAX_POINTERS_PER_PAGE,
                "remainingPointers": 1,
                "continuationRequired": True,
            },
        )
        self.assertEqual(len(runtime.commits), 1)
        batch = runtime.commits[0]
        self.assertEqual(len(batch.pointers), projection.MAX_POINTERS_PER_PAGE)
        self.assertEqual(batch.manifest_after["headPageId"], "page-2")
        self.assertEqual(batch.manifest_after["remainingPageCount"], 1)
        self.assertEqual(batch.manifest_after["livePointerCount"], 1)
        self.assertEqual(batch.manifest_after["state"], "withdrawing")
        self.assertEqual(batch.page_after["state"], "consumed")
        self.assertEqual(batch.checkpoint_after["status"], "in_progress")
        self.assertIn("/", batch.invalidation_paths)
        self.assertIn("/the-journal", batch.invalidation_paths)
        self.assertIn("/content-hub-search.json", batch.invalidation_paths)
        self.assertIn("/sitemap.xml", batch.invalidation_paths)

    def test_resume_reaches_zero_live_pointers_and_retry_is_idempotent(self):
        page_one = _page("page-1", [_article_pointer()], next_page_id="page-2")
        page_two = _page(
            "page-2",
            [_locale_pointer(), _category_pointer(), _media_pointer()],
        )
        runtime = FakeRuntime(
            manifest=_manifest(page_count=2, pointer_count=4),
            pages={"page-1": page_one, "page-2": page_two},
        )

        first = emergency.handle_withdrawal(_event(), runtime=runtime)
        second = emergency.handle_withdrawal(_event(), runtime=runtime)
        third = emergency.handle_withdrawal(_event(), runtime=runtime)

        self.assertEqual(first["status"], "in_progress")
        self.assertEqual(second["status"], "complete")
        self.assertEqual(third, second)
        self.assertEqual(len(runtime.commits), 2)
        self.assertEqual(runtime.manifest["state"], "withdrawn")
        self.assertEqual(runtime.manifest["headPageId"], "")
        self.assertEqual(runtime.manifest["remainingPageCount"], 0)
        self.assertEqual(runtime.manifest["livePointerCount"], 0)
        self.assertEqual(runtime.checkpoint["status"], "complete")
        self.assertEqual(runtime.checkpoint["processedPointerCount"], 4)

    def test_empty_manifest_still_records_global_cache_withdrawal(self):
        runtime = FakeRuntime(
            manifest=_manifest(head_page_id="", page_count=0, pointer_count=0),
        )

        response = emergency.handle_withdrawal(_event(), runtime=runtime)

        self.assertEqual(response["status"], "complete")
        self.assertEqual(response["processedPointers"], 0)
        self.assertEqual(len(runtime.commits), 1)
        self.assertEqual(
            tuple(runtime.commits[0].invalidation_paths),
            projection.GLOBAL_INVALIDATION_PATHS,
        )

    def test_missing_or_cross_tenant_manifest_fails_before_commit(self):
        valid_page = _page("page-1", [_article_pointer()])
        poisoned_page = copy.deepcopy(valid_page)
        poisoned_page["livePointers"][0]["pk"] = "HUB#zoosite-main"
        cases = (
            FakeRuntime(manifest=None),
            FakeRuntime(
                manifest=_manifest(pointer_count=1),
                pages={"page-1": poisoned_page},
            ),
        )

        for runtime in cases:
            with self.subTest(runtime=runtime):
                with self.assertRaises(emergency.EmergencyWithdrawalError):
                    emergency.handle_withdrawal(_event(), runtime=runtime)
                self.assertEqual(runtime.commits, [])

    def test_checkpoint_must_match_the_current_manifest_state(self):
        manifest = _manifest(pointer_count=1)
        manifest.update(
            {
                "state": "withdrawing",
                "withdrawalEpoch": WRITER_EPOCH,
                "completedBatches": 1,
                "stateRevision": 2,
            }
        )
        runtime = FakeRuntime(
            manifest=manifest,
            pages={"page-1": _page("page-1", [_article_pointer()])},
            checkpoint={"pk": "wrong", "sk": "wrong"},
        )

        with self.assertRaises(emergency.EmergencyWithdrawalError):
            emergency.handle_withdrawal(_event(), runtime=runtime)

        self.assertEqual(runtime.commits, [])

    def test_unexpected_commit_failure_is_always_generic(self):
        class FailingRuntime(FakeRuntime):
            def commit_batch(self, batch):
                raise RuntimeError("provider details must never escape")

        with self.assertRaisesRegex(
            emergency.EmergencyWithdrawalError,
            "^emergency withdrawal is unavailable$",
        ):
            emergency.handle_withdrawal(
                _event(),
                runtime=FailingRuntime(
                    manifest=_manifest(pointer_count=1),
                    pages={"page-1": _page("page-1", [_article_pointer()])},
                ),
            )

    def test_lambda_rejects_unqualified_invocation_before_runtime_setup(self):
        context = SimpleNamespace(
            function_name=emergency.FUNCTION_NAME,
            invoked_function_arn=(
                "arn:aws:lambda:us-east-1:123456789012:function:"
                f"{emergency.FUNCTION_NAME}"
            ),
        )
        with (
            patch.object(
                emergency.AwsEmergencyWithdrawalRuntime, "from_environment"
            ) as runtime_factory,
            self.assertRaises(emergency.EmergencyWithdrawalError),
        ):
            emergency.lambda_handler(_event(), context)

        runtime_factory.assert_not_called()

    def test_stale_publisher_epoch_cannot_commit_after_writer_disable(self):
        live = build_record(
            registry_definition(
                activationStatus="active",
                writerMode="client-owner",
                writerEpoch=7,
                registryRevision=3,
            )
        )
        client = InMemoryTransactionalDynamo(live)

        def disable_writers(store):
            store.record = _binding()

        client.before_condition_check = disable_writers
        mutation = {
            "Put": {
                "TableName": "zoolanding-content-hub-test-ThnContentHubV2Metadata",
                "Item": registry_fence.marshal_item(
                    {"pk": projection.MANIFEST_PK, "sk": projection.MANIFEST_SK}
                ),
            }
        }

        with self.assertRaises(registry_fence.RegistryFenceError):
            registry_fence.execute_registry_fenced_transaction(
                client,
                mutation_items=[mutation],
                expected_descriptor={
                    "descriptorVersionId": live["descriptorVersionId"],
                    "descriptorSha256": live["descriptorSha256"],
                    "authPolicyVersion": live["authPolicyVersion"],
                },
                expected_writer_mode="client-owner",
                expected_writer_epoch=7,
                trusted_resource_scope={
                    "partition": "aws",
                    "accountId": "123456789012",
                    "region": "us-east-1",
                },
            )

        self.assertEqual(client.applied, [])


class EmergencyWithdrawalAwsRuntimeTests(unittest.TestCase):
    @staticmethod
    def _runtime(dynamodb):
        return emergency.AwsEmergencyWithdrawalRuntime(
            dynamodb_client=dynamodb,
            private_table_name="zoolanding-content-hub-test-ThnContentHubV2Metadata",
            public_table_name="generated-public-table",
            audit_table_name="zoolanding-content-hub-test-ThnContentHubV2Audit",
            expected_descriptor={
                "descriptorVersionId": "test-v1",
                "descriptorSha256": "a" * 64,
                "authPolicyVersion": "journal-owner-v1",
            },
            trusted_resource_scope={
                "partition": "aws",
                "accountId": "123456789012",
                "region": "us-east-1",
            },
        )

    def test_batch_builds_one_atomic_25_item_transaction(self):
        pointers = [
            _media_pointer(article_id=f"article-{index}")
            for index in range(1, projection.MAX_POINTERS_PER_PAGE + 1)
        ]
        core_runtime = FakeRuntime(
            manifest=_manifest(
                page_count=2,
                pointer_count=projection.MAX_POINTERS_PER_PAGE + 1,
            ),
            pages={
                "page-1": _page("page-1", pointers, next_page_id="page-2"),
                "page-2": _page("page-2", [_article_pointer(article_id="article-20")]),
            },
        )
        emergency.handle_withdrawal(_event(), runtime=core_runtime)
        batch = core_runtime.commits[0]
        dynamodb = RecordingDynamo()
        runtime = self._runtime(dynamodb)

        runtime.commit_batch(batch)

        self.assertEqual(len(dynamodb.transactions), 1)
        call = dynamodb.transactions[0]
        transaction = call["TransactItems"]
        self.assertEqual(len(transaction), 25)
        self.assertIn("ClientRequestToken", call)
        self.assertLessEqual(len(call["ClientRequestToken"]), 36)
        self.assertEqual(
            transaction[0]["ConditionCheck"]["TableName"], emergency.REGISTRY_TABLE
        )
        self.assertEqual(transaction[1]["Put"]["TableName"], runtime.private_table_name)
        self.assertEqual(transaction[2]["Put"]["TableName"], runtime.private_table_name)
        self.assertIn(
            "livePointers",
            set(transaction[2]["Put"]["ExpressionAttributeNames"].values()),
        )
        deletes = [item["Delete"] for item in transaction if "Delete" in item]
        self.assertEqual(len(deletes), projection.MAX_POINTERS_PER_PAGE)
        self.assertTrue(
            all(item["TableName"] == runtime.public_table_name for item in deletes)
        )
        self.assertTrue(
            all(
                "attribute_not_exists" in item["ConditionExpression"]
                for item in deletes
            )
        )
        self.assertEqual(
            transaction[-3]["Put"]["TableName"], runtime.private_table_name
        )
        self.assertEqual(
            transaction[-2]["Put"]["TableName"], runtime.private_table_name
        )
        self.assertEqual(transaction[-1]["Put"]["TableName"], runtime.audit_table_name)

    def test_manifest_page_and_checkpoint_reads_are_exact_and_strong(self):
        dynamodb = RecordingDynamo()
        runtime = self._runtime(dynamodb)

        self.assertIsNone(runtime.load_projection_manifest())
        self.assertIsNone(runtime.load_projection_page("page-1"))
        self.assertIsNone(runtime.load_checkpoint(WRITER_EPOCH))

        self.assertEqual(len(dynamodb.reads), 3)
        self.assertTrue(all(call["ConsistentRead"] is True for call in dynamodb.reads))
        self.assertTrue(
            all(
                call["TableName"] == runtime.private_table_name
                for call in dynamodb.reads
            )
        )
        self.assertEqual(
            [call["Key"] for call in dynamodb.reads],
            [
                emergency.marshal_item(
                    {"pk": projection.MANIFEST_PK, "sk": projection.MANIFEST_SK}
                ),
                emergency.marshal_item(
                    {"pk": projection.MANIFEST_PK, "sk": "PAGE#page-1"}
                ),
                emergency.marshal_item(
                    {
                        "pk": projection.MANIFEST_PK,
                        "sk": f"WITHDRAWAL#{WRITER_EPOCH:020d}",
                    }
                ),
            ],
        )

    def test_adapter_rejects_a_tampered_batch_before_dynamodb(self):
        core_runtime = FakeRuntime(
            manifest=_manifest(pointer_count=1),
            pages={"page-1": _page("page-1", [_article_pointer()])},
        )
        emergency.handle_withdrawal(_event(), runtime=core_runtime)
        batch = core_runtime.commits[0]
        poisoned = copy.deepcopy(batch.pointers[0])
        poisoned["pk"] = "HUB#zoosite-main"
        tampered = replace(batch, pointers=(poisoned,))
        dynamodb = RecordingDynamo()

        with self.assertRaises(emergency.EmergencyWithdrawalError):
            self._runtime(dynamodb).commit_batch(tampered)

        self.assertEqual(dynamodb.transactions, [])

    def test_article_delete_is_bound_to_the_exact_immutable_bundle(self):
        core_runtime = FakeRuntime(
            manifest=_manifest(pointer_count=1),
            pages={"page-1": _page("page-1", [_article_pointer()])},
        )
        emergency.handle_withdrawal(_event(), runtime=core_runtime)
        dynamodb = RecordingDynamo()
        self._runtime(dynamodb).commit_batch(core_runtime.commits[0])

        deletion = next(
            item["Delete"]
            for item in dynamodb.transactions[0]["TransactItems"]
            if "Delete" in item
        )
        condition_fields = set(deletion["ExpressionAttributeNames"].values())
        self.assertIn("publishedBundleKey", condition_fields)
        self.assertNotIn("latestRevisionId", condition_fields)


def _resource(template, logical_id):
    match = re.search(
        rf"(?ms)^  {re.escape(logical_id)}:\s*$.*?(?=^  [A-Za-z0-9]+:\s*$|\Z)",
        template,
    )
    if match is None:
        raise AssertionError(f"Missing resource: {logical_id}")
    return match.group(0)


class EmergencyWithdrawalInfrastructureTests(unittest.TestCase):
    def test_function_is_alias_only_and_has_no_http_or_schedule_route(self):
        template = (PROJECT_ROOT / "template.yaml").read_text(encoding="utf-8")
        function = _resource(template, "ThnContentHubV2EmergencyWithdrawFunction")
        invoke_policy = _resource(
            template, "ThnContentHubV2EmergencyWithdrawInvokePolicy"
        )
        invoke_permission = _resource(
            template, "ThnContentHubV2EmergencyWithdrawInvokePermission"
        )

        self.assertNotIn("Events:", function)
        self.assertIn("AutoPublishAlias: test", function)
        self.assertIn("THN_CONTENT_HUB_DESCRIPTOR_VERSION_ID", function)
        self.assertIn("THN_CONTENT_HUB_AWS_ACCOUNT_ID", function)
        self.assertIn("ThnContentHubV2EmergencyWithdrawFunction.Alias", invoke_policy)
        self.assertIn("AWS::Lambda::Permission", invoke_permission)
        self.assertIn(
            "ThnContentHubV2EmergencyWithdrawFunction.Alias", invoke_permission
        )
        self.assertIn("Ref: ThnContentHubV2EmergencyOperatorRoleArn", invoke_permission)
        self.assertNotIn("AWS::Lambda::ResourcePolicy", template)

    def test_roles_are_exact_thn_only_and_publisher_can_record_the_manifest(self):
        template = (PROJECT_ROOT / "template.yaml").read_text(encoding="utf-8")
        withdraw = _resource(template, "ThnContentHubV2EmergencyWithdrawRole")
        publisher = _resource(template, "ThnContentHubV2PublisherRole")

        self.assertIn(projection.MANIFEST_PK, withdraw)
        self.assertIn(
            "LIVE_MEDIA#test#thehairnarrative.com#thehairnarrative-com-journal#*",
            withdraw,
        )
        self.assertIn("HUB#thehairnarrative-com-journal", withdraw)
        self.assertIn("SLUG#test#thehairnarrative.com#en", withdraw)
        self.assertIn("SLUG#test#thehairnarrative.com#es", withdraw)
        self.assertNotIn("HUB#zoosite-main", withdraw)
        self.assertNotIn("dynamodb:Query", withdraw)
        self.assertNotIn("dynamodb:Scan", withdraw)
        self.assertNotIn("s3:", withdraw)
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", publisher)
        self.assertIn("RecordExactThnProjectionManifest", publisher)
        self.assertIn(projection.MANIFEST_PK, publisher)

    def test_emergency_artifact_contains_only_its_closed_dependency_set(self):
        from tools import build_lambda_artifact as builder

        self.assertEqual(
            set(builder.SOURCE_ALLOWLIST["ThnContentHubV2EmergencyWithdrawFunction"]),
            {
                "emergency_withdraw_lambda.py",
                "content_hub_v2_projection_manifest.py",
                "service_binding_registry_consumer_v2.py",
                "service_binding_registry_operator_lambda.py",
                "service_binding_registry_v2.py",
            },
        )
        self.assertEqual(
            builder.RUNTIME_REQUIREMENTS["ThnContentHubV2EmergencyWithdrawFunction"],
            "requirements.txt",
        )


if __name__ == "__main__":
    unittest.main()
