from copy import deepcopy
import hashlib
import io
import json
import unittest
from unittest.mock import Mock

from content_hub_v2_editor_store import AwsEditorStore, actor_condition_checks, PRIVATE_PREFIX, ARTICLE_PK
from content_hub_v2_editor_service import EditorConflict
from content_hub_v2_editor_model import EditorValidationError
from content_hub_v2_authorization import load_authorization_context, THN_CURRENT_USER_SCOPE
from test_content_hub_v2_authorization import FakeAuthorizationStore, REGISTRY
from tests.test_service_binding_registry_v2 import build_record, registry_definition


class EditorStoreTests(unittest.TestCase):
    def setUp(self):
        self.auth = load_authorization_context(FakeAuthorizationStore(), session_id_hash="a"*64, registry_record=REGISTRY, now_epoch=1000)
        self.runtime = Mock()
        self.runtime.now_epoch.return_value = 1000
        self.registry = build_record(registry_definition(activationStatus="active", writerMode="client-owner", writerEpoch=7, registryRevision=3))
        self.runtime.load_registry.return_value = self.registry
        self.ddb, self.s3 = Mock(), Mock()
        self.store = AwsEditorStore(self.runtime, object(), self.auth, "a"*64,
                                   dynamodb=self.ddb, s3=self.s3,
                                   metadata_table="zoolanding-content-hub-test-ThnContentHubV2Metadata", private_bucket="fixture-private-bucket")

    def test_final_transaction_contains_registry_user_session_and_concurrency(self):
        row = {"articleId": "article-1", "concurrencyToken": "new", "recordPurpose": "client-owner"}
        self.store.commit(row, "old", lambda: None)
        tx = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        self.assertEqual(len(tx), 5)
        self.assertIn("#writerEpoch", tx[0]["ConditionCheck"]["ConditionExpression"])
        self.assertIn("#purpose", tx[1]["ConditionCheck"]["ConditionExpression"])
        self.assertIn("#version", tx[1]["ConditionCheck"]["ConditionExpression"])
        self.assertIn("idleExpiresAt > :now", tx[2]["ConditionCheck"]["ConditionExpression"])
        self.assertEqual(tx[-1]["Put"]["ExpressionAttributeValues"][":previous"], {"S": "old"})
        self.assertEqual(tx[-1]["Put"]["Item"]["pk"], {"S": ARTICLE_PK})

    def test_first_write_is_create_only_and_current_purpose_is_server_owned(self):
        self.store.commit({"articleId": "a", "recordPurpose": "client-owner"}, None, lambda: None)
        item = self.ddb.transact_write_items.call_args.kwargs["TransactItems"][-1]["Put"]
        self.assertEqual(item["ConditionExpression"], "attribute_not_exists(pk)")
        with self.assertRaises(EditorValidationError):
            self.store.commit({"articleId": "b", "recordPurpose": "qa"}, None, lambda: None)

    def test_stale_registry_blocks_before_the_transaction(self):
        self.registry["writerEpoch"] = 8
        with self.assertRaises(Exception):
            self.store.commit({"articleId": "a", "recordPurpose": "client-owner"}, None, lambda: None)
        self.ddb.transact_write_items.assert_not_called()

    def test_working_image_reference_and_safe_audit_are_committed_with_the_article(self):
        prior = {**THN_CURRENT_USER_SCOPE, "articleId": "article-1", "concurrencyToken": "old",
                 "recordPurpose": "client-owner", "locales": {"en": {"workingAssetIds": [], "publishedAssetIds": []}}}
        row = deepcopy(prior)
        row["concurrencyToken"] = "new"
        row["locales"]["en"]["workingAssetIds"] = ["image-1"]
        self.store.get_article = Mock(return_value=prior)
        self.store.get_assets = Mock(return_value={"image-1": {
            **THN_CURRENT_USER_SCOPE, "articleId": "article-1", "locale": "en", "assetId": "image-1",
            "recordPurpose": "client-owner", "status": "ready", "deliveryState": "private", "referenceCount": 0}})
        self.store.commit(row, "old", lambda: None)
        tx = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        updates = [item["Update"] for item in tx if "Update" in item]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]["ExpressionAttributeValues"][":next"], {"N": "1"})
        self.assertIn("referenceCount = :previousCount", updates[0]["ConditionExpression"])
        self.assertIn("#status = :ready", updates[0]["ConditionExpression"])
        audits = [x["Put"] for x in tx if "Put" in x and x["Put"]["TableName"].endswith("Audit")]
        self.assertEqual(len(audits), 1)
        self.assertNotIn(self.auth.subject, json.dumps(audits))
        self.assertNotIn("title", json.dumps(audits))

    def test_s3_snapshot_is_immutable_and_integrity_checked(self):
        self.s3.put_object.return_value = {"VersionId": "v1"}
        package = {"title": "Safe"}
        pointer = self.store.save_package("a", "en", "r", package)
        self.assertEqual(pointer["versionId"], "v1")

    def test_removing_working_references_retains_published_images_and_rejects_collection_races(self):
        for published, count in [([], 0), (["image-1"], 1)]:
            prior = {**THN_CURRENT_USER_SCOPE, "articleId": "a", "recordPurpose": "client-owner",
                     "concurrencyToken": "old", "locales": {"en": {
                         "workingAssetIds": ["image-1"], "publishedAssetIds": published}}}
            row = deepcopy(prior)
            row["concurrencyToken"] = "new"
            row["locales"]["en"]["workingAssetIds"] = []
            self.store.get_article = Mock(return_value=prior)
            asset = {"status": "ready", "referenceCount": count+1}
            self.store.get_assets = Mock(return_value={"image-1": asset})
            self.store.commit(row, "old", lambda: None)
            updates = [x["Update"] for x in self.ddb.transact_write_items.call_args.kwargs["TransactItems"] if "Update" in x]
            self.assertEqual(updates[0]["ExpressionAttributeValues"][":next"], {"N": str(count)})
            self.assertIn("domain", updates[0]["ExpressionAttributeNames"].values())
            asset["status"] = "collecting"
            self.ddb.transact_write_items.reset_mock()
            with self.assertRaises(EditorValidationError):
                self.store.commit(row, "old", lambda: None)
            self.ddb.transact_write_items.assert_not_called()

    def test_s3_snapshot_is_immutable_and_integrity_checked_on_read(self):
        self.s3.put_object.return_value = {"VersionId": "v1"}
        package = {"title": "Safe"}
        pointer = self.store.save_package("a", "en", "r", package)
        self.assertEqual(self.s3.put_object.call_args.kwargs["IfNoneMatch"], "*")
        self.assertEqual(pointer["key"], PRIVATE_PREFIX + "immutable-revisions/a/en/r/package.json")
        self.s3.get_object.return_value = {"Body": io.BytesIO(b'{"changed":true}')}
        row = {"articleId": "a", "locales": {"en": {"workingRevisionId": "r", "packagePointer": pointer}}}
        with self.assertRaises(EditorValidationError):
            self.store.load_package(row, "en")

    def test_package_pointer_cannot_escape_the_exact_article_revision(self):
        row = {"articleId": "a", "locales": {"en": {"workingRevisionId": "r", "packagePointer": {"key": "other/package.json", "sha256": "a"*64}}}}
        with self.assertRaises(EditorValidationError):
            self.store.load_package(row, "en")
        self.s3.get_object.assert_not_called()

    def test_list_uses_strong_exact_partition_queries_not_scans(self):
        self.ddb.query.side_effect = [{"Items": [], "LastEvaluatedKey": {"pk": {"S": ARTICLE_PK}, "sk": {"S": "ARTICLE#a"}}}, {"Items": []}]
        self.assertEqual(self.store.list_articles(), [])
        self.assertEqual(self.ddb.query.call_count, 2)
        for call in self.ddb.query.call_args_list:
            self.assertTrue(call.kwargs["ConsistentRead"])
            self.assertEqual(call.kwargs["ExpressionAttributeValues"][":pk"], {"S": ARTICLE_PK})
        self.ddb.scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
