import io
import json
import base64
import unittest
from unittest.mock import Mock

import test_content_hub_v2_editor_store as editor_store_fixtures
from test_content_hub_v2_private_upload import MediaStore, PrivateUpload
from content_hub_v2_registry_fence import marshal_item, unmarshal_item

try:
    from content_hub_v2_media_store import AwsMediaStore
except ImportError:
    AwsMediaStore = None


class MediaStoreTests(unittest.TestCase):
    setUp = editor_store_fixtures.EditorStoreTests.setUp

    def adapter(self):
        self.assertIsNotNone(AwsMediaStore, "Exact private media adapter must be implemented")
        self.runtime._trusted_resource_scope.return_value = {"partition": "aws", "region": "us-east-1", "accountId": "123456789012"}
        self.lambda_client = Mock()
        return AwsMediaStore(self.store, lambda_client=self.lambda_client)

    def fixture(self):
        memory = MediaStore()
        import base64
        from test_content_hub_v2_private_upload import SOURCE
        PrivateUpload(memory)(memory.row, "en", {"imageBase64": base64.b64encode(SOURCE).decode(), "contentType": "image/png", "alt": "Hair"}, lambda: None)
        return memory.row, next(iter(memory.transactions.values())), next(iter(memory.assets.values()))

    def test_begin_binds_registry_session_user_and_article_to_exact_upload_partition(self):
        adapter = self.adapter()
        row, tx, asset = self.fixture()
        adapter.begin_upload(row, tx, lambda: None)
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        self.assertEqual(len(items), 5)
        self.assertIn("#writerEpoch", items[0]["ConditionCheck"]["ConditionExpression"])
        self.assertIn("idleExpiresAt", items[2]["ConditionCheck"]["ConditionExpression"])
        self.assertIn("concurrencyToken", items[3]["ConditionCheck"]["ConditionExpression"])
        self.assertEqual(items[4]["Put"]["TableName"], "zoolanding-image-upload-test-ThnPrivateUploadTransactionsV2")
        self.assertEqual(items[4]["Put"]["ConditionExpression"], "attribute_not_exists(pk)")

    def test_finish_fences_consumed_transaction_and_only_writes_private_asset(self):
        adapter = self.adapter()
        row, tx, asset = self.fixture()
        adapter.finish_upload(row, tx, asset, lambda: None)
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        self.assertEqual(len(items), 7)
        condition = items[4]["ConditionCheck"]
        for field in ("status", "actorPurpose", "contentSha256", "writerEpoch", "variants", "revisionId"):
            self.assertIn(field, condition["ExpressionAttributeNames"].values())
        saved = unmarshal_item(items[-2]["Put"]["Item"])
        self.assertIn("#ASSETS#article-1#en", saved["pk"])
        self.assertEqual(saved["deliveryState"], "private")

    def test_finished_upload_appends_only_safe_durable_audit(self):
        adapter = self.adapter()
        row, tx, asset = self.fixture()
        adapter.finish_upload(row, tx, asset, lambda: None)
        items = self.ddb.transact_write_items.call_args.kwargs["TransactItems"]
        audits = [x["Put"] for x in items if "Put" in x and x["Put"]["TableName"].endswith("Audit")]
        self.assertEqual(len(audits), 1)
        audit = unmarshal_item(audits[0]["Item"])
        self.assertEqual(audit["operation"], "uploadAsset")
        self.assertNotIn(self.auth.subject, json.dumps(audit))
        self.assertNotIn("alt", audit)
        self.assertNotIn("variants", audit)

    def test_closed_private_processor_payload(self):
        adapter = self.adapter()
        row, tx, asset = self.fixture()
        self.lambda_client.invoke.return_value = {"Payload": io.BytesIO(b'{"ok":true}')}
        self.assertEqual(adapter.process_upload(tx, "aW1hZ2U="), {"ok": True})
        call = self.lambda_client.invoke.call_args.kwargs
        self.assertEqual(call["FunctionName"], "arn:aws:lambda:us-east-1:123456789012:function:zoolanding-image-upload-test-ThnImageUploadV2:test")
        self.assertEqual(call["InvocationType"], "RequestResponse")
        payload = json.loads(call["Payload"])
        self.assertEqual(set(payload), {"operation", "callerPrincipalArn", "transactionId", "scope", "imageBase64"})
        self.assertEqual(payload["scope"]["actorPurpose"], "client-owner")
        self.assertNotIn("session", str(payload))

    def test_stale_authorization_stops_both_storage_transactions(self):
        adapter = self.adapter()
        row, tx, asset = self.fixture()
        def revoked():
            raise PermissionError()
        for action in (lambda: adapter.begin_upload(row, tx, revoked), lambda: adapter.finish_upload(row, tx, asset, revoked)):
            with self.assertRaises(PermissionError):
                action()
        self.ddb.transact_write_items.assert_not_called()

    def test_preview_requires_exact_article_locale_asset_key_version_and_digest(self):
        adapter = self.adapter()
        self.assertTrue(callable(getattr(adapter, "preview_asset", None)))
        row, tx, asset = self.fixture()
        from test_content_hub_v2_private_upload import SOURCE
        self.ddb.get_item.return_value = {"Item": marshal_item(asset)}
        self.s3.get_object.return_value = {"Body": io.BytesIO(SOURCE)}
        preview = adapter.preview_asset(row, "en", asset["assetId"])
        self.assertEqual(preview["imageBase64"], base64.b64encode(SOURCE).decode())
        self.assertEqual(self.s3.get_object.call_args.kwargs["VersionId"], "v1")
        self.assertNotIn("variants", preview)
        self.s3.get_object.return_value = {"Body": io.BytesIO(b"corrupt")}
        with self.assertRaises(ValueError):
            adapter.preview_asset(row, "en", asset["assetId"])
        for changed in ("private/other/image.png", "private/test/thehairnarrative.com/journal-owner/thehairnarrative-com/thehairnarrative-com-journal/articles/article-1/en/revisions/../../other/assets/" + asset["assetId"] + "/w768.png"):
            asset["variants"][1]["key"] = changed
            self.ddb.get_item.return_value = {"Item": marshal_item(asset)}
            self.s3.reset_mock()
            with self.assertRaises(ValueError):
                adapter.preview_asset(row, "en", asset["assetId"])
            self.s3.get_object.assert_not_called()

    def test_asset_read_rejects_foreign_purpose_scope_locale_or_identity(self):
        adapter = self.adapter()
        row, tx, asset = self.fixture()
        for field, value in (("recordPurpose", "qa"), ("hubId", "zoosite-main"), ("tenantId", "other"),
                             ("locale", "es"), ("articleId", "other"), ("assetId", "other")):
            with self.subTest(field=field):
                self.s3.reset_mock()
                self.ddb.get_item.return_value = {"Item": marshal_item({**asset, field: value})}
                with self.assertRaises(ValueError):
                    adapter.preview_asset(row, "en", asset["assetId"])
                self.s3.get_object.assert_not_called()
