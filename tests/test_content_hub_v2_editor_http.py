import hashlib
import json
from pathlib import Path
import unittest

import content_hub_v2_authoring_handler as handler
from test_thn_content_hub_v2_task_021_authoring import FakeAuthoringRuntime, event_for
from test_content_hub_v2_editor_service import MemoryStore


class EditorHttpTests(unittest.TestCase):
    def setUp(self):
        self.runtime = FakeAuthoringRuntime()
        self.runtime.session["sessionIdHash"] = hashlib.sha256(b"fixture-session").hexdigest()
        self.runtime.session["csrfHash"] = hashlib.sha256(b"fixture-csrf").hexdigest()
        self.store = MemoryStore()
        self.runtime.get_editor_store = lambda *args: self.store

    def send(self, operation, data, *, read=False, csrf=True):
        if operation == "createArticle":
            data = {"idempotencyKey": "a" * 32, **data}
        request = event_for(handler.READ_PATH if read else handler.ACTION_PATH, operation,
                            session_token="fixture-session", csrf_token="fixture-csrf" if csrf else None)
        value = json.loads(request["body"])
        value["input"]["contentHub"]["data"] = data
        request["body"] = json.dumps(value)
        return handler.handle_request(request, object(), runtime=self.runtime)

    def test_http_create_detail_and_safe_response_contract(self):
        created = self.send("createArticle", {"locale": "en"})
        self.assertEqual(created["statusCode"], 200)
        value = json.loads(created["body"])
        self.assertTrue(value["ok"])
        article_id = value["data"]["articleId"]
        detail = self.send("articleDetail", {"articleId": article_id}, read=True)
        self.assertEqual(detail["statusCode"], 200)
        self.assertEqual(detail["headers"]["cache-control"], "no-store")
        for private in ("recordPurpose", "owner-subject", "packagePointer", "fixture-session"):
            self.assertNotIn(private, detail["body"])

    def test_upload_is_connected_to_private_store_only_after_csrf_and_owner_auth(self):
        import base64
        from test_content_hub_v2_private_upload import MediaStore, SOURCE
        from content_hub_v2_private_upload import PrivateUpload
        created = json.loads(self.send("createArticle", {"locale": "en"})["body"])["data"]
        media = MediaStore()
        media.row = self.store.get_article(created["articleId"])
        self.store.upload_asset = PrivateUpload(media)
        data = {"articleId": created["articleId"], "locale": "en", "concurrencyToken": created["concurrencyToken"],
                "contentType": "image/png", "imageBase64": base64.b64encode(SOURCE).decode(), "alt": "Hair"}
        blocked = self.send("uploadAsset", data, csrf=False)
        self.assertEqual(blocked["statusCode"], 403)
        self.assertEqual(media.invocations, [])
        response = self.send("uploadAsset", data)
        self.assertEqual(response["statusCode"], 200, response)
        self.assertEqual(json.loads(response["body"])["data"]["asset"]["status"], "ready")
        self.assertEqual(response["headers"]["cache-control"], "no-store")

    def test_private_preview_is_one_asset_through_existing_read_not_a_public_url(self):
        created = json.loads(self.send("createArticle", {"locale": "en"})["body"])["data"]
        self.store.preview_asset = lambda row, locale, asset_id: {"assetId": asset_id, "imageBase64": "aW1hZ2U=", "contentType": "image/png"}
        response = self.send("assetList", {"articleId": created["articleId"], "locale": "en", "assetId": "asset-1"}, read=True)
        self.assertEqual(response["statusCode"], 200, response)
        self.assertEqual(json.loads(response["body"])["data"]["items"][0]["assetId"], "asset-1")

    def test_private_media_iam_and_artifacts_remain_exact_and_v1_is_not_opted_in(self):
        import yaml
        from tools.build_lambda_artifact import SOURCE_ALLOWLIST
        for module in ("content_hub_v2_private_upload.py", "content_hub_v2_media_store.py"):
            self.assertIn(module, SOURCE_ALLOWLIST["ThnContentHubV2AuthoringFunction"])
            self.assertNotIn(module, SOURCE_ALLOWLIST["ContentHubFunction"])
        template = yaml.safe_load((Path(__file__).resolve().parents[1] / "template.yaml").read_text())
        statements = template["Resources"]["ThnContentHubV2AuthoringRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        media = next(x for x in statements if x["Sid"] == "ExactPrivateImageTransactions")
        self.assertEqual(set(media["Action"]), {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:ConditionCheckItem"})
        self.assertEqual(media["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"], ["UPLOAD_TX#test#thehairnarrative.com#journal-owner#thehairnarrative-com#thehairnarrative-com-journal"])
        read = next(x for x in statements if x["Sid"] == "ReadExactPrivateImageVersions")
        self.assertEqual(read["Action"], ["s3:GetObjectVersion"])
        self.assertTrue(read["Resource"]["Fn::Sub"].endswith("/private/test/thehairnarrative.com/journal-owner/thehairnarrative-com/thehairnarrative-com-journal/articles/*"))

    def test_unauthorized_write_never_reaches_storage(self):
        response = self.send("createArticle", {"locale": "en"}, csrf=False)
        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(self.store.rows, {})

    def test_invalid_input_and_unknown_id_do_not_leak_internal_errors(self):
        response = self.send("createArticle", {"locale": "en", "recordPurpose": "qa"})
        self.assertEqual(response["statusCode"], 400)
        missing = self.send("articleDetail", {"articleId": "does-not-exist"}, read=True)
        self.assertEqual(missing["statusCode"], 404)

    def test_current_user_revocation_during_commit_cannot_save(self):
        self.store.before_commit = lambda: self.runtime.user.update(enabled=False)
        response = self.send("createArticle", {"locale": "en"})
        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(self.store.rows, {})

    def test_private_commit_role_can_condition_check_only_dedicated_auth_state(self):
        import yaml
        template = yaml.safe_load((Path(__file__).resolve().parents[1] / "template.yaml").read_text())
        role = template["Resources"]["ThnContentHubV2AuthoringRole"]
        statements = role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        statement = next((x for x in statements if x["Sid"] == "CheckExactThnActorBeforeCommit"), None)
        self.assertIsNotNone(statement)
        self.assertEqual(statement["Action"], ["dynamodb:ConditionCheckItem"])
        self.assertEqual(len(statement["Resource"]), 2)
        self.assertEqual(statement["Condition"]["StringEquals"]["dynamodb:EnclosingOperation"], "TransactWriteItems")

    def test_authoring_may_read_only_its_private_object_versions(self):
        import yaml
        template = yaml.safe_load((Path(__file__).resolve().parents[1] / "template.yaml").read_text())
        statements = template["Resources"]["ThnContentHubV2AuthoringRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        matches = [x for x in statements if "s3:GetObjectVersion" in x.get("Action", [])]
        self.assertEqual(len(matches), 2)
        self.assertEqual({x["Resource"]["Fn::Sub"] for x in matches}, {
            "${ThnContentHubV2PrivateStore.Arn}/private/test/thehairnarrative.com/thehairnarrative-com-journal/*",
            "arn:${AWS::Partition}:s3:::zlp-thn-private-upload-test-${AWS::AccountId}-${AWS::Region}/private/test/thehairnarrative.com/journal-owner/thehairnarrative-com/thehairnarrative-com-journal/articles/*",
        })

    def test_duplicate_json_fields_are_rejected_before_dependencies(self):
        request = event_for(handler.ACTION_PATH, "createArticle", session_token="fixture-session", csrf_token="fixture-csrf")
        request["body"] = request["body"].replace('"createArticle"', '"other", "action": "createArticle"')
        result = handler.handle_request(request, object(), runtime=self.runtime)
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(json.loads(result["body"])["code"], "invalid_request")

    def test_nonfinite_numbers_are_rejected_before_dependencies(self):
        request = event_for(handler.ACTION_PATH, "createArticle", session_token="fixture-session", csrf_token="fixture-csrf")
        request["body"] = request["body"].replace('"createArticle"', '"createArticle", "data": {"locale":NaN,"idempotencyKey":"' + 'a'*32 + '"}')
        result = handler.handle_request(request, object(), runtime=self.runtime)
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(json.loads(result["body"])["code"], "invalid_request")

    def test_uncertain_publisher_reply_is_retryable_without_discarding_operation_identity(self):
        from content_hub_v2_editor_model import EditorValidationError
        article=json.loads(self.send("createArticle",{"locale":"en"})["body"])["data"]
        def unavailable(*args): raise EditorValidationError("publication_unavailable")
        self.runtime.get_publisher=lambda *args:unavailable
        result=self.send("unpublishArticle",{"articleId":article["articleId"],"locale":"en",
            "concurrencyToken":article["concurrencyToken"],"idempotencyKey":"f"*32})
        self.assertEqual(result["statusCode"],503)
        self.assertEqual(json.loads(result["body"])["code"],"publication_unavailable")


if __name__ == "__main__":
    unittest.main()
