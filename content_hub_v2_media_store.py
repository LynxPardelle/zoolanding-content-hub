"""IAM-only bridge to the private processor and exact versioned media reads."""
import base64
import hashlib
import json
import re

from content_hub_v2_authorization import assert_writer_epoch_current
from content_hub_v2_editor_model import EditorValidationError, safe_id, safe_locale
from content_hub_v2_editor_service import EditorConflict
from content_hub_v2_editor_store import ARTICLE_PK, PARTITION_PREFIX, AUDIT_TABLE, actor_condition_checks
from content_hub_v2_private_upload import UPLOAD_TABLE, UPLOAD_PK, MAX_ENVELOPE_BYTES, MAX_NORMALIZED_BYTES, safe_asset
from content_hub_v2_registry_fence import _condition_check, marshal_item, unmarshal_item

SCOPE_FIELDS = ("environment", "canonicalDomain", "authProfileId", "tenantId", "hubId", "articleId", "locale",
                "revisionId", "writerEpoch", "actorPurpose", "contentType", "decodedBytes", "contentSha256")


class AwsMediaStore:
    def __init__(self, editor_store, *, lambda_client=None):
        self.editor, self.auth = editor_store, editor_store.auth
        self.ddb, self._lambda = editor_store.ddb, lambda_client
        self.scope = editor_store.runtime._trusted_resource_scope(editor_store.context)
        self.bucket = f"zlp-thn-private-upload-test-{self.scope['accountId']}-{self.scope['region']}"

    def now_epoch(self):
        return self.editor.runtime.now_epoch()

    def load_upload(self, transaction_id):
        result = self.ddb.get_item(TableName=UPLOAD_TABLE,
            Key=marshal_item({"pk": UPLOAD_PK, "sk": "TX#" + safe_id(transaction_id)}), ConsistentRead=True)
        return unmarshal_item(result["Item"]) if result.get("Item") else None

    def _commit(self, row, mutations, authorize):
        authorize()
        registry = self.editor.runtime.load_registry(self.editor.context)
        assert_writer_epoch_current(self.auth, registry)
        items = [_condition_check(registry), *actor_condition_checks(self.auth, self.editor.session_hash, self.now_epoch()),
                 {"ConditionCheck": {"TableName": self.editor.table,
                    "Key": marshal_item({"pk": ARTICLE_PK, "sk": "ARTICLE#" + safe_id(row["articleId"])}),
                    "ConditionExpression": "concurrencyToken = :token AND recordPurpose = :purpose",
                    "ExpressionAttributeValues": marshal_item({":token": row["concurrencyToken"], ":purpose": self.auth.account_purpose})}},
                 *mutations]
        try:
            self.ddb.transact_write_items(TransactItems=items)
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") == "TransactionCanceledException":
                raise EditorConflict() from None
            raise

    def begin_upload(self, row, transaction, authorize):
        self._commit(row, [{"Put": {"TableName": UPLOAD_TABLE, "Item": marshal_item(transaction),
                                   "ConditionExpression": "attribute_not_exists(pk)"}}], authorize)

    def process_upload(self, transaction, image_base64):
        scope = self.scope
        payload = {"operation": "processPrivateImageV2", "transactionId": transaction["transactionId"],
                   "callerPrincipalArn": f"arn:{scope['partition']}:iam::{scope['accountId']}:role/zlp-thn-ch-test-authoring",
                   "scope": {key: transaction[key] for key in SCOPE_FIELDS}, "imageBase64": image_base64}
        body = json.dumps(payload, separators=(",", ":")).encode()
        if len(body) > MAX_ENVELOPE_BYTES:
            raise EditorValidationError("image_too_large")
        if self._lambda is None:
            import boto3
            from botocore.config import Config
            self._lambda = boto3.client("lambda", config=Config(read_timeout=95, retries={"max_attempts": 0}))
        response = self._lambda.invoke(
            FunctionName=f"arn:{scope['partition']}:lambda:{scope['region']}:{scope['accountId']}:function:zoolanding-image-upload-test-ThnImageUploadV2:test",
            InvocationType="RequestResponse", Payload=body)
        if response.get("FunctionError"):
            raise EditorValidationError("image_processing_failed")
        raw = response["Payload"].read(65537)
        if len(raw) > 65536:
            raise EditorValidationError("invalid_image_result")
        return json.loads(raw)

    def finish_upload(self, row, transaction, asset, authorize):
        fields = (*SCOPE_FIELDS, "status", "recordType", "schemaVersion", "assetId", "variants")
        condition = {"ConditionCheck": {"TableName": UPLOAD_TABLE,
            "Key": marshal_item({"pk": UPLOAD_PK, "sk": "TX#" + safe_id(transaction["transactionId"])}),
            "ConditionExpression": " AND ".join(f"#f{i} = :f{i}" for i, _ in enumerate(fields)),
            "ExpressionAttributeNames": {f"#f{i}": field for i, field in enumerate(fields)},
            "ExpressionAttributeValues": marshal_item({f":f{i}": transaction[field] for i, field in enumerate(fields)})}}
        item = {**asset, "pk": PARTITION_PREFIX + "ASSETS#" + safe_id(row["articleId"]) + "#" + safe_locale(transaction["locale"]),
                "sk": "ASSET#" + safe_id(asset["assetId"])}
        put = {"Put": {"TableName": self.editor.table, "Item": marshal_item(item),
            "ConditionExpression": "attribute_not_exists(pk) OR (uploadTransactionId = :tx AND recordPurpose = :purpose AND #status = :ready AND referenceCount = :zero AND deliveryState = :private)",
            "ExpressionAttributeNames": {"#status": "status"},
            "ExpressionAttributeValues": marshal_item({":tx": transaction["transactionId"], ":purpose": self.auth.account_purpose,
                                                      ":ready": "ready", ":zero": 0, ":private": "private"})}}
        audit = {"pk": f"AUDIT#test#thehairnarrative.com#thehairnarrative-com-journal#{row['articleId']}",
                 "sk": "EVENT#" + self.editor.new_id(), "operation": "uploadAsset", "articleId": row["articleId"],
                 "timestamp": self.editor.now(), "writerEpoch": self.auth.writer_epoch, "decision": "committed",
                 "actorHash": hashlib.sha256((PARTITION_PREFIX + self.auth.subject).encode()).hexdigest()}
        self._commit(row, [condition, put, {"Put": {"TableName": AUDIT_TABLE, "Item": marshal_item(audit),
                     "ConditionExpression": "attribute_not_exists(pk)"}}], authorize)

    def preview_asset(self, row, locale, asset_id):
        """Return one protected image; no new route, signed URL, or public ACL."""
        assets = self.editor.get_assets(row, locale, [safe_id(asset_id)])
        asset = assets.get(asset_id)
        if not asset or asset.get("status") != "ready":
            raise EditorValidationError("image_not_ready")
        variant = next((v for v in asset.get("variants", []) if v.get("variantId") == "w768"), None)
        prefix = ("private/test/thehairnarrative.com/journal-owner/thehairnarrative-com/thehairnarrative-com-journal/"
                  f"articles/{safe_id(row['articleId'])}/{safe_locale(locale)}/revisions/")
        expected = re.escape(prefix) + r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}/assets/" + re.escape(safe_id(asset_id)) + r"/w768\.(png|jpg|webp)"
        if (not variant or not isinstance(variant.get("key"), str) or re.fullmatch(expected, variant["key"]) is None
                or not variant.get("versionId") or variant["versionId"] == "null"
                or not 0 < variant.get("bytes", 0) <= MAX_NORMALIZED_BYTES
                or variant.get("contentType") not in {"image/jpeg", "image/png", "image/webp"}):
            raise EditorValidationError("invalid_image_pointer")
        response = self.editor.s3().get_object(Bucket=self.bucket, Key=variant["key"], VersionId=variant["versionId"])
        body = response["Body"].read(MAX_NORMALIZED_BYTES + 1)
        if len(body) != variant["bytes"] or hashlib.sha256(body).hexdigest() != variant["sha256"]:
            raise EditorValidationError("image_integrity_failed")
        return {**safe_asset(asset), "contentType": variant["contentType"], "imageBase64": base64.b64encode(body).decode()}
