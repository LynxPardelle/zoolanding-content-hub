"""Exact-key DynamoDB/S3 adapter for private editor state; no v1 imports."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import uuid

from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE, assert_writer_epoch_current
from content_hub_v2_registry_fence import _condition_check, marshal_item, unmarshal_item
from content_hub_v2_editor_model import EditorValidationError, MAX_PACKAGE_BYTES, safe_id, safe_locale
from content_hub_v2_editor_service import EditorConflict
from content_hub_v2_actor_fence import USER_TABLE, SESSION_TABLE, actor_condition_checks

from content_hub_v2_state_keys import PRIVATE_PREFIX, PARTITION_PREFIX, ARTICLE_PK, METADATA_TABLE, AUDIT_TABLE


class AwsEditorStore:
    def __init__(self, runtime, context, auth, session_hash, *, dynamodb=None, s3=None, metadata_table=None, private_bucket=None):
        self.runtime, self.context, self.auth, self.session_hash = runtime, context, auth, session_hash
        self.table = metadata_table or os.environ.get("THN_CONTENT_HUB_METADATA_TABLE_NAME", "")
        self.bucket = private_bucket or os.environ.get("THN_CONTENT_HUB_PRIVATE_BUCKET_NAME", "")
        if self.table != METADATA_TABLE or not self.bucket:
            raise EditorValidationError("feature_not_ready")
        self.ddb = dynamodb if dynamodb is not None else runtime._dynamodb()
        self._s3_client = s3
        self._media_store = None

    def media(self):
        if self._media_store is None:
            from content_hub_v2_media_store import AwsMediaStore
            self._media_store = AwsMediaStore(self)
        return self._media_store

    def upload_asset(self, row, locale, data, authorize):
        from content_hub_v2_private_upload import PrivateUpload
        return PrivateUpload(self.media())(row, locale, data, authorize)

    def preview_asset(self, row, locale, asset_id):
        return self.media().preview_asset(row, locale, asset_id)

    def s3(self):
        if self._s3_client is None:
            import boto3
            self._s3_client = boto3.client("s3")
        return self._s3_client

    @staticmethod
    def new_id():
        return uuid.uuid4().hex

    @staticmethod
    def now():
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    def _get(self, pk, sk):
        item = self.ddb.get_item(TableName=self.table, Key=marshal_item({"pk": pk, "sk": sk}), ConsistentRead=True).get("Item")
        return unmarshal_item(item) if item else None

    def get_article(self, article_id):
        return self._get(ARTICLE_PK, "ARTICLE#" + safe_id(article_id))

    def _query(self, pk, prefix):
        params = {"TableName": self.table, "KeyConditionExpression": "pk = :pk AND begins_with(sk, :prefix)",
                  "ExpressionAttributeValues": marshal_item({":pk": pk, ":prefix": prefix}), "ConsistentRead": True, "Limit": 100}
        values = []
        while True:
            response = self.ddb.query(**params)
            values.extend(unmarshal_item(item) for item in response.get("Items", []))
            if len(values) > 2000:
                raise EditorValidationError("list_limit_reached")
            if not response.get("LastEvaluatedKey"):
                return values
            params["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    def list_articles(self):
        return self._query(ARTICLE_PK, "ARTICLE#")

    @staticmethod
    def _package_key(article_id, locale, revision_id):
        return PRIVATE_PREFIX + f"immutable-revisions/{safe_id(article_id)}/{safe_locale(locale)}/{safe_id(revision_id)}/package.json"

    def save_package(self, article_id, locale, revision_id, package):
        body = json.dumps(package, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        if len(body) > MAX_PACKAGE_BYTES:
            raise EditorValidationError("package_too_large")
        key = self._package_key(article_id, locale, revision_id)
        response = self.s3().put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/json",
                                        CacheControl="private,no-store", ServerSideEncryption="AES256", IfNoneMatch="*")
        return {"key": key, "sha256": hashlib.sha256(body).hexdigest(), **({"versionId": response["VersionId"]} if response.get("VersionId") else {})}

    def load_package(self, row, locale):
        state = row["locales"][locale]
        pointer = state["packagePointer"]
        if pointer.get("key") != self._package_key(row["articleId"], locale, state["workingRevisionId"]):
            raise EditorValidationError("invalid_package_pointer")
        response = self.s3().get_object(Bucket=self.bucket, Key=pointer["key"], **({"VersionId": pointer["versionId"]} if pointer.get("versionId") else {}))
        body = response["Body"].read(MAX_PACKAGE_BYTES + 1)
        if len(body) > MAX_PACKAGE_BYTES or hashlib.sha256(body).hexdigest() != pointer["sha256"]:
            raise EditorValidationError("package_integrity_failed")
        return json.loads(body)

    def commit(self, value, expected, authorize):
        if value.get("recordPurpose") != self.auth.account_purpose:
            raise EditorValidationError("invalid_record_purpose")
        if len(json.dumps(value).encode()) > 65536:
            raise EditorValidationError("metadata_too_large")
        authorize()
        registry = self.runtime.load_registry(self.context)
        assert_writer_epoch_current(self.auth, registry)
        table_arn = registry["resourceBindings"]["metadataTableArn"]
        if not table_arn.endswith(":table/" + self.table):
            raise EditorValidationError("binding_mismatch")
        item = {**value, "pk": ARTICLE_PK, "sk": "ARTICLE#" + safe_id(value["articleId"])}
        put = {"TableName": self.table, "Item": marshal_item(item), "ConditionExpression": "attribute_not_exists(pk)"}
        if expected is not None:
            put.update({"ConditionExpression": "concurrencyToken = :previous AND recordPurpose = :purpose",
                        "ExpressionAttributeValues": marshal_item({":previous": expected, ":purpose": self.auth.account_purpose})})
        references = self._reference_updates(value, expected)
        audit = {"pk": f"AUDIT#test#thehairnarrative.com#thehairnarrative-com-journal#{safe_id(value['articleId'])}",
                 "sk": "EVENT#" + safe_id(value.get("concurrencyToken") or self.new_id()),
                 "operation": "createArticle" if expected is None else "updatePackage",
                 "articleId": value["articleId"], "timestamp": self.now(),
                 "actorHash": hashlib.sha256((PARTITION_PREFIX + self.auth.subject).encode()).hexdigest(),
                 "writerEpoch": self.auth.writer_epoch, "decision": "committed"}
        tx = [_condition_check(registry), *actor_condition_checks(self.auth, self.session_hash, self.runtime.now_epoch()),
              *references, {"Put": {"TableName": AUDIT_TABLE, "Item": marshal_item(audit),
                                   "ConditionExpression": "attribute_not_exists(pk)"}}, {"Put": put}]
        if len(tx) > 90:
            raise EditorValidationError("reference_limit")
        try:
            self.ddb.transact_write_items(TransactItems=tx)
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") == "TransactionCanceledException":
                raise EditorConflict() from None
            raise

    def _reference_updates(self, value, expected):
        if not value.get("locales"):
            return []
        previous = self.get_article(value["articleId"]) if expected is not None else {}
        if expected is not None and (not isinstance(previous, dict) or previous.get("concurrencyToken") != expected):
            raise EditorConflict()
        updates = []
        for locale, state in value["locales"].items():
            safe_locale(locale)
            old = previous.get("locales", {}).get(locale, {})
            before, after, published = (old.get("workingAssetIds", []), state.get("workingAssetIds", []),
                                        old.get("publishedAssetIds", []))
            if any(not isinstance(ids, list) or len(ids) > 21 or len(ids) != len(set(ids)) for ids in (before, after, published)):
                raise EditorValidationError("invalid_asset_references")
            if state.get("publishedAssetIds", []) != published:
                raise EditorValidationError("publication_requires_publisher")
            for asset_id in set(before) | set(after) | set(published):
                safe_id(asset_id)
            changed = sorted(set(before) ^ set(after))
            assets = self.get_assets(value, locale, changed)
            for asset_id in changed:
                asset = assets.get(asset_id, {})
                prior_count = int(asset_id in before) + int(asset_id in published)
                next_count = int(asset_id in after) + int(asset_id in published)
                if asset.get("status") != "ready" or asset.get("referenceCount") != prior_count:
                    raise EditorValidationError("asset_not_available")
                identity = {**THN_CURRENT_USER_SCOPE, "articleId": value["articleId"], "locale": locale, "assetId": asset_id}
                updates.append({"Update": {
                    "TableName": self.table,
                    "Key": marshal_item({"pk": PARTITION_PREFIX + f"ASSETS#{value['articleId']}#{locale}", "sk": "ASSET#" + asset_id}),
                    "UpdateExpression": "SET referenceCount = :next, referencesUpdatedAtEpoch = :now",
                    "ConditionExpression": "referenceCount = :previousCount AND #status = :ready AND recordPurpose = :purpose AND "
                        + " AND ".join(f"#i{i} = :i{i}" for i in range(len(identity))),
                    "ExpressionAttributeNames": {"#status": "status", **{f"#i{i}": k for i,k in enumerate(identity)}},
                    "ExpressionAttributeValues": marshal_item({":next": next_count, ":previousCount": prior_count,
                        ":ready": "ready", ":purpose": self.auth.account_purpose, ":now": self.runtime.now_epoch(),
                        **{f":i{i}": v for i,v in enumerate(identity.values())}})}})
        return updates

    def get_assets(self, row, locale, asset_ids):
        result = {}
        for asset_id in asset_ids:
            item = self._get(PARTITION_PREFIX + "ASSETS#" + safe_id(row["articleId"]) + "#" + safe_locale(locale), "ASSET#" + safe_id(asset_id))
            if (item and item.get("recordPurpose") == self.auth.account_purpose
                    and item.get("assetId") == asset_id and item.get("articleId") == row["articleId"] and item.get("locale") == locale
                    and all(item.get(key) == value for key, value in THN_CURRENT_USER_SCOPE.items())):
                result[asset_id] = item
        return result

    def list_assets(self, row, locale):
        items = self._query(PARTITION_PREFIX + "ASSETS#" + safe_id(row["articleId"]) + "#" + safe_locale(locale), "ASSET#")
        return [{key: item[key] for key in ("assetId", "status", "alt", "previewSrc", "width", "height") if key in item}
                for item in items if item.get("recordPurpose") == self.auth.account_purpose
                and item.get("articleId") == row["articleId"] and item.get("locale") == locale
                and all(item.get(key) == value for key, value in THN_CURRENT_USER_SCOPE.items())]
