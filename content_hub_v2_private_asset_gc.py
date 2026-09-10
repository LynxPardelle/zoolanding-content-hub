"""Exact-key, claimed-before-delete collection of unreferenced private images."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from content_hub_v2_registry_fence import _condition_check
from service_binding_registry_consumer_v2 import load_active_service_binding, marshal_item, unmarshal_item

FUNCTION_NAME = "zoolanding-content-hub-test-ThnV2PrivateAssetCollector"
TABLE = "zoolanding-content-hub-test-ThnContentHubV2Metadata"
SCOPE = {"environment":"test","domain":"thehairnarrative.com","serviceBindingId":"thn-journal-test-v2",
         "authProfileId":"journal-owner","tenantId":"thehairnarrative-com","hubId":"thehairnarrative-com-journal"}
PK = "THN#test#thehairnarrative.com#journal-owner#thehairnarrative-com#thehairnarrative-com-journal#"
SOURCE = "private/test/thehairnarrative.com/journal-owner/thehairnarrative-com/thehairnarrative-com-journal/"
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
VARIANTS = ["w480","w768","w1200","w1600"]
RETENTION_SECONDS = 7 * 24 * 60 * 60


class HandlerNotActiveError(ValueError):
    """Collection cannot proceed with the supplied binding or candidates."""


def _reject():
    raise HandlerNotActiveError("private collection unavailable")


def _candidate(value):
    if (not isinstance(value, dict) or set(value) != {"articleId","locale","assetId"}
            or value.get("locale") not in ("en","es")
            or any(not isinstance(value.get(key), str) or not ID.fullmatch(value[key]) for key in ("articleId","assetId"))):
        _reject()
    return dict(value)


def _digest(asset):
    return hashlib.sha256(json.dumps(asset["variants"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _eligible(candidate, asset, article, now):
    if not isinstance(asset, dict) or not isinstance(article, dict):
        return False
    if any(asset.get(k) != v or article.get(k) != v for k,v in SCOPE.items()):
        return False
    if (any(asset.get(k) != v for k,v in candidate.items()) or article.get("articleId") != candidate["articleId"]
            or asset.get("recordPurpose") not in ("qa","client-owner") or asset["recordPurpose"] != article.get("recordPurpose")
            or asset.get("status") not in ("ready","collecting") or asset.get("deliveryState") != "private"
            or type(asset.get("referenceCount")) is not int or asset["referenceCount"] != 0):
        return False
    age = max(asset.get("createdAtEpoch", now), asset.get("referencesUpdatedAtEpoch", 0))
    if type(age) is not int or age < 0 or age > now - RETENTION_SECONDS:
        return False
    state = article.get("locales", {}).get(candidate["locale"], {})
    # Older, untracked records require a reviewed backfill; they are never GC candidates.
    for field in ("workingAssetIds", "publishedAssetIds"):
        if not isinstance(state.get(field), list) or candidate["assetId"] in state[field]:
            return False
    variants = asset.get("variants")
    if not isinstance(variants, list) or [v.get("variantId") for v in variants if isinstance(v, dict)] != VARIANTS:
        return False
    revisions = set()
    extensions = {"image/jpeg":"jpg","image/png":"png","image/webp":"webp"}
    for variant in variants:
        extension = extensions.get(variant.get("contentType"))
        if not extension or not isinstance(variant.get("versionId"), str) or not 0 < len(variant["versionId"]) <= 1024 or variant["versionId"] == "null":
            return False
        prefix = re.escape(SOURCE + f"articles/{candidate['articleId']}/{candidate['locale']}/revisions/")
        suffix = re.escape(f"/assets/{candidate['assetId']}/{variant['variantId']}.{extension}")
        match = re.fullmatch(prefix + r"([A-Za-z0-9][A-Za-z0-9_-]{0,79})" + suffix, variant.get("key", ""))
        if not match or not re.fullmatch(r"[a-f0-9]{64}", variant.get("sha256", "")):
            return False
        revisions.add(match[1])
    return len(revisions) == 1


def collect_private_assets(candidates, *, store, now_epoch):
    if not isinstance(candidates, list) or len(candidates) > 20 or type(now_epoch) is not int:
        _reject()
    candidates = [_candidate(c) for c in candidates]
    if len({tuple(sorted(c.items())) for c in candidates}) != len(candidates):
        _reject()
    result = {"collected":0,"skipped":0,"failed":0}
    for candidate in candidates:
        try:
            asset, article = store.read_asset(candidate), store.read_article(candidate)
            if not _eligible(candidate, asset, article, now_epoch):
                result["skipped"] += 1
                continue
            # The atomic claim excludes future reference commits before any irreversible delete.
            store.claim(asset, article)
            for variant in asset["variants"]:
                store.delete_variant(variant)
            store.finish(asset)
            result["collected"] += 1
        except Exception:
            result["failed"] += 1  # Never return provider details, private keys or identifiers.
    return result


class AwsPrivateAssetCollector:
    def __init__(self, ddb, s3, *, bucket, expected_descriptor, trusted_scope, writer_epoch):
        self.ddb, self.s3, self.bucket = ddb, s3, bucket
        self.descriptor, self.scope, self.epoch = expected_descriptor, trusted_scope, writer_epoch
        if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
            _reject()
        if bucket != f"zlp-thn-private-upload-test-{trusted_scope.get('accountId')}-{trusted_scope.get('region')}":
            _reject()

    def _binding(self):
        binding = load_active_service_binding(self.ddb, expected_descriptor=self.descriptor, trusted_resource_scope=self.scope)
        if binding["writerEpoch"] != self.epoch or not binding["resourceBindings"]["metadataTableArn"].endswith(":table/" + TABLE):
            _reject()
        return binding

    def _get(self, key):
        item = self.ddb.get_item(TableName=TABLE, Key=marshal_item(key), ConsistentRead=True).get("Item")
        return unmarshal_item(item) if item else None

    def _key(self, asset):
        return {"pk":PK + f"ASSETS#{asset['articleId']}#{asset['locale']}", "sk":"ASSET#" + asset["assetId"]}

    def read_asset(self, candidate):
        return self._get(self._key(candidate))

    def read_article(self, candidate):
        return self._get({"pk":PK+"ARTICLES","sk":"ARTICLE#"+candidate["articleId"]})

    def claim(self, asset, article):
        binding = self._binding()
        fields = ("status","recordPurpose","referenceCount","deliveryState","variants","createdAtEpoch")
        names = {f"#f{i}":k for i,k in enumerate(fields)}
        values = {f":f{i}":asset[k] for i,k in enumerate(fields)}
        expression = " AND ".join(f"#f{i} = :f{i}" for i,_ in enumerate(fields))
        if "referencesUpdatedAtEpoch" in asset:
            expression += " AND referencesUpdatedAtEpoch = :referencesAt"
            values[":referencesAt"] = asset["referencesUpdatedAtEpoch"]
        else:
            expression += " AND attribute_not_exists(referencesUpdatedAtEpoch)"
        self.ddb.transact_write_items(TransactItems=[_condition_check(binding), {"ConditionCheck":{
            "TableName":TABLE,"Key":marshal_item({"pk":PK+"ARTICLES","sk":"ARTICLE#"+article["articleId"]}),
            "ConditionExpression":"concurrencyToken = :token AND locales = :locales AND recordPurpose = :purpose",
            "ExpressionAttributeValues":marshal_item({":token":article["concurrencyToken"],":locales":article["locales"],":purpose":article["recordPurpose"]})}},
            {"Update":{"TableName":TABLE,"Key":marshal_item(self._key(asset)),
                       "UpdateExpression":"SET #status = :collecting, collectionDigest = :digest",
                       "ConditionExpression":expression,"ExpressionAttributeNames":{**names,"#status":"status"},
                       "ExpressionAttributeValues":marshal_item({**values,":collecting":"collecting",":digest":_digest(asset)})}}])

    def delete_variant(self, variant):
        self._binding()
        self.s3.delete_object(Bucket=self.bucket, Key=variant["key"], VersionId=variant["versionId"])

    def finish(self, asset):
        binding = self._binding()
        self.ddb.transact_write_items(TransactItems=[_condition_check(binding),{"Update":{
            "TableName":TABLE,"Key":marshal_item(self._key(asset)),
            "UpdateExpression":"SET #status = :collected",
            "ConditionExpression":"#status = :collecting AND collectionDigest = :digest AND referenceCount = :zero",
            "ExpressionAttributeNames":{"#status":"status"},
            "ExpressionAttributeValues":marshal_item({":collected":"collected",":collecting":"collecting",":digest":_digest(asset),":zero":0})}}])


def lambda_handler(event, context):
    if (not isinstance(event, dict) or set(event) != {"schemaVersion","operation","writerEpoch","candidates"}
            or event.get("schemaVersion") != 1 or event.get("operation") != "collect-private-assets"
            or type(event.get("writerEpoch")) is not int or event["writerEpoch"] < 1):
        _reject()
    if (getattr(context,"function_name",None) != FUNCTION_NAME
            or not str(getattr(context,"invoked_function_arn","")).endswith(f":function:{FUNCTION_NAME}:test")):
        _reject()
    candidates = event["candidates"]
    if not isinstance(candidates,list) or len(candidates)>20:
        _reject()
    for candidate in candidates:
        _candidate(candidate)
    try:
        if os.environ.get("THN_CONTENT_HUB_METADATA_TABLE_NAME") != TABLE:
            _reject()
        descriptor = {k:os.environ[n] for k,n in {
            "descriptorVersionId":"THN_CONTENT_HUB_DESCRIPTOR_VERSION_ID","descriptorSha256":"THN_CONTENT_HUB_DESCRIPTOR_SHA256",
            "authPolicyVersion":"THN_CONTENT_HUB_AUTH_POLICY_VERSION"}.items()}
        scope = {k:os.environ[n] for k,n in {"partition":"THN_CONTENT_HUB_AWS_PARTITION",
            "accountId":"THN_CONTENT_HUB_AWS_ACCOUNT_ID","region":"THN_CONTENT_HUB_AWS_REGION"}.items()}
        bucket = os.environ["THN_CONTENT_HUB_PRIVATE_MEDIA_BUCKET_NAME"]
        import boto3
        store = AwsPrivateAssetCollector(boto3.client("dynamodb"),boto3.client("s3"),bucket=bucket,
                expected_descriptor=descriptor,trusted_scope=scope,writer_epoch=event["writerEpoch"])
        store._binding()
        return collect_private_assets(candidates,store=store,now_epoch=int(time.time()))
    except Exception:
        _reject()
