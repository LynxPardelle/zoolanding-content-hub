"""Private upload coordinator. No public uploader, URLs, ACLs or v1 imports."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import EditorValidationError, safe_id, safe_locale, text

MAX_NORMALIZED_BYTES = 4_194_304
MAX_BASE64_CHARS = 5_592_408
MAX_METADATA_BYTES = 65_536
MAX_ENVELOPE_BYTES = 5_750_000
UPLOAD_TABLE = "zoolanding-image-upload-test-ThnPrivateUploadTransactionsV2"
UPLOAD_PK = "UPLOAD_TX#test#thehairnarrative.com#journal-owner#thehairnarrative-com#thehairnarrative-com-journal"
VARIANTS = ("w480", "w768", "w1200", "w1600")
CONTENT_TYPES = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}


def validate_upload(data):
    encoded, content_type = data.get("imageBase64"), data.get("contentType")
    if content_type not in CONTENT_TYPES or not isinstance(encoded, str) or not 0 < len(encoded) <= MAX_BASE64_CHARS:
        raise EditorValidationError("invalid_image")
    metadata = {key: value for key, value in data.items() if key != "imageBase64"}
    if len(json.dumps(metadata, ensure_ascii=False).encode()) > MAX_METADATA_BYTES:
        raise EditorValidationError("metadata_too_large")
    alt = text(data.get("alt", ""), 240).strip()
    if not alt:
        raise EditorValidationError("image_alt_required")
    try:
        source = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise EditorValidationError("invalid_image") from None
    if not 0 < len(source) <= MAX_NORMALIZED_BYTES or base64.b64encode(source).decode() != encoded:
        raise EditorValidationError("image_too_large")
    magic = ((content_type == "image/png" and source.startswith(b"\x89PNG\r\n\x1a\n")) or
             (content_type == "image/jpeg" and source.startswith(b"\xff\xd8\xff")) or
             (content_type == "image/webp" and source.startswith(b"RIFF") and source[8:12] == b"WEBP"))
    if not magic:
        raise EditorValidationError("invalid_image")
    return source, alt


def private_variant_key(transaction, variant):
    return ("private/test/thehairnarrative.com/journal-owner/thehairnarrative-com/thehairnarrative-com-journal/"
            f"articles/{safe_id(transaction['articleId'])}/{safe_locale(transaction['locale'])}/"
            f"revisions/{safe_id(transaction['revisionId'])}/assets/{safe_id(transaction['assetId'])}/"
            f"{variant['variantId']}.{CONTENT_TYPES[variant['contentType']]}")


def safe_asset(asset):
    return {key: asset[key] for key in ("assetId", "status", "alt", "width", "height")}


def ready_asset(transaction, alt):
    if (transaction.get("status") != "consumed" or transaction.get("processingState") != "ready"
            or transaction.get("deliveryState") != "private" or transaction.get("referenceCount") != 0):
        raise EditorValidationError("image_not_ready")
    variants = transaction.get("variants")
    if not isinstance(variants, list) or [v.get("variantId") for v in variants if isinstance(v, dict)] != list(VARIANTS):
        raise EditorValidationError("invalid_image_result")
    for variant in variants:
        if (variant.get("contentType") != transaction["contentType"]
                or not isinstance(variant.get("versionId"), str) or not 0 < len(variant["versionId"]) <= 1024 or variant["versionId"] == "null"
                or not isinstance(variant.get("sha256"), str) or re.fullmatch(r"[a-f0-9]{64}", variant["sha256"]) is None
                or any(type(variant.get(key)) is not int or variant[key] <= 0 for key in ("width", "height", "bytes"))
                or variant["width"] > min(int(variant["variantId"][1:]), transaction.get("sourceWidth", 0))
                or variant["height"] > 8000):
            raise EditorValidationError("invalid_image_result")
    return {**THN_CURRENT_USER_SCOPE, "articleId": transaction["articleId"], "locale": transaction["locale"],
            "recordPurpose": transaction["actorPurpose"], "assetId": transaction["assetId"], "status": "ready",
            "alt": alt, "width": transaction["sourceWidth"], "height": transaction["sourceHeight"],
            "deliveryState": "private", "referenceCount": 0, "uploadTransactionId": transaction["transactionId"],
            "createdAtEpoch": transaction["createdAtEpoch"],
            "variants": [{**v, "key": private_variant_key(transaction, v)} for v in variants]}


class PrivateUpload:
    def __init__(self, store):
        self.store = store

    def __call__(self, row, locale, data, authorize):
        source, alt = validate_upload(data)
        authorize()
        purpose = self.store.auth.account_purpose
        if row.get("recordPurpose") != purpose or any(row.get(k) != v for k, v in THN_CURRENT_USER_SCOPE.items()):
            raise EditorValidationError("invalid_upload_scope")
        scope = {"environment": "test", "canonicalDomain": "thehairnarrative.com", "authProfileId": "journal-owner",
                 "tenantId": "thehairnarrative-com", "hubId": "thehairnarrative-com-journal", "articleId": safe_id(row["articleId"]),
                 "locale": safe_locale(locale), "revisionId": safe_id(row["locales"][locale]["workingRevisionId"]),
                 "writerEpoch": self.store.auth.writer_epoch, "actorPurpose": purpose, "contentType": data["contentType"],
                 "decodedBytes": len(source), "contentSha256": hashlib.sha256(source).hexdigest()}
        identity = hashlib.sha256(json.dumps([scope, row["concurrencyToken"], alt], sort_keys=True).encode()).hexdigest()
        transaction_id = "u" + identity[:40]
        expected = {**scope, "transactionId": transaction_id, "assetId": "m" + identity[:40],
                    "pk": UPLOAD_PK, "sk": "TX#" + transaction_id,
                    "recordType": "thn-private-upload-transaction-v2", "schemaVersion": "2"}
        now = self.store.now_epoch()
        tx = self.store.load_upload(transaction_id)
        if tx is None:
            tx = {**scope, "pk": UPLOAD_PK, "sk": "TX#" + transaction_id, "transactionId": transaction_id,
                  "assetId": "m" + identity[:40], "recordType": "thn-private-upload-transaction-v2", "schemaVersion": "2",
                  "status": "pending", "attemptCount": 0, "createdAtEpoch": now, "expiresAtEpoch": now + 900}
            self.store.begin_upload(row, tx, authorize)
            tx = self.store.load_upload(transaction_id)
        if not tx or any(tx.get(key) != value for key, value in expected.items()):
            raise EditorValidationError("invalid_upload_transaction")
        if tx["status"] != "consumed":
            if not now < tx.get("expiresAtEpoch", 0) <= now + 900 or tx.get("attemptCount", 3) >= 3:
                raise EditorValidationError("upload_expired")
            authorize()
            result = self.store.process_upload(tx, data["imageBase64"])
            if not isinstance(result, dict) or result.get("ok") is not True:
                raise EditorValidationError("image_processing_failed")
            tx = self.store.load_upload(transaction_id)
            if not tx or any(tx.get(key) != value for key, value in expected.items()):
                raise EditorValidationError("invalid_upload_transaction")
        asset = ready_asset(tx, alt)
        self.store.finish_upload(row, tx, asset, authorize)
        authorize()
        return {"asset": safe_asset(asset)}
