"""Read-only public origin for live THN Journal media revisions."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from urllib.parse import urlparse

ENVIRONMENT = "test"
DOMAIN = "thehairnarrative.com"
HUB_ID = "thehairnarrative-com-journal"
PUBLIC_HOST = "test.zoolandingpage.com.mx"
ADMIN_HOST = "admin-test.thehairnarrative.com"
MANIFEST_RECORD_TYPE = "THN_CONTENT_HUB_V2_LIVE_MEDIA_MANIFEST"
PUBLIC_MEDIA_PREFIX = "/features/content-hub-v2/public-media"
IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, s-maxage=31536000, immutable"
MAX_VARIANTS = 128
# The HTTP API uses a buffered Lambda proxy response. Keep the base64 body plus
# the response envelope below Lambda's 6 MiB synchronous response ceiling.
MAX_VARIANT_BYTES = 4 * 1024 * 1024

_PATH_PARAMETER_NAMES = frozenset(
    {"articleId", "locale", "revisionId", "assetId", "variantId"}
)
_MANIFEST_FIELDS = frozenset(
    {
        "pk",
        "sk",
        "recordType",
        "schemaVersion",
        "environment",
        "domain",
        "hubId",
        "articleId",
        "locale",
        "revisionId",
        "status",
        "visibility",
        "deliveryState",
        "variants",
    }
)
_VARIANT_FIELDS = frozenset(
    {
        "assetId",
        "variantId",
        "objectKey",
        "versionId",
        "contentType",
        "bytes",
        "sha256",
    }
)
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$")
_VERSION_ID_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{1,1024}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_TABLE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_LOCALES = frozenset({"en", "es"})
_VARIANT_IDS = frozenset({"w480", "w768", "w1200", "w1600"})
_CONTENT_TYPES = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}


class PublicMediaNotFound(RuntimeError):
    """A request cannot be resolved to one current public media revision."""


class PublicMediaUnavailable(RuntimeError):
    """The public media origin cannot safely access its server-owned state."""


@dataclass(frozen=True)
class PublicMediaPath:
    article_id: str
    locale: str
    revision_id: str
    asset_id: str
    variant_id: str


@dataclass(frozen=True)
class LiveVariant:
    object_key: str
    version_id: str
    content_type: str
    byte_length: int
    sha256: str


def _not_found() -> dict[str, Any]:
    return {
        "statusCode": 404,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
        "body": json.dumps({"ok": False, "code": "not_found"}, separators=(",", ":")),
    }


def _unavailable() -> dict[str, Any]:
    return {
        "statusCode": 503,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
        "body": json.dumps(
            {"ok": False, "code": "service_unavailable"}, separators=(",", ":")
        ),
    }


def _header_values(event: Mapping[str, Any], name: str) -> tuple[str, ...] | None:
    headers = event.get("headers")
    if not isinstance(headers, Mapping):
        return None
    lowered = name.lower()
    values: list[str] = []
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == lowered:
            if not isinstance(value, str):
                return None
            values.append(value.strip())
    return tuple(values)


def _host_from_url(value: str) -> str:
    if not value:
        return ""
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


def _is_public_origin(event: Mapping[str, Any]) -> bool:
    forwarded = _header_values(event, "x-forwarded-host")
    if forwarded is None or len(forwarded) != 1 or forwarded[0].lower() != PUBLIC_HOST:
        return False
    for header in ("origin", "referer"):
        values = _header_values(event, header)
        if values is None or len(values) > 1:
            return False
        if values and _host_from_url(values[0]) == ADMIN_HOST:
            return False
    return True


def _safe_segment(value: Any) -> str:
    if not isinstance(value, str) or not _SAFE_SEGMENT_RE.fullmatch(value):
        raise PublicMediaNotFound
    return value


def _parse_request(event: Any) -> PublicMediaPath:
    if not isinstance(event, Mapping):
        raise PublicMediaNotFound
    request_context = event.get("requestContext")
    http = request_context.get("http") if isinstance(request_context, Mapping) else None
    if not isinstance(http, Mapping) or http.get("method") != "GET":
        raise PublicMediaNotFound
    if event.get("body") not in (None, ""):
        raise PublicMediaNotFound
    if event.get("rawQueryString") not in (None, ""):
        raise PublicMediaNotFound
    query = event.get("queryStringParameters")
    if query not in (None, {}):
        raise PublicMediaNotFound
    if not _is_public_origin(event):
        raise PublicMediaNotFound

    parameters = event.get("pathParameters")
    if not isinstance(parameters, Mapping) or set(parameters) != _PATH_PARAMETER_NAMES:
        raise PublicMediaNotFound
    article_id = _safe_segment(parameters.get("articleId"))
    locale = parameters.get("locale")
    revision_id = _safe_segment(parameters.get("revisionId"))
    asset_id = _safe_segment(parameters.get("assetId"))
    variant_id = parameters.get("variantId")
    if locale not in _LOCALES or variant_id not in _VARIANT_IDS:
        raise PublicMediaNotFound

    raw_path = event.get("rawPath")
    expected_path = f"{PUBLIC_MEDIA_PREFIX}/{article_id}/{locale}/{revision_id}/{asset_id}/{variant_id}"
    if raw_path != expected_path:
        raise PublicMediaNotFound
    return PublicMediaPath(article_id, locale, revision_id, asset_id, variant_id)


def _manifest_partition_key(path: PublicMediaPath) -> str:
    return (
        f"LIVE_MEDIA#{ENVIRONMENT}#{DOMAIN}#{HUB_ID}#"
        f"{path.article_id}#{path.locale}#{path.revision_id}"
    )


def _positive_int(value: Any) -> int:
    if isinstance(value, bool):
        raise PublicMediaNotFound
    if isinstance(value, int):
        normalized = value
    elif (
        isinstance(value, Decimal)
        and value.is_finite()
        and value == value.to_integral_value()
    ):
        normalized = int(value)
    else:
        raise PublicMediaNotFound
    if not 1 <= normalized <= MAX_VARIANT_BYTES:
        raise PublicMediaNotFound
    return normalized


def _validate_version_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or value == "null"
        or not _VERSION_ID_RE.fullmatch(value)
    ):
        raise PublicMediaNotFound
    return value


def _variant_from_manifest(
    candidate: Any,
    *,
    path: PublicMediaPath,
) -> tuple[tuple[str, str], LiveVariant]:
    if not isinstance(candidate, Mapping) or set(candidate) != _VARIANT_FIELDS:
        raise PublicMediaNotFound
    asset_id = _safe_segment(candidate.get("assetId"))
    variant_id = candidate.get("variantId")
    if variant_id not in _VARIANT_IDS:
        raise PublicMediaNotFound
    content_type = candidate.get("contentType")
    extension = _CONTENT_TYPES.get(content_type)
    if extension is None:
        raise PublicMediaNotFound
    expected_key = (
        f"content-hubs/{ENVIRONMENT}/{HUB_ID}/published/{DOMAIN}/{path.locale}/"
        f"{path.article_id}/{path.revision_id}/media/{asset_id}/{variant_id}.{extension}"
    )
    if candidate.get("objectKey") != expected_key:
        raise PublicMediaNotFound
    digest = candidate.get("sha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise PublicMediaNotFound
    return (
        (asset_id, variant_id),
        LiveVariant(
            object_key=expected_key,
            version_id=_validate_version_id(candidate.get("versionId")),
            content_type=content_type,
            byte_length=_positive_int(candidate.get("bytes")),
            sha256=digest,
        ),
    )


def resolve_live_variant(runtime: Any, path: PublicMediaPath) -> LiveVariant:
    """Resolve one path through one strongly read, exact live manifest."""

    partition_key = _manifest_partition_key(path)
    sort_key = "MANIFEST#V1"
    manifest = runtime.load_live_manifest(
        partition_key=partition_key,
        sort_key=sort_key,
    )
    if not isinstance(manifest, Mapping) or set(manifest) != _MANIFEST_FIELDS:
        raise PublicMediaNotFound
    expected = {
        "pk": partition_key,
        "sk": sort_key,
        "recordType": MANIFEST_RECORD_TYPE,
        "schemaVersion": 1,
        "environment": ENVIRONMENT,
        "domain": DOMAIN,
        "hubId": HUB_ID,
        "articleId": path.article_id,
        "locale": path.locale,
        "revisionId": path.revision_id,
        "status": "published",
        "visibility": "public",
        "deliveryState": "live",
    }
    if any(manifest.get(field) != value for field, value in expected.items()):
        raise PublicMediaNotFound
    variants = manifest.get("variants")
    if not isinstance(variants, list) or not 1 <= len(variants) <= MAX_VARIANTS:
        raise PublicMediaNotFound

    resolved: LiveVariant | None = None
    seen: set[tuple[str, str]] = set()
    for candidate in variants:
        identity, variant = _variant_from_manifest(candidate, path=path)
        if identity in seen:
            raise PublicMediaNotFound
        seen.add(identity)
        if identity == (path.asset_id, path.variant_id):
            resolved = variant
    if resolved is None:
        raise PublicMediaNotFound
    return resolved


class AwsPublicMediaRuntime:
    """Exact DynamoDB/S3 adapter for the public-media Lambda identity."""

    def __init__(
        self,
        *,
        dynamodb_client: Any | None = None,
        s3_client: Any | None = None,
        metadata_table_name: str | None = None,
        packages_bucket_name: str | None = None,
    ) -> None:
        table_name = metadata_table_name or os.getenv(
            "CONTENT_HUB_METADATA_TABLE_NAME", ""
        )
        bucket_name = packages_bucket_name or os.getenv(
            "CONTENT_HUB_PACKAGES_BUCKET_NAME", ""
        )
        if not _TABLE_NAME_RE.fullmatch(table_name) or not _BUCKET_NAME_RE.fullmatch(
            bucket_name
        ):
            raise PublicMediaUnavailable
        if dynamodb_client is None or s3_client is None:
            try:
                import boto3

                dynamodb_client = dynamodb_client or boto3.client("dynamodb")
                s3_client = s3_client or boto3.client("s3")
            except Exception as error:
                raise PublicMediaUnavailable from error
        self._dynamodb = dynamodb_client
        self._s3 = s3_client
        self._metadata_table_name = table_name
        self._packages_bucket_name = bucket_name

    def load_live_manifest(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        expected_prefix = f"LIVE_MEDIA#{ENVIRONMENT}#{DOMAIN}#{HUB_ID}#"
        if not partition_key.startswith(expected_prefix) or sort_key != "MANIFEST#V1":
            raise PublicMediaNotFound
        try:
            response = self._dynamodb.get_item(
                TableName=self._metadata_table_name,
                Key={"pk": {"S": partition_key}, "sk": {"S": sort_key}},
                ConsistentRead=True,
            )
            raw_item = response.get("Item") if isinstance(response, Mapping) else None
            if not raw_item:
                return None
            if not isinstance(raw_item, Mapping):
                raise PublicMediaUnavailable
            from boto3.dynamodb.types import TypeDeserializer

            deserializer = TypeDeserializer()
            return {
                key: deserializer.deserialize(value) for key, value in raw_item.items()
            }
        except PublicMediaNotFound:
            raise
        except PublicMediaUnavailable:
            raise
        except Exception as error:
            raise PublicMediaUnavailable from error

    def get_exact_variant(self, variant: LiveVariant) -> bytes:
        stream: Any | None = None
        try:
            response = self._s3.get_object(
                Bucket=self._packages_bucket_name,
                Key=variant.object_key,
                VersionId=variant.version_id,
            )
            if not isinstance(response, Mapping):
                raise PublicMediaNotFound
            if (
                response.get("DeleteMarker") is True
                or response.get("VersionId") != variant.version_id
                or response.get("ContentType") != variant.content_type
                or response.get("ContentLength") != variant.byte_length
                or response.get("ContentEncoding") not in (None, "")
            ):
                raise PublicMediaNotFound
            stream = response.get("Body")
            if stream is None or not callable(getattr(stream, "read", None)):
                raise PublicMediaNotFound
            body = stream.read(variant.byte_length + 1)
            if not isinstance(body, bytes) or len(body) != variant.byte_length:
                raise PublicMediaNotFound
            return body
        except PublicMediaNotFound:
            raise
        except Exception as error:
            raise PublicMediaNotFound from error
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                close()


def _success(variant: LiveVariant, body: bytes) -> dict[str, Any]:
    return {
        "statusCode": 200,
        "headers": {
            "content-type": variant.content_type,
            "cache-control": IMMUTABLE_CACHE_CONTROL,
            "x-content-type-options": "nosniff",
            "content-disposition": "inline",
            "etag": f'"sha256-{variant.sha256}"',
        },
        "isBase64Encoded": True,
        "body": base64.b64encode(body).decode("ascii"),
    }


def handle_request(event: Any, *, runtime: Any | None = None) -> dict[str, Any]:
    try:
        path = _parse_request(event)
        active_runtime = runtime or AwsPublicMediaRuntime()
        variant = resolve_live_variant(active_runtime, path)
        body = active_runtime.get_exact_variant(variant)
        if (
            len(body) != variant.byte_length
            or hashlib.sha256(body).hexdigest() != variant.sha256
        ):
            raise PublicMediaNotFound
        return _success(variant, body)
    except PublicMediaNotFound:
        return _not_found()
    except PublicMediaUnavailable:
        return _unavailable()
    # This is the Lambda's final trust boundary: unexpected dependency/runtime
    # failures must not expose storage or manifest details to a public caller.
    except Exception:  # noqa: BLE001
        return _unavailable()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    return handle_request(event)


__all__ = [
    "AwsPublicMediaRuntime",
    "LiveVariant",
    "PublicMediaNotFound",
    "PublicMediaPath",
    "PublicMediaUnavailable",
    "handle_request",
    "lambda_handler",
    "resolve_live_variant",
]
