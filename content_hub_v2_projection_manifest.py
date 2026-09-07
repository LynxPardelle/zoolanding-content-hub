"""Closed THN public-projection manifest contract used by publish and withdrawal."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

SCHEMA_VERSION = 1
ENVIRONMENT = "test"
DOMAIN = "thehairnarrative.com"
HUB_ID = "thehairnarrative-com-journal"
MANIFEST_PK = (
    "THN#test#thehairnarrative.com#journal-owner#thehairnarrative-com#"
    "thehairnarrative-com-journal#PROJECTION"
)
MANIFEST_SK = "MANIFEST#V1"
MANIFEST_RECORD_TYPE = "THN_CONTENT_HUB_V2_PROJECTION_MANIFEST"
PAGE_RECORD_TYPE = "THN_CONTENT_HUB_V2_PROJECTION_MANIFEST_PAGE"
MAX_POINTERS_PER_PAGE = 19
MAX_MEDIA_INVALIDATION_PATHS = 84
MAX_MANIFEST_PAGES = 100_000
MAX_PAGE_SERIALIZED_BYTES = 300_000
GLOBAL_INVALIDATION_PATHS = (
    "/the-journal",
    "/content-hub-search.json",
    "/sitemap.xml",
)

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_PATH_ID_RE = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_LOCALES = frozenset({"en", "es"})
_POINTER_TYPES = frozenset({"article", "locale-path", "category-index", "public-media"})
_MANIFEST_FIELDS = frozenset(
    {
        "pk",
        "sk",
        "recordType",
        "schemaVersion",
        "environment",
        "domain",
        "hubId",
        "manifestId",
        "projectionDigest",
        "publicationWriterEpoch",
        "withdrawalEpoch",
        "state",
        "headPageId",
        "initialPageCount",
        "remainingPageCount",
        "initialPointerCount",
        "livePointerCount",
        "completedBatches",
        "stateRevision",
    }
)
_LIVE_PAGE_FIELDS = frozenset(
    {
        "pk",
        "sk",
        "recordType",
        "schemaVersion",
        "environment",
        "domain",
        "hubId",
        "manifestId",
        "pageId",
        "nextPageId",
        "pointerCount",
        "livePointers",
        "pageDigest",
        "state",
    }
)


class ProjectionManifestError(ValueError):
    """The private projection manifest cannot safely drive public deletion."""


def _reject() -> None:
    raise ProjectionManifestError("projection manifest is unavailable")


def _positive_int(value: Any) -> bool:
    return type(value) is int and value >= 1


def _non_negative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _safe_id(value: Any, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        _reject()
    return value


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _common_pointer_values(pointer: Mapping[str, Any]) -> tuple[str, str, str]:
    article_id = _safe_id(pointer.get("articleId"))
    locale = pointer.get("locale")
    revision_id = _safe_id(pointer.get("revisionId"))
    if locale not in _LOCALES:
        _reject()
    return article_id, locale, revision_id


def _invalidation_paths(pointer: Mapping[str, Any]) -> list[str]:
    paths = pointer.get("invalidationPaths")
    if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
        _reject()
    if len(paths) != len(set(paths)):
        _reject()
    return list(paths)


def validate_projection_pointer(value: Any) -> dict[str, Any]:
    """Validate one exact THN-only public key and its derived cache paths."""

    if not isinstance(value, Mapping):
        _reject()
    pointer = dict(value)
    pointer_type = pointer.get("pointerType")
    if pointer_type not in _POINTER_TYPES:
        _reject()
    article_id, locale, revision_id = _common_pointer_values(pointer)
    paths = _invalidation_paths(pointer)
    pk = pointer.get("pk")
    sk = pointer.get("sk")

    common_fields = {
        "pointerType",
        "pk",
        "sk",
        "articleId",
        "locale",
        "revisionId",
        "invalidationPaths",
    }
    if pointer_type == "article":
        if set(pointer) != common_fields or paths:
            _reject()
        if pk != f"HUB#{HUB_ID}" or sk != f"ARTICLE#{article_id}":
            _reject()
    elif pointer_type == "locale-path":
        if set(pointer) != common_fields | {"path"}:
            _reject()
        path = pointer.get("path")
        detail_pattern = re.compile(
            r"^/the-journal/[a-z0-9]+(?:-[a-z0-9]+)*/"
            r"[a-z0-9]+(?:-[a-z0-9]+)*$"
        )
        if not isinstance(path, str) or not detail_pattern.fullmatch(path):
            _reject()
        if (
            pk != f"SLUG#{ENVIRONMENT}#{DOMAIN}#{locale}"
            or sk != f"PATH#{path}"
            or paths != [path]
        ):
            _reject()
    elif pointer_type == "category-index":
        if set(pointer) != common_fields | {"categorySlug"}:
            _reject()
        category_slug = pointer.get("categorySlug")
        if not isinstance(category_slug, str) or not _SLUG_RE.fullmatch(category_slug):
            _reject()
        if (
            pk != f"HUB#{HUB_ID}"
            or sk != f"CATEGORY#{locale}#{category_slug}#ARTICLE#{article_id}"
            or paths != [f"/the-journal/{category_slug}"]
        ):
            _reject()
    else:
        if (
            set(pointer) != common_fields
            or not 1 <= len(paths) <= MAX_MEDIA_INVALIDATION_PATHS
        ):
            _reject()
        expected_pk = (
            f"LIVE_MEDIA#{ENVIRONMENT}#{DOMAIN}#{HUB_ID}#"
            f"{article_id}#{locale}#{revision_id}"
        )
        media_pattern = re.compile(
            r"^/features/content-hub-v2/public-media/"
            + re.escape(article_id)
            + "/"
            + locale
            + "/"
            + re.escape(revision_id)
            + rf"/{_SAFE_PATH_ID_RE}/{_SAFE_PATH_ID_RE}$"
        )
        if pk != expected_pk or sk != "MANIFEST#V1":
            _reject()
        if any(not media_pattern.fullmatch(path) for path in paths):
            _reject()

    return deepcopy(pointer)


def _page_digest_material(page: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(page[key])
        for key in sorted(_LIVE_PAGE_FIELDS - {"pageDigest", "state"})
    }


def seal_projection_page(
    *,
    manifest_id: str,
    page_id: str,
    next_page_id: str,
    live_pointers: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    manifest_id = _safe_id(manifest_id)
    page_id = _safe_id(page_id)
    next_page_id = _safe_id(next_page_id, allow_empty=True)
    if next_page_id == page_id:
        _reject()
    if (
        not isinstance(live_pointers, Sequence)
        or isinstance(live_pointers, (str, bytes, bytearray))
        or not 1 <= len(live_pointers) <= MAX_POINTERS_PER_PAGE
    ):
        _reject()
    pointers = [validate_projection_pointer(pointer) for pointer in live_pointers]
    keys = [(pointer["pk"], pointer["sk"]) for pointer in pointers]
    if len(keys) != len(set(keys)):
        _reject()
    page = {
        "pk": MANIFEST_PK,
        "sk": f"PAGE#{page_id}",
        "recordType": PAGE_RECORD_TYPE,
        "schemaVersion": SCHEMA_VERSION,
        "environment": ENVIRONMENT,
        "domain": DOMAIN,
        "hubId": HUB_ID,
        "manifestId": manifest_id,
        "pageId": page_id,
        "nextPageId": next_page_id,
        "pointerCount": len(pointers),
        "livePointers": pointers,
        "state": "live",
    }
    page["pageDigest"] = _canonical_digest(_page_digest_material(page))
    if len(_canonical_bytes(page)) > MAX_PAGE_SERIALIZED_BYTES:
        _reject()
    return page


def validate_projection_page(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _LIVE_PAGE_FIELDS:
        _reject()
    page = dict(value)
    if (
        page.get("pk") != MANIFEST_PK
        or page.get("recordType") != PAGE_RECORD_TYPE
        or page.get("schemaVersion") != SCHEMA_VERSION
        or page.get("environment") != ENVIRONMENT
        or page.get("domain") != DOMAIN
        or page.get("hubId") != HUB_ID
        or page.get("state") != "live"
    ):
        _reject()
    manifest_id = _safe_id(page.get("manifestId"))
    page_id = _safe_id(page.get("pageId"))
    next_page_id = _safe_id(page.get("nextPageId"), allow_empty=True)
    if page.get("sk") != f"PAGE#{page_id}" or next_page_id == page_id:
        _reject()
    pointer_count = page.get("pointerCount")
    pointers = page.get("livePointers")
    if (
        type(pointer_count) is not int
        or not isinstance(pointers, list)
        or pointer_count != len(pointers)
        or not 1 <= pointer_count <= MAX_POINTERS_PER_PAGE
    ):
        _reject()
    normalized_pointers = [validate_projection_pointer(pointer) for pointer in pointers]
    keys = [(pointer["pk"], pointer["sk"]) for pointer in normalized_pointers]
    if len(keys) != len(set(keys)):
        _reject()
    digest = page.get("pageDigest")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        _reject()
    page["manifestId"] = manifest_id
    page["pageId"] = page_id
    page["nextPageId"] = next_page_id
    page["livePointers"] = normalized_pointers
    if digest != _canonical_digest(_page_digest_material(page)):
        _reject()
    if len(_canonical_bytes(page)) > MAX_PAGE_SERIALIZED_BYTES:
        _reject()
    return deepcopy(page)


def seal_projection_manifest(
    *,
    manifest_id: str,
    projection_digest: str,
    publication_writer_epoch: int,
    head_page_id: str,
    page_count: int,
    pointer_count: int,
) -> dict[str, Any]:
    manifest = {
        "pk": MANIFEST_PK,
        "sk": MANIFEST_SK,
        "recordType": MANIFEST_RECORD_TYPE,
        "schemaVersion": SCHEMA_VERSION,
        "environment": ENVIRONMENT,
        "domain": DOMAIN,
        "hubId": HUB_ID,
        "manifestId": _safe_id(manifest_id),
        "projectionDigest": projection_digest,
        "publicationWriterEpoch": publication_writer_epoch,
        "withdrawalEpoch": 0,
        "state": "live",
        "headPageId": _safe_id(head_page_id, allow_empty=True),
        "initialPageCount": page_count,
        "remainingPageCount": page_count,
        "initialPointerCount": pointer_count,
        "livePointerCount": pointer_count,
        "completedBatches": 0,
        "stateRevision": 1,
    }
    return validate_projection_manifest(manifest)


def validate_projection_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _MANIFEST_FIELDS:
        _reject()
    manifest = dict(value)
    if (
        manifest.get("pk") != MANIFEST_PK
        or manifest.get("sk") != MANIFEST_SK
        or manifest.get("recordType") != MANIFEST_RECORD_TYPE
        or manifest.get("schemaVersion") != SCHEMA_VERSION
        or manifest.get("environment") != ENVIRONMENT
        or manifest.get("domain") != DOMAIN
        or manifest.get("hubId") != HUB_ID
    ):
        _reject()
    _safe_id(manifest.get("manifestId"))
    _safe_id(manifest.get("headPageId"), allow_empty=True)
    digest = manifest.get("projectionDigest")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        _reject()
    for field in (
        "publicationWriterEpoch",
        "stateRevision",
    ):
        if not _positive_int(manifest.get(field)):
            _reject()
    for field in (
        "withdrawalEpoch",
        "initialPageCount",
        "remainingPageCount",
        "initialPointerCount",
        "livePointerCount",
        "completedBatches",
    ):
        if not _non_negative_int(manifest.get(field)):
            _reject()
    initial_pages = manifest["initialPageCount"]
    remaining_pages = manifest["remainingPageCount"]
    initial_pointers = manifest["initialPointerCount"]
    live_pointers = manifest["livePointerCount"]
    completed = manifest["completedBatches"]
    state = manifest.get("state")
    if (
        remaining_pages > initial_pages
        or live_pointers > initial_pointers
        or initial_pages > MAX_MANIFEST_PAGES
        or initial_pointers > initial_pages * MAX_POINTERS_PER_PAGE
        or (initial_pages == 0) != (initial_pointers == 0)
        or (remaining_pages == 0) != (live_pointers == 0)
        or initial_pointers < initial_pages
        or live_pointers < remaining_pages
    ):
        _reject()
    if state == "live":
        if (
            manifest["withdrawalEpoch"] != 0
            or remaining_pages != initial_pages
            or live_pointers != initial_pointers
            or completed != 0
            or manifest["stateRevision"] != 1
            or (remaining_pages == 0) != (manifest["headPageId"] == "")
        ):
            _reject()
    elif state == "withdrawing":
        if (
            not _positive_int(manifest["withdrawalEpoch"])
            or remaining_pages < 1
            or not manifest["headPageId"]
            or completed != initial_pages - remaining_pages
            or manifest["stateRevision"] != completed + 1
        ):
            _reject()
    elif state == "withdrawn":
        expected_batches = max(1, initial_pages)
        if (
            not _positive_int(manifest["withdrawalEpoch"])
            or remaining_pages != 0
            or live_pointers != 0
            or manifest["headPageId"] != ""
            or completed != expected_batches
            or manifest["stateRevision"] != completed + 1
        ):
            _reject()
    else:
        _reject()
    return deepcopy(manifest)


def advance_projection_manifest(
    manifest_value: Mapping[str, Any],
    page_value: Mapping[str, Any],
    *,
    withdrawal_epoch: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = validate_projection_manifest(manifest_value)
    page = validate_projection_page(page_value)
    if not _positive_int(withdrawal_epoch):
        _reject()
    if manifest["state"] not in {"live", "withdrawing"}:
        _reject()
    if (
        manifest["state"] == "withdrawing"
        and manifest["withdrawalEpoch"] != withdrawal_epoch
    ):
        _reject()
    if (
        page["manifestId"] != manifest["manifestId"]
        or page["pageId"] != manifest["headPageId"]
        or manifest["remainingPageCount"] < 1
        or manifest["livePointerCount"] < page["pointerCount"]
    ):
        _reject()
    next_page_id = page["nextPageId"]
    last_page = manifest["remainingPageCount"] == 1
    if last_page:
        if next_page_id or manifest["livePointerCount"] != page["pointerCount"]:
            _reject()
    elif not next_page_id or manifest["livePointerCount"] == page["pointerCount"]:
        _reject()

    updated = deepcopy(manifest)
    updated["withdrawalEpoch"] = withdrawal_epoch
    updated["headPageId"] = next_page_id
    updated["remainingPageCount"] -= 1
    updated["livePointerCount"] -= page["pointerCount"]
    updated["completedBatches"] += 1
    updated["stateRevision"] += 1
    updated["state"] = "withdrawn" if last_page else "withdrawing"
    updated = validate_projection_manifest(updated)

    consumed_page = deepcopy(page)
    consumed_page["state"] = "consumed"
    consumed_page["withdrawalEpoch"] = withdrawal_epoch
    consumed_page["consumedBatch"] = updated["completedBatches"]
    return updated, consumed_page


def complete_empty_projection_manifest(
    manifest_value: Mapping[str, Any], *, withdrawal_epoch: int
) -> dict[str, Any]:
    manifest = validate_projection_manifest(manifest_value)
    if (
        manifest["state"] != "live"
        or manifest["initialPointerCount"] != 0
        or not _positive_int(withdrawal_epoch)
    ):
        _reject()
    updated = deepcopy(manifest)
    updated["withdrawalEpoch"] = withdrawal_epoch
    updated["state"] = "withdrawn"
    updated["completedBatches"] = 1
    updated["stateRevision"] = 2
    return validate_projection_manifest(updated)


__all__ = [
    "DOMAIN",
    "ENVIRONMENT",
    "GLOBAL_INVALIDATION_PATHS",
    "HUB_ID",
    "MANIFEST_PK",
    "MANIFEST_SK",
    "MAX_POINTERS_PER_PAGE",
    "ProjectionManifestError",
    "advance_projection_manifest",
    "complete_empty_projection_manifest",
    "seal_projection_manifest",
    "seal_projection_page",
    "validate_projection_manifest",
    "validate_projection_page",
    "validate_projection_pointer",
]
