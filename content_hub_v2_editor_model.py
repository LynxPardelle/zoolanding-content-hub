"""Fixed bilingual article packages and deterministic, allowlisted Delta HTML.

Independent of v1. HTML is generated here, never accepted from the browser.
Storage paths and public media resolution are supplied only by trusted stores.
"""
from __future__ import annotations

from copy import deepcopy
from html import escape
import json
import re
import unicodedata
from urllib.parse import urlsplit

LOCALES = ("en", "es")
SERIES = {
    "form-movement": {"en": ("Form & Movement", "form-and-movement"), "es": ("Forma y movimiento", "forma-y-movimiento")},
    "observation-process": {"en": ("Observation & Process", "observation-and-process"), "es": ("Observación y proceso", "observacion-y-proceso")},
    "bridal-forms": {"en": ("Bridal Forms", "bridal-forms"), "es": ("Formas nupciales", "formas-nupciales")},
}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
PACKAGE_FIELDS = {"title", "summary", "seriesId", "tags", "cover", "delta"}
MAX_PACKAGE_BYTES = 524288


class EditorValidationError(ValueError):
    def __init__(self, code="invalid_package"):
        self.code = code
        super().__init__(code)


class EditorConflict(RuntimeError):
    pass


class EditorNotFound(RuntimeError):
    pass


def safe_id(value):
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise EditorValidationError("invalid_id")
    return value


def safe_locale(value):
    if value not in LOCALES:
        raise EditorValidationError("invalid_locale")
    return value


def text(value, limit):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise EditorValidationError()
    return value


def safe_link(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 for c in value) or "\\" in value:
        raise EditorValidationError("invalid_link")
    try:
        parsed = urlsplit(value)
        if value.startswith("/") and not value.startswith("//") and not parsed.netloc:
            return value
        if parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password:
            return value
        if parsed.scheme == "mailto" and parsed.path and not parsed.netloc:
            return value
    except ValueError:
        pass
    raise EditorValidationError("invalid_link")


def _delta(value):
    if not isinstance(value, dict) or set(value) != {"ops"} or not isinstance(value["ops"], list) or not 1 <= len(value["ops"]) <= 1000:
        raise EditorValidationError("invalid_delta")
    images = []
    for op in value["ops"]:
        if not isinstance(op, dict) or not {"insert"} <= set(op) <= {"insert", "attributes"}:
            raise EditorValidationError("invalid_delta")
        attrs = op.get("attributes", {})
        if not isinstance(attrs, dict) or not set(attrs) <= {"bold", "italic", "link", "header", "list", "blockquote"}:
            raise EditorValidationError("invalid_delta")
        for key in ("bold", "italic", "blockquote"):
            if key in attrs and attrs[key] is not True:
                raise EditorValidationError("invalid_delta")
        if "header" in attrs and (type(attrs["header"]) is not int or attrs["header"] not in (2, 3)):
            raise EditorValidationError("invalid_delta")
        if "list" in attrs and attrs["list"] not in ("ordered", "bullet"):
            raise EditorValidationError("invalid_delta")
        block_keys = set(attrs) & {"header", "list", "blockquote"}
        if len(block_keys) > 1:
            raise EditorValidationError("invalid_delta")
        if "link" in attrs:
            safe_link(attrs["link"])
        inserted = op["insert"]
        if isinstance(inserted, str):
            text(inserted, MAX_PACKAGE_BYTES)
            if block_keys and inserted.strip("\n"):
                raise EditorValidationError("invalid_delta")
        elif isinstance(inserted, dict) and set(inserted) == {"image"} and not attrs:
            images.append(safe_id(inserted["image"]))
        else:
            raise EditorValidationError("invalid_delta")
    if len(images) > 20:
        raise EditorValidationError("too_many_images")
    return deepcopy(value)


def normalize_package(value):
    if not isinstance(value, dict) or not set(value) <= PACKAGE_FIELDS:
        raise EditorValidationError()
    try:
        if len(json.dumps(value, ensure_ascii=False).encode()) > MAX_PACKAGE_BYTES:
            raise EditorValidationError("package_too_large")
    except (TypeError, ValueError, RecursionError):
        raise EditorValidationError() from None
    series = value.get("seriesId", "form-movement")
    if not isinstance(series, str) or series not in SERIES:
        raise EditorValidationError("invalid_series")
    tags = value.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 12:
        raise EditorValidationError("invalid_tags")
    tags = list(dict.fromkeys(text(tag, 40).strip() for tag in tags if tag != ""))
    cover = value.get("cover")
    if cover is not None:
        if not isinstance(cover, dict) or set(cover) != {"assetId", "alt", "focalX", "focalY"}:
            raise EditorValidationError("invalid_cover")
        safe_id(cover["assetId"])
        text(cover["alt"], 240)
        if any(type(cover[k]) is not int or not 0 <= cover[k] <= 100 for k in ("focalX", "focalY")):
            raise EditorValidationError("invalid_cover")
    return {"title": text(value.get("title", ""), 160), "summary": text(value.get("summary", ""), 480),
            "seriesId": series, "tags": tags, "cover": deepcopy(cover),
            "delta": _delta(value.get("delta", {"ops": [{"insert": "\n"}]}))}


def referenced_assets(package):
    result = [op["insert"]["image"] for op in package["delta"]["ops"] if isinstance(op["insert"], dict)]
    if package["cover"]:
        result.insert(0, package["cover"]["assetId"])
    return tuple(dict.fromkeys(result))


def publication_errors(value, assets):
    package = normalize_package(value)
    errors = []
    for field in ("title", "summary"):
        if not package[field].strip():
            errors.append(f"{field}_required")
    if not any(isinstance(op["insert"], str) and op["insert"].strip() for op in package["delta"]["ops"]):
        errors.append("body_required")
    cover = package["cover"]
    if not cover:
        errors.append("cover_required")
    elif not cover["alt"].strip():
        errors.append("cover_alt_required")
    if cover and assets.get(cover["assetId"], {}).get("status") != "ready":
        errors.append("cover_not_ready")
    if any(assets.get(asset_id, {}).get("status") != "ready" for asset_id in referenced_assets(package)):
        errors.append("media_not_ready")
    return errors


def compile_delta(value, media, *, private_preview=False):
    delta = _delta(value)
    result, line = [], []
    list_tag = None

    def close_list():
        nonlocal list_tag
        if list_tag:
            result.append(f"</{list_tag}>")
            list_tag = None

    def flush(attrs):
        nonlocal list_tag
        content = "".join(line)
        line.clear()
        kind = attrs.get("list")
        if kind:
            tag = "ol" if kind == "ordered" else "ul"
            if tag != list_tag:
                close_list()
                result.append(f"<{tag}>")
                list_tag = tag
            result.append(f"<li>{content}</li>")
        else:
            close_list()
            tag = f"h{attrs['header']}" if "header" in attrs else "blockquote" if attrs.get("blockquote") else "p"
            result.append(f"<{tag}>{content}</{tag}>")

    for op in delta["ops"]:
        inserted, attrs = op["insert"], op.get("attributes", {})
        if isinstance(inserted, dict):
            if line:
                flush({})
            close_list()
            item = media.get(inserted["image"])
            if private_preview:
                if not isinstance(item, dict) or item.get("status") != "ready":
                    raise EditorValidationError("media_not_ready")
                asset_id = safe_id(inserted["image"])
                alt = escape(text(item.get("alt", ""), 240), quote=True)
                # Hydration uses one authorized assetList POST per image. There is
                # deliberately no src/GET URL until the browser owns a Blob URL.
                result.append(f'<figure><img data-private-asset="{asset_id}" alt="{alt}"></figure>')
                continue
            if not isinstance(item, dict) or not isinstance(item.get("src"), str) or not item["src"].startswith("/features/content-hub-v2/"):
                raise EditorValidationError("media_not_ready")
            source = safe_link(item["src"])
            result.append(f'<figure><img src="{escape(source, quote=True)}" alt="{escape(text(item.get("alt", ""), 240), quote=True)}" loading="lazy"></figure>')
            continue
        parts = inserted.split("\n")
        for index, part in enumerate(parts):
            if part:
                fragment = escape(part, quote=True)
                for key, tag in (("bold", "strong"), ("italic", "em")):
                    if attrs.get(key):
                        fragment = f"<{tag}>{fragment}</{tag}>"
                if "link" in attrs:
                    fragment = f'<a href="{escape(safe_link(attrs["link"]), quote=True)}">{fragment}</a>'
                line.append(fragment)
            if index < len(parts) - 1:
                flush(attrs)
    if line:
        flush({})
    close_list()
    return "".join(result)


def slugify(title):
    ascii_title = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", "-", ascii_title).strip("-")[:100].rstrip("-") or "article"


def article_path(locale, series_id, title, ordinal=1):
    safe_locale(locale)
    if series_id not in SERIES or type(ordinal) is not int or not 1 <= ordinal <= 10000:
        raise EditorValidationError("invalid_path")
    suffix = "" if ordinal == 1 else f"-{ordinal}"
    return f"/the-journal/{SERIES[series_id][locale][1]}/{slugify(title)}{suffix}"


def locale_state(locale):
    if locale.get("publishedRevisionId"):
        return "published" if locale.get("workingRevisionId") == locale["publishedRevisionId"] else "updates-pending"
    return "unpublished" if locale.get("firstPublishedAt") else "draft"
