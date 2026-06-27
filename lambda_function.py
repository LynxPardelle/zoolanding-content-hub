import base64
import hashlib
import hmac
import json
import os
import re
import time
from decimal import Decimal
from typing import Any, Optional


SESSION_COOKIE_NAME = "__Host-zlp_session"
DEFAULT_CSRF_COOKIE_NAME = "zlp_csrf"
DEFAULT_CSRF_HEADER_NAME = "x-zlp-csrf"
DOMAIN_HEADER = "x-zlp-domain"
AUTH_PROFILE_HEADER = "x-zlp-auth-profile-id"
HUB_HEADER = "x-zlp-content-hub-id"
CONFIG_ENV_BASE64 = "CONTENT_HUB_CONFIG_JSON_BASE64"
CONFIG_ENV_JSON = "CONTENT_HUB_CONFIG_JSON"
ENVIRONMENT_ENV = "CONTENT_HUB_ENVIRONMENT"
AUTH_SESSION_TABLE_ENV = "AUTH_SESSION_TABLE_NAME"
AUTH_USER_STATE_TABLE_ENV = "AUTH_USER_STATE_TABLE_NAME"
METADATA_TABLE_ENV = "CONTENT_HUB_METADATA_TABLE_NAME"
MEDIA_TABLE_ENV = "CONTENT_HUB_MEDIA_TABLE_NAME"
MODERATION_TABLE_ENV = "CONTENT_HUB_MODERATION_TABLE_NAME"
INTERACTIONS_TABLE_ENV = "CONTENT_HUB_INTERACTIONS_TABLE_NAME"
PACKAGES_BUCKET_ENV = "CONTENT_HUB_PACKAGES_BUCKET_NAME"

SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DOMAIN_RE = re.compile(r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
LOCALE_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]{2,8})?$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SECRET_KEY_RE = re.compile(
    r"(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|credential[_-]?ref|"
    r"secret[_-]?ref|private[_-]?key|server[_-]?policy|table[_-]?name|bucket[_-]?name|"
    r"lambda[_-]?arn|groups[_-]?to[_-]?roles|authorization[_-]?decision|signed[_-]?url|"
    r"tenant[_-]?id|aws[_-]?secret|aws[_-]?access)",
    re.I,
)
CONFIG_SECRET_KEY_RE = re.compile(
    r"(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|credential[_-]?ref|"
    r"secret[_-]?ref|private[_-]?key|signed[_-]?url|aws[_-]?secret|aws[_-]?access)",
    re.I,
)
UNSAFE_VALUE_RE = re.compile(
    r"(?:javascript:|data:|X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|"
    r"AWSAccessKeyId=|Signature=|Expires=|ssm:/|secretsmanager:/)",
    re.I,
)

READ_CAPABILITIES = {
    "articleList": "read",
    "articleDetail": "read",
    "taxonomyList": "read",
    "assetList": "read",
    "revisionList": "read",
    "publicBundlePreview": "read",
    "moderationQueue": "moderate",
}

ACTION_CAPABILITIES = {
    "createArticle": "edit",
    "upsertTaxonomy": "edit",
    "updatePackage": "edit",
    "validate": "edit",
    "submitReview": "edit",
    "restoreRevision": "edit",
    "publish": "publish",
    "schedule": "publish",
    "uploadAsset": "media",
    "queueComment": "moderate",
    "moderateComment": "moderate",
    "recordInteraction": "read",
}

PII_KEY_RE = re.compile(
    r"(?:email|e-mail|phone|telefono|tel[eé]fono|address|direccion|direcci[oó]n|"
    r"full[_-]?name|nombre|apellido|ip[_-]?address|session|cookie|user[_-]?agent)",
    re.I,
)
EMAIL_VALUE_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
PHONE_VALUE_RE = re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)")


class ContentHubError(Exception):
    status_code = 400
    public_message = "Invalid content hub request"

    def __init__(self, message: Optional[str] = None):
        super().__init__(message or self.public_message)
        if message:
            self.public_message = message


class ContentHubUnauthorized(ContentHubError):
    status_code = 401
    public_message = "Authentication required"


class ContentHubForbidden(ContentHubError):
    status_code = 403
    public_message = "Content hub access denied"


class ContentHubNotFound(ContentHubError):
    status_code = 404
    public_message = "Content hub item not found"


class ContentHubConfigError(ContentHubError):
    status_code = 500
    public_message = "Content hub config is invalid"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    if _method(event) == "OPTIONS":
        return _json_response(200, {"ok": True})

    try:
        path = _path(event)
        if _method(event) != "POST":
            raise ContentHubNotFound("Content hub route not found")
        if path == "/features/content-hub/read":
            return _read_response(event)
        if path == "/features/content-hub/action":
            return _action_response(event)
        raise ContentHubNotFound("Content hub route not found")
    except ContentHubError as exc:
        _log("WARNING" if exc.status_code < 500 else "ERROR", exc.public_message, statusCode=exc.status_code)
        return _json_response(exc.status_code, {"ok": False, "error": exc.public_message})
    except Exception as exc:
        _log("ERROR", "Unhandled content hub error", errorType=type(exc).__name__)
        return _json_response(500, {"ok": False, "error": "Content hub request failed"})


def _read_response(event: dict[str, Any]) -> dict[str, Any]:
    payload, session, profile, hub = _authorized_request(event, mutation=False)
    binding = _content_hub_binding(payload)
    read_kind = _safe_id(binding.get("read"))
    if read_kind not in READ_CAPABILITIES:
        raise ContentHubError("Unsupported content hub read")
    _require_capability(session, profile, hub, READ_CAPABILITIES[read_kind])
    data = _handle_read(read_kind, payload, binding, profile, hub)
    return _json_response(200, {"ok": True, "data": _public_payload(data)})


def _action_response(event: dict[str, Any]) -> dict[str, Any]:
    payload, session, profile, hub = _authorized_request(event, mutation=True)
    binding = _content_hub_binding(payload)
    action_kind = _safe_id(binding.get("action"))
    if action_kind not in ACTION_CAPABILITIES:
        raise ContentHubError("Unsupported content hub action")
    _require_capability(session, profile, hub, ACTION_CAPABILITIES[action_kind])
    data = _handle_action(action_kind, payload, binding, session, profile, hub)
    return _json_response(200, {"ok": True, "data": _public_payload(data)})


def _authorized_request(
    event: dict[str, Any],
    *,
    mutation: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    payload = _request_payload(event)
    _reject_unsafe_public_payload(payload)
    domain = _domain(payload.get("domain") or _header(event, DOMAIN_HEADER))
    auth_profile_id = _safe_id(_header(event, AUTH_PROFILE_HEADER))
    if domain != _domain(_header(event, DOMAIN_HEADER)):
        raise ContentHubUnauthorized()
    profile = _profile_for(domain, auth_profile_id)
    session = _require_session(event, profile)
    if mutation:
        _require_csrf(event, session, profile)
    if payload.get("domain") != session.get("domain") or auth_profile_id != session.get("authProfileId"):
        raise ContentHubUnauthorized()
    binding = _content_hub_binding(payload)
    hub_id = _safe_id(binding.get("hubId") or _header(event, HUB_HEADER))
    if _header(event, HUB_HEADER) and _safe_id(_header(event, HUB_HEADER)) != hub_id:
        raise ContentHubForbidden("Content hub id does not match")
    hub = _hub_for(profile, hub_id)
    return payload, session, profile, hub


def _handle_read(
    read_kind: str,
    payload: dict[str, Any],
    binding: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    store = _store()
    hub_id = hub["hubId"]
    if read_kind == "articleList":
        return {"items": [_article_summary(item) for item in store.query_metadata(f"HUB#{hub_id}", "ARTICLE#")]}
    if read_kind == "articleDetail":
        article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
        if not article_id:
            raise ContentHubError("articleId is required")
        article = store.get_metadata(f"HUB#{hub_id}", f"ARTICLE#{article_id}")
        if not article:
            raise ContentHubNotFound()
        return {"item": _article_summary(article)}
    if read_kind == "taxonomyList":
        taxonomy_kind = _clean_string(binding.get("taxonomyKind") or _input_field(payload, "taxonomyKind"))
        sk_prefix = f"TAXONOMY#{taxonomy_kind}#" if taxonomy_kind in {"category", "tag"} else "TAXONOMY#"
        items = [_taxonomy_summary(item) for item in store.query_metadata(f"HUB#{hub_id}", sk_prefix)]
        return {
            "items": items,
            "categories": [item for item in items if item.get("kind") == "category"],
            "tags": [item for item in items if item.get("kind") == "tag"],
        }
    if read_kind == "assetList":
        return {"items": [_asset_summary(item) for item in store.query_media(f"HUB#{hub_id}", "ASSET#")]}
    if read_kind == "revisionList":
        article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
        return {"items": [_revision_summary(item) for item in store.query_metadata(f"ARTICLE#{article_id}", "REVISION#")]}
    if read_kind == "moderationQueue":
        return {"items": [_moderation_summary(item) for item in store.query_moderation(f"HUB#{hub_id}", "MODERATION#")]}
    if read_kind == "publicBundlePreview":
        article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
        revision_value = binding.get("revisionId") or _input_field(payload, "revisionId")
        if not _clean_string(revision_value):
            article = store.get_metadata(f"HUB#{hub_id}", f"ARTICLE#{article_id}")
            if not article:
                raise ContentHubNotFound()
            revision_value = article.get("latestRevisionId")
        revision_id = _safe_id(revision_value)
        locale = _locale(binding.get("language") or _input_field(payload, "language") or hub.get("defaultLocale") or "es")
        render_domain = _domain(_input_field(payload, "renderDomain") or profile["domain"])
        key = _published_bundle_key(profile, hub_id, render_domain, locale, article_id, revision_id)
        return {"bundle": store.get_json(key)}
    raise ContentHubError("Unsupported content hub read")


def _handle_action(
    action_kind: str,
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    if action_kind == "createArticle":
        return _create_article(payload, session, profile, hub)
    if action_kind == "upsertTaxonomy":
        return _upsert_taxonomy(payload, binding, session, profile, hub)
    if action_kind == "updatePackage":
        return _update_package(payload, binding, session, profile, hub)
    if action_kind == "validate":
        return _validate_article(payload, binding, profile, hub)
    if action_kind == "submitReview":
        return _set_article_status(payload, binding, session, profile, hub, "review")
    if action_kind == "publish":
        return _publish_article(payload, binding, session, profile, hub)
    if action_kind == "schedule":
        return _schedule_article(payload, binding, session, profile, hub)
    if action_kind == "uploadAsset":
        return _upload_asset(payload, session, profile, hub)
    if action_kind == "queueComment":
        return _queue_comment(payload, binding, session, profile, hub)
    if action_kind == "moderateComment":
        return _moderate_comment(payload, binding, session, profile, hub)
    if action_kind == "recordInteraction":
        return _record_interaction(payload, binding, session, profile, hub)
    if action_kind == "restoreRevision":
        return _restore_revision(payload, binding, session, profile, hub)
    raise ContentHubError("Unsupported content hub action")


def _create_article(payload: dict[str, Any], session: dict[str, Any], profile: dict[str, Any], hub: dict[str, Any]) -> dict[str, Any]:
    title = _safe_text(_input_field(payload, "title") or _input_field(payload, "name") or "Nuevo artículo", max_length=160)
    locale = _locale(_input_field(payload, "language") or hub.get("defaultLocale") or "es")
    slug = _slug(_input_field(payload, "slug") or title)
    article_id = _safe_id(_input_field(payload, "articleId") or f"art_{int(time.time())}_{slug[:40]}")
    revision_id = _safe_id(_input_field(payload, "revisionId") or "rev_001")
    now = _now_iso()
    summary = _safe_text(_input_field(payload, "summary") or "", max_length=320)
    visibility = _visibility(_input_field(payload, "visibility") or "public")
    article = {
        "pk": f"HUB#{hub['hubId']}",
        "sk": f"ARTICLE#{article_id}",
        "itemFamily": "ARTICLE",
        "hubId": hub["hubId"],
        "articleId": article_id,
        "ownerDraftDomain": hub["ownerDraftDomain"],
        "originDraftDomain": profile["domain"],
        "status": "draft",
        "visibility": visibility,
        "title": title,
        "summary": summary,
        "slug": slug,
        "seoTitle": _safe_text(_input_field(payload, "seoTitle") or title, max_length=160),
        "seoDescription": _safe_text(_input_field(payload, "seoDescription") or summary, max_length=320),
        "robots": _robots_policy(_input_field(payload, "robots") or "index,follow"),
        "category": _taxonomy_ref(_input_field(payload, "category")),
        "tags": _taxonomy_refs(_input_field(payload, "tags")),
        "commentPolicy": _comment_policy(_input_field(payload, "commentPolicy") or "moderated"),
        "contentSafety": _content_safety(payload),
        "canonicalMode": _canonical_mode(_input_field(payload, "canonicalMode") or "self"),
        "canonicalUrl": _safe_canonical_url(_input_field(payload, "canonicalUrl") or ""),
        "primaryLocale": locale,
        "latestRevisionId": revision_id,
        "createdAt": now,
        "updatedAt": now,
        "updatedBy": session["subject"],
    }
    revision = _revision_item(hub["hubId"], article_id, revision_id, locale, now, session["subject"])
    package = _article_package(article, revision, payload, profile, hub)
    store = _store()
    store.put_metadata(article)
    store.put_metadata(revision)
    store.put_json(revision["packageKey"], package)
    return {"article": _article_summary(article), "revision": _revision_summary(revision)}


def _upsert_taxonomy(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    del profile
    kind = _safe_id(binding.get("taxonomyKind") or _input_field(payload, "taxonomyKind") or _input_field(payload, "kind"))
    if kind not in {"category", "tag"}:
        raise ContentHubError("Invalid taxonomy kind")
    label = _safe_text(_input_field(payload, "label") or _input_field(payload, "name") or kind, max_length=120)
    slug = _slug(_input_field(payload, "slug") or label)
    taxonomy_id = _safe_id(_input_field(payload, "taxonomyId") or f"{kind}_{slug}")
    now = _now_iso()
    existing = _store().get_metadata(f"HUB#{hub['hubId']}", f"TAXONOMY#{kind}#{taxonomy_id}") or {}
    item = {
        "pk": f"HUB#{hub['hubId']}",
        "sk": f"TAXONOMY#{kind}#{taxonomy_id}",
        "itemFamily": "TAXONOMY",
        "hubId": hub["hubId"],
        "taxonomyId": taxonomy_id,
        "kind": kind,
        "slug": slug,
        "label": label,
        "description": _safe_text(_input_field(payload, "description") or "", max_length=320),
        "locale": _locale(_input_field(payload, "language") or hub.get("defaultLocale") or "es"),
        "seoTitle": _safe_text(_input_field(payload, "seoTitle") or label, max_length=160),
        "seoDescription": _safe_text(_input_field(payload, "seoDescription") or "", max_length=320),
        "parentId": _optional_safe_id(_input_field(payload, "parentId")),
        "visible": _safe_bool(_input_field(payload, "visible"), default=True),
        "createdAt": existing.get("createdAt") or now,
        "updatedAt": now,
        "updatedBy": session["subject"],
    }
    _store().put_metadata(item)
    return {"taxonomy": _taxonomy_summary(item)}


def _update_package(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
    locale = _locale(binding.get("language") or _input_field(payload, "language") or hub.get("defaultLocale") or "es")
    revision_id = _safe_id(_input_field(payload, "revisionId") or f"rev_{int(time.time())}")
    now = _now_iso()
    revision = _revision_item(hub["hubId"], article_id, revision_id, locale, now, session["subject"])
    package = {
        "version": 1,
        "kind": "content-hub-article-package",
        "hubId": hub["hubId"],
        "articleId": article_id,
        "locale": locale,
        "revisionId": revision_id,
        "components": _safe_json_node(_input_field(payload, "components") or []),
        "variables": _safe_json_node(_input_field(payload, "variables") or {}),
        "i18n": _safe_json_node(_input_field(payload, "i18n") or {}),
        "updatedAt": now,
    }
    metadata_updates = _article_metadata_updates(payload)
    store = _store()
    store.put_metadata(revision)
    store.put_json(revision["packageKey"], package)
    store.update_metadata(f"HUB#{hub['hubId']}", f"ARTICLE#{article_id}", {
        "latestRevisionId": revision_id,
        "status": "draft",
        "updatedAt": now,
        "updatedBy": session["subject"],
        **metadata_updates,
    })
    return {"revision": _revision_summary(revision)}


def _validate_article(payload: dict[str, Any], binding: dict[str, Any], profile: dict[str, Any], hub: dict[str, Any]) -> dict[str, Any]:
    del profile
    article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
    article = _store().get_metadata(f"HUB#{hub['hubId']}", f"ARTICLE#{article_id}")
    if not article:
        raise ContentHubNotFound()
    issues = []
    if not _clean_string(article.get("title")):
        issues.append({"severity": "error", "code": "missing-title", "message": "El artículo necesita título."})
    if not _clean_string(article.get("summary")):
        issues.append({"severity": "warning", "code": "missing-summary", "message": "Agrega una descripción para SEO."})
    return {
        "valid": not any(issue["severity"] == "error" for issue in issues),
        "articleId": article_id,
        "issues": issues,
    }


def _publish_article(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
    locale = _locale(binding.get("language") or _input_field(payload, "language") or hub.get("defaultLocale") or "es")
    render_domain = _domain(_input_field(payload, "renderDomain") or profile["domain"])
    store = _store()
    article = store.get_metadata(f"HUB#{hub['hubId']}", f"ARTICLE#{article_id}")
    if not article:
        raise ContentHubNotFound()
    revision_id = _safe_id(binding.get("revisionId") or _input_field(payload, "revisionId") or article.get("latestRevisionId"))
    revision = store.get_metadata(f"ARTICLE#{article_id}", f"REVISION#{revision_id}")
    if not revision:
        raise ContentHubNotFound("Revision not found")
    package = store.get_json(revision["packageKey"])
    path = _article_path(_input_field(payload, "path") or f"/blog/{_slug(article.get('title') or article_id)}")
    canonical_mode = _canonical_mode(_input_field(payload, "canonicalMode") or article.get("canonicalMode") or "self")
    canonical_url = _safe_canonical_url(_input_field(payload, "canonicalUrl") or article.get("canonicalUrl") or "")
    now = _now_iso()
    bundle = {
        "version": 1,
        "bundleId": f"{article_id}:{revision_id}:{render_domain}:{locale}",
        "hubId": hub["hubId"],
        "articleId": article_id,
        "ownerDraftDomain": hub["ownerDraftDomain"],
        "renderDomain": render_domain,
        "locale": locale,
        "path": path,
        "safeArticlePath": path,
        "status": "published",
        "publishedAt": now,
        "title": article.get("title"),
        "summary": article.get("summary"),
        "slug": article.get("slug") or _slug(article.get("title") or article_id),
        "category": _taxonomy_ref(article.get("category")),
        "tags": _taxonomy_refs(article.get("tags")),
        "commentPolicy": _comment_policy(article.get("commentPolicy") or "moderated"),
        "contentSafety": _content_safety_from_value(article.get("contentSafety")),
        "seo": {
            "title": _safe_text(_input_field(payload, "seoTitle") or article.get("seoTitle") or article.get("title") or article_id, max_length=160),
            "description": _safe_text(_input_field(payload, "seoDescription") or article.get("seoDescription") or article.get("summary") or "", max_length=320),
            "canonical": _canonical_for_publish(canonical_mode, canonical_url, path),
            "canonicalMode": canonical_mode,
            "robots": _robots_policy(_input_field(payload, "robots") or article.get("robots") or "index,follow"),
        },
        "structuredData": [],
        "components": package.get("components") if isinstance(package, dict) else [],
        "variables": package.get("variables") if isinstance(package, dict) else {},
        "i18n": package.get("i18n") if isinstance(package, dict) else {},
        "analytics": _analytics_context(hub),
    }
    key = _published_bundle_key(profile, hub["hubId"], render_domain, locale, article_id, revision_id)
    store.put_json(key, bundle)
    store.update_metadata(f"HUB#{hub['hubId']}", f"ARTICLE#{article_id}", {
        "status": "published",
        "publishedAt": now,
        "latestRevisionId": revision_id,
        "path": path,
        "canonicalMode": canonical_mode,
        "canonicalUrl": canonical_url,
        "updatedAt": now,
        "updatedBy": session["subject"],
    })
    store.put_metadata({
        "pk": f"SLUG#{profile['environment']}#{render_domain}#{locale}",
        "sk": f"PATH#{path}",
        "itemFamily": "SLUG",
        "hubId": hub["hubId"],
        "articleId": article_id,
        "revisionId": revision_id,
        "path": path,
        "publishedBundleKey": key,
        "updatedAt": now,
    })
    return {"articleId": article_id, "revisionId": revision_id, "path": path, "publishedAt": now}


def _schedule_article(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
    revision_id = _safe_id(binding.get("revisionId") or _input_field(payload, "revisionId"))
    scheduled_at = _safe_text(_input_field(payload, "scheduledAt") or _input_field(payload, "publishAt"), max_length=40)
    if not scheduled_at or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})", scheduled_at):
        raise ContentHubError("Invalid schedule time")
    schedule_id = _safe_id(_input_field(payload, "scheduleId") or f"sch_{hashlib.sha256(f'{article_id}:{revision_id}:{scheduled_at}'.encode()).hexdigest()[:16]}")
    item = {
        "pk": f"SCHEDULE#{profile['environment']}",
        "sk": f"DUE#{scheduled_at}#ARTICLE#{article_id}#REVISION#{revision_id}",
        "itemFamily": "SCHEDULE",
        "scheduleId": schedule_id,
        "hubId": hub["hubId"],
        "articleId": article_id,
        "revisionId": revision_id,
        "action": _safe_id(_input_field(payload, "scheduleAction") or "publish"),
        "scheduledAt": scheduled_at,
        "createdBy": session["subject"],
        "createdAt": _now_iso(),
    }
    _store().put_metadata(item)
    return {"schedule": _schedule_summary(item)}


def _upload_asset(payload: dict[str, Any], session: dict[str, Any], profile: dict[str, Any], hub: dict[str, Any]) -> dict[str, Any]:
    del profile
    file_name = _safe_filename(_input_field(payload, "fileName") or "asset.bin")
    mime_type = _safe_text(_input_field(payload, "mimeType") or "application/octet-stream", max_length=120)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,80}/[A-Za-z0-9][A-Za-z0-9.+-]{0,80}", mime_type):
        raise ContentHubError("Invalid asset MIME type")
    asset_id = _safe_id(_input_field(payload, "assetId") or f"asset_{int(time.time())}_{hashlib.sha256(file_name.encode()).hexdigest()[:8]}")
    public_url = _safe_public_url(_input_field(payload, "publicUrl") or "")
    body_b64 = _clean_string(_input_field(payload, "base64"))
    key = f"content-hubs/{os.getenv(ENVIRONMENT_ENV, 'dev')}/{hub['hubId']}/assets/{asset_id}/original/{file_name}"
    if body_b64:
        try:
            content = base64.b64decode(body_b64, validate=True)
        except Exception as exc:
            raise ContentHubError("Invalid asset payload") from exc
        if len(content) > int(hub.get("maxUploadBytes") or 5_000_000):
            raise ContentHubError("Asset is too large")
        _store().put_bytes(key, content, mime_type)
    item = {
        "pk": f"HUB#{hub['hubId']}",
        "sk": f"ASSET#{asset_id}",
        "itemFamily": "ASSET",
        "hubId": hub["hubId"],
        "assetId": asset_id,
        "kind": _asset_kind(mime_type),
        "fileName": file_name,
        "mimeType": mime_type,
        "bytes": int(_input_field(payload, "bytes") or 0),
        "publicUrl": public_url,
        "title": _safe_text(_input_field(payload, "title") or "", max_length=160),
        "alt": _safe_text(_input_field(payload, "alt") or "", max_length=240),
        "objectKey": key if body_b64 else "",
        "createdBy": session["subject"],
        "createdAt": _now_iso(),
    }
    _store().put_media(item)
    return {"asset": _asset_summary(item)}


def _queue_comment(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    del profile
    article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
    text = _safe_text(_input_field(payload, "commentText") or _input_field(payload, "body") or "", max_length=2000)
    if not text:
        raise ContentHubError("Comment text is required")
    now = _now_iso()
    comment_seed = f"{article_id}:{now}:{session['subject']}"
    comment_id = _safe_id(_input_field(payload, "commentId") or f"cmt_{hashlib.sha256(comment_seed.encode()).hexdigest()[:16]}")
    item = {
        "pk": f"HUB#{hub['hubId']}",
        "sk": f"MODERATION#queued#{now}#{comment_id}",
        "itemFamily": "MODERATION",
        "hubId": hub["hubId"],
        "articleId": article_id,
        "commentId": comment_id,
        "status": "queued",
        "bodyPreview": _redacted_preview(text, 240),
        "bodyHash": _sha256(text),
        "createdByHash": _sha256(session["subject"]),
        "queuedAt": now,
    }
    _store().put_moderation(item)
    return {"comment": _moderation_summary(item)}


def _moderate_comment(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    del profile
    comment_id = _safe_id(binding.get("commentId") or _input_field(payload, "commentId"))
    status = _safe_id(_input_field(payload, "moderationStatus") or "approved")
    if status not in {"approved", "rejected", "spam", "queued"}:
        raise ContentHubError("Invalid moderation status")
    item = {
        "pk": f"HUB#{hub['hubId']}",
        "sk": f"MODERATION#{status}#{_now_iso()}#{comment_id}",
        "itemFamily": "MODERATION",
        "hubId": hub["hubId"],
        "commentId": comment_id,
        "status": status,
        "moderatedBy": session["subject"],
        "moderatedAt": _now_iso(),
    }
    _store().put_moderation(item)
    return {"moderation": _moderation_summary(item)}


def _record_interaction(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    del profile
    event_type = _safe_id(_input_field(payload, "eventType") or _input_field(payload, "interactionType") or "reaction")
    if event_type not in {"reaction", "like", "cta", "form"}:
        raise ContentHubError("Invalid interaction type")
    article_id_value = binding.get("articleId") or _input_field(payload, "articleId")
    article_id = _optional_safe_id(article_id_value)
    now = _now_iso()
    interaction_seed = f"{event_type}:{now}:{session['subject']}"
    interaction_id = _safe_id(_input_field(payload, "interactionId") or f"evt_{hashlib.sha256(interaction_seed.encode()).hexdigest()[:16]}")
    item = {
        "pk": f"HUB#{hub['hubId']}",
        "sk": f"INTERACTION#{event_type}#{now}#{interaction_id}",
        "itemFamily": "INTERACTION",
        "hubId": hub["hubId"],
        "interactionId": interaction_id,
        "eventType": event_type,
        "articleId": article_id,
        "targetId": _optional_safe_id(_input_field(payload, "targetId")),
        "value": _safe_text(_input_field(payload, "value") or "", max_length=120),
        "path": _optional_article_path(_input_field(payload, "path")),
        "metadata": _safe_event_metadata(_input_field(payload, "metadata") or {}),
        "actorHash": _sha256(session["subject"]),
        "createdAt": now,
    }
    _store().put_interaction(item)
    return {"interaction": _interaction_summary(item)}


def _restore_revision(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    del profile
    article_id = _safe_id(binding.get("articleId") or _input_field(payload, "articleId"))
    revision_id = _safe_id(binding.get("revisionId") or _input_field(payload, "revisionId"))
    if not _store().get_metadata(f"ARTICLE#{article_id}", f"REVISION#{revision_id}"):
        raise ContentHubNotFound("Revision not found")
    _store().update_metadata(f"HUB#{hub['hubId']}", f"ARTICLE#{article_id}", {
        "latestRevisionId": revision_id,
        "status": "draft",
        "updatedBy": session["subject"],
        "updatedAt": _now_iso(),
    })
    return {"articleId": article_id, "revisionId": revision_id, "status": "draft"}


def _set_article_status(
    payload: dict[str, Any],
    binding: dict[str, Any],
    session: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    del payload, profile
    article_id = _safe_id(binding.get("articleId"))
    _store().update_metadata(f"HUB#{hub['hubId']}", f"ARTICLE#{article_id}", {
        "status": status,
        "updatedBy": session["subject"],
        "updatedAt": _now_iso(),
    })
    return {"articleId": article_id, "status": status}


_CONFIG_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def load_config() -> dict[str, Any]:
    raw = os.getenv(CONFIG_ENV_JSON)
    if not raw:
        encoded = os.getenv(CONFIG_ENV_BASE64, "")
        if encoded:
            raw = base64.b64decode(encoded).decode("utf-8")
    if not raw:
        raise ContentHubConfigError("Content hub config is required")
    cache_key = (raw, os.getenv(ENVIRONMENT_ENV, "dev"))
    cached = _CONFIG_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        config = json.loads(raw)
    except Exception as exc:
        raise ContentHubConfigError("Content hub config must be valid JSON") from exc
    _reject_secret_like_config(config)
    if config.get("version") != 1 or not isinstance(config.get("profiles"), list):
        raise ContentHubConfigError("Content hub config version/profiles are invalid")
    profiles = [_normalize_profile(profile) for profile in config["profiles"]]
    normalized = {"version": 1, "profiles": profiles}
    _CONFIG_CACHE.clear()
    _CONFIG_CACHE[cache_key] = normalized
    return normalized


def _normalize_profile(profile: Any) -> dict[str, Any]:
    if not isinstance(profile, dict):
        raise ContentHubConfigError("Content hub profile must be an object")
    normalized = {
        "enabled": profile.get("enabled", True) is True,
        "environment": _safe_id(profile.get("environment") or os.getenv(ENVIRONMENT_ENV, "dev")),
        "domain": _domain(profile.get("domain")),
        "authProfileId": _safe_id(profile.get("authProfileId")),
        "tenantId": _safe_id(profile.get("tenantId") or "tenant"),
        "adminGroups": _string_list(profile.get("adminGroups")),
        "contentHubs": [],
        "session": profile.get("session") if isinstance(profile.get("session"), dict) else {},
    }
    if normalized["environment"] not in {"dev", "test", "prod"}:
        raise ContentHubConfigError("Invalid profile environment")
    if not normalized["adminGroups"]:
        raise ContentHubConfigError("Profile requires adminGroups")
    hubs = profile.get("contentHubs")
    if not isinstance(hubs, list) or not hubs:
        raise ContentHubConfigError("Profile requires contentHubs")
    for hub in hubs:
        if not isinstance(hub, dict):
            raise ContentHubConfigError("Content hub policy must be an object")
        normalized["contentHubs"].append(_normalize_hub(hub, normalized["adminGroups"], normalized["domain"]))
    return normalized


def _normalize_hub(hub: dict[str, Any], admin_groups: list[str], domain: str) -> dict[str, Any]:
    roles = hub.get("roles") if isinstance(hub.get("roles"), dict) else {}
    normalized_roles = {
        capability: _string_list(roles.get(capability)) or admin_groups
        for capability in ["read", "edit", "publish", "media", "moderate"]
    }
    return {
        "hubId": _safe_id(hub.get("hubId")),
        "ownerDraftDomain": _domain(hub.get("ownerDraftDomain") or domain),
        "authorizedDraftDomains": [_domain(item) for item in _string_list(hub.get("authorizedDraftDomains") or [domain])],
        "defaultLocale": _locale(hub.get("defaultLocale") or "es"),
        "roles": normalized_roles,
        "maxUploadBytes": int(hub.get("maxUploadBytes") or 5_000_000),
        "analyticsContext": hub.get("analyticsContext") if isinstance(hub.get("analyticsContext"), dict) else {},
    }


def _profile_for(domain: str, auth_profile_id: str) -> dict[str, Any]:
    environment = os.getenv(ENVIRONMENT_ENV, "dev")
    for profile in load_config()["profiles"]:
        if (
            profile["enabled"]
            and profile["domain"] == domain
            and profile["authProfileId"] == auth_profile_id
            and profile["environment"] == environment
        ):
            return profile
    raise ContentHubUnauthorized()


def _hub_for(profile: dict[str, Any], hub_id: str) -> dict[str, Any]:
    for hub in profile["contentHubs"]:
        if hub["hubId"] == hub_id and profile["domain"] in hub["authorizedDraftDomains"]:
            return hub
    raise ContentHubForbidden("Content hub is not authorized for this draft")


def _require_session(event: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    session_value = _cookie_value(event, SESSION_COOKIE_NAME)
    if not session_value:
        raise ContentHubUnauthorized()
    store = _store()
    session = store.get_auth_session(_sha256(session_value))
    if not session or session.get("revokedAt") or int(session.get("expiresAt") or 0) <= _now_epoch():
        raise ContentHubUnauthorized()
    if session.get("tenantProfileKey") != _tenant_profile_key(profile):
        raise ContentHubUnauthorized()
    if session.get("domain") != profile["domain"] or session.get("authProfileId") != profile["authProfileId"]:
        raise ContentHubUnauthorized()
    user = store.get_auth_user(_tenant_profile_key(profile), f"USER#{_safe_id(session.get('subject'))}")
    if not user:
        raise ContentHubUnauthorized()
    if int(user.get("sessionVersion") or 1) != int(session.get("sessionVersion") or 1):
        raise ContentHubUnauthorized()
    if user.get("enabled", True) is not True or _clean_string(user.get("approvalStatus")) != "approved":
        raise ContentHubForbidden("Account is not approved")
    refreshed = dict(session)
    refreshed["roles"] = _string_list(user.get("roles") or session.get("roles"))
    refreshed["approvalStatus"] = user.get("approvalStatus")
    refreshed["enabled"] = user.get("enabled", True)
    return refreshed


def _require_csrf(event: dict[str, Any], session: dict[str, Any], profile: dict[str, Any]) -> None:
    header = _header(event, _csrf_header_name(profile))
    cookie = _cookie_value(event, _csrf_cookie_name(profile))
    if not header or not cookie or not hmac.compare_digest(header, cookie):
        raise ContentHubForbidden("CSRF validation failed")
    if not hmac.compare_digest(_sha256(header), str(session.get("csrfHash") or "")):
        raise ContentHubForbidden("CSRF validation failed")


def _require_capability(session: dict[str, Any], profile: dict[str, Any], hub: dict[str, Any], capability: str) -> None:
    allowed = set(hub["roles"].get(capability) or profile["adminGroups"])
    roles = set(_string_list(session.get("roles")))
    if not roles.intersection(allowed):
        raise ContentHubForbidden("Content hub access denied")


class DynamoContentHubStore:
    def __init__(self) -> None:
        self.auth_session_table_name = _env_required(AUTH_SESSION_TABLE_ENV)
        self.auth_user_table_name = _env_required(AUTH_USER_STATE_TABLE_ENV)
        self.metadata_table_name = _env_required(METADATA_TABLE_ENV)
        self.media_table_name = _env_required(MEDIA_TABLE_ENV)
        self.moderation_table_name = _env_required(MODERATION_TABLE_ENV)
        self.interactions_table_name = _env_required(INTERACTIONS_TABLE_ENV)
        self.packages_bucket_name = _env_required(PACKAGES_BUCKET_ENV)
        self.dynamodb = _dynamodb_resource()
        self._s3 = None
        self._tables: dict[str, Any] = {}

    def table(self, table_name: str) -> Any:
        if table_name not in self._tables:
            self._tables[table_name] = self.dynamodb.Table(table_name)
        return self._tables[table_name]

    @property
    def s3(self) -> Any:
        if self._s3 is None:
            self._s3 = _s3_client()
        return self._s3

    def get_auth_session(self, session_hash: str) -> Optional[dict[str, Any]]:
        return self.table(self.auth_session_table_name).get_item(Key={"sessionIdHash": session_hash}).get("Item")

    def get_auth_user(self, tenant_profile_key: str, user_key: str) -> Optional[dict[str, Any]]:
        return self.table(self.auth_user_table_name).get_item(
            Key={"tenantProfileKey": tenant_profile_key, "userKey": user_key}
        ).get("Item")

    def get_metadata(self, pk: str, sk: str) -> Optional[dict[str, Any]]:
        return self.table(self.metadata_table_name).get_item(Key={"pk": pk, "sk": sk}).get("Item")

    def put_metadata(self, item: dict[str, Any]) -> None:
        self.table(self.metadata_table_name).put_item(Item=_without_empty(item))

    def update_metadata(self, pk: str, sk: str, updates: dict[str, Any]) -> dict[str, Any]:
        return _update_item(self.table(self.metadata_table_name), {"pk": pk, "sk": sk}, updates)

    def query_metadata(self, pk: str, sk_prefix: str) -> list[dict[str, Any]]:
        return _query_items(self.table(self.metadata_table_name), pk, sk_prefix)

    def put_media(self, item: dict[str, Any]) -> None:
        self.table(self.media_table_name).put_item(Item=_without_empty(item))

    def query_media(self, pk: str, sk_prefix: str) -> list[dict[str, Any]]:
        return _query_items(self.table(self.media_table_name), pk, sk_prefix)

    def put_moderation(self, item: dict[str, Any]) -> None:
        self.table(self.moderation_table_name).put_item(Item=_without_empty(item))

    def query_moderation(self, pk: str, sk_prefix: str) -> list[dict[str, Any]]:
        return _query_items(self.table(self.moderation_table_name), pk, sk_prefix)

    def put_interaction(self, item: dict[str, Any]) -> None:
        self.table(self.interactions_table_name).put_item(Item=_without_empty(item))

    def put_json(self, key: str, payload: dict[str, Any]) -> None:
        self.s3.put_object(
            Bucket=self.packages_bucket_name,
            Key=key,
            Body=json.dumps(_public_payload(payload), separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            ContentType="application/json; charset=utf-8",
        )

    def get_json(self, key: str) -> dict[str, Any]:
        try:
            response = self.s3.get_object(Bucket=self.packages_bucket_name, Key=key)
        except Exception as exc:
            raise ContentHubNotFound("Content hub package not found") from exc
        return json.loads(response["Body"].read().decode("utf-8"))

    def put_bytes(self, key: str, payload: bytes, content_type: str) -> None:
        self.s3.put_object(Bucket=self.packages_bucket_name, Key=key, Body=payload, ContentType=content_type)


def _query_items(table: Any, pk: str, sk_prefix: str) -> list[dict[str, Any]]:
    response = table.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": pk, ":sk": sk_prefix},
        Limit=200,
    )
    return response.get("Items", [])


def _update_item(table: Any, key: dict[str, str], updates: dict[str, Any]) -> dict[str, Any]:
    safe_updates = _without_empty(updates)
    if not safe_updates:
        return {}
    names = {f"#k{index}": field for index, field in enumerate(safe_updates)}
    values = {f":v{index}": value for index, value in enumerate(safe_updates.values())}
    expression = ", ".join(f"{name} = {value}" for name, value in zip(names, values))
    response = table.update_item(
        Key=key,
        UpdateExpression=f"SET {expression}",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    return response.get("Attributes", {})


_STORE: Optional[DynamoContentHubStore] = None


def _store() -> DynamoContentHubStore:
    global _STORE
    if _STORE is None:
        _STORE = DynamoContentHubStore()
    return _STORE


def _content_hub_binding(payload: dict[str, Any]) -> dict[str, Any]:
    input_value = payload.get("input") if isinstance(payload.get("input"), dict) else {}
    binding = input_value.get("contentHub") if isinstance(input_value.get("contentHub"), dict) else {}
    if not binding:
        raise ContentHubError("Content hub binding is required")
    return binding


def _input_field(payload: dict[str, Any], key: str) -> Any:
    input_value = payload.get("input") if isinstance(payload.get("input"), dict) else {}
    if key in input_value:
        return input_value[key]
    aliases = {
        "title": ["articleTitle"],
        "name": ["articleTitle"],
        "language": ["articleLanguage", "locale"],
        "summary": ["articleSummary"],
        "slug": ["articleSlug"],
        "visibility": ["articleVisibility"],
        "seoTitle": ["articleSeoTitle"],
        "seoDescription": ["articleSeoDescription"],
        "robots": ["seoRobots", "articleRobots"],
        "category": ["categoryId", "articleCategory", "articleCategoryId", "primaryCategory", "primaryCategoryId"],
        "tags": ["tagIds", "articleTags"],
        "commentPolicy": ["comments.policy", "articleCommentPolicy"],
        "contentSafety": ["safety", "articleContentSafety", "articleContentSafetyPolicy"],
        "canonicalMode": ["canonical.mode", "articleCanonicalMode", "articleCanonicalPolicy"],
        "canonicalUrl": ["canonical.url", "canonical.path", "canonicalPath", "articleCanonicalUrl"],
        "taxonomyKind": ["kind"],
        "label": ["taxonomyLabel", "displayName", "translation"],
        "description": ["taxonomyDescription"],
        "parentId": ["parentTaxonomyId"],
        "visible": ["isVisible"],
        "commentText": ["comment.body", "comment.text"],
        "body": ["commentBody"],
        "eventType": ["event.kind", "interaction.kind"],
        "interactionType": ["eventType"],
        "targetId": ["event.targetId", "interaction.targetId"],
        "value": ["event.value", "interaction.value"],
        "metadata": ["event.metadata", "interaction.metadata"],
        "scheduledAt": ["publishAt"],
        "moderationStatus": ["decision"],
        "fileName": ["upload.fileName", "upload.name", "metadata.fileName"],
        "mimeType": ["upload.mimeType", "metadata.mimeType"],
        "publicUrl": ["upload.publicUrl", "metadata.publicUrl"],
        "base64": ["upload.base64", "upload.dataBase64", "upload.file.base64", "upload.file.dataBase64", "dataBase64", "file.dataBase64"],
        "bytes": ["upload.bytes", "metadata.bytes"],
        "alt": ["metadata.alt"],
    }.get(key, [])
    for alias in aliases:
        value = _nested_input(input_value, alias)
        if value is not None:
            return value
    return payload.get(key)


def _nested_input(input_value: dict[str, Any], path: str) -> Any:
    current: Any = input_value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _article_package(
    article: dict[str, Any],
    revision: dict[str, Any],
    payload: dict[str, Any],
    profile: dict[str, Any],
    hub: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": 1,
        "kind": "content-hub-article-package",
        "hubId": hub["hubId"],
        "articleId": article["articleId"],
        "ownerDraftDomain": hub["ownerDraftDomain"],
        "originDraftDomain": profile["domain"],
        "status": "draft",
        "visibility": article["visibility"],
        "title": article.get("title"),
        "summary": article.get("summary"),
        "slug": article.get("slug"),
        "seo": {
            "title": article.get("seoTitle"),
            "description": article.get("seoDescription"),
            "robots": article.get("robots"),
        },
        "category": _taxonomy_ref(article.get("category")),
        "tags": _taxonomy_refs(article.get("tags")),
        "commentPolicy": article.get("commentPolicy"),
        "contentSafety": _content_safety_from_value(article.get("contentSafety")),
        "canonical": {
            "mode": article.get("canonicalMode"),
            "url": article.get("canonicalUrl"),
        },
        "primaryLocale": article["primaryLocale"],
        "revisionId": revision["revisionId"],
        "components": _safe_json_node(_input_field(payload, "components") or []),
        "variables": _safe_json_node(_input_field(payload, "variables") or {}),
        "i18n": _safe_json_node(_input_field(payload, "i18n") or {}),
        "analytics": _analytics_context(hub),
        "createdAt": article["createdAt"],
        "updatedAt": article["updatedAt"],
    }


def _revision_item(hub_id: str, article_id: str, revision_id: str, locale: str, now: str, subject: str) -> dict[str, Any]:
    package_key = f"content-hubs/{os.getenv(ENVIRONMENT_ENV, 'dev')}/{hub_id}/articles/{article_id}/lang/{locale}/revisions/{revision_id}/package.json"
    return {
        "pk": f"ARTICLE#{article_id}",
        "sk": f"REVISION#{revision_id}",
        "itemFamily": "REVISION",
        "hubId": hub_id,
        "articleId": article_id,
        "revisionId": revision_id,
        "locale": locale,
        "kind": "snapshot",
        "packageKey": package_key,
        "createdAt": now,
        "createdBy": subject,
    }


def _published_bundle_key(profile: dict[str, Any], hub_id: str, render_domain: str, locale: str, article_id: str, revision_id: str) -> str:
    return f"content-hubs/{profile['environment']}/{hub_id}/published/{render_domain}/{locale}/{article_id}/{revision_id}/bundle.json"


def _article_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "articleId": item.get("articleId"),
        "title": item.get("title"),
        "summary": item.get("summary"),
        "slug": item.get("slug"),
        "status": item.get("status"),
        "visibility": item.get("visibility"),
        "seoTitle": item.get("seoTitle"),
        "seoDescription": item.get("seoDescription"),
        "robots": item.get("robots"),
        "category": _taxonomy_ref(item.get("category")),
        "tags": _taxonomy_refs(item.get("tags")),
        "commentPolicy": item.get("commentPolicy"),
        "contentSafety": _content_safety_from_value(item.get("contentSafety")),
        "canonicalMode": item.get("canonicalMode"),
        "canonicalUrl": item.get("canonicalUrl"),
        "primaryLocale": item.get("primaryLocale"),
        "latestRevisionId": item.get("latestRevisionId"),
        "path": item.get("path"),
        "publishedAt": item.get("publishedAt"),
        "updatedAt": item.get("updatedAt"),
    }


def _taxonomy_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "taxonomyId": item.get("taxonomyId"),
        "kind": item.get("kind"),
        "slug": item.get("slug"),
        "label": item.get("label"),
        "description": item.get("description"),
        "locale": item.get("locale"),
        "seoTitle": item.get("seoTitle"),
        "seoDescription": item.get("seoDescription"),
        "parentId": item.get("parentId"),
        "visible": item.get("visible", True),
        "updatedAt": item.get("updatedAt"),
    }


def _revision_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "articleId": item.get("articleId"),
        "revisionId": item.get("revisionId"),
        "locale": item.get("locale"),
        "kind": item.get("kind"),
        "createdAt": item.get("createdAt"),
        "createdBy": item.get("createdBy"),
    }


def _asset_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "assetId": item.get("assetId"),
        "kind": item.get("kind"),
        "fileName": item.get("fileName"),
        "mimeType": item.get("mimeType"),
        "bytes": item.get("bytes"),
        "publicUrl": item.get("publicUrl"),
        "title": item.get("title"),
        "alt": item.get("alt"),
        "createdAt": item.get("createdAt"),
    }


def _moderation_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "articleId": item.get("articleId"),
        "commentId": item.get("commentId"),
        "status": item.get("status"),
        "bodyPreview": item.get("bodyPreview"),
        "queuedAt": item.get("queuedAt"),
        "moderatedAt": item.get("moderatedAt"),
    }


def _interaction_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "interactionId": item.get("interactionId"),
        "eventType": item.get("eventType"),
        "articleId": item.get("articleId"),
        "targetId": item.get("targetId"),
        "value": item.get("value"),
        "path": item.get("path"),
        "metadata": item.get("metadata"),
        "createdAt": item.get("createdAt"),
    }


def _schedule_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "scheduleId": item.get("scheduleId"),
        "articleId": item.get("articleId"),
        "revisionId": item.get("revisionId"),
        "action": item.get("action"),
        "scheduledAt": item.get("scheduledAt"),
    }


def _analytics_context(hub: dict[str, Any]) -> dict[str, Any]:
    context = hub.get("analyticsContext") if isinstance(hub.get("analyticsContext"), dict) else {}
    return {
        "contentGroup": _safe_id(context.get("contentGroup") or "blog"),
        "eventPrefix": _safe_id(context.get("eventPrefix") or "blog"),
        "piiPolicy": "no-pii",
    }


def _public_payload(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, dict):
        output = {}
        for key, entry in value.items():
            if SECRET_KEY_RE.search(str(key)):
                continue
            sanitized = _public_payload(entry)
            if sanitized is not None:
                output[key] = sanitized
        return output
    if isinstance(value, list):
        return [_public_payload(entry) for entry in value if _public_payload(entry) is not None]
    if isinstance(value, str) and UNSAFE_VALUE_RE.search(value):
        return None
    return value


def _safe_json_node(value: Any) -> Any:
    _reject_unsafe_public_payload(value)
    return value if isinstance(value, (dict, list, str, int, float, bool)) or value is None else None


def _reject_unsafe_public_payload(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SECRET_KEY_RE.search(str(key)):
                raise ContentHubError(f"Forbidden public field at {path}.{key}")
            _reject_unsafe_public_payload(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_unsafe_public_payload(child, f"{path}[{index}]")
    elif isinstance(value, str) and UNSAFE_VALUE_RE.search(value):
        raise ContentHubError(f"Forbidden public value at {path}")


def _reject_secret_like_config(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if CONFIG_SECRET_KEY_RE.search(str(key)):
                raise ContentHubConfigError(f"Secret-like config key is not allowed at {path}.{key}")
            _reject_secret_like_config(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_like_config(child, f"{path}[{index}]")
    elif isinstance(value, str) and any(marker in value for marker in ["-----BEGIN ", "AKIA", "ASIA", "ghp_", "xoxb-"]):
        raise ContentHubConfigError(f"Secret-like config value is not allowed at {path}")


def _request_payload(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("body")
    if event.get("isBase64Encoded") is True and isinstance(raw, str):
        raw = base64.b64decode(raw).decode("utf-8")
    if not raw:
        return {}
    parsed = json.loads(str(raw))
    if not isinstance(parsed, dict):
        raise ContentHubError("Request body must be a JSON object")
    return parsed


def _json_response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
        },
        "body": json.dumps(body, separators=(",", ":"), default=_json_default, ensure_ascii=False),
    }


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _method(event: dict[str, Any]) -> str:
    return _clean_string((event.get("requestContext") or {}).get("http", {}).get("method") or event.get("httpMethod")).upper()


def _path(event: dict[str, Any]) -> str:
    path = _clean_string(event.get("rawPath") or event.get("path") or (event.get("requestContext") or {}).get("http", {}).get("path"))
    stage = _clean_string((event.get("requestContext") or {}).get("stage"))
    if stage and path.startswith(f"/{stage}/"):
        return path[len(stage) + 1:]
    return path or "/"


def _header(event: dict[str, Any], name: str) -> str:
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return _clean_string(value)
    return ""


def _cookie_value(event: dict[str, Any], name: str) -> str:
    cookies = event.get("cookies") if isinstance(event.get("cookies"), list) else []
    for cookie in cookies:
        parts = str(cookie).split(";", 1)[0].split("=", 1)
        if len(parts) == 2 and parts[0].strip() == name:
            return parts[1].strip()
    header = _header(event, "cookie")
    for cookie in header.split(";"):
        parts = cookie.strip().split("=", 1)
        if len(parts) == 2 and parts[0] == name:
            return parts[1]
    return ""


def _csrf_cookie_name(profile: dict[str, Any]) -> str:
    value = _clean_string(profile.get("session", {}).get("csrfCookieName"))
    return value if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value) else DEFAULT_CSRF_COOKIE_NAME


def _csrf_header_name(profile: dict[str, Any]) -> str:
    value = _clean_string(profile.get("session", {}).get("csrfHeaderName"))
    return value if re.fullmatch(r"[A-Za-z0-9-]{1,64}", value) else DEFAULT_CSRF_HEADER_NAME


def _domain(value: Any) -> str:
    domain = _clean_string(value).lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise ContentHubError("Invalid domain")
    return domain


def _safe_id(value: Any) -> str:
    safe_id = _clean_string(value)
    if not SAFE_ID_RE.fullmatch(safe_id):
        raise ContentHubError("Invalid id")
    return safe_id


def _locale(value: Any) -> str:
    locale = _clean_string(value).lower()
    if not LOCALE_RE.fullmatch(locale):
        raise ContentHubError("Invalid locale")
    return locale


def _slug(value: Any) -> str:
    text = _clean_string(value).lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    if not text:
        text = "article"
    if not SLUG_RE.fullmatch(text):
        raise ContentHubError("Invalid slug")
    return text[:96]


def _article_path(value: Any) -> str:
    path = _clean_string(value)
    if not path.startswith("/") or path.startswith("//") or "\\" in path or re.search(r"[\s\x00-\x1f\x7f]", path):
        raise ContentHubError("Invalid article path")
    return path


def _safe_text(value: Any, *, max_length: int) -> str:
    text = _clean_string(value)
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", text):
        raise ContentHubError("Invalid text")
    return text[:max_length]


def _visibility(value: Any) -> str:
    aliases = {
        "private-draft": "private",
        "draft-private": "private",
        "review-ready": "private",
        "ready-for-review": "private",
        "published": "public",
    }
    visibility = aliases.get(_clean_string(value), _safe_id(value))
    if visibility not in {"public", "unlisted", "protected", "private"}:
        raise ContentHubError("Invalid visibility")
    return visibility


def _asset_kind(mime_type: str) -> str:
    if mime_type.startswith("image/"):
        return "image"
    if mime_type.startswith("video/"):
        return "video"
    if mime_type.startswith("audio/"):
        return "audio"
    if mime_type in {"application/pdf", "text/plain"}:
        return "document"
    return "download"


def _safe_filename(value: Any) -> str:
    file_name = _clean_string(value)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,180}", file_name):
        raise ContentHubError("Invalid file name")
    return file_name


def _safe_public_url(value: Any) -> str:
    url = _clean_string(value)
    if not url:
        return ""
    if not url.startswith("https://") or "\\" in url or UNSAFE_VALUE_RE.search(url) or re.search(r"[\s\x00-\x1f\x7f]", url):
        raise ContentHubError("Invalid public asset URL")
    return url


def _safe_canonical_url(value: Any) -> str:
    url = _clean_string(value)
    if not url:
        return ""
    if url.startswith("/"):
        return _article_path(url)
    if not url.startswith("https://") or "\\" in url or UNSAFE_VALUE_RE.search(url) or re.search(r"[\s\x00-\x1f\x7f]", url):
        raise ContentHubError("Invalid canonical URL")
    return url[:400]


def _canonical_mode(value: Any) -> str:
    aliases = {
        "creator-domain": "self",
        "host-adaptive": "self",
        "draft-domain": "self",
        "canonical-url": "custom",
        "custom-url": "custom",
        "disabled": "none",
    }
    mode = aliases.get(_clean_string(value), _safe_id(value))
    if mode not in {"self", "custom", "none"}:
        raise ContentHubError("Invalid canonical mode")
    return mode


def _canonical_for_publish(mode: str, canonical_url: str, path: str) -> str:
    if mode == "none":
        return ""
    if mode == "custom":
        if not canonical_url:
            raise ContentHubError("Canonical URL is required")
        return canonical_url
    return path


def _robots_policy(value: Any) -> str:
    robots = _clean_string(value).lower().replace(" ", "")
    allowed = {"index,follow", "noindex,follow", "index,nofollow", "noindex,nofollow"}
    if robots not in allowed:
        raise ContentHubError("Invalid robots policy")
    return robots


def _comment_policy(value: Any) -> str:
    aliases = {
        "authenticated-moderated": "authenticated",
        "auth-moderated": "authenticated",
        "public-moderated": "moderated",
        "moderation": "moderated",
        "off": "disabled",
    }
    policy = aliases.get(_clean_string(value), _safe_id(value))
    if policy not in {"disabled", "moderated", "authenticated"}:
        raise ContentHubError("Invalid comment policy")
    return policy


def _content_safety(payload: dict[str, Any]) -> dict[str, Any]:
    return _content_safety_from_value(_input_field(payload, "contentSafety") or {})


def _content_safety_from_value(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        aliases = {
            "trusted-authors": "general",
            "advanced-freeform": "sensitive",
            "strict": "restricted",
            "general": "general",
            "sensitive": "sensitive",
            "restricted": "restricted",
        }
        rating = aliases.get(_clean_string(value), "")
        if not rating:
            raise ContentHubError("Invalid content safety rating")
        return {"rating": rating, "warnings": []}
    if not isinstance(value, dict):
        return {"rating": "general", "warnings": []}
    rating = _safe_id(value.get("rating") or value.get("audience") or "general")
    if rating not in {"general", "sensitive", "restricted"}:
        raise ContentHubError("Invalid content safety rating")
    return {
        "rating": rating,
        "warnings": [_safe_text(item, max_length=80) for item in _list_value(value.get("warnings"))[:10]],
    }


def _taxonomy_ref(value: Any) -> dict[str, Any]:
    if value is None or value == "":
        return {}
    if isinstance(value, str):
        text = _clean_string(value)
        if not text:
            return {}
        return {"taxonomyId": _safe_id(text)}
    if not isinstance(value, dict):
        raise ContentHubError("Invalid taxonomy reference")
    taxonomy_id = _optional_safe_id(value.get("taxonomyId") or value.get("id"))
    slug = _slug(value.get("slug")) if _clean_string(value.get("slug")) else ""
    label = _safe_text(value.get("label") or value.get("name") or "", max_length=120)
    return _without_empty({"taxonomyId": taxonomy_id, "slug": slug, "label": label})


def _taxonomy_refs(value: Any) -> list[dict[str, Any]]:
    refs = []
    items = [part.strip() for part in value.split(",")] if isinstance(value, str) else _list_value(value)
    for item in items:
        ref = _taxonomy_ref(item)
        if ref:
            refs.append(ref)
    return refs[:20]


def _article_metadata_updates(payload: dict[str, Any]) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    field_builders = {
        "seoTitle": lambda: _safe_text(_input_field(payload, "seoTitle"), max_length=160),
        "seoDescription": lambda: _safe_text(_input_field(payload, "seoDescription"), max_length=320),
        "robots": lambda: _robots_policy(_input_field(payload, "robots")),
        "category": lambda: _taxonomy_ref(_input_field(payload, "category")),
        "tags": lambda: _taxonomy_refs(_input_field(payload, "tags")),
        "commentPolicy": lambda: _comment_policy(_input_field(payload, "commentPolicy")),
        "contentSafety": lambda: _content_safety(payload),
        "canonicalMode": lambda: _canonical_mode(_input_field(payload, "canonicalMode")),
        "canonicalUrl": lambda: _safe_canonical_url(_input_field(payload, "canonicalUrl")),
    }
    for field, builder in field_builders.items():
        if _input_field(payload, field) is not None:
            updates[field] = builder()
    return updates


def _safe_event_metadata(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ContentHubError("Invalid interaction metadata")
    output = {}
    for key, entry in list(value.items())[:20]:
        safe_key = _safe_id(key)
        if PII_KEY_RE.search(safe_key) or SECRET_KEY_RE.search(safe_key):
            raise ContentHubError("Interaction metadata cannot include private fields")
        if isinstance(entry, bool) or isinstance(entry, int) or isinstance(entry, float):
            output[safe_key] = entry
        elif isinstance(entry, str):
            text = _safe_text(entry, max_length=160)
            if EMAIL_VALUE_RE.search(text) or PHONE_VALUE_RE.search(text):
                raise ContentHubError("Interaction metadata cannot include private values")
            output[safe_key] = text
        elif entry is None:
            continue
        else:
            raise ContentHubError("Interaction metadata must be scalar")
    return output


def _redacted_preview(value: str, max_length: int) -> str:
    text = EMAIL_VALUE_RE.sub("[redacted-email]", value)
    text = PHONE_VALUE_RE.sub("[redacted-phone]", text)
    return _safe_text(text, max_length=max_length)


def _safe_bool(value: Any, *, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    text = _clean_string(value).lower()
    if text in {"true", "1", "yes", "si", "sí"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    raise ContentHubError("Invalid boolean value")


def _optional_safe_id(value: Any) -> str:
    return _safe_id(value) if _clean_string(value) else ""


def _optional_article_path(value: Any) -> str:
    return _article_path(value) if _clean_string(value) else ""


def _list_value(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [_clean_string(value)] if _clean_string(value) else []
    if not isinstance(value, list):
        raise ContentHubConfigError("Expected string list")
    output = []
    for item in value:
        text = _clean_string(item)
        if text:
            output.append(text)
    return output


def _without_empty(item: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if value is not None and value != ""}


def _tenant_profile_key(profile: dict[str, Any]) -> str:
    return f"{profile['domain']}#{profile['authProfileId']}#{profile['environment']}"


def _sha256(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _now_epoch() -> int:
    return int(time.time())


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _env_required(name: str) -> str:
    value = _clean_string(os.getenv(name))
    if not value:
        raise ContentHubConfigError(f"{name} is required")
    return value


def _clean_string(value: Any) -> str:
    return str(value or "").strip()


def _dynamodb_resource() -> Any:
    import boto3  # type: ignore

    return boto3.resource("dynamodb")


def _s3_client() -> Any:
    import boto3  # type: ignore

    return boto3.client("s3")


def _log(level: str, message: str, **kwargs: Any) -> None:
    configured = str(os.getenv("LOG_LEVEL", "INFO")).upper()
    order = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
    if order.get(level, 20) < order.get(configured, 20):
        return
    print(json.dumps({"level": level, "message": message, **kwargs}, separators=(",", ":")))
