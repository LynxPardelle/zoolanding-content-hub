"""Private fixed-template use cases, independent of storage and v1 handlers."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
import json
import re

from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import (
    EditorValidationError, EditorConflict, EditorNotFound, LOCALES, SERIES, compile_delta, locale_state,
    normalize_package, publication_errors, referenced_assets, safe_id, safe_locale,
)


def package_digest(package):
    return hashlib.sha256(json.dumps(package, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def safe_article(record, packages=None):
    value = {key: record[key] for key in ("articleId", "seriesId", "concurrencyToken", "createdAt", "updatedAt")}
    value["seriesLocked"] = record.get("seriesLocked", False)
    value["locales"] = {}
    for locale, state in record["locales"].items():
        public = {key: deepcopy(state[key]) for key in ("title", "summary", "tags", "workingRevisionId", "publishedRevisionId", "firstPublishedAt", "path") if key in state}
        public["state"] = locale_state(state)
        if packages is not None:
            public["package"] = packages[locale]
        value["locales"][locale] = public
    return value


class EditorService:
    def __init__(self, store, *, purpose, authorize, publisher=None, uploader=None):
        if purpose not in ("qa", "client-owner"):
            raise EditorNotFound()
        self.store, self.purpose, self.authorize = store, purpose, authorize
        self.publisher, self.uploader = publisher, uploader

    def _record(self, article_id):
        safe_id(article_id)
        value = self.store.get_article(article_id)
        if (not isinstance(value, dict) or value.get("articleId") != article_id
                or value.get("recordPurpose") != self.purpose
                or any(value.get(k) != v for k, v in THN_CURRENT_USER_SCOPE.items())):
            raise EditorNotFound()
        return value

    def _detail(self, record):
        packages = {locale: self._package(record, locale) for locale in record["locales"]}
        result = safe_article(record, packages)
        self.authorize()
        return result

    def _package(self, record, locale):
        # Series belongs to the bilingual article, never to one editable body.
        return {**self.store.load_package(record, locale), "seriesId": record["seriesId"]}

    def run(self, operation, data):
        allowed = {
            "createArticle": {"locale", "idempotencyKey"}, "updatePackage": {"articleId", "locale", "concurrencyToken", "package"},
            "articleList": {"search", "locale", "state", "seriesId"}, "articleDetail": {"articleId"},
            "taxonomyList": set(), "assetList": {"articleId", "locale", "assetId"},
            "publicBundlePreview": {"articleId", "locale"}, "validate": {"articleId", "locale", "concurrencyToken"},
            "publish": {"articleId", "locale", "concurrencyToken", "revisionId", "idempotencyKey"},
            "unpublishArticle": {"articleId", "locale", "concurrencyToken", "idempotencyKey"},
            "uploadAsset": {"articleId", "locale", "concurrencyToken", "imageBase64", "contentType", "alt"},
        }
        if operation not in allowed or not isinstance(data, dict) or not set(data) <= allowed[operation]:
            raise EditorValidationError("invalid_request")
        self.authorize()
        if operation == "createArticle":
            key = data.get("idempotencyKey")
            if not isinstance(key, str) or re.fullmatch(r"[a-f0-9]{32}", key) is None:
                raise EditorValidationError("idempotency_key_required")
            return self._create(safe_locale(data.get("locale")), key)
        if operation == "taxonomyList":
            result = {"items": [{"seriesId": key, "localizations": {loc: {"title": pair[0], "slug": pair[1]} for loc, pair in val.items()}} for key, val in SERIES.items()]}
            self.authorize()
            return result
        if operation == "articleList":
            return self._list(data)
        record = self._record(data.get("articleId"))
        if operation == "articleDetail":
            return self._detail(record)
        locale = safe_locale(data.get("locale"))
        if operation == "updatePackage":
            return self._update(record, locale, data)
        if locale not in record["locales"]:
            raise EditorNotFound()
        if operation == "assetList":
            result = {"items": ([self.store.preview_asset(record, locale, safe_id(data["assetId"]))]
                                 if "assetId" in data else self.store.list_assets(record, locale))}
            self.authorize()
            return result
        if operation == "publicBundlePreview":
            package = self._package(record, locale)
            assets = self.store.get_assets(record, locale, referenced_assets(package))
            value = {"articleId": record["articleId"], "locale": locale, "title": package["title"],
                     "summary": package["summary"], "seriesId": record["seriesId"], "cover": deepcopy(package["cover"]),
                     "articleContent": {"html": compile_delta(package["delta"], assets, private_preview=True)}}
            self.authorize()
            return value
        if operation in {"publish", "unpublishArticle"}:
            if self.publisher is None:
                raise EditorValidationError("feature_not_ready")
            if operation == "publish" and data.get("concurrencyToken") == record["concurrencyToken"]:
                if data.get("revisionId") != record["locales"][locale].get("workingRevisionId"):
                    raise EditorConflict()
                package = self._package(record, locale)
                errors = publication_errors(package, self.store.get_assets(record, locale, referenced_assets(package)))
                if errors:
                    self.authorize()
                    return {"valid": False, "errors": errors}
            # Only the publisher can decide whether an old token is an exact
            # successful replay. Otherwise its final private CAS rejects it.
            self.authorize()
            return self.publisher(operation, record, locale, self.authorize, data)
        if data.get("concurrencyToken") != record["concurrencyToken"]:
            raise EditorConflict()
        package = self._package(record, locale)
        if operation == "uploadAsset":
            if self.uploader is None:
                raise EditorValidationError("feature_not_ready")
            return self.uploader(record, locale, data, self.authorize)
        errors = publication_errors(package, self.store.get_assets(record, locale, referenced_assets(package)))
        self.authorize()
        if operation == "validate":
            return {"valid": not errors, "errors": errors}
        if errors:
            return {"valid": False, "errors": errors}
        raise EditorValidationError("invalid_request")

    def _create(self, locale, idempotency_key):
        article_id = "a" + hashlib.sha256((self.purpose + ":" + idempotency_key).encode()).hexdigest()[:40]
        existing = self.store.get_article(article_id)
        if existing:
            return self._detail(self._record(article_id))
        revision_id, token = self.store.new_id(), self.store.new_id()
        package = normalize_package({})
        pointer = self.store.save_package(article_id, locale, revision_id, package)
        now = self.store.now()
        record = {**THN_CURRENT_USER_SCOPE, "recordPurpose": self.purpose, "articleId": article_id,
                  "seriesId": package["seriesId"], "seriesLocked": False, "concurrencyToken": token,
                  "createdAt": now, "updatedAt": now, "locales": {locale: {
                      "title": "", "summary": "", "tags": [], "workingRevisionId": revision_id,
                      "packagePointer": pointer, "workingAssetIds": [], "publishedAssetIds": []}}}
        if self.purpose == "qa":
            record["retentionUntil"] = (datetime.fromisoformat(now.replace("Z", "+00:00")) + timedelta(days=30)).isoformat(timespec="seconds").replace("+00:00", "Z")
        try:
            self.store.commit(record, None, self.authorize)
        except EditorConflict:
            # Concurrent retry: the winning record remains the single identity.
            return self._detail(self._record(article_id))
        return self._detail(record)

    def _update(self, record, locale, data):
        package = normalize_package(data.get("package"))
        digest = package_digest(package)
        previous_token = data.get("concurrencyToken")
        if not isinstance(previous_token, str):
            raise EditorConflict()
        if previous_token != record["concurrencyToken"]:
            if record.get("lastWrite") == {"previousToken": previous_token, "locale": locale, "sha256": digest}:
                return self._detail(record)
            raise EditorConflict()
        if record.get("seriesLocked") and package["seriesId"] != record["seriesId"]:
            raise EditorValidationError("series_locked")
        revision_id = self.store.new_id()
        record = deepcopy(record)
        record["seriesId"] = package["seriesId"]
        record["locales"][locale] = {**record["locales"].get(locale, {}),
            "title": package["title"], "summary": package["summary"], "tags": package["tags"],
            "workingRevisionId": revision_id,
            "workingAssetIds": sorted(referenced_assets(package)),
            "publishedAssetIds": record["locales"].get(locale, {}).get("publishedAssetIds", []),
            "packagePointer": self.store.save_package(record["articleId"], locale, revision_id, package)}
        record["updatedAt"], record["concurrencyToken"] = self.store.now(), self.store.new_id()
        record["lastWrite"] = {"previousToken": previous_token, "locale": locale, "sha256": digest}
        self.store.commit(record, previous_token, self.authorize)
        return self._detail(record)

    def _list(self, data):
        search = data.get("search", "")
        if not isinstance(search, str) or len(search) > 160:
            raise EditorValidationError("invalid_search")
        locale, state, series_id = data.get("locale"), data.get("state"), data.get("seriesId")
        if locale is not None:
            safe_locale(locale)
        if state is not None and state not in {"draft", "published", "updates-pending", "unpublished"}:
            raise EditorValidationError("invalid_state")
        if series_id is not None and series_id not in SERIES:
            raise EditorValidationError("invalid_series")
        result = []
        for row in self.store.list_articles():
            if any(row.get(k) != v for k, v in THN_CURRENT_USER_SCOPE.items()):
                raise EditorNotFound()
            if row.get("recordPurpose") != self.purpose or (series_id and row["seriesId"] != series_id):
                continue
            candidates = [v for k, v in row["locales"].items() if not locale or k == locale]
            if not candidates or (state and not any(locale_state(v) == state for v in candidates)):
                continue
            haystack = " ".join(v.get("title", "") + " " + " ".join(v.get("tags", [])) for v in row["locales"].values())
            if search.casefold() not in haystack.casefold():
                continue
            result.append(safe_article(row))
        result.sort(key=lambda row: (row["updatedAt"], row["articleId"]), reverse=True)
        self.authorize()
        return {"items": result}
