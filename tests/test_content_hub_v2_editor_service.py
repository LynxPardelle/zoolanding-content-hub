"""Real editor service, isolated storage fixture, no AWS requests."""
from copy import deepcopy
import unittest

from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_service import EditorService, EditorConflict, EditorNotFound
from content_hub_v2_editor_model import EditorValidationError
from test_content_hub_v2_editor_model import package


class MemoryStore:
    """Storage adapter only; authorization and business logic remain real."""
    def __init__(self):
        self.rows, self.packages, self.assets = {}, {}, {}
        self.before_commit = lambda: None
        self.counter = 0

    def new_id(self):
        self.counter += 1
        return f"id-{self.counter}"

    def now(self):
        return "2026-09-07T12:00:00Z"

    def get_article(self, article_id):
        return deepcopy(self.rows.get(article_id))

    def list_articles(self):
        return deepcopy(list(self.rows.values()))

    def save_package(self, article_id, locale, revision_id, value):
        key = (article_id, locale, revision_id)
        self.packages[key] = deepcopy(value)
        return {"key": "/".join(key), "sha256": "a" * 64}

    def load_package(self, row, locale):
        return deepcopy(self.packages[(row["articleId"], locale, row["locales"][locale]["workingRevisionId"])])

    def get_assets(self, row, locale, asset_ids):
        return {key: deepcopy(self.assets[key]) for key in asset_ids if key in self.assets}

    def list_assets(self, row, locale):
        return list(self.get_assets(row, locale, self.assets).values())

    def commit(self, value, expected, authorize):
        self.before_commit()
        authorize()
        current = self.rows.get(value["articleId"])
        if (current or {}).get("concurrencyToken") != expected:
            raise EditorConflict()
        self.rows[value["articleId"]] = deepcopy(value)


class EditorServiceTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.active = True
        def authorize():
            if not self.active:
                raise PermissionError("session_changed")
        self.service = EditorService(self.store, purpose="client-owner", authorize=authorize)

    def create(self, locale="en"):
        return self.service.run("createArticle", {"locale": locale, "idempotencyKey": f"{self.store.counter + 1:032x}"})

    def save(self, article, locale="en", value=None):
        return self.service.run("updatePackage", {"articleId": article["articleId"], "locale": locale,
            "concurrencyToken": article["concurrencyToken"], "package": package() if value is None else value})

    def test_create_and_save_preserve_one_bilingual_identity(self):
        article = self.create()
        saved = self.save(article)
        spanish = self.save(saved, "es", package(title="Texto español"))
        self.assertEqual(spanish["articleId"], article["articleId"])
        self.assertEqual(spanish["locales"]["en"]["package"]["title"], "Forma y movimiento")
        self.assertEqual(spanish["locales"]["es"]["package"]["title"], "Texto español")
        self.assertNotEqual(article["concurrencyToken"], spanish["concurrencyToken"])
        self.assertNotIn("recordPurpose", spanish)
        self.assertNotIn("packagePointer", str(spanish))
        self.assertEqual(self.store.rows[article["articleId"]]["recordPurpose"], "client-owner")

    def test_stale_write_cannot_clobber_either_locale(self):
        article = self.create()
        self.save(article)
        before = deepcopy(self.store.rows)
        with self.assertRaises(EditorConflict):
            self.save(article, "es")
        self.assertEqual(self.store.rows, before)

    def test_same_payload_retry_does_not_create_another_revision(self):
        original = self.create()
        saved = self.save(original)
        replay = self.save(original)
        self.assertEqual(replay, saved)

    def test_private_purpose_isolation_list_and_direct_id(self):
        owner = self.create()
        qa = EditorService(self.store, purpose="qa", authorize=lambda: None)
        qa_article = qa.run("createArticle", {"locale": "en", "idempotencyKey": "f" * 32})
        self.assertEqual([x["articleId"] for x in self.service.run("articleList", {})["items"]], [owner["articleId"]])
        with self.assertRaises(EditorNotFound):
            self.service.run("articleDetail", {"articleId": qa_article["articleId"]})

    def test_wrong_scope_fails_instead_of_becoming_visible(self):
        article = self.create()
        self.store.rows[article["articleId"]]["hubId"] = "zoosite-main"
        with self.assertRaises(EditorNotFound):
            self.service.run("articleDetail", {"articleId": article["articleId"]})

    def test_disabled_or_expired_actor_at_final_commit_leaves_old_state(self):
        article = self.create()
        before = deepcopy(self.store.rows)
        self.store.before_commit = lambda: setattr(self, "active", False)
        with self.assertRaises(PermissionError):
            self.save(article)
        self.assertEqual(before, self.store.rows)

    def test_final_read_revalidates_after_loading_private_package(self):
        article = self.create()
        original = self.store.load_package
        def expired(*args):
            self.active = False
            return original(*args)
        self.store.load_package = expired
        with self.assertRaises(PermissionError):
            self.service.run("articleDetail", {"articleId": article["articleId"]})

    def test_private_search_matches_both_locales_and_tags(self):
        a = self.save(self.create(), value=package(tags=["private-note"]))
        self.save(a, "es", package(title="Cabello"))
        for query in ("cabello", "private-note", "FORMA"):
            self.assertEqual(len(self.service.run("articleList", {"search": query})["items"]), 1)
        self.assertEqual(self.service.run("articleList", {"search": "absent"})["items"], [])

    def test_series_locks_after_first_publication_in_either_locale(self):
        a = self.save(self.create())
        self.store.rows[a["articleId"]]["seriesLocked"] = True
        with self.assertRaises(EditorValidationError):
            self.save(a, "es", package(seriesId="bridal-forms"))

    def test_preview_and_validation_never_publish_or_return_private_pointers(self):
        a = self.save(self.create())
        before = deepcopy(self.store.rows)
        result = self.service.run("publicBundlePreview", {"articleId": a["articleId"], "locale": "en"})
        self.assertIn("<p>Primera", result["articleContent"]["html"])
        self.assertNotIn("tags", result)
        self.assertNotIn("packagePointer", str(result))
        validation = self.service.run("validate", {"articleId": a["articleId"], "locale": "en", "concurrencyToken": a["concurrencyToken"]})
        self.assertIn("cover_not_ready", validation["errors"])
        self.assertEqual(before, self.store.rows)

    def test_private_inline_preview_uses_inert_asset_references_not_nonexistent_get_urls(self):
        value = package(delta={"ops": [{"insert": "A letter\n"}, {"insert": {"image": "asset-1"}}]})
        article = self.save(self.create(), value=value)
        self.store.assets["asset-1"] = {"assetId": "asset-1", "status": "ready", "alt": 'Hair <quiet> "form"',
                                         "variants": [{"key": "private/secret", "versionId": "private-version"}]}
        result = self.service.run("publicBundlePreview", {"articleId": article["articleId"], "locale": "en"})
        html = result["articleContent"]["html"]
        self.assertIn('data-private-asset="asset-1"', html)
        self.assertNotIn('src=', html)
        self.assertNotIn("private/secret", str(result))
        self.assertNotIn("private-version", str(result))
        self.assertIn("&lt;quiet&gt;", html)
        self.store.assets.clear()
        with self.assertRaises(EditorValidationError):
            self.service.run("publicBundlePreview", {"articleId": article["articleId"], "locale": "en"})

    def test_no_arbitrary_commands_fields_paths_or_client_purpose(self):
        for op, value in (("archiveArticle", {}), ("createArticle", {"locale": "en", "recordPurpose": "qa"}),
                          ("articleDetail", {"articleId": "../x"})):
            with self.subTest(op=op), self.assertRaises(EditorValidationError):
                self.service.run(op, value)

    def test_create_replay_returns_same_identity_and_no_extra_revision(self):
        data = {"locale": "en", "idempotencyKey": "a" * 32}
        first = self.service.run("createArticle", data)
        second = self.service.run("createArticle", data)
        self.assertEqual(first, second)
        self.assertEqual(len(self.store.rows), 1)
        self.assertEqual(len(self.store.packages), 1)

    def test_shared_series_cannot_revert_when_editing_a_sibling_title(self):
        a = self.save(self.create())
        a = self.save(a, "es", package(seriesId="bridal-forms"))
        english = a["locales"]["en"]["package"]
        self.assertEqual(english["seriesId"], "bridal-forms")
        english["title"] = "A corrected title"
        saved = self.save(a, "en", english)
        self.assertEqual(saved["seriesId"], "bridal-forms")

    def test_qa_retention_is_server_owned_and_not_returned(self):
        from datetime import datetime, timedelta
        qa = EditorService(self.store, purpose="qa", authorize=lambda: None)
        article = qa.run("createArticle", {"locale": "en", "idempotencyKey": "f" * 32})
        row = self.store.rows[article["articleId"]]
        self.assertEqual(row["retentionUntil"], (datetime.fromisoformat(row["createdAt"].replace("Z", "+00:00")) + timedelta(days=30)).isoformat(timespec="seconds").replace("+00:00", "Z"))
        self.assertNotIn("retentionUntil", article)


if __name__ == "__main__":
    unittest.main()
