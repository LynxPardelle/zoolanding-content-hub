import base64
import json
import os
import unittest
from unittest.mock import patch

import lambda_function as content_hub


def encoded_config(**overrides):
    profile = {
        "enabled": True,
        "environment": "test",
        "domain": "zoositioweb.com.mx",
        "authProfileId": "staff",
        "tenantId": "zoosite",
        "adminGroups": ["zoosite-admin"],
        "session": {
            "csrfCookieName": "zlp_csrf",
            "csrfHeaderName": "X-ZLP-CSRF",
        },
        "contentHubs": [
            {
                "hubId": "zoosite-main",
                "ownerDraftDomain": "zoositioweb.com.mx",
                "authorizedDraftDomains": ["zoositioweb.com.mx"],
                "defaultLocale": "es",
                "roles": {
                    "read": ["zoosite-admin", "zoosite-blog-editor"],
                    "edit": ["zoosite-admin", "zoosite-blog-editor"],
                    "publish": ["zoosite-admin", "zoosite-blog-publisher"],
                    "media": ["zoosite-admin", "zoosite-blog-media"],
                    "moderate": ["zoosite-admin", "zoosite-blog-moderator"],
                },
                "analyticsContext": {
                    "contentGroup": "zoosite_blog",
                    "eventPrefix": "blog",
                },
            }
        ],
    }
    profile.update(overrides)
    raw = json.dumps({"version": 1, "profiles": [profile]}, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def event(path, body, *, csrf=True, cookies=None, headers=None):
    req_headers = {
        "x-zlp-domain": "zoositioweb.com.mx",
        "x-zlp-auth-profile-id": "staff",
        "x-zlp-content-hub-id": "zoosite-main",
    }
    if csrf:
        req_headers["x-zlp-csrf"] = "csrf-value"
    req_headers.update(headers or {})
    request_cookies = [
        f"__Host-zlp_session={SESSION_VALUE}",
        "zlp_csrf=csrf-value",
    ] if cookies is None else cookies
    return {
        "version": "2.0",
        "rawPath": path,
        "headers": req_headers,
        "cookies": request_cookies,
        "requestContext": {"http": {"method": "POST", "path": path}, "stage": "test"},
        "body": json.dumps(body),
    }


def body(response):
    return json.loads(response.get("body") or "{}")


SESSION_VALUE = "session-value"
SESSION_HASH = content_hub._sha256(SESSION_VALUE)
CSRF_HASH = content_hub._sha256("csrf-value")


class FakeStore:
    def __init__(self, roles=None):
        self.metadata = {}
        self.media = {}
        self.moderation = {}
        self.interactions = {}
        self.objects = {}
        self.bytes = {}
        self.roles = roles or ["zoosite-admin"]

    def get_auth_session(self, session_hash):
        if session_hash != SESSION_HASH:
            return None
        return {
            "sessionIdHash": session_hash,
            "tenantProfileKey": "zoositioweb.com.mx#staff#test",
            "domain": "zoositioweb.com.mx",
            "authProfileId": "staff",
            "environment": "test",
            "tenantId": "zoosite",
            "subject": "admin-sub",
            "roles": self.roles,
            "approvalStatus": "approved",
            "enabled": True,
            "sessionVersion": 1,
            "csrfHash": CSRF_HASH,
            "expiresAt": 4_102_444_800,
        }

    def get_auth_user(self, tenant_profile_key, user_key):
        if tenant_profile_key != "zoositioweb.com.mx#staff#test" or user_key != "USER#admin-sub":
            return None
        return {
            "roles": self.roles,
            "approvalStatus": "approved",
            "enabled": True,
            "sessionVersion": 1,
        }

    def get_metadata(self, pk, sk):
        return self.metadata.get((pk, sk))

    def put_metadata(self, item):
        self.metadata[(item["pk"], item["sk"])] = dict(item)

    def update_metadata(self, pk, sk, updates):
        item = self.metadata.setdefault((pk, sk), {"pk": pk, "sk": sk})
        item.update(updates)
        return dict(item)

    def query_metadata(self, pk, sk_prefix):
        return [dict(item) for (item_pk, item_sk), item in self.metadata.items() if item_pk == pk and item_sk.startswith(sk_prefix)]

    def put_media(self, item):
        self.media[(item["pk"], item["sk"])] = dict(item)

    def query_media(self, pk, sk_prefix):
        return [dict(item) for (item_pk, item_sk), item in self.media.items() if item_pk == pk and item_sk.startswith(sk_prefix)]

    def put_moderation(self, item):
        self.moderation[(item["pk"], item["sk"])] = dict(item)

    def query_moderation(self, pk, sk_prefix):
        return [dict(item) for (item_pk, item_sk), item in self.moderation.items() if item_pk == pk and item_sk.startswith(sk_prefix)]

    def put_interaction(self, item):
        self.interactions[(item["pk"], item["sk"])] = dict(item)

    def put_json(self, key, payload):
        self.objects[key] = dict(payload)

    def get_json(self, key):
        if key not in self.objects:
            raise content_hub.ContentHubNotFound()
        return dict(self.objects[key])

    def put_bytes(self, key, payload, content_type):
        self.bytes[key] = (payload, content_type)


class ContentHubHandlerTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        env = {
            "CONTENT_HUB_ENVIRONMENT": "test",
            "CONTENT_HUB_CONFIG_JSON_BASE64": encoded_config(),
            "LOG_LEVEL": "ERROR",
        }
        self.env_patch = patch.dict(os.environ, env, clear=True)
        self.env_patch.start()
        self.store_patch = patch.object(content_hub, "_store", return_value=self.store)
        self.store_patch.start()

    def tearDown(self):
        self.store_patch.stop()
        self.env_patch.stop()
        content_hub._CONFIG_CACHE.clear()

    def request(self, path, binding, extra=None, **kwargs):
        payload = {
            "domain": "zoositioweb.com.mx",
            "input": {
                "contentHub": {
                    "hubId": "zoosite-main",
                    **binding,
                },
                **(extra or {}),
            },
        }
        return content_hub.lambda_handler(event(path, payload, **kwargs), None)

    def test_read_requires_session(self):
        response = self.request(
            "/features/content-hub/read",
            {"read": "articleList"},
            cookies=[],
            csrf=False,
        )
        self.assertEqual(response["statusCode"], 401)

    def test_mutation_requires_csrf(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Blog builder SEO"},
            csrf=False,
        )
        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(body(response)["error"], "CSRF validation failed")

    def test_action_requires_content_hub_action(self):
        response = self.request(
            "/features/content-hub/action",
            {},
            {"title": "Blog builder SEO"},
        )
        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body(response)["error"], "contentHub.action is required")

    def test_rejects_server_only_public_payload(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Leak", "bucketName": "private-bucket"},
        )
        self.assertEqual(response["statusCode"], 400)
        self.assertNotIn("private-bucket", response["body"])

    def test_editor_can_create_article_and_read_list(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Blog builder SEO", "summary": "Guía de SEO"},
        )
        self.assertEqual(create["statusCode"], 200)
        article_id = body(create)["data"]["article"]["articleId"]
        self.assertTrue(article_id.startswith("art_"))

        read = self.request("/features/content-hub/read", {"read": "articleList"}, csrf=False)
        self.assertEqual(read["statusCode"], 200)
        self.assertEqual(len(body(read)["data"]["items"]), 1)
        self.assertNotIn("packageKey", read["body"])

        detail = self.request(
            "/features/content-hub/read",
            {"read": "articleDetail"},
            {"articleId": article_id},
            csrf=False,
        )
        self.assertEqual(detail["statusCode"], 200)
        self.assertEqual(body(detail)["data"]["item"]["articleId"], article_id)
        self.assertEqual(body(detail)["data"]["item"]["title"], "Blog builder SEO")
        self.assertEqual(body(detail)["data"]["item"]["summary"], "Guía de SEO")
        self.assertNotIn("packageKey", detail["body"])

    def test_create_article_does_not_require_article_id(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Sin id previo"},
        )
        self.assertEqual(create["statusCode"], 200)
        self.assertTrue(body(create)["data"]["article"]["articleId"].startswith("art_"))

    def test_article_detail_requires_existing_article(self):
        read = self.request(
            "/features/content-hub/read",
            {"read": "articleDetail"},
            {"articleId": "missing-article"},
            csrf=False,
        )
        self.assertEqual(read["statusCode"], 404)

    def test_create_article_stores_blog_metadata_and_public_summary(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {
                "articleTitle": "SEO local",
                "articleSummary": "Guía de posicionamiento local",
                "articleSeoTitle": "SEO local para veterinarias",
                "articleSeoDescription": "Descripción SEO segura",
                "categoryId": "cat-seo",
                "articleTags": ["tag-seo", {"taxonomyId": "tag-vet", "slug": "veterinarias", "label": "Veterinarias"}],
                "articleCommentPolicy": "authenticated",
                "articleContentSafety": {"rating": "sensitive", "warnings": ["salud"]},
                "articleCanonicalMode": "custom",
                "articleCanonicalUrl": "https://zoositioweb.com.mx/blog/seo-local",
            },
        )
        self.assertEqual(create["statusCode"], 200)
        article = body(create)["data"]["article"]
        self.assertEqual(article["seoTitle"], "SEO local para veterinarias")
        self.assertEqual(article["category"]["taxonomyId"], "cat-seo")
        self.assertEqual(article["tags"][1]["slug"], "veterinarias")
        self.assertEqual(article["commentPolicy"], "authenticated")
        self.assertEqual(article["contentSafety"]["rating"], "sensitive")
        self.assertEqual(article["canonicalMode"], "custom")

        read = self.request("/features/content-hub/read", {"read": "articleList"}, csrf=False)
        self.assertEqual(body(read)["data"]["items"][0]["canonicalUrl"], "https://zoositioweb.com.mx/blog/seo-local")
        self.assertNotIn("updatedBy", read["body"])

    def test_create_article_accepts_draft_policy_aliases_and_comma_tags(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {
                "articleTitle": "Editor visual",
                "articleTags": "seo, blog-builder",
                "articleCanonicalPolicy": "creator-domain",
                "articleCommentPolicy": "authenticated-moderated",
                "articleContentSafetyPolicy": "advanced-freeform",
                "articleVisibility": "private-draft",
            },
        )
        self.assertEqual(create["statusCode"], 200)
        article = body(create)["data"]["article"]
        self.assertEqual(article["canonicalMode"], "self")
        self.assertEqual(article["commentPolicy"], "authenticated")
        self.assertEqual(article["contentSafety"]["rating"], "sensitive")
        self.assertEqual(article["visibility"], "private")
        self.assertEqual([item["taxonomyId"] for item in article["tags"]], ["seo", "blog-builder"])

    def test_create_article_accepts_localized_builder_labels_and_human_tags(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {
                "articleTitle": "E2E Test Article Manual",
                "articleLanguage": "es",
                "articleCategory": "test",
                "articleTags": "test, algo más, manual",
                "articleSummary": "Este es un artículo de test manual.",
                "articleSeoTitle": "E2E Test Manual",
                "articleSeoDescription": "Este es un artículo de test manual.",
                "articleSlug": "e2e-test-manual",
                "articleCanonicalPolicy": "Adaptable al sitio actual",
                "articleCommentPolicy": "Públicos + moderación",
                "articleContentSafetyPolicy": "Avanzado libre",
                "articleVisibility": "Listo para revisión",
            },
        )
        self.assertEqual(create["statusCode"], 200)
        article = body(create)["data"]["article"]
        self.assertEqual(article["canonicalMode"], "self")
        self.assertEqual(article["commentPolicy"], "moderated")
        self.assertEqual(article["contentSafety"]["rating"], "sensitive")
        self.assertEqual(article["visibility"], "private")
        self.assertEqual([item["taxonomyId"] for item in article["tags"]], ["test", "algo-mas", "manual"])
        self.assertEqual(article["tags"][1]["label"], "algo más")
        self.assertEqual(article["categorySlug"], "test")
        self.assertEqual(article["path"], "/blog/test/e2e-test-manual")

        taxonomy = self.request("/features/content-hub/read", {"read": "taxonomyList"}, csrf=False)
        self.assertEqual(taxonomy["statusCode"], 200)
        taxonomy_items = body(taxonomy)["data"]["items"]
        self.assertTrue(any(item["kind"] == "category" and item["slug"] == "test" for item in taxonomy_items))
        self.assertTrue(any(item["kind"] == "tag" and item["slug"] == "algo-mas" for item in taxonomy_items))

        self.store.roles = ["zoosite-blog-publisher"]
        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article["articleId"], "revisionId": "rev_001"},
            {"seoDescription": "Descripción SEO"},
        )
        self.assertEqual(publish["statusCode"], 200)
        self.assertEqual(body(publish)["data"]["path"], "/blog/test/e2e-test-manual")

    def test_create_article_rejects_empty_human_tag_slugs(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"articleTitle": "Invalid tag", "articleTags": "!!!"},
        )
        self.assertEqual(create["statusCode"], 400)
        self.assertEqual(body(create)["error"], "Invalid slug")

    def test_taxonomy_upsert_and_list_exposes_safe_fields(self):
        self.store.roles = ["zoosite-blog-editor"]
        upsert = self.request(
            "/features/content-hub/action",
            {"action": "upsertTaxonomy", "taxonomyKind": "category"},
            {
                "taxonomyId": "cat-blog",
                "translation": "Blog",
                "description": "Categoría principal",
                "seoTitle": "Blog Zoosite",
                "visible": True,
            },
        )
        self.assertEqual(upsert["statusCode"], 200)
        self.assertEqual(body(upsert)["data"]["taxonomy"]["slug"], "blog")

        read = self.request(
            "/features/content-hub/read",
            {"read": "taxonomyList", "taxonomyKind": "category"},
            csrf=False,
        )
        data = body(read)["data"]
        self.assertEqual(len(data["categories"]), 1)
        self.assertEqual(data["categories"][0]["seoTitle"], "Blog Zoosite")
        self.assertNotIn("updatedBy", read["body"])

    def test_config_is_cached_for_same_environment(self):
        first = content_hub.load_config()
        with patch("lambda_function.json.loads") as loads:
            second = content_hub.load_config()
        self.assertIs(second, first)
        loads.assert_not_called()

    def test_store_does_not_create_s3_client_until_object_storage_is_used(self):
        env = {
            "AUTH_SESSION_TABLE_NAME": "auth-session",
            "AUTH_USER_STATE_TABLE_NAME": "auth-user",
            "CONTENT_HUB_METADATA_TABLE_NAME": "metadata",
            "CONTENT_HUB_MEDIA_TABLE_NAME": "media",
            "CONTENT_HUB_MODERATION_TABLE_NAME": "moderation",
            "CONTENT_HUB_INTERACTIONS_TABLE_NAME": "interactions",
            "CONTENT_HUB_PACKAGES_BUCKET_NAME": "packages",
        }
        fake_dynamodb = unittest.mock.Mock()
        with patch.dict(os.environ, env, clear=True), \
             patch("lambda_function._dynamodb_resource", return_value=fake_dynamodb), \
             patch("lambda_function._s3_client") as s3_client:
            store = content_hub.DynamoContentHubStore()
            s3_client.assert_not_called()

            store.query_metadata("HUB#zoosite-main", "ARTICLE#")
            s3_client.assert_not_called()

            _ = store.s3
            s3_client.assert_called_once()

    def test_editor_cannot_publish_without_publish_role(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "No publicar"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id, "revisionId": "rev_001"},
            {"path": "/blog/no-publicar"},
        )
        self.assertEqual(publish["statusCode"], 403)

    def test_publisher_can_publish_existing_revision(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {
                "title": "Publicar",
                "summary": "Descripción",
                "category": {"taxonomyId": "cat-blog", "slug": "blog", "label": "Blog"},
                "tags": ["tag-seo"],
                "commentPolicy": "moderated",
                "canonicalMode": "custom",
                "canonicalUrl": "https://zoositioweb.com.mx/blog/publicar",
            },
        )
        article_id = body(create)["data"]["article"]["articleId"]
        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id, "revisionId": "rev_001"},
            {"path": "/blog/publicar", "seoDescription": "Descripción SEO"},
        )
        self.assertEqual(publish["statusCode"], 200)
        data = body(publish)["data"]
        self.assertEqual(data["path"], "/blog/publicar")
        self.assertNotIn("publishedBundleKey", data)
        self.assertNotIn("publishedBundleKey", publish["body"])
        bundle = next(item for item in self.store.objects.values() if item.get("safeArticlePath") == "/blog/publicar")
        self.assertEqual(bundle["safeArticlePath"], "/blog/publicar")
        self.assertEqual(bundle["category"]["taxonomyId"], "cat-blog")
        self.assertEqual(bundle["tags"][0]["taxonomyId"], "tag-seo")
        self.assertEqual(bundle["commentPolicy"], "moderated")
        self.assertEqual(bundle["seo"]["canonicalMode"], "custom")
        self.assertEqual(bundle["seo"]["canonical"], "https://zoositioweb.com.mx/blog/publicar")
        self.assertEqual(bundle["analytics"]["piiPolicy"], "no-pii")
        self.assertNotIn("bucket", publish["body"].lower())

    def test_public_preview_uses_latest_revision_when_revision_id_is_omitted(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Preview latest"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id},
            {"path": "/blog/preview-latest"},
        )
        self.assertEqual(publish["statusCode"], 200)

        preview = self.request(
            "/features/content-hub/read",
            {"read": "publicBundlePreview", "articleId": article_id},
            csrf=False,
        )
        self.assertEqual(preview["statusCode"], 200)
        self.assertEqual(body(preview)["data"]["bundle"]["articleId"], article_id)

    def test_update_package_and_restore_do_not_expose_storage_keys(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Restaurar"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        update = self.request(
            "/features/content-hub/action",
            {"action": "updatePackage"},
            {"articleId": article_id, "revisionId": "rev_restore", "components": []},
        )
        self.assertEqual(update["statusCode"], 200)
        self.assertNotIn("packageKey", update["body"])

        restore = self.request(
            "/features/content-hub/action",
            {"action": "restoreRevision"},
            {"articleId": article_id, "revisionId": "rev_restore"},
        )
        self.assertEqual(restore["statusCode"], 200)
        self.assertEqual(body(restore)["data"]["revisionId"], "rev_restore")

    def test_queue_comment_redacts_private_contact_values(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "queueComment", "articleId": "art_123"},
            {"commentText": "Escríbeme a persona@example.com o +52 555 555 5555"},
        )
        self.assertEqual(response["statusCode"], 200)
        queued = body(response)["data"]["comment"]
        self.assertEqual(queued["status"], "queued")
        self.assertIn("[redacted-email]", queued["bodyPreview"])
        self.assertIn("[redacted-phone]", queued["bodyPreview"])
        self.assertNotIn("persona@example.com", response["body"])

    def test_record_interaction_accepts_safe_metadata_and_rejects_pii(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "recordInteraction", "articleId": "art_123"},
            {
                "eventType": "cta",
                "targetId": "newsletter-button",
                "value": "click",
                "path": "/blog/publicar",
                "metadata": {"placement": "hero", "variant": "a"},
            },
        )
        self.assertEqual(response["statusCode"], 200)
        interaction = body(response)["data"]["interaction"]
        self.assertEqual(interaction["metadata"]["placement"], "hero")
        self.assertNotIn("actorHash", response["body"])

        rejected = self.request(
            "/features/content-hub/action",
            {"action": "recordInteraction", "articleId": "art_123"},
            {"eventType": "form", "metadata": {"email": "persona@example.com"}},
        )
        self.assertEqual(rejected["statusCode"], 400)
        self.assertNotIn("persona@example.com", rejected["body"])


    def test_media_upload_accepts_public_metadata_without_signed_url(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "uploadAsset"},
            {
                "fileName": "foto.png",
                "mimeType": "image/png",
                "publicUrl": "https://cdn.example.test/foto.png",
                "title": "Foto",
            },
        )
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body(response)["data"]["asset"]["kind"], "image")

    def test_media_upload_accepts_browser_upload_bridge_data_base64(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "uploadAsset"},
            {
                "upload": {
                    "name": "foto.png",
                    "mimeType": "image/png",
                    "dataBase64": base64.b64encode(b"asset").decode("ascii"),
                },
                "metadata": {"alt": "Foto del editor"},
            },
        )
        self.assertEqual(response["statusCode"], 200)
        asset = body(response)["data"]["asset"]
        self.assertEqual(asset["kind"], "image")
        self.assertEqual(asset["fileName"], "foto.png")

    def test_media_upload_rejects_signed_url(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "uploadAsset"},
            {
                "fileName": "foto.png",
                "mimeType": "image/png",
                "publicUrl": "https://cdn.example.test/foto.png?X-Amz-Signature=abc",
            },
        )
        self.assertEqual(response["statusCode"], 400)
        self.assertNotIn("X-Amz-Signature", response["body"])


if __name__ == "__main__":
    unittest.main()
