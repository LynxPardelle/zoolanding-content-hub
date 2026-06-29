import base64
import json
import os
import unittest
from pathlib import Path
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


def encoded_role_policy_config(role_policies):
    raw = json.loads(base64.b64decode(encoded_config()).decode("utf-8"))
    hub = raw["profiles"][0]["contentHubs"][0]
    hub.pop("roles", None)
    hub["rolePolicies"] = role_policies
    return base64.b64encode(json.dumps(raw, separators=(",", ":")).encode("utf-8")).decode("ascii")


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

    def delete_metadata(self, pk, sk):
        self.metadata.pop((pk, sk), None)

    def query_metadata(self, pk, sk_prefix):
        return [dict(item) for (item_pk, item_sk), item in self.metadata.items() if item_pk == pk and item_sk.startswith(sk_prefix)]

    def put_media(self, item):
        self.media[(item["pk"], item["sk"])] = dict(item)

    def query_media(self, pk, sk_prefix):
        return [dict(item) for (item_pk, item_sk), item in self.media.items() if item_pk == pk and item_sk.startswith(sk_prefix)]

    def put_moderation(self, item):
        self.moderation[(item["pk"], item["sk"])] = dict(item)

    def delete_moderation(self, pk, sk):
        self.moderation.pop((pk, sk), None)

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

    def test_role_policies_authorize_by_action_scoped_permission(self):
        os.environ["CONTENT_HUB_CONFIG_JSON_BASE64"] = encoded_role_policy_config([
            {
                "roleId": "blog-editor",
                "groups": ["zoosite-blog-editor"],
                "permissions": [
                    "blog:article:read",
                    "blog:article:create",
                    "blog:article:update",
                    "blog:article:validate",
                ],
            },
            {
                "roleId": "blog-publisher",
                "groups": ["zoosite-blog-publisher"],
                "permissions": [
                    "blog:article:read",
                    "blog:article:publish",
                ],
            },
        ])
        content_hub._CONFIG_CACHE.clear()
        self.store.roles = ["zoosite-blog-editor"]

        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Policy article", "summary": "Permisos accionables"},
        )
        self.assertEqual(create["statusCode"], 200)
        article_id = body(create)["data"]["article"]["articleId"]

        read = self.request("/features/content-hub/read", {"read": "articleDetail"}, {"articleId": article_id}, csrf=False)
        self.assertEqual(read["statusCode"], 200)

        self.store.roles = ["zoosite-blog-publisher"]
        published = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id, "revisionId": "rev_001"},
        )
        self.assertEqual(published["statusCode"], 200)

        self.store.roles = ["zoosite-blog-editor"]
        preview = self.request(
            "/features/content-hub/read",
            {"read": "publicBundlePreview", "articleId": article_id},
            csrf=False,
        )
        self.assertEqual(preview["statusCode"], 200)

        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id, "revisionId": "rev_001"},
        )
        self.assertEqual(publish["statusCode"], 403)

    def test_role_policy_config_rejects_wildcard_permission(self):
        os.environ["CONTENT_HUB_CONFIG_JSON_BASE64"] = encoded_role_policy_config([
            {
                "roleId": "bad-role",
                "groups": ["zoosite-admin"],
                "permissions": ["blog:article:*"],
            },
        ])
        content_hub._CONFIG_CACHE.clear()

        response = self.request("/features/content-hub/read", {"read": "articleList"}, csrf=False)
        self.assertEqual(response["statusCode"], 500)
        self.assertEqual(body(response)["error"], "Content hub config is invalid")

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
        published_article = self.store.get_metadata(f"HUB#zoosite-main", f"ARTICLE#{article['articleId']}")
        self.assertEqual(published_article["status"], "published")
        self.assertEqual(published_article["visibility"], "public")

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
        fake_dynamodb.Table.return_value.query.return_value = {"Items": []}
        with patch.dict(os.environ, env, clear=True), \
             patch("lambda_function._dynamodb_resource", return_value=fake_dynamodb), \
             patch("lambda_function._s3_client") as s3_client:
            store = content_hub.DynamoContentHubStore()
            s3_client.assert_not_called()

            store.query_metadata("HUB#zoosite-main", "ARTICLE#")
            s3_client.assert_not_called()

            _ = store.s3
            s3_client.assert_called_once()

    def test_dynamo_query_metadata_reads_every_page(self):
        class PagedTable:
            def __init__(self):
                self.calls = []

            def query(self, **kwargs):
                self.calls.append(kwargs)
                if len(self.calls) == 1:
                    return {
                        "Items": [{"pk": "HUB#zoosite-main", "sk": "ARTICLE#1"}],
                        "LastEvaluatedKey": {"pk": "HUB#zoosite-main", "sk": "ARTICLE#1"},
                    }
                return {"Items": [{"pk": "HUB#zoosite-main", "sk": "ARTICLE#2"}]}

        env = {
            "AUTH_SESSION_TABLE_NAME": "auth-session",
            "AUTH_USER_STATE_TABLE_NAME": "auth-user",
            "CONTENT_HUB_METADATA_TABLE_NAME": "metadata",
            "CONTENT_HUB_MEDIA_TABLE_NAME": "media",
            "CONTENT_HUB_MODERATION_TABLE_NAME": "moderation",
            "CONTENT_HUB_INTERACTIONS_TABLE_NAME": "interactions",
            "CONTENT_HUB_PACKAGES_BUCKET_NAME": "packages",
        }
        table = PagedTable()
        fake_dynamodb = unittest.mock.Mock()
        fake_dynamodb.Table.return_value = table

        with patch.dict(os.environ, env, clear=True), patch("lambda_function._dynamodb_resource", return_value=fake_dynamodb):
            store = content_hub.DynamoContentHubStore()
            items = store.query_metadata("HUB#zoosite-main", "ARTICLE#")

        self.assertEqual([item["sk"] for item in items], ["ARTICLE#1", "ARTICLE#2"])
        self.assertEqual(table.calls[1]["ExclusiveStartKey"], {"pk": "HUB#zoosite-main", "sk": "ARTICLE#1"})

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
        published_article = self.store.get_metadata(f"HUB#zoosite-main", f"ARTICLE#{article_id}")
        self.assertEqual(published_article["visibility"], "public")
        bundle_key, bundle = next((key, item) for key, item in self.store.objects.items() if item.get("safeArticlePath") == "/blog/publicar")
        self.assertEqual(published_article.get("publishedBundleKey"), bundle_key)
        self.assertEqual(bundle["safeArticlePath"], "/blog/publicar")
        self.assertEqual(bundle["category"]["taxonomyId"], "cat-blog")
        self.assertEqual(bundle["tags"][0]["taxonomyId"], "tag-seo")
        self.assertEqual(bundle["commentPolicy"], "moderated")
        self.assertEqual(bundle["seo"]["canonicalMode"], "custom")
        self.assertEqual(bundle["seo"]["canonical"], "https://zoositioweb.com.mx/blog/publicar")
        self.assertEqual(bundle["analytics"]["piiPolicy"], "no-pii")
        self.assertNotIn("bucket", publish["body"].lower())

    def test_publish_rejects_path_collision_with_another_article(self):
        first = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Primero", "slug": "primero"},
        )
        second = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Segundo", "slug": "segundo"},
        )
        first_id = body(first)["data"]["article"]["articleId"]
        second_id = body(second)["data"]["article"]["articleId"]
        first_publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": first_id, "revisionId": "rev_001"},
            {"path": "/blog/colision"},
        )
        self.assertEqual(first_publish["statusCode"], 200)

        collision = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": second_id, "revisionId": "rev_001"},
            {"path": "/blog/colision"},
        )

        self.assertEqual(collision["statusCode"], 400)
        self.assertEqual(body(collision)["error"], "Article path already exists")
        slug = self.store.get_metadata("SLUG#test#zoositioweb.com.mx#es", "PATH#/blog/colision")
        self.assertEqual(slug["articleId"], first_id)

    def test_unpublish_does_not_remove_slug_owned_by_another_article(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "No borrar ajeno"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        self.store.put_metadata({
            "pk": "SLUG#test#zoositioweb.com.mx#es",
            "sk": "PATH#/blog/ajeno",
            "itemFamily": "SLUG",
            "hubId": "zoosite-main",
            "articleId": "art_other",
            "revisionId": "rev_001",
            "path": "/blog/ajeno",
        })

        unpublish = self.request(
            "/features/content-hub/action",
            {"action": "unpublishArticle", "articleId": article_id},
            {"path": "/blog/ajeno"},
        )

        self.assertEqual(unpublish["statusCode"], 200)
        slug = self.store.get_metadata("SLUG#test#zoositioweb.com.mx#es", "PATH#/blog/ajeno")
        self.assertEqual(slug["articleId"], "art_other")

    def test_publish_rejects_revision_from_another_hub(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Revision ajena"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        revision = self.store.get_metadata(f"ARTICLE#{article_id}", "REVISION#rev_001")
        revision["hubId"] = "other-hub"

        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id, "revisionId": "rev_001"},
            {"path": "/blog/revision-ajena"},
        )

        self.assertEqual(publish["statusCode"], 404)

    def test_publisher_can_approve_unpublish_and_archive_article(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Ciclo editorial", "summary": "Flujo completo"},
        )
        article_id = body(create)["data"]["article"]["articleId"]

        self.store.roles = ["zoosite-blog-publisher"]
        approve = self.request(
            "/features/content-hub/action",
            {"action": "approveArticle", "articleId": article_id},
        )
        self.assertEqual(approve["statusCode"], 200)
        self.assertEqual(body(approve)["data"]["status"], "approved")

        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id, "revisionId": "rev_001"},
            {"path": "/blog/ciclo-editorial"},
        )
        self.assertEqual(publish["statusCode"], 200)
        self.assertIsNotNone(self.store.get_metadata("SLUG#test#zoositioweb.com.mx#es", "PATH#/blog/ciclo-editorial"))

        unpublish = self.request(
            "/features/content-hub/action",
            {"action": "unpublishArticle", "articleId": article_id},
        )
        self.assertEqual(unpublish["statusCode"], 200)
        self.assertEqual(body(unpublish)["data"]["status"], "unpublished")
        article = self.store.get_metadata("HUB#zoosite-main", f"ARTICLE#{article_id}")
        self.assertEqual(article["visibility"], "private")
        self.assertIsNone(self.store.get_metadata("SLUG#test#zoositioweb.com.mx#es", "PATH#/blog/ciclo-editorial"))
        self.assertNotIn("publishedBundleKey", unpublish["body"])

        archive = self.request(
            "/features/content-hub/action",
            {"action": "archiveArticle", "articleId": article_id},
        )
        self.assertEqual(archive["statusCode"], 200)
        self.assertEqual(body(archive)["data"]["status"], "archived")
        article = self.store.get_metadata("HUB#zoosite-main", f"ARTICLE#{article_id}")
        self.assertEqual(article["visibility"], "private")

    def test_editorial_release_flow_creates_updates_reviews_publishes_previews_and_schedules_unpublish(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {
                "articleTitle": "Flujo editorial completo",
                "articleSummary": "Resumen inicial",
                "articleCategory": "web",
                "articleTags": "seo, blog, seo",
                "articleSlug": "flujo-editorial-completo",
                "articleVisibility": "Listo para revisión",
            },
        )
        self.assertEqual(create["statusCode"], 200)
        article_id = body(create)["data"]["article"]["articleId"]
        self.assertEqual(body(create)["data"]["article"]["path"], "/blog/web/flujo-editorial-completo")

        update = self.request(
            "/features/content-hub/action",
            {"action": "updatePackage"},
            {
                "articleId": article_id,
                "revisionId": "rev_release",
                "articleTitle": "Flujo editorial completo actualizado",
                "articleSummary": "Resumen listo para publicar",
                "articleCategory": {"taxonomyId": "web", "slug": "web", "label": "Web"},
                "articleTags": "seo, producto, blog",
                "components": [
                    {
                        "type": "generic-text",
                        "config": {
                            "text": "Contenido editorial aprobado.",
                        },
                    },
                ],
            },
        )
        self.assertEqual(update["statusCode"], 200)
        self.assertNotIn("packageKey", update["body"])

        submit_review = self.request(
            "/features/content-hub/action",
            {"action": "submitReview", "articleId": article_id},
        )
        self.assertEqual(submit_review["statusCode"], 200)
        self.assertEqual(body(submit_review)["data"]["status"], "review")

        self.store.roles = ["zoosite-blog-publisher"]
        approve = self.request(
            "/features/content-hub/action",
            {"action": "approveArticle", "articleId": article_id},
        )
        self.assertEqual(approve["statusCode"], 200)
        self.assertEqual(body(approve)["data"]["status"], "approved")

        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id, "revisionId": "rev_release"},
            {
                "seoTitle": "Flujo editorial completo SEO",
                "seoDescription": "Prueba completa de publicación editorial.",
            },
        )
        self.assertEqual(publish["statusCode"], 200)
        self.assertEqual(body(publish)["data"]["path"], "/blog/web/flujo-editorial-completo")
        self.assertNotIn("publishedBundleKey", publish["body"])

        self.store.roles = ["zoosite-admin"]
        detail = self.request(
            "/features/content-hub/read",
            {"read": "articleDetail", "articleId": article_id},
            csrf=False,
        )
        self.assertEqual(detail["statusCode"], 200)
        self.assertEqual(body(detail)["data"]["item"]["status"], "published")
        self.assertEqual(body(detail)["data"]["item"]["latestRevisionId"], "rev_release")

        preview = self.request(
            "/features/content-hub/read",
            {"read": "publicBundlePreview", "articleId": article_id},
            csrf=False,
        )
        self.assertEqual(preview["statusCode"], 200)
        preview_bundle = body(preview)["data"]["bundle"]
        self.assertEqual(preview_bundle["articleId"], article_id)
        self.assertEqual(preview_bundle["seo"]["title"], "Flujo editorial completo SEO")
        self.assertEqual(preview_bundle["components"][0]["type"], "generic-text")

        schedule = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {
                "scheduleAction": "unpublish",
                "unpublishAt": "2000-01-01T00:00:00Z",
                "timezone": "UTC",
            },
        )
        self.assertEqual(schedule["statusCode"], 200)
        self.assertEqual(body(schedule)["data"]["schedule"]["action"], "unpublish")

        scheduled_run = content_hub.lambda_handler({"contentHubTask": "runDueSchedules"}, None)
        self.assertEqual(scheduled_run["data"]["processed"], 1)
        article = self.store.get_metadata("HUB#zoosite-main", f"ARTICLE#{article_id}")
        self.assertEqual(article["status"], "unpublished")
        self.assertEqual(article["visibility"], "private")
        self.assertIsNone(self.store.get_metadata("SLUG#test#zoositioweb.com.mx#es", "PATH#/blog/web/flujo-editorial-completo"))

    def test_editor_cannot_approve_or_unpublish_article(self):
        self.store.roles = ["zoosite-blog-editor"]
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Permisos ciclo editorial"},
        )
        article_id = body(create)["data"]["article"]["articleId"]

        approve = self.request(
            "/features/content-hub/action",
            {"action": "approveArticle", "articleId": article_id},
        )
        self.assertEqual(approve["statusCode"], 403)

        unpublish = self.request(
            "/features/content-hub/action",
            {"action": "unpublishArticle", "articleId": article_id},
        )
        self.assertEqual(unpublish["statusCode"], 403)

    def test_status_transition_requires_existing_article(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "submitReview", "articleId": "art_missing"},
        )
        self.assertEqual(response["statusCode"], 404)

    def test_schedule_requires_existing_article_and_safe_publish_time(self):
        missing = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": "art_missing"},
            {"publishAt": "2026-07-01T10:00:00Z", "timezone": "America/Mexico_City"},
        )
        self.assertEqual(missing["statusCode"], 404)

        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Programar", "summary": "Programacion segura"},
        )
        article_id = body(create)["data"]["article"]["articleId"]

        invalid_time = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"publishAt": "not-a-date", "timezone": "America/Mexico_City"},
        )
        self.assertEqual(invalid_time["statusCode"], 400)
        self.assertEqual(body(invalid_time)["error"], "Invalid publish time")

        invalid_timezone = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"publishAt": "2026-07-01T10:00:00Z", "timezone": "../UTC"},
        )
        self.assertEqual(invalid_timezone["statusCode"], 400)
        self.assertEqual(body(invalid_timezone)["error"], "Invalid timezone")

    def test_schedule_publish_uses_existing_immutable_revision(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Revision programada", "summary": "Revision fija"},
        )
        article_id = body(create)["data"]["article"]["articleId"]

        schedule = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"publishAt": "2026-07-01T10:00:00Z", "timezone": "America/Mexico_City"},
        )
        self.assertEqual(schedule["statusCode"], 200)
        scheduled = body(schedule)["data"]["schedule"]
        self.assertEqual(scheduled["revisionId"], "rev_001")
        self.assertEqual(scheduled["publishAt"], "2026-07-01T10:00:00Z")
        self.assertEqual(scheduled["timezone"], "America/Mexico_City")
        self.assertNotIn("createdBy", schedule["body"])

        rejected = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"publishAt": "2026-07-01T10:00:00Z", "revisionId": "rev_missing"},
        )
        self.assertEqual(rejected["statusCode"], 404)
        self.assertEqual(body(rejected)["error"], "Revision not found")

    def test_schedule_list_and_cancel_schedule_are_supported(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Programable"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        schedule = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"publishAt": "2026-07-01T10:00:00Z", "timezone": "America/Mexico_City"},
        )
        self.assertEqual(schedule["statusCode"], 200)
        schedule_id = body(schedule)["data"]["schedule"]["scheduleId"]

        read = self.request(
            "/features/content-hub/read",
            {"read": "scheduleList", "articleId": article_id},
            csrf=False,
        )
        self.assertEqual(read["statusCode"], 200)
        self.assertEqual([item["scheduleId"] for item in body(read)["data"]["items"]], [schedule_id])

        cancel = self.request(
            "/features/content-hub/action",
            {"action": "cancelSchedule", "articleId": article_id, "scheduleId": schedule_id},
            {},
        )
        self.assertEqual(cancel["statusCode"], 200)
        self.assertEqual(body(cancel)["data"]["schedule"]["status"], "canceled")
        self.assertEqual(self.store.query_metadata("SCHEDULE#test", "DUE#"), [])

    def test_schedule_unpublish_validates_unpublish_time_without_revision(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Desprogramar", "summary": "Salida programada"},
        )
        article_id = body(create)["data"]["article"]["articleId"]

        schedule = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {
                "scheduleAction": "unpublish",
                "unpublishAt": "2026-07-02T18:30:00-06:00",
                "timezone": "America/Mexico_City",
            },
        )
        self.assertEqual(schedule["statusCode"], 200)
        scheduled = body(schedule)["data"]["schedule"]
        self.assertEqual(scheduled["action"], "unpublish")
        self.assertNotIn("revisionId", scheduled)
        self.assertEqual(scheduled["unpublishAt"], "2026-07-02T18:30:00-06:00")

        invalid = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"scheduleAction": "unpublish", "publishAt": "2026-07-02T18:30:00Z"},
        )
        self.assertEqual(invalid["statusCode"], 400)
        self.assertEqual(body(invalid)["error"], "unpublishAt is required")

    def test_scheduler_event_publishes_due_schedule_and_removes_it(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Publicacion vencida", "slug": "publicacion-vencida"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        article = self.store.get_metadata("HUB#zoosite-main", f"ARTICLE#{article_id}")
        schedule = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"publishAt": "2000-01-01T00:00:00Z", "timezone": "UTC"},
        )
        schedule_data = body(schedule)["data"]["schedule"]

        result = content_hub.lambda_handler({"contentHubTask": "runDueSchedules"}, None)

        self.assertEqual(result["data"]["processed"], 1)
        self.assertEqual(result["data"]["failed"], 0)
        published = self.store.get_metadata("HUB#zoosite-main", f"ARTICLE#{article_id}")
        self.assertEqual(published["status"], "published")
        slug = self.store.get_metadata("SLUG#test#zoositioweb.com.mx#es", f"PATH#{article['path']}")
        self.assertEqual(slug["articleId"], article_id)
        remaining = self.store.query_metadata("SCHEDULE#test", "DUE#")
        self.assertEqual([item["scheduleId"] for item in remaining], [])
        self.assertEqual(result["data"]["items"][0]["scheduleId"], schedule_data["scheduleId"])

    def test_scheduler_event_leaves_future_schedule_pending(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Futura", "slug": "futura"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        schedule = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"publishAt": "2999-01-01T00:00:00Z", "timezone": "UTC"},
        )
        schedule_id = body(schedule)["data"]["schedule"]["scheduleId"]

        result = content_hub.lambda_handler({"contentHubTask": "runDueSchedules"}, None)

        self.assertEqual(result["data"]["processed"], 0)
        remaining = self.store.query_metadata("SCHEDULE#test", "DUE#")
        self.assertEqual([item["scheduleId"] for item in remaining], [schedule_id])

    def test_scheduler_event_records_invalid_schedule_without_stopping_batch(self):
        self.store.put_metadata({
            "pk": "SCHEDULE#test",
            "sk": "DUE#bad#ARTICLE#bad#ACTION#publish",
            "itemFamily": "SCHEDULE",
            "scheduleId": "sch_bad",
            "hubId": "zoosite-main",
            "domain": "zoositioweb.com.mx",
            "authProfileId": "staff",
            "articleId": "art_bad",
            "revisionId": "rev_001",
            "action": "publish",
            "scheduledAt": "bad",
        })

        result = content_hub.lambda_handler({"contentHubTask": "runDueSchedules"}, None)

        self.assertEqual(result["data"]["processed"], 0)
        self.assertEqual(result["data"]["failed"], 1)
        self.assertEqual(result["data"]["failures"][0]["scheduleId"], "sch_bad")
        failed = self.store.get_metadata("SCHEDULE#test", "DUE#bad#ARTICLE#bad#ACTION#publish")
        self.assertEqual(failed["lastError"], "Invalid schedule time")

    def test_scheduler_event_unpublishes_due_schedule_and_removes_slug(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Retiro vencido", "slug": "retiro-vencido"},
        )
        article_id = body(create)["data"]["article"]["articleId"]
        article = self.store.get_metadata("HUB#zoosite-main", f"ARTICLE#{article_id}")
        publish = self.request(
            "/features/content-hub/action",
            {"action": "publish", "articleId": article_id, "revisionId": "rev_001"},
        )
        self.assertEqual(publish["statusCode"], 200)
        schedule = self.request(
            "/features/content-hub/action",
            {"action": "schedule", "articleId": article_id},
            {"scheduleAction": "unpublish", "unpublishAt": "2000-01-01T00:00:00Z", "timezone": "UTC"},
        )
        self.assertEqual(schedule["statusCode"], 200)

        result = content_hub.lambda_handler({"detail": {"contentHubTask": "runDueSchedules"}}, None)

        self.assertEqual(result["data"]["processed"], 1)
        unpublished = self.store.get_metadata("HUB#zoosite-main", f"ARTICLE#{article_id}")
        self.assertEqual(unpublished["status"], "unpublished")
        self.assertIsNone(self.store.get_metadata("SLUG#test#zoositioweb.com.mx#es", f"PATH#{article['path']}"))

    def test_revision_list_requires_existing_article_and_redacts_actor(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Revisiones", "summary": "Historial seguro"},
        )
        article_id = body(create)["data"]["article"]["articleId"]

        read = self.request(
            "/features/content-hub/read",
            {"read": "revisionList"},
            {"articleId": article_id},
            csrf=False,
        )
        self.assertEqual(read["statusCode"], 200)
        revision = body(read)["data"]["items"][0]
        self.assertEqual(revision["revisionId"], "rev_001")
        self.assertNotIn("createdBy", revision)
        self.assertNotIn("admin-sub", read["body"])

        missing = self.request(
            "/features/content-hub/read",
            {"read": "revisionList"},
            {"articleId": "art_missing"},
            csrf=False,
        )
        self.assertEqual(missing["statusCode"], 404)

    def test_restore_revision_requires_existing_article_and_safe_revision_id(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Restauracion segura", "summary": "Sin fantasma"},
        )
        article_id = body(create)["data"]["article"]["articleId"]

        unsafe = self.request(
            "/features/content-hub/action",
            {"action": "restoreRevision"},
            {"articleId": article_id, "revisionId": "../rev_001"},
        )
        self.assertEqual(unsafe["statusCode"], 400)
        self.assertEqual(body(unsafe)["error"], "Invalid id")

        missing_article = self.request(
            "/features/content-hub/action",
            {"action": "restoreRevision"},
            {"articleId": "art_missing", "revisionId": "rev_001"},
        )
        self.assertEqual(missing_article["statusCode"], 404)
        self.assertIsNone(self.store.get_metadata("HUB#zoosite-main", "ARTICLE#art_missing"))

        restore = self.request(
            "/features/content-hub/action",
            {"action": "restoreRevision"},
            {"articleId": article_id, "revisionId": "rev_001"},
        )
        self.assertEqual(restore["statusCode"], 200)
        self.assertEqual(body(restore)["data"]["revisionId"], "rev_001")

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

    def test_update_package_requires_existing_article(self):
        update = self.request(
            "/features/content-hub/action",
            {"action": "updatePackage"},
            {"articleId": "art_missing", "revisionId": "rev_missing", "components": []},
        )

        self.assertEqual(update["statusCode"], 404)
        self.assertIsNone(self.store.get_metadata("HUB#zoosite-main", "ARTICLE#art_missing"))

    def test_update_package_updates_public_identity_fields_and_taxonomy(self):
        create = self.request(
            "/features/content-hub/action",
            {"action": "createArticle"},
            {"title": "Antes", "summary": "Resumen anterior"},
        )
        article_id = body(create)["data"]["article"]["articleId"]

        update = self.request(
            "/features/content-hub/action",
            {"action": "updatePackage"},
            {
                "articleId": article_id,
                "revisionId": "rev_update",
                "title": "Despues",
                "summary": "Resumen actualizado",
                "slug": "despues",
                "path": "/blog/web/despues",
                "language": "es",
                "visibility": "public",
                "category": {"taxonomyId": "cat-web", "slug": "web", "label": "Web"},
                "tags": "seo, sitios web, seo",
                "components": [],
            },
        )

        self.assertEqual(update["statusCode"], 200)
        article = self.store.get_metadata("HUB#zoosite-main", f"ARTICLE#{article_id}")
        self.assertEqual(article["title"], "Despues")
        self.assertEqual(article["summary"], "Resumen actualizado")
        self.assertEqual(article["slug"], "despues")
        self.assertEqual(article["path"], "/blog/web/despues")
        self.assertEqual(article["visibility"], "public")
        self.assertEqual(article["categorySlug"], "web")
        self.assertEqual(article["category"]["taxonomyId"], "cat-web")
        self.assertEqual([tag["slug"] for tag in article["tags"]], ["seo", "sitios-web"])
        self.assertIsNotNone(self.store.get_metadata("HUB#zoosite-main", "TAXONOMY#category#cat-web"))
        self.assertIsNotNone(self.store.get_metadata("HUB#zoosite-main", "TAXONOMY#tag#seo"))

    def test_template_allows_delete_item_for_public_slug_cleanup(self):
        template = Path("template.yaml").read_text(encoding="utf-8")
        self.assertIn("dynamodb:DeleteItem", template)

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

    def test_moderate_comment_updates_existing_queue_record(self):
        queued = self.request(
            "/features/content-hub/action",
            {"action": "queueComment", "articleId": "art_123"},
            {"commentText": "Comentario listo para revisar"},
        )
        self.assertEqual(queued["statusCode"], 200)
        comment_id = body(queued)["data"]["comment"]["commentId"]

        moderated = self.request(
            "/features/content-hub/action",
            {"action": "moderateComment", "commentId": comment_id},
            {"moderationStatus": "approved"},
        )

        self.assertEqual(moderated["statusCode"], 200)
        self.assertEqual(body(moderated)["data"]["moderation"]["status"], "approved")
        moderation_rows = self.store.query_moderation("HUB#zoosite-main", "MODERATION#")
        self.assertEqual(len(moderation_rows), 1)
        self.assertEqual(moderation_rows[0]["commentId"], comment_id)
        self.assertEqual(moderation_rows[0]["articleId"], "art_123")
        self.assertEqual(moderation_rows[0]["bodyPreview"], "Comentario listo para revisar")

    def test_moderate_comment_requires_existing_comment(self):
        response = self.request(
            "/features/content-hub/action",
            {"action": "moderateComment", "commentId": "cmt_missing"},
            {"moderationStatus": "approved"},
        )

        self.assertEqual(response["statusCode"], 404)

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
