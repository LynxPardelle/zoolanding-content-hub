import base64
import hashlib
import io
import json
import pathlib
import re
import unittest
from copy import deepcopy

import public_media_lambda as public_media

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
PAYLOAD = b"safe-public-image"
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


def _event(
    *,
    article_id="article-1",
    locale="en",
    revision_id="revision-1",
    asset_id="asset-1",
    variant_id="w768",
    headers=None,
):
    path = (
        "/features/content-hub-v2/public-media/"
        f"{article_id}/{locale}/{revision_id}/{asset_id}/{variant_id}"
    )
    return {
        "rawPath": path,
        "rawQueryString": "",
        "headers": (
            {"x-forwarded-host": "test.zoolandingpage.com.mx"}
            if headers is None
            else headers
        ),
        "pathParameters": {
            "articleId": article_id,
            "locale": locale,
            "revisionId": revision_id,
            "assetId": asset_id,
            "variantId": variant_id,
        },
        "requestContext": {"http": {"method": "GET", "path": path}},
    }


def _manifest():
    return {
        "pk": (
            "LIVE_MEDIA#test#thehairnarrative.com#thehairnarrative-com-journal#"
            "article-1#en#revision-1"
        ),
        "sk": "MANIFEST#V1",
        "recordType": "THN_CONTENT_HUB_V2_LIVE_MEDIA_MANIFEST",
        "schemaVersion": 1,
        "environment": "test",
        "domain": "thehairnarrative.com",
        "hubId": "thehairnarrative-com-journal",
        "articleId": "article-1",
        "locale": "en",
        "revisionId": "revision-1",
        "status": "published",
        "visibility": "public",
        "deliveryState": "live",
        "variants": [
            {
                "assetId": "asset-1",
                "variantId": "w768",
                "objectKey": (
                    "content-hubs/test/thehairnarrative-com-journal/published/"
                    "thehairnarrative.com/en/article-1/revision-1/media/asset-1/w768.jpg"
                ),
                "versionId": "s3-version-1",
                "contentType": "image/jpeg",
                "bytes": len(PAYLOAD),
                "sha256": PAYLOAD_SHA256,
            }
        ],
    }


class FakeRuntime:
    def __init__(self, manifest=None, payload=PAYLOAD):
        self.manifest = deepcopy(_manifest() if manifest is None else manifest)
        self.payload = payload
        self.calls = []

    def load_live_manifest(self, *, partition_key, sort_key):
        self.calls.append(("load", partition_key, sort_key))
        return deepcopy(self.manifest)

    def get_exact_variant(self, variant):
        self.calls.append(("get", variant))
        return self.payload


class PublicMediaRequestTests(unittest.TestCase):
    def test_declared_byte_limit_fits_buffered_lambda_base64_response(self):
        encoded_body_bytes = 4 * ((public_media.MAX_VARIANT_BYTES + 2) // 3)

        self.assertLess(
            encoded_body_bytes + (16 * 1024),
            6 * 1024 * 1024,
        )

    def test_serves_only_the_exact_live_immutable_variant(self):
        runtime = FakeRuntime()

        response = public_media.handle_request(_event(), runtime=runtime)

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(response["isBase64Encoded"])
        self.assertEqual(base64.b64decode(response["body"]), PAYLOAD)
        self.assertEqual(response["headers"]["content-type"], "image/jpeg")
        self.assertEqual(
            response["headers"]["cache-control"],
            "public, max-age=31536000, s-maxage=31536000, immutable",
        )
        self.assertEqual(response["headers"]["x-content-type-options"], "nosniff")
        self.assertEqual(response["headers"]["etag"], f'"sha256-{PAYLOAD_SHA256}"')
        self.assertEqual(
            runtime.calls[0],
            (
                "load",
                (
                    "LIVE_MEDIA#test#thehairnarrative.com#thehairnarrative-com-journal#"
                    "article-1#en#revision-1"
                ),
                "MANIFEST#V1",
            ),
        )
        self.assertEqual(runtime.calls[1][0], "get")
        resolved = runtime.calls[1][1]
        self.assertEqual(resolved.version_id, "s3-version-1")
        self.assertTrue(resolved.object_key.endswith("/media/asset-1/w768.jpg"))

    def test_malformed_paths_methods_queries_and_admin_origin_fail_before_io(self):
        cases = []
        traversal = _event(article_id="..")
        cases.append(traversal)
        cases.append(_event(locale="fr"))
        cases.append(_event(variant_id="original"))

        encoded = _event()
        encoded["rawPath"] = encoded["rawPath"].replace("article-1", "article%2F1")
        cases.append(encoded)

        mismatch = _event()
        mismatch["pathParameters"]["assetId"] = "asset-2"
        cases.append(mismatch)

        extra_parameter = _event()
        extra_parameter["pathParameters"]["bucket"] = "private-store"
        cases.append(extra_parameter)

        wrong_method = _event()
        wrong_method["requestContext"]["http"]["method"] = "POST"
        cases.append(wrong_method)

        query = _event()
        query["rawQueryString"] = "bucket=private-store"
        query["queryStringParameters"] = {"bucket": "private-store"}
        cases.append(query)

        body = _event()
        body["body"] = json.dumps({"key": "private/object"})
        cases.append(body)

        cases.append(
            _event(headers={"x-forwarded-host": "admin-test.thehairnarrative.com"})
        )
        cases.append(_event(headers={}))
        cases.append(
            _event(headers={"x-forwarded-host": "api.example.execute-api.test"})
        )
        cases.append(
            _event(headers={"x-forwarded-host": "test.zoolandingpage.com.mx:8443"})
        )
        cases.append(
            _event(
                headers={
                    "X-Forwarded-Host": "test.zoolandingpage.com.mx",
                    "x-forwarded-host": "admin-test.thehairnarrative.com",
                }
            )
        )

        for event in cases:
            with self.subTest(event=event):
                runtime = FakeRuntime()
                response = public_media.handle_request(event, runtime=runtime)
                self.assertEqual(response["statusCode"], 404)
                self.assertEqual(
                    json.loads(response["body"]), {"ok": False, "code": "not_found"}
                )
                self.assertEqual(response["headers"]["cache-control"], "no-store")
                self.assertEqual(runtime.calls, [])

    def test_draft_working_orphan_withdrawn_wrong_scope_and_zoosite_never_reach_s3(
        self,
    ):
        mutations = [
            ("status", "draft"),
            ("visibility", "private"),
            ("deliveryState", "working"),
            ("deliveryState", "prepared-orphan"),
            ("deliveryState", "withdrawn"),
            ("environment", "prod"),
            ("domain", "zoositioweb.com.mx"),
            ("hubId", "zoosite-main"),
            ("articleId", "other-article"),
            ("locale", "es"),
            ("revisionId", "working-revision"),
            (
                "pk",
                "LIVE_MEDIA#test#zoositioweb.com.mx#zoosite-main#article-1#en#revision-1",
            ),
            ("sk", "MANIFEST#WORKING"),
        ]
        manifests = []
        for field, value in mutations:
            manifest = _manifest()
            manifest[field] = value
            manifests.append(manifest)
        withdrawn_marker = _manifest()
        withdrawn_marker["withdrawnAt"] = "2026-09-04T12:00:00Z"
        manifests.append(withdrawn_marker)

        for manifest in manifests:
            with self.subTest(manifest=manifest):
                runtime = FakeRuntime(manifest=manifest)
                response = public_media.handle_request(_event(), runtime=runtime)
                self.assertEqual(response["statusCode"], 404)
                self.assertEqual([call[0] for call in runtime.calls], ["load"])

    def test_manifest_must_name_one_canonical_versioned_variant(self):
        invalid_variants = []

        no_target = _manifest()
        no_target["variants"][0]["variantId"] = "w480"
        invalid_variants.append(no_target)

        duplicate = _manifest()
        duplicate["variants"].append(deepcopy(duplicate["variants"][0]))
        invalid_variants.append(duplicate)

        for field, value in (
            ("objectKey", "private/test/secret.jpg"),
            (
                "objectKey",
                (
                    "content-hubs/test/zoosite-main/published/zoositioweb.com.mx/"
                    "en/article-1/revision-1/media/asset-1/w768.jpg"
                ),
            ),
            (
                "objectKey",
                (
                    "content-hubs/test/thehairnarrative-com-journal/published/"
                    "thehairnarrative.com/en/article-1/revision-1/bundle.json"
                ),
            ),
            ("versionId", ""),
            ("contentType", "text/html"),
            ("bytes", 0),
            ("sha256", "not-a-digest"),
        ):
            manifest = _manifest()
            manifest["variants"][0][field] = value
            invalid_variants.append(manifest)

        for manifest in invalid_variants:
            with self.subTest(manifest=manifest):
                runtime = FakeRuntime(manifest=manifest)
                response = public_media.handle_request(_event(), runtime=runtime)
                self.assertEqual(response["statusCode"], 404)
                self.assertEqual([call[0] for call in runtime.calls], ["load"])

    def test_object_digest_and_length_are_revalidated_before_delivery(self):
        for payload in (b"changed", PAYLOAD + b"extra"):
            with self.subTest(payload=payload):
                runtime = FakeRuntime(payload=payload)
                response = public_media.handle_request(_event(), runtime=runtime)
                self.assertEqual(response["statusCode"], 404)
                self.assertEqual([call[0] for call in runtime.calls], ["load", "get"])
                self.assertNotIn("objectKey", response["body"])
                self.assertNotIn("bucket", response["body"].lower())

    def test_unexpected_runtime_failure_is_generic_and_never_cached(self):
        class FailingRuntime:
            def load_live_manifest(self, **_kwargs):
                raise RuntimeError("private-bucket/secret-object")

        response = public_media.handle_request(_event(), runtime=FailingRuntime())

        self.assertEqual(response["statusCode"], 503)
        self.assertEqual(
            json.loads(response["body"]),
            {"ok": False, "code": "service_unavailable"},
        )
        self.assertEqual(response["headers"]["cache-control"], "no-store")
        self.assertNotIn("private-bucket", response["body"])
        self.assertNotIn("secret-object", response["body"])


class _DynamoDbClient:
    def __init__(self):
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        return {}


class _S3Client:
    def __init__(self, payload=PAYLOAD, response_overrides=None):
        self.calls = []
        self.payload = payload
        self.response_overrides = response_overrides or {}

    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        response = {
            "Body": io.BytesIO(self.payload),
            "ContentLength": len(self.payload),
            "ContentType": "image/jpeg",
            "VersionId": "s3-version-1",
        }
        response.update(self.response_overrides)
        return response


class PublicMediaAwsRuntimeTests(unittest.TestCase):
    def test_runtime_uses_one_strong_exact_manifest_read_and_versioned_get(self):
        dynamodb = _DynamoDbClient()
        s3 = _S3Client()
        runtime = public_media.AwsPublicMediaRuntime(
            dynamodb_client=dynamodb,
            s3_client=s3,
            metadata_table_name="metadata-table",
            packages_bucket_name="packages-bucket",
        )

        self.assertIsNone(
            runtime.load_live_manifest(
                partition_key=(
                    "LIVE_MEDIA#test#thehairnarrative.com#thehairnarrative-com-journal#"
                    "article-1#en#revision-1"
                ),
                sort_key="MANIFEST#V1",
            )
        )
        variant = public_media.LiveVariant(
            object_key=_manifest()["variants"][0]["objectKey"],
            version_id="s3-version-1",
            content_type="image/jpeg",
            byte_length=len(PAYLOAD),
            sha256=PAYLOAD_SHA256,
        )
        self.assertEqual(runtime.get_exact_variant(variant), PAYLOAD)

        self.assertEqual(
            dynamodb.calls,
            [
                {
                    "TableName": "metadata-table",
                    "Key": {
                        "pk": {
                            "S": (
                                "LIVE_MEDIA#test#thehairnarrative.com#"
                                "thehairnarrative-com-journal#article-1#en#revision-1"
                            )
                        },
                        "sk": {"S": "MANIFEST#V1"},
                    },
                    "ConsistentRead": True,
                }
            ],
        )
        self.assertEqual(
            s3.calls,
            [
                {
                    "Bucket": "packages-bucket",
                    "Key": variant.object_key,
                    "VersionId": "s3-version-1",
                }
            ],
        )

    def test_runtime_rejects_unexpected_s3_content_encoding(self):
        runtime = public_media.AwsPublicMediaRuntime(
            dynamodb_client=_DynamoDbClient(),
            s3_client=_S3Client(response_overrides={"ContentEncoding": "gzip"}),
            metadata_table_name="metadata-table",
            packages_bucket_name="packages-bucket",
        )
        variant = public_media.LiveVariant(
            object_key=_manifest()["variants"][0]["objectKey"],
            version_id="s3-version-1",
            content_type="image/jpeg",
            byte_length=len(PAYLOAD),
            sha256=PAYLOAD_SHA256,
        )

        with self.assertRaises(public_media.PublicMediaNotFound):
            runtime.get_exact_variant(variant)


def _resource(template: str, logical_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(logical_id)}:\s*$.*?(?=^  [A-Za-z0-9]+:\s*$|\Z)",
        template,
    )
    if match is None:
        raise AssertionError(f"Missing resource: {logical_id}")
    return match.group(0)


class PublicMediaTemplateTests(unittest.TestCase):
    def test_role_can_only_strongly_resolve_live_manifest_and_versioned_media(self):
        template = (PROJECT_ROOT / "template.yaml").read_text(encoding="utf-8")
        role = _resource(template, "ThnContentHubV2PublicMediaRole")
        function = _resource(template, "ThnContentHubV2PublicMediaFunction")

        self.assertIn("dynamodb:GetItem", role)
        self.assertIn(
            "LIVE_MEDIA#test#thehairnarrative.com#thehairnarrative-com-journal#*",
            role,
        )
        self.assertNotIn("HUB#thehairnarrative-com-journal", role)
        self.assertIn("s3:GetObjectVersion", role)
        self.assertNotIn("s3:GetObject\n", role)
        self.assertNotIn("s3:ListBucket", role)
        for forbidden in (
            "s3:PutObject",
            "s3:DeleteObject",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "lambda:InvokeFunction",
        ):
            self.assertNotIn(forbidden, role)
        self.assertIn(
            "/content-hubs/test/thehairnarrative-com-journal/published/"
            "thehairnarrative.com/*/*/*/media/*/*",
            role,
        )
        self.assertNotIn("published/*", role)
        from tests.test_thn_content_hub_v2_task_019_template import _thn_routes
        self.assertIn(("ThnContentHubV2PublicMediaFunction", "GET",
            "/features/content-hub-v2/public-media/{articleId}/{locale}/{revisionId}/{assetId}/{variantId}"), _thn_routes(template))
        self.assertNotIn("Events:", function)


if __name__ == "__main__":
    unittest.main()
