"""Local opt-in consumer compatibility; this does not sign or deploy C."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def spanish_only_index():
    localized = {"title": "Synthetic Spanish article", "summary": "Synthetic summary",
        "path": "/the-journal/formas-nupciales/synthetic", "categorySlug": "formas-nupciales",
        "publishedAt": "2026-09-01T00:00:00Z", "updatedAt": "2026-09-07T00:00:00Z",
        "canonicalPath": "/the-journal/formas-nupciales/synthetic", "robots": "index,follow",
        "imageSrc": "/features/content-hub-v2/public-media/synthetic/es/r1/cover/w768", "imageAlt": "Synthetic"}
    return {"pk": "HUB#thehairnarrative-com-journal", "sk": "ARTICLE#synthetic",
        "articleId": "synthetic", "locale": "es", "status": "published", "visibility": "public",
        **localized, "localizations": {"es": localized},
        "publishedBundleKey": "content-hubs/test/thehairnarrative-com-journal/published/thehairnarrative.com/es/synthetic/r1/bundle.json"}


@unittest.skipUnless(os.environ.get("THN_RUNTIME_READ_SOURCE"), "Local Runtime Read candidate must be selected explicitly")
class OptInRuntimeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(os.environ["THN_RUNTIME_READ_SOURCE"]) / "lambda_function.py"
        spec = importlib.util.spec_from_file_location("readonly_thn_contract", source)
        cls.runtime = importlib.util.module_from_spec(spec)
        common_spec = importlib.util.spec_from_file_location("zoolanding_lambda_common", source.with_name("zoolanding_lambda_common.py"))
        common = importlib.util.module_from_spec(common_spec)
        common_spec.loader.exec_module(common)
        with patch.dict(sys.modules, {"zoolanding_lambda_common": common}):
            spec.loader.exec_module(cls.runtime)

    def test_live_spanish_locale_remains_readable(self):
        result = self.runtime._content_hub_article_summary(spanish_only_index(), {"localePolicy": "published-only"}, "es")
        self.assertEqual(result["path"], "/the-journal/formas-nupciales/synthetic")

    def test_unpublished_english_locale_must_be_excluded(self):
        # Explicit local scope amendment approved on 2026-09-07. The deployed
        # reader remains unchanged; only this opt-in candidate may pass the gate.
        self.assertIsNone(self.runtime._content_hub_article_summary(
            spanish_only_index(), {"localePolicy": "published-only"}, "en"))

    def test_legacy_hubs_are_not_opted_in_by_the_thn_contract(self):
        result = self.runtime._content_hub_article_summary(spanish_only_index(), {}, "en")
        self.assertEqual(result["path"], "/the-journal/formas-nupciales/synthetic")

    def test_generated_projection_and_immutable_bundle_are_consumed_without_reader_changes(self):
        import content_hub_v2_projection as projection
        package={"title":"A quiet shape","summary":"A small observation.","seriesId":"bridal-forms","tags":["private"],
            "cover":{"assetId":"m1","alt":"Hair","focalX":35,"focalY":45},
            "delta":{"ops":[{"insert":"A small observation.\n"}]}}
        live=projection.build_locale_projection("a1","es","r1",package,{"m1":{"status":"ready"}},
            path="/the-journal/formas-nupciales/a-quiet-shape",first_published_at="2026-09-01T00:00:00Z",
            updated_at="2026-09-07T00:00:00Z")
        item=projection.build_article_index_item("a1",{"es":live})
        summary=self.runtime._content_hub_article_summary(item,{"localePolicy":"published-only"},"es")
        for internal in ("pk","sk","hubId","itemFamily","revisionId","publishedBundleKey"):
            self.assertNotIn(internal,summary)
        self.assertIsNone(self.runtime._content_hub_article_summary(item,{"localePolicy":"published-only"},"en"))
        bundle=self.runtime._public_content_hub_bundle(projection.build_public_bundle("a1","es",live),summary)
        self.assertEqual(bundle["variables"]["articleContent"],{"html":"<p>A small observation.</p>"})
        self.assertEqual(bundle["variables"]["journalArticle"]["coverFocalX"],35)
        self.assertEqual(bundle["seo"]["canonical"],summary["path"])
        self.assertNotIn("tags",bundle["variables"]["journalArticle"])


if __name__ == "__main__": unittest.main()
