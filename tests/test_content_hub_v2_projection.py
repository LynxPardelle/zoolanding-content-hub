"""Pure C contract tests; no resource clients or public writes."""
from copy import deepcopy
import importlib
import json
import unittest

from content_hub_v2_editor_model import EditorValidationError


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.p = importlib.import_module("content_hub_v2_projection")
        self.package = {"title":"Una forma serena","summary":"Una observación breve.",
            "seriesId":"bridal-forms","tags":["private-tag"],"cover":{"assetId":"m1","alt":"Hair","focalX":35,"focalY":45},
            "delta":{"ops":[{"insert":"A quiet observation.\n"},{"insert":{"image":"m1"}}]}}
        self.assets = {"m1":{"status":"ready","alt":"Soft shape"}}
        self.live = self.p.build_locale_projection("a1","es","r1",self.package,self.assets,
            path="/the-journal/formas-nupciales/una-forma-serena",first_published_at="2026-09-01T00:00:00Z",
            updated_at="2026-09-07T00:00:00Z")

    def test_spanish_only_index_contains_only_published_safe_fields(self):
        item = self.p.build_article_index_item("a1",{"es":self.live})
        self.assertEqual(item["locale"],"es")
        self.assertEqual(set(item["localizations"]),{"es"})
        self.assertEqual(item["pk"],"HUB#thehairnarrative-com-journal")
        self.assertEqual(item["sk"],"ARTICLE#a1")
        serialized=json.dumps(item)
        for key in ["primaryLocale","tags","private-tag","articleContent","workingRevisionId","recordPurpose"]:
            self.assertNotIn(key,serialized)

    def test_primary_language_promotes_and_sibling_is_retained_without_retranslation(self):
        english=deepcopy(self.package);english["title"]="A quiet shape"
        en=self.p.build_locale_projection("a1","en","r2",english,self.assets,
            path="/the-journal/bridal-forms/a-quiet-shape",first_published_at="2026-09-02T00:00:00Z",
            updated_at="2026-09-07T00:00:00Z")
        item=self.p.build_article_index_item("a1",{"es":self.live,"en":en})
        self.assertEqual(item["locale"],"en")
        self.assertEqual(item["localizations"]["es"]["title"],"Una forma serena")
        self.assertEqual(self.p.build_article_index_item("a1",{"es":self.live})["locale"],"es")
        self.assertIsNone(self.p.build_article_index_item("a1",{}))

    def test_exact_bundle_pointer_category_and_sanitized_inline_media(self):
        bundle=self.p.build_public_bundle("a1","es",self.live)
        self.assertEqual(bundle["variables"]["articleContent"]["html"],'<p>A quiet observation.</p><figure><img src="/features/content-hub-v2/public-media/a1/es/r1/m1/w1200" alt="Soft shape" loading="lazy"></figure>')
        pointer=self.p.build_slug_pointer("a1","es",self.live)
        self.assertEqual(pointer["pk"],"SLUG#test#thehairnarrative.com#es")
        self.assertTrue(pointer["publishedBundleKey"].endswith("/es/a1/r1/bundle.json"))
        categories=self.p.build_category_items("a1",{"es":self.live})
        self.assertEqual(categories[0]["sk"],"CATEGORY#es#formas-nupciales#ARTICLE#a1")

    def test_rejects_wrong_series_path_invalid_time_private_fields_and_missing_images(self):
        for kwargs in [{"path":"/blog/nope"},{"updated_at":"today"},{"first_published_at":"2026-10-01T00:00:00Z"}]:
            params=dict(path="/the-journal/formas-nupciales/una-forma-serena",
                first_published_at="2026-09-01T00:00:00Z",updated_at="2026-09-07T00:00:00Z")
            params.update(kwargs)
            with self.assertRaises(EditorValidationError):
                self.p.build_locale_projection("a1","es","r1",self.package,self.assets,**params)
        with self.assertRaises(EditorValidationError):
            self.p.build_article_index_item("a1",{"es":{**self.live,"tags":["private"]}})
        with self.assertRaises(EditorValidationError):
            self.p.build_locale_projection("a1","es","r1",self.package,{},
                path="/the-journal/formas-nupciales/title",first_published_at="2026-09-01T00:00:00Z",updated_at="2026-09-07T00:00:00Z")


    def test_private_fields_are_rejected_at_every_public_bundle_boundary(self):
        for location,key in [("bundle","ownerEmail"),("variables","internalActor"),("journalArticle","tags")]:
            live=deepcopy(self.live)
            target=live["bundle"] if location=="bundle" else live["bundle"]["variables"]
            if location=="journalArticle": target=target["journalArticle"]
            target[key]="must-not-be-public"
            with self.assertRaises(EditorValidationError):
                self.p.build_public_bundle("a1","es",live)

    def test_existing_public_media_reader_accepts_only_the_complete_versioned_manifest(self):
        from unittest.mock import Mock
        from public_media_lambda import PublicMediaPath, resolve_live_variant
        variants=[{"assetId":"m1","variantId":v,"contentType":"image/webp","versionId":"immutable-version",
            "bytes":24,"sha256":"a"*64,"objectKey":f"{self.p.ROOT}/es/a1/r1/media/m1/{v}.webp"} for v in self.p.VARIANTS]
        manifest=self.p.build_delivery_manifest("a1","es","r1",variants)
        runtime=Mock()
        runtime.load_live_manifest.return_value=manifest
        resolved=resolve_live_variant(runtime,PublicMediaPath("a1","es","r1","m1","w768"))
        self.assertEqual(resolved.version_id,"immutable-version")
        for corrupt in [variants[:3],variants+[variants[0]],
            [{**v,"objectKey":"outside/object.webp"} for v in variants],
            [{**v,"versionId":"null"} for v in variants]]:
            with self.assertRaises(EditorValidationError):
                self.p.build_delivery_manifest("a1","es","r1",corrupt)

    def test_storage_projection_matches_the_existing_emergency_withdraw_conditions(self):
        from emergency_withdraw_lambda import _pointer_delete
        from content_hub_v2_registry_fence import unmarshal_item
        common={"articleId":"a1","locale":"es","revisionId":"r1"}
        path=self.live["fields"]["path"]
        cases=[
            (self.p.build_article_index_item("a1",{"es":self.live}),"article",{},[]),
            (self.p.build_slug_pointer("a1","es",self.live),"locale-path",{"path":path},[path]),
            (self.p.build_category_items("a1",{"es":self.live})[0],"category-index",
             {"categorySlug":"formas-nupciales"},["/the-journal/formas-nupciales"]),
        ]
        for item,kind,extra,paths in cases:
            pointer={**common,"pointerType":kind,"pk":item["pk"],"sk":item["sk"],
                     "invalidationPaths":paths,**extra}
            deletion=_pointer_delete(pointer,table_name="fixture-public-table")["Delete"]
            values=unmarshal_item(deletion["ExpressionAttributeValues"])
            for name,field in deletion["ExpressionAttributeNames"].items():
                if name=="#pk": continue
                self.assertEqual(item.get(field),values[":"+name[1:]],f"{kind}: missing or inconsistent {field}")


if __name__=="__main__": unittest.main()
