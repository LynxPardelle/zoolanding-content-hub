"""Bilingual pointer transitions; only pure data, never service clients."""
from copy import deepcopy
import importlib.util
import unittest

import content_hub_v2_projection as projection
from content_hub_v2_editor_model import EditorValidationError
from content_hub_v2_projection_manifest import validate_projection_pointer


class ProjectionDeltaTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("content_hub_v2_projection_delta"),
                             "the bounded public pointer transition is not implemented")
        self.module=__import__("content_hub_v2_projection_delta")
        self.package={"title":"Quiet shape","summary":"A small observation.","seriesId":"bridal-forms","tags":[],
            "cover":{"assetId":"m1","alt":"Hair","focalX":50,"focalY":50},
            "delta":{"ops":[{"insert":"A small observation.\n"}]}}

    def locale(self,locale="es",revision="r1",**overrides):
        slug="formas-nupciales" if locale=="es" else "bridal-forms"
        params=dict(path=f"/the-journal/{slug}/quiet-shape",first_published_at="2026-09-01T00:00:00Z",
                    updated_at="2026-09-07T00:00:00Z")
        params.update(overrides)
        live=projection.build_locale_projection("a1",locale,revision,self.package,{"m1":{"status":"ready"}},**params)
        variants=[{"assetId":"m1","variantId":v,"contentType":"image/webp","versionId":"v1",
            "bytes":24,"sha256":"a"*64,"objectKey":f"{projection.ROOT}/{locale}/a1/{revision}/media/m1/{v}.webp"}
            for v in projection.VARIANTS]
        return live,projection.build_delivery_manifest("a1",locale,revision,variants)

    def snapshot(self,*locales):
        live={};media={}
        for locale,revision in locales:
            live[locale],media[locale]=self.locale(locale,revision)
        return live,media

    def delta(self,before,after):
        return self.module.build_projection_delta("a1",before[0],before[1],after[0],after[1])

    def test_initial_publication_has_exact_four_targets_and_a_closed_withdrawal_page(self):
        result=self.delta(({},{}),self.snapshot(("es","r1")))
        self.assertEqual(len(result["changes"]),4)
        self.assertTrue(all(c["before"] is None and c["after"] for c in result["changes"]))
        self.assertEqual(len(result["afterPointers"]),4)
        for pointer in result["afterPointers"]: validate_projection_pointer(pointer)
        self.assertIn("/",result["invalidationPaths"])
        self.assertIn("/the-journal/formas-nupciales/quiet-shape",result["invalidationPaths"])
        self.assertIn("/sitemap.xml",result["invalidationPaths"])
        self.assertIn("/content-hub-search.json",result["invalidationPaths"])

    def test_add_english_promotes_index_and_does_not_rewrite_spanish_targets(self):
        result=self.delta(self.snapshot(("es","r1")),self.snapshot(("es","r1"),("en","r2")))
        self.assertEqual(len(result["changes"]),4)
        index=next(c for c in result["changes"] if c["after"]["sk"]=="ARTICLE#a1")
        self.assertEqual(index["before"]["locale"],"es")
        self.assertEqual(index["after"]["locale"],"en")
        self.assertEqual(set(index["after"]["localizations"]),{"en","es"})
        self.assertEqual(len(result["afterPointers"]),7)

    def test_revision_update_removes_old_live_media_and_invalidates_both_revisions(self):
        result=self.delta(self.snapshot(("es","r1")),self.snapshot(("es","r2")))
        self.assertEqual(len(result["changes"]),5)
        removed=[c for c in result["changes"] if c["after"] is None]
        self.assertEqual(len(removed),1)
        self.assertTrue(removed[0]["before"]["pk"].endswith("#r1"))
        for revision in ("r1","r2"):
            self.assertIn(f"/features/content-hub-v2/public-media/a1/es/{revision}/m1/w768",result["invalidationPaths"])

    def test_unpublish_promotes_sibling_and_last_locale_removes_all_targets(self):
        bilingual=self.snapshot(("es","r1"),("en","r2")); spanish=self.snapshot(("es","r1"))
        result=self.delta(bilingual,spanish)
        self.assertEqual(len(result["changes"]),4)
        self.assertEqual(sum(c["after"] is None for c in result["changes"]),3)
        index=next(c for c in result["changes"] if c["after"] is not None)
        self.assertEqual(index["after"]["locale"],"es")
        result=self.delta(spanish,({},{}))
        self.assertEqual(len(result["changes"]),4)
        self.assertTrue(all(c["after"] is None for c in result["changes"]))
        self.assertEqual(result["afterPointers"],[])

    def test_same_snapshot_is_noop_and_returned_data_cannot_mutate_inputs(self):
        before=self.snapshot(("es","r1"))
        result=self.delta(before,before)
        self.assertEqual(result["changes"],[])
        self.assertEqual(result["invalidationPaths"],[])
        result["afterPointers"][0]["articleId"]="different"
        self.assertEqual(before[0]["es"]["bundle"]["articleId"],"a1")

    def test_mismatched_or_extra_media_fails_closed(self):
        for mutate in (
            lambda live,media: media.clear(),
            lambda live,media: media["es"].update(hubId="zoosite-main"),
            lambda live,media: media["es"]["variants"].pop(),
            lambda live,media: live["es"]["fields"].update(imageSrc="https://example.com/other.jpg"),
            lambda live,media: media.update(en=deepcopy(media["es"])),
        ):
            after=self.snapshot(("es","r1"));mutate(*after)
            with self.assertRaises(EditorValidationError): self.delta(({},{}),after)

    def test_path_publication_time_and_series_are_frozen_for_an_existing_locale(self):
        before=self.snapshot(("es","r1"))
        for kwargs in ({"path":"/the-journal/formas-nupciales/different"},
                       {"first_published_at":"2026-09-02T00:00:00Z"},
                       {"updated_at":"2026-09-06T00:00:00Z"}):
            live,media=self.locale("es","r2",**kwargs)
            with self.assertRaises(EditorValidationError): self.delta(before,({"es":live},{"es":media}))

    def test_same_revision_cannot_change_content_or_media_version(self):
        before=self.snapshot(("es","r1"))
        after=deepcopy(before)
        after[0]["es"]["bundle"]["variables"]["articleContent"]["html"]="<p>Changed</p>"
        with self.assertRaises(EditorValidationError): self.delta(before,after)
        after=deepcopy(before)
        after[1]["es"]["variants"][0]["versionId"]="another-version"
        with self.assertRaises(EditorValidationError): self.delta(before,after)

    def test_no_unreferenced_asset_can_become_live(self):
        after=self.snapshot(("es","r1"))
        variants=after[1]["es"]["variants"]
        variants.extend([{**v,"assetId":"unused","objectKey":v["objectKey"].replace("/m1/","/unused/")}
                         for v in list(variants)])
        with self.assertRaises(EditorValidationError): self.delta(({},{}),after)

    def test_closed_fields_still_cannot_point_at_external_or_different_revision_images(self):
        for source in ("https://example.com/other.webp", "/features/content-hub-v2/public-media/a1/es/r2/m1/w1200"):
            after=self.snapshot(("es","r1"))
            live=after[0]["es"]
            live["fields"]["imageSrc"]=source
            live["bundle"]["variables"]["journalArticle"]["imageSrc"]=source
            with self.assertRaises(EditorValidationError): self.delta(({},{}),after)

    def test_es_en_publication_update_withdraw_republish_lifecycle_converges(self):
        states=[({},{}),self.snapshot(("es","r1")),self.snapshot(("es","r1"),("en","r2")),
                self.snapshot(("es","r1"),("en","r3")),self.snapshot(("es","r1")),({},{}),
                self.snapshot(("es","r1"))]
        current={}
        for before,after in zip(states,states[1:]):
            result=self.delta(before,after)
            targets=[]
            for change in result["changes"]:
                row=change["before"] or change["after"]
                key=row["pk"],row["sk"]
                self.assertEqual(current.get(key),change["before"])
                targets.append(key)
                if change["after"] is None: current.pop(key)
                else: current[key]=deepcopy(change["after"])
            self.assertEqual(len(targets),len(set(targets)))
            self.assertEqual(set(current),{(p["pk"],p["sk"]) for p in result["afterPointers"]})
            for locale,live in after[0].items():
                self.assertEqual(current["HUB#thehairnarrative-com-journal","ARTICLE#a1"]["localizations"][locale]["publishedAt"],live["fields"]["publishedAt"])


if __name__=="__main__":unittest.main()
